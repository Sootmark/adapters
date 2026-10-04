//! The live-state adapter on outputs shaped as the collector's PowerShell
//! commands write them (synthetic, `tests/fixtures/live/live/`): a byte
//! order mark, one item as an object, an empty output, PowerShell's empty
//! object for a missing value.

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, Record, TimeKind, Value};
use sootmark_adapters::live::{LiveAdapter, NAMESPACE};

fn read(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/live/live/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn parse(name: &str) -> Vec<Record> {
    let data = read(name);
    let path = format!("live/{name}");
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name: &path,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    LiveAdapter.parse(&input, &mut sink).expect("items");
    sink.records
}

#[test]
fn conforms_and_probes() {
    for name in [
        "processes.json",
        "connections.json",
        "services.json",
        "dns-cache.json",
        "sessions.json",
        "udp.json",
    ] {
        assert_conforms(&LiveAdapter, &format!("live/{name}"), &read(name));
    }
    assert_eq!(
        LiveAdapter.probe("live/processes.json", b"[{"),
        Confidence::Certain
    );
    assert_eq!(LiveAdapter.probe("processes.json", b"[{"), Confidence::No);
    assert_eq!(LiveAdapter.probe("live/other.json", b"[{"), Confidence::No);
}

#[test]
fn processes_connections_services_and_sessions() {
    let processes = parse("processes.json");
    assert_eq!(processes.len(), 2);
    assert_eq!(processes[0].namespace(), NAMESPACE);
    assert_eq!(
        processes[0].facets.user_name, None,
        "PowerShell's {{}} is no owner"
    );
    let shell = &processes[1];
    assert_eq!(
        shell.summary,
        r"Process powershell.exe (pid 4242) as LAB\alice: powershell.exe -nop -w hidden -enc SQBFAFgA"
    );
    assert_eq!(shell.facets.process_id, Some(4242));
    assert_eq!(shell.times[0].kind, TimeKind::Created);
    assert_eq!(
        shell.times[0].ts.to_iso8601().unwrap(),
        "2026-10-04T03:12:00.1234567Z"
    );
    assert_eq!(shell.fields.get("ParentProcessId"), Some(&Value::Int(3100)));

    let connections = parse("connections.json");
    assert_eq!(
        connections[0].facets.destination_ip, None,
        "a listening socket has no peer"
    );
    assert_eq!(
        connections[1].summary,
        "TCP 192.0.2.10:51515 → 203.0.113.9:443 Established (pid 4242)"
    );
    assert_eq!(
        connections[1].facets.destination_ip.as_deref(),
        Some("203.0.113.9")
    );

    let services = parse("services.json");
    assert_eq!(services.len(), 1, "one service, written as an object");
    assert_eq!(
        services[0].summary,
        r"Service PSEXESVC (Running, Manual): C:\Windows\PSEXESVC.exe as LocalSystem"
    );
    assert_eq!(services[0].facets.service_name.as_deref(), Some("PSEXESVC"));

    assert_eq!(
        parse("dns-cache.json")[0].summary,
        "DNS cache: update.example.org → 203.0.113.9 (A)"
    );
    let sessions = parse("sessions.json");
    assert_eq!(
        sessions[0].summary,
        r"Logon session LAB\alice (remote desktop)"
    );
    assert!(parse("udp.json").is_empty(), "no output: no records");
}
