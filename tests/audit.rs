//! The audit adapter on plaso's audit log (Apache-2.0) and a lab log made
//! for the `audit` crate (`tests/fixtures/audit/`): the contract, commands
//! with their login user, sudo, SSH logins and failures (an invalid user's
//! name, which audit doesn't keep, left out), and connections.

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, Record, TimeKind, Value};
use sootmark_adapters::audit::{AuditAdapter, NAMESPACE};

fn read(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/audit/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn parse(name: &str) -> Collected {
    let data = read(name);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name: "var/log/audit/audit.log",
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    AuditAdapter.parse(&input, &mut sink).expect("events");
    sink
}

fn with_action<'r>(records: &'r [Record], action: &str) -> Vec<&'r Record> {
    records
        .iter()
        .filter(|r| r.fields.get("Action") == Some(&Value::from(action)))
        .collect()
}

#[test]
fn conforms_and_probes() {
    for name in ["plaso-audit.log", "lab-audit.log"] {
        assert_conforms(&AuditAdapter, "var/log/audit/audit.log", &read(name));
    }
    let data = read("lab-audit.log");
    assert_eq!(
        AuditAdapter.probe("var/log/audit/audit.log.1", &data),
        Confidence::Certain
    );
    assert_eq!(AuditAdapter.probe("notes.txt", &data), Confidence::Certain);
    assert_eq!(
        AuditAdapter.probe("var/log/audit/audit.log", b"hello"),
        Confidence::Maybe
    );
    assert_eq!(AuditAdapter.probe("notes.txt", b"hello"), Confidence::No);
}

#[test]
fn commands_logins_and_connections() {
    let collected = parse("lab-audit.log");
    assert!(collected.skipped.is_empty(), "{:?}", collected.skipped);
    let records = collected.records;
    assert_eq!(records[0].namespace(), NAMESPACE);
    assert_eq!(records[0].times[0].kind, TimeKind::Logged);

    let group = with_action(&records, "group added");
    assert_eq!(group[0].summary, "Group added sootmarkops (by analyst)");
    let command = records
        .iter()
        .find(|r| r.summary == "analyst$ sudo groupadd sootmarkops")
        .unwrap();
    assert_eq!(command.facets.user_name.as_deref(), Some("analyst"));
    assert_eq!(
        command.facets.process_command_line.as_deref(),
        Some("sudo groupadd sootmarkops")
    );
    assert!(with_action(&records, "sudo")
        .iter()
        .any(|r| r.summary == "sudo analyst: groupadd sootmarkops"));

    let login = with_action(&records, "ssh login");
    assert_eq!(login.len(), 1);
    assert_eq!(login[0].summary, "SSH login sootmarktest from 127.0.0.1");
    assert_eq!(login[0].facets.source_ip.as_deref(), Some("127.0.0.1"));
    let failed = with_action(&records, "ssh failed login");
    assert_eq!(
        failed[0].summary,
        "SSH failed login, invalid user from 127.0.0.1"
    );
    assert_eq!(failed[0].facets.user_name, None, "not sshd's own account");

    let connect = with_action(&records, "network connect");
    assert!(connect
        .iter()
        .any(|r| r.facets.destination_ip.as_deref() == Some("::1")
            && r.fields.get("DestinationPort") == Some(&Value::UInt(22))));
}

#[test]
fn plaso_log_reads() {
    let collected = parse("plaso-audit.log");
    assert!(!collected.records.is_empty());
}
