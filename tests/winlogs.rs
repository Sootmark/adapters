//! The Windows text logs adapter on plaso's test logs (Apache-2.0,
//! `tests/fixtures/winlogs/`, gzip-compressed): a record per entry, in the
//! right namespace, with the facets hunts use; and a Windows Error
//! Reporting report written for the sootmark-winlogs tests
//! (`tests/fixtures/wer/`); and ScreenConnect client settings and a server
//! session database written for them too (`tests/fixtures/screenconnect/`,
//! by its `make.py`).

use std::io::Read;

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, Locator, Record, TimeKind, Value};
use sootmark_adapters::winlogs::{
    WinlogsAdapter, ANYDESK, FIREWALL, IIS, PCA, SCCM, SCREENCONNECT_CONFIG,
    SCREENCONNECT_CONNECTIONS, SCREENCONNECT_EVENTS, SCREENCONNECT_SESSIONS, SETUPAPI, TEAMVIEWER,
    TRANSCRIPT, WER,
};

fn records(name: &str) -> Vec<Record> {
    let path = format!(
        "{}/tests/fixtures/winlogs/{name}.gz",
        env!("CARGO_MANIFEST_DIR")
    );
    let compressed = std::fs::read(path).unwrap();
    let mut data = Vec::new();
    common::gzip::Decoder::new(compressed.as_slice())
        .read_to_end(&mut data)
        .unwrap();
    assert_eq!(
        WinlogsAdapter.probe(name, &data[..data.len().min(4096)]),
        Confidence::Certain,
        "{name}"
    );
    assert_conforms(&WinlogsAdapter, name, &data);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    WinlogsAdapter.parse(&input, &mut sink).unwrap();
    sink.records
}

#[test]
fn every_log_family() {
    let pca = records("PcaAppLaunchDic.txt");
    assert_eq!(pca.len(), 4);
    assert!(pca.iter().all(|r| r.namespace() == PCA));
    assert!(pca[0]
        .summary
        .starts_with("PCA: ran C:\\Program Files\\WindowsApps\\MicrosoftTeams"));
    assert_eq!(records("PcaGeneralDb0.txt").len(), 3);

    let iis = records("iis6.log");
    assert!(iis.iter().all(|r| r.namespace() == IIS));
    assert_eq!(iis[1].facets.source_ip.as_deref(), Some("22.22.22.200"));
    assert_eq!(
        iis[1].summary,
        "IIS GET /some/image/path/something.htm 404 from 22.22.22.200"
    );

    let firewall = records("windows_firewall.log");
    assert_eq!(firewall.len(), 15);
    assert!(firewall.iter().all(|r| r.namespace() == FIREWALL));
    assert!(firewall[0]
        .summary
        .starts_with("Firewall DROP UDP 123.45.78.90:137 -> 123.156.78.255:137"));

    let transcript = records("powershell_transcript_ger.txt");
    assert_eq!(transcript.len(), 3);
    assert!(transcript.iter().all(|r| r.namespace() == TRANSCRIPT));
    assert_eq!(transcript[0].facets.user_name.as_deref(), Some("DE\\User"));
    assert_eq!(transcript[0].facets.host_name.as_deref(), Some("MySystem"));
    assert_eq!(
        transcript[0].facets.process_command_line.as_deref(),
        Some("whoami; echo $null >> filename; ping 8.8.8.8; Get-Content .\\myfile.txt")
    );

    let sessions = records("connections_incoming.txt");
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].namespace(), TEAMVIEWER);
    assert_eq!(
        sessions[0].summary,
        "TeamViewer session in from 1660360496 (TestUserRedacted) as IEUser: RemoteControl"
    );

    let setup = records("setupapi.setup.log");
    assert_eq!(setup.len(), 16);
    assert!(setup.iter().all(|r| r.namespace() == SETUPAPI));

    let sccm = records("sccm_various.log");
    assert_eq!(sccm.len(), 10);
    assert!(sccm.iter().all(|r| r.namespace() == SCCM));
}

#[test]
fn anydesk_logs() {
    let trace = records("ad_svc.trace");
    assert_eq!(trace.len(), 7);
    assert!(trace.iter().all(|r| r.namespace() == ANYDESK));
    let login = &trace[1];
    assert_eq!(login.facets.source_ip.as_deref(), Some("198.51.100.4"));
    let sessions = records("connection_trace.txt");
    assert_eq!(
        sessions[0].summary,
        "AnyDesk session in from 221436813 (User)"
    );
    assert_eq!(
        sessions[2].summary,
        "AnyDesk session out to 377110044 (Token)"
    );
}

#[test]
fn error_reports() {
    let data = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/wer/Report.wer"
    ))
    .unwrap();
    let name = r"C\ProgramData\Microsoft\Windows\WER\ReportArchive\AppCrash_lsass.exe_1\Report.wer";
    assert_eq!(WinlogsAdapter.probe(name, &data), Confidence::Certain);
    assert_conforms(&WinlogsAdapter, name, &data);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    WinlogsAdapter.parse(&input, &mut sink).unwrap();
    let report = &sink.records[0];
    assert_eq!(report.namespace(), WER);
    assert_eq!(
        report.summary,
        r"WER APPCRASH: C:\Windows\system32\lsass.exe (faulting module dbghelp.dll)"
    );
    assert_eq!(
        report.fields.get("FaultModuleName"),
        Some(&Value::from("dbghelp.dll"))
    );
}

/// The ScreenConnect fixture `name`, recognised, conforming and parsed
/// (with an empty `-wal` file: the same records as without one).
fn screenconnect(path: &str) -> Vec<Record> {
    let name = path.rsplit('/').next().unwrap();
    let data = std::fs::read(format!(
        "{}/tests/fixtures/screenconnect/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    assert_eq!(WinlogsAdapter.probe(path, &data), Confidence::Certain);
    assert_conforms(&WinlogsAdapter, path, &data);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name: path,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    WinlogsAdapter.parse(&input, &mut sink).unwrap();
    assert!(sink.skipped.is_empty(), "{:?}", sink.skipped);
    let mut with_log = Collected::default();
    WinlogsAdapter
        .parse_with_log(&input, &[], &mut with_log)
        .unwrap();
    assert_eq!(with_log.records, sink.records);
    sink.records
}

fn field<'r>(record: &'r Record, name: &str) -> Option<&'r Value> {
    record.fields.get(name)
}

#[test]
fn screenconnect_client_settings() {
    let user = screenconnect(
        r"C/Users/alice/AppData/Local/Apps/2.0/ScreenConnect Client (e6f5ce1d563c8e3f)/user.config",
    );
    assert_eq!(user.len(), 1);
    let user = &user[0];
    assert_eq!(user.namespace(), SCREENCONNECT_CONFIG);
    assert_eq!(user.facets.user_name.as_deref(), Some("alice"));
    assert_eq!(
        user.summary,
        "ScreenConnect client relays to relay.example.net:8041, session 6f1b3c3e-2a4d-4c5e-9f00-1a2b3c4d5e6f (Access, Guest)"
    );
    for (name, value) in [
        ("RelayHost", "relay.example.net"),
        ("RelayPort", "8041"),
        ("SessionId", "6f1b3c3e-2a4d-4c5e-9f00-1a2b3c4d5e6f"),
        ("SessionType", "Access"),
        ("ProcessType", "Guest"),
        (
            "Setting.LastFileTransferDirectory",
            r"C:\Users\alice\Documents\Payroll & HR",
        ),
    ] {
        assert_eq!(field(user, name), Some(&Value::from(value)), "{name}");
    }
    let Some(Value::List(parameters)) = field(user, "LaunchParameters") else {
        panic!("no launch parameters");
    };
    assert_eq!(parameters.len(), 9);
    assert_eq!(parameters[0], Value::from("e=Access"));
    assert_eq!(
        field(user, "CustomProperties"),
        Some(&Value::List(vec![
            Value::from("Example Co"),
            Value::from(""),
            Value::from("Finance laptop"),
        ]))
    );

    let system = screenconnect(
        "C/Program Files (x86)/ScreenConnect Client (e6f5ce1d563c8e3f)/system.config",
    );
    assert_eq!(system.len(), 1);
    assert_eq!(system[0].facets.user_name, None);
    assert_eq!(
        system[0].summary,
        "ScreenConnect client relays to relay.example.net:8041"
    );
}

#[test]
fn screenconnect_session_database() {
    let records = screenconnect("C/Program Files (x86)/ScreenConnect/App_Data/Session.db");
    let of = |namespace| {
        records
            .iter()
            .filter(|r| r.namespace() == namespace)
            .collect::<Vec<_>>()
    };
    let (sessions, connections, events) = (
        of(SCREENCONNECT_SESSIONS),
        of(SCREENCONNECT_CONNECTIONS),
        of(SCREENCONNECT_EVENTS),
    );
    assert_eq!((sessions.len(), connections.len()), (2, 2));
    assert_eq!(
        sessions[0].summary,
        "ScreenConnect Access session FIN-LAPTOP-07 owned by tech1"
    );

    let technician = connections[0];
    assert_eq!(technician.facets.user_name.as_deref(), Some("tech1"));
    assert_eq!(technician.facets.source_ip.as_deref(), Some("203.0.113.50"));
    assert_eq!(
        technician.summary,
        "ScreenConnect Host tech1 connected from 203.0.113.50 to session FIN-LAPTOP-07"
    );
    let times: Vec<(TimeKind, &str)> = technician
        .times
        .iter()
        .map(|t| (t.kind, t.field.as_str()))
        .collect();
    assert_eq!(
        times,
        [
            (TimeKind::FirstSeen, "ConnectedTime"),
            (TimeKind::LastSeen, "DisconnectedTime")
        ]
    );
    assert_eq!(
        connections[1].facets.source_ip.as_deref(),
        Some("198.51.100.23")
    );

    // 5 live events, and 241 of the 242 the generator deleted (a freeblock
    // header overwrote the start of the last), as the crate's tests count.
    let (deleted, live): (Vec<&Record>, Vec<&Record>) = events
        .iter()
        .partition(|r| field(r, "Deleted") == Some(&Value::Bool(true)));
    assert_eq!((live.len(), deleted.len()), (5, 241));
    assert!(deleted.iter().all(|r| r.flags.recovered));
    let deleted_from = |table: &str| {
        deleted
            .iter()
            .filter(|r| matches!(r.locator(), Locator::TableRow { table: t, .. } if t == table))
            .count()
    };
    assert_eq!(
        (
            deleted_from("deleted SessionEvent"),
            deleted_from("deleted SessionConnectionEvent")
        ),
        (120, 121)
    );
    assert!(deleted
        .iter()
        .any(|r| r.summary.starts_with("Deleted ScreenConnect QueuedCommand")));

    let queued = live[0];
    assert_eq!(
        queued.facets.process_command_line.as_deref(),
        Some("#!ps\nwhoami /all")
    );
    assert_eq!(queued.facets.user_name.as_deref(), Some("tech1"));
    assert_eq!(
        queued.summary,
        "ScreenConnect QueuedCommand in session FIN-LAPTOP-07 by tech1: #!ps whoami /all"
    );
    let transfer = live
        .iter()
        .find(|r| field(r, "Data") == Some(&Value::from("mimikatz.zip")))
        .unwrap();
    assert_eq!(field(transfer, "EventType"), Some(&Value::Int(27)));
    assert_eq!(transfer.facets.user_name.as_deref(), Some("tech1"));
    assert_eq!(transfer.facets.source_ip.as_deref(), Some("203.0.113.50"));
    assert_eq!(transfer.facets.process_command_line, None);
}
