//! The application log adapter on plaso's test logs (Apache-2.0,
//! `tests/fixtures/applogs/`, `santa.log` stored gzip-compressed):
//! recognition, the contract, and each log's records.

use std::io::Read;

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, Namespace, Record, TimeKind, Ts, Value};
use sootmark_adapters::applogs::{
    ApplogsAdapter, APPFIREWALL, GLOG, POPCONTEST, POSTGRESQL, SANTA, SECURITYD, SNORT, VSFTPD,
};

fn fixture(name: &str) -> Vec<u8> {
    let raw = std::fs::read(format!(
        "{}/tests/fixtures/applogs/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    if !std::path::Path::new(name)
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("gz"))
    {
        return raw;
    }
    let mut data = Vec::new();
    common::gzip::Decoder::new(raw.as_slice())
        .read_to_end(&mut data)
        .unwrap();
    data
}

/// The records of a log, all in `namespace`; `modified` dates logs
/// without a year.
fn read_log(name: &str, path: &str, namespace: Namespace, modified: Option<Ts>) -> Vec<Record> {
    let data = fixture(name);
    assert_eq!(
        ApplogsAdapter.probe(path, &data),
        Confidence::Certain,
        "{path}"
    );
    assert_conforms(&ApplogsAdapter, path, &data);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name: path,
        data: &data,
        modified,
    };
    let mut sink = Collected::default();
    ApplogsAdapter.parse(&input, &mut sink).unwrap();
    assert!(sink.skipped.is_empty(), "{path}: {:?}", sink.skipped);
    assert!(
        sink.records.iter().all(|r| r.namespace() == namespace),
        "{path}"
    );
    sink.records
}

#[test]
fn vsftpd_sessions() {
    let records = read_log("vsftpd.log", "var/log/vsftpd.log", VSFTPD, None);
    assert_eq!(records.len(), 25);
    let mkdir = &records[2];
    assert_eq!(
        mkdir.summary,
        "vsftpd: jean OK MKDIR /home/jean/trains from 192.168.1.9"
    );
    assert_eq!(mkdir.facets.user_name.as_deref(), Some("jean"));
    assert_eq!(mkdir.facets.source_ip.as_deref(), Some("192.168.1.9"));
    assert_eq!(mkdir.facets.file_path.as_deref(), Some("/home/jean/trains"));
    assert_eq!(mkdir.times[0].kind, TimeKind::Logged);
}

#[test]
fn postgresql_and_popularity_contest() {
    let records = read_log(
        "postgresql.log",
        "var/log/postgresql/postgresql-12-main.log",
        POSTGRESQL,
        None,
    );
    assert_eq!(records.len(), 20);
    assert!(records
        .iter()
        .any(|r| r.facets.user_name.as_deref() == Some("user")
            && r.fields.get("database") == Some(&Value::from("databasename"))));

    let records = read_log(
        "popcontest1.log",
        "var/log/popularity-contest",
        POPCONTEST,
        None,
    );
    assert_eq!(records.len(), 13);
    let atd = records
        .iter()
        .find(|r| r.summary == "popularity-contest: at /usr/sbin/atd")
        .unwrap();
    assert_eq!(atd.times[0].kind, TimeKind::Accessed);
    assert_eq!(atd.times[1].kind, TimeKind::MetadataChanged);
    assert_eq!(atd.facets.file_path.as_deref(), Some("/usr/sbin/atd"));
    assert!(records[0]
        .summary
        .starts_with("popularity-contest: session 0"));
}

#[test]
fn ids_alerts() {
    // Snort writes no year here: the file's modification time gives it.
    let modified = Ts::from_unix_seconds(1_643_000_000);
    let records = read_log(
        "snort3_alert_fast.log",
        "var/log/snort/alert",
        SNORT,
        Some(modified),
    );
    assert_eq!(records.len(), 4);
    let shellcode = &records[2];
    assert_eq!(
        shellcode.summary,
        "IDS alert: 1:648:18 INDICATOR-SHELLCODE x86 NOOP 10.6.6.254 -> 10.6.6.103"
    );
    assert_eq!(shellcode.facets.source_ip.as_deref(), Some("10.6.6.254"));
    assert_eq!(
        shellcode.facets.destination_ip.as_deref(),
        Some("10.6.6.103")
    );
    assert_eq!(
        shellcode.fields.get("YearInferred"),
        Some(&Value::Bool(true))
    );
    assert_eq!(shellcode.times.len(), 1);
    let records = read_log(
        "suricata_alert_fast.log",
        "var/log/suricata/fast.log",
        SNORT,
        None,
    );
    assert_eq!(records.len(), 5);
}

#[test]
fn glog_and_santa() {
    let records = read_log("googlelog_test.INFO", "tmp/app.INFO", GLOG, None);
    assert_eq!(records.len(), 5);
    assert!(records
        .iter()
        .all(|r| r.facets.host_name.as_deref() == Some("plasotest1")));
    assert!(records
        .iter()
        .any(|r| r.summary == "glog: FATAL This line is a fatal log"));

    let records = read_log("santa2.log", "var/db/santa/santa.log", SANTA, None);
    assert_eq!(records.len(), 11);
    let exec = &records[0];
    assert_eq!(
        exec.summary,
        "Santa: EXEC ALLOW /bin/ps /bin/ps -x -o utime,stime -p 57680"
    );
    assert_eq!(exec.facets.process_path.as_deref(), Some("/bin/ps"));
    assert_eq!(
        exec.facets.process_command_line.as_deref(),
        Some("/bin/ps -x -o utime,stime -p 57680")
    );
    assert_eq!(exec.facets.user_name.as_deref(), Some("root"));
    assert_eq!(exec.facets.process_id, Some(75780));
    assert_eq!(exec.fields.get("decision"), Some(&Value::from("ALLOW")));
    let write = &records[2];
    assert!(write
        .facets
        .file_path
        .as_deref()
        .is_some_and(|p| p.starts_with("/Users/testuser/")));
    assert_eq!(
        read_log("santa.log.gz", "var/db/santa/santa.log.1", SANTA, None).len(),
        194
    );
}

#[test]
fn securityd_and_application_firewall() {
    let modified = Ts::from_unix_seconds(1_700_000_000);
    let records = read_log(
        "security.log",
        "var/log/security.log",
        SECURITYD,
        Some(modified),
    );
    assert_eq!(records.len(), 9);
    assert!(records.iter().all(|r| r.times.len() == 1));
    assert_eq!(
        records[0].fields.get("facility"),
        Some(&Value::from("user"))
    );
    let records = read_log(
        "appfirewall.log",
        "var/log/appfirewall.log",
        APPFIREWALL,
        Some(modified),
    );
    assert_eq!(records.len(), 47);
    let dropbox = &records[1];
    assert_eq!(dropbox.fields.get("process"), Some(&Value::from("Dropbox")));
    assert_eq!(
        dropbox.facets.host_name.as_deref(),
        Some("DarkTemplar-2.local")
    );
}

#[test]
fn other_text_is_not_an_application_log() {
    assert_eq!(
        ApplogsAdapter.probe("notes.txt", b"hello\nworld\n"),
        Confidence::No
    );
}
