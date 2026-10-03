//! The journal adapter on journals made for the `journal` crate (synthetic
//! entries; `tests/fixtures/journal/`): the contract, sshd and sudo read
//! from the journal, Zstandard fields, and entries recovered from damage.

use std::io::Read;

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, TimeKind, Value};
use sootmark_adapters::journal::{JournalAdapter, NAMESPACE};

fn read(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/tests/fixtures/journal/{name}.gz",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut bytes = Vec::new();
    common::gzip::Decoder::new(std::fs::File::open(path).unwrap())
        .read_to_end(&mut bytes)
        .unwrap();
    bytes
}

fn parse(name: &str) -> Collected {
    let data = read(name);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    JournalAdapter.parse(&input, &mut sink).expect("entries");
    sink
}

#[test]
fn conforms_and_probes() {
    for name in ["zstd.journal", "xz.journal", "corrupt.journal~"] {
        assert_conforms(&JournalAdapter, name, &read(name));
    }
    let data = read("zstd.journal");
    assert_eq!(
        JournalAdapter.probe("var/log/journal/x/system.journal", &data),
        Confidence::Certain
    );
    assert_eq!(
        JournalAdapter.probe("system.journal", b"not one"),
        Confidence::No
    );
}

#[test]
fn logins_and_sudo_from_the_journal() {
    let collected = parse("zstd.journal");
    assert!(collected.skipped.is_empty(), "{:?}", collected.skipped);
    let records = collected.records;
    assert_eq!(records.len(), 24);
    assert_eq!(records[0].namespace(), NAMESPACE);
    assert_eq!(records[0].times[0].kind, TimeKind::Logged);
    assert_eq!(records[0].facets.host_name.as_deref(), Some("lab-host"));
    let login = records
        .iter()
        .find(|r| r.fields.get("Action") == Some(&Value::from("ssh login")))
        .unwrap();
    assert_eq!(
        login.summary,
        "SSH login alice from 198.51.100.23 (publickey)"
    );
    assert_eq!(login.facets.source_ip.as_deref(), Some("198.51.100.23"));
    assert_eq!(
        login.fields.get("SYSLOG_IDENTIFIER"),
        Some(&Value::from("sshd"))
    );
    let failed = records
        .iter()
        .filter(|r| r.fields.get("Action") == Some(&Value::from("ssh failed login")))
        .count();
    assert_eq!(failed, 4, "two per boot");
    let sudo = records
        .iter()
        .find(|r| r.summary.starts_with("sudo "))
        .unwrap();
    assert_eq!(
        sudo.facets.process_command_line.as_deref(),
        Some("/usr/bin/systemctl restart nginx")
    );
    // A Zstandard-compressed message, decoded.
    let backup = records
        .iter()
        .find(|r| r.summary.starts_with("backup: line 000"))
        .unwrap();
    assert!(matches!(backup.fields.get("MESSAGE"), Some(Value::Text(m)) if m.len() > 512));
}

#[test]
fn xz_fields_named_and_reported() {
    let collected = parse("xz.journal");
    assert_eq!(collected.records.len(), 24);
    assert_eq!(collected.skipped.len(), 1);
    assert!(collected.records.iter().any(|r| matches!(
        r.fields.get("MESSAGE"),
        Some(Value::Text(m)) if m.starts_with("[XZ-compressed")
    )));
}

#[test]
fn recovered_entries_are_marked() {
    let records = parse("corrupt.journal~").records;
    assert_eq!(records.len(), 24);
    assert!(records
        .iter()
        .any(|r| r.fields.get("Recovered") == Some(&Value::Bool(true))));
}
