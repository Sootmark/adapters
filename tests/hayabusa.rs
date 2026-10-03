//! The Hayabusa importer on Hayabusa 4.1.0's output, unaltered: every
//! profile and time format we read (`tests/fixtures/hayabusa/`), from
//! `dfir-timeline -d cc0 -w -s` on two logs of EVTX-to-MITRE-Attack (CC0,
//! `tests/fixtures/cc0/`), local times in Europe/Paris.

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Input};
use model::{EvidenceId, Locator, Record, Value};
use sootmark_adapters::hayabusa::{HayabusaAdapter, NAMESPACE};

fn read(dir: &str, name: &str) -> Option<Vec<u8>> {
    std::fs::read(format!(
        "{}/tests/fixtures/{dir}/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .ok()
}

fn fixture(name: &str) -> Vec<u8> {
    read("hayabusa", name).expect("committed fixture")
}

fn parse(name: &str, bytes: &[u8]) -> Collected {
    let input = Input {
        evidence: EvidenceId::of_content(bytes),
        name,
        data: bytes,
        modified: None,
    };
    let mut sink = Collected::default();
    HayabusaAdapter
        .parse(&input, &mut sink)
        .expect("Hayabusa output");
    sink
}

const FIXTURES: [&str; 7] = [
    "standard.csv",
    "verbose-utc.csv",
    "allfield-iso.csv",
    "timesketch.csv",
    "multiline.csv",
    "superverbose.jsonl",
    "allfield.jsonl",
];

fn text(record: &Record, name: &str) -> Option<String> {
    match record.fields.get(name)? {
        Value::Text(t) => Some(t.clone()),
        other => Some(format!("{other:?}")),
    }
}

/// UTC milliseconds: the precision every format has.
fn millis(record: &Record) -> i64 {
    record.times[0].ts.ticks().expect("a time") / 10_000
}

#[test]
fn conforms_on_every_profile_and_format() {
    for name in FIXTURES {
        assert_conforms(&HayabusaAdapter, name, &fixture(name));
        let output = parse(name, &fixture(name));
        assert_eq!(output.records.len(), 17, "{name}");
        assert!(output.skipped.is_empty(), "{name}: {:?}", output.skipped);
    }
}

#[test]
fn every_format_says_the_same_thing() {
    let reference = parse("standard.csv", &fixture("standard.csv")).records;
    for name in FIXTURES {
        let records = parse(name, &fixture(name)).records;
        for (a, b) in reference.iter().zip(&records) {
            assert_eq!(millis(a), millis(b), "{name}: time");
            assert_eq!(a.facets.host_name, b.facets.host_name, "{name}: host");
            assert_eq!(a.facets.event_code, b.facets.event_code, "{name}: event");
            assert_eq!(text(a, "Level"), text(b, "Level"), "{name}: level");
            assert_eq!(text(a, "RuleTitle"), text(b, "RuleTitle"), "{name}: title");
        }
    }
    // The multiline layout splits details the same way as the default one.
    let multiline = parse("multiline.csv", &fixture("multiline.csv")).records;
    for (a, b) in reference.iter().zip(&multiline) {
        assert_eq!(a.fields, b.fields);
        assert_eq!(a.facets, b.facets);
    }
}

#[test]
fn maps_detections_into_the_timeline() {
    let records = parse("standard.csv", &fixture("standard.csv")).records;
    let first = &records[0];
    assert_eq!(first.namespace(), NAMESPACE);
    assert!(matches!(first.locator(), Locator::Line(2)));
    let levels: Vec<String> = records.iter().filter_map(|r| text(r, "Level")).collect();
    assert!(levels.iter().any(|l| l == "high"));
    assert!(levels
        .iter()
        .all(|l| ["informational", "low", "medium", "high", "critical"].contains(&l.as_str())));
    assert!(!levels.iter().any(|l| l == "info" || l == "med"));
    let logon = records
        .iter()
        .find(|r| r.facets.event_code == Some(4648))
        .expect("an explicit logon");
    assert_eq!(logon.facets.user_name.as_deref(), Some("test10"));
    assert_eq!(logon.facets.host_name.as_deref(), Some("FS03.offsec.lan"));
    assert!(logon.summary.starts_with(
        "Hayabusa high: Explicit Logon Attempt (Susp Proc) - Possible Mimikatz PrivEsc · 4648"
    ));
    assert!(text(logon, "RuleID").is_some());
}

#[test]
fn refuses_timestamps_it_would_have_to_guess() {
    let csv = "\"Timestamp\",\"RuleTitle\",\"Level\",\"Computer\",\"Channel\",\"EventID\",\"RecordID\",\"Details\"\n\
               \"22-02-2022 22:00:00.123 +02:00\",\"X\",\"high\",\"WS\",\"Sec\",4624,1,\"-\"\n";
    let output = parse("eu.csv", csv.as_bytes());
    assert!(output.records.is_empty());
    assert!(output.skipped[0].reason.contains("-O"));
}
