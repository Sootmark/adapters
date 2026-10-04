//! The browser adapter on the `browser` crate's synthetic databases
//! (`tests/fixtures/browser/`, laid out as in a home): the contract,
//! recognition, visits and downloads with the profile's owner.

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, Record, TimeKind, Value};
use sootmark_adapters::browser::{BrowserAdapter, NAMESPACE};

const CHROMIUM: &str = "home/alice/.config/chromium/Default/History";
const FIREFOX: &str = "home/alice/.mozilla/firefox/x.default/places.sqlite";

fn read(path: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/browser/{path}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn parse(path: &str) -> Collected {
    let data = read(path);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name: path,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    BrowserAdapter.parse(&input, &mut sink).expect("history");
    sink
}

fn field<'r>(record: &'r Record, name: &str) -> Option<&'r Value> {
    record.fields.get(name)
}

#[test]
fn conforms_and_probes() {
    for path in [CHROMIUM, FIREFOX] {
        assert_conforms(&BrowserAdapter, path, &read(path));
        assert_eq!(BrowserAdapter.probe(path, &read(path)), Confidence::Certain);
    }
    assert_eq!(
        BrowserAdapter.probe(CHROMIUM, b"not a database"),
        Confidence::No
    );
    assert_eq!(
        BrowserAdapter.probe("var/lib/wtmpdb/wtmp.db", b"SQLite format 3\0"),
        Confidence::No
    );
}

#[test]
fn chromium_visits_and_downloads() {
    let collected = parse(CHROMIUM);
    assert_eq!(collected.skipped.len(), 1, "a visit without its url row");
    let records = &collected.records;
    assert!(records.iter().all(|r| r.namespace() == NAMESPACE));
    assert!(records
        .iter()
        .all(|r| r.facets.user_name.as_deref() == Some("alice")));
    let first = &records[0];
    assert!(first
        .summary
        .starts_with("Visited https://example.com/ (Example Domain) via "));
    assert_eq!(field(first, "Domain"), Some(&Value::from("example.com")));
    assert_eq!(field(first, "Typed"), Some(&Value::Bool(true)));
    assert_eq!(first.times[0].kind, TimeKind::Logged);

    let setup = records
        .iter()
        .find(|r| field(r, "TargetPath") == Some(&Value::from("/srv/downloads/setup.exe")))
        .unwrap();
    assert_eq!(
        setup.summary,
        "Downloaded http://192.0.2.10/setup.exe to /srv/downloads/setup.exe (interrupted)"
    );
    assert_eq!(field(setup, "Domain"), Some(&Value::from("192.0.2.10")));
    assert_eq!(
        setup.facets.file_path.as_deref(),
        Some("/srv/downloads/setup.exe")
    );
}

#[test]
fn firefox_downloads() {
    let records = parse(FIREFOX).records;
    let download = records
        .iter()
        .find(|r| r.summary.starts_with("Downloaded "))
        .unwrap();
    assert_eq!(
        field(download, "Url"),
        Some(&Value::from("https://example.com/file.zip"))
    );
    assert_eq!(field(download, "Browser"), Some(&Value::from("firefox")));
}
