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

/// plaso's `WebCacheV01.dat` (Apache-2.0, `tests/fixtures/webcache/`,
/// stored gzip-compressed): Internet Explorer visits with their account.
#[test]
fn webcache_visits() {
    let compressed = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/webcache/WebCacheV01.dat.gz"
    ))
    .unwrap();
    let mut data = Vec::new();
    std::io::Read::read_to_end(
        &mut common::gzip::Decoder::new(compressed.as_slice()),
        &mut data,
    )
    .unwrap();
    let path = "C/Users/test/AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.dat";
    assert_eq!(BrowserAdapter.probe(path, &data), Confidence::Certain);
    assert_conforms(&BrowserAdapter, path, &data);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name: path,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    BrowserAdapter.parse(&input, &mut sink).unwrap();
    assert_eq!(sink.records.len(), 113);
    let overview = sink
        .records
        .iter()
        .find(|r| {
            field(r, "Url")
                == Some(&Value::from(
                    "http://code.google.com/p/libyal/wiki/Overview",
                ))
        })
        .unwrap();
    assert_eq!(
        overview.summary,
        "Visited http://code.google.com/p/libyal/wiki/Overview"
    );
    assert_eq!(overview.facets.user_name.as_deref(), Some("test"));
    assert_eq!(
        field(overview, "Browser"),
        Some(&Value::from("internet explorer"))
    );
}

/// A Chromium-like history with a time range of visits cleared
/// (`tests/fixtures/browser-recovery/`): the deleted visits and pages come
/// back as records of their own, marked deleted, with where they were
/// found.
#[test]
fn deleted_visits_and_pages() {
    let data = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/browser-recovery/History"
    ))
    .unwrap();
    let path = "home/alice/.config/chromium/Default/History";
    assert_conforms(&BrowserAdapter, path, &data);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name: path,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    BrowserAdapter.parse(&input, &mut sink).unwrap();
    let deleted: Vec<_> = sink
        .records
        .iter()
        .filter(|r| field(r, "Deleted") == Some(&Value::Bool(true)))
        .collect();
    let visits = deleted
        .iter()
        .filter(|r| r.summary.starts_with("Deleted visit (recovered, "))
        .count();
    let pages = deleted
        .iter()
        .filter(|r| r.summary.starts_with("Deleted page (recovered, "))
        .count();
    assert_eq!((visits, pages), (61, 20));
    assert!(deleted
        .iter()
        .all(|r| field(r, "RecoveredFrom").is_some() && field(r, "Confidence").is_some()));
    // Live visits aren't marked.
    assert!(sink
        .records
        .iter()
        .any(|r| r.summary.starts_with("Visited ") && field(r, "Deleted").is_none()));
}

/// A Chromium history whose deleted visits survive only in its
/// write-ahead log: read with the log, they come back.
#[test]
fn deleted_visits_from_the_log() {
    let read_file = |name: &str| {
        std::fs::read(format!(
            "{}/tests/fixtures/browser-recovery/wal/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    };
    let (database, log) = (read_file("History"), read_file("History-wal"));
    let input = Input {
        evidence: EvidenceId::of_content(&database),
        name: "home/alice/.config/chromium/Default/History",
        data: &database,
        modified: None,
    };
    let deleted = |log: &[u8]| {
        let mut sink = Collected::default();
        BrowserAdapter
            .parse_with_log(&input, log, &mut sink)
            .unwrap();
        sink.records
            .iter()
            .filter(|r| field(r, "Deleted") == Some(&Value::Bool(true)))
            .count()
    };
    assert_eq!(deleted(&[]), 0);
    assert_eq!(deleted(&log), 8, "5 visits, 2 pages, 1 download");
}
