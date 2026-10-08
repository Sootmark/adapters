//! Property lists no named artifact reads, on every file of plaso's
//! `test_data/plist/` (`tests/fixtures/plist-default/`, see its NOTICE),
//! against what plaso's `plist_default` plugin reads from them
//! (`tests/oracle/plaso-plist-keys.tsv`, see `tests/oracle/README`): the
//! same keys, under the same roots, with the same dates.
//!
//! plaso ran with its named plist plugins off, so its default plugin read
//! every file; here each file is read under a name no named artifact
//! claims.

use std::fs;
use std::path::Path;

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, Record, Value};
use sootmark_adapters::macos::{MacosAdapter, PLIST};

const FIXTURES: &str = "tests/fixtures/plist-default";

/// What each file is read as: a name no named artifact claims.
const UNCLAIMED: &str = "Users/analyst/Desktop/copy.bin";

/// As the oracle writes text: `%`, and control characters, as `%XX`.
fn escape(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c == '%' || c.is_ascii_control() {
                format!("%{:02X}", u32::from(c))
            } else {
                c.to_string()
            }
        })
        .collect()
}

fn text<'r>(record: &'r Record, field: &str) -> &'r str {
    match record.fields.get(field) {
        Some(Value::Text(text)) => text,
        other => panic!("{field}: {other:?}"),
    }
}

/// A record as the oracle's line: file, root, key, microseconds.
fn line(file: &str, record: &Record) -> String {
    let ticks = record.times[0].ts.ticks().expect("a date");
    assert_eq!(
        ticks % 10,
        0,
        "{file}: a date finer than plaso's microseconds"
    );
    format!(
        "{file}\t{}\t{}\t{}",
        escape(text(record, "Root")),
        escape(text(record, "Key")),
        ticks / 10
    )
}

#[test]
fn every_dated_key_as_plaso_reads_it() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURES);
    let mut files: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|name| Path::new(name).extension().is_some_and(|e| e == "plist"))
        .collect();
    files.sort();
    assert_eq!(files.len(), 27);
    let mut ours = Vec::new();
    for file in &files {
        let data = fs::read(dir.join(file)).unwrap();
        assert_eq!(
            MacosAdapter.probe(UNCLAIMED, &data),
            Confidence::Maybe,
            "{file}"
        );
        assert_conforms(&MacosAdapter, UNCLAIMED, &data);
        let input = Input {
            evidence: EvidenceId::of_content(&data),
            name: UNCLAIMED,
            data: &data,
            modified: None,
        };
        let mut sink = Collected::default();
        // truncated.plist's binary trailer points outside the file, and
        // empty.plist holds no value: nothing to read, for plaso too.
        if MacosAdapter.parse(&input, &mut sink).is_err() {
            assert!(
                ["empty.plist", "truncated.plist"].contains(&file.as_str()),
                "{file}"
            );
            continue;
        }
        assert!(sink.skipped.is_empty(), "{file}: {:?}", sink.skipped);
        for record in &sink.records {
            assert_eq!(record.namespace(), PLIST);
            ours.push(line(file, record));
        }
    }
    ours.sort();
    let oracle = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/oracle/plaso-plist-keys.tsv"),
    )
    .unwrap();
    let theirs: Vec<&str> = oracle.lines().collect();
    // plistlib refuses the year 0 of this file's applicationDate, and plaso
    // loses the file with it; read as CoreFoundation reads it, its dates
    // are three more keys.
    let (beyond, ours): (Vec<String>, Vec<String>) = ours
        .into_iter()
        .partition(|line| line.starts_with("com.apple.security.KCN.plist\t"));
    assert_eq!(
        beyond,
        [
            "com.apple.security.KCN.plist\t\tapplicationDate\t-62135769600000000",
            "com.apple.security.KCN.plist\t\tlastWritten\t1568659364000000",
            "com.apple.security.KCN.plist\t\tpendingApplicationReminder\t64092211200000000",
        ]
    );
    assert_eq!(ours, theirs);
    eprintln!("{} dated keys match plaso", ours.len());
}

#[test]
fn a_dated_key_becomes_a_record() {
    let file = "com.apple.bluetooth.plist";
    let data = fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(FIXTURES)
            .join(file),
    )
    .unwrap();
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name: UNCLAIMED,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    MacosAdapter.parse(&input, &mut sink).unwrap();
    let record = sink
        .records
        .iter()
        .find(|r| text(r, "Root") == "/DeviceCache/44-00-00-00-00-03")
        .unwrap();
    assert_eq!(text(record, "Key"), "LastInquiryUpdate");
    assert_eq!(
        text(record, "Path"),
        "/DeviceCache/44-00-00-00-00-03/LastInquiryUpdate"
    );
    assert_eq!(
        record.times[0].field,
        "/DeviceCache/44-00-00-00-00-03/LastInquiryUpdate"
    );
    assert_eq!(
        record.times[0].ts.to_string(),
        "2011-03-25T00:16:41.4147660Z"
    );
    assert_eq!(record.facets.user_name.as_deref(), Some("analyst"));
    assert_eq!(
        record.summary,
        "Property list date /DeviceCache/44-00-00-00-00-03/LastInquiryUpdate"
    );
}

#[test]
fn only_property_lists_are_probed() {
    let probe = |head: &[u8]| MacosAdapter.probe("Users/analyst/notes.txt", head);
    assert_eq!(probe(b"bplist00\xd1\x01\x02"), Confidence::Maybe);
    assert_eq!(
        probe(b"\xEF\xBB\xBF  <?xml version=\"1.0\"?>\n<plist version=\"1.0\">"),
        Confidence::Maybe
    );
    assert_eq!(probe(b"<?xml version=\"1.0\"?>\n<svg/>"), Confidence::No);
    assert_eq!(probe(b"bplist15"), Confidence::No);
    assert_eq!(probe(b"plain text"), Confidence::No);
}
