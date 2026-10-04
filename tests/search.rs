//! The Windows Search adapter on plaso's `Windows.edb` (Apache-2.0, a
//! Windows 7 index, `tests/fixtures/search/`, stored gzip-compressed): the
//! contract, recognition, indexed items and unindexed gathered entries;
//! and on five items of SIDR's `Windows.db` (Apache-2.0, a Windows 11
//! index, same folder, see its `NOTICE`): files, a link with its summary,
//! a favourite, and an activity of the Timeline.

use std::io::Read;

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, TimeKind, Value};
use sootmark_adapters::search::{SearchAdapter, GATHERED, ITEMS};

#[test]
fn items_and_gathered_entries() {
    let compressed = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/search/Windows.edb.gz"
    ))
    .unwrap();
    let mut data = Vec::new();
    common::gzip::Decoder::new(compressed.as_slice())
        .read_to_end(&mut data)
        .unwrap();
    let path = "C/ProgramData/Microsoft/Search/Data/Applications/Windows/Windows.edb";
    assert_eq!(
        SearchAdapter.probe(path, &data[..4096]),
        Confidence::Certain
    );
    assert_eq!(
        SearchAdapter.probe("SRUDB.dat", &data[..4096]),
        Confidence::No
    );
    assert_conforms(&SearchAdapter, path, &data);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name: path,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    SearchAdapter.parse(&input, &mut sink).unwrap();
    let items = sink
        .records
        .iter()
        .filter(|r| r.namespace() == ITEMS)
        .count();
    let gathered = sink
        .records
        .iter()
        .filter(|r| r.namespace() == GATHERED)
        .count();
    assert_eq!((items, gathered), (322, 17));
    let summarised = sink
        .records
        .iter()
        .filter(|r| r.fields.contains_key("Summary"))
        .count();
    assert_eq!(summarised, 81);
    assert!(sink.records.iter().any(|r| {
        r.summary.starts_with("Indexed ") && matches!(r.fields.get("Size"), Some(Value::UInt(_)))
    }));
}

#[test]
fn windows_11_items_and_an_activity() {
    let data = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/search/Windows.db"
    ))
    .unwrap();
    let path = "C/ProgramData/Microsoft/Search/Data/Applications/Windows/Windows.db";
    assert_eq!(SearchAdapter.probe(path, &data[..100]), Confidence::Certain);
    assert_eq!(SearchAdapter.probe("History", &data[..100]), Confidence::No);
    assert_conforms(&SearchAdapter, path, &data);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name: path,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    SearchAdapter
        .parse_with_log(&input, &[], &mut sink)
        .unwrap();
    assert!(sink.skipped.is_empty(), "{:?}", sink.skipped);
    let summaries: Vec<&str> = sink.records.iter().map(|r| r.summary.as_str()).collect();
    assert_eq!(
        summaries,
        [
            r"Indexed C:\ProgramData\Microsoft\Windows\Start Menu",
            r"Indexed C:\Users",
            "Activity in notepad++.exe: New-beacon.xml",
            r"Indexed C:\Users\Public\Public Desktop\Microsoft Edge.lnk: Browse the web",
            r"Indexed C:\Users\fisft\Favorites\Bing.url",
        ]
    );
    let activity = &sink.records[2];
    assert_eq!(
        activity.facets.user_sid.as_deref(),
        Some("S-1-5-21-4268361623-692440835-3372367631-1001")
    );
    let start = activity
        .times
        .iter()
        .find(|t| t.kind == TimeKind::FirstSeen)
        .unwrap();
    assert_eq!(
        start.ts.to_iso8601().as_deref(),
        Some("2023-01-31T02:42:42.0000000Z")
    );
    assert!(matches!(
        activity.fields.get("ContentUri"),
        Some(Value::Text(uri)) if uri.starts_with("file:///C:/Users/Public/malware/New-beacon.xml")
    ));
    let favourite = &sink.records[4];
    assert_eq!(
        favourite.facets.user_name.as_deref(),
        Some(r"DESKTOP-O47KVAD\fisft")
    );
}
