//! The Windows Timeline adapter on plaso's `ActivitiesCache.db`
//! (Apache-2.0, `tests/fixtures/wintimeline/`, stored gzip-compressed):
//! the contract, recognition, activities.

use std::io::Read;

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, Value};
use sootmark_adapters::wintimeline::{TimelineAdapter, NAMESPACE};

#[test]
fn activities() {
    let compressed = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/wintimeline/ActivitiesCache.db.gz"
    ))
    .unwrap();
    let mut data = Vec::new();
    common::gzip::Decoder::new(compressed.as_slice())
        .read_to_end(&mut data)
        .unwrap();
    let path = r"C:\Users\alice\AppData\Local\ConnectedDevicesPlatform\L.alice\ActivitiesCache.db";
    assert_eq!(TimelineAdapter.probe(path, &data), Confidence::Certain);
    assert_conforms(&TimelineAdapter, path, &data);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name: path,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    TimelineAdapter.parse(&input, &mut sink).unwrap();
    let records = &sink.records;
    assert_eq!(records.len(), 112);
    assert!(records.iter().all(|r| r.namespace() == NAMESPACE));
    assert!(records
        .iter()
        .all(|r| r.facets.user_name.as_deref() == Some("alice")));
    let python = records
        .iter()
        .find(|r| {
            matches!(r.fields.get("App"), Some(Value::Text(app)) if app.eq_ignore_ascii_case(r"c:\python34\python.exe"))
                && r.fields.get("Type") == Some(&Value::from("UserEngaged"))
        })
        .unwrap();
    assert_eq!(python.fields.get("DurationSeconds"), Some(&Value::UInt(9)));
}
