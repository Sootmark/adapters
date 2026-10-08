//! The `$I30` adapter on a folder's index written for these tests
//! (`tests/fixtures/i30/`, see its NOTICE): recognition, the names the
//! folder lists, and the deleted ones recovered from slack.

use std::io::Read;

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, Value};
use sootmark_adapters::indx::{I30Adapter, NAMESPACE};

fn index() -> Vec<u8> {
    let compressed = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/i30/docs_I30.bin.gz"
    ))
    .unwrap();
    let mut data = Vec::new();
    common::gzip::Decoder::new(compressed.as_slice())
        .read_to_end(&mut data)
        .unwrap();
    data
}

#[test]
fn listed_and_deleted_names() {
    let data = index();
    let name = "C/docs/$I30";
    assert_eq!(I30Adapter.probe(name, &data[..64]), Confidence::Certain);
    assert_eq!(
        I30Adapter.probe("C/docs/a.bin", &data[..64]),
        Confidence::No
    );
    assert_conforms(&I30Adapter, name, &data);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    I30Adapter.parse(&input, &mut sink).unwrap();
    assert!(sink.records.iter().all(|r| r.namespace() == NAMESPACE));
    let names = |in_slack: bool| -> Vec<String> {
        sink.records
            .iter()
            .filter(|r| r.fields.get("InSlack") == Some(&Value::Bool(in_slack)))
            .filter_map(|r| r.facets.file_path.clone())
            .collect()
    };
    let listed = names(false);
    let slack = names(true);
    assert_eq!(listed.len(), 260, "{listed:#?}");
    assert!(listed.contains(&"C/docs/report_001.txt".to_owned()));
    assert!(!listed.contains(&"C/docs/report_050.txt".to_owned()));
    for deleted in (50..70).chain(200..220) {
        let path = format!("C/docs/report_{deleted:03}.txt");
        assert!(slack.contains(&path), "{path} not in slack: {slack:#?}");
    }
    assert!(sink.records.iter().all(|r| !r.times.is_empty()));
}
