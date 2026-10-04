//! The Windows Search adapter on plaso's `Windows.edb` (Apache-2.0, a
//! Windows 7 index, `tests/fixtures/search/`, stored gzip-compressed): the
//! contract, recognition, indexed items and unindexed gathered entries.

use std::io::Read;

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, Value};
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
