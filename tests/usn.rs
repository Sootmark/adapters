//! The USN journal adapter on plaso's `UsnJrnl.raw` (Apache-2.0,
//! `tests/fixtures/usn/`): the contract, and each change with its name,
//! reasons and MFT references, as The Sleuth Kit's `usnjls` reads them.

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, TimeKind, Value};
use sootmark_adapters::usn::{UsnAdapter, NAMESPACE};

fn read() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/usn/UsnJrnl.raw"
    ))
    .unwrap()
}

fn parse() -> Collected {
    let data = read();
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name: "C/$Extend/$UsnJrnl:$J",
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    UsnAdapter.parse(&input, &mut sink).expect("changes");
    sink
}

#[test]
fn conforms_and_probes() {
    assert_conforms(&UsnAdapter, "C/$Extend/$J", &read());
    for name in [
        "C/$Extend/$J",
        "C/$Extend/$UsnJrnl:$J",
        "uploads/ntfs/%5C%5C.%5CC%3A/$Extend/$UsnJrnl%3A$J",
    ] {
        assert_eq!(
            UsnAdapter.probe(name, &[0; 64]),
            Confidence::Certain,
            "{name}"
        );
    }
    assert_eq!(UsnAdapter.probe("C/notes.txt", &read()), Confidence::No);
}

#[test]
fn changes_with_names_reasons_and_references() {
    let collected = parse();
    assert!(collected.skipped.is_empty(), "{:?}", collected.skipped);
    let records = collected.records;
    assert_eq!(records.len(), 19, "as plaso and libfsntfs count them");
    let first = &records[0];
    assert_eq!(first.namespace(), NAMESPACE);
    assert_eq!(first.times[0].kind, TimeKind::Logged);
    assert_eq!(
        first.times[0].ts.to_iso8601().unwrap(),
        "2015-11-30T21:15:27.2031250Z"
    );
    assert_eq!(
        first.fields.get("Reasons"),
        Some(&Value::from("FILE_CREATE"))
    );
    assert_eq!(first.fields.get("File"), Some(&Value::from("30-1")));
    assert_eq!(first.fields.get("ParentRecord"), Some(&Value::UInt(5)));
    let name = first.facets.file_path.clone().unwrap();
    assert_eq!(first.summary, format!("{name}: file create"));
}
