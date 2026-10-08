//! The Office document adapter on plaso's `Document.doc` and
//! `Document.docx` (Apache-2.0, `tests/fixtures/office/`): recognition by
//! name and content, the contract, and one record per document.

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, Record, TimeKind, Value};
use sootmark_adapters::office::{OfficeAdapter, NAMESPACE};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/office/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn document(fixture_name: &str, path: &str) -> Record {
    let data = fixture(fixture_name);
    assert_eq!(
        OfficeAdapter.probe(path, &data),
        Confidence::Certain,
        "{path}"
    );
    assert_conforms(&OfficeAdapter, path, &data);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name: path,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    OfficeAdapter.parse(&input, &mut sink).unwrap();
    assert!(sink.skipped.is_empty(), "{:?}", sink.skipped);
    assert_eq!(sink.records.len(), 1);
    let record = sink.records.remove(0);
    assert_eq!(record.namespace(), NAMESPACE);
    record
}

#[test]
fn compound_file_properties() {
    let doc = document("Document.doc", r"C\Users\alice\Documents\Document.doc");
    assert_eq!(
        doc.summary,
        "Office document Document.doc \"Table of Context\" by DAVID NIDES, last saved by Nides (Microsoft Office Word)"
    );
    assert_eq!(doc.fields.get("Company"), Some(&Value::from("KPMG")));
    assert_eq!(doc.fields.get("Format"), Some(&Value::from("OLE")));
    assert_eq!(doc.facets.user_name.as_deref(), Some("Nides"));
    assert_eq!(
        doc.times.iter().map(|t| t.kind).collect::<Vec<_>>(),
        [TimeKind::Created, TimeKind::Modified]
    );
}

#[test]
fn package_properties() {
    let docx = document("Document.docx", "Users/alice/Documents/Document.docx");
    assert_eq!(docx.fields.get("Format"), Some(&Value::from("OOXML")));
    assert_eq!(docx.fields.get("Author"), Some(&Value::from("Nides")));
    assert_eq!(
        docx.fields.get("EditTimeSeconds"),
        Some(&Value::UInt(83_100))
    );
    assert_eq!(
        docx.fields.get("Template"),
        Some(&Value::from("Normal.dotm"))
    );
}

#[test]
fn only_office_names_and_signatures() {
    let doc = fixture("Document.doc");
    let docx = fixture("Document.docx");
    // The content must match the name's format.
    assert_eq!(OfficeAdapter.probe("a.docx", &doc), Confidence::No);
    assert_eq!(OfficeAdapter.probe("a.doc", &docx), Confidence::No);
    // A compound file or zip archive under another name isn't taken.
    assert_eq!(OfficeAdapter.probe("Thumbs.db", &doc), Confidence::No);
    assert_eq!(OfficeAdapter.probe("archive.zip", &docx), Confidence::No);
}
