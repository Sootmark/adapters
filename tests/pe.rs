//! The PE adapter on plaso's test images (Apache-2.0, `tests/fixtures/pe/`):
//! the probe takes images only in folders users write to, and one record
//! per image with its compile time, kind and import hash.

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, TimeKind, Value};
use sootmark_adapters::pe::{PeAdapter, NAMESPACE};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/pe/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn collect(path: &str, data: &[u8]) -> Collected {
    assert_eq!(PeAdapter.probe(path, data), Confidence::Certain, "{path}");
    assert_conforms(&PeAdapter, path, data);
    let input = Input {
        evidence: EvidenceId::of_content(data),
        name: path,
        data,
        modified: None,
    };
    let mut sink = Collected::default();
    PeAdapter.parse(&input, &mut sink).unwrap();
    assert!(sink.skipped.is_empty(), "{:?}", sink.skipped);
    sink
}

#[test]
fn images_in_user_folders() {
    let exe = fixture("test_pe.exe");
    let sink = collect(r"C\Users\alice\Downloads\test_pe.exe", &exe);
    assert_eq!(sink.records.len(), 1);
    let record = &sink.records[0];
    assert_eq!(record.namespace(), NAMESPACE);
    assert_eq!(record.summary, "PE Executable (EXE): test_pe.exe");
    assert_eq!(record.times[0].kind, TimeKind::Created);
    assert_eq!(record.times[0].field, "Compiled");
    assert_eq!(record.facets.user_name.as_deref(), Some("alice"));
    assert_eq!(
        record.facets.file_path.as_deref(),
        Some(r"C\Users\alice\Downloads\test_pe.exe")
    );
    assert!(matches!(record.fields.get("Imphash"), Some(Value::Text(h)) if h.len() == 32));

    let driver = fixture("test_driver.sys");
    let sink = collect(r"C\Windows\Temp\test_driver.sys", &driver);
    assert_eq!(
        sink.records[0].fields.get("Kind"),
        Some(&Value::from("Driver (SYS)"))
    );
}

#[test]
fn installed_images_are_not_taken() {
    let exe = fixture("test_pe.exe");
    for path in [
        r"C\Windows\System32\test_pe.exe",
        r"C\Program Files\Vendor\test_pe.exe",
    ] {
        assert_eq!(PeAdapter.probe(path, &exe), Confidence::No, "{path}");
    }
    assert_eq!(
        PeAdapter.probe(r"C\Users\alice\notes.txt", b"MZ but no more"),
        Confidence::No
    );
}
