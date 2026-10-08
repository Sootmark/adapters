//! The File History adapter on plaso's `Catalog1.edb` (Apache-2.0,
//! `tests/fixtures/filehistory/`, stored gzip-compressed): recognition,
//! the contract, files and folders, backup runs and protected folders.

use std::io::Read;

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, TimeKind, Value};
use sootmark_adapters::filehistory::{FileHistoryAdapter, BACKUPS, FILES, LIBRARIES};

const PATH: &str =
    r"C\Users\alice\AppData\Local\Microsoft\Windows\FileHistory\Configuration\Catalog1.edb";

fn catalog() -> Vec<u8> {
    let compressed = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/filehistory/Catalog1.edb.gz"
    ))
    .unwrap();
    let mut data = Vec::new();
    common::gzip::Decoder::new(compressed.as_slice())
        .read_to_end(&mut data)
        .unwrap();
    data
}

#[test]
fn files_runs_and_folders() {
    let data = catalog();
    assert_eq!(
        FileHistoryAdapter.probe(PATH, &data[..4096]),
        Confidence::Certain
    );
    assert_eq!(
        FileHistoryAdapter.probe("Windows.edb", &data[..4096]),
        Confidence::No
    );
    assert_conforms(&FileHistoryAdapter, PATH, &data);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name: PATH,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    FileHistoryAdapter.parse(&input, &mut sink).unwrap();
    assert!(sink.skipped.is_empty(), "{:?}", sink.skipped);
    let count = |namespace| {
        sink.records
            .iter()
            .filter(|r| r.namespace() == namespace)
            .count()
    };
    assert_eq!(count(FILES), 1373);
    assert_eq!(count(BACKUPS), 150);
    assert_eq!(count(LIBRARIES), 14);
    let photo = sink
        .records
        .iter()
        .find(|r| r.facets.file_path.as_deref() == Some(r"?PP\Pictures\WP_20130728_004.jpg"))
        .unwrap();
    assert_eq!(photo.facets.user_name.as_deref(), Some("alice"));
    assert_eq!(photo.fields.get("IsFolder"), Some(&Value::Bool(false)));
    let kinds: Vec<TimeKind> = photo.times.iter().map(|t| t.kind).collect();
    assert_eq!(
        kinds,
        [
            TimeKind::Created,
            TimeKind::Modified,
            TimeKind::FirstSeen,
            TimeKind::LastSeen
        ]
    );
    assert!(sink
        .records
        .iter()
        .any(|r| r.summary == r"File History protected folder: ?UP\Favorites"));
}
