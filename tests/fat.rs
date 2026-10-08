//! The FAT directory adapter on directories written for these tests
//! (`tests/fixtures/fat/`, see its NOTICE): the entries each lists, with
//! their sizes and times as The Sleuth Kit reads them, wall-clock on FAT
//! and UTC on exFAT.

use common::time::{Semantic, Ts};
use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, Record, TimeKind, Value};
use sootmark_adapters::fat::{FatDirectoryAdapter, NAMESPACE};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/fat/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

/// The records of the directory stream `fixture`, listed as `name`.
fn records(fixture_name: &str, name: &str) -> Vec<Record> {
    let data = fixture(fixture_name);
    assert_eq!(FatDirectoryAdapter.probe(name, &data), Confidence::Certain);
    assert_conforms(&FatDirectoryAdapter, name, &data);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    FatDirectoryAdapter.parse(&input, &mut sink).unwrap();
    assert!(sink.skipped.is_empty());
    assert!(sink.records.iter().all(|r| r.namespace() == NAMESPACE));
    sink.records
}

fn paths(records: &[Record]) -> Vec<&str> {
    records
        .iter()
        .filter_map(|r| r.facets.file_path.as_deref())
        .collect()
}

fn find<'a>(records: &'a [Record], path: &str) -> &'a Record {
    records
        .iter()
        .find(|r| r.facets.file_path.as_deref() == Some(path))
        .unwrap_or_else(|| panic!("{path} listed"))
}

fn time(record: &Record, kind: TimeKind) -> Ts {
    record
        .times
        .iter()
        .find(|t| t.kind == kind)
        .map(|t| t.ts)
        .unwrap()
}

fn iso(record: &Record, kind: TimeKind) -> String {
    time(record, kind).to_iso8601().unwrap()
}

#[test]
fn a_fat_root_lists_its_files_and_folders() {
    let records = records("fat32-root.bin", "vol0/$FAT_DIRECTORY");
    // Neither the volume label nor the deleted file.
    assert_eq!(
        paths(&records),
        [
            "vol0/Folder A",
            "vol0/Empty Folder",
            "vol0/README.TXT",
            "vol0/Long Name Document.docx",
            "vol0/résumé été.txt",
        ]
    );
    let readme = find(&records, "vol0/README.TXT");
    assert_eq!(readme.summary, "File vol0/README.TXT");
    assert_eq!(readme.fields.get("Size"), Some(&Value::UInt(7)));
    assert_eq!(readme.fields.get("IsFolder"), Some(&Value::Bool(false)));
    // Touched to 06:07:09: FAT keeps even seconds, and a date for access.
    assert_eq!(
        iso(readme, TimeKind::Modified),
        "2023-04-05T06:07:08.0000000"
    );
    assert_eq!(
        iso(readme, TimeKind::Accessed),
        "2022-01-02T00:00:00.0000000"
    );
    assert_eq!(
        time(readme, TimeKind::Modified).semantic(),
        Semantic::LocalUnknownZone
    );
    let folder = find(&records, "vol0/Folder A");
    assert_eq!(folder.summary, "Folder vol0/Folder A");
    assert_eq!(
        iso(folder, TimeKind::Modified),
        "2019-07-04T17:45:30.0000000"
    );
}

#[test]
fn a_fat_folder_leaves_out_its_dot_entries() {
    let records = records("fat32-folder-a.bin", "vol0/Folder A/$FAT_DIRECTORY");
    assert_eq!(
        paths(&records),
        ["vol0/Folder A/nested", "vol0/Folder A/empty.bin"]
    );
    let empty = find(&records, "vol0/Folder A/empty.bin");
    assert_eq!(
        empty.fields.get("Folder"),
        Some(&Value::from("vol0/Folder A"))
    );
    assert_eq!(empty.fields.get("Size"), Some(&Value::UInt(0)));
    assert_eq!(
        iso(empty, TimeKind::Modified),
        "1999-09-09T09:09:08.0000000"
    );
}

#[test]
fn exfat_times_are_utc() {
    let records = records("exfat-root.bin", "vol2/$EXFAT_DIRECTORY");
    assert_eq!(records.len(), 5);
    let readme = find(&records, "vol2/README.TXT");
    assert_eq!(
        iso(readme, TimeKind::Modified),
        "2023-04-05T06:07:09.0000000Z"
    );
    assert_eq!(
        iso(readme, TimeKind::Accessed),
        "2022-01-02T13:14:14.0000000Z"
    );
    assert_eq!(time(readme, TimeKind::Accessed).semantic(), Semantic::Utc);
    // exFAT records a folder's size.
    let folder = find(&records, "vol2/Folder A");
    assert_eq!(folder.fields.get("Size"), Some(&Value::UInt(4096)));
}
