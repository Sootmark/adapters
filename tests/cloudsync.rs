//! The cloudsync adapter on plaso's Dropbox and Google Drive test files
//! (Apache-2.0, `tests/fixtures/cloudsync/`, see its NOTICE): recognition,
//! the contract, and the synchronized changes, Drive's files and its sync
//! log as records.

use std::io::Read;

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, Namespace, Value};
use sootmark_adapters::cloudsync::{
    CloudSyncAdapter, DROPBOX_SYNC, GDRIVE_FILES, GDRIVE_LOCAL_FILES, GDRIVE_SYNC_LOG,
};

/// A fixture's content, decompressed when stored gzip-compressed.
fn fixture(name: &str) -> Vec<u8> {
    let stored = std::fs::read(format!(
        "{}/tests/fixtures/cloudsync/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    if !common::gzip::is_gzip(&stored) {
        return stored;
    }
    let mut data = Vec::new();
    common::gzip::Decoder::new(stored.as_slice())
        .read_to_end(&mut data)
        .unwrap();
    data
}

/// Recognised from its head, conforming, parsed without a skip, every
/// record in `namespace`.
fn collect(name: &str, path: &str, namespace: &[Namespace]) -> Collected {
    let data = fixture(name);
    let head = &data[..data.len().min(4096)];
    assert_eq!(
        CloudSyncAdapter.probe(path, head),
        Confidence::Certain,
        "{name}"
    );
    assert_conforms(&CloudSyncAdapter, path, &data);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name: path,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    CloudSyncAdapter.parse(&input, &mut sink).unwrap();
    assert!(sink.skipped.is_empty(), "{name}: {:?}", sink.skipped);
    assert!(sink
        .records
        .iter()
        .all(|r| namespace.contains(&r.namespace())));
    sink
}

#[test]
fn dropbox_sync_history() {
    let history = collect(
        "dropbox_sync_history.db",
        "home/useraa/.dropbox/instance1/sync_history.db",
        &[DROPBOX_SYNC],
    );
    // As plaso: six changes.
    assert_eq!(history.records.len(), 6);
    let first = &history.records[0];
    assert_eq!(
        first.summary,
        "Dropbox upload add /home/useraa/Dropbox/loc1/create_local.txt"
    );
    assert_eq!(
        first.facets.file_path.as_deref(),
        Some("/home/useraa/Dropbox/loc1/create_local.txt")
    );
    assert_eq!(first.facets.user_name.as_deref(), Some("useraa"));
    assert_eq!(first.fields.get("OtherUser"), Some(&Value::Bool(false)));
}

#[test]
fn drive_snapshot() {
    let snapshot = collect(
        "snapshot.db.gz",
        "Users/kiddi/AppData/Local/Google/Drive/user_default/snapshot.db",
        &[GDRIVE_FILES, GDRIVE_LOCAL_FILES],
    );
    let count = |namespace| {
        snapshot
            .records
            .iter()
            .filter(|r| r.namespace() == namespace)
            .count()
    };
    // Every entry, those without a modification time too (plaso leaves
    // out My Drive and the sync root).
    assert_eq!((count(GDRIVE_FILES), count(GDRIVE_LOCAL_FILES)), (11, 11));
    let local = snapshot
        .records
        .iter()
        .find(|r| r.namespace() == GDRIVE_LOCAL_FILES && r.fields.contains_key("Checksum"))
        .unwrap();
    assert!(matches!(
        local.facets.file_path.as_deref(),
        Some(path) if path.starts_with("/Users/kiddi/Google Drive/")
    ));
    assert_eq!(
        CloudSyncAdapter.probe(
            "Users/kiddi/AppData/Local/x/snapshot.db",
            b"SQLite format 3\0"
        ),
        Confidence::No
    );
}

#[test]
fn drive_sync_log() {
    let log = collect(
        "sync_log.log.gz",
        "Users/kiddi/AppData/Local/Google/Drive/user_default/sync_log.log",
        &[GDRIVE_SYNC_LOG],
    );
    // As plaso: 2,190 entries.
    assert_eq!(log.records.len(), 2190);
    let first = &log.records[0];
    assert_eq!(first.summary, "Google Drive INFO: OS: Windows/6.1-SP1");
    assert_eq!(first.facets.process_id, Some(2376));
    assert_eq!(
        CloudSyncAdapter.probe("Users/kiddi/notes/sync_log.log", b"not an entry\n"),
        Confidence::No
    );
}
