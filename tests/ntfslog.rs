//! The `$LogFile` adapter on go-ntfs's test volume's log (Apache-2.0,
//! `tests/fixtures/logfile/`, see its NOTICE): recognition, and the
//! changes that name files or rewrite their times.

use std::io::Read;

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::EvidenceId;
use sootmark_adapters::ntfslog::{LogFileAdapter, NAMESPACE};

fn log() -> Vec<u8> {
    let compressed = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/logfile/LogFile.gz"
    ))
    .unwrap();
    let mut data = Vec::new();
    common::gzip::Decoder::new(compressed.as_slice())
        .read_to_end(&mut data)
        .unwrap();
    data
}

#[test]
fn file_names_and_times() {
    let data = log();
    let name = "C/$LogFile";
    assert_eq!(LogFileAdapter.probe(name, &data[..64]), Confidence::Certain);
    assert_eq!(
        LogFileAdapter.probe("notes.txt", &data[..64]),
        Confidence::No
    );
    assert_conforms(&LogFileAdapter, name, &data);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    LogFileAdapter.parse(&input, &mut sink).unwrap();
    assert!(!sink.records.is_empty());
    assert!(sink.records.iter().all(|r| r.namespace() == NAMESPACE));
    let summaries: Vec<&str> = sink.records.iter().map(|r| r.summary.as_str()).collect();
    assert!(
        summaries
            .iter()
            .any(|s| s.starts_with("$LogFile: deleted.bin name removed")),
        "{summaries:#?}"
    );
    assert!(summaries
        .iter()
        .any(|s| s.starts_with("$LogFile: Folder A")));
    assert!(sink
        .records
        .iter()
        .any(|r| r.fields.contains_key("NewModified")));
}
