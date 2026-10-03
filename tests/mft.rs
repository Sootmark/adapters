//! The `$MFT` adapter on loose MFTs from the `disk` crate's synthetic
//! volumes (`tests/fixtures/mft/`, zlib-compressed): the contract, paths
//! with the drive, deleted and orphaned files, `Zone.Identifier`, and a
//! timestomped file flagged.

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, TimeKind, Value};
use sootmark_adapters::mft::{MftAdapter, NAMESPACE};

fn read(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/tests/fixtures/mft/{name}.zlib",
        env!("CARGO_MANIFEST_DIR")
    );
    common::deflate::zlib_decompress(&std::fs::read(path).unwrap(), 64 << 20).unwrap()
}

fn parse(fixture: &str, name: &str) -> Collected {
    let data = read(fixture);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    MftAdapter.parse(&input, &mut sink).expect("records");
    sink
}

fn by_path<'r>(records: &'r [model::Record], path: &str) -> &'r model::Record {
    records
        .iter()
        .find(|r| r.facets.file_path.as_deref() == Some(path))
        .unwrap_or_else(|| panic!("{path}"))
}

#[test]
fn conforms_and_probes() {
    for fixture in ["fin-wks-07.mft", "deleted.mft"] {
        assert_conforms(&MftAdapter, "C/$MFT", &read(fixture));
    }
    let data = read("fin-wks-07.mft");
    assert_eq!(MftAdapter.probe("C/$MFT", &data), Confidence::Certain);
    assert_eq!(MftAdapter.probe("C/$MFT", b"not one"), Confidence::No);
    assert_eq!(MftAdapter.probe("C/notes.txt", &data), Confidence::No);
}

#[test]
fn files_with_their_drive_times_and_flags() {
    let collected = parse("fin-wks-07.mft", "WS07/C/$MFT");
    assert!(collected.skipped.is_empty(), "{:?}", collected.skipped);
    let records = &collected.records;
    assert_eq!(records[0].namespace(), NAMESPACE);

    // Its $STANDARD_INFORMATION times rolled back to 2019, in whole
    // seconds; its $FILE_NAME creation is the real one.
    let stomped = by_path(records, r"C:\ProgramData\Intel\m64.exe");
    assert_eq!(
        stomped.summary,
        r"File C:\ProgramData\Intel\m64.exe (possible timestomping: created before its name was, whole-second creation time)"
    );
    let time = |field: &str| {
        stomped
            .times
            .iter()
            .find(|t| t.field == field)
            .map(|t| (t.kind, t.ts.to_iso8601().unwrap()))
    };
    assert_eq!(
        time("si_created"),
        Some((TimeKind::Created, "2019-03-18T04:12:00.0000000Z".to_owned()))
    );
    assert_eq!(
        time("fn_created"),
        Some((TimeKind::Created, "2026-09-14T10:07:31.5261049Z".to_owned()))
    );
    assert_eq!(stomped.fields.get("Size"), Some(&Value::UInt(9216)));

    // A download, with where it came from.
    let download = by_path(records, r"C:\Users\svc_backup\Downloads\tools.zip");
    assert!(matches!(
        download.fields.get("ZoneIdentifier"),
        Some(Value::Text(zone)) if zone.starts_with("[ZoneTransfer]")
    ));
    assert_eq!(
        download.fields.get("Streams"),
        Some(&Value::from("Zone.Identifier"))
    );
    assert!(download.fields.get("Timestomp").is_none());

    assert!(records
        .iter()
        .any(|r| r.summary.starts_with("Deleted file ")
            && r.fields.get("InUse") == Some(&Value::Bool(false))));
}

#[test]
fn orphans_and_no_drive() {
    let records = parse("deleted.mft", "$MFT").records;
    let lost = by_path(&records, r"\$OrphanFiles\lost.txt");
    assert_eq!(lost.fields.get("Orphan"), Some(&Value::Bool(true)));
    by_path(&records, r"\Users\alice\report.txt");
}
