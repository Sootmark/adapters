//! The Velociraptor importer on real 0.77.2 `artifacts collect` results,
//! cross-checked against other tools' readings of the same artifacts:
//!
//! - `Lnk`, `RecycleBin`, `NTFS.MFT`: the synthetic FIN-WKS-07 artifacts
//!   (paths replaced), against `MFTECmd` and `RBCmd`;
//! - `Prefetch`: the open prefetch files (`tests/fixtures/prefetch/`),
//!   against `PECmd`;
//! - `SRUM`: plaso's test `SRUDB.dat` (Apache-2.0), the first rows of each
//!   table;
//! - `EvtxHunter`: two logs of EVTX-to-MITRE-Attack (CC0,
//!   `tests/fixtures/cc0/`), against the native EVTX parser.

use std::collections::BTreeSet;

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Input};
use model::{EvidenceId, Namespace, Record, TimeKind, Value};
use sootmark_adapters::evtx::EvtxAdapter;
use sootmark_adapters::ez::EzAdapter;
use sootmark_adapters::velociraptor::VelociraptorAdapter;

fn root() -> String {
    format!("{}/tests/fixtures", env!("CARGO_MANIFEST_DIR"))
}

fn results(dir: &str, file: &str) -> Option<(String, Vec<u8>)> {
    let bytes = std::fs::read(format!("{}/{dir}/results/{file}", root())).ok()?;
    Some((format!("results/{file}"), bytes))
}

fn parse_with(adapter: &dyn Adapter, name: &str, bytes: &[u8]) -> Vec<Record> {
    let input = Input {
        evidence: EvidenceId::of_content(bytes),
        name,
        data: bytes,
        modified: None,
    };
    let mut sink = Collected::default();
    adapter.parse(&input, &mut sink).expect("parses");
    assert!(sink.skipped.is_empty(), "{name}: {:?}", sink.skipped);
    sink.records
}

fn velociraptor(file: &str) -> Vec<Record> {
    let (name, bytes) = results("velociraptor", file).expect("committed fixture");
    assert_conforms(&VelociraptorAdapter, &name, &bytes);
    parse_with(&VelociraptorAdapter, &name, &bytes)
}

fn ez(file: &str) -> Vec<Record> {
    let bytes = std::fs::read(format!("{}/ez/20260914103000_{file}", root())).unwrap();
    parse_with(&EzAdapter, file, &bytes)
}

fn text(record: &Record, field: &str) -> String {
    match record.fields.get(field) {
        Some(Value::Text(t)) => t.clone(),
        Some(Value::Int(n)) => n.to_string(),
        Some(Value::UInt(n)) => n.to_string(),
        other => panic!("{field}: {other:?}"),
    }
}

fn seconds(record: &Record, kind: TimeKind) -> BTreeSet<String> {
    record
        .times
        .iter()
        .filter(|t| t.kind == kind)
        .map(|t| t.ts.to_iso8601().unwrap()[..19].to_owned())
        .collect()
}

#[test]
fn imports_known_and_unknown_artifacts() {
    for (file, namespace, rows) in [
        (
            "Windows.Forensics.Prefetch.json",
            "velociraptor.prefetch",
            62,
        ),
        ("Windows.Forensics.Lnk.json", "velociraptor.lnk", 6),
        (
            "Windows.Forensics.RecycleBin.json",
            "velociraptor.recyclebin",
            5,
        ),
        ("Windows.NTFS.MFT.json", "velociraptor.mft", 69),
        (
            "Windows.Forensics.SRUM%2FApplication Resource Usage.json",
            "velociraptor.srum",
            200,
        ),
        (
            "Windows.Forensics.SRUM%2FNetwork Usage.json",
            "velociraptor.srum",
            200,
        ),
        (
            "Windows.Forensics.SRUM%2FNetwork Connections.json",
            "velociraptor.srum",
            60,
        ),
        (
            "Windows.Forensics.SRUM%2FUpload.json",
            "velociraptor.result",
            1,
        ),
    ] {
        let records = velociraptor(file);
        assert_eq!(records.len(), rows, "{file}");
        assert!(
            records
                .iter()
                .all(|r| r.namespace() == Namespace::new(namespace)),
            "{file}"
        );
    }
    // An artifact without a mapping: kept, with its fields, untimed here.
    let upload = &velociraptor("Windows.Forensics.SRUM%2FUpload.json")[0];
    assert!(upload.times.is_empty());
    assert_eq!(text(upload, "Artifact"), "Windows.Forensics.SRUM/Upload");
    assert_eq!(text(upload, "Upload_sha256").len(), 64);

    let srum = velociraptor("Windows.Forensics.SRUM%2FApplication Resource Usage.json");
    assert!(srum
        .iter()
        .all(|r| r.times.len() == 1 && r.times[0].kind == TimeKind::Logged));
    assert!(srum.iter().any(|r| r
        .facets
        .process_path
        .as_deref()
        .is_some_and(|p| p.ends_with(r"\svchost.exe"))));

    let lnk = velociraptor("Windows.Forensics.Lnk.json");
    assert!(lnk
        .iter()
        .any(|r| r.facets.file_path.as_deref() == Some(r"C:\Users\Public\rclone.exe")));
}

/// Velociraptor and `PECmd` read the same prefetch files: same run times.
#[test]
fn prefetch_runs_agree_with_pecmd() {
    let ours = velociraptor("Windows.Forensics.Prefetch.json");
    let pecmd = ez("PECmd_Output.csv");
    assert_eq!(ours.len(), pecmd.len());
    for record in &ours {
        // By path: two of the files share a name and a hash.
        let os_path = text(record, "OSPath");
        let path = os_path.trim_start_matches("/triage/prefetch/");
        let theirs = pecmd
            .iter()
            .find(|r| text(r, "SourceFilename").replace('\\', "/").ends_with(path))
            .expect("same file in PECmd");
        let hash = text(record, "Hash").trim_start_matches("0X").to_owned();
        assert_eq!(hash, text(theirs, "Hash"), "{path}");
        assert_eq!(
            seconds(record, TimeKind::Executed),
            seconds(theirs, TimeKind::Executed),
            "{path}"
        );
    }
}

/// Velociraptor and `MFTECmd` read the same `$MFT`: same entries, same times.
#[test]
fn mft_agrees_with_mftecmd() {
    let ours = velociraptor("Windows.NTFS.MFT.json");
    let mftecmd = ez("MFTECmd_$MFT_Output.csv");
    for record in &ours {
        let entry = text(record, "EntryNumber");
        let theirs = mftecmd
            .iter()
            .find(|r| text(r, "EntryNumber") == entry)
            .expect("same entry");
        for kind in [
            TimeKind::Created,
            TimeKind::Modified,
            TimeKind::MetadataChanged,
            TimeKind::Accessed,
        ] {
            assert_eq!(
                seconds(record, kind),
                seconds(theirs, kind),
                "entry {entry} {kind:?}"
            );
        }
    }
}

/// Velociraptor and `RBCmd` read the same `$I` files: same deletions.
#[test]
fn recycle_bin_agrees_with_rbcmd() {
    let deletions = |records: &[Record]| -> BTreeSet<(String, String)> {
        records
            .iter()
            .map(|r| {
                (
                    r.facets.file_path.clone().unwrap(),
                    seconds(r, TimeKind::Deleted).into_iter().next().unwrap(),
                )
            })
            .collect()
    };
    assert_eq!(
        deletions(&velociraptor("Windows.Forensics.RecycleBin.json")),
        deletions(&ez("RBCmd_Output.csv"))
    );
}

/// Every event Velociraptor's `EvtxHunter` returned is one the native parser
/// read, at the same second, and the other way round.
#[test]
fn evtx_rows_are_native_events() {
    let hunted = velociraptor("Windows.EventLogs.EvtxHunter.json");
    let mut native = Vec::new();
    for name in [
        "ID4624-Mimikatz Pass the hash.evtx",
        "ID4648-4624-RunAsCS login.evtx",
    ] {
        let log = std::fs::read(format!("{}/cc0/{name}", root())).unwrap();
        native.extend(parse_with(&EvtxAdapter, name, &log));
    }
    let key = |r: &Record| {
        (
            text(r, "EventRecordID"),
            seconds(r, TimeKind::Logged).into_iter().next().unwrap(),
        )
    };
    let known: BTreeSet<(String, String)> = native.iter().map(key).collect();
    let found: BTreeSet<(String, String)> = hunted.iter().map(key).collect();
    assert_eq!(hunted.len(), 14);
    assert_eq!(found, known);
}
