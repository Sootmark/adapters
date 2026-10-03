//! The Prefetch adapter on openly licensed files of every version
//! (`tests/fixtures/prefetch/`: Eric Zimmerman's test set, MIT, and
//! plaso's, Apache-2.0): the contract, and the same runs as the `PECmd`
//! import of those files; and a built file.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Input};
use model::{EvidenceId, Record, TimeKind, Value};
use sootmark_adapters::ez::EzAdapter;
use sootmark_adapters::prefetch::{PrefetchAdapter, NAMESPACE};

fn parse(adapter: &dyn Adapter, name: &str, bytes: &[u8]) -> Collected {
    let input = Input {
        evidence: EvidenceId::of_content(bytes),
        name,
        data: bytes,
        modified: None,
    };
    let mut sink = Collected::default();
    adapter.parse(&input, &mut sink).expect("parses");
    sink
}

/// Every open prefetch file, by its path under `tests/fixtures/prefetch/`.
fn open_files() -> Vec<(String, Vec<u8>)> {
    fn walk(dir: &Path, root: &Path, files: &mut Vec<(String, Vec<u8>)>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, root, files);
            } else if path.extension().is_some_and(|e| e == "pf") {
                let name = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                files.push((name, fs::read(&path).unwrap()));
            }
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/prefetch");
    let mut files = Vec::new();
    walk(&root, &root, &mut files);
    files.sort();
    files
}

fn executed(record: &Record) -> BTreeSet<String> {
    record
        .times
        .iter()
        .filter(|t| t.kind == TimeKind::Executed)
        .map(|t| t.ts.to_string().chars().take(19).collect())
        .collect()
}

#[test]
fn conforms_on_open_files() {
    for (name, bytes) in &open_files() {
        assert_conforms(&PrefetchAdapter, name, bytes);
    }
}

/// `PECmd` read the same files (its import is a committed fixture): the
/// native records carry the same runs, run count and executable.
#[test]
fn agrees_with_the_pecmd_import() {
    let files = open_files();
    let csv = fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/ez/20260914103000_PECmd_Output.csv"),
    )
    .unwrap();
    let imported = parse(&EzAdapter, "PECmd_Output.csv", &csv).records;
    assert_eq!(files.len(), imported.len());
    for (name, bytes) in &files {
        let output = parse(&PrefetchAdapter, name, bytes);
        assert!(output.skipped.is_empty(), "{name}: {:?}", output.skipped);
        let native = &output.records[0];
        assert_eq!(native.namespace(), NAMESPACE);
        // By path: two of the files share a name and a hash.
        let theirs = imported
            .iter()
            .find(|r| match r.fields.get("SourceFilename") {
                Some(Value::Text(source)) => source.replace('\\', "/").ends_with(name.as_str()),
                _ => false,
            })
            .unwrap_or_else(|| panic!("{name}: not in the PECmd import"));
        let Some(Value::Text(hash)) = native.fields.get("Hash") else {
            panic!("{name}: hash");
        };
        assert_eq!(
            Some(&Value::Text(hash.trim_start_matches('0').to_owned())),
            theirs.fields.get("Hash"),
            "{name}: hash"
        );
        assert_eq!(executed(native), executed(theirs), "{name}: runs");
        let (Some(Value::UInt(ours)), Some(Value::Text(theirs_count))) =
            (native.fields.get("RunCount"), theirs.fields.get("RunCount"))
        else {
            panic!("{name}: run counts");
        };
        assert_eq!(&ours.to_string(), theirs_count, "{name}: run count");
        let executable = native.facets.process_path.as_deref().unwrap();
        assert!(
            executable
                .to_ascii_uppercase()
                .ends_with(theirs.facets.process_path.as_deref().unwrap()),
            "{name}: {executable}"
        );
    }
}

/// A version 23 file, byte by byte: one run, one file, no volumes.
fn built() -> Vec<u8> {
    let path: Vec<u8> = r"\VOLUME{01}\TOOLS\RCLONE.EXE"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let (metrics, strings) = (84 + 156, 84 + 156 + 32);
    let mut data = vec![0_u8; strings];
    data[0..4].copy_from_slice(&23_u32.to_le_bytes());
    data[4..8].copy_from_slice(b"SCCA");
    let name: Vec<u8> = "RCLONE.EXE"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    data[16..16 + name.len()].copy_from_slice(&name);
    data[76..80].copy_from_slice(&0x0EE4_1A20_u32.to_le_bytes());
    data[84..88].copy_from_slice(&(metrics as u32).to_le_bytes());
    data[88..92].copy_from_slice(&1_u32.to_le_bytes());
    data[100..104].copy_from_slice(&(strings as u32).to_le_bytes());
    data[128..136].copy_from_slice(&0x01d9_0000_0000_0000_u64.to_le_bytes());
    data[152..156].copy_from_slice(&3_u32.to_le_bytes());
    data[metrics + 16..metrics + 20].copy_from_slice(&((path.len() / 2) as u32).to_le_bytes());
    data.extend(&path);
    data.extend([0, 0]);
    data
}

#[test]
fn maps_a_built_file() {
    let bytes = built();
    assert_conforms(&PrefetchAdapter, "RCLONE.EXE-0EE41A20.pf", &bytes);
    let output = parse(&PrefetchAdapter, "RCLONE.EXE-0EE41A20.pf", &bytes);
    let record = &output.records[0];
    assert_eq!(record.summary, "Prefetch RCLONE.EXE · run 3 times");
    assert_eq!(
        record.facets.process_path.as_deref(),
        Some(r"\VOLUME{01}\TOOLS\RCLONE.EXE")
    );
    assert_eq!(record.times.len(), 1);
    assert_eq!(record.times[0].kind, TimeKind::Executed);
    assert_eq!(record.times[0].field, "LastRun");
    assert_eq!(
        record.fields.get("Hash"),
        Some(&Value::Text("0EE41A20".to_owned()))
    );
}

#[test]
fn rejects_what_isnt_prefetch() {
    let bytes = b"MAM\x04\x10\0\0\0garbage".to_vec();
    let input = Input {
        evidence: EvidenceId::of_content(&bytes),
        name: "x.pf",
        data: &bytes,
        modified: None,
    };
    assert!(PrefetchAdapter
        .parse(&input, &mut Collected::default())
        .is_err());
}
