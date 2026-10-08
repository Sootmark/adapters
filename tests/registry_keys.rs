//! Every key as plaso's `winreg_default` plugin reads it (see
//! `tests/oracle/README`): the same keys, at the same paths, written at the
//! same times, holding the same values.
//!
//! On the test hives `tests/fetch-hives.sh` fetches
//! (`tests/oracle/plaso-registry-keys.tsv.gz`; skipped when they aren't
//! fetched), and on a copy of one of them with values changed into the
//! shapes they lack (`tests/fixtures/registry-edges/`,
//! `tests/oracle/plaso-registry-edges.tsv`).

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Input};
use model::{EvidenceId, Record, Value};
use sootmark_adapters::registry::{RegistryAdapter, KEYS};

/// The hives the oracle holds: all `tests/fetch-hives.sh` fetches but
/// Andrew Rathbun's SOFTWARE (see `tests/oracle/README`).
const HIVES: [&str; 7] = [
    "ERZ_Win81_UsrClass.dat",
    "NTUSER.DAT",
    "SOFTWARE",
    "SYSTEM",
    "plaso-NTUSER-WIN7.DAT",
    "rathbun-win10-NTUSER.DAT",
    "rathbun-win10-SYSTEM",
];
/// FILETIME's ticks at 1970-01-01.
const FILETIME_UNIX_OFFSET: i64 = 116_444_736_000_000_000;

fn path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn gunzip(relative: &str) -> Vec<u8> {
    let compressed = fs::read(path(relative)).unwrap_or_else(|e| panic!("{relative}: {e}"));
    let mut data = Vec::new();
    common::gzip::Decoder::new(compressed.as_slice())
        .read_to_end(&mut data)
        .unwrap();
    data
}

/// As the oracle writes text: `%`, and control characters, as `%XX`.
fn escape(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c == '%' || c.is_ascii_control() {
                format!("%{:02X}", u32::from(c))
            } else {
                c.to_string()
            }
        })
        .collect()
}

fn text<'r>(record: &'r Record, field: &str) -> &'r str {
    match record.fields.get(field) {
        Some(Value::Text(text)) => text,
        other => panic!("{field}: {other:?}"),
    }
}

/// A key record as the oracle's line: file, key path, FILETIME, values.
fn line(file: &str, record: &Record) -> String {
    let written = record.times[0].ts.ticks().map_or_else(
        || "Not set".to_owned(),
        |t| (t + FILETIME_UNIX_OFFSET).to_string(),
    );
    format!(
        "{file}\t{}\t{written}\t{}",
        escape(text(record, "KeyPath")),
        escape(text(record, "Values"))
    )
}

/// The hive's keys as the oracle's lines, sorted, and every record.
fn key_lines(file: &str, data: &[u8]) -> (Vec<String>, Collected) {
    let input = Input {
        evidence: EvidenceId::of_content(data),
        name: file,
        data,
        modified: None,
    };
    let mut sink = Collected::default();
    RegistryAdapter.parse(&input, &mut sink).unwrap();
    let mut lines: Vec<String> = sink
        .records
        .iter()
        .filter(|r| r.namespace() == KEYS)
        .map(|r| line(file, r))
        .collect();
    lines.sort();
    (lines, sink)
}

#[test]
fn every_key_of_the_test_hives_as_plaso_reads_it() {
    let oracle = String::from_utf8(gunzip("tests/oracle/plaso-registry-keys.tsv.gz")).unwrap();
    let (mut compared, mut differing) = (0, Vec::new());
    for file in HIVES {
        let Ok(data) = fs::read(path("tests/fixtures/hives").join(file)) else {
            eprintln!("skipped: {file} not fetched (tests/fetch-hives.sh)");
            continue;
        };
        let started = Instant::now();
        let (ours, all) = key_lines(file, &data);
        let elapsed = started.elapsed();
        let prefix = format!("{file}\t");
        let theirs: Vec<&str> = oracle.lines().filter(|l| l.starts_with(&prefix)).collect();
        eprintln!(
            "{file}: {} keys ({} in plaso), {} records in all, {elapsed:?}",
            ours.len(),
            theirs.len(),
            all.records.len()
        );
        let plaso_only: Vec<&&str> = theirs
            .iter()
            .filter(|l| ours.binary_search_by(|o| o.as_str().cmp(l)).is_err())
            .collect();
        let ours_only: Vec<&String> = ours
            .iter()
            .filter(|o| theirs.binary_search(&o.as_str()).is_err())
            .collect();
        for l in plaso_only.iter().take(5) {
            eprintln!("  plaso only: {l}");
        }
        for l in ours_only.iter().take(5) {
            eprintln!("  ours only:  {l}");
        }
        if !plaso_only.is_empty() || !ours_only.is_empty() {
            differing.push(format!(
                "{file}: {} plaso only, {} ours only",
                plaso_only.len(),
                ours_only.len()
            ));
        }
        compared += ours.len();
    }
    assert!(differing.is_empty(), "{differing:#?}");
    eprintln!("{compared} keys match plaso");
}

#[test]
fn value_shapes_the_test_hives_lack_as_plaso_reads_them() {
    let file = "NTUSER-edges.DAT";
    let data = gunzip("tests/fixtures/registry-edges/NTUSER-edges.DAT.gz");
    assert_conforms(&RegistryAdapter, file, &data);
    let (ours, all) = key_lines(file, &data);
    assert!(all.skipped.is_empty(), "{:?}", all.skipped);
    let oracle = fs::read_to_string(path("tests/oracle/plaso-registry-edges.tsv")).unwrap();
    for line in oracle.lines() {
        // Where this adapter parts from plaso, on purpose: an unpaired
        // UTF-16 surrogate, which Python keeps, is U+FFFD (a Rust string
        // can't hold one); a name stored in one byte per character is
        // Latin-1, as Windows writes it, where plaso reads Windows-1252.
        let expected = line
            .replace("%uD800", "\u{FFFD}")
            .replace("%uDC00", "\u{FFFD}")
            .replace("\u{2019}enuShowDelay", "\u{92}enuShowDelay");
        assert!(
            ours.binary_search(&expected).is_ok(),
            "not read as plaso reads it: {expected}"
        );
    }
}
