//! The Plaso importer on real `psort` output (Plaso 20260720), in every
//! format:
//!
//! - `fin-wks-07.*`: the synthetic FIN-WKS-07 artifacts (MFT, USN, LNK,
//!   jump lists).
//! - `open.*`: the open prefetch files of `sootmark-prefetch` (Eric
//!   Zimmerman's test set, MIT; plaso's, Apache-2.0) and two logs of
//!   EVTX-to-MITRE-Attack (CC0, `tests/fixtures/cc0/`), the logs checked
//!   against Sootmark's own EVTX parser.

use std::collections::HashSet;

use common::time::Semantic;
use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Input};
use model::{EvidenceId, Namespace, Record, TimeKind};
use sootmark_adapters::evtx::EvtxAdapter;
use sootmark_adapters::plaso::PlasoAdapter;

fn read(path: &str) -> Option<Vec<u8>> {
    std::fs::read(format!(
        "{}/tests/fixtures/{path}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .ok()
}

fn parse(name: &str, bytes: &[u8]) -> Collected {
    let input = Input {
        evidence: EvidenceId::of_content(bytes),
        name,
        data: bytes,
    };
    let mut sink = Collected::default();
    PlasoAdapter.parse(&input, &mut sink).expect("psort output");
    sink
}

fn fixture(format: &str) -> Collected {
    let name = format!("fin-wks-07.{format}");
    let bytes = read(&format!("plaso/{name}")).expect("committed fixture");
    assert_conforms(&PlasoAdapter, &name, &bytes);
    let output = parse(&name, &bytes);
    assert!(output.skipped.is_empty(), "{name}: {:?}", output.skipped);
    output
}

/// UTC times as (ticks, kind), sorted: the part every format shares.
fn utc_times(records: &[Record], divisor: i64) -> Vec<(i64, TimeKind)> {
    let mut times: Vec<(i64, TimeKind)> = records
        .iter()
        .flat_map(|r| &r.times)
        .filter(|t| t.ts.semantic() == Semantic::Utc)
        .map(|t| (t.ts.ticks().unwrap() / divisor, t.kind))
        .collect();
    times.sort_unstable_by_key(|&(ticks, kind)| (ticks, format!("{kind:?}")));
    times
}

#[test]
fn imports_every_format() {
    let json = fixture("json_line.jsonl").records;
    let dynamic = fixture("dynamic.csv").records;
    let l2t = fixture("l2tcsv.csv").records;
    assert_eq!(json.len(), 840);
    assert_eq!(dynamic.len(), 840);
    assert_eq!(l2t.len(), 411);

    // FAT times are local by nature: JSON keeps them local, the CSV formats
    // can only carry Plaso's UTC reading, so compare what's UTC in JSON.
    let local: usize = json
        .iter()
        .filter(|r| r.times[0].ts.semantic() == Semantic::LocalUnknownZone)
        .count();
    assert!(local > 0, "shell item FAT times are local");
    // Microseconds: psort's CSV rounds FILETIMEs where its JSON truncates
    // (`…251841` for `…2518402` ticks), so allow one microsecond.
    // Both CSV formats are kept to the second (psort's `dynamic` misprints
    // fractions that start with a zero): compare seconds.
    let json_seconds = utc_times(&json, 10_000_000);
    let dynamic_seconds = utc_times(&dynamic, 10_000_000);
    // Every UTC time in the JSON is in the CSV (which also holds the FAT
    // times, as UTC), duplicates included.
    let mut remaining = dynamic_seconds.clone();
    for time in &json_seconds {
        let at = remaining
            .iter()
            .position(|t| t == time)
            .unwrap_or_else(|| panic!("{time:?} missing from dynamic"));
        remaining.swap_remove(at);
    }
    assert_eq!(remaining.len(), json.len() - json_seconds.len());
    assert!(dynamic
        .iter()
        .all(|r| r.times[0].ts.precision() == common::time::Precision::Second));
    // l2tcsv: to the second, several descriptions per row.
    let l2t_seconds: HashSet<i64> = utc_times(&l2t, 10_000_000)
        .into_iter()
        .map(|t| t.0)
        .collect();
    assert!(json_seconds.iter().all(|t| l2t_seconds.contains(&t.0)));
}

#[test]
fn maps_what_plaso_found() {
    let json = fixture("json_line.jsonl").records;
    let open = parse(
        "open.json_line.jsonl",
        &read("plaso/open.json_line.jsonl").unwrap(),
    )
    .records;
    let namespaces: HashSet<Namespace> = json.iter().chain(&open).map(Record::namespace).collect();
    for expected in [
        "plaso.mft",
        "plaso.prefetch",
        "plaso.lnk",
        "plaso.olecf",
        "plaso.custom_destinations",
        "plaso.winevtx",
    ] {
        assert!(namespaces.contains(&Namespace::new(expected)), "{expected}");
    }
    let runs: Vec<&Record> = open
        .iter()
        .filter(|r| {
            r.times[0].kind == TimeKind::Executed
                && r.facets.process_path.as_deref() == Some("BYTECODEGENERATOR.EXE")
        })
        .collect();
    assert_eq!(
        runs.len(),
        7,
        "prefetch executions of BYTECODEGENERATOR.EXE"
    );
    assert!(runs.iter().all(|r| r.fields.contains_key("run_count")));
    assert!(json.iter().chain(&open).all(|r| !r.summary.is_empty()));
}

#[test]
fn every_native_event_log_record_is_in_plasos_timeline() {
    let plaso = parse(
        "open.json_line.jsonl",
        &read("plaso/open.json_line.jsonl").unwrap(),
    );
    // Plaso numbers records by their header, which a log exported from
    // another renumbers: match on event id and creation time.
    let plaso_events: HashSet<(Option<u32>, i64)> = plaso
        .records
        .iter()
        .filter(|r| r.namespace() == Namespace::new("plaso.winevtx"))
        .filter(|r| r.times[0].kind == TimeKind::Created)
        .map(|r| (r.facets.event_code, r.times[0].ts.ticks().unwrap()))
        .collect();
    let mut native = Collected::default();
    for name in [
        "ID4624-Mimikatz Pass the hash.evtx",
        "ID4648-4624-RunAsCS login.evtx",
    ] {
        let log = read(&format!("cc0/{name}")).unwrap();
        let input = Input {
            evidence: EvidenceId::of_content(&log),
            name,
            data: &log,
        };
        EvtxAdapter
            .parse(&input, &mut native)
            .expect("a readable log");
    }
    assert_eq!(native.records.len(), 14);
    for record in &native.records {
        let event = (
            record.facets.event_code,
            record.times[0].ts.ticks().unwrap(),
        );
        assert!(plaso_events.contains(&event), "{event:?}");
    }
}
