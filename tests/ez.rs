//! The EZ Tools importer on real EZ output (.NET 9 builds): on the synthetic
//! FIN-WKS-07 artifacts; `EvtxECmd` on two logs of EVTX-to-MITRE-Attack
//! (CC0, `tests/fixtures/cc0/`); `PECmd` on Windows on the open prefetch
//! files of `sootmark-prefetch` (Eric Zimmerman's test set, MIT, and
//! plaso's, Apache-2.0: its `oracle` workflow); `AppCompatCacheParser`,
//! `SBECmd` and `RECmd` (Kroll batch) on the MIT-licensed test hives of
//! EZ's Registry library, excerpted.

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Input};
use model::{EvidenceId, Namespace, Record, TimeKind, Value};
use sootmark_adapters::evtx::EvtxAdapter;
use sootmark_adapters::ez::EzAdapter;

fn path(dir: &str, name: &str) -> String {
    format!("{}/tests/fixtures/{dir}/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(path("ez", &format!("20260914103000_{name}"))).expect("committed fixture")
}

fn parse(name: &str, bytes: &[u8]) -> Collected {
    let input = Input {
        evidence: EvidenceId::of_content(bytes),
        name,
        data: bytes,
    };
    let mut sink = Collected::default();
    EzAdapter.parse(&input, &mut sink).expect("EZ output");
    sink
}

/// Output file, namespace, rows.
const FIXTURES: [(&str, &str, usize); 15] = [
    ("PECmd_Output.csv", "ez.prefetch", 62),
    ("PECmd_Output_Timeline.csv", "ez.prefetch.runs", 122),
    (
        "Windows81_Windows2012R2_SYSTEM_AppCompatCache.csv",
        "ez.shimcache",
        100,
    ),
    ("SBECmd_UsrClass.csv", "ez.shellbags", 100),
    ("RECmd_Batch_Kroll_Batch_Output.csv", "ez.registry", 292),
    ("MFTECmd_$MFT_Output.csv", "ez.mft", 69),
    ("MFTECmd_$J_Output.csv", "ez.usnjrnl", 173),
    ("LECmd_Output.csv", "ez.lnk", 6),
    ("AutomaticDestinations.csv", "ez.jumplist.automatic", 11),
    ("CustomDestinations.csv", "ez.jumplist.custom", 5),
    ("RBCmd_Output.csv", "ez.recyclebin", 5),
    ("EvtxECmd_Output.csv", "ez.evtx", 14),
    ("Amcache_UnassociatedFileEntries.csv", "ez.amcache.file", 12),
    ("Amcache_AssociatedFileEntries.csv", "ez.amcache.file", 18),
    ("Amcache_ProgramEntries.csv", "ez.amcache.program", 75),
];

fn one<'r>(records: &'r [Record], summary_part: &str) -> &'r Record {
    records
        .iter()
        .find(|r| r.summary.contains(summary_part))
        .unwrap_or_else(|| panic!("no record with '{summary_part}'"))
}

fn time(record: &Record, field: &str) -> Option<(TimeKind, String)> {
    record
        .times
        .iter()
        .find(|t| t.field == field)
        .map(|t| (t.kind, t.ts.to_iso8601().unwrap()))
}

#[test]
fn imports_every_tool_it_knows() {
    for (name, namespace, rows) in FIXTURES {
        let bytes = fixture(name);
        assert_conforms(&EzAdapter, name, &bytes);
        let output = parse(name, &bytes);
        assert_eq!(output.records.len(), rows, "{name}");
        assert!(output.skipped.is_empty(), "{name}: {:?}", output.skipped);
        assert!(
            output
                .records
                .iter()
                .all(|r| r.namespace() == Namespace::new(namespace)),
            "{name}"
        );
    }
}

#[test]
fn maps_what_each_tool_found() {
    let lnk = parse("l", &fixture("LECmd_Output.csv")).records;
    let rclone = one(&lnk, "rclone.exe");
    assert_eq!(
        rclone.facets.file_path.as_deref(),
        Some(r"C:\Users\Public\rclone.exe")
    );
    assert!(rclone
        .summary
        .ends_with(r"copy \\198.51.100.20\finance$\HR E:\exfil --transfers 8 --no-console"));
    assert_eq!(
        time(rclone, "TargetAccessed"),
        Some((TimeKind::Accessed, "2026-09-14T10:44:58.0000000Z".into()))
    );

    let bin = parse("r", &fixture("RBCmd_Output.csv")).records;
    let tools = one(&bin, r"C:\Users\svc_backup\Downloads\tools.zip");
    assert_eq!(
        tools.facets.user_sid.as_deref(),
        Some("S-1-5-21-3623811015-3361044348-30300820-1119")
    );
    assert_eq!(
        time(tools, "DeletedOn"),
        Some((TimeKind::Deleted, "2026-09-14T10:53:12.0000000Z".into()))
    );

    let mft = parse("m", &fixture("MFTECmd_$MFT_Output.csv")).records;
    let record = one(&mft, r"rclone.exe");
    assert!(record.times.iter().any(|t| t.kind == TimeKind::Created));
    assert!(record.fields.contains_key("SI<FN"));

    let jump = parse("j", &fixture("AutomaticDestinations.csv")).records;
    let creds = one(&jump, r"C:\ProgramData\Intel\creds.txt");
    assert_eq!(
        time(creds, "CreationTime").map(|t| t.0),
        Some(TimeKind::FirstSeen)
    );
    assert_eq!(
        time(creds, "LastModified").map(|t| t.0),
        Some(TimeKind::LastSeen)
    );

    let csv = fixture("Amcache_UnassociatedFileEntries.csv");
    let amcache = parse("a", &csv).records;
    let seven = one(&amcache, r"c:\users\john doe\downloads\7z1900-x64.exe");
    assert_eq!(
        time(seven, "LinkDate"),
        Some((TimeKind::Other, "2019-02-21T17:00:00.0000000Z".into()))
    );
    assert_eq!(
        seven.fields.get("SHA1"),
        Some(&Value::from("9fa11a63b43f83980e0b48dc9ba2cb59d545a4e8"))
    );
    // .NET's "no date" is no time, not year 1.
    let undated = String::from_utf8(csv)
        .unwrap()
        .replace("2019-02-21 17:00:00", "0001-01-01 00:00:00");
    let undated = parse("a", undated.as_bytes()).records;
    let seven = one(&undated, r"c:\users\john doe\downloads\7z1900-x64.exe");
    assert!(time(seven, "LinkDate").is_none());
}

/// EZ's `EvtxECmd` and Sootmark's own EVTX parser, reading the same logs,
/// agree on every event's id and time.
#[test]
fn evtxecmd_agrees_with_the_native_parser() {
    let csv = fixture("EvtxECmd_Output.csv");
    let imported = parse("EvtxECmd_Output.csv", &csv).records;
    let mut native = Collected::default();
    for name in [
        "ID4624-Mimikatz Pass the hash.evtx",
        "ID4648-4624-RunAsCS login.evtx",
    ] {
        let log = std::fs::read(path("cc0", name)).unwrap();
        let input = Input {
            evidence: EvidenceId::of_content(&log),
            name,
            data: &log,
        };
        EvtxAdapter
            .parse(&input, &mut native)
            .expect("a readable log");
    }
    assert_eq!(imported.len(), native.records.len());
    let key = |r: &Record, id: &str| {
        (
            match r.fields.get(id) {
                Some(Value::Text(t)) => t.parse::<u64>().unwrap(),
                Some(Value::UInt(n)) => *n,
                other => panic!("{other:?}"),
            },
            r.facets.event_code,
            r.times[0].ts.ticks(),
        )
    };
    let mut ez: Vec<_> = imported.iter().map(|r| key(r, "EventRecordId")).collect();
    let mut ours: Vec<_> = native
        .records
        .iter()
        .map(|r| key(r, "EventRecordID"))
        .collect();
    ez.sort_unstable();
    ours.sort_unstable();
    assert_eq!(ez, ours);
}

#[test]
fn maps_registry_and_prefetch_tools() {
    let prefetch = parse("p", &fixture("PECmd_Output.csv")).records;
    let generator = one(&prefetch, "Prefetch BYTECODEGENERATOR.EXE");
    let runs: Vec<String> = generator
        .times
        .iter()
        .filter(|t| t.kind == TimeKind::Executed)
        .map(|t| t.ts.to_iso8601().unwrap())
        .collect();
    assert_eq!(runs.len(), 7, "run count 7: last run and six previous");
    assert_eq!(runs[0], "2015-05-14T22:11:58.0000000Z");

    let shim = parse(
        "s",
        &fixture("Windows81_Windows2012R2_SYSTEM_AppCompatCache.csv"),
    )
    .records;
    let java = one(&shim, r"SYSVOL\Program Files\CrashPlan\jre\bin\java.exe");
    assert_eq!(
        time(java, "LastModifiedTimeUTC"),
        Some((TimeKind::Modified, "2013-12-04T23:47:23.0000000Z".into()))
    );
    assert!(
        shim.iter()
            .all(|r| r.times.iter().all(|t| t.kind != TimeKind::Executed)),
        "ShimCache times aren't runs"
    );

    let bags = parse("b", &fixture("SBECmd_UsrClass.csv")).records;
    assert!(bags
        .iter()
        .any(|r| r.facets.file_path.as_deref() == Some(r"Desktop\ControlPanelHome")));

    let registry = parse("r", &fixture("RECmd_Batch_Kroll_Batch_Output.csv")).records;
    assert!(registry
        .iter()
        .any(|r| r.summary.starts_with("Program Execution: ")));
    assert!(registry.iter().all(|r| r.times.len() <= 1));
}

/// `PECmd` and Plaso parse prefetch independently: for every file both saw
/// (matched by prefetch hash), they agree on every run time.
#[test]
fn pecmd_and_plaso_agree_on_prefetch_runs() {
    use std::collections::{BTreeMap, BTreeSet};
    let pecmd = parse("p", &fixture("PECmd_Output.csv")).records;
    let mut ours: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
    for record in &pecmd {
        let Some(Value::Text(hash)) = record.fields.get("Hash") else {
            panic!("Hash")
        };
        let runs = record
            .times
            .iter()
            .filter(|t| t.kind == TimeKind::Executed)
            .map(|t| t.ts.to_iso8601().unwrap());
        ours.entry(u64::from_str_radix(hash, 16).unwrap())
            .or_default()
            .extend(runs);
    }
    let plaso = std::fs::read(path("plaso", "open.json_line.jsonl")).unwrap();
    let mut theirs: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
    for line in String::from_utf8(plaso).unwrap().lines() {
        let event = common::json::parse(line).unwrap();
        let executed = event
            .get("timestamp_desc")
            .and_then(common::json::Json::as_str)
            .is_some_and(|d| d.contains("Time Executed"));
        if event.get("parser").and_then(common::json::Json::as_str) != Some("prefetch") || !executed
        {
            continue;
        }
        let hash = event
            .get("prefetch_hash")
            .and_then(common::json::Json::as_u64)
            .unwrap();
        let micros = event
            .get("timestamp")
            .and_then(common::json::Json::as_i64)
            .unwrap();
        // PECmd writes whole seconds.
        let seconds = common::time::Ts::from_unix_micros(micros - micros.rem_euclid(1_000_000));
        theirs
            .entry(hash)
            .or_default()
            .insert(seconds.to_iso8601().unwrap());
    }
    assert!(!theirs.is_empty());
    for (hash, runs) in &theirs {
        assert_eq!(ours.get(hash), Some(runs), "prefetch hash {hash:08X}");
    }
}
