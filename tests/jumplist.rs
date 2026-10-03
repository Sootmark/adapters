//! The jump list adapter on one of Eric Zimmerman's MIT test lists
//! (Windows 10 Explorer) and one of plaso's Apache-2.0 custom lists (the
//! parser is checked against `JLECmd` on both sets in `sootmark-shell`): the
//! contract, and what `JLECmd` reports for them.

use std::fs;
use std::path::Path;

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, Record, TimeKind, Value};
use sootmark_adapters::jumplist::{JumpListAdapter, NAMESPACE};

const AUTOMATIC: &str = "f01b4d95cf55d32a.automaticDestinations-ms";
const CUSTOM: &str = "368d807282ccde9d.customDestinations-ms";

fn parse(name: &str) -> (Vec<u8>, Collected) {
    let bytes = fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/jumplist")
            .join(name),
    )
    .unwrap();
    let input = Input {
        evidence: EvidenceId::of_content(&bytes),
        name,
        data: &bytes,
    };
    let mut sink = Collected::default();
    JumpListAdapter
        .parse(&input, &mut sink)
        .expect("a jump list");
    (bytes, sink)
}

fn field<'a>(record: &'a Record, name: &str) -> Option<&'a Value> {
    record.fields.get(name)
}

#[test]
fn maps_automatic_entries_as_jlecmd_reads_them() {
    let (bytes, output) = parse(AUTOMATIC);
    assert_conforms(&JumpListAdapter, AUTOMATIC, &bytes);
    assert!(output.skipped.is_empty());
    assert_eq!(output.records.len(), 9);
    let first = &output.records[0];
    assert_eq!(first.namespace(), NAMESPACE);
    assert_eq!(first.facets.file_path.as_deref(), Some(r"C:\Temp"));
    assert_eq!(
        field(first, "AppId"),
        Some(&Value::from("f01b4d95cf55d32a"))
    );
    assert_eq!(field(first, "EntryNumber"), Some(&Value::UInt(7)));
    assert_eq!(field(first, "MRU"), Some(&Value::UInt(0)));
    assert_eq!(field(first, "InteractionCount"), Some(&Value::UInt(2)));
    assert_eq!(field(first, "Pinned"), Some(&Value::Bool(false)));
    assert_eq!(
        field(first, "Hostname"),
        Some(&Value::from("desktop-annfp9d"))
    );
    assert_eq!(
        field(first, "MacAddress"),
        Some(&Value::from("00:15:5d:01:6d:02"))
    );
    let last_used = first
        .times
        .iter()
        .find(|t| t.kind == TimeKind::LastSeen)
        .unwrap();
    assert!(
        last_used.ts.to_string().starts_with("2015-11-24T20:31:34"),
        "{}",
        last_used.ts
    );
    // Its file identifier is its link's tracker identifier: one time.
    let fields: Vec<&str> = first.times.iter().map(|t| t.field.as_str()).collect();
    assert!(
        fields.contains(&"TrackerCreatedOn") && !fields.contains(&"FileDroidCreated"),
        "{fields:?}"
    );
    assert_eq!(
        first.summary,
        r"Used via f01b4d95cf55d32a's jump list on desktop-annfp9d: C:\Temp"
    );
    let pinned: Vec<_> = output
        .records
        .iter()
        .filter(|r| field(r, "Pinned") == Some(&Value::Bool(true)))
        .map(|r| r.fields.get("Path").cloned().unwrap())
        .collect();
    assert_eq!(pinned.len(), 4);
    assert_eq!(pinned[0], Value::from(r"C:\Users\e\Desktop"));
}

#[test]
fn maps_custom_links_by_category() {
    let (bytes, output) = parse(CUSTOM);
    assert_conforms(&JumpListAdapter, CUSTOM, &bytes);
    let categories: Vec<_> = output
        .records
        .iter()
        .map(|r| r.fields.get("Category").cloned().unwrap())
        .collect();
    assert_eq!(
        categories,
        ["My Category 1", "Tasks", "My Category 2"].map(Value::from)
    );
    let record = &output.records[0];
    assert_eq!(record.facets.file_path.as_deref(), Some(r"C:\test"));
    assert_eq!(
        record.facets.process_command_line.as_deref(),
        Some("My Arguments")
    );
    assert_eq!(
        record.summary,
        r"368d807282ccde9d's jump list, My Category 1: C:\test My Arguments"
    );
}

#[test]
fn probes_by_name_and_signature() {
    let ole = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
    let probe = |name, head: &[u8]| JumpListAdapter.probe(name, head);
    assert_eq!(probe(AUTOMATIC, &ole), Confidence::Certain);
    assert_eq!(probe(CUSTOM, b"\x02\0\0\0"), Confidence::Maybe);
    assert_eq!(probe("report.doc", &ole), Confidence::No);
}

#[test]
fn rejects_what_isnt_a_jump_list() {
    for name in [AUTOMATIC, CUSTOM] {
        let bytes = b"not a jump list".to_vec();
        let input = Input {
            evidence: EvidenceId::of_content(&bytes),
            name,
            data: &bytes,
        };
        assert!(
            JumpListAdapter
                .parse(&input, &mut Collected::default())
                .is_err(),
            "{name}"
        );
    }
}
