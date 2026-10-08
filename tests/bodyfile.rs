//! The bodyfile importer on plaso's test bodyfile (Apache-2.0,
//! `tests/fixtures/bodyfile/`): every time plaso's `bodyfile` parser reads,
//! read the same (`plaso.tsv`, written from plaso's output: name, link
//! target, which time, microseconds). Times with a fraction are written to
//! the nanosecond; plaso goes through floating point and lands a
//! microsecond either side, so those are compared to within one.

use std::collections::BTreeSet;

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, Value};
use sootmark_adapters::bodyfile::BodyfileAdapter;

#[test]
fn every_time_as_plaso_reads_it() {
    let folder = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/bodyfile");
    let data = std::fs::read(format!("{folder}/bodyfile")).unwrap();
    assert_eq!(
        BodyfileAdapter.probe("case/fls.body", &data),
        Confidence::Certain
    );
    assert_conforms(&BodyfileAdapter, "fls.body", &data);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name: "fls.body",
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    BodyfileAdapter.parse(&input, &mut sink).unwrap();
    assert!(sink.skipped.is_empty(), "{:?}", sink.skipped);
    let mut got: Vec<(String, i64)> = Vec::new();
    for record in &sink.records {
        let text = |name: &str| match record.fields.get(name) {
            Some(Value::Text(t)) => t.clone(),
            _ => String::new(),
        };
        let deleted = record.fields.get("Deleted") == Some(&Value::Bool(true));
        let name = if deleted {
            format!("{} (deleted)", text("Name"))
        } else {
            text("Name")
        };
        for time in &record.times {
            got.push((
                format!("{name}\t{}\t{}", text("LinkTarget"), time.field),
                time.ts.ticks().unwrap() / 10,
            ));
        }
    }
    let expected: Vec<(String, i64)> = std::fs::read_to_string(format!("{folder}/plaso.tsv"))
        .unwrap()
        .lines()
        .map(|line| {
            let (key, micros) = line.rsplit_once('\t').unwrap();
            (key.to_owned(), micros.parse().unwrap())
        })
        .collect();
    let distinct: BTreeSet<(String, i64)> = got.iter().cloned().collect();
    assert_eq!(distinct.len(), expected.len());
    for (key, micros) in &expected {
        let tolerance = i64::from(micros % 1_000_000 != 0);
        assert!(
            got.iter()
                .any(|(k, m)| k == key && (m - micros).abs() <= tolerance),
            "{key} {micros}"
        );
    }
}

#[test]
fn other_text_is_no_bodyfile() {
    assert_eq!(BodyfileAdapter.probe("x", b"a|b|c\n"), Confidence::No);
}
