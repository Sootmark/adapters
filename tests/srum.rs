//! The SRUM adapter on plaso's `SRUDB.dat` (Apache-2.0,
//! `tests/fixtures/srum/`, stored gzip-compressed): the contract,
//! recognition, and records with their program, account and figures.

use std::io::Read;

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, TimeKind, Value};
use sootmark_adapters::srum::{SrumAdapter, NAMESPACE};

const PATH: &str = "C/Windows/System32/sru/SRUDB.dat";

fn database() -> Vec<u8> {
    let compressed = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/srum/SRUDB.dat.gz"
    ))
    .unwrap();
    let mut data = Vec::new();
    common::gzip::Decoder::new(compressed.as_slice())
        .read_to_end(&mut data)
        .unwrap();
    data
}

#[test]
fn records_with_programs_and_figures() {
    let data = database();
    assert_eq!(SrumAdapter.probe(PATH, &data[..4096]), Confidence::Certain);
    assert_eq!(
        SrumAdapter.probe("Windows.edb", &data[..4096]),
        Confidence::No
    );
    assert_conforms(&SrumAdapter, PATH, &data);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name: PATH,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    SrumAdapter.parse(&input, &mut sink).unwrap();
    assert!(sink.skipped.is_empty(), "{:?}", sink.skipped);
    let records = &sink.records;
    assert!(records.iter().all(|r| r.namespace() == NAMESPACE));
    let network = records
        .iter()
        .find(|r| {
            r.fields.get("Provider") == Some(&Value::from("network usage"))
                && r.fields.get("App") == Some(&Value::from("DiagTrack"))
                && r.fields.get("BytesSent") == Some(&Value::Int(2076))
        })
        .unwrap();
    assert!(network
        .summary
        .starts_with("DiagTrack sent 2076 bytes, received "));
    assert_eq!(network.facets.user_sid.as_deref(), Some("S-1-5-18"));
    assert_eq!(network.times[0].kind, TimeKind::Logged);
    let connectivity = records
        .iter()
        .find(|r| r.fields.get("Provider") == Some(&Value::from("network connectivity")))
        .unwrap();
    assert_eq!(
        connectivity.times.len(),
        2,
        "TimeStamp and ConnectStartTime"
    );
}
