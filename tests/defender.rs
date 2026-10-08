//! The Defender detection history adapter on plaso's test files
//! (Apache-2.0, `tests/fixtures/defender/`, stored gzip-compressed):
//! recognition and the records.

use std::io::Read;

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, Value};
use sootmark_adapters::defender::DefenderAdapter;

const NAME: &str = "FC380697-A68D-4C94-B67F-9B6449039463";

fn fixture(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/tests/fixtures/defender/{name}.gz",
        env!("CARGO_MANIFEST_DIR")
    );
    let compressed = std::fs::read(path).unwrap();
    let mut data = Vec::new();
    common::gzip::Decoder::new(compressed.as_slice())
        .read_to_end(&mut data)
        .unwrap();
    data
}

#[test]
fn a_detection_per_file() {
    let data = fixture(NAME);
    let path = format!(
        "C/ProgramData/Microsoft/Windows Defender/Scans/History/Service/DetectionHistory/02/{NAME}"
    );
    assert_eq!(
        DefenderAdapter.probe(&path, &data[..128]),
        Confidence::Certain
    );
    assert_eq!(
        DefenderAdapter.probe(&path, b"Magic.Version:1.2"),
        Confidence::No
    );
    assert_conforms(&DefenderAdapter, &path, &data);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name: &path,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    DefenderAdapter.parse(&input, &mut sink).unwrap();
    assert!(sink.skipped.is_empty(), "{:?}", sink.skipped);
    let [record] = &sink.records[..] else {
        panic!("{} records", sink.records.len());
    };
    assert_eq!(
        record.summary,
        r"Defender detected PUA:Win32/EICAR_Test_File in C:\Users\testuser\Downloads\PotentiallyUnwanted.exe"
    );
    assert_eq!(
        record.fields.get("CategoryName"),
        Some(&Value::from("POTENTIALUNWANTEDSOFTWARE"))
    );
    assert_eq!(
        record.fields.get("Sha256"),
        Some(&Value::from(
            "d6f6c6b9fde37694e12b12009ad11ab9ec8dd0f193e7319c523933bdad8a50ad"
        ))
    );
    assert_eq!(
        record.facets.process_path.as_deref(),
        Some(r"C:\Windows\explorer.exe")
    );
    assert_eq!(
        record.facets.user_name.as_deref(),
        Some(r"FRYPTOP\testuser")
    );
    assert_eq!(
        record.times[0].ts.to_iso8601().as_deref(),
        Some("2022-07-22T05:32:27.8302783Z")
    );
    let names: Vec<&str> = record.times.iter().map(|t| t.field.as_str()).collect();
    // Not remediated: a potentially unwanted program allowed or pending.
    assert_eq!(
        names,
        [
            "ThreatTrackingStartTime",
            "InitialDetectionTime",
            "LastThreatStatusChangeTime"
        ]
    );
}

#[test]
fn an_unknown_process_is_no_facet() {
    let data = fixture("6AFE33A0-19BA-4FFF-892F-B700539D7D63");
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name: "x",
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    DefenderAdapter.parse(&input, &mut sink).unwrap();
    let record = &sink.records[0];
    assert_eq!(record.facets.process_path, None);
    assert_eq!(record.fields.get("Process"), Some(&Value::from("Unknown")));
    let resources = record.fields.get("Resources").unwrap();
    assert!(format!("{resources:?}")
        .contains("containerfile: C:\\\\Users\\\\testuser\\\\Downloads\\\\eicar_com.zip"));
}
