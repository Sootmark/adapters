//! The User Access Logging adapter on plaso's test databases (Apache-2.0,
//! a Windows Server 2019 domain controller, `tests/fixtures/ual/`, stored
//! gzip-compressed): recognition, the identity database as companion, and
//! the records.

use std::io::Read;

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Companion, Confidence, Input};
use model::{EvidenceId, Value};
use sootmark_adapters::ual::UalAdapter;

fn fixture(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/tests/fixtures/ual/{name}.gz",
        env!("CARGO_MANIFEST_DIR")
    );
    let compressed = std::fs::read(path).unwrap();
    let mut data = Vec::new();
    common::gzip::Decoder::new(compressed.as_slice())
        .read_to_end(&mut data)
        .unwrap();
    data
}

const YEAR: &str = "C/Windows/System32/LogFiles/Sum/{C519A76A-D9B5-4F85-B667-5FAC08E0E1B4}.mdb";

#[test]
fn clients_with_role_names_and_days() {
    let year = fixture("{C519A76A-D9B5-4F85-B667-5FAC08E0E1B4}.mdb");
    let identity = fixture("SystemIdentity.mdb");
    assert_eq!(UalAdapter.probe(YEAR, &year[..64]), Confidence::Certain);
    assert_eq!(
        UalAdapter.probe("C/x/Current.mdb", b"Standard Jet DB"),
        Confidence::No
    );
    assert_eq!(UalAdapter.companions(YEAR), ["SystemIdentity.mdb"]);
    assert_conforms(&UalAdapter, YEAR, &year);
    let input = Input {
        evidence: EvidenceId::of_content(&year),
        name: YEAR,
        data: &year,
        modified: None,
    };
    let companion = Companion {
        name: "SystemIdentity.mdb",
        data: &identity,
    };
    let mut sink = Collected::default();
    UalAdapter
        .parse_with_companions(&input, &[companion], &mut sink)
        .unwrap();
    assert!(sink.skipped.is_empty(), "{:?}", sink.skipped);
    // 14 clients, 3 roles, 6 name resolutions.
    assert_eq!(sink.records.len(), 23);
    let hunter = sink
        .records
        .iter()
        .find(|r| {
            r.fields.get("Account") == Some(&Value::from("ual\\hunter"))
                && r.fields.get("Address") == Some(&Value::from("10.0.11.10"))
                && r.fields.get("RoleName") == Some(&Value::from("File Server"))
        })
        .unwrap();
    assert_eq!(
        hunter.summary,
        "UAL: ual\\hunter from 10.0.11.10 used File Server 2 times (1 days)"
    );
    assert_eq!(hunter.facets.source_ip.as_deref(), Some("10.0.11.10"));
    assert_eq!(
        hunter.fields.get("Days"),
        Some(&Value::from("2022-07-16: 2"))
    );
    // Without the identity database, roles stay identifiers.
    let mut alone = Collected::default();
    UalAdapter.parse(&input, &mut alone).unwrap();
    assert!(alone
        .records
        .iter()
        .all(|r| !r.fields.contains_key("RoleName")));
}

#[test]
fn the_server_identity() {
    let identity = fixture("SystemIdentity.mdb");
    let name = "C/Windows/System32/LogFiles/Sum/SystemIdentity.mdb";
    assert!(UalAdapter.companions(name).is_empty());
    let input = Input {
        evidence: EvidenceId::of_content(&identity),
        name,
        data: &identity,
        modified: None,
    };
    let mut sink = Collected::default();
    UalAdapter.parse(&input, &mut sink).unwrap();
    let summaries: Vec<&str> = sink.records.iter().map(|r| r.summary.as_str()).collect();
    assert_eq!(
        summaries,
        [
            "UAL server identity: DC-1 (WORKGROUP), Windows 10.0.17763",
            "UAL server identity: DC-1 (ual.lab), Windows 10.0.17763"
        ]
    );
}
