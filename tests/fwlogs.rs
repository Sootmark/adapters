//! The firewall log adapter on open PAN-OS and Cisco ASA samples and a
//! FortiGate log written for the sootmark-fwlogs tests
//! (`tests/fixtures/fwlogs/`, see its NOTICE): recognition and records.

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, Value};
use sootmark_adapters::fwlogs::{FwlogsAdapter, ASA, FORTIGATE, PANOS};

fn collect(name: &str) -> Collected {
    let data = std::fs::read(format!(
        "{}/tests/fixtures/fwlogs/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    assert_eq!(
        FwlogsAdapter.probe(name, &data),
        Confidence::Certain,
        "{name}"
    );
    assert_conforms(&FwlogsAdapter, name, &data);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    FwlogsAdapter.parse(&input, &mut sink).unwrap();
    assert!(sink.skipped.is_empty(), "{:?}", sink.skipped);
    sink
}

#[test]
fn three_makers() {
    let pan = collect("pan_screenconnect_traffic.log");
    assert_eq!(pan.records.len(), 1);
    assert_eq!(pan.records[0].namespace(), PANOS);
    assert_eq!(
        pan.records[0].facets.source_ip.as_deref(),
        Some("192.168.1.205")
    );
    assert_eq!(
        pan.records[0].fields.get("Application"),
        Some(&Value::from("screenconnect"))
    );

    let asa = collect("asa_generic.log");
    assert_eq!(asa.records.len(), 48);
    assert!(asa.records.iter().all(|r| r.namespace() == ASA));
    assert!(asa
        .records
        .iter()
        .any(|r| r.fields.get("Kind") == Some(&Value::from("502101"))));

    let forti = collect("fortigate-kv.log");
    assert_eq!(forti.records.len(), 10);
    assert!(forti.records.iter().all(|r| r.namespace() == FORTIGATE));
}

#[test]
fn other_text_is_not_a_firewall_log() {
    assert_eq!(
        FwlogsAdapter.probe("x.log", b"hello\nworld\n"),
        Confidence::No
    );
}
