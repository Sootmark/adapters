//! The audit trail adapter on plaso's macOS trail (Apache-2.0,
//! `tests/fixtures/bsm/`): recognition and records.

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, Value};
use sootmark_adapters::bsm::{BsmAdapter, NAMESPACE};

#[test]
fn audited_events() {
    let data = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/bsm/apple.bsm"
    ))
    .unwrap();
    let name = "private/var/audit/20131104171720.crash_recovery";
    assert_eq!(BsmAdapter.probe(name, &data[..64]), Confidence::Certain);
    assert_eq!(BsmAdapter.probe("x.bin", &data[..64]), Confidence::Maybe);
    assert_eq!(BsmAdapter.probe(name, b"not a trail"), Confidence::No);
    assert_conforms(&BsmAdapter, name, &data);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    BsmAdapter.parse(&input, &mut sink).unwrap();
    assert!(sink.skipped.is_empty(), "{:?}", sink.skipped);
    assert_eq!(sink.records.len(), 54);
    assert!(sink.records.iter().all(|r| r.namespace() == NAMESPACE));

    let login = sink
        .records
        .iter()
        .find(|r| r.fields.get("EventName") == Some(&Value::from("loginwindow login")))
        .unwrap();
    assert_eq!(login.fields.get("AuditUid"), Some(&Value::Int(501)));
    assert_eq!(login.fields.get("Success"), Some(&Value::Bool(true)));
    assert_eq!(login.facets.process_id, Some(67));
    assert_eq!(login.facets.event_code, Some(45021));
    assert_eq!(
        login.summary,
        "loginwindow login by audit user 501 (uid 501, pid 67)"
    );

    let recovery = &sink.records[0];
    assert_eq!(
        recovery.facets.file_path.as_deref(),
        Some("/var/audit/20131104171720.crash_recovery")
    );
    assert_eq!(
        recovery.summary,
        "audit crash recovery: /var/audit/20131104171720.crash_recovery"
    );
}
