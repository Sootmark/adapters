//! The `.evt` adapter on plaso's `SysEvent.Evt` (Apache-2.0,
//! `tests/fixtures/evt/`, stored gzip-compressed): recognition, the
//! contract, and records shaped as the `.evtx` adapter's.

use std::io::Read;

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, TimeKind, Value};
use sootmark_adapters::evt::{EvtAdapter, NAMESPACE};

const PATH: &str = r"C\WINDOWS\system32\config\SysEvent.Evt";

fn log() -> Vec<u8> {
    let compressed = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/evt/SysEvent.Evt.gz"
    ))
    .unwrap();
    let mut data = Vec::new();
    common::gzip::Decoder::new(compressed.as_slice())
        .read_to_end(&mut data)
        .unwrap();
    data
}

#[test]
fn events_with_codes_sources_and_channel() {
    let data = log();
    assert_eq!(EvtAdapter.probe(PATH, &data[..4096]), Confidence::Certain);
    assert_eq!(EvtAdapter.probe("x.evt", b"not a log"), Confidence::No);
    assert_conforms(&EvtAdapter, PATH, &data);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name: PATH,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    EvtAdapter.parse(&input, &mut sink).unwrap();
    // One record's length copy is damaged: reported, the rest read.
    assert_eq!(sink.skipped.len(), 1);
    assert_eq!(sink.records.len(), 6501);
    assert!(sink.records.iter().all(|r| r.namespace() == NAMESPACE));
    assert!(sink
        .records
        .iter()
        .all(|r| r.facets.channel.as_deref() == Some("System")));
    let first = &sink.records[0];
    assert_eq!(first.facets.event_code, Some(40961));
    assert_eq!(first.facets.provider.as_deref(), Some("LSASRV"));
    assert_eq!(first.facets.host_name.as_deref(), Some("WKS-WINXP32BIT"));
    assert_eq!(first.fields.get("EventType"), Some(&Value::from("Warning")));
    assert_eq!(
        first.fields.get("String1"),
        Some(&Value::from("cifs/CONTROLLER"))
    );
    assert_eq!(first.times[0].kind, TimeKind::Logged);
    assert!(first
        .summary
        .starts_with("40961 LSASRV · cifs/CONTROLLER · "));
    assert!(!first.summary.contains('\n'));
    assert!(sink.records.iter().any(|r| r.flags.recovered));
}
