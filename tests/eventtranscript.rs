//! The diagnostic data adapter on a database derived from plaso's
//! `EventTranscript.db` (Apache-2.0, `tests/fixtures/eventtranscript/`):
//! recognition and records.

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::EvidenceId;
use sootmark_adapters::eventtranscript::{EventTranscriptAdapter, NAMESPACE};

#[test]
fn telemetry_events() {
    let data = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/eventtranscript/EventTranscript.db"
    ))
    .unwrap();
    let name = "C/ProgramData/Microsoft/Diagnosis/EventTranscript/EventTranscript.db";
    assert_eq!(
        EventTranscriptAdapter.probe(name, &data[..100]),
        Confidence::Certain
    );
    assert_conforms(&EventTranscriptAdapter, name, &data);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    EventTranscriptAdapter.parse(&input, &mut sink).unwrap();
    assert!(sink.skipped.is_empty(), "{:?}", sink.skipped);
    assert_eq!(sink.records.len(), 30);
    assert!(sink.records.iter().all(|r| r.namespace() == NAMESPACE));
    assert!(sink.records.iter().any(|r| r
        .summary
        .starts_with("Diagnostic data HJ_NavigateCompleteExtended: http")));
}
