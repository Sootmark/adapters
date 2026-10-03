//! The EVTX adapter keeps the adapter contract on real logs: five of
//! EVTX-to-MITRE-Attack (CC0, `tests/fixtures/cc0/`): Security, System,
//! Sysmon and `PowerShell`.

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Input};
use model::{EvidenceId, TimeKind};
use sootmark_adapters::evtx::{EvtxAdapter, NAMESPACE};

const LOGS: [&str; 5] = [
    "ID4624-Mimikatz Pass the hash.evtx",
    "ID4648-4624-RunAsCS login.evtx",
    "ID1-SYSMON driver unload (FilterManager).evtx",
    "ID1-WMI spwaning PowerShell process - WMImplant.evtx",
    "ID4103-4104-Payload download via PowerShell.evtx",
];

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/cc0/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn parse(bytes: &[u8]) -> Collected {
    let input = Input {
        evidence: EvidenceId::of_content(bytes),
        name: "Security.evtx",
        data: bytes,
        modified: None,
    };
    let mut sink = Collected::default();
    EvtxAdapter
        .parse(&input, &mut sink)
        .expect("a readable log");
    sink
}

#[test]
fn conforms_on_real_logs() {
    for name in LOGS {
        assert_conforms(&EvtxAdapter, name, &fixture(name));
    }
}

#[test]
fn maps_every_event_with_its_time_and_facets() {
    let output = parse(&fixture(LOGS[0]));
    assert_eq!(output.records.len(), 8);
    assert!(output.skipped.is_empty());
    for record in &output.records {
        assert_eq!(record.namespace(), NAMESPACE);
        assert_eq!(record.times.len(), 1);
        assert_eq!(record.times[0].kind, TimeKind::Logged);
        assert_eq!(record.times[0].field, "TimeCreated");
        assert!(record.facets.event_code.is_some());
        assert_eq!(record.facets.channel.as_deref(), Some("Security"));
    }
}

#[test]
fn rejects_files_that_are_not_event_logs() {
    let bytes = b"not an event log at all".to_vec();
    let input = Input {
        evidence: EvidenceId::of_content(&bytes),
        name: "x.evtx",
        data: &bytes,
        modified: None,
    };
    let error = EvtxAdapter
        .parse(&input, &mut Collected::default())
        .unwrap_err();
    assert_eq!(error.offset, Some(0));
}
