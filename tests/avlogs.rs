//! The antivirus log adapter on plaso's test logs (Apache-2.0,
//! `tests/fixtures/avlogs/`).

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, Value};
use sootmark_adapters::avlogs::{AvlogsAdapter, NAMESPACE};

fn collect(name: &str) -> Collected {
    let data = std::fs::read(format!(
        "{}/tests/fixtures/avlogs/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    assert_eq!(
        AvlogsAdapter.probe(name, &data),
        Confidence::Certain,
        "{name}"
    );
    assert_conforms(&AvlogsAdapter, name, &data);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    AvlogsAdapter.parse(&input, &mut sink).unwrap();
    assert!(sink.skipped.is_empty(), "{:?}", sink.skipped);
    sink
}

#[test]
fn antivirus_entries() {
    let mcafee = collect("AccessProtectionLog.txt");
    assert_eq!(mcafee.records.len(), 14);
    assert!(mcafee.records.iter().all(|r| r.namespace() == NAMESPACE));
    let symantec = collect("Symantec.Log");
    let virus = symantec
        .records
        .iter()
        .find(|r| r.fields.get("Threat") == Some(&Value::from("W32.Changeup!gen33")))
        .unwrap();
    assert_eq!(
        virus.facets.file_path.as_deref(),
        Some(r"D:\Twinkle_Prod$\VM11 XXX\outside\test.exe.txt")
    );
    let sophos = collect("sav.txt");
    assert_eq!(sophos.records.len(), 9);
    assert!(sophos
        .records
        .iter()
        .any(|r| r.summary.starts_with("Sophos: EICAR-AV-Test")));
}
