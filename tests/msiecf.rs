//! The `index.dat` adapter on plaso's test files (Apache-2.0,
//! `tests/fixtures/msiecf/`): recognition, the contract, cache, history
//! and daily history records with their times named for what they mean.

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, TimeKind, Value};
use sootmark_adapters::msiecf::{MsiecfAdapter, NAMESPACE};

fn collect(fixture: &str, path: &str) -> Collected {
    let data = std::fs::read(format!(
        "{}/tests/fixtures/msiecf/{fixture}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    assert_eq!(MsiecfAdapter.probe(path, &data), Confidence::Certain);
    assert_conforms(&MsiecfAdapter, path, &data);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name: path,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    MsiecfAdapter.parse(&input, &mut sink).unwrap();
    assert!(sink.skipped.is_empty(), "{:?}", sink.skipped);
    assert!(sink.records.iter().all(|r| r.namespace() == NAMESPACE));
    sink
}

#[test]
fn cache_records() {
    let sink = collect(
        "Content.IE5/index.dat",
        r"C\Users\alice\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5\index.dat",
    );
    assert_eq!(sink.records.len(), 35);
    let icon = &sink.records[0];
    assert_eq!(
        icon.summary,
        "IE cache: http://static-hp-neu.s-msn.com/sc/54/4f1880.ico (1 hits)"
    );
    assert_eq!(icon.times[0].kind, TimeKind::Accessed);
    assert_eq!(icon.times[1].kind, TimeKind::Modified);
    assert_eq!(icon.facets.user_name.as_deref(), Some("alice"));
    assert!(icon.facets.file_path.is_some());
}

#[test]
fn history_with_the_account() {
    let sink = collect("History.IE5/index.dat", "History.IE5/index.dat");
    assert_eq!(sink.records.len(), 17);
    let visit = &sink.records[0];
    assert_eq!(
        visit.summary,
        "IE history (gold_administrator): http://www.msn.com/?ocid=iehp (1 hits)"
    );
    assert_eq!(
        visit.facets.user_name.as_deref(),
        Some("gold_administrator")
    );
    assert_eq!(visit.times[0].kind, TimeKind::LastSeen);
    let sink = collect(
        "MSHist012013031020130311-index.dat",
        "MSHist012013031020130311/index.dat",
    );
    assert_eq!(sink.records.len(), 23);
    assert_eq!(
        sink.records[0].fields.get("Usage"),
        Some(&Value::from("daily history"))
    );
    assert_eq!(sink.records[0].facets.user_name, None);
}
