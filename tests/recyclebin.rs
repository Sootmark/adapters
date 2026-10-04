//! The Recycle Bin adapter on plaso's test files (Apache-2.0,
//! `tests/fixtures/recyclebin/`): the contract, recognition, records.

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, TimeKind};
use sootmark_adapters::recyclebin::RecycleBinAdapter;

fn parse(fixture: &str, path: &str) -> Vec<model::Record> {
    let data = std::fs::read(format!(
        "{}/tests/fixtures/recyclebin/{fixture}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    assert_eq!(RecycleBinAdapter.probe(path, &data), Confidence::Certain);
    assert_conforms(&RecycleBinAdapter, path, &data);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name: path,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    RecycleBinAdapter.parse(&input, &mut sink).unwrap();
    sink.records
}

#[test]
fn index_files_and_info2() {
    let windows10 = parse(
        "$I103S5F.jpg",
        r"C:\$Recycle.Bin\S-1-5-21-1-2-3-1001\$I103S5F.jpg",
    );
    assert_eq!(
        windows10[0].summary,
        r"Deleted to the Recycle Bin: C:\Users\random\Downloads\bunnies.jpg"
    );
    assert_eq!(windows10[0].times[0].kind, TimeKind::Deleted);
    assert_eq!(
        windows10[0].facets.user_sid.as_deref(),
        Some("S-1-5-21-1-2-3-1001")
    );
    let xp = parse("INFO2", r"C:\RECYCLER\S-1-5-21-9-1004\INFO2");
    assert_eq!(xp.len(), 4);
}
