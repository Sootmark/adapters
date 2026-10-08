//! The containers adapter on plaso's Docker and CRI test files
//! (Apache-2.0, `tests/fixtures/containers/`).

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, Value};
use sootmark_adapters::containers::{ContainersAdapter, CONTAINERS, LAYERS, LOGS};

fn collect(path: &str) -> Collected {
    let data = std::fs::read(format!(
        "{}/tests/fixtures/containers/{path}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let name = format!("var/lib/{path}");
    assert_eq!(
        ContainersAdapter.probe(&name, &data),
        Confidence::Certain,
        "{path}"
    );
    assert_conforms(&ContainersAdapter, &name, &data);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name: &name,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    ContainersAdapter.parse(&input, &mut sink).unwrap();
    assert!(sink.skipped.is_empty(), "{:?}", sink.skipped);
    sink
}

#[test]
fn containers_logs_and_layers() {
    let id = "docker/containers/e7d0b7ea5ccf08366e2b0c8afa2318674e8aefe802315378125d2bb83fe3110c";
    let container = collect(&format!("{id}/config.json"));
    assert_eq!(container.records[0].namespace(), CONTAINERS);
    assert_eq!(
        container.records[0].fields.get("Name"),
        Some(&Value::from("desperate_galileo"))
    );
    let log = collect(&format!("{id}/container-json.log"));
    // Ten lines; psort shows seven, dropping repeats.
    assert_eq!(log.records.len(), 10);
    assert!(log.records.iter().all(|r| r.namespace() == LOGS));
    let layer = collect(
        "docker/graph/3c9a9d7cc6a235eb2de58ca9ef3551c67ae42a991933ba4958d207b29142902b/json",
    );
    assert_eq!(layer.records[0].namespace(), LAYERS);
    let cri = collect("cri.log");
    assert_eq!(cri.records.len(), 17);
}
