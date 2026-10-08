//! The ESXi adapter on files written for the sootmark-esxi tests
//! (`tests/fixtures/esxi/`): recognition and records.

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, Value};
use sootmark_adapters::esxi::{EsxiAdapter, HOST, INVENTORY, SNAPSHOT, VM};

fn collect(fixture: &str, path: &str) -> Collected {
    let data = std::fs::read(format!(
        "{}/tests/fixtures/esxi/{fixture}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    assert_eq!(
        EsxiAdapter.probe(path, &data),
        Confidence::Certain,
        "{path}"
    );
    assert_conforms(&EsxiAdapter, path, &data);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name: path,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    EsxiAdapter.parse(&input, &mut sink).unwrap();
    assert!(sink.skipped.is_empty(), "{:?}", sink.skipped);
    sink
}

#[test]
fn host_inventory_vm_and_snapshots() {
    let host = collect("esx.conf", "etc/vmware/esx.conf");
    assert_eq!(host.records.len(), 1);
    assert_eq!(host.records[0].namespace(), HOST);
    assert_eq!(
        host.records[0].fields.get("SshAllowed"),
        Some(&Value::Bool(true))
    );
    assert_eq!(
        host.records[0].facets.host_name.as_deref(),
        Some("esxi01.example.com")
    );

    let inventory = collect("vmInventory.xml", "etc/vmware/hostd/vmInventory.xml");
    assert_eq!(inventory.records.len(), 3);
    assert!(inventory.records.iter().all(|r| r.namespace() == INVENTORY));

    let vm = collect("dc01.vmx", "vmfs/volumes/ds1/dc01/dc01.vmx");
    assert_eq!(vm.records[0].namespace(), VM);
    assert_eq!(
        vm.records[0].fields.get("VncPort"),
        Some(&Value::UInt(5901))
    );
    assert_eq!(
        vm.records[0].summary,
        "ESXi VM dc01 \"primary\" DC (windows2019srv-64), console open to VNC"
    );

    let snapshots = collect("dc01.vmsd", "vmfs/volumes/ds1/dc01/dc01.vmsd");
    assert_eq!(snapshots.records.len(), 2);
    assert!(snapshots.records.iter().all(|r| r.namespace() == SNAPSHOT));
    assert_eq!(
        snapshots.records[1].fields.get("Current"),
        Some(&Value::Bool(true))
    );
}

#[test]
fn other_files_are_not_esxi() {
    assert_eq!(EsxiAdapter.probe("notes.txt", b"a = b"), Confidence::No);
    assert_eq!(
        EsxiAdapter.probe("x.vmx", b"\x00\x01binary"),
        Confidence::No
    );
}
