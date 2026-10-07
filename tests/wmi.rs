//! The WMI adapter on flare-wmi's wmikatz repository (Apache-2.0, a
//! Windows 7 repository, downloaded by `tests/fetch-wmi.sh`; skipped
//! without it): recognition, the companion files, and a record per filter,
//! consumer and binding.

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Companion, Confidence, Input};
use model::{EvidenceId, Value};
use sootmark_adapters::wmi::WmiAdapter;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/wmi");

#[test]
fn subscriptions_of_a_repository() {
    let read = |file: &str| std::fs::read(format!("{DIR}/{file}")).ok();
    let Some(objects) = read("OBJECTS.DATA") else {
        return;
    };
    let path = "C/Windows/System32/wbem/Repository/OBJECTS.DATA";
    assert_eq!(
        WmiAdapter.probe(path, &objects[..8192]),
        Confidence::Certain
    );
    assert_eq!(
        WmiAdapter.probe("C/x/INDEX.BTR", &objects[..8192]),
        Confidence::No
    );
    assert_eq!(WmiAdapter.companions(path).len(), 4);
    let names = WmiAdapter.companions(path);
    let files: Vec<(String, Vec<u8>)> = names
        .iter()
        .map(|name| (name.clone(), read(name).unwrap()))
        .collect();
    let companions: Vec<Companion<'_>> = files
        .iter()
        .map(|(name, data)| Companion { name, data })
        .collect();
    let input = Input {
        evidence: EvidenceId::of_content(&objects),
        name: path,
        data: &objects,
        modified: None,
    };
    // Alone, the file can't be read.
    let mut alone = Collected::default();
    assert!(WmiAdapter.parse(&input, &mut alone).is_err());
    assert_conforms(&WmiAdapter, path, &objects);

    let mut sink = Collected::default();
    WmiAdapter
        .parse_with_companions(&input, &companions, &mut sink)
        .unwrap();
    assert!(sink.skipped.is_empty(), "{:?}", sink.skipped);
    let kinds: Vec<&Value> = sink
        .records
        .iter()
        .filter_map(|r| r.fields.get("Kind"))
        .collect();
    assert_eq!(kinds.len(), 6);
    let binding = sink
        .records
        .iter()
        .find(|r| {
            r.fields.get("Kind") == Some(&Value::from("binding"))
                && r.fields.get("ConsumerClass") == Some(&Value::from("CommandLineEventConsumer"))
        })
        .unwrap();
    assert_eq!(
        binding.summary,
        "WMI subscription (root\\subscription): when SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA \"Win32_Processor\" AND TargetInstance.LoadPercentage > 99 run CommandLineEventConsumer: cscript KernCap.vbs"
    );
    assert_eq!(
        binding.facets.process_command_line.as_deref(),
        Some("cscript KernCap.vbs")
    );
    let consumer = sink
        .records
        .iter()
        .find(|r| r.fields.get("Class") == Some(&Value::from("CommandLineEventConsumer")))
        .unwrap();
    assert_eq!(
        consumer.facets.user_sid.as_deref(),
        Some("S-1-5-21-3111613574-2524581245-2586426736-500"),
        "{:?}",
        consumer.fields
    );
}
