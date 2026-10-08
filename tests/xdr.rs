//! The Defender XDR device timeline importer on exports written for these
//! tests after Microsoft's documented columns (`tests/fixtures/xdr/`).

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, Value};
use sootmark_adapters::xdr::XdrAdapter;

fn collect(name: &str) -> Collected {
    let data = std::fs::read(format!(
        "{}/tests/fixtures/xdr/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    assert_eq!(XdrAdapter.probe(name, &data), Confidence::Certain, "{name}");
    assert_conforms(&XdrAdapter, name, &data);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    XdrAdapter.parse(&input, &mut sink).unwrap();
    assert!(sink.skipped.is_empty(), "{:?}", sink.skipped);
    sink
}

#[test]
fn a_portal_timeline() {
    let sink = collect("timeline.csv");
    assert_eq!(sink.records.len(), 5);
    let process = &sink.records[0];
    assert_eq!(
        process.summary,
        "XDR ProcessCreated on fin-wks-07.contoso.example: powershell.exe -NoP -W Hidden -Enc SQBFAFgA"
    );
    assert_eq!(
        process.facets.process_path.as_deref(),
        Some(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
    );
    assert_eq!(
        process.facets.parent_process_path.as_deref(),
        Some(r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE")
    );
    assert_eq!(process.facets.user_name.as_deref(), Some(r"contoso\bob"));
    assert_eq!(
        process.times[0].ts.to_iso8601().as_deref(),
        Some("2024-03-05T09:40:01.1230000Z")
    );
    let connection = &sink.records[1];
    assert_eq!(
        connection.facets.destination_ip.as_deref(),
        Some("198.51.100.80")
    );
    assert_eq!(
        connection.facets.process_command_line.as_deref(),
        Some("powershell.exe -NoP -W Hidden -Enc SQBFAFgA")
    );
    let file = &sink.records[2];
    assert_eq!(
        file.facets.file_path.as_deref(),
        Some(r"C:\Users\bob\AppData\Roaming\upd.exe")
    );
    let registry = &sink.records[3];
    assert_eq!(
        registry.fields.get("Registry Value Name"),
        Some(&Value::from("Updater"))
    );
    assert!(sink.records[4].fields.contains_key("Additional Fields"));
}

#[test]
fn an_advanced_hunting_export() {
    let sink = collect("hunting.csv");
    let [record] = &sink.records[..] else {
        panic!("{} records", sink.records.len());
    };
    assert_eq!(
        record.facets.process_command_line.as_deref(),
        Some("whoami /all")
    );
    assert_eq!(record.facets.host_name.as_deref(), Some("fin-wks-07"));
    assert_eq!(
        record.times[0].ts.to_iso8601().as_deref(),
        Some("2024-03-05T09:40:01.1234567Z")
    );
}

#[test]
fn other_csvs_are_not_timelines() {
    assert_eq!(
        XdrAdapter.probe("x.csv", b"Timestamp,RuleTitle,Level\n"),
        Confidence::No
    );
}
