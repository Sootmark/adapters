//! The protection log adapter on a log written as Defender writes them
//! (`tests/fixtures/mplog/`, see `NOTICE`): recognition and records.

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, Value};
use sootmark_adapters::mplog::{MpLogAdapter, NAMESPACE};

#[test]
fn protection_log_entries() {
    let data = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/mplog/MPLog-20231219-093000.log"
    ))
    .unwrap();
    let name = r"C\ProgramData\Microsoft\Windows Defender\Support\MPLog-20231219-093000.log";
    assert_eq!(MpLogAdapter.probe(name, &data[..64]), Confidence::Certain);
    assert_eq!(
        MpLogAdapter.probe("MpCmdRun.log", &data[..64]),
        Confidence::No
    );
    assert_conforms(&MpLogAdapter, name, &data);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    MpLogAdapter.parse(&input, &mut sink).unwrap();
    assert!(sink.skipped.is_empty(), "{:?}", sink.skipped);
    assert_eq!(sink.records.len(), 23);
    assert!(sink.records.iter().all(|r| r.namespace() == NAMESPACE));

    let kind = |k: &'static str| {
        sink.records
            .iter()
            .filter(move |r| r.fields.get("Kind") == Some(&Value::from(k)))
    };
    let impact = kind("EstimatedImpact").next().unwrap();
    assert_eq!(
        impact.facets.process_path.as_deref(),
        Some("powershell.exe")
    );
    assert_eq!(impact.facets.process_id, Some(7968));
    let lowfi = kind("Lowfi").next().unwrap();
    assert!(lowfi
        .facets
        .process_command_line
        .as_deref()
        .unwrap()
        .contains("UseLogonCredential"));
    let added = kind("DetectionAdd").next().unwrap();
    assert_eq!(
        added.summary,
        r"Defender MPLog DetectionAdd: HackTool:Win32/Example!MSR in C:\Users\alice\Videos\tool.exe"
    );
    let rtp = kind("RtpPerf").next().unwrap();
    assert_eq!(
        rtp.fields.get("PathExclusion"),
        Some(&Value::from(r"C:\Tools\*; %windir%\Temp\*.ps1"))
    );
}
