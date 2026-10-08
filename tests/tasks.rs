//! The scheduled task adapter on a task XML file written for the
//! sootmark-tasks tests and plaso's `.job` file (Apache-2.0), in
//! `tests/fixtures/tasks/`, stored gzip-compressed.

use std::io::Read;

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, Record, Value};
use sootmark_adapters::tasks::{TasksAdapter, JOB, XML};

fn fixture(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/tests/fixtures/tasks/{name}.gz",
        env!("CARGO_MANIFEST_DIR")
    );
    let compressed = std::fs::read(path).unwrap();
    let mut data = Vec::new();
    common::gzip::Decoder::new(compressed.as_slice())
        .read_to_end(&mut data)
        .unwrap();
    data
}

fn parse(name: &str, data: &[u8]) -> Record {
    assert_conforms(&TasksAdapter, name, data);
    let input = Input {
        evidence: EvidenceId::of_content(data),
        name,
        data,
        modified: None,
    };
    let mut sink = Collected::default();
    TasksAdapter.parse(&input, &mut sink).unwrap();
    assert!(sink.skipped.is_empty(), "{:?}", sink.skipped);
    assert_eq!(sink.records.len(), 1);
    sink.records.remove(0)
}

#[test]
fn a_task_xml_file() {
    let data = fixture("OneDriveSync");
    let name = "C/Windows/System32/Tasks/Microsoft/Windows/SyncCenter/OneDriveSync";
    assert_eq!(TasksAdapter.probe(name, &data[..512]), Confidence::Certain);
    assert_eq!(
        TasksAdapter.probe("C/x/sync.xml", &data[..512]),
        Confidence::Maybe
    );
    let record = parse(name, &data);
    assert_eq!(record.namespace(), XML);
    assert_eq!(
        record.summary,
        r"Scheduled task \Microsoft\Windows\SyncCenter\OneDriveSync: %SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoP -W Hidden -Enc SQBFAFgA, hidden"
    );
    assert_eq!(record.fields.get("Hidden"), Some(&Value::Bool(true)));
    assert_eq!(
        record.fields.get("RunLevel"),
        Some(&Value::from("HighestAvailable"))
    );
    assert_eq!(
        record.fields.get("ComClassId"),
        Some(&Value::from("{A6BA00FE-40E8-477C-B713-C64A14F18ADB}"))
    );
    assert_eq!(record.facets.user_name.as_deref(), Some("S-1-5-18"));
    assert_eq!(
        record.facets.process_command_line.as_deref(),
        Some(
            r"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoP -W Hidden -Enc SQBFAFgA"
        )
    );
    let Some(Value::List(triggers)) = record.fields.get("Triggers") else {
        panic!("no triggers");
    };
    assert_eq!(
        triggers,
        &[
            Value::from("Calendar every PT15M"),
            Value::from("Boot (disabled)"),
            Value::from("Event"),
            Value::from("Logon"),
        ]
    );
    assert_eq!(record.times.len(), 2);
}

#[test]
fn a_job_file() {
    let data = fixture("wintask.job");
    let name = "C/Windows/Tasks/GoogleUpdateTaskMachineCore.job";
    assert_eq!(TasksAdapter.probe(name, &data[..128]), Confidence::Certain);
    let record = parse(name, &data);
    assert_eq!(record.namespace(), JOB);
    assert_eq!(
        record.summary,
        r"Scheduled job GoogleUpdateTaskMachineCore.job: C:\Program Files (x86)\Google\Update\GoogleUpdate.exe /ua /installsource scheduler"
    );
    assert_eq!(
        record.fields.get("StatusName"),
        Some(&Value::from("SCHED_S_TASK_READY"))
    );
    assert_eq!(record.facets.user_name.as_deref(), Some("Brian"));
    assert_eq!(
        record.times[0].ts.to_iso8601().as_deref(),
        Some("2013-08-24T12:42:00.1120000")
    );
}

#[test]
fn other_files_are_not_tasks() {
    assert_eq!(TasksAdapter.probe("x", b"<plist/>"), Confidence::No);
}
