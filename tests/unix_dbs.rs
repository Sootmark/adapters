//! The print job and locate database adapters on plaso's test files
//! (Apache-2.0, `tests/fixtures/cups/` and `tests/fixtures/mlocate/`, see
//! their NOTICEs): recognition and records.

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, Value};
use sootmark_adapters::mlocate::MlocateAdapter;
use sootmark_adapters::printing::CupsAdapter;

fn collect(adapter: &dyn Adapter, fixture: &str, path: &str) -> Collected {
    let data = std::fs::read(format!(
        "{}/tests/fixtures/{fixture}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    assert_eq!(adapter.probe(path, &data), Confidence::Certain, "{path}");
    assert_conforms(adapter, path, &data);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name: path,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    adapter.parse(&input, &mut sink).unwrap();
    assert!(sink.skipped.is_empty(), "{:?}", sink.skipped);
    sink
}

#[test]
fn print_jobs() {
    let sink = collect(
        &CupsAdapter,
        "cups/mac_cups_ipp",
        "private/var/spool/cups/c00001",
    );
    assert_eq!(sink.records.len(), 1);
    let job = &sink.records[0];
    assert_eq!(job.summary, "moxilo printed Assignament 1 on RHULBW");
    assert_eq!(
        job.fields.get("Application"),
        Some(&Value::from("LibreOffice"))
    );
    assert_eq!(job.times.len(), 3);
    assert_eq!(
        CupsAdapter.probe(
            "notes/c00001",
            &std::fs::read(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/cups/mac_cups_ipp"
            ))
            .unwrap()
        ),
        Confidence::No
    );
}

#[test]
fn locate_directories() {
    let sink = collect(
        &MlocateAdapter,
        "mlocate/mlocate.db",
        "var/lib/mlocate/mlocate.db",
    );
    assert_eq!(sink.records.len(), 6);
    assert!(sink
        .records
        .iter()
        .any(|r| r.summary == "locate: /home/user/temp/1 (2 entries: 1a.txt, 1b.txt)"));
}
