//! The BITS adapter on the `sootmark-bits` test queues, gzip-compressed:
//! go-ese's Windows 11 `qmgr.db` (Apache-2.0, `tests/fixtures/bits/go-ese/`)
//! and the `qmgr0.dat` and `qmgr1.dat` of NIST CFReDS's Data Leakage Case
//! (Windows 7, public domain, `tests/fixtures/bits/cfreds/`): the contract,
//! recognition, a record per job (the carved ones included, as many as the
//! crate's tests count) and per file, with the facets hunts use.

use std::io::Read;

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, Record, TimeKind, Value};
use sootmark_adapters::bits::{BitsAdapter, FILES, JOBS};

const DOWNLOADER: &str = "C/ProgramData/Microsoft/Network/Downloader";

/// The fixture `tests/fixtures/bits/<folder>/<name>.gz`, decompressed.
fn queue(folder: &str, name: &str) -> Vec<u8> {
    let path = format!(
        "{}/tests/fixtures/bits/{folder}/{name}.gz",
        env!("CARGO_MANIFEST_DIR")
    );
    let compressed = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let mut data = Vec::new();
    common::gzip::Decoder::new(compressed.as_slice())
        .read_to_end(&mut data)
        .unwrap();
    data
}

/// The queue's records, split into jobs and files, and what was skipped.
fn parse(folder: &str, name: &str) -> (Vec<Record>, Vec<Record>, Vec<String>) {
    let data = queue(folder, name);
    let path = format!("{DOWNLOADER}/{name}");
    assert_eq!(
        BitsAdapter.probe(&path, &data[..4096]),
        Confidence::Certain,
        "{name}"
    );
    assert_conforms(&BitsAdapter, &path, &data);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name: &path,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    BitsAdapter.parse(&input, &mut sink).unwrap();
    let (jobs, files): (Vec<Record>, Vec<Record>) = sink
        .records
        .into_iter()
        .partition(|r| r.namespace() == JOBS);
    assert!(files.iter().all(|r| r.namespace() == FILES));
    let skipped = sink.skipped.into_iter().map(|s| s.reason).collect();
    (jobs, files, skipped)
}

fn text<'r>(record: &'r Record, name: &str) -> Option<&'r str> {
    match record.fields.get(name)? {
        Value::Text(text) => Some(text),
        _ => None,
    }
}

fn time(record: &Record, field: &str) -> String {
    let time = record.times.iter().find(|t| t.field == field).unwrap();
    time.ts.to_iso8601().unwrap()
}

fn is_carved(record: &Record) -> bool {
    text(record, "Origin") == Some("carved")
}

#[test]
fn windows_11_database() {
    let data = queue("go-ese", "qmgr.db");
    assert_eq!(
        BitsAdapter.probe("C/Windows/System32/sru/SRUDB.dat", &data[..4096]),
        Confidence::No
    );
    let (jobs, files, skipped) = parse("go-ese", "qmgr.db");
    assert_eq!(
        skipped,
        ["dirty shutdown: changes still only in the transaction log files are missing (logs are not replayed)"]
    );
    // The Jobs table's job and the 55 carved from free pages; the live
    // job's file, 4 carved files that carved jobs list and the 80 no job
    // claims. With the queue files' 2 and 2, the crate's 60 jobs.
    assert_eq!(jobs.len(), 56);
    assert_eq!(jobs.iter().filter(|r| is_carved(r)).count(), 55);
    assert_eq!(files.len(), 85);
    assert_eq!(files.iter().filter(|r| is_carved(r)).count(), 84);
    assert!(jobs
        .iter()
        .chain(&files)
        .all(|r| r.flags.recovered == is_carved(r)));

    let job = &jobs[0];
    assert_eq!(
        job.summary,
        "BITS download job \"Edge Component Updater\" (Transferred), 1 file, owner S-1-5-21-549467458-3727351111-1684278619-1001"
    );
    assert_eq!(
        job.facets.user_sid.as_deref(),
        Some("S-1-5-21-549467458-3727351111-1684278619-1001")
    );
    assert_eq!(job.facets.process_path, None, "no notify command");
    assert_eq!(
        text(job, "JobId"),
        Some("d387e452-e2b3-472d-b3b3-85c2be33cbb3")
    );
    assert_eq!(
        (text(job, "Kind"), text(job, "State"), text(job, "Priority")),
        (Some("Download"), Some("Transferred"), Some("Normal"))
    );
    assert_eq!(job.fields.get("Page"), Some(&Value::UInt(31)));
    assert_eq!(time(job, "Completed"), "2024-07-30T07:19:08.7576073Z");
    assert_eq!(time(job, "Expires"), "2024-10-28T07:19:08.7576073Z");

    let file = &files[0];
    assert_eq!(
        text(file, "JobId"),
        Some("d387e452-e2b3-472d-b3b3-85c2be33cbb3")
    );
    assert_eq!(
        file.facets.file_path.as_deref(),
        Some(
            r"C:\Users\bob\AppData\Local\Temp\edge_BITS_2972_515758394\2132f61f-f790-4ae6-a355-8cf9a1533800"
        )
    );
    assert!(text(file, "RemoteUrl").unwrap().starts_with(
        "http://msedge.b.tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files/2132f61f-"
    ));
    assert_eq!(
        text(file, "TempPath"),
        Some(r"C:\Users\bob\AppData\Local\Temp\edge_BITS_2972_515758394\BIT2B52.tmp")
    );
    assert_eq!(
        (
            file.fields.get("BytesTransferred"),
            file.fields.get("BytesTotal")
        ),
        (Some(&Value::UInt(975_576)), Some(&Value::UInt(975_576)))
    );
    assert_eq!(file.times[0].kind, TimeKind::Modified);
    assert_eq!(
        time(file, "RemoteLastModified"),
        "2022-03-08T02:44:10.0000000Z"
    );
}

#[test]
fn windows_7_queue_files() {
    let (listed, listed_files, skipped) = parse("cfreds", "qmgr1.dat");
    assert!(skipped.is_empty(), "{skipped:?}");
    assert_eq!((listed.len(), listed_files.len()), (2, 4));
    let job = &listed[0];
    assert_eq!(text(job, "Name"), Some("Setup Installer"));
    assert_eq!(text(job, "Priority"), Some("Foreground"));
    assert_eq!(job.fields.get("Offset"), Some(&Value::UInt(68)));
    assert!(!job.flags.recovered);
    assert!(is_carved(&listed[1]));

    let (carved, carved_files, skipped) = parse("cfreds", "qmgr0.dat");
    assert!(skipped.is_empty(), "{skipped:?}");
    assert_eq!((carved.len(), carved_files.len()), (2, 4));
    assert!(carved.iter().all(|r| is_carved(r) && r.flags.recovered));
    // The listed job before its transfer ended, its start overwritten.
    let older = &carved[0];
    assert_eq!(older.fields.get("Offset"), Some(&Value::UInt(136)));
    assert_eq!(text(older, "Name"), None);
    assert_eq!(older.facets.user_sid, job.facets.user_sid);
    assert_eq!(
        older.summary,
        "Carved BITS job (name lost), 1 file, owner S-1-5-21-2425377081-3129163575-2985601102-1000"
    );
    // The Outlook address book download whose first file lost its start.
    let damaged = carved_files.iter().find(|r| r.flags.corrupted).unwrap();
    assert_eq!(damaged.fields.get("Damaged"), Some(&Value::Bool(true)));
    assert_eq!(
        text(damaged, "TempPath"),
        Some(r"cf15-73c9-4426-8bf9-3f5b9b52ce92\BIT9A34.tmp")
    );
    for file in listed_files.iter().chain(&carved_files) {
        assert_eq!(text(file, "VolumeSerial"), Some("CA0C-7A48"));
    }
}
