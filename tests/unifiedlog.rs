//! The unified log adapter on the `unifiedlog` crate's fixtures: five small
//! log archives cut from Mandiant's macos-UnifiedLogs test data
//! (Apache-2.0, `tests/fixtures/unifiedlog/`, every file gzipped), read
//! with their timesync and strings files from the collection.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::PathBuf;
use std::sync::OnceLock;

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Collection, Confidence, Input};
use model::{EvidenceId, Record, Value};
use sootmark_adapters::unifiedlog::{UnifiedLogAdapter, NAMESPACE};

/// The fixtures, by name.
const FIXTURES: [&str; 5] = [
    "big_sur",
    "big_sur_private",
    "high_sierra",
    "monterey",
    "tahoe",
];
/// The folders tracev3 files are in.
const TRACE_FOLDERS: [&str; 4] = ["HighVolume", "Persist", "Signpost", "Special"];

/// The fixtures as a collection: paths are `<fixture>/<path in archive>`,
/// each file stored with `.gz` added.
struct Fixtures(PathBuf);

impl Fixtures {
    fn new() -> Self {
        Self(PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/unifiedlog"
        )))
    }

    /// The tracev3 files of a fixture, by path.
    fn tracev3_files(&mut self, fixture: &str) -> Vec<String> {
        TRACE_FOLDERS
            .iter()
            .flat_map(|folder| self.list(&format!("{fixture}/{folder}")))
            .collect()
    }
}

impl Collection for Fixtures {
    fn read(&mut self, path: &str) -> Option<Vec<u8>> {
        let raw = std::fs::read(self.0.join(format!("{path}.gz"))).ok()?;
        let mut data = Vec::new();
        common::gzip::Decoder::new(raw.as_slice())
            .read_to_end(&mut data)
            .ok()?;
        Some(data)
    }

    fn list(&mut self, folder: &str) -> Vec<String> {
        let mut paths: Vec<String> = std::fs::read_dir(self.0.join(folder))
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter_map(|name| Some(format!("{folder}/{}", name.strip_suffix(".gz")?)))
            .collect();
        paths.sort();
        paths
    }
}

/// The records of a tracev3 file, read with the rest of `collection`.
fn parse(name: &str, data: &[u8], collection: &mut dyn Collection) -> Collected {
    let input = Input {
        evidence: EvidenceId::of_content(data),
        name,
        data,
        modified: None,
    };
    let mut sink = Collected::default();
    UnifiedLogAdapter
        .parse_with_collection(&input, collection, &mut sink)
        .unwrap();
    sink
}

/// Every fixture's records, by fixture; read once, as the strings files
/// are large (the shared cache strings files are 20 to 160 MB).
fn fixture_records() -> &'static BTreeMap<&'static str, Vec<Record>> {
    static RECORDS: OnceLock<BTreeMap<&'static str, Vec<Record>>> = OnceLock::new();
    RECORDS.get_or_init(|| {
        let mut fixtures = Fixtures::new();
        FIXTURES
            .into_iter()
            .map(|fixture| {
                let mut records = Vec::new();
                for path in fixtures.tracev3_files(fixture) {
                    let data = fixtures.read(&path).unwrap();
                    let sink = parse(&path, &data, &mut fixtures);
                    assert!(sink.skipped.is_empty(), "{path}: {:?}", sink.skipped);
                    records.extend(sink.records);
                }
                (fixture, records)
            })
            .collect()
    })
}

fn text<'r>(record: &'r Record, field: &str) -> Option<&'r str> {
    match record.fields.get(field) {
        Some(Value::Text(text)) => Some(text),
        _ => None,
    }
}

#[test]
fn recognised_by_name_and_header() {
    let mut fixtures = Fixtures::new();
    let data = fixtures
        .read("big_sur/Special/0000000000000001.tracev3")
        .unwrap();
    let name = "private/var/db/diagnostics/Special/0000000000000001.tracev3";
    let adapter = UnifiedLogAdapter;
    assert_eq!(adapter.probe(name, &data[..64]), Confidence::Certain);
    assert_eq!(
        adapter.probe("0000000000000001.bin", &data[..64]),
        Confidence::No
    );
    assert_eq!(adapter.probe(name, b"not a tracev3 file"), Confidence::No);
}

#[test]
fn every_entry_of_the_fixtures() {
    let fixtures = fixture_records();
    let counts: Vec<usize> = fixtures.values().map(Vec::len).collect();
    // As the `unifiedlog` crate, and Mandiant's reader, give them.
    assert_eq!(counts.iter().sum::<usize>(), 10_081, "{counts:?}");
    for record in fixtures.values().flatten() {
        assert_eq!(record.namespace(), NAMESPACE);
        assert_eq!(record.times.len(), 1, "{record:?}");
        assert!(record.facets.process_id.is_some());
        assert!(record.fields.contains_key("BootUuid"));
    }
    let with_message = fixtures
        .values()
        .flatten()
        .filter(|r| text(r, "Message").is_some())
        .count();
    assert!(with_message > 9_500, "{with_message}");
    // Entries whose values are in an oversize chunk no file of the fixture
    // holds (as with the `unifiedlog` crate reading the whole archive):
    // still records, last, saying so.
    let high_sierra = &fixtures["high_sierra"];
    let late = &high_sierra[high_sierra.len() - 3..];
    for record in late {
        assert!(text(record, "Missing").is_some_and(|m| m.starts_with("no oversize chunk")));
        assert!(text(record, "Message").is_some_and(|m| m.contains("<Missing message data>")));
    }
}

#[test]
fn messages_as_apple_shows_them() {
    let fixtures = fixture_records();
    // Fixture, thread, format string and the message Apple's `log show`
    // (macOS 26) gives for the entry (`tests/oracle/apple.tsv.gz` in the
    // `unifiedlog` repository).
    let apple = [
        (
            "big_sur",
            855,
            "%{public}s starting with schema version %llu for effective user %llu",
            "lsd starting with schema version 2548 for effective user 0",
        ),
        (
            "high_sierra",
            3074,
            "Device Information: %@",
            "Device Information: Production: Mac (VMware7,1), Mac OS X 10.13.6 (17G66), no battery",
        ),
        (
            "monterey",
            3819,
            "%s[%d] SetInterfaceRank(%s) = %s (%u)",
            "configd[290] SetInterfaceRank(en1) = Never (3)",
        ),
        (
            "tahoe",
            2681,
            "\"Client is not entitled account type %@\"",
            "\"Client is not entitled account type com.apple.account.Exchange\"",
        ),
        (
            "big_sur_private",
            715,
            "Inserted load info for %d in-kernel extensions.",
            "Inserted load info for 463 in-kernel extensions.",
        ),
    ];
    for (fixture, thread, format, message) in apple {
        let found: Vec<&Record> = fixtures[fixture]
            .iter()
            .filter(|r| {
                r.fields.get("ThreadId") == Some(&Value::UInt(thread))
                    && text(r, "FormatString") == Some(format)
            })
            .collect();
        assert_eq!(found.len(), 1, "{fixture} {thread} {format}");
        assert_eq!(text(found[0], "Message"), Some(message));
    }
}

#[test]
fn a_record_names_its_process_and_where_it_logged() {
    let fixtures = fixture_records();
    let record = fixtures["big_sur"]
        .iter()
        .find(|r| {
            text(r, "Message") == Some("lsd starting with schema version 2548 for effective user 0")
        })
        .unwrap();
    assert_eq!(
        record.facets.process_path.as_deref(),
        Some("/usr/libexec/lsd")
    );
    assert_eq!(text(record, "Process"), Some("/usr/libexec/lsd"));
    assert_eq!(text(record, "EventType"), Some("Log"));
    assert_eq!(text(record, "LogType"), Some("Default"));
    assert_eq!(record.fields.get("Euid"), Some(&Value::UInt(0)));
    assert!(record.fields.contains_key("ProcessUuid"));
    assert!(record.fields.contains_key("Subsystem"));
    assert_eq!(
        record.summary,
        "lsd: lsd starting with schema version 2548 for effective user 0"
    );
    let signpost = fixtures["big_sur_private"]
        .iter()
        .find(|r| text(r, "EventType") == Some("Signpost"))
        .unwrap();
    assert!(signpost.fields.contains_key("SignpostId"));
    assert!(signpost.fields.contains_key("SignpostNameReference"));
}

#[test]
fn read_from_a_disk_layout() {
    // The big_sur archive's files where macOS keeps them: tracev3 and
    // timesync files in diagnostics/, strings files in uuidtext/.
    let mut fixtures = Fixtures::new();
    let mut paths = vec!["big_sur/timesync".to_owned(), "big_sur/dsc".to_owned()];
    paths.extend((0..=0xff).map(|byte| format!("big_sur/{byte:02X}")));
    let files: Vec<String> = paths.iter().flat_map(|f| fixtures.list(f)).collect();
    let mut disk = BTreeMap::new();
    for path in files {
        let inside = path.strip_prefix("big_sur/").unwrap();
        let place = if inside.starts_with("timesync/") {
            format!("private/var/db/diagnostics/{inside}")
        } else {
            format!("private/var/db/uuidtext/{inside}")
        };
        disk.insert(place, fixtures.read(&path).unwrap());
    }
    let archive_path = "big_sur/Special/0000000000000001.tracev3";
    let data = fixtures.read(archive_path).unwrap();
    let from_archive = parse(archive_path, &data, &mut fixtures);
    let disk_path = "private/var/db/diagnostics/Special/0000000000000001.tracev3";
    let from_disk = parse(disk_path, &data, &mut disk);
    assert_eq!(from_disk.records, from_archive.records);
    assert!(from_disk.skipped.is_empty(), "{:?}", from_disk.skipped);
}

#[test]
fn without_the_collection_entries_still_come() {
    let mut fixtures = Fixtures::new();
    for fixture in FIXTURES {
        let mut alone = Vec::new();
        for path in fixtures.tracev3_files(fixture) {
            let data = fixtures.read(&path).unwrap();
            assert_conforms(&UnifiedLogAdapter, &path, &data);
            alone.extend(parse(&path, &data, &mut BTreeMap::new()).records);
        }
        assert_eq!(alone.len(), fixture_records()[fixture].len(), "{fixture}");
        assert!(alone.iter().all(|r| r.times.is_empty()));
        assert!(alone
            .iter()
            .any(|r| text(r, "Missing").is_some_and(|m| m.starts_with("no uuidtext file"))));
    }
}
