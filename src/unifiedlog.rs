//! macOS unified logs (`/private/var/db/diagnostics/{Persist,Special,
//! Signpost,HighVolume}/*.tracev3`, and the same files in a `.logarchive`),
//! via the `unifiedlog` parser: one record per entry, with its time,
//! process, library, subsystem and category, level, thread and activity,
//! format string and message.
//!
//! A tracev3 file holds no text of its own: its entries' format strings are
//! in the `uuidtext` files (`uuidtext/XX/YYYY…`, by image UUID, and the
//! shared cache strings files `uuidtext/dsc/<UUID>`), and their times turn
//! into wall-clock times with the timesync files (`timesync/*.timesync`).
//! The adapter reads them from the collection
//! ([`Adapter::parse_with_collection`]): in a log archive, beside the
//! tracev3 folders; on a disk, the timesync files in `diagnostics/` and the
//! strings files in `uuidtext/` beside it. Without them, entries still come,
//! without their times or message text, and `Missing` says why.
//!
//! An entry whose values are in another file's oversize chunk comes last,
//! with `<Missing message data>` in its message.

use std::collections::BTreeMap;

use model::adapter::{Adapter, Collection, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};
use unifiedlog::{Entry, LogType, Reader, StringFile};

/// Records of unified log entries.
pub const NAMESPACE: Namespace = Namespace::new("macos.unified_log");

/// A tracev3 file's first chunk: the header (tag 0x1000, sub-tag 0x11).
const HEADER: [u8; 8] = [0x00, 0x10, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00];
/// The folders tracev3 files are in, in `diagnostics/` or an archive.
const TRACE_FOLDERS: [&str; 4] = ["Persist", "Special", "Signpost", "HighVolume"];
/// The folder that holds the tracev3 folders on a disk; the strings files
/// are in `uuidtext/` beside it.
const DIAGNOSTICS: &str = "diagnostics";
const SUMMARY_MESSAGE: usize = 160;

/// One record per log entry.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnifiedLogAdapter;

impl Adapter for UnifiedLogAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "unifiedlog",
            version: unifiedlog::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[NAMESPACE]
    }

    /// By name (`.tracev3`) and the header chunk it starts with.
    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        let tracev3 = name.to_ascii_lowercase().ends_with(".tracev3");
        if tracev3 && head.starts_with(&HEADER) {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        self.parse_with_collection(input, &mut BTreeMap::new(), sink)
    }

    fn parse_with_collection(
        &self,
        input: &Input<'_>,
        collection: &mut dyn Collection,
        sink: &mut dyn Sink,
    ) -> Result<(), ParseError> {
        let layout = Layout::of(input.name);
        let timesyncs: Vec<(String, Vec<u8>)> = collection
            .list(&layout.timesync)
            .into_iter()
            .filter(|path| path.to_ascii_lowercase().ends_with(".timesync"))
            .filter_map(|path| {
                let data = collection.read(&path)?;
                Some((path, data))
            })
            .collect();
        let mut reader = Reader::new(|file: StringFile| collection.read(&layout.strings(file)));
        for (path, data) in &timesyncs {
            for problem in reader.add_timesync(data) {
                skip(sink, format!("{path}: {problem}"));
            }
        }
        let log = reader.read(input.data);
        for problem in log.problems {
            skip(sink, problem);
        }
        let late = reader.finish();
        for (row, entry) in (0u64..).zip(log.entries.into_iter().chain(late)) {
            sink.record(self.record(input, row, &entry));
        }
        Ok(())
    }
}

/// A problem the reader met (damage, or a timesync or strings file that
/// does not read): reading went on past it, and it has no place of its own
/// in the file, so it is reported at its start.
fn skip(sink: &mut dyn Sink, reason: String) {
    sink.skipped(Skipped {
        locator: Locator::ByteOffset(0),
        reason,
    });
}

/// Where a tracev3 file's companions are, in the collection.
struct Layout {
    /// The folder of the timesync files.
    timesync: String,
    /// The folder of the uuidtext files and of `dsc/`.
    strings: String,
}

impl Layout {
    /// The layout around the tracev3 file at `name`: its folder, or the
    /// folder above a tracev3 folder, holds `timesync/`; that is
    /// `diagnostics/` on a disk, with `uuidtext/` beside it, or else an
    /// archive, which holds the strings files too.
    fn of(name: &str) -> Self {
        let name = name.replace('\\', "/");
        let folder = parent(&name);
        let in_trace_folder = TRACE_FOLDERS
            .iter()
            .any(|trace| file_name(folder).eq_ignore_ascii_case(trace));
        let root = if in_trace_folder {
            parent(folder)
        } else {
            folder
        };
        let strings = if file_name(root).eq_ignore_ascii_case(DIAGNOSTICS) {
            join(parent(root), "uuidtext")
        } else {
            root.to_owned()
        };
        Self {
            timesync: join(root, "timesync"),
            strings,
        }
    }

    /// The path of a strings file.
    fn strings(&self, file: StringFile) -> String {
        join(&self.strings, &file.path())
    }
}

/// The folder a path is in; empty at the top.
fn parent(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(folder, _)| folder)
}

/// A path's last part.
fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn join(folder: &str, name: &str) -> String {
    if folder.is_empty() {
        name.to_owned()
    } else {
        format!("{folder}/{name}")
    }
}

impl UnifiedLogAdapter {
    /// The record of the `row`th entry read from the file.
    fn record(self, input: &Input<'_>, row: u64, entry: &Entry) -> Record {
        let mut record = Record::new(
            input.evidence,
            NAMESPACE,
            Locator::TableRow {
                table: "entries".to_owned(),
                row,
            },
            self.parser(),
        );
        if let Some(time) = entry.time() {
            record
                .times
                .push(RecordTime::new(TimeKind::Logged, "Time", time));
        }
        record.facets = Facets {
            process_path: Some(entry.process.clone()).filter(|p| !p.is_empty()),
            process_id: Some(entry.pid),
            ..Facets::default()
        };
        record.fields = fields(entry);
        record.summary = summary(entry);
        record
    }
}

fn fields(entry: &Entry) -> Fields {
    let mut fields = Fields::new();
    let texts = [
        ("Process", &entry.process),
        ("Library", &entry.library),
        ("Subsystem", &entry.subsystem),
        ("Category", &entry.category),
        ("Message", &entry.message),
        ("FormatString", &entry.raw_message),
    ];
    for (name, text) in texts.into_iter().filter(|(_, text)| !text.is_empty()) {
        fields.insert(name.into(), Value::from(text.as_str()));
    }
    let uuids = [
        ("ProcessUuid", entry.process_uuid),
        ("LibraryUuid", entry.library_uuid),
        ("BootUuid", Some(entry.boot_uuid)),
    ];
    for (name, uuid) in uuids {
        if let Some(uuid) = uuid.filter(|u| !u.is_nil()) {
            fields.insert(name.into(), Value::from(uuid.to_string()));
        }
    }
    fields.insert("EventType".into(), Value::from(entry.event_type.name()));
    fields.insert("LogType".into(), Value::from(entry.log_type.name()));
    fields.insert("Pid".into(), Value::UInt(entry.pid));
    fields.insert("Euid".into(), Value::UInt(u64::from(entry.euid)));
    fields.insert("ThreadId".into(), Value::UInt(entry.thread_id));
    fields.insert("ActivityId".into(), Value::UInt(entry.activity_id));
    if let Some(signpost) = entry.signpost {
        fields.insert("SignpostId".into(), Value::UInt(signpost.id));
        fields.insert(
            "SignpostNameReference".into(),
            Value::UInt(u64::from(signpost.name)),
        );
    }
    if let Some(missing) = &entry.missing {
        fields.insert("Missing".into(), Value::from(missing.as_str()));
    }
    fields
}

/// `kernel: message`, with the level for errors and faults
/// (`kernel fault: message`); losses say how many entries were lost.
fn summary(entry: &Entry) -> String {
    let process = match file_name(&entry.process) {
        "" => format!("pid {}", entry.pid),
        name => name.to_owned(),
    };
    let level = match entry.log_type {
        LogType::Error => " error",
        LogType::Fault => " fault",
        _ => "",
    };
    let first_line = entry.message.lines().next().unwrap_or_default();
    let text: String = match entry.loss {
        Some(loss) => format!("lost {} entries", loss.count),
        None if first_line.is_empty() => entry.event_type.name().to_owned(),
        None => first_line.chars().take(SUMMARY_MESSAGE).collect(),
    };
    format!("{process}{level}: {text}")
}
