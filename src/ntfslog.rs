//! The NTFS transaction journal (`$LogFile`), via the `ntfslog` parser:
//! one record per logged change that says something about a file: a name
//! created, deleted or renamed (from the `$FILE_NAME` values the change
//! carries) or `$STANDARD_INFORMATION` times rewritten (timestomping shows
//! here, old and new). Changes that carry neither are counted, not kept.

use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};
use ntfslog::{FileName, LogRecord, StandardTimes, Update};

/// Records of `$LogFile` changes.
pub const NAMESPACE: Namespace = Namespace::new("windows.logfile");

/// One record per change naming a file or rewriting its times.
#[derive(Debug, Default, Clone, Copy)]
pub struct LogFileAdapter;

impl Adapter for LogFileAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "ntfslog",
            version: ntfslog::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[NAMESPACE]
    }

    /// By name (`$LogFile`, `LogFile`) and the first restart page's
    /// signature (`RSTR`, or `CHKD` after chkdsk).
    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
        let named = base.eq_ignore_ascii_case("$LogFile") || base.eq_ignore_ascii_case("LogFile");
        let signed = head.starts_with(b"RSTR") || head.starts_with(b"CHKD");
        if named && signed {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let log = ntfslog::parse(input.data);
        for problem in &log.problems {
            sink.skipped(Skipped {
                locator: Locator::ByteOffset(problem.offset),
                reason: problem.to_string(),
            });
        }
        for record in &log.records {
            if let Some(update) = record.update().filter(|u| tells_about_files(u)) {
                sink.record(self.record(input, record, update));
            }
        }
        Ok(())
    }
}

/// Whether a change names a file or rewrites its times.
fn tells_about_files(update: &Update) -> bool {
    !update.redo_names.is_empty()
        || !update.undo_names.is_empty()
        || update.redo_times.is_some()
        || update.undo_times.is_some()
}

impl LogFileAdapter {
    fn record(self, input: &Input<'_>, log_record: &LogRecord, update: &Update) -> Record {
        let mut record = Record::new(
            input.evidence,
            NAMESPACE,
            Locator::ByteOffset(log_record.offset),
            self.parser(),
        );
        let mut fields = Fields::new();
        fields.insert("Lsn".into(), Value::UInt(log_record.lsn));
        fields.insert(
            "TransactionId".into(),
            Value::UInt(u64::from(log_record.transaction_id)),
        );
        fields.insert("Redo".into(), Value::from(update.redo.to_string().as_str()));
        fields.insert("Undo".into(), Value::from(update.undo.to_string().as_str()));
        if let Some(mft) = update.mft_record {
            fields.insert("MftRecord".into(), Value::UInt(mft));
        }
        names(&mut fields, "Name", &update.redo_names);
        names(&mut fields, "OldName", &update.undo_names);
        times(&mut record, &mut fields, "New", update.redo_times.as_ref());
        times(&mut record, &mut fields, "Old", update.undo_times.as_ref());
        // The times a new name carries date the change when no $SI time
        // does.
        if record.times.is_empty() {
            if let Some(name) = update.redo_names.first() {
                record.times.push(RecordTime::new(
                    TimeKind::Modified,
                    "NameChanged",
                    name.changed,
                ));
            }
        }
        record.fields = fields;
        let name = update
            .redo_names
            .first()
            .or(update.undo_names.first())
            .map(|n| n.name.clone());
        record.facets = Facets {
            file_path: name.clone(),
            ..Facets::default()
        };
        record.summary = summary(update, name.as_deref());
        record
    }
}

/// The names a side carries, joined, and the first's parent.
fn names(fields: &mut Fields, key: &str, names: &[FileName]) {
    if names.is_empty() {
        return;
    }
    let joined: Vec<&str> = names.iter().map(|n| n.name.as_str()).collect();
    fields.insert(key.into(), Value::from(joined.join(", ").as_str()));
    fields.insert(
        format!("{key}Parent"),
        Value::from(names[0].parent.to_string().as_str()),
    );
}

/// `$STANDARD_INFORMATION` times a side writes, as fields and, for the new
/// ones, record times.
fn times(record: &mut Record, fields: &mut Fields, side: &str, times: Option<&StandardTimes>) {
    let Some(times) = times else {
        return;
    };
    for (kind, name, time) in [
        (TimeKind::Created, "Created", times.created),
        (TimeKind::Modified, "Modified", times.modified),
        (TimeKind::MetadataChanged, "Changed", times.changed),
        (TimeKind::Accessed, "Accessed", times.accessed),
    ] {
        let Some(time) = time else {
            continue;
        };
        if let Some(text) = time.to_iso8601() {
            fields.insert(format!("{side}{name}"), Value::from(text.as_str()));
        }
        if side == "New" {
            record.times.push(RecordTime::new(kind, name, time));
        }
    }
}

/// `$LogFile: Hello.txt named (AddIndexEntryAllocation)`, by what the
/// change does.
fn summary(update: &Update, name: Option<&str>) -> String {
    let name = name.unwrap_or("?");
    let what = match (
        update.redo_names.is_empty(),
        update.undo_names.is_empty(),
        update.redo_times.is_some(),
    ) {
        (false, true, _) => "named",
        (true, false, _) => "name removed",
        (false, false, _) => "renamed",
        (true, true, true) => "times set",
        (true, true, false) => "times undone",
    };
    format!("$LogFile: {name} {what} ({})", update.redo)
}
