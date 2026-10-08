//! NTFS directory indexes (`$I30`, a folder's `$INDEX_ALLOCATION`), via the
//! `indx` parser: one record per name the folder lists, with the
//! `$FILE_NAME` times and sizes the index keeps, and one per name recovered
//! from the blocks' slack, where entries of removed files linger.

use common::time::Ts;
use indx::Entry;
use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};

/// Records of directory index entries.
pub const NAMESPACE: Namespace = Namespace::new("windows.i30");

/// The signature each index block starts with.
const SIGNATURE: &[u8; 4] = b"INDX";

/// One record per entry, listed or recovered from slack.
#[derive(Debug, Default, Clone, Copy)]
pub struct I30Adapter;

impl Adapter for I30Adapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "indx",
            version: indx::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[NAMESPACE]
    }

    /// By name (`$I30`, with or without its `:$INDEX_ALLOCATION` stream
    /// suffix, `:` escaped as `%3A` by some collectors) and the first
    /// block's signature.
    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
        if base.starts_with("$I30") && head.starts_with(SIGNATURE) {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let index = indx::read_allocation(input.data);
        for problem in &index.problems {
            sink.skipped(Skipped {
                locator: Locator::ByteOffset(0),
                reason: problem.clone(),
            });
        }
        let folder = folder(input.name);
        for entry in index.entries() {
            sink.record(self.record(input, folder, entry, false));
        }
        for entry in index.slack() {
            sink.record(self.record(input, folder, entry, true));
        }
        Ok(())
    }
}

impl I30Adapter {
    fn record(self, input: &Input<'_>, folder: &str, entry: &Entry, in_slack: bool) -> Record {
        let mut record = Record::new(
            input.evidence,
            NAMESPACE,
            Locator::ByteOffset(entry.offset as u64),
            self.parser(),
        );
        let mut fields = Fields::new();
        fields.insert("Name".into(), Value::from(entry.name.as_str()));
        fields.insert("Folder".into(), Value::from(folder));
        fields.insert("InSlack".into(), Value::Bool(in_slack));
        fields.insert("IsFolder".into(), Value::Bool(entry.is_folder()));
        if let Some(file) = entry.file {
            fields.insert("MftEntry".into(), Value::UInt(file.entry));
            fields.insert("MftSequence".into(), Value::UInt(u64::from(file.sequence)));
        }
        fields.insert("ParentEntry".into(), Value::UInt(entry.parent.entry));
        fields.insert(
            "ParentSequence".into(),
            Value::UInt(u64::from(entry.parent.sequence)),
        );
        fields.insert("Size".into(), Value::UInt(entry.size));
        fields.insert("AllocatedSize".into(), Value::UInt(entry.allocated_size));
        fields.insert(
            "Attributes".into(),
            Value::UInt(u64::from(entry.attributes)),
        );
        fields.insert("NameSpace".into(), Value::UInt(u64::from(entry.namespace)));
        times(&mut record, &mut fields, entry);
        record.fields = fields;
        let path = join(folder, &entry.name);
        record.summary = if in_slack {
            format!("$I30 slack: {path} (removed from the folder's index)")
        } else {
            format!("$I30: {path}")
        };
        record.facets = Facets {
            file_path: Some(path),
            ..Facets::default()
        };
        record
    }
}

/// The `$FILE_NAME` times the entry keeps, as fields and record times.
fn times(record: &mut Record, fields: &mut Fields, entry: &Entry) {
    let times: [(TimeKind, &str, Option<Ts>); 4] = [
        (TimeKind::Created, "Created", entry.created),
        (TimeKind::Modified, "Modified", entry.modified),
        (TimeKind::MetadataChanged, "Changed", entry.changed),
        (TimeKind::Accessed, "Accessed", entry.accessed),
    ];
    for (kind, name, time) in times {
        let Some(time) = time else {
            continue;
        };
        if let Some(text) = time.to_iso8601() {
            fields.insert(name.into(), Value::from(text.as_str()));
        }
        record.times.push(RecordTime::new(kind, name, time));
    }
}

/// The folder the index belongs to: the input's path without `$I30…`.
fn folder(name: &str) -> &str {
    name.rfind(['/', '\\']).map_or("", |at| &name[..at])
}

/// The folder and name joined with the folder's own separator, or the name
/// alone at the top.
fn join(folder: &str, name: &str) -> String {
    let separator = if folder.contains('\\') { '\\' } else { '/' };
    if folder.is_empty() {
        name.to_owned()
    } else {
        format!("{folder}{separator}{name}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probes_by_name_and_signature() {
        let adapter = I30Adapter;
        assert_eq!(
            adapter.probe("C/Users/$I30", b"INDX\x28\0"),
            Confidence::Certain
        );
        assert_eq!(
            adapter.probe("C/Users/$I30%3A$INDEX_ALLOCATION", b"INDX"),
            Confidence::Certain
        );
        assert_eq!(adapter.probe("C/Users/$I30", b"RSTR"), Confidence::No);
        assert_eq!(adapter.probe("C/Users/notes.txt", b"INDX"), Confidence::No);
    }

    #[test]
    fn paths_join_the_folder() {
        assert_eq!(folder("C/Users/$I30"), "C/Users");
        assert_eq!(join(folder("$I30"), "a.txt"), "a.txt");
        assert_eq!(join("C/Users", "a.txt"), "C/Users/a.txt");
        assert_eq!(join("C:\\Users", "a.txt"), "C:\\Users\\a.txt");
    }
}
