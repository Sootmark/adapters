//! NTFS `$MFT` files, as triage collections copy them out of a volume, via
//! the `disk` crate's MFT reader: one record per named file, deleted ones
//! included, with its `$STANDARD_INFORMATION` times (what Windows shows)
//! and its `$FILE_NAME` creation time (which timestomping tools rarely
//! touch).
//!
//! Two signs of timestomping are flagged: `$STANDARD_INFORMATION`
//! creation before `$FILE_NAME` creation, and a creation time with no
//! fraction of a second (NTFS keeps 100 ns; tools that set a time often
//! give whole seconds).

use disk::{FileName, Mft, MftFile, Namespace};
use std::io::Read;

use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped, StreamInput};
use model::{
    EvidenceId, Facets, Fields, Locator, Namespace as RecordNamespace, ParserInfo, Record,
    RecordTime, TimeKind, Value,
};

/// Records of `$MFT` files.
pub const NAMESPACE: RecordNamespace = RecordNamespace::new("windows.mft");

/// Ticks (100 ns) in a second.
const TICKS_PER_SECOND: i64 = 10_000_000;
/// Longest `Zone.Identifier` kept: it is a few lines of text.
const MAX_ZONE_IDENTIFIER: usize = 4096;

/// One record per named file.
#[derive(Debug, Default, Clone, Copy)]
pub struct MftAdapter;

impl Adapter for MftAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "disk-mft",
            version: disk::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [RecordNamespace] {
        &[NAMESPACE]
    }

    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
        let record = head.starts_with(b"FILE") || head.starts_with(b"BAAD");
        if base.eq_ignore_ascii_case("$MFT") && record {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        self.emit(&Mft::parse(input.data), input.evidence, input.name, sink)
    }

    /// An `$MFT` is read a record at a time; only the files it lists are
    /// kept.
    fn parse_stream(
        &self,
        input: &StreamInput<'_>,
        content: &mut dyn Read,
        sink: &mut dyn Sink,
    ) -> Option<Result<(), ParseError>> {
        Some(match Mft::read(content) {
            Ok(mft) => self.emit(&mft, input.evidence, input.name, sink),
            Err(error) => Err(ParseError::at(0, error.to_string())),
        })
    }
}

impl MftAdapter {
    fn emit(
        self,
        mft: &Mft,
        evidence: EvidenceId,
        name: &str,
        sink: &mut dyn Sink,
    ) -> Result<(), ParseError> {
        for problem in &mft.problems {
            sink.skipped(Skipped {
                locator: Locator::ByteOffset(0),
                reason: problem.to_string(),
            });
        }
        if mft.files.is_empty() && !mft.problems.is_empty() {
            return Err(ParseError::at(0, "no MFT records"));
        }
        let drive = drive_of(name);
        for file in mft.files.iter().filter(|f| !f.names.is_empty()) {
            sink.record(self.to_record(evidence, file, drive));
        }
        Ok(())
    }

    fn to_record(self, evidence: EvidenceId, file: &MftFile, drive: Option<char>) -> Record {
        let mut record = Record::new(
            evidence,
            NAMESPACE,
            Locator::MftEntry {
                entry: file.record,
                sequence: file.sequence,
            },
            self.parser(),
        );
        let si = &file.times;
        for (kind, field, time) in [
            (TimeKind::Created, "si_created", si.created),
            (TimeKind::Modified, "si_modified", si.modified),
            (TimeKind::MetadataChanged, "si_changed", si.changed),
            (TimeKind::Accessed, "si_accessed", si.accessed),
        ] {
            if let Some(time) = time {
                record.times.push(RecordTime::new(kind, field, time));
            }
        }
        let name = primary(&file.names);
        if let Some(created) = name.and_then(|n| n.times.created) {
            record
                .times
                .push(RecordTime::new(TimeKind::Created, "fn_created", created));
        }
        let path = match drive {
            Some(letter) => format!("{letter}:\\{}", file.display_path()),
            None => format!("\\{}", file.display_path()),
        };
        record.facets = Facets {
            file_path: Some(path.clone()),
            ..Facets::default()
        };
        let stomped = timestomp_signs(file, name);
        record.fields = fields(file, name, &stomped);
        let state = match (file.in_use, file.is_directory) {
            (true, false) => "File",
            (true, true) => "Folder",
            (false, false) => "Deleted file",
            (false, true) => "Deleted folder",
        };
        record.summary = if stomped.is_empty() {
            format!("{state} {path}")
        } else {
            format!(
                "{state} {path} (possible timestomping: {})",
                stomped.join(", ")
            )
        };
        record
    }
}

/// The name a path is built from: a Windows long name, else any but an
/// 8.3 alias, else the first.
fn primary(names: &[FileName]) -> Option<&FileName> {
    names
        .iter()
        .find(|n| matches!(n.namespace, Namespace::Win32 | Namespace::Win32AndDos))
        .or_else(|| names.iter().find(|n| n.namespace != Namespace::Dos))
        .or_else(|| names.first())
}

/// What hints the `$STANDARD_INFORMATION` times were set by a tool.
fn timestomp_signs(file: &MftFile, name: Option<&FileName>) -> Vec<&'static str> {
    let mut signs = Vec::new();
    let si = file.times.created.and_then(|t| t.ticks());
    let fn_created = name.and_then(|n| n.times.created).and_then(|t| t.ticks());
    if let (Some(si), Some(fn_created)) = (si, fn_created) {
        if si < fn_created {
            signs.push("created before its name was");
        }
    }
    if si.is_some_and(|ticks| ticks % TICKS_PER_SECOND == 0)
        && fn_created.is_some_and(|ticks| ticks % TICKS_PER_SECOND != 0)
    {
        signs.push("whole-second creation time");
    }
    signs
}

/// The volume's drive letter, when the collection's path names it:
/// `C/$MFT` (KAPE) or `…/%5C%5C.%5CC%3A/$MFT` (Velociraptor).
fn drive_of(name: &str) -> Option<char> {
    let mut parts = name.rsplit(['/', '\\']);
    parts.next();
    let parent = parts.next()?;
    let parent = parent
        .strip_suffix("%3A")
        .or_else(|| parent.strip_suffix(':'))
        .unwrap_or(parent);
    let letter = parent.chars().last()?;
    let single = parent.len() == 1
        || parent.ends_with(&format!("%5C{letter}"))
        || parent.ends_with(&format!("\\{letter}"));
    (letter.is_ascii_alphabetic() && single).then(|| letter.to_ascii_uppercase())
}

fn fields(file: &MftFile, name: Option<&FileName>, stomped: &[&str]) -> Fields {
    let mut fields = Fields::new();
    fields.insert("Record".into(), Value::UInt(file.record));
    fields.insert("Sequence".into(), Value::UInt(u64::from(file.sequence)));
    fields.insert("InUse".into(), Value::Bool(file.in_use));
    fields.insert("Directory".into(), Value::Bool(file.is_directory));
    if file.is_orphan() {
        fields.insert("Orphan".into(), Value::Bool(true));
    }
    if let Some(name) = name {
        fields.insert("Name".into(), Value::from(name.name.as_str()));
        fields.insert("ParentRecord".into(), Value::UInt(name.parent));
        for (field, time) in [
            ("FnModified", name.times.modified),
            ("FnChanged", name.times.changed),
            ("FnAccessed", name.times.accessed),
        ] {
            if let Some(time) = time {
                fields.insert(field.into(), Value::from(time.to_string().as_str()));
            }
        }
    }
    if let Some(size) = file
        .streams
        .iter()
        .find(|s| s.name.is_none())
        .map(|s| s.size)
    {
        fields.insert("Size".into(), Value::UInt(size));
    }
    let streams: Vec<&str> = file
        .streams
        .iter()
        .filter_map(|s| s.name.as_deref())
        .collect();
    if !streams.is_empty() {
        fields.insert("Streams".into(), Value::from(streams.join("\n").as_str()));
    }
    let zone = file
        .streams
        .iter()
        .find(|s| s.name.as_deref() == Some("Zone.Identifier"))
        .and_then(|s| s.resident.as_deref())
        .filter(|bytes| bytes.len() <= MAX_ZONE_IDENTIFIER);
    if let Some(zone) = zone {
        fields.insert(
            "ZoneIdentifier".into(),
            Value::from(String::from_utf8_lossy(zone).trim()),
        );
    }
    if !stomped.is_empty() {
        fields.insert("Timestomp".into(), Value::from(stomped.join("; ").as_str()));
    }
    fields
}

#[cfg(test)]
mod tests {
    use super::drive_of;

    #[test]
    fn drive_from_the_collection_path() {
        assert_eq!(drive_of("C/$MFT"), Some('C'));
        assert_eq!(drive_of("WS01/d/$MFT"), Some('D'));
        assert_eq!(drive_of("uploads/ntfs/%5C%5C.%5CC%3A/$MFT"), Some('C'));
        assert_eq!(drive_of("uploads/ntfs/\\\\.\\C:/$MFT"), Some('C'));
        assert_eq!(drive_of("$MFT"), None);
        assert_eq!(drive_of("triage/$MFT"), None);
    }
}
