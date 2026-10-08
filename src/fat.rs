//! FAT12, FAT16, FAT32 and exFAT directories, as disk images list them
//! (`<folder>/$FAT_DIRECTORY`, `<folder>/$EXFAT_DIRECTORY`), via the `disk`
//! crate's directory reader: one record per file or folder the directory
//! lists, with the times its entry keeps. What plaso's `filestat` gives for
//! a FAT volume, which has no `$MFT` to read them from.
//!
//! FAT times are wall-clock times in an unknown zone, never passed off as
//! UTC; exFAT times are UTC when their entry records its offset.

use disk::{DirectoryEntry, DirectoryFormat};

use model::adapter::{Adapter, Confidence, Input, ParseError, Sink};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};

use crate::paths;

/// Records of FAT and exFAT directory entries.
pub const NAMESPACE: Namespace = Namespace::new("filesystem.fat");

/// One record per file or folder a directory lists.
#[derive(Debug, Default, Clone, Copy)]
pub struct FatDirectoryAdapter;

impl Adapter for FatDirectoryAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "disk-fat",
            version: disk::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[NAMESPACE]
    }

    /// By name: a directory's entries have no signature (an empty one is
    /// all zeros).
    fn probe(&self, name: &str, _head: &[u8]) -> Confidence {
        if format_of(name).is_some() {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let format = format_of(input.name)
            .ok_or_else(|| ParseError::at(0, "not a FAT or exFAT directory's entries"))?;
        let folder = paths::folder_of_stream(input.name);
        for entry in format.entries(input.data) {
            sink.record(self.record(input, folder, &entry));
        }
        Ok(())
    }
}

impl FatDirectoryAdapter {
    fn record(self, input: &Input<'_>, folder: &str, entry: &DirectoryEntry) -> Record {
        let mut record = Record::new(
            input.evidence,
            NAMESPACE,
            Locator::ByteOffset(entry.offset),
            self.parser(),
        );
        let mut fields = Fields::new();
        fields.insert("Name".into(), Value::from(entry.name.as_str()));
        fields.insert("Folder".into(), Value::from(folder));
        fields.insert("IsFolder".into(), Value::Bool(entry.is_directory));
        fields.insert("Size".into(), Value::UInt(entry.size));
        fields.insert(
            "Attributes".into(),
            Value::UInt(u64::from(entry.attributes)),
        );
        times(&mut record, &mut fields, entry);
        record.fields = fields;
        let path = paths::join(folder, &entry.name);
        let kind = if entry.is_directory { "Folder" } else { "File" };
        record.summary = format!("{kind} {path}");
        record.facets = Facets {
            file_path: Some(path),
            ..Facets::default()
        };
        record
    }
}

/// The directory format a stream at `name` holds, by its last part.
fn format_of(name: &str) -> Option<DirectoryFormat> {
    DirectoryFormat::of_stream(name.rsplit(['/', '\\']).next().unwrap_or(name))
}

/// The times the entry keeps, as fields and record times. FAT and exFAT
/// keep no metadata change time.
fn times(record: &mut Record, fields: &mut Fields, entry: &DirectoryEntry) {
    let times = [
        (TimeKind::Created, "Created", entry.times.created),
        (TimeKind::Modified, "Modified", entry.times.modified),
        (TimeKind::Accessed, "Accessed", entry.times.accessed),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probes_by_name() {
        let adapter = FatDirectoryAdapter;
        for name in [
            "vol2/$FAT_DIRECTORY",
            "vol2/Photos/$EXFAT_DIRECTORY",
            "$FAT_DIRECTORY",
        ] {
            assert_eq!(adapter.probe(name, &[0; 32]), Confidence::Certain, "{name}");
        }
        for name in ["vol2/$I30", "vol2/FAT_DIRECTORY", "vol2/$FAT_DIRECTORY.txt"] {
            assert_eq!(adapter.probe(name, &[0; 32]), Confidence::No, "{name}");
        }
    }
}
