//! The Windows Recycle Bin, via the `recyclebin` parser: one record per
//! deleted file (an `$I` file, or each record of XP's `INFO2`), timed when
//! it was deleted, with its original path and size.

use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};
use recyclebin::{Deleted, Kind};

/// Records of Recycle Bin files.
pub const NAMESPACE: Namespace = Namespace::new("windows.recyclebin");

/// One record per deleted file.
#[derive(Debug, Default, Clone, Copy)]
pub struct RecycleBinAdapter;

impl Adapter for RecycleBinAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "recyclebin",
            version: recyclebin::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[NAMESPACE]
    }

    /// By name, and a version the format has (1 or 2 for `$I`, an INFO2
    /// header's record size).
    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        let readable = match recyclebin::detect(name) {
            Some(Kind::Index) => matches!(head.first(), Some(1 | 2)),
            Some(Kind::Info2) => head.get(12..16) == Some(&800u32.to_le_bytes()[..]),
            None => false,
        };
        if readable {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let failed = |e: recyclebin::Error| ParseError::at(0, e.0);
        match recyclebin::detect(input.name) {
            Some(Kind::Index) => {
                let deleted = recyclebin::parse_index(input.data).map_err(failed)?;
                sink.record(self.record(input, Locator::ByteOffset(0), &deleted));
            }
            Some(Kind::Info2) => {
                let info2 = recyclebin::parse_info2(input.data).map_err(failed)?;
                for reason in info2.problems {
                    sink.skipped(Skipped {
                        locator: Locator::ByteOffset(0),
                        reason,
                    });
                }
                for (row, deleted) in (0u64..).zip(&info2.entries) {
                    let locator = Locator::ByteOffset(20 + row * 800);
                    sink.record(self.record(input, locator, deleted));
                }
            }
            None => return Err(ParseError::at(0, "not a Recycle Bin file")),
        }
        Ok(())
    }
}

impl RecycleBinAdapter {
    fn record(self, input: &Input<'_>, locator: Locator, deleted: &Deleted) -> Record {
        let mut record = Record::new(input.evidence, NAMESPACE, locator, self.parser());
        if let Some(time) = deleted.deleted {
            record
                .times
                .push(RecordTime::new(TimeKind::Deleted, "deletion_time", time));
        }
        record.facets = Facets {
            user_sid: owner_sid(input.name),
            file_path: Some(deleted.path.clone()).filter(|p| !p.is_empty()),
            ..Facets::default()
        };
        let mut fields = Fields::new();
        fields.insert("OriginalPath".into(), Value::from(deleted.path.as_str()));
        if let Some(size) = deleted.size {
            fields.insert("Size".into(), Value::UInt(size));
        }
        fields.insert("Version".into(), Value::UInt(u64::from(deleted.version)));
        if let Some(index) = deleted.index {
            fields.insert("Index".into(), Value::UInt(u64::from(index)));
        }
        if let Some(drive) = deleted.drive {
            fields.insert("Drive".into(), Value::UInt(u64::from(drive)));
        }
        record.fields = fields;
        record.summary = format!("Deleted to the Recycle Bin: {}", deleted.path);
        record
    }
}

/// The SID of the folder the file is in (`$Recycle.Bin\<SID>\`,
/// `RECYCLER\<SID>\`): whose Recycle Bin it is.
fn owner_sid(path: &str) -> Option<String> {
    path.split(['/', '\\'])
        .rev()
        .nth(1)
        .filter(|folder| folder.starts_with("S-1-"))
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owners_from_folders() {
        assert_eq!(
            owner_sid(r"C:\$Recycle.Bin\S-1-5-21-1-2-3-1001\$I103S5F.jpg").as_deref(),
            Some("S-1-5-21-1-2-3-1001")
        );
        assert_eq!(owner_sid("$I103S5F.jpg"), None);
    }
}
