//! The locate database (`/var/lib/mlocate/mlocate.db`), via the `mlocate`
//! parser: one record per directory `updatedb` indexed, with its
//! modification time then and the names in it.

use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};

/// Records of locate database directories.
pub const NAMESPACE: Namespace = Namespace::new("linux.mlocate");

/// The most names kept in a summary.
const SUMMARY_NAMES: usize = 10;

/// One record per directory.
#[derive(Debug, Default, Clone, Copy)]
pub struct MlocateAdapter;

impl Adapter for MlocateAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "mlocate",
            version: mlocate::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[NAMESPACE]
    }

    /// By the `\0mlocate` signature.
    fn probe(&self, _name: &str, head: &[u8]) -> Confidence {
        if mlocate::is_mlocate(head) {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let db = mlocate::read(input.data);
        for reason in db.problems {
            sink.skipped(Skipped {
                locator: Locator::ByteOffset(0),
                reason,
            });
        }
        for dir in &db.directories {
            let mut record = Record::new(
                input.evidence,
                NAMESPACE,
                Locator::ByteOffset(dir.offset),
                self.parser(),
            );
            if let Some(time) = dir.modified {
                record
                    .times
                    .push(RecordTime::new(TimeKind::Modified, "Modified", time));
            }
            let names: Vec<&str> = dir.entries.iter().map(|e| e.name.as_str()).collect();
            let mut fields = Fields::new();
            fields.insert("Path".into(), Value::from(dir.path.as_str()));
            fields.insert("Entries".into(), Value::from(names.join("; ").as_str()));
            fields.insert("EntryCount".into(), Value::UInt(names.len() as u64));
            record.fields = fields;
            record.facets = Facets {
                file_path: Some(dir.path.clone()),
                ..Facets::default()
            };
            let shown: Vec<&str> = names.iter().take(SUMMARY_NAMES).copied().collect();
            record.summary = format!(
                "locate: {} ({} entries{}{})",
                dir.path,
                names.len(),
                if shown.is_empty() { "" } else { ": " },
                shown.join(", ")
            );
            sink.record(record);
        }
        Ok(())
    }
}
