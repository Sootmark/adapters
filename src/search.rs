//! The Windows Search index (`Windows.edb`), via the `search` parser: one
//! record per indexed item (a file, folder, e-mail or page, with its path,
//! kind, size, times, owner and text snippet), and one per entry the
//! gatherer listed that has no indexed item (found, never indexed, or gone
//! since).

use std::path::Path;

use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};
use search::{Gathered, Item};

/// Indexed items.
pub const ITEMS: Namespace = Namespace::new("windows.search");
/// Gathered entries without an indexed item.
pub const GATHERED: Namespace = Namespace::new("windows.search.gather");

/// An ESE database's signature, at offset 4 of its header.
const ESE_SIGNATURE: [u8; 4] = [0xef, 0xcd, 0xab, 0x89];
/// Characters of a snippet kept in the summary line.
const SUMMARY_SNIPPET: usize = 160;

/// One record per indexed item and unindexed gathered entry.
#[derive(Debug, Default, Clone, Copy)]
pub struct SearchAdapter;

impl Adapter for SearchAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "search",
            version: search::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[ITEMS, GATHERED]
    }

    /// By name (`Windows.edb`) and the ESE signature.
    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        let named = Path::new(name)
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.eq_ignore_ascii_case("Windows.edb"));
        if named && head.get(4..8) == Some(&ESE_SIGNATURE[..]) {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let index = search::read(input.data).map_err(|e| ParseError::at(0, e.0))?;
        for reason in index.problems {
            sink.skipped(Skipped {
                locator: Locator::ByteOffset(0),
                reason,
            });
        }
        for (row, item) in (0u64..).zip(&index.items) {
            sink.record(self.item(input, row, item));
        }
        for (row, entry) in (0u64..).zip(&index.gathered) {
            if !entry.indexed {
                sink.record(self.gathered(input, row, entry));
            }
        }
        Ok(())
    }
}

impl SearchAdapter {
    fn record(self, input: &Input<'_>, namespace: Namespace, table: &str, row: u64) -> Record {
        Record::new(
            input.evidence,
            namespace,
            Locator::TableRow {
                table: table.to_owned(),
                row,
            },
            self.parser(),
        )
    }

    fn item(self, input: &Input<'_>, row: u64, item: &Item) -> Record {
        let id = item
            .work_id
            .and_then(|id| u64::try_from(id).ok())
            .unwrap_or(row);
        let mut record = self.record(input, ITEMS, "items", id);
        for (time, kind, name) in [
            (item.modified, TimeKind::Modified, "System_DateModified"),
            (item.created, TimeKind::Created, "System_DateCreated"),
            (item.accessed, TimeKind::Accessed, "System_DateAccessed"),
            (
                item.gather_time,
                TimeKind::Other,
                "System_Search_GatherTime",
            ),
        ] {
            if let Some(time) = time {
                record.times.push(RecordTime::new(kind, name, time));
            }
        }
        record.facets = Facets {
            user_name: item.owner.clone(),
            file_path: item.path.clone(),
            ..Facets::default()
        };
        let mut fields = Fields::new();
        text(&mut fields, "Path", item.path.as_deref());
        text(&mut fields, "Url", item.url.as_deref());
        text(&mut fields, "ItemType", item.item_type.as_deref());
        text(&mut fields, "Kind", Some(&item.kind.join(", ")));
        text(&mut fields, "Owner", item.owner.as_deref());
        text(&mut fields, "Computer", item.computer.as_deref());
        text(&mut fields, "Title", item.title.as_deref());
        text(&mut fields, "Summary", item.summary.as_deref());
        if let Some(size) = item.size {
            fields.insert("Size".into(), Value::UInt(size));
        }
        if let Some(id) = item.work_id {
            fields.insert("WorkId".into(), Value::Int(id));
        }
        record.fields = fields;
        let what = item
            .path
            .as_deref()
            .or(item.url.as_deref())
            .unwrap_or("an item");
        record.summary = match item.summary.as_deref() {
            Some(snippet) => format!("Indexed {what}: {}", shorten(snippet)),
            None => format!("Indexed {what}"),
        };
        record
    }

    fn gathered(self, input: &Input<'_>, row: u64, entry: &Gathered) -> Record {
        let mut record = self.record(input, GATHERED, "SystemIndex_Gthr", row);
        if let Some(time) = entry.modified {
            record
                .times
                .push(RecordTime::new(TimeKind::Modified, "LastModified", time));
        }
        let path = entry.path();
        record.facets = Facets {
            file_path: path.clone(),
            ..Facets::default()
        };
        let mut fields = Fields::new();
        text(&mut fields, "Path", path.as_deref());
        text(&mut fields, "FileName", entry.file_name.as_deref());
        if let Some(id) = entry.document_id {
            fields.insert("DocumentId".into(), Value::Int(id));
        }
        record.fields = fields;
        record.summary = format!(
            "Gathered, not indexed: {}",
            path.as_deref().unwrap_or("an item")
        );
        record
    }
}

fn shorten(text: &str) -> String {
    let line = text.split_whitespace().collect::<Vec<_>>().join(" ");
    match line.char_indices().nth(SUMMARY_SNIPPET) {
        Some((at, _)) => format!("{}…", &line[..at]),
        None => line,
    }
}

fn text(fields: &mut Fields, name: &str, value: Option<&str>) {
    if let Some(value) = value.filter(|v| !v.is_empty()) {
        fields.insert(name.into(), Value::from(value));
    }
}
