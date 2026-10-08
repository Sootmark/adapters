//! macOS Spotlight store databases (`/.Spotlight-V100/Store-V2/<UUID>/
//! store.db` and its copy `.store.db`, and the CoreSpotlight stores under
//! `~/Library/Metadata/CoreSpotlight/`), via the `spotlight` parser: one
//! record per item Spotlight indexed, kept after the file is deleted, with
//! its path, name, kind, content type, where it was downloaded from, its
//! times (added, used, created, modified, downloaded, last updated in the
//! index) and every attribute under its own name.
//!
//! From macOS 12 a store's tables are in the streams maps beside it
//! (`dbStr-{1,2,4,5}.map.{header,offsets,data}`), which the caller hands
//! over as companion files; without them the items are listed without
//! their attributes, and the gap reported.

use model::adapter::{Adapter, Companion, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};
use spotlight::{Item, Value as Attribute};

use crate::home::profile_owner;
use crate::key::field_name;

/// Records of Spotlight stores.
pub const NAMESPACE: Namespace = Namespace::new("macos.spotlight_store");

/// The file system identifier of the record holding the store's own
/// properties.
const VOLUME_STORE_ID: u64 = 1;
/// What a reference to a missing localized string reads as.
const NULL_TEXT: &str = "(null)";
/// The attributes that name an item without a path, in order of
/// preference.
const LABELS: [&str; 3] = ["kMDItemDisplayName", "kMDItemTitle", "_kMDItemExternalID"];

/// One record per indexed item.
#[derive(Debug, Default, Clone, Copy)]
pub struct SpotlightAdapter;

impl Adapter for SpotlightAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "spotlight",
            version: spotlight::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[NAMESPACE]
    }

    /// By name (`store.db`, `.store.db`) and the signature (`8tsd`).
    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        if spotlight::is_store_name(name) && spotlight::is_store(head) {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn companions(&self, name: &str) -> Vec<String> {
        if spotlight::is_store_name(name) {
            spotlight::STREAMS_MAP_FILES
                .iter()
                .map(|file| (*file).to_owned())
                .collect()
        } else {
            Vec::new()
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        self.parse_with_companions(input, &[], sink)
    }

    fn parse_with_companions(
        &self,
        input: &Input<'_>,
        companions: &[Companion<'_>],
        sink: &mut dyn Sink,
    ) -> Result<(), ParseError> {
        let maps: Vec<(&str, &[u8])> = spotlight::STREAMS_MAP_FILES
            .iter()
            .filter_map(|file| {
                companions
                    .iter()
                    .find(|c| c.name.eq_ignore_ascii_case(file))
                    .map(|c| (*file, c.data))
            })
            .collect();
        let store = spotlight::read_store(input.data, &maps).map_err(|e| ParseError::at(0, e.0))?;
        for reason in store.problems {
            sink.skipped(Skipped {
                locator: Locator::ByteOffset(0),
                reason,
            });
        }
        let owner = profile_owner(input.name);
        for item in &store.items {
            sink.record(self.record(input, item, owner.as_deref()));
        }
        Ok(())
    }
}

impl SpotlightAdapter {
    fn record(self, input: &Input<'_>, item: &Item, owner: Option<&str>) -> Record {
        let mut record = Record::new(
            input.evidence,
            NAMESPACE,
            Locator::TableRow {
                table: "items".to_owned(),
                row: item.item_id,
            },
            self.parser(),
        );
        for (name, time) in item.times() {
            record
                .times
                .push(RecordTime::new(time_kind(name), name, time));
        }
        let mut fields = Fields::new();
        for (name, value) in &item.attributes {
            fields.insert(field_name(name), attribute(value));
        }
        let where_froms = item.where_froms();
        text(&mut fields, "Path", item.path.as_deref());
        text(&mut fields, "Name", item.name());
        text(&mut fields, "Kind", item.kind());
        text(
            &mut fields,
            "ContentType",
            item.content_type().filter(|t| *t != NULL_TEXT),
        );
        if !where_froms.is_empty() {
            text(&mut fields, "WhereFroms", Some(&where_froms.join(" | ")));
        }
        fields.insert("FileId".into(), Value::UInt(item.id));
        fields.insert("ParentId".into(), Value::UInt(item.parent_id));
        fields.insert("ItemId".into(), Value::UInt(item.item_id));
        fields.insert("Flags".into(), Value::UInt(u64::from(item.flags)));
        record.fields = fields;
        record.facets = Facets {
            user_name: owner.map(str::to_owned),
            file_path: item.path.clone().or_else(|| item.name().map(str::to_owned)),
            ..Facets::default()
        };
        let from = where_froms
            .first()
            .map_or_else(String::new, |url| format!(", from {url}"));
        record.summary = if item.id == VOLUME_STORE_ID && item.parent_id == 0 {
            "Spotlight store properties".to_owned()
        } else {
            format!(
                "Spotlight indexed {}{}{from}",
                label(item),
                item.kind()
                    .map_or_else(String::new, |kind| format!(" ({kind})")),
            )
        };
        record
    }
}

/// What names an item: its path, its name, or what a CoreSpotlight item
/// (an app's, with no file) is called.
fn label(item: &Item) -> String {
    item.path
        .as_deref()
        .or(item.name())
        .or_else(|| {
            LABELS
                .iter()
                .find_map(|name| item.text(name).filter(|t| *t != NULL_TEXT))
        })
        .map_or_else(|| format!("item {}", item.item_id), str::to_owned)
}

/// The kind of an item's time, by the name [`Item::times`] gives it.
fn time_kind(name: &str) -> TimeKind {
    match name {
        "created" | "content_created" => TimeKind::Created,
        "modified" | "content_modified" => TimeKind::Modified,
        "attribute_changed" => TimeKind::MetadataChanged,
        "used" => TimeKind::Accessed,
        "added" => TimeKind::FirstSeen,
        _ => TimeKind::Other,
    }
}

fn attribute(value: &Attribute) -> Value {
    match value {
        Attribute::Integer(n) => Value::UInt(*n),
        Attribute::Integers(list) => Value::List(list.iter().map(|n| Value::UInt(*n)).collect()),
        Attribute::Bytes(bytes) => Value::Bytes(bytes.clone()),
        Attribute::Real(n) => Value::Float(*n),
        Attribute::Reals(list) => Value::List(list.iter().map(|n| Value::Float(*n)).collect()),
        Attribute::Date(time) => Value::Time(*time),
        Attribute::Dates(list) => Value::List(list.iter().map(|t| Value::Time(*t)).collect()),
        Attribute::Text(text) => Value::from(text.as_str()),
        Attribute::Texts(list) => {
            Value::List(list.iter().map(|t| Value::from(t.as_str())).collect())
        }
    }
}

fn text(fields: &mut Fields, name: &str, value: Option<&str>) {
    if let Some(value) = value.filter(|v| !v.is_empty()) {
        fields.insert(name.into(), Value::from(value));
    }
}
