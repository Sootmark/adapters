//! Jump lists, via the `shell` parser: per application (its identifier is
//! the file name), what its taskbar menu offered. Automatic lists
//! (`…\Recent\AutomaticDestinations\*.automaticDestinations-ms`) record
//! files and folders a user opened, when last, how often, and pins;
//! custom lists (`…\CustomDestinations\*.customDestinations-ms`) the
//! entries and tasks the application added.

use std::path::Path;

use common::time::Ts;
use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};
use shell::jumplist::{self, Kind};
use shell::lnk::Link;

use crate::lnk;

/// Records of jump list entries.
pub const NAMESPACE: Namespace = Namespace::new("windows.jumplist");

const AUTOMATIC: &str = "automaticDestinations-ms";
const CUSTOM: &str = "customDestinations-ms";
const OLE: &[u8] = &[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];

/// One record per entry: each `DestList` entry of an automatic list, each
/// link of a custom one.
#[derive(Debug, Default, Clone, Copy)]
pub struct JumpListAdapter;

fn extension(name: &str) -> Option<&str> {
    Path::new(name).extension().and_then(|e| e.to_str())
}

/// What the parser couldn't read: reading stopped there.
fn skip(sink: &mut dyn Sink, problems: &[String]) {
    for problem in problems {
        sink.skipped(Skipped {
            locator: Locator::ByteOffset(0),
            reason: problem.clone(),
        });
    }
}

/// The application identifier: the file name before its extension.
fn app_id(name: &str) -> String {
    Path::new(name)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_owned()
}

impl Adapter for JumpListAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "jumplist",
            version: shell::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[NAMESPACE]
    }

    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        match extension(name) {
            Some(e) if e.eq_ignore_ascii_case(AUTOMATIC) && head.starts_with(OLE) => {
                Confidence::Certain
            }
            Some(e) if e.eq_ignore_ascii_case(AUTOMATIC) || e.eq_ignore_ascii_case(CUSTOM) => {
                Confidence::Maybe
            }
            _ => Confidence::No,
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let is_custom = extension(input.name).is_some_and(|e| e.eq_ignore_ascii_case(CUSTOM))
            && !input.data.starts_with(OLE);
        if is_custom {
            self.custom(input, sink)
        } else {
            self.automatic(input, sink)
        }
    }
}

impl JumpListAdapter {
    fn record(self, input: &Input<'_>, table: &str, row: u64, link: Option<&Link>) -> Record {
        let mut record = Record::new(
            input.evidence,
            NAMESPACE,
            Locator::TableRow {
                table: table.to_owned(),
                row,
            },
            self.parser(),
        );
        if let Some(link) = link {
            record.times = lnk::times(link);
            record.facets = lnk::facets(link);
            record.fields = lnk::fields(link);
        }
        record
            .fields
            .insert("AppId".into(), Value::Text(app_id(input.name)));
        record
    }

    fn automatic(self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let list = jumplist::automatic(input.data).map_err(|e| ParseError::at(0, e.reason))?;
        skip(sink, &list.problems);
        for d in &list.destinations {
            let mut record = self.record(input, "DestList", u64::from(d.entry), d.link.as_ref());
            // The file identifier is usually the link's own tracker
            // identifier: its time only once, then.
            let tracker_time = d
                .link
                .as_ref()
                .and_then(|l| l.tracker.as_ref())
                .map(|t| t.created);
            let droid_time = if tracker_time == Some(d.droid_created) {
                0
            } else {
                d.droid_created
            };
            for (kind, field, time) in [
                (TimeKind::LastSeen, "LastUsed", d.last_used),
                (TimeKind::Other, "FileDroidCreated", droid_time),
            ] {
                if time != 0 {
                    record
                        .times
                        .push(RecordTime::new(kind, field, Ts::from_filetime(time)));
                }
            }
            if record.facets.file_path.is_none() || d.link.is_none() {
                record.facets.file_path = Some(d.path.clone());
            }
            let fields = &mut record.fields;
            fields.insert("Path".into(), Value::from(d.path.as_str()));
            fields.insert("EntryNumber".into(), Value::UInt(u64::from(d.entry)));
            fields.insert("MRU".into(), Value::UInt(d.position as u64));
            fields.insert(
                "DestListVersion".into(),
                Value::UInt(u64::from(list.version)),
            );
            fields.insert("Pinned".into(), Value::Bool(d.pin.is_some()));
            if let Some(pin) = d.pin {
                fields.insert("PinPosition".into(), Value::UInt(u64::from(pin)));
            }
            if let Some(count) = d.access_count {
                fields.insert("InteractionCount".into(), Value::UInt(u64::from(count)));
            }
            for (name, value) in [
                ("Hostname", &d.hostname),
                ("MacAddress", &d.mac),
                ("FileDroid", &d.file_droid),
                ("VolumeDroid", &d.volume_droid),
                ("FileBirthDroid", &d.file_birth_droid),
                ("VolumeBirthDroid", &d.volume_birth_droid),
            ] {
                if !value.is_empty() {
                    fields.insert(name.into(), Value::from(value.as_str()));
                }
            }
            record.summary = match (d.pin.is_some(), d.hostname.is_empty()) {
                (true, _) => format!("Pinned in {}'s jump list: {}", app_id(input.name), d.path),
                (false, true) => format!("Used via {}'s jump list: {}", app_id(input.name), d.path),
                (false, false) => format!(
                    "Used via {}'s jump list on {}: {}",
                    app_id(input.name),
                    d.hostname,
                    d.path
                ),
            };
            sink.record(record);
        }
        Ok(())
    }

    fn custom(self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let list = jumplist::custom(input.data);
        if list.categories.is_empty() && !list.problems.is_empty() {
            return Err(ParseError::at(0, list.problems.join("; ")));
        }
        skip(sink, &list.problems);
        let mut row = 0;
        for category in &list.categories {
            let name = match &category.kind {
                Kind::Custom(name) => name.clone(),
                Kind::Known(1) => "Frequent".to_owned(),
                Kind::Known(2) => "Recent".to_owned(),
                Kind::Known(id) => format!("Known category {id}"),
                Kind::Tasks => "Tasks".to_owned(),
            };
            for link in &category.links {
                let mut record = self.record(input, "CustomDestinations", row, Some(link));
                record
                    .fields
                    .insert("Category".into(), Value::from(name.as_str()));
                let mut command = lnk::target(link);
                if !link.arguments.is_empty() {
                    command = format!("{command} {}", link.arguments);
                }
                record.summary = format!("{}'s jump list, {name}: {command}", app_id(input.name));
                sink.record(record);
                row += 1;
            }
        }
        Ok(())
    }
}
