//! Plaso timelines (`psort`), imported from `json_line`, `dynamic` (CSV) or
//! `l2tcsv` output.
//!
//! One Plaso event (one timestamp) becomes one record, under a namespace
//! for the file-level parser that produced it (`plaso.winevtx`,
//! `plaso.mft`, …; `plaso.other` for the rest), with Plaso's own parser
//! chain and data type kept as fields.
//!
//! Times: `json_line` is exact. FILETIME values keep their 100 ns ticks,
//! and times that are local by nature (`FATDateTime`, or marked local) are
//! kept local, zone unknown, instead of Plaso's UTC reading of them. The CSV
//! formats only carry Plaso's normalised time: `dynamic` with its offset,
//! `l2tcsv` with its zone column, which must say UTC (rerun psort with
//! `-z UTC` otherwise). Both are kept to the second: psort 20260720's
//! `dynamic` output misprints sub-second fractions that start with a zero
//! (FILETIME `…0059180` as `.591800`), so its sub-second digits can't be
//! trusted. Prefer `json_line`.

use common::json::{self, Json};
use common::time::{Precision, Ts};
use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};

use crate::csv;
use crate::timestamp;

/// Namespaces by Plaso's file-level parser.
const PARSERS: &[(&str, Namespace)] = &[
    ("winevtx", Namespace::new("plaso.winevtx")),
    ("winevt", Namespace::new("plaso.winevt")),
    ("mft", Namespace::new("plaso.mft")),
    ("usnjrnl", Namespace::new("plaso.usnjrnl")),
    ("filestat", Namespace::new("plaso.filestat")),
    ("prefetch", Namespace::new("plaso.prefetch")),
    ("lnk", Namespace::new("plaso.lnk")),
    ("olecf", Namespace::new("plaso.olecf")),
    (
        "custom_destinations",
        Namespace::new("plaso.custom_destinations"),
    ),
    ("winreg", Namespace::new("plaso.winreg")),
    ("esedb", Namespace::new("plaso.esedb")),
    ("sqlite", Namespace::new("plaso.sqlite")),
    ("recycle_bin", Namespace::new("plaso.recycle_bin")),
    ("text", Namespace::new("plaso.text")),
];
const OTHER: Namespace = Namespace::new("plaso.other");

/// Every namespace this importer produces.
pub const NAMESPACES: &[Namespace] = &[
    PARSERS[0].1,
    PARSERS[1].1,
    PARSERS[2].1,
    PARSERS[3].1,
    PARSERS[4].1,
    PARSERS[5].1,
    PARSERS[6].1,
    PARSERS[7].1,
    PARSERS[8].1,
    PARSERS[9].1,
    PARSERS[10].1,
    PARSERS[11].1,
    PARSERS[12].1,
    PARSERS[13].1,
    OTHER,
];

fn namespace(parser_chain: &str) -> Namespace {
    let root = parser_chain.split('/').next().unwrap_or("");
    PARSERS
        .iter()
        .find(|(name, _)| *name == root)
        .map_or(OTHER, |(_, namespace)| *namespace)
}

/// What a Plaso `timestamp_desc` means.
fn kind(description: &str) -> TimeKind {
    match description {
        "Creation Time" => TimeKind::Created,
        "Content Modification Time" | "Modification Time" => TimeKind::Modified,
        "Last Access Time" => TimeKind::Accessed,
        "Metadata Modification Time" | "Entry Modification Time" => TimeKind::MetadataChanged,
        "Last Time Executed" | "Previous Last Time Executed" => TimeKind::Executed,
        "Deletion Time" => TimeKind::Deleted,
        "Event Recorded" | "Written Time" | "Recorded Time" | "Log Time" => TimeKind::Logged,
        "First Connection Time" | "First Time Seen" => TimeKind::FirstSeen,
        "Last Connection Time" | "Last Visited Time" | "Last Time Seen" => TimeKind::LastSeen,
        _ => TimeKind::Other,
    }
}

const L2TCSV_HEADER: &str =
    "date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra";
const DYNAMIC_HEADER: &str =
    "datetime,timestamp_desc,source,source_long,message,parser,display_name";

/// Imports Plaso's `psort` output.
#[derive(Debug, Default, Clone, Copy)]
pub struct PlasoAdapter;

impl Adapter for PlasoAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "plaso-import",
            version: env!("CARGO_PKG_VERSION"),
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        NAMESPACES
    }

    fn probe(&self, _name: &str, head: &[u8]) -> Confidence {
        let text = String::from_utf8_lossy(head);
        let first = text
            .trim_start_matches('\u{feff}')
            .lines()
            .next()
            .unwrap_or("");
        let json_event = first.starts_with('{')
            && first.contains("\"__container_type__\": \"event\"")
            && first.contains("\"timestamp_desc\"");
        if json_event || first.starts_with(DYNAMIC_HEADER) || first.starts_with(L2TCSV_HEADER) {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let text = std::str::from_utf8(input.data).map_err(|e| {
            ParseError::at(e.valid_up_to() as u64, "not UTF-8 text: not Plaso output")
        })?;
        let text = text.trim_start_matches('\u{feff}');
        let first = text.lines().next().unwrap_or("");
        if first.starts_with('{') {
            self.parse_json_lines(input, text, sink);
            Ok(())
        } else if first.starts_with(DYNAMIC_HEADER) || first.starts_with(L2TCSV_HEADER) {
            self.parse_csv(input, text, sink);
            Ok(())
        } else {
            Err(ParseError::at(
                0,
                "not psort json_line, dynamic or l2tcsv output",
            ))
        }
    }
}

impl PlasoAdapter {
    fn parse_json_lines(self, input: &Input<'_>, text: &str, sink: &mut dyn Sink) {
        for (index, line) in text.lines().enumerate() {
            let locator = Locator::Line(index as u64 + 1);
            if line.trim().is_empty() {
                continue;
            }
            let event = match json::parse(line) {
                Ok(event @ Json::Object(_)) => event,
                Ok(_) => {
                    sink.skipped(Skipped {
                        locator,
                        reason: "not a JSON object".to_owned(),
                    });
                    continue;
                }
                Err(e) => {
                    sink.skipped(Skipped {
                        locator,
                        reason: format!("invalid JSON: {e}"),
                    });
                    continue;
                }
            };
            let Some(ts) = json_time(&event) else {
                sink.skipped(Skipped {
                    locator,
                    reason: "no usable timestamp".to_owned(),
                });
                continue;
            };
            let text = |name: &str| event.get(name).and_then(Json::as_str).map(str::to_owned);
            let parser = text("parser").unwrap_or_default();
            let mut record =
                Record::new(input.evidence, namespace(&parser), locator, self.parser());
            let description = text("timestamp_desc").unwrap_or_else(|| "time".to_owned());
            record
                .times
                .push(RecordTime::new(kind(&description), description, ts));
            record.facets = json_facets(&event);
            record.summary = text("message").unwrap_or_default();
            record.fields = json_fields(&event);
            sink.record(record);
        }
    }

    fn parse_csv(self, input: &Input<'_>, text: &str, sink: &mut dyn Sink) {
        let mut rows = csv::records(text);
        let Some(Ok(header)) = rows.next() else {
            return;
        };
        let header = header.fields;
        let l2tcsv = header.first().is_some_and(|c| c == "date");
        for row in rows {
            let row = match row {
                Ok(row) => row,
                Err(e) => {
                    sink.skipped(Skipped {
                        locator: Locator::Line(e.line),
                        reason: e.message.to_owned(),
                    });
                    continue;
                }
            };
            let locator = Locator::Line(row.line);
            if row.fields.len() != header.len() {
                sink.skipped(Skipped {
                    locator,
                    reason: format!(
                        "{} fields where the header has {}",
                        row.fields.len(),
                        header.len()
                    ),
                });
                continue;
            }
            let r = CsvRow {
                header: &header,
                cells: &row.fields,
            };
            let parsed = if l2tcsv {
                l2tcsv_times(&r)
            } else {
                dynamic_times(&r)
            };
            let times = match parsed {
                Ok(times) => times,
                Err(reason) => {
                    sink.skipped(Skipped { locator, reason });
                    continue;
                }
            };
            let parser = r
                .get(if l2tcsv { "format" } else { "parser" })
                .unwrap_or("");
            let mut record = Record::new(input.evidence, namespace(parser), locator, self.parser());
            record.times = times;
            r.get(if l2tcsv { "desc" } else { "message" })
                .unwrap_or("")
                .clone_into(&mut record.summary);
            record.facets = Facets {
                host_name: r.get("host").map(str::to_owned),
                user_name: r.get("user").map(str::to_owned),
                ..Facets::default()
            };
            let mut fields = Fields::new();
            for (column, value) in header.iter().zip(&row.fields) {
                if !value.is_empty() && value != "-" {
                    fields.insert(column.clone(), Value::from(value.as_str()));
                }
            }
            record.fields = fields;
            sink.record(record);
        }
    }
}

/// A CSV row, by column name; empty cells and `-` read as absent.
struct CsvRow<'a> {
    header: &'a [String],
    cells: &'a [String],
}

impl<'a> CsvRow<'a> {
    fn get(&self, column: &str) -> Option<&'a str> {
        let index = self.header.iter().position(|c| c == column)?;
        self.cells
            .get(index)
            .map(String::as_str)
            .filter(|v| !v.is_empty() && *v != "-")
    }
}

/// `dynamic`: one zoned ISO 8601 time and its description.
fn dynamic_times(r: &CsvRow<'_>) -> Result<Vec<RecordTime>, String> {
    let stamp = r.get("datetime").ok_or("no datetime")?;
    let ts = timestamp::zoned(stamp)
        .and_then(|ts| to_the_second(&ts))
        .ok_or_else(|| format!("datetime '{stamp}' isn't ISO 8601 with an offset"))?;
    let description = r.get("timestamp_desc").unwrap_or("time");
    Ok(vec![RecordTime::new(kind(description), description, ts)])
}

/// `ts` without its (untrustworthy) fraction, at second precision.
fn to_the_second(ts: &Ts) -> Option<Ts> {
    let ticks = ts.ticks()?;
    Some(Ts::from_ticks(
        ticks - ticks.rem_euclid(10_000_000),
        Precision::Second,
    ))
}

/// `l2tcsv`: `MM/DD/YYYY`, `HH:MM:SS`, a zone that must be UTC, and one or
/// more descriptions for the same instant (`Creation Time; Last Access Time`).
fn l2tcsv_times(r: &CsvRow<'_>) -> Result<Vec<RecordTime>, String> {
    let zone = r.get("timezone").unwrap_or("");
    if zone != "UTC" {
        return Err(format!("time zone '{zone}': rerun psort with -z UTC"));
    }
    let (date, time) = (
        r.get("date").ok_or("no date")?,
        r.get("time").ok_or("no time")?,
    );
    let mut parts = date.split('/');
    let (Some(month), Some(day), Some(year), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(format!("date '{date}' isn't MM/DD/YYYY"));
    };
    let ts = timestamp::utc(&format!("{year}-{month}-{day} {time}"))
        .ok_or_else(|| format!("date '{date} {time}' isn't MM/DD/YYYY HH:MM:SS"))?;
    Ok(r.get("type")
        .unwrap_or("time")
        .split("; ")
        .map(|description| RecordTime::new(kind(description), description, ts))
        .collect())
}

/// 100 ns ticks per microsecond.
const TICKS_PER_MICRO: i64 = 10;

/// An event's time: FILETIME exactly, local-by-nature times as local,
/// anything else from Plaso's normalised microseconds.
fn json_time(event: &Json) -> Option<Ts> {
    let micros = event.get("timestamp").and_then(Json::as_i64)?;
    let date_time = event.get("date_time");
    let class = date_time
        .and_then(|d| d.get("__class_name__"))
        .and_then(Json::as_str);
    let is_local = date_time
        .and_then(|d| d.get("is_local_time"))
        .is_some_and(|v| *v == Json::Bool(true));
    if class == Some("FATDateTime") || is_local {
        return Some(Ts::from_local_ticks(
            micros * TICKS_PER_MICRO,
            Precision::TwoSeconds,
        ));
    }
    if class == Some("Filetime") {
        let filetime = date_time?.get("timestamp").and_then(Json::as_u64)?;
        return Some(Ts::from_filetime(filetime));
    }
    Some(Ts::from_unix_micros(micros))
}

/// Members that are envelope or become the record's time and summary.
const ENVELOPE: [&str; 5] = [
    "__container_type__",
    "__type__",
    "timestamp",
    "timestamp_desc",
    "message",
];

fn json_fields(event: &Json) -> Fields {
    let mut fields = Fields::new();
    let Json::Object(members) = event else {
        return fields;
    };
    for (name, value) in members {
        if ENVELOPE.contains(&name.as_str()) {
            continue;
        }
        if name == "date_time" {
            if let Some(class) = value.get("__class_name__").and_then(Json::as_str) {
                fields.insert("date_time_class".to_owned(), Value::from(class));
            }
            continue;
        }
        if name == "pathspec" {
            if let Some(location) = value.get("location").and_then(Json::as_str) {
                fields.insert("pathspec_location".to_owned(), Value::from(location));
            }
            continue;
        }
        fields.insert(name.clone(), json_value(value));
    }
    fields
}

fn json_value(value: &Json) -> Value {
    match value {
        Json::Null => Value::Null,
        Json::Bool(b) => Value::Bool(*b),
        Json::Int(n) => Value::Int(*n),
        Json::UInt(n) => Value::UInt(*n),
        Json::Float(f) => Value::Float(*f),
        Json::String(s) => Value::from(s.as_str()),
        Json::Array(items) => Value::List(items.iter().map(json_value).collect()),
        Json::Object(_) => Value::from(value.to_string()),
    }
}

fn json_facets(event: &Json) -> Facets {
    let text = |name: &str| {
        event
            .get(name)
            .and_then(Json::as_str)
            .filter(|v| !v.is_empty() && *v != "-")
            .map(str::to_owned)
    };
    let parser = text("parser").unwrap_or_default();
    let file_path = text("local_path").or_else(|| text("filename")).or_else(|| {
        // For file system parsers the display name is the file.
        ["mft", "filestat", "usnjrnl"]
            .contains(&parser.split('/').next().unwrap_or(""))
            .then(|| text("display_name"))
            .flatten()
            .map(|name| {
                name.split_once(':')
                    .map_or(name.clone(), |(_, path)| path.to_owned())
            })
    });
    Facets {
        host_name: text("hostname").or_else(|| text("computer_name")),
        user_name: text("username"),
        user_sid: text("user_sid"),
        event_code: event
            .get("event_identifier")
            .and_then(Json::as_u64)
            .and_then(|id| u32::try_from(id).ok()),
        provider: text("source_name"),
        channel: text("xml_string").and_then(|xml| between(&xml, "<Channel>", "</Channel>")),
        process_path: text("executable"),
        process_command_line: text("command_line_arguments"),
        file_path,
        ..Facets::default()
    }
}

fn between(text: &str, open: &str, close: &str) -> Option<String> {
    let start = text.find(open)? + open.len();
    let end = start + text[start..].find(close)?;
    Some(text[start..end].to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespaces_follow_the_file_level_parser() {
        assert_eq!(
            namespace("olecf/olecf_automatic_destinations/lnk"),
            Namespace::new("plaso.olecf")
        );
        assert_eq!(namespace("winevtx"), Namespace::new("plaso.winevtx"));
        assert_eq!(namespace("something_new/x"), OTHER);
        assert_eq!(NAMESPACES.len(), PARSERS.len() + 1);
    }

    #[test]
    fn keeps_filetime_ticks_and_local_times_local() {
        let event = |class: &str, extra: &str| {
            json::parse(&format!(
                r#"{{"timestamp": 1585879293551811, "date_time": {{"__class_name__": "{class}", "timestamp": 132303528935518108{extra}}}}}"#
            ))
            .unwrap()
        };
        let exact = json_time(&event("Filetime", "")).unwrap();
        assert_eq!(
            exact.to_iso8601().as_deref(),
            Some("2020-04-03T02:01:33.5518108Z")
        );
        let fat = json_time(&event("FATDateTime", "")).unwrap();
        assert_eq!(fat.semantic(), common::time::Semantic::LocalUnknownZone);
        let posix = json_time(&event("PosixTimeInNanoseconds", "")).unwrap();
        assert_eq!(
            posix.to_iso8601().as_deref(),
            Some("2020-04-03T02:01:33.5518110Z")
        );
    }

    #[test]
    fn reads_l2tcsv_groups_and_refuses_other_zones() {
        let header: Vec<String> = ["date", "time", "timezone", "type"]
            .map(String::from)
            .to_vec();
        let cells = |zone: &str| -> Vec<String> {
            [
                "03/02/2025",
                "08:14:37",
                zone,
                "Content Modification Time; Creation Time",
            ]
            .map(String::from)
            .to_vec()
        };
        let utc = cells("UTC");
        let times = l2tcsv_times(&CsvRow {
            header: &header,
            cells: &utc,
        })
        .unwrap();
        assert_eq!(times.len(), 2);
        assert_eq!(times[1].kind, TimeKind::Created);
        assert_eq!(
            times[0].ts.to_iso8601().as_deref(),
            Some("2025-03-02T08:14:37.0000000Z")
        );
        let paris = cells("Europe/Paris");
        assert!(l2tcsv_times(&CsvRow {
            header: &header,
            cells: &paris
        })
        .unwrap_err()
        .contains("-z UTC"));
    }
}
