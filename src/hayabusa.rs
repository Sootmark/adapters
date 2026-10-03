//! Hayabusa detections (`hayabusa dfir-timeline`), imported from its CSV or
//! JSON Lines output, any profile.
//!
//! Each detection becomes one record: when the event happened, which rule
//! fired at what level, on which computer, and the event fields Hayabusa
//! printed (`Details`, `ExtraFieldInfo` or `AllFieldInfo`). Hayabusa's own
//! abbreviations are kept as written (`Sec` for Security, `TgtUser`, …),
//! except levels, which are spelled out so they compare with Sigma levels.
//!
//! Timestamps: the default (`2022-02-22 22:00:00.123 +09:00`), `-U`,
//! `-O` (ISO 8601) and `--rfc-3339` carry their zone and are read exactly.
//! The European, US and RFC 2822 formats are refused with a hint to rerun
//! with `-O`, rather than guessed.

use std::path::Path;

use common::json::{self, Json};
use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};

use crate::csv;
use crate::timestamp::zoned as parse_timestamp;

/// Hayabusa detections.
pub const NAMESPACE: Namespace = Namespace::new("hayabusa.detection");

/// Placeholder Hayabusa and Windows use for "no value".
const EMPTY: &str = "-";

/// Imports Hayabusa's timeline output.
#[derive(Debug, Default, Clone, Copy)]
pub struct HayabusaAdapter;

impl Adapter for HayabusaAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "hayabusa-import",
            version: env!("CARGO_PKG_VERSION"),
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[NAMESPACE]
    }

    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        let text = String::from_utf8_lossy(head);
        let text = text.trim_start_matches('\u{feff}').trim_start();
        let first_line = text.lines().next().unwrap_or("");
        let csv_header = first_line.starts_with("\"Timestamp\",\"RuleTitle\"")
            || first_line.starts_with("Timestamp,RuleTitle")
            || (first_line.starts_with("\"datetime\",\"timestamp_desc\",\"message\"")
                && text
                    .lines()
                    .nth(1)
                    .is_some_and(|l| l.contains(",\"hayabusa\",")));
        let jsonl = first_line.starts_with('{')
            && first_line.contains("\"Timestamp\"")
            && first_line.contains("\"RuleTitle\"");
        if csv_header || jsonl {
            Confidence::Certain
        } else if Path::new(name).file_name().is_some_and(|n| {
            n.to_string_lossy()
                .to_ascii_lowercase()
                .contains("hayabusa")
        }) {
            Confidence::Maybe
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let text = std::str::from_utf8(input.data).map_err(|e| {
            ParseError::at(
                e.valid_up_to() as u64,
                "not UTF-8 text: not Hayabusa output",
            )
        })?;
        let text = text.trim_start_matches('\u{feff}');
        if text.trim_start().starts_with('{') {
            self.parse_jsonl(input, text, sink);
            Ok(())
        } else {
            self.parse_csv(input, text, sink)
        }
    }
}

/// One detection, whatever the output format.
#[derive(Default)]
struct Detection {
    /// Hayabusa's columns other than event data, by their canonical names.
    columns: Vec<(String, Value)>,
    /// Event fields from `Details`, `ExtraFieldInfo` and `AllFieldInfo`.
    data: Vec<(String, String)>,
    timestamp: Option<String>,
}

impl Detection {
    fn column(&self, name: &str) -> Option<&Value> {
        self.columns.iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }

    fn text(&self, name: &str) -> Option<String> {
        match self.column(name)? {
            Value::Text(text) if !text.is_empty() && text != EMPTY => Some(text.clone()),
            Value::UInt(n) => Some(n.to_string()),
            Value::Int(n) => Some(n.to_string()),
            _ => None,
        }
    }

    fn datum(&self, names: &[&str]) -> Option<String> {
        names.iter().find_map(|name| {
            self.data
                .iter()
                .find(|(n, v)| n == name && !v.is_empty() && v != EMPTY)
                .map(|(_, v)| v.clone())
        })
    }
}

/// Timesketch profile columns, by the names the other profiles use.
fn canonical(column: &str) -> &str {
    match column {
        "datetime" => "Timestamp",
        "message" => "RuleTitle",
        other => other,
    }
}

/// Columns holding event data as `Key: value ¦ Key: value`.
const DATA_COLUMNS: [&str; 3] = ["Details", "ExtraFieldInfo", "AllFieldInfo"];

impl HayabusaAdapter {
    fn parse_csv(
        self,
        input: &Input<'_>,
        text: &str,
        sink: &mut dyn Sink,
    ) -> Result<(), ParseError> {
        let mut rows = csv::records(text);
        let header = match rows.next() {
            Some(Ok(header)) => header.fields,
            Some(Err(e)) => {
                return Err(ParseError::at(0, format!("line {}: {}", e.line, e.message)))
            }
            None => return Err(ParseError::at(0, "empty file")),
        };
        let header: Vec<&str> = header.iter().map(|c| canonical(c)).collect();
        if !header.contains(&"Timestamp") || !header.contains(&"RuleTitle") {
            return Err(ParseError::at(
                0,
                "no Timestamp and RuleTitle columns: not Hayabusa output",
            ));
        }
        for row in rows {
            let row = match row {
                Ok(row) => row,
                Err(e) => {
                    sink.skipped(Skipped {
                        locator: Locator::Line(e.line),
                        reason: e.message.to_owned(),
                    });
                    // A broken quote leaves the rest unreadable; the reader stops.
                    continue;
                }
            };
            if row.fields.len() != header.len() {
                sink.skipped(Skipped {
                    locator: Locator::Line(row.line),
                    reason: format!(
                        "{} fields where the header has {}",
                        row.fields.len(),
                        header.len()
                    ),
                });
                continue;
            }
            let mut detection = Detection::default();
            for (column, value) in header.iter().zip(row.fields) {
                match *column {
                    "Timestamp" => detection.timestamp = Some(value),
                    "timestamp_desc" => {}
                    name if DATA_COLUMNS.contains(&name) => {
                        detection.data.extend(split_details(&value));
                    }
                    "EventID" | "RecordID" => detection
                        .columns
                        .push(((*column).to_owned(), integer_or_text(value))),
                    name => detection
                        .columns
                        .push((name.to_owned(), Value::Text(value))),
                }
            }
            self.emit(input, row.line, &detection, sink);
        }
        Ok(())
    }

    fn parse_jsonl(self, input: &Input<'_>, text: &str, sink: &mut dyn Sink) {
        for (index, line) in text.lines().enumerate() {
            let number = index as u64 + 1;
            if line.trim().is_empty() {
                continue;
            }
            let object = match json::parse(line) {
                Ok(Json::Object(members)) => members,
                Ok(_) => {
                    sink.skipped(Skipped {
                        locator: Locator::Line(number),
                        reason: "not a JSON object".to_owned(),
                    });
                    continue;
                }
                Err(e) => {
                    sink.skipped(Skipped {
                        locator: Locator::Line(number),
                        reason: format!("invalid JSON: {e}"),
                    });
                    continue;
                }
            };
            let mut detection = Detection::default();
            for (name, value) in object {
                match canonical(&name) {
                    "Timestamp" => detection.timestamp = value.as_str().map(str::to_owned),
                    "timestamp_desc" => {}
                    column if DATA_COLUMNS.contains(&column) => match value {
                        Json::Object(members) => {
                            detection
                                .data
                                .extend(members.into_iter().map(|(k, v)| (k, json_text(&v))));
                        }
                        other => detection.data.extend(split_details(&json_text(&other))),
                    },
                    column => detection
                        .columns
                        .push((column.to_owned(), json_value(value))),
                }
            }
            self.emit(input, number, &detection, sink);
        }
    }

    fn emit(self, input: &Input<'_>, line: u64, detection: &Detection, sink: &mut dyn Sink) {
        let locator = Locator::Line(line);
        let Some(stamp) = detection.timestamp.as_deref() else {
            sink.skipped(Skipped {
                locator,
                reason: "no Timestamp".to_owned(),
            });
            return;
        };
        let Some(ts) = parse_timestamp(stamp) else {
            sink.skipped(Skipped {
                locator,
                reason: format!(
                    "timestamp '{stamp}' isn't in a zoned format: rerun Hayabusa with -O (ISO 8601)"
                ),
            });
            return;
        };
        let mut record = Record::new(input.evidence, NAMESPACE, locator, self.parser());
        record
            .times
            .push(RecordTime::new(TimeKind::Logged, "Timestamp", ts));
        record.facets = facets(detection);
        record.fields = fields(detection);
        record.summary = summary(detection);
        sink.record(record);
    }
}

fn integer_or_text(value: String) -> Value {
    value.parse::<u64>().map_or(Value::Text(value), Value::UInt)
}

fn json_text(value: &Json) -> String {
    match value {
        Json::String(text) => text.clone(),
        Json::Array(items) => items.iter().map(json_text).collect::<Vec<_>>().join(" ¦ "),
        other => other.to_string(),
    }
}

fn json_value(value: Json) -> Value {
    match value {
        Json::String(text) => Value::Text(text),
        Json::Int(n) => Value::Int(n),
        Json::UInt(n) => Value::UInt(n),
        Json::Bool(b) => Value::Bool(b),
        Json::Array(items) => Value::List(items.into_iter().map(json_value).collect()),
        other => Value::Text(other.to_string()),
    }
}

/// `Key: value ¦ Key: value`, or one pair per line (`-M`) or tab (`-S`).
/// Text that isn't in that shape is kept whole under `Details`.
fn split_details(text: &str) -> Vec<(String, String)> {
    if text.is_empty() || text == EMPTY {
        return Vec::new();
    }
    let separator = if text.contains(" ¦ ") {
        " ¦ "
    } else if text.contains('\t') {
        "\t"
    } else {
        "\n"
    };
    let pairs: Option<Vec<(String, String)>> = text
        .split(separator)
        .map(|part| {
            let (key, value) = part
                .split_once(": ")
                .or_else(|| part.strip_suffix(':').map(|k| (k, "")))?;
            Some((key.trim().to_owned(), value.trim().to_owned()))
        })
        .collect();
    pairs.unwrap_or_else(|| vec![("Details".to_owned(), text.to_owned())])
}

/// Hayabusa's level names, spelled out.
fn level(abbreviated: &str) -> &str {
    match abbreviated {
        "info" => "informational",
        "med" => "medium",
        "crit" => "critical",
        other => other,
    }
}

fn facets(d: &Detection) -> Facets {
    Facets {
        host_name: d.text("Computer"),
        channel: d.text("Channel"),
        provider: d.text("Provider"),
        event_code: d.text("EventID").and_then(|id| id.parse().ok()),
        user_name: d.datum(&[
            "TgtUser",
            "TargetUserName",
            "User",
            "SrcUser",
            "SubjectUserName",
        ]),
        logon_id: d.datum(&["LID", "TargetLogonId", "SubjectLogonId"]),
        logon_type: d
            .datum(&["Type", "LogonType"])
            .and_then(|t| t.split_whitespace().next()?.parse().ok()),
        process_path: d.datum(&["Proc", "Image", "NewProcessName", "ProcessName"]),
        process_command_line: d.datum(&["Cmdline", "CommandLine"]),
        parent_process_path: d.datum(&["ParentImage", "ParentProcessName"]),
        source_ip: d.datum(&["SrcIP", "IpAddress", "SourceIp"]),
        destination_ip: d.datum(&["TgtIP", "DestinationIp"]),
        service_name: d.datum(&["Svc", "ServiceName"]),
        task_name: d.datum(&["TaskName", "Name"]),
        ..Facets::default()
    }
}

fn fields(d: &Detection) -> Fields {
    let mut fields = Fields::new();
    for (name, value) in &d.columns {
        let value = match (name.as_str(), value) {
            ("Level", Value::Text(text)) => Value::from(level(text)),
            _ => value.clone(),
        };
        fields.insert(name.clone(), value);
    }
    for (name, value) in &d.data {
        // Event data never replaces Hayabusa's own columns.
        let key = if fields.contains_key(name) {
            format!("{name}_data")
        } else {
            name.clone()
        };
        fields
            .entry(key)
            .or_insert_with(|| Value::from(value.as_str()));
    }
    fields
}

fn summary(d: &Detection) -> String {
    let mut line = format!(
        "Hayabusa {}: {}",
        d.text("Level").as_deref().map_or("?", level),
        d.text("RuleTitle").unwrap_or_default()
    );
    if let Some(event) = d.text("EventID") {
        line.push_str(" · ");
        line.push_str(&event);
    }
    let details: Vec<String> = d
        .data
        .iter()
        .take(4)
        .map(|(k, v)| format!("{k}: {v}"))
        .collect();
    if !details.is_empty() {
        line.push_str(" · ");
        line.push_str(&details.join(" · "));
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_details_in_every_layout() {
        let pairs = |t: &str| split_details(t);
        assert_eq!(
            pairs("TgtUser: admin ¦ SrcIP: - ¦ Proc: C:\\a.exe"),
            [
                ("TgtUser".into(), "admin".into()),
                ("SrcIP".into(), "-".into()),
                ("Proc".into(), "C:\\a.exe".into())
            ]
        );
        assert_eq!(pairs("A: 1\tB: 2").len(), 2);
        assert_eq!(
            pairs("A: 1\nB: x: y"),
            [("A".into(), "1".into()), ("B".into(), "x: y".into())]
        );
        assert_eq!(
            pairs("ProcessName:"),
            [("ProcessName".into(), String::new())]
        );
        assert_eq!(pairs("free text"), [("Details".into(), "free text".into())]);
        assert!(pairs("-").is_empty());
    }

    #[test]
    fn probes_headers_and_lines() {
        let a = HayabusaAdapter;
        assert_eq!(
            a.probe("x.csv", b"\"Timestamp\",\"RuleTitle\",\"Level\"\n"),
            Confidence::Certain
        );
        assert_eq!(
            a.probe("x.jsonl", b"{ \"Timestamp\":\"2020\",\"RuleTitle\":\"x\" }"),
            Confidence::Certain
        );
        assert_eq!(
            a.probe(
                "t.csv",
                b"\"datetime\",\"timestamp_desc\",\"message\"\n\"2020\",\"hayabusa\",\"x\"\n"
            ),
            Confidence::Certain
        );
        assert_eq!(
            a.probe("hayabusa-results.csv", b"garbage"),
            Confidence::Maybe
        );
        assert_eq!(a.probe("other.csv", b"a,b,c\n"), Confidence::No);
    }
}
