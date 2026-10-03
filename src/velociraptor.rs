//! Velociraptor artifact results (`results/<Artifact>.json` in a
//! collection, JSON Lines), imported row by row.
//!
//! Common artifacts get their own mapping: which timestamps mean what and
//! which values fill the timeline's facets. Every other artifact is still
//! imported: each UTC timestamp in its rows becomes a time (meaning
//! unknown, named by its field), and every value is kept as a field, nested
//! objects flattened (`ShellLinkHeader_CreationTime`). Rows without any
//! timestamp stay in the case, untimed.

use common::json::{self, Json};
use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};

use crate::timestamp;

use TimeKind::{Accessed, Created, Deleted, Executed, Logged, MetadataChanged, Modified};

/// How a known artifact's rows map.
struct Spec {
    /// Artifact names (sources included, `Artifact/Source`).
    artifacts: &'static [&'static str],
    namespace: Namespace,
    /// Flattened field names of times, and what they mean. `[]` expands a
    /// list of times.
    times: &'static [(&'static str, TimeKind)],
    facets: fn(&Row) -> Facets,
    summary: fn(&Row) -> String,
}

/// A row, flattened: `a_b_c` for nested members.
struct Row {
    artifact: String,
    fields: Vec<(String, Json)>,
}

impl Row {
    fn get(&self, name: &str) -> Option<&Json> {
        self.fields.iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }

    fn text(&self, name: &str) -> Option<String> {
        match self.get(name)? {
            Json::String(s) if !s.is_empty() => Some(s.clone()),
            Json::Int(n) => Some(n.to_string()),
            Json::UInt(n) => Some(n.to_string()),
            _ => None,
        }
    }
}

const RESULT: Namespace = Namespace::new("velociraptor.result");

const SPECS: &[Spec] = &[
    Spec {
        artifacts: &["Windows.Forensics.Prefetch"],
        namespace: Namespace::new("velociraptor.prefetch"),
        times: &[
            ("LastRunTimes[]", Executed),
            ("CreationTime", Created),
            ("ModificationTime", Modified),
        ],
        facets: |r| Facets {
            process_path: r.text("Binary").or_else(|| r.text("Executable")),
            ..Facets::default()
        },
        summary: |r| {
            format!(
                "Prefetch {} · run {} times",
                r.text("Executable").unwrap_or_else(|| "?".into()),
                r.text("RunCount").unwrap_or_else(|| "?".into())
            )
        },
    },
    Spec {
        artifacts: &["Windows.Forensics.Lnk"],
        namespace: Namespace::new("velociraptor.lnk"),
        times: &[
            ("ShellLinkHeader_CreationTime", Created),
            ("ShellLinkHeader_WriteTime", Modified),
            ("ShellLinkHeader_AccessTime", Accessed),
            ("SourceFile_Btime", Created),
            ("SourceFile_Mtime", Modified),
        ],
        facets: |r| Facets {
            file_path: r
                .text("LinkInfo_Target_Path")
                .or_else(|| r.text("LinkTarget_LinkTarget")),
            process_command_line: r.text("StringData_Arguments"),
            ..Facets::default()
        },
        summary: |r| {
            let mut line = format!(
                "LNK → {}",
                r.text("LinkInfo_Target_Path")
                    .or_else(|| r.text("LinkTarget_LinkTarget"))
                    .unwrap_or_else(|| "(no target path)".into())
            );
            if let Some(arguments) = r.text("StringData_Arguments") {
                line.push(' ');
                line.push_str(&arguments);
            }
            line
        },
    },
    Spec {
        artifacts: &["Windows.Forensics.RecycleBin"],
        namespace: Namespace::new("velociraptor.recyclebin"),
        times: &[("DeletedTimestamp", Deleted)],
        facets: |r| Facets {
            file_path: r.text("OriginalFilePath"),
            user_sid: r.text("OSPath").and_then(|p| {
                p.split(['\\', '/'])
                    .find(|part| part.starts_with("S-1-"))
                    .map(str::to_owned)
            }),
            ..Facets::default()
        },
        summary: |r| {
            format!(
                "Recycle bin: deleted {}",
                r.text("OriginalFilePath").unwrap_or_else(|| "?".into())
            )
        },
    },
    Spec {
        artifacts: &["Windows.NTFS.MFT"],
        namespace: Namespace::new("velociraptor.mft"),
        times: &[
            ("Created0x10", Created),
            ("Created0x30", Created),
            ("LastModified0x10", Modified),
            ("LastModified0x30", Modified),
            ("LastRecordChange0x10", MetadataChanged),
            ("LastRecordChange0x30", MetadataChanged),
            ("LastAccess0x10", Accessed),
            ("LastAccess0x30", Accessed),
        ],
        facets: |r| Facets {
            file_path: r.text("OSPath"),
            ..Facets::default()
        },
        summary: |r| {
            let deleted = if r.get("InUse") == Some(&Json::Bool(false)) {
                " (deleted)"
            } else {
                ""
            };
            format!(
                "MFT entry{deleted} · {}",
                r.text("OSPath").unwrap_or_else(|| "?".into())
            )
        },
    },
    Spec {
        artifacts: &["Windows.EventLogs.EvtxHunter", "Windows.EventLogs.Evtx"],
        namespace: Namespace::new("velociraptor.evtx"),
        times: &[("EventTime", Logged), ("TimeCreated", Logged)],
        facets: |r| Facets {
            host_name: r.text("Computer"),
            channel: r.text("Channel"),
            provider: r.text("Provider"),
            event_code: r.text("EventID").and_then(|id| id.parse().ok()),
            user_name: r.text("Username"),
            user_sid: r.text("UserSID"),
            ..Facets::default()
        },
        summary: |r| {
            let mut line = format!(
                "{} {}",
                r.text("EventID").unwrap_or_else(|| "?".into()),
                r.text("Provider").unwrap_or_else(|| "?".into())
            );
            if let Some(message) = r.text("Message") {
                line.push_str(" · ");
                line.push_str(&message);
            }
            line
        },
    },
    Spec {
        artifacts: &[
            "Windows.Forensics.SRUM/Application Resource Usage",
            "Windows.Forensics.SRUM/Network Usage",
            "Windows.Forensics.SRUM/Network Connections",
            "Windows.Forensics.SRUM/Execution Stats",
        ],
        namespace: Namespace::new("velociraptor.srum"),
        // When SRUM recorded the interval's totals.
        times: &[("TimeStamp", Logged)],
        facets: |r| Facets {
            process_path: r.text("App"),
            user_sid: r.text("UserSid"),
            user_name: r.text("User"),
            ..Facets::default()
        },
        summary: |r| {
            let table = r.artifact.split('/').nth(1).unwrap_or("SRUM");
            format!(
                "SRUM {table} · {}",
                r.text("App").unwrap_or_else(|| "?".into())
            )
        },
    },
];

/// Every namespace this importer produces.
pub const NAMESPACES: &[Namespace] = &[
    SPECS[0].namespace,
    SPECS[1].namespace,
    SPECS[2].namespace,
    SPECS[3].namespace,
    SPECS[4].namespace,
    SPECS[5].namespace,
    RESULT,
];

/// The artifact a results path names: `results/Windows.X.json`, or with a
/// source, `results/Windows.X%2FSource.json` (as collections write it) or
/// `results/Windows.X/Source.json`.
fn artifact_of(name: &str) -> Option<String> {
    let normalised = percent_decode(&name.replace('\\', "/"));
    let rest = normalised.split("results/").nth(1)?;
    let artifact = rest.strip_suffix(".json")?;
    let first = artifact.split('/').next()?;
    let looks_like_artifact = first.contains('.')
        && first.split('.').all(|part| {
            !part.is_empty() && part.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        });
    looks_like_artifact.then(|| artifact.to_owned())
}

/// `%XX` escapes decoded; invalid ones kept as written.
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let escaped = (bytes[i] == b'%')
            .then(|| text.get(i + 1..i + 3))
            .flatten()
            .and_then(|hex| u8::from_str_radix(hex, 16).ok());
        if let Some(byte) = escaped {
            out.push(byte);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| text.to_owned())
}

/// Imports Velociraptor artifact results.
#[derive(Debug, Default, Clone, Copy)]
pub struct VelociraptorAdapter;

impl Adapter for VelociraptorAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "velociraptor-import",
            version: env!("CARGO_PKG_VERSION"),
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        NAMESPACES
    }

    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        let starts_with_object = head.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'{');
        match (artifact_of(name), starts_with_object || head.is_empty()) {
            (Some(_), true) => Confidence::Certain,
            _ => Confidence::No,
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let artifact = artifact_of(input.name).ok_or_else(|| {
            ParseError::at(
                0,
                "not a Velociraptor results file (results/<Artifact>.json)",
            )
        })?;
        let text = std::str::from_utf8(input.data)
            .map_err(|e| ParseError::at(e.valid_up_to() as u64, "not UTF-8 JSON Lines"))?;
        let spec = SPECS
            .iter()
            .find(|spec| spec.artifacts.contains(&artifact.as_str()));
        for (index, line) in text.lines().enumerate() {
            let locator = Locator::Line(index as u64 + 1);
            if line.trim().is_empty() {
                continue;
            }
            let row = match json::parse(line) {
                Ok(Json::Object(members)) => {
                    let mut fields = Vec::new();
                    flatten("", members, 0, &mut fields);
                    Row {
                        artifact: artifact.clone(),
                        fields,
                    }
                }
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
            sink.record(self.record(input, spec, &row, locator));
        }
        Ok(())
    }
}

/// Deeper than this, objects are kept as JSON text.
const MAX_DEPTH: usize = 3;

fn flatten(
    prefix: &str,
    members: Vec<(String, Json)>,
    depth: usize,
    out: &mut Vec<(String, Json)>,
) {
    for (name, value) in members {
        let key = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}_{name}")
        };
        match value {
            Json::Object(inner) if depth < MAX_DEPTH => flatten(&key, inner, depth + 1, out),
            other => out.push((key, other)),
        }
    }
}

impl VelociraptorAdapter {
    fn record(self, input: &Input<'_>, spec: Option<&Spec>, row: &Row, locator: Locator) -> Record {
        let namespace = spec.map_or(RESULT, |s| s.namespace);
        let mut record = Record::new(input.evidence, namespace, locator, self.parser());
        record.times = match spec {
            Some(spec) => known_times(spec, row),
            None => any_times(row),
        };
        let mut fields = Fields::new();
        fields.insert("Artifact".to_owned(), Value::from(row.artifact.as_str()));
        for (name, value) in &row.fields {
            if *value != Json::Null {
                fields.insert(name.clone(), value_of(value));
            }
        }
        record.fields = fields;
        match spec {
            Some(spec) => {
                record.facets = (spec.facets)(row);
                record.summary = (spec.summary)(row);
            }
            None => record.summary = generic_summary(row),
        }
        record
    }
}

fn utc(value: &Json) -> Option<common::time::Ts> {
    let text = value.as_str()?;
    // Zero times ("0001-01-01…", "1601-01-01…") mean "not set".
    if text.starts_with("0001-") || text.starts_with("1601-01-01T00:00:00") {
        return None;
    }
    timestamp::zoned(text)
}

fn known_times(spec: &Spec, row: &Row) -> Vec<RecordTime> {
    let mut times = Vec::new();
    for &(field, kind) in spec.times {
        if let Some(list) = field.strip_suffix("[]") {
            if let Some(Json::Array(items)) = row.get(list) {
                for (index, item) in items.iter().enumerate() {
                    if let Some(ts) = utc(item) {
                        times.push(RecordTime::new(kind, format!("{list}[{index}]"), ts));
                    }
                }
            }
        } else if let Some(ts) = row.get(field).and_then(utc) {
            times.push(RecordTime::new(kind, field, ts));
        }
    }
    times
}

/// Every top-level or flattened string that is a zoned timestamp.
fn any_times(row: &Row) -> Vec<RecordTime> {
    row.fields
        .iter()
        .filter_map(|(name, value)| {
            Some(RecordTime::new(TimeKind::Other, name.clone(), utc(value)?))
        })
        .collect()
}

fn generic_summary(row: &Row) -> String {
    let details: Vec<String> = row
        .fields
        .iter()
        .filter(|(name, _)| !name.starts_with('_'))
        .filter_map(|(name, value)| match value {
            Json::String(s) if !s.is_empty() && utc(value).is_none() => {
                Some(format!("{name}: {s}"))
            }
            Json::Int(n) => Some(format!("{name}: {n}")),
            _ => None,
        })
        .take(4)
        .collect();
    format!("{} · {}", row.artifact, details.join(" · "))
}

fn value_of(value: &Json) -> Value {
    match value {
        Json::Null => Value::Null,
        Json::Bool(b) => Value::Bool(*b),
        Json::Int(n) => Value::Int(*n),
        Json::UInt(n) => Value::UInt(*n),
        Json::Float(f) => Value::Float(*f),
        Json::String(s) => Value::from(s.as_str()),
        Json::Array(items) => Value::List(items.iter().map(value_of).collect()),
        Json::Object(_) => Value::from(value.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_artifacts_from_results_paths() {
        assert_eq!(
            artifact_of("results/Windows.Forensics.Prefetch.json").as_deref(),
            Some("Windows.Forensics.Prefetch")
        );
        assert_eq!(
            artifact_of(r"results\Windows.KapeFiles.Targets\All File Metadata.json").as_deref(),
            Some("Windows.KapeFiles.Targets/All File Metadata")
        );
        assert_eq!(
            artifact_of("results/Windows.Forensics.Prefetch.json.index"),
            None
        );
        assert_eq!(artifact_of("uploads/auto/C%3A/x.json"), None);
        assert_eq!(artifact_of("results/notes.json"), None);
    }

    #[test]
    fn flattens_nested_members() {
        let Json::Object(members) = json::parse(r#"{"A": {"B": {"C": 1}}, "D": [1]}"#).unwrap()
        else {
            unreachable!()
        };
        let mut out = Vec::new();
        flatten("", members, 0, &mut out);
        assert_eq!(out[0].0, "A_B_C");
        assert_eq!(out[1].0, "D");
    }

    #[test]
    fn ignores_unset_times() {
        assert!(utc(&Json::from("1601-01-01T00:00:00Z")).is_none());
        assert!(utc(&Json::from("0001-01-01T00:00:00Z")).is_none());
        assert!(utc(&Json::from("2026-09-14T10:52:41Z")).is_some());
        assert!(utc(&Json::from("not a time")).is_none());
    }
}
