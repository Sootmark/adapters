//! Windows Event Logs, via the `evtx` parser.

use std::path::Path;

use evtx::{DamagedRecord, DataItem, EvtxFile, System};
use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};

/// Records of `.evtx` files.
pub const NAMESPACE: Namespace = Namespace::new("windows.evtx");

const FILE_SIGNATURE: &[u8] = b"ElfFile\0";
/// Security log placeholder meaning "no value".
const EMPTY_PLACEHOLDER: &str = "-";

/// Maps `evtx` records into Sootmark records: one record per event, located
/// by its file offset, timed by `TimeCreated`.
#[derive(Debug, Default, Clone, Copy)]
pub struct EvtxAdapter;

impl Adapter for EvtxAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "evtx",
            version: evtx::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[NAMESPACE]
    }

    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        let has_extension = Path::new(name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("evtx"));
        if head.starts_with(FILE_SIGNATURE) {
            Confidence::Certain
        } else if has_extension {
            Confidence::Maybe
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let file =
            EvtxFile::new(input.data).map_err(|e| ParseError::at(e.offset, e.kind.to_string()))?;
        for chunk in file.chunks() {
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(e) => {
                    sink.skipped(Skipped {
                        locator: Locator::ByteOffset(e.offset),
                        reason: format!("chunk: {}", e.kind),
                    });
                    continue;
                }
            };
            for record in chunk.records() {
                match record {
                    Ok(record) => sink.record(self.to_record(input, &record)),
                    Err(damaged) => sink.skipped(skipped(&damaged)),
                }
            }
        }
        Ok(())
    }
}

impl EvtxAdapter {
    fn to_record(self, input: &Input<'_>, event: &evtx::Record) -> Record {
        let system = event.system();
        let data = event.data();
        let mut record = Record::new(
            input.evidence,
            NAMESPACE,
            Locator::ByteOffset(event.offset),
            self.parser(),
        );
        record.times.push(match system.time_created {
            Some(ts) => RecordTime::new(TimeKind::Logged, "TimeCreated", ts),
            None => RecordTime::new(TimeKind::Logged, "RecordWritten", event.written_ts()),
        });
        record.facets = facets(&system, &data);
        // The event's own EventRecordID, as Event Viewer shows it; a log
        // exported from another renumbers its record headers.
        let record_id = system.record_id.unwrap_or(event.id);
        record.fields = fields(record_id, &system, &data);
        record.summary = summary(&system, &record.facets);
        record
    }
}

fn skipped(damaged: &DamagedRecord) -> Skipped {
    Skipped {
        locator: Locator::ByteOffset(damaged.offset),
        reason: damaged.error.kind.to_string(),
    }
}

/// The first non-empty value among data items named `names`, in order of preference.
fn first(data: &[DataItem], names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| {
        data.iter()
            .find(|item| item.name.as_deref() == Some(name))
            .map(|item| item.value.trim())
            .filter(|value| !value.is_empty() && *value != EMPTY_PLACEHOLDER)
            .map(str::to_owned)
    })
}

/// Parse a decimal or `0x` hexadecimal integer, as event logs write both.
fn parse_integer(text: &str) -> Option<u64> {
    match text.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}

fn facets(system: &System, data: &[DataItem]) -> Facets {
    Facets {
        host_name: system.computer.clone(),
        user_name: first(data, &["TargetUserName", "SubjectUserName", "User"]),
        user_sid: first(data, &["TargetUserSid", "SubjectUserSid"])
            .or_else(|| system.user_id.clone()),
        logon_id: first(data, &["TargetLogonId", "SubjectLogonId", "LogonId"]),
        logon_type: first(data, &["LogonType"]).and_then(|t| t.parse().ok()),
        process_path: first(data, &["NewProcessName", "Image", "ProcessName"]),
        process_command_line: first(data, &["CommandLine"]),
        process_id: first(data, &["NewProcessId", "ProcessId"])
            .as_deref()
            .and_then(parse_integer),
        parent_process_path: first(data, &["ParentProcessName", "ParentImage"]),
        file_path: first(data, &["TargetFilename", "ImagePath"]),
        service_name: first(data, &["ServiceName"]),
        task_name: first(data, &["TaskName"]),
        source_ip: first(data, &["IpAddress", "SourceIp", "SourceAddress"]),
        destination_ip: first(data, &["DestinationIp", "DestAddress"]),
        event_code: system.event_id,
        channel: system.channel.clone(),
        provider: system.provider.clone(),
    }
}

fn fields(record_id: u64, system: &System, data: &[DataItem]) -> Fields {
    let mut fields = Fields::new();
    fields.insert("EventRecordID".into(), Value::from(record_id));
    if let Some(level) = system.level {
        fields.insert("Level".into(), Value::from(u64::from(level)));
    }
    for (index, item) in data.iter().enumerate() {
        let name = item
            .name
            .clone()
            .unwrap_or_else(|| format!("Data[{index}]"));
        let unique = if fields.contains_key(&name) {
            format!("{name}[{index}]")
        } else {
            name
        };
        fields.insert(unique, Value::from(item.value.as_str()));
    }
    fields
}

/// One line for the timeline: event id and provider, then the key facets.
fn summary(system: &System, facets: &Facets) -> String {
    let event_id = system
        .event_id
        .map_or_else(|| "?".to_owned(), |id| id.to_string());
    let provider = system.provider.as_deref().unwrap_or("unknown provider");
    let details = [
        facets.user_name.clone(),
        facets.logon_type.map(|t| format!("logon type {t}")),
        facets.service_name.clone(),
        facets.task_name.clone(),
        facets.source_ip.clone(),
        facets.process_path.clone(),
        facets.process_command_line.clone(),
        facets.file_path.clone(),
    ];
    let mut line = format!("{event_id} {provider}");
    for detail in details.into_iter().flatten() {
        line.push_str(" · ");
        line.push_str(&detail);
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(name: &str, value: &str) -> DataItem {
        DataItem {
            name: Some(name.into()),
            value: value.into(),
        }
    }

    #[test]
    fn prefers_target_over_subject_and_ignores_placeholders() {
        let data = [
            item("SubjectUserName", "SYSTEM"),
            item("TargetUserName", "-"),
        ];
        assert_eq!(
            first(&data, &["TargetUserName", "SubjectUserName"]).as_deref(),
            Some("SYSTEM")
        );
    }

    #[test]
    fn parses_decimal_and_hex_integers() {
        assert_eq!(parse_integer("1234"), Some(1234));
        assert_eq!(parse_integer("0x1a4"), Some(420));
        assert_eq!(parse_integer("zzz"), None);
    }

    #[test]
    fn duplicate_data_names_stay_distinct() {
        let data = [item("Param", "a"), item("Param", "b")];
        let fields = fields(7, &System::default(), &data);
        assert_eq!(fields.get("Param"), Some(&Value::from("a")));
        assert_eq!(fields.get("Param[1]"), Some(&Value::from("b")));
    }

    #[test]
    fn summary_lists_key_facets() {
        let system = System {
            event_id: Some(4624),
            provider: Some("Microsoft-Windows-Security-Auditing".into()),
            ..System::default()
        };
        let facets = Facets {
            user_name: Some("alice".into()),
            logon_type: Some(3),
            source_ip: Some("10.0.0.5".into()),
            ..Facets::default()
        };
        assert_eq!(
            summary(&system, &facets),
            "4624 Microsoft-Windows-Security-Auditing · alice · logon type 3 · 10.0.0.5"
        );
    }

    #[test]
    fn probes_by_signature_then_extension() {
        assert_eq!(
            EvtxAdapter.probe("x.bin", b"ElfFile\0rest"),
            Confidence::Certain
        );
        assert_eq!(EvtxAdapter.probe("Security.EVTX", b""), Confidence::Maybe);
        assert_eq!(EvtxAdapter.probe("notes.txt", b"hello"), Confidence::No);
    }
}
