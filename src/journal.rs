//! systemd journal files, via the `journal` parser: one record per entry,
//! with its fields, and what sshd, sudo, su, cron and the account tools
//! logged read as in syslog files (on systems without `auth.log`, the
//! journal is where logins are).
//!
//! Entries recovered from a damaged file, which journalctl wouldn't show,
//! are kept and marked (`Recovered`).

use std::collections::BTreeMap;

use journal::{Entry, Journal, Value as JournalValue};
use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};
use syslog::auth::{classify_message, Event};

use crate::syslog::{event_fields, event_summary};

/// Records of systemd journal files.
pub const NAMESPACE: Namespace = Namespace::new("linux.journal");

const SIGNATURE: &[u8] = b"LPKSHHRH";
const SUMMARY_MESSAGE: usize = 160;
/// Longest field value kept as text; core dumps and the like are cut.
const MAX_VALUE_TEXT: usize = 64 * 1024;

/// One record per entry.
#[derive(Debug, Default, Clone, Copy)]
pub struct JournalAdapter;

impl Adapter for JournalAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "journal",
            version: journal::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[NAMESPACE]
    }

    fn probe(&self, _name: &str, head: &[u8]) -> Confidence {
        if head.starts_with(SIGNATURE) {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let parsed =
            Journal::parse(input.data).map_err(|error| ParseError::at(0, error.to_string()))?;
        for problem in parsed.problems {
            sink.skipped(Skipped {
                locator: Locator::ByteOffset(0),
                reason: problem,
            });
        }
        for entry in &parsed.entries {
            sink.record(self.to_record(input, entry));
        }
        Ok(())
    }
}

impl JournalAdapter {
    fn to_record(self, input: &Input<'_>, entry: &Entry) -> Record {
        let mut record = Record::new(
            input.evidence,
            NAMESPACE,
            Locator::ByteOffset(entry.offset),
            self.parser(),
        );
        record.times.push(RecordTime::new(
            TimeKind::Logged,
            "__REALTIME_TIMESTAMP",
            entry.time,
        ));
        let identifier = entry.syslog_identifier().or_else(|| entry.comm());
        let message = entry.message().unwrap_or_default();
        let event = identifier
            .as_deref()
            .and_then(|program| classify_message(program, &message));
        record.facets = Facets {
            host_name: entry.hostname().map(Into::into),
            user_name: event.as_ref().and_then(|e| e.user.clone()),
            process_path: entry.exe().map(Into::into),
            process_command_line: event
                .as_ref()
                .and_then(|e| e.command.clone())
                .or_else(|| entry.cmdline().map(Into::into)),
            process_id: entry.pid().map(u64::from),
            service_name: entry.systemd_unit().map(Into::into),
            source_ip: event.as_ref().and_then(|e| e.source_ip.clone()),
            ..Facets::default()
        };
        record.fields = fields(entry, event.as_ref());
        record.summary = event.as_ref().map_or_else(
            || {
                let line: String = message
                    .lines()
                    .next()
                    .unwrap_or("")
                    .chars()
                    .take(SUMMARY_MESSAGE)
                    .collect();
                match &identifier {
                    Some(program) => format!("{program}: {line}"),
                    None => line,
                }
            },
            event_summary,
        );
        record
    }
}

/// Every journal field under its own name (repeated ones joined by line),
/// the entry's place in the file, and the event read from its message.
fn fields(entry: &Entry, event: Option<&Event>) -> Fields {
    let mut values: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for field in &entry.fields {
        values
            .entry(field.name.as_str())
            .or_default()
            .push(value_text(&field.value));
    }
    let mut fields = Fields::new();
    for (name, texts) in values {
        fields.insert(name.into(), Value::from(texts.join("\n").as_str()));
    }
    fields.insert("Seqnum".into(), Value::UInt(entry.seqnum));
    fields.insert(
        "BootId".into(),
        Value::from(entry.boot_id.to_string().as_str()),
    );
    fields.insert("Monotonic".into(), Value::UInt(entry.monotonic));
    if !entry.linked {
        fields.insert("Recovered".into(), Value::Bool(true));
    }
    if let Some(event) = event {
        event_fields(&mut fields, event);
    }
    fields
}

fn value_text(value: &JournalValue) -> String {
    match value {
        JournalValue::Bytes(bytes) => match std::str::from_utf8(bytes) {
            Ok(text) if text.len() <= MAX_VALUE_TEXT => text.to_owned(),
            Ok(text) => {
                let cut = (0..=MAX_VALUE_TEXT)
                    .rev()
                    .find(|&at| text.is_char_boundary(at))
                    .unwrap_or(0);
                format!("{}… [{} bytes in all]", &text[..cut], text.len())
            }
            Err(_) => format!("[{} bytes, not text]", bytes.len()),
        },
        JournalValue::Compressed { compression, size } => {
            format!("[{compression}-compressed, {size} bytes, not decoded]")
        }
    }
}
