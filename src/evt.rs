//! Windows NT to XP and Server 2003 event logs (`.evt`), via the `evt`
//! parser: one record per event, those recovered from the log's free space
//! marked so, shaped as the `.evtx` adapter's records are so that the same
//! hunts match: the event code (the identifier's low 16 bits, as Event
//! Viewer shows it) as `event_code`, the source as `provider`, the log
//! (`System` for `SysEvent.Evt`, …) as `channel`, the computer and SID.
//! The strings inserted into the source's message are `String1`,
//! `String2`, … as the message's `%1`, `%2` number them (hunts can't
//! query the `Data[n]` names the `.evtx` adapter gives unnamed data).

use evt::{EventType, Record as Event};
use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};

/// Records of `.evt` files.
pub const NAMESPACE: Namespace = Namespace::new("windows.evt");

/// The logs Windows keeps, by file name, and their channels.
const CHANNELS: [(&str, &str); 3] = [
    ("sysevent.evt", "System"),
    ("appevent.evt", "Application"),
    ("secevent.evt", "Security"),
];

/// The most inserted strings shown in a summary.
const SUMMARY_STRINGS: usize = 4;

/// One record per event.
#[derive(Debug, Default, Clone, Copy)]
pub struct EvtAdapter;

impl Adapter for EvtAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "evt",
            version: evt::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[NAMESPACE]
    }

    /// By the header (`LfLe` at offset 4).
    fn probe(&self, _name: &str, head: &[u8]) -> Confidence {
        if evt::detect(head) {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let log = evt::read(input.data).map_err(|e| ParseError::at(0, e.0))?;
        for reason in log.problems {
            sink.skipped(Skipped {
                locator: Locator::ByteOffset(0),
                reason,
            });
        }
        let channel = channel(input.name);
        for event in &log.records {
            sink.record(self.record(input, event, channel.as_deref()));
        }
        Ok(())
    }
}

impl EvtAdapter {
    fn record(self, input: &Input<'_>, event: &Event, channel: Option<&str>) -> Record {
        let mut record = Record::new(
            input.evidence,
            NAMESPACE,
            Locator::ByteOffset(event.offset),
            self.parser(),
        );
        record.flags.recovered = event.recovered;
        record.times.push(RecordTime::new(
            TimeKind::Logged,
            "TimeGenerated",
            event.generated,
        ));
        record.times.push(RecordTime::new(
            TimeKind::Other,
            "TimeWritten",
            event.written,
        ));
        let mut fields = Fields::new();
        fields.insert("EventRecordID".into(), Value::UInt(u64::from(event.number)));
        fields.insert("EventID".into(), Value::UInt(u64::from(event.event_id)));
        fields.insert("EventCode".into(), Value::UInt(u64::from(event.code())));
        fields.insert("EventType".into(), Value::from(type_name(event.event_type)));
        fields.insert("Category".into(), Value::UInt(u64::from(event.category)));
        fields.insert("Source".into(), Value::from(event.source.as_str()));
        fields.insert("Computer".into(), Value::from(event.computer.as_str()));
        if let Some(sid) = &event.sid {
            fields.insert("Sid".into(), Value::from(sid.as_str()));
        }
        for (number, string) in (1..).zip(&event.strings) {
            fields.insert(format!("String{number}"), Value::from(string.as_str()));
        }
        if !event.data.is_empty() {
            fields.insert("Binary".into(), Value::Bytes(event.data.clone()));
        }
        record.fields = fields;
        record.facets = Facets {
            host_name: Some(event.computer.clone()).filter(|c| !c.is_empty()),
            user_sid: event.sid.clone(),
            event_code: Some(u32::from(event.code())),
            channel: channel.map(str::to_owned),
            provider: Some(event.source.clone()).filter(|s| !s.is_empty()),
            ..Facets::default()
        };
        let strings = event
            .strings
            .iter()
            .map(|s| s.split_whitespace().collect::<Vec<_>>().join(" "))
            .filter(|s| !s.is_empty())
            .take(SUMMARY_STRINGS);
        let mut summary = format!("{} {}", event.code(), event.source);
        for string in strings {
            summary.push_str(" · ");
            summary.push_str(&string);
        }
        record.summary = summary;
        record
    }
}

/// The log's channel from its file name: Windows' own logs by name, any
/// other by its name without `.evt`.
fn channel(name: &str) -> Option<String> {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let lower = base.to_ascii_lowercase();
    CHANNELS
        .iter()
        .find(|(file, _)| *file == lower)
        .map(|(_, channel)| (*channel).to_owned())
        .or_else(|| {
            lower
                .strip_suffix(".evt")
                .map(|stem| base[..stem.len()].to_owned())
        })
        .filter(|channel| !channel.is_empty())
}

fn type_name(kind: EventType) -> String {
    match kind {
        EventType::Success => "Success".to_owned(),
        EventType::Error => "Error".to_owned(),
        EventType::Warning => "Warning".to_owned(),
        EventType::Information => "Information".to_owned(),
        EventType::AuditSuccess => "Audit Success".to_owned(),
        EventType::AuditFailure => "Audit Failure".to_owned(),
        EventType::Other(value) => format!("0x{value:x}"),
    }
}

#[cfg(test)]
mod tests {
    use super::channel;

    #[test]
    fn channels_from_file_names() {
        assert_eq!(
            channel(r"C\WINDOWS\system32\config\SecEvent.Evt").as_deref(),
            Some("Security")
        );
        assert_eq!(
            channel("Internet Explorer.evt").as_deref(),
            Some("Internet Explorer")
        );
        assert_eq!(channel("log.bin"), None);
    }
}
