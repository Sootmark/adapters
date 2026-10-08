//! Windows diagnostic data (`EventTranscript.db`), via the
//! `eventtranscript` parser: one record per telemetry event, its name,
//! program, producer, tags and every `data` value under its dotted path;
//! a visited URL, an app or a path the event names in facets.

use eventtranscript::Event;
use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};

/// Records of diagnostic data events.
pub const NAMESPACE: Namespace = Namespace::new("windows.diagnostic_data");

/// `data` paths that name a page visited.
const URLS: [&str; 3] = ["navigationUrl", "PageUrl", "url"];
/// `data` paths that name a program or file.
const PATHS: [&str; 4] = ["AppId", "LowerCaseLongPath", "Path", "FileName"];

/// One record per event.
#[derive(Debug, Default, Clone, Copy)]
pub struct EventTranscriptAdapter;

impl Adapter for EventTranscriptAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "eventtranscript",
            version: eventtranscript::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[NAMESPACE]
    }

    /// By name, and the SQLite signature.
    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        let named = name
            .rsplit(['/', '\\'])
            .next()
            .is_some_and(|n| n.eq_ignore_ascii_case("EventTranscript.db"));
        if named && head.starts_with(b"SQLite format 3\0") {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        self.parse_with_log(input, &[], sink)
    }

    fn parse_with_log(
        &self,
        input: &Input<'_>,
        log: &[u8],
        sink: &mut dyn Sink,
    ) -> Result<(), ParseError> {
        let transcript =
            eventtranscript::read(input.data, log).map_err(|e| ParseError::at(0, e.0))?;
        for reason in transcript.problems {
            sink.skipped(Skipped {
                locator: Locator::ByteOffset(0),
                reason,
            });
        }
        for event in &transcript.events {
            sink.record(self.record(input, event));
        }
        Ok(())
    }
}

impl EventTranscriptAdapter {
    fn record(self, input: &Input<'_>, event: &Event) -> Record {
        let mut record = Record::new(
            input.evidence,
            NAMESPACE,
            Locator::TableRow {
                table: "events_persisted".to_owned(),
                row: u64::try_from(event.rowid).unwrap_or_default(),
            },
            self.parser(),
        );
        if let Some(time) = event.time {
            record
                .times
                .push(RecordTime::new(TimeKind::Logged, "Time", time));
        }
        let mut fields = Fields::new();
        for (path, value) in &event.data {
            fields.insert(path.clone(), Value::from(value.as_str()));
        }
        fields.insert("EventName".into(), Value::from(event.name.as_str()));
        for (name, value) in [
            ("Binary", &event.binary),
            ("FriendlyBinary", &event.friendly_binary),
            ("Producer", &event.producer),
            ("Sid", &event.sid),
            ("IKey", &event.ikey),
        ] {
            if let Some(value) = value {
                fields.insert(name.into(), Value::from(value.as_str()));
            }
        }
        if !event.tags.is_empty() {
            fields.insert("Tags".into(), Value::from(event.tags.join(", ").as_str()));
        }
        record.fields = fields;
        let url = URLS.iter().find_map(|p| event.data(p));
        record.facets = Facets {
            user_sid: event.sid.clone(),
            file_path: PATHS.iter().find_map(|p| event.data(p)).map(str::to_owned),
            ..Facets::default()
        };
        let short = event.name.rsplit('.').next().unwrap_or(&event.name);
        record.summary = match url {
            Some(url) => format!("Diagnostic data {short}: {url}"),
            None => format!("Diagnostic data {short}"),
        };
        record
    }
}
