//! Antivirus logs, via the `avlogs` parser: McAfee access protection,
//! Symantec scan logs, Sophos `SAV.txt`, Trend Micro virus detections and
//! web reputation; one record per entry, the threat, file, account and
//! action as fields and facets.

use avlogs::{Entry, Kind};
use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};

/// Records of antivirus logs.
pub const NAMESPACE: Namespace = Namespace::new("windows.antivirus");

/// One record per antivirus log entry.
#[derive(Debug, Default, Clone, Copy)]
pub struct AvlogsAdapter;

impl Adapter for AvlogsAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "avlogs",
            version: avlogs::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[NAMESPACE]
    }

    /// By name and first line.
    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        if avlogs::detect(name, head).is_some() {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let kind = avlogs::detect(input.name, input.data)
            .ok_or_else(|| ParseError::at(0, "not an antivirus log this parser reads"))?;
        let log = avlogs::read(kind, input.data);
        for entry in &log.entries {
            sink.record(self.record(input, kind, entry));
        }
        for reason in log.problems {
            sink.skipped(Skipped {
                locator: Locator::ByteOffset(0),
                reason,
            });
        }
        Ok(())
    }
}

impl AvlogsAdapter {
    fn record(self, input: &Input<'_>, kind: Kind, entry: &Entry) -> Record {
        let mut record = Record::new(
            input.evidence,
            NAMESPACE,
            Locator::Line(entry.line as u64),
            self.parser(),
        );
        if let Some(time) = entry.time {
            record
                .times
                .push(RecordTime::new(TimeKind::Logged, "Time", time));
        }
        let mut fields = Fields::new();
        fields.insert("Product".into(), Value::from(kind.product()));
        for (name, value) in [
            ("Threat", &entry.threat),
            ("Path", &entry.path),
            ("User", &entry.user),
            ("Action", &entry.action),
            ("Message", &entry.message),
        ] {
            if let Some(value) = value {
                fields.insert(name.into(), Value::from(value.as_str()));
            }
        }
        for (name, value) in &entry.fields {
            fields.insert(name.clone(), Value::from(value.as_str()));
        }
        record.fields = fields;
        let is_process = matches!(kind, Kind::McAfeeAccessProtection | Kind::TrendMicroWeb);
        record.facets = Facets {
            user_name: entry.user.clone(),
            process_path: entry.path.clone().filter(|_| is_process),
            file_path: entry.path.clone().filter(|_| !is_process),
            ..Facets::default()
        };
        let what = entry
            .threat
            .as_deref()
            .or(entry.message.as_deref())
            .unwrap_or("entry");
        record.summary = match &entry.path {
            Some(path) => format!("{}: {what} ({path})", kind.product()),
            None => format!("{}: {what}", kind.product()),
        };
        record
    }
}
