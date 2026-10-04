//! macOS artifacts kept in SQLite, via the `macos` parser, each read with
//! its write-ahead log when the caller hands it over: quarantine events
//! (where each downloaded file came from), TCC (which apps were granted
//! privacy permissions, and when) and KnowledgeC (app usage and device
//! events over time).

use macos::{Artifact, KnowledgeEvent, QuarantineEvent, Scope, TccEntry};
use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};

use crate::home::profile_owner;

/// Quarantine events.
pub const QUARANTINE: Namespace = Namespace::new("macos.quarantine");
/// TCC permission entries.
pub const TCC: Namespace = Namespace::new("macos.tcc");
/// KnowledgeC events.
pub const KNOWLEDGEC: Namespace = Namespace::new("macos.knowledgec");

/// One record per quarantine event, TCC entry or KnowledgeC event.
#[derive(Debug, Default, Clone, Copy)]
pub struct MacosAdapter;

impl Adapter for MacosAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "macos",
            version: macos::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[QUARANTINE, TCC, KNOWLEDGEC]
    }

    /// By name, and the SQLite signature.
    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        if macos::detect(name).is_some() && head.starts_with(b"SQLite format 3\0") {
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
        let failed = |e: macos::Error| ParseError::at(0, e.0);
        let owner = profile_owner(input.name);
        let mut emit = |problems: Vec<String>, records: Vec<Record>| {
            for reason in problems {
                sink.skipped(Skipped {
                    locator: Locator::ByteOffset(0),
                    reason,
                });
            }
            for record in records {
                sink.record(record);
            }
        };
        match macos::detect(input.name) {
            Some(Artifact::QuarantineEvents) => {
                let parsed = macos::read_quarantine(input.data, log).map_err(failed)?;
                let records = parsed
                    .events
                    .iter()
                    .map(|event| self.quarantine(input, event, owner.as_deref()))
                    .collect();
                emit(parsed.problems, records);
            }
            Some(Artifact::Tcc(scope)) => {
                let parsed = macos::read_tcc(input.data, log).map_err(failed)?;
                let owner = (scope == Scope::User).then_some(owner).flatten();
                let records = parsed
                    .entries
                    .iter()
                    .map(|entry| self.tcc(input, entry, scope, owner.as_deref()))
                    .collect();
                emit(parsed.problems, records);
            }
            Some(Artifact::KnowledgeC(scope)) => {
                let parsed = macos::read_knowledgec(input.data, log).map_err(failed)?;
                let owner = (scope == Scope::User).then_some(owner).flatten();
                let records = parsed
                    .events
                    .iter()
                    .map(|event| self.knowledge(input, event, owner.as_deref()))
                    .collect();
                emit(parsed.problems, records);
            }
            None => return Err(ParseError::at(0, "not a macOS database this parser reads")),
        }
        Ok(())
    }
}

impl MacosAdapter {
    fn record(self, input: &Input<'_>, namespace: Namespace, table: &str, row: i64) -> Record {
        Record::new(
            input.evidence,
            namespace,
            Locator::TableRow {
                table: table.to_owned(),
                row: u64::try_from(row).unwrap_or_default(),
            },
            self.parser(),
        )
    }

    fn quarantine(self, input: &Input<'_>, event: &QuarantineEvent, owner: Option<&str>) -> Record {
        let mut record = self.record(input, QUARANTINE, "LSQuarantineEvent", event.rowid);
        if let Some(time) = event.time {
            record.times.push(RecordTime::new(
                TimeKind::Created,
                "LSQuarantineTimeStamp",
                time,
            ));
        }
        record.facets = Facets {
            user_name: owner.map(str::to_owned),
            ..Facets::default()
        };
        let mut fields = Fields::new();
        text(&mut fields, "Agent", event.agent_name.as_deref());
        text(
            &mut fields,
            "AgentBundleId",
            event.agent_bundle_id.as_deref(),
        );
        text(&mut fields, "DataUrl", event.data_url.as_deref());
        text(&mut fields, "OriginUrl", event.origin_url.as_deref());
        text(&mut fields, "OriginTitle", event.origin_title.as_deref());
        text(&mut fields, "SenderName", event.sender_name.as_deref());
        text(
            &mut fields,
            "SenderAddress",
            event.sender_address.as_deref(),
        );
        text(&mut fields, "EventId", Some(&event.id));
        if let Some(kind) = event.type_number {
            fields.insert("TypeNumber".into(), Value::Int(kind));
        }
        record.fields = fields;
        let agent = event.agent_name.as_deref().unwrap_or("an app");
        let url = event
            .data_url
            .as_deref()
            .or(event.origin_url.as_deref())
            .unwrap_or("?");
        record.summary = format!("Downloaded by {agent}: {url}");
        record
    }

    fn tcc(self, input: &Input<'_>, entry: &TccEntry, scope: Scope, owner: Option<&str>) -> Record {
        let mut record = self.record(input, TCC, "access", entry.rowid);
        for (time, name) in [
            (entry.last_modified, "last_modified"),
            (entry.last_reminded, "last_reminded"),
        ] {
            if let Some(time) = time {
                record
                    .times
                    .push(RecordTime::new(TimeKind::Modified, name, time));
            }
        }
        record.facets = Facets {
            user_name: owner.map(str::to_owned),
            process_path: Some(entry.client.clone()).filter(|c| c.starts_with('/')),
            ..Facets::default()
        };
        let authorization = entry.authorization.map(|a| format!("{a:?}").to_lowercase());
        let mut fields = Fields::new();
        text(&mut fields, "Service", Some(&entry.service));
        text(&mut fields, "Client", Some(&entry.client));
        text(&mut fields, "Authorization", authorization.as_deref());
        text(
            &mut fields,
            "Reason",
            entry.reason.map(|r| format!("{r:?}")).as_deref(),
        );
        text(
            &mut fields,
            "Scope",
            Some(&format!("{scope:?}").to_lowercase()),
        );
        text(
            &mut fields,
            "IndirectObject",
            entry.indirect_object.as_deref(),
        );
        record.fields = fields;
        let service = entry
            .service
            .strip_prefix("kTCCService")
            .unwrap_or(&entry.service);
        record.summary = format!(
            "{} {} for {service}",
            entry.client,
            authorization.as_deref().unwrap_or("recorded")
        );
        record
    }

    fn knowledge(self, input: &Input<'_>, event: &KnowledgeEvent, owner: Option<&str>) -> Record {
        let mut record = self.record(input, KNOWLEDGEC, "ZOBJECT", event.rowid);
        for (time, kind, name) in [
            (event.start, TimeKind::FirstSeen, "ZSTARTDATE"),
            (event.end, TimeKind::LastSeen, "ZENDDATE"),
        ] {
            if let Some(time) = time {
                record.times.push(RecordTime::new(kind, name, time));
            }
        }
        record.facets = Facets {
            user_name: owner.map(str::to_owned),
            ..Facets::default()
        };
        let mut fields = Fields::new();
        text(&mut fields, "Stream", Some(&event.stream));
        text(&mut fields, "App", event.app());
        text(&mut fields, "Value", event.value_string.as_deref());
        text(&mut fields, "Title", event.title.as_deref());
        text(&mut fields, "ActivityType", event.activity_type.as_deref());
        text(&mut fields, "DeviceId", event.device_id.as_deref());
        if let Some(duration) = event.duration() {
            fields.insert("DurationSeconds".into(), Value::UInt(duration.as_secs()));
        }
        record.fields = fields;
        record.summary = match event.app().or(event.value_string.as_deref()) {
            Some(what) => format!("{} {what}", event.stream),
            None => event.stream.clone(),
        };
        record
    }
}

fn text(fields: &mut Fields, name: &str, value: Option<&str>) {
    if let Some(value) = value.filter(|v| !v.is_empty()) {
        fields.insert(name.into(), Value::from(value));
    }
}
