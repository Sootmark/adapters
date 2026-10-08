//! OneDrive's logs, via the `onedrive` parser: the sync engine's binary
//! logs (`*.odl`, `*.odlgz`, `*.odlsent`, `*.aodl`), one record per entry
//! with its time, the function that logged it and its parameters' strings
//! (file and folder names, accounts); and the text logs of the SkyDrive
//! client (OneDrive's earlier name), one record per entry.
//!
//! The words OneDrive obfuscated in a binary log are restored with the
//! `ObfuscationStringMap.txt` beside it, which the caller hands over as a
//! companion file; without it they stay as stored. Recent versions encrypt
//! the words instead (the key in `general.keystore`): those stay as stored.

use model::adapter::{Adapter, Companion, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};
use onedrive::{Entry, Kind, ObfuscationMap, Odl};

use crate::home::profile_owner;

/// Records of OneDrive's and SkyDrive's logs.
pub const NAMESPACE: Namespace = Namespace::new("windows.onedrive");

/// The file that restores a binary log's obfuscated words.
const OBFUSCATION_MAP: &str = "ObfuscationStringMap.txt";
/// The binary logs' extensions.
const ODL_EXTENSIONS: [&str; 4] = ["odl", "odlgz", "odlsent", "aodl"];
/// Words in a text log's path that say it is the sync client's.
const TEXT_LOG_WORDS: [&str; 2] = ["onedrive", "skydrive"];
/// The longest text kept in a summary.
const SUMMARY_TEXT: usize = 200;

/// One record per log entry.
#[derive(Debug, Default, Clone, Copy)]
pub struct OneDriveAdapter;

impl Adapter for OneDriveAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "onedrive",
            version: onedrive::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[NAMESPACE]
    }

    /// A binary log by its signature (`EBFGONED`); a text log by its
    /// first line, when its path names OneDrive or SkyDrive (a text line
    /// alone looks like many other logs').
    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        let lower = name.to_ascii_lowercase();
        match onedrive::detect(head) {
            Some(Kind::Odl) => Confidence::Certain,
            Some(Kind::Text(_)) if TEXT_LOG_WORDS.iter().any(|w| lower.contains(w)) => {
                Confidence::Certain
            }
            _ => Confidence::No,
        }
    }

    fn companions(&self, name: &str) -> Vec<String> {
        let extension = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase());
        if extension.is_some_and(|e| ODL_EXTENSIONS.contains(&e.as_str())) {
            vec![OBFUSCATION_MAP.to_owned()]
        } else {
            Vec::new()
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        self.parse_with_companions(input, &[], sink)
    }

    fn parse_with_companions(
        &self,
        input: &Input<'_>,
        companions: &[Companion<'_>],
        sink: &mut dyn Sink,
    ) -> Result<(), ParseError> {
        let failed = |e: onedrive::Error| ParseError::at(0, e.0);
        let owner = profile_owner(input.name);
        let (problems, records): (Vec<String>, Vec<Record>) = match onedrive::detect(input.data) {
            Some(Kind::Odl) => {
                let odl = onedrive::read_odl(input.data).map_err(failed)?;
                let map = companions
                    .iter()
                    .find(|c| c.name.eq_ignore_ascii_case(OBFUSCATION_MAP))
                    .map(|c| ObfuscationMap::read(c.data));
                let records = odl
                    .records
                    .iter()
                    .map(|entry| {
                        self.odl_record(input, &odl, entry, map.as_ref(), owner.as_deref())
                    })
                    .collect();
                (odl.problems, records)
            }
            Some(Kind::Text(_)) => {
                let log = onedrive::read_text_log(input.data).map_err(failed)?;
                let records = log
                    .entries
                    .iter()
                    .map(|entry| self.text_record(input, entry, owner.as_deref()))
                    .collect();
                (log.problems, records)
            }
            None => return Err(ParseError::at(0, "not a OneDrive log this parser reads")),
        };
        for reason in problems {
            sink.skipped(Skipped {
                locator: Locator::ByteOffset(0),
                reason,
            });
        }
        for record in records {
            sink.record(record);
        }
        Ok(())
    }
}

impl OneDriveAdapter {
    /// A binary log's record, its parameters restored when the map is
    /// there.
    fn odl_record(
        self,
        input: &Input<'_>,
        odl: &Odl,
        entry: &onedrive::Record,
        map: Option<&ObfuscationMap>,
        owner: Option<&str>,
    ) -> Record {
        let mut record = Record::new(
            input.evidence,
            NAMESPACE,
            Locator::ByteOffset(entry.offset),
            self.parser(),
        );
        if let Some(time) = entry.time {
            record
                .times
                .push(RecordTime::new(TimeKind::Logged, "Time", time));
        }
        let parameters: Vec<String> = entry
            .parameters
            .iter()
            .map(|p| map.map_or_else(|| p.clone(), |map| map.deobfuscate(p)))
            .collect();
        let mut fields = Fields::new();
        text(&mut fields, "Function", Some(&entry.function));
        text(&mut fields, "CodeFile", Some(&entry.code_file));
        fields.insert("CodeLine".into(), Value::UInt(u64::from(entry.code_line)));
        if !parameters.is_empty() {
            text(&mut fields, "Parameters", Some(&parameters.join(" | ")));
            if parameters != entry.parameters {
                text(
                    &mut fields,
                    "ParametersAsStored",
                    Some(&entry.parameters.join(" | ")),
                );
            }
        }
        for (name, value) in [
            ("ProcessId", entry.process_id),
            ("ThreadId", entry.thread_id),
        ] {
            if let Some(value) = value {
                fields.insert(name.into(), Value::UInt(u64::from(value)));
            }
        }
        text(&mut fields, "Guid", entry.guid.as_deref());
        text(&mut fields, "OneDriveVersion", Some(&odl.onedrive_version));
        text(&mut fields, "OsVersion", Some(&odl.os_version));
        fields.insert("Deobfuscated".into(), Value::Bool(map.is_some()));
        record.fields = fields;
        record.facets = Facets {
            user_name: owner.map(str::to_owned),
            process_id: entry.process_id.map(u64::from),
            file_path: parameters.iter().find(|p| looks_like_path(p)).cloned(),
            ..Facets::default()
        };
        let shown = parameters.join(", ");
        record.summary = format!(
            "OneDrive {}{}{}",
            entry.function,
            if shown.is_empty() { "" } else { ": " },
            shown.chars().take(SUMMARY_TEXT).collect::<String>()
        );
        record
    }

    /// A SkyDrive text log's entry, or a session's start.
    fn text_record(self, input: &Input<'_>, entry: &Entry, owner: Option<&str>) -> Record {
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
        text(&mut fields, "Level", entry.level.as_deref());
        text(&mut fields, "Module", entry.module.as_deref());
        text(&mut fields, "Source", entry.source.as_deref());
        text(&mut fields, "Message", Some(&entry.message));
        if let Some(sequence) = entry.sequence {
            fields.insert("Sequence".into(), Value::UInt(sequence));
        }
        let mut process_id = None;
        if let Some(thread) = entry.thread_id {
            fields.insert("ThreadId".into(), Value::UInt(u64::from(thread)));
        }
        if let Some(session) = &entry.session {
            text(&mut fields, "ClientVersion", Some(&session.client_version));
            text(
                &mut fields,
                "ContinuedFrom",
                session.continued_from.as_deref(),
            );
            if let Some(local) = session.local_time {
                fields.insert("LocalTime".into(), Value::Time(local));
            }
            if let Some(pid) = session.process_id {
                fields.insert("ProcessId".into(), Value::UInt(u64::from(pid)));
                process_id = Some(u64::from(pid));
            }
        }
        record.fields = fields;
        record.facets = Facets {
            user_name: owner.map(str::to_owned),
            process_id,
            ..Facets::default()
        };
        let first_line = entry.message.lines().next().unwrap_or_default();
        record.summary = format!(
            "SkyDrive {}{}: {}",
            entry.level.as_deref().unwrap_or("entry"),
            entry
                .source
                .as_deref()
                .map_or_else(String::new, |s| format!(" {s}")),
            first_line.chars().take(SUMMARY_TEXT).collect::<String>()
        );
        record
    }
}

/// Whether a parameter is a Windows path (`C:\…`, `\\server\…`).
fn looks_like_path(text: &str) -> bool {
    let bytes = text.as_bytes();
    text.starts_with(r"\\")
        || (bytes.len() > 2 && bytes[0].is_ascii_alphabetic() && &bytes[1..3] == br":\")
}

fn text(fields: &mut Fields, name: &str, value: Option<&str>) {
    if let Some(value) = value.filter(|v| !v.is_empty()) {
        fields.insert(name.into(), Value::from(value));
    }
}
