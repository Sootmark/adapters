//! Microsoft Defender XDR (Defender for Endpoint) device timelines,
//! imported from the CSV the portal's device timeline exports (`Event
//! Time`, `Computer Name`, `Action Type`, …) or an advanced hunting query
//! exports (`Timestamp`, `DeviceName`, `ActionType`, …): one record per
//! event, every column kept under its own name, the process, file, account,
//! addresses and registry key in facets.
//!
//! Columns are matched without spaces, underscores or case, so both
//! spellings read alike. Times are UTC, as both exports write them.

use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};

use crate::csv;
use crate::timestamp;

/// Defender XDR device timeline events.
pub const NAMESPACE: Namespace = Namespace::new("xdr.timeline");

/// Imports Defender XDR device timelines.
#[derive(Debug, Default, Clone, Copy)]
pub struct XdrAdapter;

impl Adapter for XdrAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "xdr-import",
            version: env!("CARGO_PKG_VERSION"),
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[NAMESPACE]
    }

    /// By the header: an action type, a device and a time.
    fn probe(&self, _name: &str, head: &[u8]) -> Confidence {
        let text = String::from_utf8_lossy(head);
        let header = text
            .trim_start_matches('\u{feff}')
            .lines()
            .next()
            .unwrap_or("");
        let columns: Vec<String> = header
            .split(',')
            .map(|c| key(c.trim_matches('"')))
            .collect();
        let has = |name: &str| columns.iter().any(|c| c == name);
        if has("actiontype")
            && (has("computername") || has("devicename"))
            && (has("eventtime") || has("timestamp"))
        {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let text = String::from_utf8_lossy(input.data);
        let mut rows = csv::records(&text);
        let header = match rows.next() {
            Some(Ok(header)) => header.fields,
            _ => return Err(ParseError::at(0, "no CSV header")),
        };
        let keys: Vec<String> = header.iter().map(|h| key(h)).collect();
        for row in rows {
            match row {
                Ok(row) => sink.record(self.record(input, &header, &keys, &row)),
                Err(error) => sink.skipped(Skipped {
                    locator: Locator::Line(error.line),
                    reason: error.message.to_owned(),
                }),
            }
        }
        Ok(())
    }
}

impl XdrAdapter {
    fn record(
        self,
        input: &Input<'_>,
        header: &[String],
        keys: &[String],
        row: &csv::CsvRecord,
    ) -> Record {
        let get = |name: &str| {
            keys.iter()
                .position(|k| k == name)
                .and_then(|at| row.fields.get(at))
                .map(|v| v.trim())
                .filter(|v| !v.is_empty())
        };
        let mut record = Record::new(
            input.evidence,
            NAMESPACE,
            Locator::Line(row.line),
            self.parser(),
        );
        if let Some(time) = get("eventtime")
            .or_else(|| get("timestamp"))
            .and_then(|t| timestamp::zoned(t).or_else(|| timestamp::utc(t)))
        {
            record
                .times
                .push(RecordTime::new(TimeKind::Logged, "EventTime", time));
        }
        let mut fields = Fields::new();
        for (name, value) in header.iter().zip(&row.fields) {
            if !value.is_empty() {
                fields.insert(name.clone(), Value::from(value.as_str()));
            }
        }
        record.fields = fields;
        let action = get("actiontype").unwrap_or("?");
        let file = path(get("folderpath"), get("filename"));
        let initiating = path(
            get("initiatingprocessfolderpath"),
            get("initiatingprocessfilename"),
        );
        let account = |domain: Option<&str>, name: Option<&str>| match (domain, name) {
            (Some(domain), Some(name)) => Some(format!("{domain}\\{name}")),
            (None, name) => name.map(str::to_owned),
            (Some(_), None) => None,
        };
        let created = action.eq_ignore_ascii_case("ProcessCreated");
        record.facets = Facets {
            host_name: get("computername")
                .or_else(|| get("devicename"))
                .map(str::to_owned),
            user_name: account(get("accountdomain"), get("accountname")).or_else(|| {
                account(
                    get("initiatingprocessaccountdomain"),
                    get("initiatingprocessaccountname"),
                )
            }),
            user_sid: get("accountsid").map(str::to_owned),
            process_path: if created {
                file.clone()
            } else {
                initiating.clone()
            },
            process_command_line: get("processcommandline")
                .filter(|_| created)
                .or_else(|| get("initiatingprocesscommandline"))
                .map(str::to_owned),
            parent_process_path: if created {
                initiating
            } else {
                get("initiatingprocessparentfilename").map(str::to_owned)
            },
            file_path: if created { None } else { file.clone() },
            source_ip: get("localip").map(str::to_owned),
            destination_ip: get("remoteip").map(str::to_owned),
            ..Facets::default()
        };
        let what = get("processcommandline")
            .map(str::to_owned)
            .or_else(|| file.clone())
            .or_else(|| get("remoteurl").map(str::to_owned))
            .or_else(|| get("remoteip").map(str::to_owned))
            .or_else(|| get("registrykey").map(str::to_owned))
            .unwrap_or_default();
        record.summary = format!(
            "XDR {action} on {}: {what}",
            record.facets.host_name.as_deref().unwrap_or("?")
        );
        record
    }
}

/// A column's name without spaces, underscores or case.
fn key(column: &str) -> String {
    column
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '_')
        .flat_map(char::to_lowercase)
        .collect()
}

/// A folder and a file name as one path; the folder alone when it already
/// ends with the file's name, as Defender's often does.
fn path(folder: Option<&str>, file: Option<&str>) -> Option<String> {
    match (folder, file) {
        (Some(folder), Some(file)) => {
            let ends = folder
                .to_ascii_lowercase()
                .ends_with(&file.to_ascii_lowercase());
            Some(if ends {
                folder.to_owned()
            } else {
                format!("{}\\{file}", folder.trim_end_matches('\\'))
            })
        }
        (folder, file) => folder.or(file).map(str::to_owned),
    }
}
