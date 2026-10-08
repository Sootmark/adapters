//! Application text logs, via the `applogs` parser: vsftpd, PostgreSQL,
//! Debian's popularity-contest, Snort's and Suricata's fast alerts, Google
//! logging (glog), Santa, macOS securityd and the application firewall; one
//! record per entry with its time, host, program, process, level, account
//! and message under the same names across logs, and every other value
//! under the log's own name (`decision`, `sha256`, `client`, `rule`, …).
//!
//! Times are as each log writes them: UTC where it says so, local of an
//! unknown zone otherwise. Logs that write no year have it inferred from
//! the order of their lines and the file's modification time
//! (`YearInferred`); a line that can't be dated keeps its time as written
//! (`TimeText`).

use applogs::{Context, Entry, Kind};
use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};

use crate::key::field_name;

/// vsftpd's log.
pub const VSFTPD: Namespace = Namespace::new("linux.vsftpd");
/// PostgreSQL's server log.
pub const POSTGRESQL: Namespace = Namespace::new("linux.postgresql");
/// Debian's popularity-contest log.
pub const POPCONTEST: Namespace = Namespace::new("linux.popcontest");
/// Snort's and Suricata's fast alerts.
pub const SNORT: Namespace = Namespace::new("network.snort");
/// Google logging (glog) files.
pub const GLOG: Namespace = Namespace::new("unix.glog");
/// Santa's log.
pub const SANTA: Namespace = Namespace::new("macos.santa");
/// macOS securityd's log.
pub const SECURITYD: Namespace = Namespace::new("macos.securityd");
/// The macOS application firewall's log.
pub const APPFIREWALL: Namespace = Namespace::new("macos.appfirewall");

/// The longest message kept in a summary.
const SUMMARY_TEXT: usize = 200;

/// One record per log entry.
#[derive(Debug, Default, Clone, Copy)]
pub struct ApplogsAdapter;

impl Adapter for ApplogsAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "applogs",
            version: applogs::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[
            VSFTPD,
            POSTGRESQL,
            POPCONTEST,
            SNORT,
            GLOG,
            SANTA,
            SECURITYD,
            APPFIREWALL,
        ]
    }

    /// By the first line (glog: its header), each log's shape.
    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        if applogs::detect(name, head).is_some() {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let kind = applogs::detect(input.name, input.data)
            .ok_or_else(|| ParseError::at(0, "not an application log this parser reads"))?;
        let log = applogs::read(
            kind,
            input.data,
            Context {
                modified: input.modified,
            },
        );
        for reason in log.problems {
            sink.skipped(Skipped {
                locator: Locator::ByteOffset(0),
                reason,
            });
        }
        for entry in &log.entries {
            sink.record(self.record(input, kind, entry));
        }
        Ok(())
    }
}

impl ApplogsAdapter {
    fn record(self, input: &Input<'_>, kind: Kind, entry: &Entry) -> Record {
        let (namespace, label) = describe(kind);
        let mut record = Record::new(
            input.evidence,
            namespace,
            Locator::Line(entry.line as u64),
            self.parser(),
        );
        let package = entry.get("package").is_some();
        if let Some(time) = entry.time {
            let (kind, name) = if package {
                (TimeKind::Accessed, "atime")
            } else {
                (TimeKind::Logged, "Time")
            };
            record.times.push(RecordTime::new(kind, name, time));
        }
        for (name, time) in &entry.times {
            let kind = match *name {
                "ctime" => TimeKind::MetadataChanged,
                _ => TimeKind::Other,
            };
            record.times.push(RecordTime::new(kind, *name, *time));
        }
        let mut fields = Fields::new();
        for (name, value) in &entry.fields {
            fields.insert(field_name(name), Value::from(value.as_str()));
        }
        text(&mut fields, "Host", entry.host.as_deref());
        text(&mut fields, "Program", entry.program.as_deref());
        text(&mut fields, "Level", entry.level.as_deref());
        text(&mut fields, "User", entry.user.as_deref());
        text(&mut fields, "Message", entry.message.as_deref());
        if let Some(pid) = entry.pid {
            fields.insert("ProcessId".into(), Value::UInt(u64::from(pid)));
        }
        if entry.year_inferred {
            fields.insert("YearInferred".into(), Value::Bool(true));
        }
        if entry.time.is_none() || entry.year_inferred {
            text(&mut fields, "TimeText", Some(&entry.time_text));
        }
        record.fields = fields;
        record.facets = facets(kind, entry);
        record.summary = summary(kind, label, entry);
        record
    }
}

fn describe(kind: Kind) -> (Namespace, &'static str) {
    match kind {
        Kind::Vsftpd => (VSFTPD, "vsftpd"),
        Kind::PostgreSql => (POSTGRESQL, "PostgreSQL"),
        Kind::PopularityContest => (POPCONTEST, "popularity-contest"),
        Kind::SnortFast => (SNORT, "IDS alert"),
        Kind::Glog => (GLOG, "glog"),
        Kind::Santa => (SANTA, "Santa"),
        Kind::Securityd => (SECURITYD, "securityd"),
        Kind::AppFirewall => (APPFIREWALL, "Application firewall"),
    }
}

/// The values hunts look for: the account, process, addresses and files.
fn facets(kind: Kind, entry: &Entry) -> Facets {
    let owned = |name: &str| entry.get(name).map(str::to_owned);
    let mut facets = Facets {
        host_name: entry.host.clone(),
        user_name: entry.user.clone(),
        process_id: entry.pid.map(u64::from),
        ..Facets::default()
    };
    match kind {
        Kind::Vsftpd => {
            facets.source_ip = owned("client");
            facets.file_path = owned("path");
        }
        Kind::PopularityContest => facets.file_path = owned("path"),
        Kind::SnortFast => {
            facets.source_ip = owned("source");
            facets.destination_ip = owned("destination");
        }
        Kind::Santa => {
            if entry.get("action") == Some("EXEC") {
                facets.process_path = owned("path");
                facets.process_command_line = owned("args");
            } else {
                facets.process_path = owned("processpath");
                facets.file_path = owned("path");
            }
        }
        Kind::Glog | Kind::PostgreSql | Kind::Securityd | Kind::AppFirewall => {}
    }
    facets
}

/// A line for the timeline: the log, then what the entry says.
fn summary(kind: Kind, label: &str, entry: &Entry) -> String {
    let message: String = entry
        .message
        .as_deref()
        .and_then(|m| m.lines().next())
        .unwrap_or_default()
        .chars()
        .take(SUMMARY_TEXT)
        .collect();
    let words: Vec<&str> = match kind {
        Kind::Vsftpd => vec![
            entry.user.as_deref(),
            entry.get("result"),
            entry.get("action"),
            entry.get("path").or(entry.get("command")),
            entry.get("client").map(|_| "from"),
            entry.get("client"),
        ],
        Kind::SnortFast => vec![
            entry.get("rule"),
            Some(message.as_str()),
            entry.get("source"),
            entry.get("destination").map(|_| "->"),
            entry.get("destination"),
        ],
        Kind::Santa => vec![
            entry.get("action"),
            entry.get("decision"),
            entry.get("path").or(entry.get("mount")),
            entry
                .get("args")
                .filter(|_| entry.get("action") == Some("EXEC")),
        ],
        Kind::PopularityContest => match entry.get("package") {
            Some(package) => vec![Some(package), Some(message.as_str()), entry.get("tag")],
            None => vec![
                Some("session"),
                entry.get("session"),
                entry.get("host_id").map(|_| "of host"),
                entry.get("host_id"),
            ],
        },
        Kind::PostgreSql | Kind::Glog | Kind::Securityd | Kind::AppFirewall => vec![
            entry.level.as_deref(),
            entry.program.as_deref(),
            entry.user.as_deref(),
            Some(message.as_str()),
        ],
    }
    .into_iter()
    .flatten()
    .filter(|word| !word.is_empty())
    .collect();
    format!("{label}: {}", words.join(" "))
}

fn text(fields: &mut Fields, name: &str, value: Option<&str>) {
    if let Some(value) = value.filter(|v| !v.is_empty()) {
        fields.insert(name.into(), Value::from(value));
    }
}
