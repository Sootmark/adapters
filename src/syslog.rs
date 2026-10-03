//! Linux syslog files, via the `syslog` parser: every entry, and what sshd,
//! sudo, su, cron and the account tools recorded, with the account and the
//! address they name.
//!
//! Classic lines have no year and no zone: their times are wall-clock times
//! in the host's zone, the year inferred from the file's modification time
//! ([`Input::modified`]) and marked (`YearInferred`); without it they are
//! untimed, their text kept in `TimeText`.

use std::path::Path;

use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};
use syslog::auth::{classify, Event};
use syslog::{Context, Entry, Format};

/// Records of syslog files.
pub const NAMESPACE: Namespace = Namespace::new("linux.syslog");

/// Files syslog daemons write (rotated copies included: `auth.log.1`).
const NAMES: [&str; 10] = [
    "syslog",
    "messages",
    "auth.log",
    "secure",
    "kern.log",
    "daemon.log",
    "user.log",
    "cron",
    "cron.log",
    "maillog",
];
const SUMMARY_MESSAGE: usize = 160;

/// One record per entry.
#[derive(Debug, Default, Clone, Copy)]
pub struct SyslogAdapter;

fn known_name(name: &str) -> bool {
    let Some(base) = Path::new(name).file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let base = base.to_ascii_lowercase();
    NAMES.iter().any(|known| {
        base == *known
            || base
                .strip_prefix(known)
                .and_then(|r| r.strip_prefix('.'))
                .is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit()))
    })
}

impl Adapter for SyslogAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "syslog",
            version: syslog::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[NAMESPACE]
    }

    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        if name.to_ascii_lowercase().ends_with(".gz") {
            return Confidence::No;
        }
        // The first line must read as a syslog entry.
        let first_line = head.split(|&b| b == b'\n').next().unwrap_or_default();
        let reads = !syslog::parse(first_line, Context::default())
            .entries
            .is_empty();
        match (known_name(name), reads) {
            (true, true) => Confidence::Certain,
            (false, true) | (true, false) => Confidence::Maybe,
            (false, false) => Confidence::No,
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let parsed = syslog::parse(
            input.data,
            Context {
                modified: input.modified,
            },
        );
        for problem in &parsed.problems {
            sink.skipped(Skipped {
                locator: Locator::ByteOffset(0),
                reason: problem.clone(),
            });
        }
        if parsed.entries.is_empty() && !input.data.is_empty() {
            return Err(ParseError::at(0, "no syslog entries"));
        }
        for entry in &parsed.entries {
            sink.record(self.to_record(input, entry));
        }
        Ok(())
    }
}

impl SyslogAdapter {
    fn to_record(self, input: &Input<'_>, entry: &Entry) -> Record {
        let mut record = Record::new(
            input.evidence,
            NAMESPACE,
            Locator::ByteOffset(entry.offset),
            self.parser(),
        );
        if let Some(time) = entry.time {
            record
                .times
                .push(RecordTime::new(TimeKind::Logged, "timestamp", time));
        }
        let event = classify(entry);
        record.facets = Facets {
            host_name: entry.host.clone(),
            process_path: entry.program.clone(),
            process_id: entry.pid.map(u64::from),
            user_name: event.as_ref().and_then(|e| e.user.clone()),
            source_ip: event.as_ref().and_then(|e| e.source_ip.clone()),
            process_command_line: event.as_ref().and_then(|e| e.command.clone()),
            ..Facets::default()
        };
        record.fields = fields(entry, event.as_ref());
        record.summary = event.as_ref().map_or_else(|| plain_summary(entry), summary);
        record
    }
}

fn plain_summary(entry: &Entry) -> String {
    let message: String = entry
        .message
        .lines()
        .next()
        .unwrap_or("")
        .chars()
        .take(SUMMARY_MESSAGE)
        .collect();
    match &entry.program {
        Some(program) => format!("{program}: {message}"),
        None => message,
    }
}

fn summary(event: &Event) -> String {
    let user = event.user.as_deref().unwrap_or("?");
    let target = event.target_user.as_deref().unwrap_or("?");
    let from = event
        .source_ip
        .as_deref()
        .map_or(String::new(), |ip| format!(" from {ip}"));
    let method = event
        .method
        .as_deref()
        .map_or(String::new(), |m| format!(" ({m})"));
    match event.action {
        "ssh login" => format!("SSH login {user}{from}{method}"),
        "ssh failed login" if event.invalid_user => {
            format!("SSH failed login, invalid user {user}{from}{method}")
        }
        "ssh failed login" => format!("SSH failed login {user}{from}{method}"),
        "ssh invalid user" => format!("SSH invalid user {user}{from}"),
        "ssh connection" => format!("SSH connection{from}"),
        "ssh disconnect" => format!("SSH disconnect {user}{from}"),
        "sudo" => format!(
            "sudo {user} as {target}: {}",
            event.command.as_deref().unwrap_or("")
        ),
        "su" => format!("su {user} to {target}"),
        "cron command" => format!("cron ({user}): {}", event.command.as_deref().unwrap_or("")),
        "session opened" => format!("Session opened for {user}"),
        "user added" => format!("User added: {target}"),
        "user deleted" => format!("User deleted: {target}"),
        "user changed" => format!(
            "User {target} added to group {}",
            event.group.as_deref().unwrap_or("?")
        ),
        "group added" => format!("Group added: {}", event.group.as_deref().unwrap_or("?")),
        "password changed" => format!("Password changed for {target}"),
        action => action.to_owned(),
    }
}

fn fields(entry: &Entry, event: Option<&Event>) -> Fields {
    let mut fields = Fields::new();
    let mut text = |name: &str, value: Option<&str>| {
        if let Some(value) = value.filter(|v| !v.is_empty()) {
            fields.insert(name.into(), Value::from(value));
        }
    };
    text(
        "Format",
        Some(match entry.format {
            Format::Classic => "classic",
            Format::Rfc3339 => "rfc3339",
            Format::Rfc5424 => "rfc5424",
        }),
    );
    text("TimeText", Some(&entry.time_text));
    text("Host", entry.host.as_deref());
    text("Program", entry.program.as_deref());
    text("Level", entry.level.as_deref());
    text("MessageId", entry.message_id.as_deref());
    text("Message", Some(&entry.message));
    if let Some(event) = event {
        text("Action", Some(event.action));
        text("User", event.user.as_deref());
        text("TargetUser", event.target_user.as_deref());
        text("SourceIp", event.source_ip.as_deref());
        text("Method", event.method.as_deref());
        text("Fingerprint", event.fingerprint.as_deref());
        text("Command", event.command.as_deref());
        text("Group", event.group.as_deref());
    }
    if entry.format == Format::Classic {
        fields.insert("YearInferred".into(), Value::Bool(entry.time.is_some()));
    }
    if let Some(pid) = entry.pid {
        fields.insert("Pid".into(), Value::UInt(u64::from(pid)));
    }
    if let (Some(facility), Some(severity)) = (entry.facility(), entry.severity()) {
        fields.insert("Facility".into(), Value::UInt(u64::from(facility)));
        fields.insert("Severity".into(), Value::UInt(u64::from(severity)));
    }
    if let Some(event) = event {
        if let Some(port) = event.port {
            fields.insert("Port".into(), Value::UInt(u64::from(port)));
        }
        if event.invalid_user {
            fields.insert("InvalidUser".into(), Value::Bool(true));
        }
    }
    fields
}
