//! macOS and FreeBSD audit trails (`/var/audit/*`), via the `bsm` parser:
//! one record per audited event, its subject (audit user, real and
//! effective user, process, session, where a remote session came from),
//! what it touched (paths, program arguments, sockets, file attributes,
//! system call arguments) and how it ended. The account is the audit user
//! (`AuditUid`): who logged in, whatever `sudo` or `su` made them since.

use std::net::IpAddr;
use std::path::Path;

use bsm::{Record as BsmRecord, Role, TokenData};
use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};

/// Records of audit trails.
pub const NAMESPACE: Namespace = Namespace::new("unix.bsm");

/// The longest command line kept in a summary.
const SUMMARY_COMMAND: usize = 160;

/// One record per audited event.
#[derive(Debug, Default, Clone, Copy)]
pub struct BsmAdapter;

/// A trail's name: in `/var/audit/`, or `<start>.<end>` where the end is a
/// time, `not_terminated` or `crash_recovery`.
fn known_name(name: &str) -> bool {
    let normalized = name.replace('\\', "/");
    if normalized.contains("/var/audit/") {
        return true;
    }
    let base = Path::new(&normalized)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    base.split_once('.').is_some_and(|(start, end)| {
        start.len() == 14
            && start.bytes().all(|b| b.is_ascii_digit())
            && (matches!(end, "not_terminated" | "crash_recovery")
                || (end.len() == 14 && end.bytes().all(|b| b.is_ascii_digit())))
    })
}

impl Adapter for BsmAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "bsm",
            version: bsm::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[NAMESPACE]
    }

    /// By the first record's header (or file token), and the name.
    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        match (bsm::detect(head), known_name(name)) {
            (true, true) => Confidence::Certain,
            (true, false) => Confidence::Maybe,
            (false, _) => Confidence::No,
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let trail = bsm::read(input.data);
        for reason in trail.problems {
            let offset = reason
                .strip_prefix("offset 0x")
                .and_then(|rest| rest.split_once(':'))
                .and_then(|(hex, _)| u64::from_str_radix(hex, 16).ok())
                .unwrap_or_default();
            sink.skipped(Skipped {
                locator: Locator::ByteOffset(offset),
                reason,
            });
        }
        for record in &trail.records {
            sink.record(self.record(input, record));
        }
        Ok(())
    }
}

impl BsmAdapter {
    fn record(self, input: &Input<'_>, event: &BsmRecord) -> Record {
        let mut record = Record::new(
            input.evidence,
            NAMESPACE,
            Locator::ByteOffset(event.offset),
            self.parser(),
        );
        if let Some(time) = event.time {
            record
                .times
                .push(RecordTime::new(TimeKind::Logged, "Time", time));
        }
        let mut fields = Fields::new();
        fields.insert("EventType".into(), Value::UInt(u64::from(event.event_type)));
        if let Some(name) = event.event_name() {
            fields.insert("EventName".into(), Value::from(name));
        }
        fields.insert("Modifier".into(), Value::UInt(u64::from(event.modifier)));
        if let Some(host) = event.host {
            fields.insert("Host".into(), Value::from(host.to_string().as_str()));
        }
        let names: Vec<Value> = event.tokens.iter().map(|t| Value::from(t.name())).collect();
        fields.insert("Tokens".into(), Value::List(names));
        for token in &event.tokens {
            token_fields(&token.data, &mut fields);
        }
        let paths: Vec<&str> = event.paths().collect();
        if let Some(first) = paths.first() {
            fields.insert("Path".into(), Value::from(*first));
        }
        if paths.len() > 1 {
            let all = paths.iter().map(|p| Value::from(*p)).collect();
            fields.insert("Paths".into(), Value::List(all));
        }
        let texts: Vec<&str> = event.texts().collect();
        if !texts.is_empty() {
            fields.insert("Text".into(), Value::from(texts.join(" | ").as_str()));
        }
        let command = event.exec_args().map(|args| args.join(" "));
        if let Some(command) = &command {
            fields.insert("CommandLine".into(), Value::from(command.as_str()));
        }
        record.fields = fields;
        let subject = event.subject();
        record.facets = Facets {
            process_id: subject.map(|s| u64::from(s.pid)),
            process_path: event.exec_args().and_then(|args| args.first()).cloned(),
            process_command_line: command.clone(),
            file_path: paths.first().map(|p| (*p).to_owned()),
            source_ip: subject
                .and_then(|s| s.terminal_address)
                .map(|ip| ip.to_string()),
            destination_ip: remote_address(event).map(|ip| ip.to_string()),
            event_code: Some(u32::from(event.event_type)),
            ..Facets::default()
        };
        record.summary = summary(event, command.as_deref(), paths.first().copied());
        record
    }
}

/// A token's values as fields (a subject's under its own names, a process
/// acted on under `Target…`).
fn token_fields(data: &TokenData, fields: &mut Fields) {
    match data {
        TokenData::Subject(s) if s.role == Role::Subject && !fields.contains_key("AuditUid") => {
            for (name, value) in [
                ("AuditUid", s.audit_uid),
                ("Uid", s.ruid),
                ("Gid", s.rgid),
                ("Euid", s.euid),
                ("Egid", s.egid),
            ] {
                fields.insert(name.into(), Value::Int(i64::from(value)));
            }
            fields.insert("Pid".into(), Value::UInt(u64::from(s.pid)));
            fields.insert("SessionId".into(), Value::UInt(u64::from(s.session)));
            fields.insert("TerminalPort".into(), Value::UInt(s.terminal_port));
            if let Some(ip) = s.terminal_address {
                fields.insert(
                    "TerminalAddress".into(),
                    Value::from(ip.to_string().as_str()),
                );
            }
        }
        TokenData::Subject(s) if s.role == Role::Process => {
            fields.insert("TargetPid".into(), Value::UInt(u64::from(s.pid)));
            fields.insert("TargetUid".into(), Value::Int(i64::from(s.ruid)));
        }
        TokenData::Return(r) => {
            fields.insert("Success".into(), Value::Bool(r.succeeded()));
            fields.insert("ErrorCode".into(), Value::UInt(u64::from(r.status)));
            if let Some(error) = bsm::error_name(r.status).filter(|_| !r.succeeded()) {
                fields.insert("Error".into(), Value::from(error));
            }
            fields.insert("ReturnValue".into(), Value::Int(r.value));
        }
        TokenData::Exit(r) => {
            fields.insert("ExitStatus".into(), Value::UInt(u64::from(r.status)));
        }
        TokenData::Argument { name, value, .. } if !name.is_empty() => {
            fields.insert(format!("Argument.{name}"), Value::UInt(*value));
        }
        TokenData::Attributes(a) => {
            fields.insert("Mode".into(), Value::from(format!("{:o}", a.mode).as_str()));
            fields.insert("Owner".into(), Value::Int(i64::from(a.uid)));
            fields.insert("Inode".into(), Value::UInt(a.node));
        }
        TokenData::ExecEnv(env) => {
            let env = env.iter().map(|v| Value::from(v.as_str())).collect();
            fields.insert("Environment".into(), Value::List(env));
        }
        TokenData::Socket(s) => {
            fields.insert(
                "LocalAddress".into(),
                Value::from(s.local.0.to_string().as_str()),
            );
            fields.insert("LocalPort".into(), Value::UInt(u64::from(s.local.1)));
            fields.insert(
                "RemoteAddress".into(),
                Value::from(s.remote.0.to_string().as_str()),
            );
            fields.insert("RemotePort".into(), Value::UInt(u64::from(s.remote.1)));
        }
        TokenData::SocketAddress { port, address, .. } => {
            fields.insert(
                "RemoteAddress".into(),
                Value::from(address.to_string().as_str()),
            );
            fields.insert("RemotePort".into(), Value::UInt(u64::from(*port)));
        }
        TokenData::UnixSocket { path, .. } => {
            fields.insert("SocketPath".into(), Value::from(path.as_str()));
        }
        TokenData::Zone(zone) => {
            fields.insert("Zone".into(), Value::from(zone.as_str()));
        }
        _ => {}
    }
}

/// The far end of a socket the event names.
fn remote_address(event: &BsmRecord) -> Option<IpAddr> {
    event.tokens.iter().find_map(|t| match &t.data {
        TokenData::Socket(s) => Some(s.remote.0),
        TokenData::SocketAddress { address, .. } => Some(*address),
        _ => None,
    })
}

/// `execve(2) by audit user 501 (uid 0, pid 812): /usr/bin/curl -o x`,
/// with `failed (Permission denied)` when it did.
fn summary(event: &BsmRecord, command: Option<&str>, path: Option<&str>) -> String {
    let name = event.event_name().map_or_else(
        || format!("Audit event {}", event.event_type),
        str::to_owned,
    );
    let mut out = match event.subject() {
        Some(s) => format!(
            "{name} by audit user {} (uid {}, pid {})",
            s.audit_uid, s.ruid, s.pid
        ),
        None => name,
    };
    let what = command
        .map(|c| c.chars().take(SUMMARY_COMMAND).collect::<String>())
        .or_else(|| path.map(str::to_owned))
        .or_else(|| event.texts().next().map(str::to_owned));
    if let Some(what) = what {
        out.push_str(": ");
        out.push_str(&what);
    }
    if let Some(outcome) = event.outcome().filter(|r| !r.succeeded()) {
        let error = bsm::error_name(outcome.status).unwrap_or("error");
        out = format!("{out}, failed ({error})");
    }
    out
}
