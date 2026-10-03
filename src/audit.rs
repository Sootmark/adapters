//! Linux audit logs (`/var/log/audit/audit.log`), via the `audit` parser:
//! one record per event (its records grouped by time and serial), and the
//! commands, logins, sudo, account changes and connections read from them
//! in the words the syslog records use. The account is the login user
//! (`auid`): who logged in, whatever `sudo` or `su` made them since.

use std::path::Path;

use audit::{Account, Activity, Event, Log};
use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};

/// Records of audit logs.
pub const NAMESPACE: Namespace = Namespace::new("linux.audit");

const SUMMARY_COMMAND: usize = 160;

/// One record per event.
#[derive(Debug, Default, Clone, Copy)]
pub struct AuditAdapter;

fn known_name(name: &str) -> bool {
    let base = Path::new(name)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    base == "audit.log"
        || base
            .strip_prefix("audit.log.")
            .is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit()))
}

impl Adapter for AuditAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "audit",
            version: audit::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[NAMESPACE]
    }

    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        if name.to_ascii_lowercase().ends_with(".gz") {
            return Confidence::No;
        }
        let first_line = head.split(|&b| b == b'\n').next().unwrap_or_default();
        let reads = (first_line.starts_with(b"type=") || first_line.starts_with(b"node="))
            && first_line.windows(10).any(|w| w == b"msg=audit(");
        match (known_name(name), reads) {
            (_, true) => Confidence::Certain,
            (true, false) => Confidence::Maybe,
            (false, false) => Confidence::No,
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let Log { events, problems } = audit::parse(input.data);
        for problem in problems {
            sink.skipped(Skipped {
                locator: Locator::ByteOffset(0),
                reason: problem,
            });
        }
        if events.is_empty() && !input.data.is_empty() {
            return Err(ParseError::at(0, "no audit records"));
        }
        for event in &events {
            sink.record(self.to_record(input, event));
        }
        Ok(())
    }
}

impl AuditAdapter {
    fn to_record(self, input: &Input<'_>, event: &Event) -> Record {
        let line = event.records.first().map_or(0, |r| r.line);
        let mut record = Record::new(
            input.evidence,
            NAMESPACE,
            Locator::Line(line as u64),
            self.parser(),
        );
        record
            .times
            .push(RecordTime::new(TimeKind::Logged, "msg", event.time));
        let activity = audit::classify(event);
        let syscall = event.syscall();
        let user = activity.as_ref().and_then(subject);
        let command = activity
            .as_ref()
            .and_then(|a| a.command.clone())
            .or_else(|| event.command_line());
        record.facets = Facets {
            host_name: event.node.clone(),
            user_name: user.clone(),
            process_path: activity
                .as_ref()
                .and_then(|a| a.exe.clone())
                .or_else(|| syscall.as_ref().and_then(|s| s.exe).map(str::to_owned)),
            process_command_line: command.clone(),
            process_id: syscall.as_ref().and_then(|s| s.pid).map(u64::from),
            source_ip: activity.as_ref().and_then(|a| a.source_ip.clone()),
            destination_ip: activity.as_ref().and_then(|a| a.destination_ip.clone()),
            ..Facets::default()
        };
        let kinds: Vec<&str> = event.records.iter().map(|r| r.kind.as_str()).collect();
        record.fields = fields(event, &kinds, activity.as_ref(), syscall.as_ref());
        record.summary = activity.as_ref().map_or_else(
            || {
                let name = syscall.as_ref().and_then(|s| s.name);
                match name {
                    Some(name) => format!("{} {name}", kinds.join(" ")),
                    None => kinds.join(" "),
                }
            },
            |activity| summary(activity, user.as_deref(), command.as_deref()),
        );
        record
    }
}

/// Whom an activity is about: for a login, the account logging in (none
/// when audit didn't record it, as for an invalid user); otherwise the
/// login user, else the process's user.
fn subject(activity: &Activity) -> Option<String> {
    if is_login(activity.action) {
        return activity.account.as_ref().and_then(name_of);
    }
    activity
        .login_user
        .as_ref()
        .or(activity.user.as_ref())
        .and_then(name_of)
}

fn is_login(action: &str) -> bool {
    matches!(
        action,
        "ssh login" | "ssh failed login" | "login" | "failed login"
    )
}

/// An account by name, else by number.
fn name_of(account: &Account) -> Option<String> {
    account
        .name
        .clone()
        .or_else(|| account.id.map(|id| id.to_string()))
}

fn summary(activity: &Activity, user: Option<&str>, command: Option<&str>) -> String {
    let user = user.unwrap_or("?");
    let failed = if activity.success == Some(false) {
        " (failed)"
    } else {
        ""
    };
    let from = activity
        .source_ip
        .as_deref()
        .map_or(String::new(), |ip| format!(" from {ip}"));
    let command: String = command
        .unwrap_or("")
        .chars()
        .take(SUMMARY_COMMAND)
        .collect();
    let account = activity
        .account
        .as_ref()
        .or(activity.group.as_ref())
        .and_then(name_of)
        .unwrap_or_default();
    match activity.action {
        "command executed" => format!("{user}$ {command}{failed}"),
        "sudo" => format!("sudo {user}: {command}{failed}"),
        "network connect" => {
            let to = activity.destination_ip.as_deref().unwrap_or("?");
            let port = activity
                .destination_port
                .map_or(String::new(), |p| format!(":{p}"));
            format!("{user} connected to {to}{port} ({command}){failed}")
        }
        action if is_login(action) => {
            let invalid = if activity.invalid_user {
                ", invalid user"
            } else {
                ""
            };
            let account = if account.is_empty() {
                String::new()
            } else {
                format!(" {account}")
            };
            format!("{}{invalid}{account}{from}", capitalised(action))
        }
        action if !account.is_empty() => {
            format!("{} {account} (by {user}){failed}", capitalised(action))
        }
        action => format!("{} (by {user}){failed}", capitalised(action)),
    }
}

/// `ssh login` as `SSH login`, `user added` as `User added`.
fn capitalised(action: &str) -> String {
    if let Some(rest) = action.strip_prefix("ssh ") {
        return format!("SSH {rest}");
    }
    let mut chars = action.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(chars).collect()
    })
}

fn fields(
    event: &Event,
    kinds: &[&str],
    activity: Option<&Activity>,
    syscall: Option<&audit::Syscall<'_>>,
) -> Fields {
    let mut fields = Fields::new();
    fields.insert("Types".into(), Value::from(kinds.join(" ").as_str()));
    fields.insert("Serial".into(), Value::UInt(event.serial));
    let mut text = |name: &str, value: Option<&str>| {
        if let Some(value) = value.filter(|v| !v.is_empty()) {
            fields.insert(name.into(), Value::from(value));
        }
    };
    if let Some(syscall) = syscall {
        text("Syscall", syscall.name);
        text("Comm", syscall.comm);
        text("Key", Some(&syscall.keys.join(" ")));
    }
    text("Cwd", event.cwd());
    text("Paths", Some(&event.paths().collect::<Vec<_>>().join("\n")));
    if let Some(activity) = activity {
        text("Action", Some(activity.action));
        text(
            "LoginUser",
            activity.login_user.as_ref().and_then(name_of).as_deref(),
        );
        text("User", activity.user.as_ref().and_then(name_of).as_deref());
        text(
            "Account",
            activity.account.as_ref().and_then(name_of).as_deref(),
        );
        text(
            "Group",
            activity.group.as_ref().and_then(name_of).as_deref(),
        );
        text("SourceIp", activity.source_ip.as_deref());
        text("DestinationIp", activity.destination_ip.as_deref());
        text("Command", activity.command.as_deref());
        text("Exe", activity.exe.as_deref());
        text("Terminal", activity.terminal.as_deref());
        if let Some(success) = activity.success {
            fields.insert("Success".into(), Value::Bool(success));
        }
        if let Some(port) = activity.destination_port {
            fields.insert("DestinationPort".into(), Value::UInt(u64::from(port)));
        }
        if activity.invalid_user {
            fields.insert("InvalidUser".into(), Value::Bool(true));
        }
    }
    fields
}
