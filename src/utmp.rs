//! Linux login records (`utmp`, `wtmp`, `btmp`), via the `utmp` parser:
//! logins with where they came from, logouts, boots, run level and clock
//! changes, and (from `btmp`) failed logins; `lastlog`, each account's
//! last login; and the SQLite databases newer distributions keep instead,
//! wtmpdb's `wtmp.db` (sessions) and `lastlog2.db`, read with their
//! `-wal` file when the caller hands it over (`parse_with_log`): the
//! latest sessions are often only there.

use std::path::Path;

use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};
use utmp::Kind;

/// Records of login record files.
pub const NAMESPACE: Namespace = Namespace::new("linux.utmp");

/// One record per login record (unused slots left out). Which file it came
/// from matters: in `btmp` a user process is a failed login.
#[derive(Debug, Default, Clone, Copy)]
pub struct UtmpAdapter;

/// Which login record file: `wtmp`, `btmp`, `utmp` or `lastlog`, from the
/// name (rotated copies included: `wtmp.1`, `btmp-20260901`), or the
/// databases `wtmpdb` (`wtmp.db`) and `lastlog2` (`lastlog2.db`).
fn file_kind(name: &str) -> Option<&'static str> {
    let base = Path::new(name).file_name()?.to_str()?.to_ascii_lowercase();
    match base.as_str() {
        "wtmp.db" => return Some("wtmpdb"),
        "lastlog2.db" => return Some("lastlog2"),
        _ => {}
    }
    let stem = base.split(['.', '-']).next()?;
    ["wtmp", "btmp", "utmp", "utmpx", "lastlog"]
        .into_iter()
        .find(|kind| *kind == stem)
}

impl Adapter for UtmpAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "utmp",
            version: utmp::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[NAMESPACE]
    }

    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        // Compressed rotations (`wtmp.1.gz`) aren't read here.
        if name.to_ascii_lowercase().ends_with(".gz") || file_kind(name).is_none() {
            return Confidence::No;
        }
        let database = matches!(file_kind(name), Some("wtmpdb" | "lastlog2"));
        if database && !head.starts_with(b"SQLite format 3\0") {
            return Confidence::No;
        }
        if database || file_kind(name) == Some("lastlog") || utmp::parse(head).is_ok() {
            Confidence::Certain
        } else {
            Confidence::Maybe
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        self.parse_with_log(input, &[], sink)
    }

    /// The wtmpdb and lastlog2 databases with their write-ahead log, where
    /// the latest sessions often are; the log means nothing to the other
    /// files.
    fn parse_with_log(
        &self,
        input: &Input<'_>,
        log: &[u8],
        sink: &mut dyn Sink,
    ) -> Result<(), ParseError> {
        match file_kind(input.name) {
            Some("lastlog") => {
                self.parse_lastlog(input, sink);
                return Ok(());
            }
            Some("wtmpdb") => return self.parse_wtmpdb(input, log, sink),
            Some("lastlog2") => return self.parse_lastlog2(input, log, sink),
            _ => {}
        }
        let records = utmp::parse(input.data).map_err(|e| ParseError::at(0, e.0))?;
        skipped(sink, records.problems.iter().cloned());
        let file = file_kind(input.name).unwrap_or("utmp");
        for entry in records
            .records
            .iter()
            .filter(|r| !matches!(r.kind, Kind::Empty | Kind::Signature))
        {
            sink.record(self.to_record(input, entry, file));
        }
        Ok(())
    }
}

impl UtmpAdapter {
    /// One record per account that has logged in.
    fn parse_lastlog(self, input: &Input<'_>, sink: &mut dyn Sink) {
        let lastlog = utmp::parse_lastlog(input.data);
        skipped(sink, lastlog.problems);
        // `struct lastlog`: a 32- or 64-bit time, then 32 + 256 bytes.
        let size = match lastlog.layout {
            utmp::Layout::Time32 | utmp::Layout::Time32BigEndian | utmp::Layout::MacUtmpx => 292,
            utmp::Layout::Time64 | utmp::Layout::Time64BigEndian => 296,
        };
        for login in &lastlog.entries {
            sink.record(self.last_login(input, login, u64::from(login.uid) * size));
        }
    }

    /// One record per session: a boot or a login, timed by its login and,
    /// once it ended, its logout.
    fn parse_wtmpdb(
        self,
        input: &Input<'_>,
        log: &[u8],
        sink: &mut dyn Sink,
    ) -> Result<(), ParseError> {
        let parsed = utmp::parse_wtmpdb(input.data, log).map_err(|e| ParseError::at(0, e.0))?;
        skipped(sink, parsed.problems);
        for session in &parsed.sessions {
            sink.record(self.session(input, session));
        }
        Ok(())
    }

    fn session(self, input: &Input<'_>, session: &utmp::Session) -> Record {
        let mut record = Record::new(
            input.evidence,
            NAMESPACE,
            Locator::TableRow {
                table: "wtmp".to_owned(),
                row: u64::try_from(session.id).unwrap_or_default(),
            },
            self.parser(),
        );
        for (time, name) in [(session.login, "Login"), (session.logout, "Logout")] {
            if let Some(time) = time {
                record
                    .times
                    .push(RecordTime::new(TimeKind::Logged, name, time));
            }
        }
        let is_login = session.kind == utmp::SessionKind::User;
        record.facets = Facets {
            user_name: is_login.then(|| session.user.clone()),
            source_ip: is_login.then(|| ip(&session.remote_host)).flatten(),
            ..Facets::default()
        };
        let mut fields = Fields::new();
        fields.insert("File".into(), Value::from("wtmpdb"));
        let kind = match session.kind {
            utmp::SessionKind::Boot => "boot".to_owned(),
            utmp::SessionKind::RunLevel => "run level".to_owned(),
            utmp::SessionKind::User => "login".to_owned(),
            utmp::SessionKind::Other(n) => n.to_string(),
        };
        fields.insert("Type".into(), Value::from(kind.as_str()));
        texts(
            &mut fields,
            [
                ("User", &session.user),
                ("Line", &session.tty),
                ("Host", &session.remote_host),
                ("Service", &session.service),
            ],
        );
        record.fields = fields;
        let open = if session.logout.is_some() {
            ""
        } else {
            ", not logged out"
        };
        record.summary = match session.kind {
            utmp::SessionKind::Boot => format!("Boot, kernel {}", session.remote_host),
            utmp::SessionKind::User => format!(
                "Login {}{}{}{open}",
                session.user,
                from(&session.remote_host),
                on(&session.tty)
            ),
            _ => format!("{kind} {}", session.user),
        };
        record
    }

    /// One record per account's last login.
    fn parse_lastlog2(
        self,
        input: &Input<'_>,
        log: &[u8],
        sink: &mut dyn Sink,
    ) -> Result<(), ParseError> {
        let parsed = utmp::parse_lastlog2(input.data, log).map_err(|e| ParseError::at(0, e.0))?;
        skipped(sink, parsed.problems);
        for (row, login) in (1..).zip(&parsed.logins) {
            let mut record = Record::new(
                input.evidence,
                NAMESPACE,
                Locator::TableRow {
                    table: "Lastlog2".to_owned(),
                    row,
                },
                self.parser(),
            );
            if let Some(time) = login.time {
                record
                    .times
                    .push(RecordTime::new(TimeKind::Logged, "Time", time));
            }
            record.facets = Facets {
                user_name: Some(login.user.clone()),
                source_ip: ip(&login.remote_host),
                ..Facets::default()
            };
            let mut fields = Fields::new();
            fields.insert("File".into(), Value::from("lastlog2"));
            texts(
                &mut fields,
                [
                    ("User", &login.user),
                    ("Line", &login.tty),
                    ("Host", &login.remote_host),
                    ("Service", &login.service),
                ],
            );
            record.fields = fields;
            record.summary = format!(
                "Last login of {}{}{}",
                login.user,
                from(&login.remote_host),
                on(&login.tty)
            );
            sink.record(record);
        }
        Ok(())
    }

    fn last_login(self, input: &Input<'_>, login: &utmp::LastLogin, offset: u64) -> Record {
        let mut record = Record::new(
            input.evidence,
            NAMESPACE,
            Locator::ByteOffset(offset),
            self.parser(),
        );
        record
            .times
            .push(RecordTime::new(TimeKind::Logged, "ll_time", login.time));
        record.facets = Facets {
            source_ip: ip(&login.host),
            ..Facets::default()
        };
        let mut fields = Fields::new();
        fields.insert("File".into(), Value::from("lastlog"));
        fields.insert("Uid".into(), Value::UInt(u64::from(login.uid)));
        texts(&mut fields, [("Line", &login.line), ("Host", &login.host)]);
        record.fields = fields;
        record.summary = format!(
            "Last login of uid {}{}{}",
            login.uid,
            from(&login.host),
            on(&login.line)
        );
        record
    }

    fn to_record(self, input: &Input<'_>, entry: &utmp::Record, file: &str) -> Record {
        let mut record = Record::new(
            input.evidence,
            NAMESPACE,
            Locator::ByteOffset(entry.offset),
            self.parser(),
        );
        record
            .times
            .push(RecordTime::new(TimeKind::Logged, "ut_tv", entry.time()));
        let source_ip = entry
            .address
            .map(|a| a.to_string())
            .or_else(|| ip(&entry.host));
        let is_session = matches!(entry.kind, Kind::UserProcess | Kind::LoginProcess);
        record.facets = Facets {
            user_name: (is_session && !entry.user.is_empty()).then(|| entry.user.clone()),
            source_ip: source_ip.clone(),
            process_id: u64::try_from(entry.pid).ok().filter(|&pid| pid != 0),
            ..Facets::default()
        };
        record.fields = fields(entry, file);
        record.summary = summary(entry, file);
        record
    }
}

fn summary(entry: &utmp::Record, file: &str) -> String {
    let (from, on) = (from(&entry.host), on(&entry.line));
    match (entry.kind, file) {
        (Kind::UserProcess | Kind::LoginProcess, "btmp") => {
            format!("Failed login {}{from}{on}", entry.user)
        }
        (Kind::UserProcess, _) => format!("Login {}{from}{on}", entry.user),
        (Kind::LoginProcess, _) => format!("Login prompt{on}"),
        (Kind::DeadProcess, _) => format!("Logout{on} (pid {})", entry.pid),
        (Kind::BootTime, _) => format!(
            "Boot{}",
            if entry.host.is_empty() {
                String::new()
            } else {
                format!(", kernel {}", entry.host)
            }
        ),
        (Kind::RunLevel, _) => format!("Run level change: {} {}", entry.user, entry.line)
            .trim_end()
            .to_owned(),
        (Kind::OldTime, _) => "Clock set: the time before".to_owned(),
        (Kind::NewTime, _) => "Clock set: the time after".to_owned(),
        (kind, _) => kind.name().to_owned(),
    }
}

fn fields(entry: &utmp::Record, file: &str) -> Fields {
    let mut fields = Fields::new();
    fields.insert("File".into(), Value::from(file));
    fields.insert("Type".into(), Value::from(entry.kind.name()));
    fields.insert("Pid".into(), Value::Int(i64::from(entry.pid)));
    for (name, value) in [
        ("Line", &entry.line),
        ("Id", &entry.id),
        ("User", &entry.user),
        ("Host", &entry.host),
    ] {
        if !value.is_empty() {
            fields.insert(name.into(), Value::from(value.as_str()));
        }
    }
    if let Some(address) = entry.address {
        fields.insert("Address".into(), Value::Text(address.to_string()));
    }
    if entry.kind == Kind::DeadProcess {
        fields.insert(
            "ExitStatus".into(),
            Value::Int(i64::from(entry.exit_status)),
        );
    }
    if entry.session != 0 {
        fields.insert("Session".into(), Value::Int(entry.session));
    }
    fields
}

fn skipped(sink: &mut dyn Sink, problems: impl IntoIterator<Item = String>) {
    for reason in problems {
        sink.skipped(Skipped {
            locator: Locator::ByteOffset(0),
            reason,
        });
    }
}

/// The text fields that aren't empty.
fn texts<const N: usize>(fields: &mut Fields, values: [(&str, &String); N]) {
    for (name, value) in values {
        if !value.is_empty() {
            fields.insert(name.into(), Value::from(value.as_str()));
        }
    }
}

/// An address, normalised, when `host` is one.
fn ip(host: &str) -> Option<String> {
    host.parse::<std::net::IpAddr>().ok().map(|a| a.to_string())
}

/// ` from <host>`, or nothing.
fn from(host: &str) -> String {
    if host.is_empty() {
        String::new()
    } else {
        format!(" from {host}")
    }
}

/// ` on <line>`, or nothing.
fn on(line: &str) -> String {
    if line.is_empty() {
        String::new()
    } else {
        format!(" on {line}")
    }
}
