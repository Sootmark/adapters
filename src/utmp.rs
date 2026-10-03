//! Linux login records (`utmp`, `wtmp`, `btmp`), via the `utmp` parser:
//! logins with where they came from, logouts, boots, run level and clock
//! changes, and (from `btmp`) failed logins.

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

/// Which login record file: `wtmp`, `btmp` or `utmp`, from the name
/// (rotated copies included: `wtmp.1`, `btmp-20260901`).
fn file_kind(name: &str) -> Option<&'static str> {
    let base = Path::new(name).file_name()?.to_str()?.to_ascii_lowercase();
    let stem = base.split(['.', '-']).next()?;
    ["wtmp", "btmp", "utmp"]
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
        if utmp::parse(head).is_ok() {
            Confidence::Certain
        } else {
            Confidence::Maybe
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let records = utmp::parse(input.data).map_err(|e| ParseError::at(0, e.0))?;
        for problem in &records.problems {
            sink.skipped(Skipped {
                locator: Locator::ByteOffset(0),
                reason: problem.clone(),
            });
        }
        let file = file_kind(input.name).unwrap_or("utmp");
        for entry in records.records.iter().filter(|r| r.kind != Kind::Empty) {
            sink.record(self.to_record(input, entry, file));
        }
        Ok(())
    }
}

impl UtmpAdapter {
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
        let source_ip = entry.address.map(|a| a.to_string()).or_else(|| {
            entry
                .host
                .parse::<std::net::IpAddr>()
                .ok()
                .map(|a| a.to_string())
        });
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
    let from = if entry.host.is_empty() {
        String::new()
    } else {
        format!(" from {}", entry.host)
    };
    let on = if entry.line.is_empty() {
        String::new()
    } else {
        format!(" on {}", entry.line)
    };
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
