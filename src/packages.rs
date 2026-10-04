//! Linux package-manager logs, via the `packages` parser: `dpkg.log`, apt's
//! `history.log`, `dnf.rpm.log` and `yum.log`. One record per package
//! installed, upgraded, downgraded, reinstalled or removed; apt's carry the
//! command line and who ran it. dpkg's configure and trigger steps, its
//! status lines and the logs' other messages are left out: the changes
//! say what happened.

use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};
use packages::{Action, Change, Context, Event, Kind, Transaction};

/// Records of package-manager logs.
pub const NAMESPACE: Namespace = Namespace::new("linux.packages");

/// One record per package change.
#[derive(Debug, Default, Clone, Copy)]
pub struct PackagesAdapter;

impl Adapter for PackagesAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "packages",
            version: packages::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[NAMESPACE]
    }

    /// By name: these logs are plain text any line reader would accept.
    fn probe(&self, name: &str, _head: &[u8]) -> Confidence {
        if packages::detect(name).is_some() {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let kind = packages::detect(input.name)
            .ok_or_else(|| ParseError::at(0, "not a package-manager log"))?;
        let parsed = packages::parse(
            kind,
            input.data,
            Context {
                modified: input.modified,
            },
        );
        for reason in parsed.problems {
            sink.skipped(Skipped {
                locator: Locator::ByteOffset(0),
                reason,
            });
        }
        for entry in &parsed.entries {
            if let Event::Change(change) = &entry.event {
                if is_change(change.action) {
                    let mut record = self.record(input, Locator::Line(entry.line as u64));
                    fill(&mut record, kind, change, entry.time, None);
                    sink.record(record);
                }
            }
        }
        for transaction in &parsed.transactions {
            for (index, change) in transaction.changes.iter().enumerate() {
                let locator = Locator::TableRow {
                    table: format!("transaction at line {}", transaction.line),
                    row: index as u64,
                };
                let mut record = self.record(input, locator);
                fill(
                    &mut record,
                    kind,
                    change,
                    transaction.start,
                    Some(transaction),
                );
                sink.record(record);
            }
        }
        Ok(())
    }
}

impl PackagesAdapter {
    fn record(self, input: &Input<'_>, locator: Locator) -> Record {
        Record::new(input.evidence, NAMESPACE, locator, self.parser())
    }
}

/// Whether an action changes what's installed (not a step of one).
fn is_change(action: Action) -> bool {
    !matches!(
        action,
        Action::Configure | Action::Trigger | Action::Cleanup
    )
}

fn fill(
    record: &mut Record,
    kind: Kind,
    change: &Change,
    time: Option<common::time::Ts>,
    transaction: Option<&Transaction>,
) {
    if let Some(time) = time {
        record
            .times
            .push(RecordTime::new(TimeKind::Logged, "logged", time));
    }
    let command = transaction.and_then(|t| t.command.clone());
    record.facets = Facets {
        user_name: transaction
            .and_then(|t| t.requested_by.as_ref())
            .map(|user| user.name.clone()),
        process_command_line: command.clone(),
        ..Facets::default()
    };
    let mut fields = Fields::new();
    let mut text = |name: &str, value: Option<&str>| {
        if let Some(value) = value.filter(|v| !v.is_empty()) {
            fields.insert(name.into(), Value::from(value));
        }
    };
    text("Log", Some(log_name(kind)));
    text("Action", Some(change.action.as_str()));
    text("Package", Some(&change.package));
    text("Arch", change.arch.as_deref());
    text("OldVersion", change.old_version.as_deref());
    text("NewVersion", change.new_version.as_deref());
    text("Command", command.as_deref());
    text("Error", transaction.and_then(|t| t.error.as_deref()));
    if change.automatic {
        fields.insert("Automatic".into(), Value::Bool(true));
    }
    record.fields = fields;
    record.summary = match command {
        Some(command) => format!("{} (by {command})", change.summary()),
        None => change.summary(),
    };
}

fn log_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Dpkg => "dpkg",
        Kind::AptHistory => "apt",
        Kind::DnfRpm => "dnf",
        Kind::Yum => "yum",
    }
}
