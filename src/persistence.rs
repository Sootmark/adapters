//! Linux and Unix persistence files, via the `persistence` parser:
//! crontabs, `at` jobs, systemd units, init scripts, `authorized_keys` and
//! `sshd_config`, `rc.local` and shell start-up files, `ld.so.preload`,
//! sudoers, PAM, udev rules, XDG autostart entries and kernel modules. One
//! record per entry, with what it runs and as whom, timed by the file's
//! modification time (when the entry may last have changed), and its
//! suspicious traits flagged.

use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};
use persistence::{Detail, Entry};

/// Records of persistence files.
pub const NAMESPACE: Namespace = Namespace::new("unix.persistence");

/// One record per entry.
#[derive(Debug, Default, Clone, Copy)]
pub struct PersistenceAdapter;

impl Adapter for PersistenceAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "persistence",
            version: persistence::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[NAMESPACE]
    }

    /// By where the file is: a crontab spool's files are named after their
    /// users.
    fn probe(&self, name: &str, _head: &[u8]) -> Confidence {
        if persistence::detect(name).is_some() {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let kind = persistence::detect(input.name)
            .ok_or_else(|| ParseError::at(0, "not a persistence file"))?;
        let parsed = persistence::parse(kind, input.data, input.name);
        for problem in parsed.problems {
            sink.skipped(Skipped {
                locator: Locator::ByteOffset(0),
                reason: problem,
            });
        }
        for entry in &parsed.entries {
            sink.record(self.to_record(input, entry));
        }
        Ok(())
    }
}

impl PersistenceAdapter {
    fn to_record(self, input: &Input<'_>, entry: &Entry) -> Record {
        let mut record = Record::new(
            input.evidence,
            NAMESPACE,
            Locator::Line(entry.line as u64),
            self.parser(),
        );
        if let Some(modified) = input.modified {
            record.times.push(RecordTime::new(
                TimeKind::Modified,
                "file_modified",
                modified,
            ));
        }
        record.facets = Facets {
            user_name: entry.user.clone(),
            process_command_line: entry.command.clone(),
            file_path: Some(input.name.to_owned()),
            ..Facets::default()
        };
        let flags: Vec<String> = persistence::flags(entry)
            .iter()
            .map(ToString::to_string)
            .collect();
        record.summary = if flags.is_empty() {
            entry.summary()
        } else {
            format!("{} (flags: {})", entry.summary(), flags.join(", "))
        };
        record.fields = fields(entry, &flags);
        record
    }
}

fn fields(entry: &Entry, flags: &[String]) -> Fields {
    let mut fields = Fields::new();
    text(&mut fields, "Kind", Some(entry.kind.name()));
    text(&mut fields, "Schedule", entry.schedule.as_deref());
    text(&mut fields, "Flags", Some(&flags.join("; ")));
    match &entry.detail {
        Detail::AuthorizedKey(key) => {
            text(&mut fields, "KeyType", Some(&key.key_type));
            text(&mut fields, "Fingerprint", key.fingerprint.as_deref());
            text(&mut fields, "Comment", key.comment.as_deref());
        }
        Detail::AtJob { queue, job, uid } => {
            text(&mut fields, "Queue", queue.map(String::from).as_deref());
            number(&mut fields, "Job", *job);
            number(&mut fields, "Uid", *uid);
        }
        Detail::PamRule(rule) => {
            text(&mut fields, "Service", Some(&rule.service));
            text(&mut fields, "PamType", Some(&rule.rule_type));
            text(&mut fields, "Control", Some(&rule.control));
            text(&mut fields, "Module", Some(&rule.module));
            text(&mut fields, "Arguments", Some(&rule.arguments.join(" ")));
        }
        Detail::PamInclude(file) => text(&mut fields, "Include", Some(file)),
        Detail::SshdSetting {
            key,
            value,
            condition,
        } => {
            text(&mut fields, "Setting", Some(key));
            text(&mut fields, "Value", Some(value));
            text(&mut fields, "Match", condition.as_deref());
        }
        Detail::Autostart { name, disabled } => {
            text(&mut fields, "Name", name.as_deref());
            fields.insert("Disabled".into(), Value::Bool(*disabled));
        }
        Detail::ModprobeDirective {
            directive, module, ..
        } => {
            text(&mut fields, "Directive", Some(directive));
            text(&mut fields, "Module", Some(module));
        }
        _ => {}
    }
    fields.insert("Line".into(), Value::UInt(entry.line as u64));
    fields
}

fn text(fields: &mut Fields, name: &str, value: Option<&str>) {
    if let Some(value) = value.filter(|v| !v.is_empty()) {
        fields.insert(name.into(), Value::from(value));
    }
}

fn number(fields: &mut Fields, name: &str, value: Option<u32>) {
    if let Some(value) = value {
        fields.insert(name.into(), Value::UInt(u64::from(value)));
    }
}
