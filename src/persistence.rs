//! Linux and Unix persistence files, via the `persistence` parser:
//! crontabs, systemd units, `authorized_keys`, `rc.local` and shell
//! start-up files, `ld.so.preload` and sudoers. One record per entry, with
//! what it runs and as whom, timed by the file's modification time (when
//! the entry may last have changed), and its suspicious traits flagged.

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
    let mut text = |name: &str, value: Option<&str>| {
        if let Some(value) = value.filter(|v| !v.is_empty()) {
            fields.insert(name.into(), Value::from(value));
        }
    };
    text("Kind", Some(entry.kind.name()));
    text("Schedule", entry.schedule.as_deref());
    text("Flags", Some(&flags.join("; ")));
    if let Detail::AuthorizedKey(key) = &entry.detail {
        text("KeyType", Some(&key.key_type));
        text("Fingerprint", key.fingerprint.as_deref());
        text("Comment", key.comment.as_deref());
    }
    fields.insert("Line".into(), Value::UInt(entry.line as u64));
    fields
}
