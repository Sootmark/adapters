//! Cloud sync clients' records, via the `cloudsync` parser, the databases
//! read with their write-ahead logs when the caller hands them over:
//! Dropbox's `sync_history.db`, one record per file change synchronized
//! (added, edited or deleted, uploaded or downloaded); Google Drive's
//! `snapshot.db`, one record per file and folder in the cloud and per
//! file and folder in the local folder; and Google Drive's
//! `sync_log.log`, one record per entry. The user from the profile's path.

use cloudsync::{CloudEntry, DropboxSyncEvent, Kind, LocalEntry, SyncLogEntry};
use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};

use crate::home::profile_owner;

/// Files Dropbox synchronized.
pub const DROPBOX_SYNC: Namespace = Namespace::new("cloud.dropbox_sync");
/// Google Drive's files and folders, as the cloud holds them.
pub const GDRIVE_FILES: Namespace = Namespace::new("cloud.gdrive_files");
/// Google Drive's files and folders, as the local folder holds them.
pub const GDRIVE_LOCAL_FILES: Namespace = Namespace::new("cloud.gdrive_local_files");
/// Google Drive's sync log.
pub const GDRIVE_SYNC_LOG: Namespace = Namespace::new("cloud.gdrive_sync_log");

/// The longest text kept in a summary.
const SUMMARY_TEXT: usize = 200;

/// One record per synchronized change, Drive entry and log entry.
#[derive(Debug, Default, Clone, Copy)]
pub struct CloudSyncAdapter;

impl Adapter for CloudSyncAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "cloudsync",
            version: cloudsync::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[
            DROPBOX_SYNC,
            GDRIVE_FILES,
            GDRIVE_LOCAL_FILES,
            GDRIVE_SYNC_LOG,
        ]
    }

    /// By name and signature: `sync_history.db` and `snapshot.db` (in a
    /// Google Drive folder) as SQLite databases, `sync_log.log` by its
    /// first entry.
    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        let fits = match named(name) {
            Some(Kind::DriveSyncLog) => cloudsync::detect(head) == Some(Kind::DriveSyncLog),
            Some(_) => head.starts_with(b"SQLite format 3\0"),
            None => false,
        };
        if fits {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        self.parse_with_log(input, &[], sink)
    }

    fn parse_with_log(
        &self,
        input: &Input<'_>,
        log: &[u8],
        sink: &mut dyn Sink,
    ) -> Result<(), ParseError> {
        let failed = |e: cloudsync::Error| ParseError::at(0, e.0);
        let owner = profile_owner(input.name);
        let owner = owner.as_deref();
        let (problems, records): (Vec<String>, Vec<Record>) = match cloudsync::detect(input.data) {
            Some(Kind::DropboxSyncHistory) => {
                let history =
                    cloudsync::read_dropbox_sync_history(input.data, log).map_err(failed)?;
                let records = history
                    .events
                    .iter()
                    .map(|event| self.dropbox_event(input, event, owner))
                    .collect();
                (history.problems, records)
            }
            Some(Kind::DriveSnapshot) => {
                let snapshot = cloudsync::read_drive_snapshot(input.data, log).map_err(failed)?;
                let cloud = (0i64..)
                    .zip(&snapshot.cloud)
                    .map(|(row, entry)| self.cloud_entry(input, row, entry, owner));
                let local = snapshot
                    .local
                    .iter()
                    .map(|entry| self.local_entry(input, entry, owner));
                let records = cloud.chain(local).collect();
                (snapshot.problems, records)
            }
            Some(Kind::DriveSyncLog) => {
                let log = cloudsync::read_drive_sync_log(input.data).map_err(failed)?;
                let records = log
                    .entries
                    .iter()
                    .map(|entry| self.sync_log_entry(input, entry, owner))
                    .collect();
                (log.problems, records)
            }
            None => return Err(ParseError::at(0, "not a cloud sync file this parser reads")),
        };
        for reason in problems {
            sink.skipped(Skipped {
                locator: Locator::ByteOffset(0),
                reason,
            });
        }
        for record in records {
            sink.record(record);
        }
        Ok(())
    }
}

impl CloudSyncAdapter {
    fn new_record(self, input: &Input<'_>, namespace: Namespace, locator: Locator) -> Record {
        Record::new(input.evidence, namespace, locator, self.parser())
    }

    fn dropbox_event(
        self,
        input: &Input<'_>,
        event: &DropboxSyncEvent,
        owner: Option<&str>,
    ) -> Record {
        let mut record = self.new_record(input, DROPBOX_SYNC, row("sync_history", event.rowid));
        push_times(&mut record, &[(TimeKind::Logged, "Time", event.time)]);
        let mut fields = Fields::new();
        text(&mut fields, "App", Some("dropbox"));
        text(&mut fields, "EventType", Some(&event.event_type));
        text(&mut fields, "FileEvent", event.file_event_type.as_deref());
        text(&mut fields, "Direction", event.direction.as_deref());
        text(&mut fields, "FileId", event.file_id.as_deref());
        text(&mut fields, "LocalPath", event.local_path.as_deref());
        if let Some(other) = event.other_user {
            fields.insert("OtherUser".into(), Value::Bool(other));
        }
        record.fields = fields;
        record.facets = Facets {
            file_path: event.local_path.clone().filter(|p| !p.is_empty()),
            ..owned_by(owner)
        };
        record.summary = format!(
            "Dropbox {} {} {}",
            event.direction.as_deref().unwrap_or("sync"),
            event
                .file_event_type
                .as_deref()
                .unwrap_or(&event.event_type),
            event.local_path.as_deref().unwrap_or("?")
        );
        record
    }

    fn cloud_entry(
        self,
        input: &Input<'_>,
        row_number: i64,
        entry: &CloudEntry,
        owner: Option<&str>,
    ) -> Record {
        let mut record = self.new_record(input, GDRIVE_FILES, row("cloud_entry", row_number));
        push_times(
            &mut record,
            &[
                (TimeKind::Created, "Created", entry.created),
                (TimeKind::Modified, "Modified", entry.modified),
            ],
        );
        let kind = entry.doc_type.map(doc_type_name);
        let mut fields = Fields::new();
        text(&mut fields, "App", Some("google drive"));
        text(&mut fields, "ResourceId", Some(&entry.resource_id));
        text(&mut fields, "FileName", Some(&entry.filename));
        text(&mut fields, "Path", Some(&entry.path));
        text(&mut fields, "Parent", entry.parent.as_deref());
        number(&mut fields, "DocType", entry.doc_type);
        text(&mut fields, "DocTypeName", kind.as_deref());
        text(&mut fields, "Url", entry.url.as_deref());
        number(&mut fields, "Size", entry.size);
        text(&mut fields, "Checksum", entry.checksum.as_deref());
        for (name, value) in [("Shared", entry.shared), ("Removed", entry.removed)] {
            if let Some(value) = value {
                fields.insert(name.into(), Value::Bool(value));
            }
        }
        number(&mut fields, "AclRole", entry.acl_role);
        record.fields = fields;
        record.facets = owned_by(owner);
        record.summary = format!(
            "Google Drive {} in the cloud: {}{}",
            kind.as_deref().unwrap_or("entry"),
            entry.path,
            if entry.removed == Some(true) {
                " (removed)"
            } else {
                ""
            }
        );
        record
    }

    fn local_entry(self, input: &Input<'_>, entry: &LocalEntry, owner: Option<&str>) -> Record {
        let mut record =
            self.new_record(input, GDRIVE_LOCAL_FILES, row("local_entry", entry.inode));
        push_times(
            &mut record,
            &[(TimeKind::Modified, "Modified", entry.modified)],
        );
        let mut fields = Fields::new();
        text(&mut fields, "App", Some("google drive"));
        fields.insert("Inode".into(), Value::Int(entry.inode));
        text(&mut fields, "FileName", Some(&entry.filename));
        text(&mut fields, "Path", Some(&entry.path));
        number(&mut fields, "Size", entry.size);
        text(&mut fields, "Checksum", entry.checksum.as_deref());
        text(&mut fields, "ResourceId", entry.resource_id.as_deref());
        record.fields = fields;
        record.facets = Facets {
            file_path: Some(entry.path.clone()).filter(|p| !p.is_empty()),
            ..owned_by(owner)
        };
        record.summary = format!("Google Drive local file {}", entry.path);
        record
    }

    fn sync_log_entry(
        self,
        input: &Input<'_>,
        entry: &SyncLogEntry,
        owner: Option<&str>,
    ) -> Record {
        let mut record = self.new_record(input, GDRIVE_SYNC_LOG, Locator::Line(entry.line as u64));
        push_times(&mut record, &[(TimeKind::Logged, "Time", entry.time)]);
        let mut fields = Fields::new();
        text(&mut fields, "App", Some("google drive"));
        text(&mut fields, "Level", Some(&entry.level));
        fields.insert("ProcessId".into(), Value::UInt(u64::from(entry.pid)));
        text(&mut fields, "Thread", Some(&entry.thread));
        text(&mut fields, "Source", Some(&entry.source));
        text(&mut fields, "Message", Some(&entry.message));
        fields.insert(
            "UtcOffsetMinutes".into(),
            Value::Int(i64::from(entry.utc_offset_minutes)),
        );
        record.fields = fields;
        record.facets = Facets {
            process_id: Some(u64::from(entry.pid)),
            ..owned_by(owner)
        };
        record.summary = format!(
            "Google Drive {}: {}",
            entry.level,
            entry.message.chars().take(SUMMARY_TEXT).collect::<String>()
        );
        record
    }
}

/// The file a name says a file is: `sync_history.db`, `snapshot.db` in a
/// Google Drive folder (other apps use the name), `sync_log.log`.
fn named(name: &str) -> Option<Kind> {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    if base.eq_ignore_ascii_case("sync_history.db") {
        Some(Kind::DropboxSyncHistory)
    } else if base.eq_ignore_ascii_case("snapshot.db")
        && name.to_ascii_lowercase().contains("google")
    {
        Some(Kind::DriveSnapshot)
    } else if base.eq_ignore_ascii_case("sync_log.log") {
        Some(Kind::DriveSyncLog)
    } else {
        None
    }
}

/// What Drive's `doc_type` names.
fn doc_type_name(number: i64) -> String {
    let name = match number {
        0 => "folder",
        1 => "file",
        2 => "presentation",
        4 => "spreadsheet",
        6 => "document",
        other => return format!("type {other}"),
    };
    name.to_owned()
}

fn row(table: &str, row: i64) -> Locator {
    Locator::TableRow {
        table: table.to_owned(),
        row: u64::try_from(row).unwrap_or_default(),
    }
}

fn owned_by(owner: Option<&str>) -> Facets {
    Facets {
        user_name: owner.map(str::to_owned),
        ..Facets::default()
    }
}

fn push_times(record: &mut Record, times: &[(TimeKind, &str, Option<model::Ts>)]) {
    for &(kind, name, time) in times {
        if let Some(time) = time {
            record.times.push(RecordTime::new(kind, name, time));
        }
    }
}

fn text(fields: &mut Fields, name: &str, value: Option<&str>) {
    if let Some(value) = value.filter(|v| !v.is_empty()) {
        fields.insert(name.into(), Value::from(value));
    }
}

fn number(fields: &mut Fields, name: &str, value: Option<i64>) {
    if let Some(value) = value {
        fields.insert(name.into(), Value::Int(value));
    }
}
