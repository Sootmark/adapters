//! Windows File History catalogs (`Catalog1.edb`, `Catalog2.edb`), via
//! the `filehistory` parser: one record per version of a file or folder
//! File History saw (its path, times, attributes, change journal number,
//! the backup runs it was first and last part of, its copy on the target),
//! kept after the file was deleted; one per backup run and one per folder
//! protected or excluded.

use std::collections::HashMap;

use filehistory::{BackupSet, Catalog, Entry, FileRecord, LibraryFolder};
use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{
    Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Ts, Value,
};

use crate::home::profile_owner;

/// Files and folders seen.
pub const FILES: Namespace = Namespace::new("windows.filehistory");
/// Backup runs.
pub const BACKUPS: Namespace = Namespace::new("windows.filehistory_backup");
/// Folders protected or excluded.
pub const LIBRARIES: Namespace = Namespace::new("windows.filehistory_library");

/// The backup set a version still visible names as its last.
const STILL_VISIBLE: i64 = 2_147_483_647;
/// The ESE signature, at offset 4.
const ESE_SIGNATURE: [u8; 4] = [0xef, 0xcd, 0xab, 0x89];

/// One record per entry, backup run and library folder.
#[derive(Debug, Default, Clone, Copy)]
pub struct FileHistoryAdapter;

impl Adapter for FileHistoryAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "filehistory",
            version: filehistory::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[FILES, BACKUPS, LIBRARIES]
    }

    /// By name (`Catalog1.edb`, `Catalog2.edb`) and the ESE signature.
    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
        let named = ["Catalog1.edb", "Catalog2.edb"]
            .iter()
            .any(|n| base.eq_ignore_ascii_case(n));
        if named && head.get(4..8) == Some(&ESE_SIGNATURE[..]) {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let catalog = filehistory::read(input.data).map_err(|e| ParseError::at(0, e.0))?;
        for reason in &catalog.problems {
            sink.skipped(Skipped {
                locator: Locator::ByteOffset(0),
                reason: reason.clone(),
            });
        }
        let owner = profile_owner(input.name);
        let index = Index::of(&catalog);
        for entry in &catalog.entries {
            sink.record(self.entry(input, &index, entry, owner.as_deref()));
        }
        let mut first_seen: HashMap<i64, u64> = HashMap::new();
        for set in catalog.entries.iter().filter_map(|entry| entry.created_in) {
            *first_seen.entry(set).or_default() += 1;
        }
        for set in &catalog.backup_sets {
            let count = first_seen.get(&set.id).copied().unwrap_or_default();
            sink.record(self.backup_set(input, set, count));
        }
        for folder in &catalog.library_folders {
            sink.record(self.library_folder(input, folder, owner.as_deref()));
        }
        Ok(())
    }
}

impl FileHistoryAdapter {
    fn new_record(self, input: &Input<'_>, namespace: Namespace, table: &str, id: i64) -> Record {
        Record::new(
            input.evidence,
            namespace,
            Locator::TableRow {
                table: table.to_owned(),
                row: u64::try_from(id).unwrap_or_default(),
            },
            self.parser(),
        )
    }

    fn entry(
        self,
        input: &Input<'_>,
        index: &Index<'_>,
        entry: &Entry,
        owner: Option<&str>,
    ) -> Record {
        let mut record = self.new_record(input, FILES, "namespace", entry.id);
        let set_time = |id: Option<i64>| id.and_then(|id| index.set_times.get(&id).copied());
        let still_visible = entry.visible_until == Some(STILL_VISIBLE);
        let last_set = entry.visible_until.filter(|_| !still_visible);
        for (kind, name, time) in [
            (TimeKind::Created, "FileCreated", entry.created),
            (TimeKind::Modified, "FileModified", entry.modified),
            (
                TimeKind::FirstSeen,
                "FirstBackedUp",
                set_time(entry.created_in),
            ),
            (TimeKind::LastSeen, "LastBackedUp", set_time(last_set)),
        ] {
            if let Some(time) = time {
                record.times.push(RecordTime::new(kind, name, time));
            }
        }
        let mut fields = Fields::new();
        text(&mut fields, "Path", entry.path.as_deref());
        text(&mut fields, "Name", entry.name.as_deref());
        text(&mut fields, "Folder", entry.folder.as_deref());
        fields.insert("IsFolder".into(), Value::Bool(entry.is_folder()));
        fields.insert("StillVisible".into(), Value::Bool(still_visible));
        if let Some(attributes) = entry.attributes {
            fields.insert("Attributes".into(), Value::UInt(u64::from(attributes)));
        }
        for (name, value) in [
            ("Usn", entry.usn),
            ("Status", entry.status),
            ("FirstBackupSet", entry.created_in),
            ("LastBackupSet", last_set),
        ] {
            if let Some(value) = value {
                fields.insert(name.into(), Value::Int(value));
            }
        }
        let copy = entry
            .file_record_id
            .filter(|id| *id != 0)
            .and_then(|id| index.files.get(&id));
        if let Some(copy) = copy {
            text(&mut fields, "CopyPath", copy.path.as_deref());
            if let Some(size) = copy.size {
                fields.insert("Size".into(), Value::Int(size));
            }
        }
        record.fields = fields;
        record.facets = Facets {
            user_name: owner.map(str::to_owned),
            file_path: entry.path.clone(),
            ..Facets::default()
        };
        record.summary = format!(
            "File History {}: {}{}",
            if entry.is_folder() { "folder" } else { "file" },
            entry.path.as_deref().unwrap_or("?"),
            if still_visible {
                ""
            } else {
                " (no longer in the last backup)"
            }
        );
        record
    }

    /// A run, and how many versions it saw first.
    fn backup_set(self, input: &Input<'_>, set: &BackupSet, first_seen: u64) -> Record {
        let mut record = self.new_record(input, BACKUPS, "backupset", set.id);
        if let Some(time) = set.time {
            record
                .times
                .push(RecordTime::new(TimeKind::Executed, "Time", time));
        }
        let mut fields = Fields::new();
        fields.insert("BackupSet".into(), Value::Int(set.id));
        fields.insert("EntriesFirstSeen".into(), Value::UInt(first_seen));
        record.fields = fields;
        record.summary = format!(
            "File History backup run {} ({first_seen} new versions)",
            set.id
        );
        record
    }

    fn library_folder(
        self,
        input: &Input<'_>,
        folder: &LibraryFolder,
        owner: Option<&str>,
    ) -> Record {
        let mut record = self.new_record(input, LIBRARIES, "library", folder.id);
        let excluded = folder.library.as_deref() == Some("?Exclude");
        let mut fields = Fields::new();
        text(&mut fields, "Library", folder.library.as_deref());
        text(&mut fields, "Folder", folder.folder.as_deref());
        fields.insert("Excluded".into(), Value::Bool(excluded));
        for (name, value) in [
            ("FirstBackupSet", folder.created_in),
            (
                "LastBackupSet",
                folder.visible_until.filter(|v| *v != STILL_VISIBLE),
            ),
        ] {
            if let Some(value) = value {
                fields.insert(name.into(), Value::Int(value));
            }
        }
        record.fields = fields;
        record.facets = Facets {
            user_name: owner.map(str::to_owned),
            file_path: folder.folder.clone(),
            ..Facets::default()
        };
        record.summary = format!(
            "File History {}: {}",
            if excluded {
                "excluded folder"
            } else {
                "protected folder"
            },
            folder.folder.as_deref().unwrap_or("?")
        );
        record
    }
}

/// The backup runs' times and the copies, by id: a catalog holds as many
/// entries as files backed up, each looked up once.
struct Index<'a> {
    set_times: HashMap<i64, Ts>,
    files: HashMap<i64, &'a FileRecord>,
}

impl<'a> Index<'a> {
    fn of(catalog: &'a Catalog) -> Self {
        Self {
            set_times: catalog
                .backup_sets
                .iter()
                .filter_map(|set| Some((set.id, set.time?)))
                .collect(),
            files: catalog.files.iter().map(|file| (file.id, file)).collect(),
        }
    }
}

fn text(fields: &mut Fields, name: &str, value: Option<&str>) {
    if let Some(value) = value.filter(|v| !v.is_empty()) {
        fields.insert(name.into(), Value::from(value));
    }
}
