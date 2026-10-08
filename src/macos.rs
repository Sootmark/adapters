//! macOS artifacts, via the `macos` parser: launchd jobs (LaunchAgents and
//! LaunchDaemons, macOS's main persistence, with their suspicious traits
//! flagged), and those kept in SQLite, each read with its write-ahead log
//! when the caller hands it over: quarantine events (where each downloaded
//! file came from), TCC (which apps were granted privacy permissions, and
//! when), KnowledgeC (app usage and device events over time), crankd's
//! application usage, document versions, Notes, Notification Center and
//! Messages; keychains' items (names, accounts, servers, times; never
//! a secret), Spotlight's searched terms and indexed volumes; and the text
//! logs of Wi-Fi (`wifi.log`, its years inferred) and launchd
//! (`launchd.log`). Any other property list is read as plaso's
//! `plist_default` plugin reads it: one record per key holding a date.

use macos::{
    Artifact, AslRecord, BackgroundItem, FsEvent, JobKind, KnowledgeEvent, LaunchJob, PrefEntry,
    PrefKind, QuarantineEvent, Scope, TccEntry,
};
use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};

use crate::home::profile_owner;

mod logs;
mod personal;
mod plist_dates;
mod usage;

/// Quarantine events.
pub const QUARANTINE: Namespace = Namespace::new("macos.quarantine");
/// TCC permission entries.
pub const TCC: Namespace = Namespace::new("macos.tcc");
/// KnowledgeC events.
pub const KNOWLEDGEC: Namespace = Namespace::new("macos.knowledgec");
/// launchd jobs.
pub const LAUNCHD: Namespace = Namespace::new("macos.launchd");
/// FSEvents changes.
pub const FSEVENTS: Namespace = Namespace::new("macos.fsevents");
/// Login items (background items, legacy login items).
pub const LOGIN_ITEMS: Namespace = Namespace::new("macos.login_items");
/// Installations.
pub const INSTALL_HISTORY: Namespace = Namespace::new("macos.install_history");
/// Software Update's checks.
pub const SOFTWARE_UPDATE: Namespace = Namespace::new("macos.software_update");
/// Wi-Fi networks remembered.
pub const WIFI: Namespace = Namespace::new("macos.wifi");
/// Bluetooth devices.
pub const BLUETOOTH: Namespace = Namespace::new("macos.bluetooth");
/// Apple accounts signed in.
pub const APPLE_ACCOUNTS: Namespace = Namespace::new("macos.apple_account");
/// Login and logout hooks, login applications.
pub const LOGIN_WINDOW: Namespace = Namespace::new("macos.login_window");
/// Local accounts.
pub const USERS: Namespace = Namespace::new("macos.user");
/// Startup items.
pub const STARTUP_ITEMS: Namespace = Namespace::new("macos.startup_item");
/// Time Machine destinations and snapshots.
pub const TIME_MACHINE: Namespace = Namespace::new("macos.time_machine");
/// Apple System Log messages.
pub const ASL: Namespace = Namespace::new("macos.asl");
/// App launches and quits (crankd's application usage).
pub const APP_USAGE: Namespace = Namespace::new("macos.app_usage");
/// Saved document versions.
pub const DOCUMENT_VERSIONS: Namespace = Namespace::new("macos.document_versions");
/// Notes.
pub const NOTES: Namespace = Namespace::new("macos.notes");
/// Notification Center notifications.
pub const NOTIFICATIONS: Namespace = Namespace::new("macos.notifications");
/// Terms searched for with Spotlight and the items opened from them.
pub const SPOTLIGHT_SEARCHES: Namespace = Namespace::new("macos.spotlight_searches");
/// Spotlight's stores on a volume and the paths it doesn't index.
pub const SPOTLIGHT_VOLUME: Namespace = Namespace::new("macos.spotlight_volume");
/// iMessage and SMS messages.
pub const MESSAGES: Namespace = Namespace::new("macos.messages");
/// Keychain items, without their secrets.
pub const KEYCHAIN: Namespace = Namespace::new("macos.keychain");
/// Lines of Wi-Fi's log (`wifi.log`).
pub const WIFI_LOG: Namespace = Namespace::new("macos.wifi_log");
/// Lines of launchd's log (`launchd.log`).
pub const LAUNCHD_LOG: Namespace = Namespace::new("macos.launchd_log");
/// Dates in property lists no named artifact reads, one per key.
pub const PLIST: Namespace = Namespace::new("macos.plist");

/// Whether a file starts as a property list does: `bplist00`, or XML (after
/// a UTF-8 byte order mark and blank space) that names a `plist` early.
fn is_plist(head: &[u8]) -> bool {
    if head.starts_with(b"bplist00") {
        return true;
    }
    let text = head.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(head);
    text.trim_ascii_start().starts_with(b"<") && text.windows(6).any(|w| w == b"<plist")
}

fn pref_namespace(kind: PrefKind) -> Namespace {
    match kind {
        PrefKind::InstallHistory => INSTALL_HISTORY,
        PrefKind::SoftwareUpdate => SOFTWARE_UPDATE,
        PrefKind::Airport => WIFI,
        PrefKind::Bluetooth => BLUETOOTH,
        PrefKind::AppleAccount => APPLE_ACCOUNTS,
        PrefKind::LoginItems => LOGIN_ITEMS,
        PrefKind::LoginWindow => LOGIN_WINDOW,
        PrefKind::User => USERS,
        PrefKind::StartupItem => STARTUP_ITEMS,
        PrefKind::TimeMachine => TIME_MACHINE,
        PrefKind::SpotlightShortcuts => SPOTLIGHT_SEARCHES,
        PrefKind::SpotlightVolume => SPOTLIGHT_VOLUME,
    }
}

/// One record per quarantine event, TCC entry or KnowledgeC event.
#[derive(Debug, Default, Clone, Copy)]
pub struct MacosAdapter;

impl Adapter for MacosAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "macos",
            version: macos::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[
            QUARANTINE,
            TCC,
            KNOWLEDGEC,
            LAUNCHD,
            FSEVENTS,
            LOGIN_ITEMS,
            INSTALL_HISTORY,
            SOFTWARE_UPDATE,
            WIFI,
            BLUETOOTH,
            APPLE_ACCOUNTS,
            LOGIN_WINDOW,
            USERS,
            STARTUP_ITEMS,
            TIME_MACHINE,
            ASL,
            APP_USAGE,
            DOCUMENT_VERSIONS,
            NOTES,
            NOTIFICATIONS,
            SPOTLIGHT_SEARCHES,
            SPOTLIGHT_VOLUME,
            MESSAGES,
            KEYCHAIN,
            WIFI_LOG,
            LAUNCHD_LOG,
            PLIST,
        ]
    }

    /// By name, and the SQLite signature (a property list's for launchd
    /// jobs and login items, gzip's or a page's for FSEvents, `kych` for
    /// keychains; for text logs, a first line that reads as one of theirs).
    /// Any other property list, by its signature, maybe: an adapter sure
    /// of it reads it instead.
    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        let signed = match macos::detect(name) {
            Some(Artifact::Launchd(_) | Artifact::Prefs(_)) => {
                head.starts_with(b"bplist") || head.trim_ascii_start().starts_with(b"<")
            }
            Some(Artifact::BackgroundItems) => head.starts_with(b"bplist"),
            Some(Artifact::Asl) => macos::is_asl(head),
            Some(Artifact::Keychain) => head.starts_with(b"kych"),
            Some(artifact @ (Artifact::WifiLog | Artifact::LaunchdLog)) => {
                logs::starts_like(artifact, head)
            }
            Some(Artifact::FsEvents) => {
                head.starts_with(&[0x1f, 0x8b]) || head.get(1..4) == Some(b"SLD")
            }
            Some(_) => head.starts_with(b"SQLite format 3\0"),
            None if is_plist(head) => return Confidence::Maybe,
            None => false,
        };
        if signed {
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
        let failed = |e: macos::Error| ParseError::at(0, e.0);
        let owner = profile_owner(input.name);
        let mut emit = |problems: Vec<String>, records: Vec<Record>| {
            for reason in problems {
                sink.skipped(Skipped {
                    locator: Locator::ByteOffset(0),
                    reason,
                });
            }
            for record in records {
                sink.record(record);
            }
        };
        match macos::detect(input.name) {
            Some(Artifact::QuarantineEvents) => {
                let parsed = macos::read_quarantine(input.data, log).map_err(failed)?;
                let records = parsed
                    .events
                    .iter()
                    .map(|event| self.quarantine(input, event, owner.as_deref()))
                    .collect();
                emit(parsed.problems, records);
            }
            Some(Artifact::Tcc(scope)) => {
                let parsed = macos::read_tcc(input.data, log).map_err(failed)?;
                let owner = (scope == Scope::User).then_some(owner).flatten();
                let records = parsed
                    .entries
                    .iter()
                    .map(|entry| self.tcc(input, entry, scope, owner.as_deref()))
                    .collect();
                emit(parsed.problems, records);
            }
            Some(Artifact::KnowledgeC(scope)) => {
                let parsed = macos::read_knowledgec(input.data, log).map_err(failed)?;
                let owner = (scope == Scope::User).then_some(owner).flatten();
                let records = parsed
                    .events
                    .iter()
                    .map(|event| self.knowledge(input, event, owner.as_deref()))
                    .collect();
                emit(parsed.problems, records);
            }
            Some(Artifact::Launchd(kind)) => {
                let read = macos::read_launchd(input.data, input.name).map_err(failed)?;
                let record = self.launchd(input, &read.job, kind, owner.as_deref());
                emit(read.problems, vec![record]);
            }
            Some(Artifact::FsEvents) => {
                let parsed = macos::read_fsevents(input.data);
                let records = (0u64..)
                    .zip(&parsed.events)
                    .map(|(index, event)| self.fsevent(input, index, event))
                    .collect();
                emit(parsed.problems, records);
            }
            Some(Artifact::BackgroundItems) => {
                let parsed = macos::read_background_items(input.data);
                let records = (0u64..)
                    .zip(&parsed.items)
                    .map(|(index, item)| self.login_item(input, index, item, owner.as_deref()))
                    .collect();
                emit(parsed.problems, records);
            }
            Some(Artifact::Prefs(kind)) => {
                let parsed = macos::read_prefs(kind, input.data);
                let records = (0u64..)
                    .zip(&parsed.entries)
                    .map(|(index, entry)| self.pref(input, kind, index, entry, owner.as_deref()))
                    .collect();
                emit(parsed.problems, records);
            }
            Some(
                artifact @ (Artifact::AppUsage
                | Artifact::DocumentVersions
                | Artifact::Notes
                | Artifact::Notifications),
            ) => {
                let (problems, records) = self.usage(artifact, input, log).map_err(failed)?;
                emit(problems, records);
            }
            Some(artifact @ (Artifact::Messages | Artifact::Keychain)) => {
                let (problems, records) = self
                    .personal(artifact, input, log, owner.as_deref())
                    .map_err(failed)?;
                emit(problems, records);
            }
            Some(artifact @ (Artifact::Asl | Artifact::WifiLog | Artifact::LaunchdLog)) => {
                let (problems, records) = self.logs(artifact, input);
                emit(problems, records);
            }
            None => {
                let (problems, records) = self
                    .plist_dates(input, owner.as_deref())
                    .map_err(|e| ParseError::at(0, e.to_string()))?;
                emit(problems, records);
            }
        }
        Ok(())
    }
}

impl MacosAdapter {
    fn record(self, input: &Input<'_>, namespace: Namespace, table: &str, row: i64) -> Record {
        Record::new(
            input.evidence,
            namespace,
            Locator::TableRow {
                table: table.to_owned(),
                row: u64::try_from(row).unwrap_or_default(),
            },
            self.parser(),
        )
    }

    fn quarantine(self, input: &Input<'_>, event: &QuarantineEvent, owner: Option<&str>) -> Record {
        let mut record = self.record(input, QUARANTINE, "LSQuarantineEvent", event.rowid);
        if let Some(time) = event.time {
            record.times.push(RecordTime::new(
                TimeKind::Created,
                "LSQuarantineTimeStamp",
                time,
            ));
        }
        record.facets = Facets {
            user_name: owner.map(str::to_owned),
            ..Facets::default()
        };
        let mut fields = Fields::new();
        text(&mut fields, "Agent", event.agent_name.as_deref());
        text(
            &mut fields,
            "AgentBundleId",
            event.agent_bundle_id.as_deref(),
        );
        text(&mut fields, "DataUrl", event.data_url.as_deref());
        text(&mut fields, "OriginUrl", event.origin_url.as_deref());
        text(&mut fields, "OriginTitle", event.origin_title.as_deref());
        text(&mut fields, "SenderName", event.sender_name.as_deref());
        text(
            &mut fields,
            "SenderAddress",
            event.sender_address.as_deref(),
        );
        text(&mut fields, "EventId", Some(&event.id));
        if let Some(kind) = event.type_number {
            fields.insert("TypeNumber".into(), Value::Int(kind));
        }
        record.fields = fields;
        let agent = event.agent_name.as_deref().unwrap_or("an app");
        let url = event
            .data_url
            .as_deref()
            .or(event.origin_url.as_deref())
            .unwrap_or("?");
        record.summary = format!("Downloaded by {agent}: {url}");
        record
    }

    fn tcc(self, input: &Input<'_>, entry: &TccEntry, scope: Scope, owner: Option<&str>) -> Record {
        let mut record = self.record(input, TCC, "access", entry.rowid);
        for (time, name) in [
            (entry.last_modified, "last_modified"),
            (entry.last_reminded, "last_reminded"),
        ] {
            if let Some(time) = time {
                record
                    .times
                    .push(RecordTime::new(TimeKind::Modified, name, time));
            }
        }
        record.facets = Facets {
            user_name: owner.map(str::to_owned),
            process_path: Some(entry.client.clone()).filter(|c| c.starts_with('/')),
            ..Facets::default()
        };
        let authorization = entry.authorization.map(|a| format!("{a:?}").to_lowercase());
        let mut fields = Fields::new();
        text(&mut fields, "Service", Some(&entry.service));
        text(&mut fields, "Client", Some(&entry.client));
        text(&mut fields, "Authorization", authorization.as_deref());
        text(
            &mut fields,
            "Reason",
            entry.reason.map(|r| format!("{r:?}")).as_deref(),
        );
        text(
            &mut fields,
            "Scope",
            Some(&format!("{scope:?}").to_lowercase()),
        );
        text(
            &mut fields,
            "IndirectObject",
            entry.indirect_object.as_deref(),
        );
        record.fields = fields;
        let service = entry
            .service
            .strip_prefix("kTCCService")
            .unwrap_or(&entry.service);
        record.summary = format!(
            "{} {} for {service}",
            entry.client,
            authorization.as_deref().unwrap_or("recorded")
        );
        record
    }

    fn knowledge(self, input: &Input<'_>, event: &KnowledgeEvent, owner: Option<&str>) -> Record {
        let mut record = self.record(input, KNOWLEDGEC, "ZOBJECT", event.rowid);
        for (time, kind, name) in [
            (event.start, TimeKind::FirstSeen, "ZSTARTDATE"),
            (event.end, TimeKind::LastSeen, "ZENDDATE"),
        ] {
            if let Some(time) = time {
                record.times.push(RecordTime::new(kind, name, time));
            }
        }
        record.facets = Facets {
            user_name: owner.map(str::to_owned),
            ..Facets::default()
        };
        let mut fields = Fields::new();
        text(&mut fields, "Stream", Some(&event.stream));
        text(&mut fields, "App", event.app());
        text(&mut fields, "Value", event.value_string.as_deref());
        text(&mut fields, "Title", event.title.as_deref());
        text(&mut fields, "ActivityType", event.activity_type.as_deref());
        text(&mut fields, "DeviceId", event.device_id.as_deref());
        if let Some(duration) = event.duration() {
            fields.insert("DurationSeconds".into(), Value::UInt(duration.as_secs()));
        }
        record.fields = fields;
        record.summary = match event.app().or(event.value_string.as_deref()) {
            Some(what) => format!("{} {what}", event.stream),
            None => event.stream.clone(),
        };
        record
    }
}

impl MacosAdapter {
    /// An Apple System Log message.
    fn asl(self, input: &Input<'_>, message: &AslRecord) -> Record {
        let mut record = Record::new(
            input.evidence,
            ASL,
            Locator::ByteOffset(message.offset),
            self.parser(),
        );
        if let Some(time) = message.time {
            record
                .times
                .push(RecordTime::new(TimeKind::Logged, "Time", time));
        }
        let mut fields = Fields::new();
        text(&mut fields, "Sender", message.sender.as_deref());
        text(&mut fields, "Facility", message.facility.as_deref());
        text(&mut fields, "Host", message.host.as_deref());
        text(&mut fields, "Message", message.message.as_deref());
        fields.insert("Level".into(), Value::UInt(u64::from(message.level)));
        fields.insert("Uid".into(), Value::Int(i64::from(message.uid)));
        fields.insert("Gid".into(), Value::Int(i64::from(message.gid)));
        for (key, value) in &message.extra {
            text(&mut fields, key, Some(value));
        }
        record.fields = fields;
        record.facets = Facets {
            host_name: message.host.clone(),
            process_id: Some(u64::from(message.pid)),
            ..Facets::default()
        };
        record.summary = format!(
            "{}: {}",
            message.sender.as_deref().unwrap_or("?"),
            message
                .message
                .as_deref()
                .unwrap_or_default()
                .chars()
                .take(200)
                .collect::<String>()
        );
        record
    }

    /// An entry of a property list: its times and values, the account
    /// whose home it is in.
    fn pref(
        self,
        input: &Input<'_>,
        kind: PrefKind,
        index: u64,
        entry: &PrefEntry,
        owner: Option<&str>,
    ) -> Record {
        let mut record = Record::new(
            input.evidence,
            pref_namespace(kind),
            Locator::TableRow {
                table: kind.name().to_owned(),
                row: index,
            },
            self.parser(),
        );
        for (name, time) in &entry.times {
            record
                .times
                .push(RecordTime::new(pref_time_kind(name), *name, *time));
        }
        let mut fields = Fields::new();
        for (name, value) in &entry.fields {
            fields.insert((*name).into(), Value::from(value.as_str()));
        }
        record.fields = fields;
        record.facets = Facets {
            user_name: match kind {
                PrefKind::User => entry.get("Name").map(str::to_owned),
                _ => owner.map(str::to_owned),
            },
            process_path: match kind {
                PrefKind::LoginItems => entry.get("TargetPath").map(str::to_owned),
                PrefKind::LoginWindow => entry.get("Path").map(str::to_owned),
                _ => None,
            },
            file_path: match kind {
                PrefKind::SpotlightShortcuts | PrefKind::SpotlightVolume => entry
                    .get("Path")
                    .or_else(|| entry.get("PartialPath"))
                    .map(str::to_owned),
                _ => None,
            },
            ..Facets::default()
        };
        let label = match kind {
            PrefKind::InstallHistory => "installed",
            PrefKind::SoftwareUpdate => "software update",
            PrefKind::Airport => "Wi-Fi network",
            PrefKind::Bluetooth => "Bluetooth device",
            PrefKind::AppleAccount => "Apple account",
            PrefKind::LoginItems => "login item",
            PrefKind::LoginWindow => entry.get("Kind").unwrap_or("login window"),
            PrefKind::User => "local account",
            PrefKind::StartupItem => "startup item",
            PrefKind::TimeMachine => "Time Machine destination",
            PrefKind::SpotlightShortcuts => "Spotlight search",
            PrefKind::SpotlightVolume => match entry.get("Kind") {
                Some("exclusion") => "Spotlight exclusion",
                _ => "Spotlight store",
            },
        };
        let detail = entry
            .get("Name")
            .filter(|name| *name != entry.subject)
            .map_or_else(String::new, |name| format!(" ({name})"));
        let target = match kind {
            PrefKind::SpotlightShortcuts => entry.get("Path"),
            PrefKind::SpotlightVolume => entry.get("PartialPath"),
            _ => None,
        }
        .map_or_else(String::new, |path| format!(" -> {path}"));
        record.summary = format!("macOS {label}: {}{detail}{target}", entry.subject);
        record
    }

    /// A change: no time of its own, the log's modification time bounds it.
    fn fsevent(self, input: &Input<'_>, index: u64, event: &FsEvent) -> Record {
        let mut record = Record::new(
            input.evidence,
            FSEVENTS,
            Locator::TableRow {
                table: "records".to_owned(),
                row: index,
            },
            self.parser(),
        );
        if let Some(modified) = input.modified {
            record
                .times
                .push(RecordTime::new(TimeKind::Other, "log_modified", modified));
        }
        let flags = event.flag_names();
        let mut fields = Fields::new();
        text(&mut fields, "Path", Some(&event.path));
        fields.insert("EventId".into(), Value::UInt(event.id));
        text(&mut fields, "Flags", Some(&flags.join("; ")));
        if let Some(node) = event.node {
            fields.insert("NodeId".into(), Value::UInt(node));
        }
        record.fields = fields;
        record.facets.file_path = Some(format!("/{}", event.path)).filter(|p| p.len() > 1);
        record.summary = format!("FSEvents {}: /{}", flags.join(", "), event.path);
        record
    }

    fn login_item(
        self,
        input: &Input<'_>,
        index: u64,
        item: &BackgroundItem,
        owner: Option<&str>,
    ) -> Record {
        let mut record = Record::new(
            input.evidence,
            LOGIN_ITEMS,
            Locator::TableRow {
                table: "items".to_owned(),
                row: index,
            },
            self.parser(),
        );
        for (kind, name, time) in [
            (TimeKind::Created, "TargetCreated", item.target_created),
            (TimeKind::Other, "VolumeCreated", item.volume_created),
        ] {
            if let Some(time) = time {
                record.times.push(RecordTime::new(kind, name, time));
            }
        }
        let mut fields = Fields::new();
        text(&mut fields, "Name", item.name.as_deref());
        text(&mut fields, "TargetPath", item.target_path.as_deref());
        text(&mut fields, "VolumeName", item.volume_name.as_deref());
        text(
            &mut fields,
            "VolumeMountPoint",
            item.volume_mount_point.as_deref(),
        );
        // macOS 13+ stores keep an item's record beside its bookmark, and
        // launch daemons there have no bookmark at all.
        let item_record = item.record.as_ref();
        if let Some(item_record) = item_record {
            item_record_fields(&mut fields, item_record);
        }
        let name = item
            .name
            .as_deref()
            .or(item_record.and_then(|r| r.name.as_deref()));
        let program = item
            .target_path
            .as_deref()
            .or(item_record.and_then(|r| r.executable_path.as_deref()));
        record.fields = fields;
        record.facets = Facets {
            user_name: owner.map(str::to_owned),
            process_path: program.map(str::to_owned),
            file_path: Some(input.name.to_owned()),
            ..Facets::default()
        };
        record.summary = format!(
            "login item {}: {}",
            name.unwrap_or("?"),
            program.unwrap_or("?")
        );
        record
    }

    fn launchd(
        self,
        input: &Input<'_>,
        job: &LaunchJob,
        kind: JobKind,
        owner: Option<&str>,
    ) -> Record {
        let mut record = Record::new(
            input.evidence,
            LAUNCHD,
            Locator::ByteOffset(0),
            self.parser(),
        );
        if let Some(modified) = input.modified {
            record.times.push(RecordTime::new(
                TimeKind::Modified,
                "file_modified",
                modified,
            ));
        }
        // An agent runs for the user whose home it's in, a daemon as its
        // UserName, else root.
        let runs_as = match kind {
            JobKind::Agent => owner.map(str::to_owned),
            JobKind::Daemon => Some(job.user_name.clone().unwrap_or_else(|| "root".to_owned())),
        };
        record.facets = Facets {
            user_name: runs_as,
            process_path: job.executable().map(str::to_owned),
            process_command_line: job.command_line(),
            file_path: Some(input.name.to_owned()),
            ..Facets::default()
        };
        let flags: Vec<&str> = job.flags().iter().map(|f| f.label()).collect();
        let kind_name = match kind {
            JobKind::Agent => "launch agent",
            JobKind::Daemon => "launch daemon",
        };
        let mut fields = Fields::new();
        text(&mut fields, "Kind", Some(kind_name));
        text(&mut fields, "Label", job.label.as_deref());
        text(&mut fields, "Flags", Some(&flags.join("; ")));
        text(
            &mut fields,
            "WatchPaths",
            Some(&job.triggers.watch_paths.join(", ")),
        );
        for (name, set) in [
            ("RunAtLoad", job.triggers.run_at_load),
            ("KeepAlive", job.triggers.keep_alive),
            ("Calendar", job.triggers.calendar),
            ("Disabled", job.disabled),
        ] {
            if set {
                fields.insert(name.into(), Value::Bool(true));
            }
        }
        if let Some(seconds) = job.triggers.start_interval {
            fields.insert("StartInterval".into(), Value::Int(seconds));
        }
        record.fields = fields;
        let label = job.label.as_deref().unwrap_or("unlabelled");
        let command = job.command_line().unwrap_or_else(|| "nothing".to_owned());
        record.summary = if flags.is_empty() {
            format!("{kind_name} {label}: {command}")
        } else {
            format!(
                "{kind_name} {label}: {command} (flags: {})",
                flags.join(", ")
            )
        };
        record
    }
}

/// The kind of a property list entry's time, by its name.
fn pref_time_kind(name: &str) -> TimeKind {
    match name {
        "Installed" | "Created" | "TargetCreated" | "Added" => TimeKind::Created,
        "PasswordLastSet" => TimeKind::Modified,
        "LastConnected" | "LastLogin" | "LastSuccessfulConnect" | "LastAutoJoin" | "LastUsed" => {
            TimeKind::LastSeen
        }
        _ => TimeKind::Other,
    }
}

fn text(fields: &mut Fields, name: &str, value: Option<&str>) {
    if let Some(value) = value.filter(|v| !v.is_empty()) {
        fields.insert(name.into(), Value::from(value));
    }
}

/// The fields of a macOS 13+ background item's record.
fn item_record_fields(fields: &mut Fields, item: &macos::ItemRecord) {
    text(fields, "ItemUser", Some(item.user.as_str()));
    for (name, value) in [
        ("ItemUuid", &item.uuid),
        ("ItemName", &item.name),
        ("Identifier", &item.identifier),
        ("Url", &item.url),
        ("ExecutablePath", &item.executable_path),
        ("BundleIdentifier", &item.bundle_identifier),
        ("TeamIdentifier", &item.team_identifier),
        ("DeveloperName", &item.developer_name),
        ("Container", &item.container),
    ] {
        text(fields, name, value.as_deref());
    }
    for (name, value) in [("ItemType", item.kind), ("Disposition", item.disposition)] {
        if let Some(value) = value {
            fields.insert(name.into(), Value::UInt(value));
        }
    }
}
