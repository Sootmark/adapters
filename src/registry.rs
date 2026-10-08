//! Registry hives, via the `registry` parser: the artifacts first-hour
//! questions need. SYSTEM: ShimCache and services (of the current control
//! set). NTUSER.DAT: UserAssist. SOFTWARE and NTUSER.DAT: Run and RunOnce.
//! UsrClass.dat and NTUSER.DAT: ShellBags. Amcache.hve: every entry (files
//! with their SHA-1, programs, shortcuts, drivers, devices). SYSTEM, every
//! control set: BAM and DAM (per user, programs and their last run).
//!
//! The incident-response artifacts, each in its own namespace (submodules
//! below): SYSTEM, the current control set: USB devices and
//! `MountedDevices`. NTUSER.DAT: outbound Remote Desktop history and the
//! `RecentDocs`, `RunMRU`, `TypedPaths` and `WordWheelQuery` lists.
//! SOFTWARE: network profiles and scheduled tasks. SOFTWARE and NTUSER.DAT:
//! persistence keys (each flagged when it departs from Windows' default)
//! and installed programs. SYSTEM and SOFTWARE: what the machine is (name,
//! time zone, last shutdown, Windows version) and its user profiles.
//!
//! And every key of every hive, the named artifacts' keys included, in its
//! own namespace: its path under the root Windows mounts the hive at, its
//! last write and its values, as plaso's `winreg_default` plugin writes
//! them (`registry/keys.rs`).
//!
//! Damage the parser met is reported as skipped, located by key and value.
//!
//! A dirty hive (an interrupted write, its latest changes still in
//! `.LOG1`/`.LOG2`) is read as it is and reported as skipped, so the gap is
//! never silent.

mod accounts;
mod activity;
mod apps;
mod devices;
mod identity;
mod keys;
mod network;
mod persistence;
mod programs;
mod tasks;
mod user;

use std::path::Path;

use common::time::{Precision, Ts};
use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};
use std::collections::HashMap;

use registry::amcache::{self, Class};
use registry::{bam, shellbags, shimcache, userassist, Data, Hive, Key, Problem, SystemTime};

/// ShimCache entries.
pub const SHIMCACHE: Namespace = Namespace::new("windows.registry.shimcache");
/// UserAssist entries.
pub const USERASSIST: Namespace = Namespace::new("windows.registry.userassist");
/// Run and RunOnce values.
pub const RUN: Namespace = Namespace::new("windows.registry.run");
/// Services.
pub const SERVICES: Namespace = Namespace::new("windows.registry.services");
/// ShellBags: folders opened in Explorer.
pub const SHELLBAGS: Namespace = Namespace::new("windows.registry.shellbags");
/// BAM and DAM entries: programs each user ran, and when last.
pub const BAM: Namespace = Namespace::new("windows.registry.bam");
/// Amcache file entries.
pub const AMCACHE_FILE: Namespace = Namespace::new("windows.registry.amcache.file");
/// Amcache program entries.
pub const AMCACHE_PROGRAM: Namespace = Namespace::new("windows.registry.amcache.program");
/// Amcache shortcut entries.
pub const AMCACHE_SHORTCUT: Namespace = Namespace::new("windows.registry.amcache.shortcut");
/// Amcache driver binaries.
pub const AMCACHE_DRIVER_BINARY: Namespace =
    Namespace::new("windows.registry.amcache.driver_binary");
/// Amcache driver packages.
pub const AMCACHE_DRIVER_PACKAGE: Namespace =
    Namespace::new("windows.registry.amcache.driver_package");
/// Amcache Plug and Play devices.
pub const AMCACHE_DEVICE_PNP: Namespace = Namespace::new("windows.registry.amcache.device_pnp");
/// Amcache device containers.
pub const AMCACHE_DEVICE_CONTAINER: Namespace =
    Namespace::new("windows.registry.amcache.device_container");

/// USB devices (USBSTOR and USB instances).
pub const USB: Namespace = Namespace::new("windows.registry.usb");
/// `MountedDevices`: drive letters and volumes, and what they're bound to.
pub const MOUNTED_DEVICES: Namespace = Namespace::new("windows.registry.mounted_devices");
/// Outbound Remote Desktop connections.
pub const RDP: Namespace = Namespace::new("windows.registry.rdp");
/// `RecentDocs`: files and folders opened from Explorer.
pub const RECENT_DOCS: Namespace = Namespace::new("windows.registry.recentdocs");
/// `RunMRU`: Run dialog commands.
pub const RUN_MRU: Namespace = Namespace::new("windows.registry.runmru");
/// `TypedPaths`: paths typed in Explorer.
pub const TYPED_PATHS: Namespace = Namespace::new("windows.registry.typedpaths");
/// `WordWheelQuery`: Explorer searches.
pub const WORD_WHEEL_QUERY: Namespace = Namespace::new("windows.registry.wordwheelquery");
/// `TypedURLs`: addresses typed in Internet Explorer.
pub const TYPED_URLS: Namespace = Namespace::new("windows.registry.typedurls");
/// WinRAR's archive and extraction folder history.
pub const WINRAR: Namespace = Namespace::new("windows.registry.winrar");
/// `MountPoints2`: drives, volumes and shares a user's Explorer saw.
pub const MOUNT_POINTS: Namespace = Namespace::new("windows.registry.mountpoints2");
/// Network drives mapped to a letter.
pub const NETWORK_DRIVES: Namespace = Namespace::new("windows.registry.network_drives");
/// Office's recently opened documents and folders.
pub const OFFICE_MRU: Namespace = Namespace::new("windows.registry.office_mru");
/// Office trust records: documents trusted, macros enabled.
pub const TRUST_RECORDS: Namespace = Namespace::new("windows.registry.trust_records");
/// Network profiles.
pub const NETWORKS: Namespace = Namespace::new("windows.registry.networks");
/// Scheduled tasks from the Task Scheduler's cache.
pub const TASKS: Namespace = Namespace::new("windows.registry.tasks");
/// Persistence keys beyond Run and RunOnce.
pub const PERSISTENCE: Namespace = Namespace::new("windows.registry.persistence");
/// Installed programs (`Uninstall` keys).
pub const PROGRAMS: Namespace = Namespace::new("windows.registry.programs");
/// What the machine is: name, time zone, last shutdown, Windows version.
pub const SYSTEM: Namespace = Namespace::new("windows.registry.system");
/// User profiles (`ProfileList`).
pub const PROFILES: Namespace = Namespace::new("windows.registry.profiles");
/// SAM: local accounts.
pub const SAM_USERS: Namespace = Namespace::new("windows.registry.sam_users");
/// SAM: local groups' members.
pub const SAM_GROUPS: Namespace = Namespace::new("windows.registry.sam_groups");
/// Security zone settings (NTUSER.DAT, SOFTWARE).
pub const ZONES: Namespace = Namespace::new("windows.registry.zones");
/// Explorer's Start menu and taskbar caches (NTUSER.DAT).
pub const PROGRAMS_CACHE: Namespace = Namespace::new("windows.registry.programscache");
/// Outlook's search stores (NTUSER.DAT).
pub const OUTLOOK_SEARCH: Namespace = Namespace::new("windows.registry.outlook_search");
/// CCleaner's settings (NTUSER.DAT).
pub const CCLEANER: Namespace = Namespace::new("windows.registry.ccleaner");
/// Applications Windows' memory leak diagnosis watched (SOFTWARE).
pub const DIAGNOSED_APPLICATIONS: Namespace =
    Namespace::new("windows.registry.diagnosed_applications");
/// Every key of any hive, with its values, as plaso's `winreg_default`
/// reads it.
pub const KEYS: Namespace = Namespace::new("windows.registry.key");

fn amcache_namespace(class: Class) -> Namespace {
    match class {
        Class::File => AMCACHE_FILE,
        Class::Program => AMCACHE_PROGRAM,
        Class::Shortcut => AMCACHE_SHORTCUT,
        Class::DriverBinary => AMCACHE_DRIVER_BINARY,
        Class::DriverPackage => AMCACHE_DRIVER_PACKAGE,
        Class::DevicePnp => AMCACHE_DEVICE_PNP,
        Class::DeviceContainer => AMCACHE_DEVICE_CONTAINER,
    }
}

const RUN_KEYS: &[&str] = &[
    r"Microsoft\Windows\CurrentVersion\Run",
    r"Microsoft\Windows\CurrentVersion\RunOnce",
    r"Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
];
const USERASSIST_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";

/// Maps registry artifacts into Sootmark records, located by key path and
/// value name.
#[derive(Debug, Default, Clone, Copy)]
pub struct RegistryAdapter;

impl Adapter for RegistryAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "registry",
            version: registry::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[
            SHIMCACHE,
            USERASSIST,
            RUN,
            SERVICES,
            SHELLBAGS,
            BAM,
            AMCACHE_FILE,
            AMCACHE_PROGRAM,
            AMCACHE_SHORTCUT,
            AMCACHE_DRIVER_BINARY,
            AMCACHE_DRIVER_PACKAGE,
            AMCACHE_DEVICE_PNP,
            AMCACHE_DEVICE_CONTAINER,
            USB,
            MOUNTED_DEVICES,
            RDP,
            RECENT_DOCS,
            RUN_MRU,
            TYPED_PATHS,
            WORD_WHEEL_QUERY,
            TYPED_URLS,
            WINRAR,
            MOUNT_POINTS,
            NETWORK_DRIVES,
            OFFICE_MRU,
            TRUST_RECORDS,
            NETWORKS,
            TASKS,
            PERSISTENCE,
            PROGRAMS,
            SYSTEM,
            PROFILES,
            SAM_USERS,
            SAM_GROUPS,
            ZONES,
            PROGRAMS_CACHE,
            OUTLOOK_SEARCH,
            CCLEANER,
            DIAGNOSED_APPLICATIONS,
            KEYS,
        ]
    }

    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        let file = Path::new(name)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        let named = [
            "SYSTEM",
            "SOFTWARE",
            "NTUSER.DAT",
            "SAM",
            "SECURITY",
            "USRCLASS.DAT",
            "AMCACHE.HVE",
        ]
        .iter()
        .any(|n| file.eq_ignore_ascii_case(n));
        if head.starts_with(b"regf") {
            Confidence::Certain
        } else if named {
            Confidence::Maybe
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let hive =
            Hive::parse(input.data).map_err(|e| ParseError::at(e.offset as u64, e.reason))?;
        if hive.is_dirty() {
            sink.skipped(Skipped {
                locator: Locator::ByteOffset(0),
                reason: "dirty hive (an interrupted write): changes still in its .LOG1/.LOG2 aren't applied".to_owned(),
            });
        }
        let mut out = Out {
            adapter: *self,
            input,
            sink,
        };
        out.system(&hive);
        out.userassist(&hive);
        out.run_keys(&hive);
        out.shellbags(&hive);
        out.amcache(&hive);
        out.bam(&hive);
        out.devices(&hive);
        out.remote_desktop(&hive);
        out.recently_used(&hive);
        out.drives(&hive);
        out.office(&hive);
        out.networks(&hive);
        out.tasks(&hive);
        out.persistence(&hive);
        out.programs(&hive);
        out.identity(&hive);
        out.accounts(&hive);
        out.apps(&hive);
        out.keys(&hive);
        Ok(())
    }
}

struct Out<'a, 'i> {
    adapter: RegistryAdapter,
    input: &'a Input<'i>,
    sink: &'a mut dyn Sink,
}

fn text(key: &Key<'_>, name: &str) -> Option<String> {
    match key.value(name).ok()??.data() {
        Data::String(s) => Some(s),
        _ => None,
    }
}

fn dword(key: &Key<'_>, name: &str) -> Option<u32> {
    match key.value(name).ok()??.data() {
        Data::Dword(n) => Some(n),
        _ => None,
    }
}

fn start_type(start: u32) -> &'static str {
    match start {
        0 => "boot",
        1 => "system",
        2 => "automatic",
        3 => "manual",
        4 => "disabled",
        _ => "unknown",
    }
}

/// A wall-clock time (local, zone unknown) as a timestamp of `precision`.
fn local(time: SystemTime, precision: Precision) -> Option<Ts> {
    let ticks = Ts::from_filetime(time.wall_clock_filetime()?).ticks()?;
    Some(Ts::from_local_ticks(ticks, precision))
}

/// Text fields, those present.
fn insert_texts(fields: &mut Fields, texts: &[(&str, Option<&String>)]) {
    for (name, value) in texts {
        if let Some(value) = value {
            fields.insert((*name).to_owned(), Value::from(value.as_str()));
        }
    }
}

/// What an Amcache entry points at, and its summary.
fn amcache_description(entry: &amcache::Entry) -> (Option<&str>, String) {
    let get = |name| entry.get(name).unwrap_or_default();
    let (file_path, summary) = match entry.class {
        Class::File => {
            let path = entry.file_path().unwrap_or_default();
            let summary = match entry.sha1() {
                Some(sha1) => format!("Amcache file {path} (SHA-1 {sha1})"),
                None => format!("Amcache file {path}"),
            };
            (entry.file_path(), summary)
        }
        Class::Program => (
            entry.get("RootDirPath"),
            format!("Amcache program {} {}", get("Name"), get("Version")),
        ),
        Class::Shortcut => (
            entry.get("ShortcutPath"),
            format!("Amcache shortcut {}", get("ShortcutPath")),
        ),
        Class::DriverBinary => (
            entry.get("DriverName"),
            format!("Amcache driver {}", entry.key),
        ),
        Class::DriverPackage => (None, format!("Amcache driver package {}", entry.key)),
        Class::DevicePnp => (
            None,
            format!(
                "Amcache device {}",
                entry.get("Description").unwrap_or(&entry.key)
            ),
        ),
        Class::DeviceContainer => (
            None,
            format!(
                "Amcache device container {}",
                entry
                    .get("FriendlyName")
                    .or_else(|| entry.get("ModelName"))
                    .unwrap_or(&entry.key)
            ),
        ),
    };
    (file_path, summary.trim_end().to_owned())
}

impl Out<'_, '_> {
    fn record(&self, namespace: Namespace, key: &str, value: Option<String>) -> Record {
        Record::new(
            self.input.evidence,
            namespace,
            Locator::Registry {
                key: key.to_owned(),
                value,
            },
            self.adapter.parser(),
        )
    }

    /// A record located at `key` (and `value`), with its key's last write.
    fn keyed(&self, namespace: Namespace, key: &str, value: Option<&str>, written: u64) -> Record {
        let mut record = self.record(namespace, key, value.map(str::to_owned));
        record.times.push(RecordTime::new(
            TimeKind::Modified,
            "KeyLastWritten",
            Ts::from_filetime(written),
        ));
        record
    }

    /// The parser's problems, as skipped.
    fn problems(&mut self, problems: Vec<Problem>) {
        for problem in problems {
            self.skip(&problem.key, problem.value.as_deref(), problem.reason);
        }
    }

    fn skip(&mut self, key: &str, value: Option<&str>, reason: String) {
        self.sink.skipped(Skipped {
            locator: Locator::Registry {
                key: key.to_owned(),
                value: value.map(str::to_owned),
            },
            reason,
        });
    }

    /// SYSTEM: the current control set's ShimCache and services.
    fn system(&mut self, hive: &Hive<'_>) {
        let Ok(Some(set)) = hive.current_control_set() else {
            return;
        };
        let cache_key = format!(r"{set}\Control\Session Manager\AppCompatCache");
        if let Ok(Some(key)) = hive.open(&cache_key) {
            match key.value("AppCompatCache") {
                Ok(Some(value)) => match shimcache::parse(&value.bytes) {
                    Ok((format, entries)) => {
                        for entry in entries {
                            self.shimcache(&cache_key, &set, format, &entry);
                        }
                    }
                    Err(e) => self.skip(&cache_key, Some("AppCompatCache"), e.to_string()),
                },
                Ok(None) => {}
                Err(e) => self.skip(&cache_key, Some("AppCompatCache"), e.to_string()),
            }
        }
        let services_key = format!(r"{set}\Services");
        match hive.open(&services_key) {
            Ok(Some(services)) => match services.subkeys() {
                Ok(list) => {
                    for service in list {
                        self.service(&services_key, &service);
                    }
                }
                Err(e) => self.skip(&services_key, None, e.to_string()),
            },
            Ok(None) => {}
            Err(e) => self.skip(&services_key, None, e.to_string()),
        }
    }

    fn shimcache(
        &mut self,
        key: &str,
        set: &str,
        format: shimcache::Format,
        entry: &shimcache::Entry,
    ) {
        let mut record = self.record(
            SHIMCACHE,
            key,
            Some(format!("AppCompatCache[{}]", entry.position)),
        );
        if entry.last_modified != 0 {
            record.times.push(RecordTime::new(
                TimeKind::Modified,
                "LastModifiedTimeUTC",
                Ts::from_filetime(entry.last_modified),
            ));
        }
        record.facets = Facets {
            file_path: Some(entry.path.clone()),
            ..Facets::default()
        };
        let mut fields = Fields::new();
        fields.insert("Path".into(), Value::from(entry.path.as_str()));
        fields.insert("Position".into(), Value::UInt(entry.position as u64));
        fields.insert("ControlSet".into(), Value::from(set));
        fields.insert("Format".into(), Value::Text(format!("{format:?}")));
        if let Some(executed) = entry.executed {
            fields.insert("Executed".into(), Value::Bool(executed));
        }
        record.fields = fields;
        record.summary = format!("ShimCache {} (position {})", entry.path, entry.position);
        self.sink.record(record);
    }

    fn service(&mut self, parent: &str, service: &Key<'_>) {
        let path = format!(r"{parent}\{}", service.name);
        let image = text(service, "ImagePath");
        // The DLL an svchost service runs: under Parameters, or (older
        // services, EventLog) in the service key itself.
        let dll = service
            .subkey("Parameters")
            .ok()
            .flatten()
            .and_then(|p| text(&p, "ServiceDll"))
            .filter(|d| !d.is_empty())
            .or_else(|| text(service, "ServiceDll"));
        let start = dword(service, "Start");
        let mut record = self.record(SERVICES, &path, None);
        record.times.push(RecordTime::new(
            TimeKind::Modified,
            "KeyLastWritten",
            Ts::from_filetime(service.last_written),
        ));
        record.facets = Facets {
            service_name: Some(service.name.clone()),
            process_path: dll.clone().or_else(|| image.clone()),
            ..Facets::default()
        };
        let mut fields = Fields::new();
        for (name, value) in [
            ("ImagePath", image.clone()),
            ("ServiceDll", dll),
            ("DisplayName", text(service, "DisplayName")),
            ("ObjectName", text(service, "ObjectName")),
            ("Description", text(service, "Description")),
        ] {
            if let Some(value) = value {
                fields.insert(name.into(), Value::Text(value));
            }
        }
        if let Some(start) = start {
            fields.insert("Start".into(), Value::from(start_type(start)));
        }
        if let Some(kind) = dword(service, "Type") {
            fields.insert("Type".into(), Value::UInt(u64::from(kind)));
        }
        record.fields = fields;
        record.summary = format!(
            "Service {} · {} · {}",
            service.name,
            start.map_or("start unknown", start_type),
            image.as_deref().unwrap_or("no image path")
        );
        self.sink.record(record);
    }

    /// NTUSER.DAT: every UserAssist entry with counters.
    fn userassist(&mut self, hive: &Hive<'_>) {
        let Ok(Some(root)) = hive.open(USERASSIST_KEY) else {
            return;
        };
        let Ok(guids) = root.subkeys() else {
            self.skip(USERASSIST_KEY, None, "unreadable subkeys".to_owned());
            return;
        };
        for guid in guids {
            let Ok(Some(count)) = guid.subkey("Count") else {
                continue;
            };
            let key = format!(r"{USERASSIST_KEY}\{}\Count", guid.name);
            let Ok(values) = count.values() else {
                self.skip(&key, None, "unreadable values".to_owned());
                continue;
            };
            for value in values {
                let value = match value {
                    Ok(value) => value,
                    Err(e) => {
                        self.skip(&key, None, e.to_string());
                        continue;
                    }
                };
                // Session data and other records without counters.
                let Some(counts) = userassist::counts(&value.bytes) else {
                    continue;
                };
                let decoded = userassist::decode(&value.name);
                let path = userassist::path(&decoded);
                let mut record = self.record(USERASSIST, &key, Some(value.name.clone()));
                if counts.last_run != 0 {
                    record.times.push(RecordTime::new(
                        TimeKind::Executed,
                        "LastExecuted",
                        Ts::from_filetime(counts.last_run),
                    ));
                }
                record.facets = Facets {
                    process_path: Some(path.clone()),
                    ..Facets::default()
                };
                let mut fields = Fields::new();
                fields.insert("Name".into(), Value::Text(decoded));
                fields.insert("RunCount".into(), Value::UInt(u64::from(counts.run_count)));
                if let Some(n) = counts.focus_count {
                    fields.insert("FocusCount".into(), Value::UInt(u64::from(n)));
                }
                if let Some(ms) = counts.focus_ms {
                    fields.insert("FocusMs".into(), Value::UInt(u64::from(ms)));
                }
                fields.insert("Guid".into(), Value::from(guid.name.as_str()));
                record.fields = fields;
                record.summary = format!(
                    "UserAssist {path} · run {} {}",
                    counts.run_count,
                    if counts.run_count == 1 {
                        "time"
                    } else {
                        "times"
                    }
                );
                self.sink.record(record);
            }
        }
    }

    /// ShellBags: each folder opened, with its own times and, for the most
    /// recently opened in each folder, when (its key's last write).
    fn shellbags(&mut self, hive: &Hive<'_>) {
        let bags = match shellbags::bags(hive) {
            Ok(bags) => bags,
            Err(e) => {
                self.skip("BagMRU", None, e.to_string());
                return;
            }
        };
        for bag in bags {
            let item = &bag.item;
            let mut record = self.record(SHELLBAGS, &bag.bag_path, Some(bag.slot.to_string()));
            for (kind, field, time) in [
                (TimeKind::Created, "CreatedOn", item.created),
                (TimeKind::Modified, "ModifiedOn", item.modified),
                (TimeKind::Accessed, "AccessedOn", item.accessed),
            ] {
                if let Some(secs) = time {
                    record
                        .times
                        .push(RecordTime::new(kind, field, Ts::from_unix_seconds(secs)));
                }
            }
            if bag.mru_position == Some(0) {
                record.times.push(RecordTime::new(
                    TimeKind::LastSeen,
                    "LastInteracted",
                    Ts::from_filetime(bag.parent_written),
                ));
            }
            record.facets = Facets {
                file_path: Some(bag.path.clone()),
                ..Facets::default()
            };
            let mut fields = Fields::new();
            fields.insert("BagPath".into(), Value::from(bag.bag_path.as_str()));
            fields.insert("Slot".into(), Value::UInt(u64::from(bag.slot)));
            fields.insert("Name".into(), Value::from(item.name.as_str()));
            fields.insert("ShellType".into(), Value::Text(format!("{:?}", item.kind)));
            if let Some(position) = bag.mru_position {
                fields.insert("MRUPosition".into(), Value::UInt(position as u64));
            }
            if let Some(slot) = bag.node_slot {
                fields.insert("NodeSlot".into(), Value::UInt(u64::from(slot)));
            }
            if let Some((entry, sequence)) = item.mft {
                fields.insert("MFTEntry".into(), Value::UInt(entry));
                fields.insert("MFTSequenceNumber".into(), Value::UInt(u64::from(sequence)));
            }
            record.fields = fields;
            record.summary = format!("ShellBag {}", bag.path);
            self.sink.record(record);
        }
    }

    /// Run and RunOnce values, in SOFTWARE and NTUSER.DAT.
    fn run_keys(&mut self, hive: &Hive<'_>) {
        for path in RUN_KEYS {
            let Ok(Some(key)) = hive.open(path) else {
                continue;
            };
            let Ok(values) = key.values() else {
                self.skip(path, None, "unreadable values".to_owned());
                continue;
            };
            for value in values.into_iter().flatten() {
                let command = match value.data() {
                    Data::String(s) => s,
                    other => format!("{other:?}"),
                };
                let mut record = self.record(RUN, path, Some(value.name.clone()));
                record.times.push(RecordTime::new(
                    TimeKind::Modified,
                    "KeyLastWritten",
                    Ts::from_filetime(key.last_written),
                ));
                record.facets = Facets {
                    process_command_line: Some(command.clone()),
                    ..Facets::default()
                };
                let mut fields = Fields::new();
                fields.insert("Key".into(), Value::from(*path));
                fields.insert("Name".into(), Value::from(value.name.as_str()));
                fields.insert("Command".into(), Value::Text(command.clone()));
                record.fields = fields;
                record.summary = format!("Run {}: {command}", value.name);
                self.sink.record(record);
            }
        }
    }

    /// Amcache.hve: one record per entry, every value kept; files name the
    /// program they belong to.
    fn amcache(&mut self, hive: &Hive<'_>) {
        let cache = match amcache::read(hive) {
            Ok(Some(cache)) => cache,
            Ok(None) => return,
            Err(e) => {
                self.skip("Root", None, e.to_string());
                return;
            }
        };
        for problem in cache.problems {
            self.skip("Root", None, problem);
        }
        let programs: HashMap<&str, &str> = cache
            .entries
            .iter()
            .filter(|e| e.class == Class::Program)
            .filter_map(|e| Some((e.key.as_str(), e.get("Name")?)))
            .collect();
        for entry in &cache.entries {
            let application = entry.program_id().and_then(|id| programs.get(id).copied());
            let record = self.amcache_record(entry, application);
            self.sink.record(record);
        }
    }

    fn amcache_record(&self, entry: &amcache::Entry, application: Option<&str>) -> Record {
        let mut record = self.record(amcache_namespace(entry.class), &entry.path, None);
        record.times.push(RecordTime::new(
            TimeKind::Modified,
            "KeyLastWritten",
            Ts::from_filetime(entry.last_written),
        ));
        for (kind, field, time) in [
            (TimeKind::Other, "LinkDate", entry.link_date()),
            (TimeKind::Other, "InstallDate", entry.install_date()),
            (
                TimeKind::Other,
                "DriverTimeStamp",
                entry.unix_time("DriverTimeStamp"),
            ),
            (
                TimeKind::Modified,
                "FileModified",
                entry.filetime("FileModified"),
            ),
            (
                TimeKind::Created,
                "FileCreated",
                entry.filetime("FileCreated"),
            ),
            (
                TimeKind::Other,
                "EntryWritten",
                entry.filetime("EntryWritten"),
            ),
        ] {
            if let Some(time) = time {
                record
                    .times
                    .push(RecordTime::new(kind, field, Ts::from_filetime(time)));
            }
        }
        let mut fields = Fields::new();
        for (name, value) in &entry.values {
            if !value.is_empty() {
                fields.insert(name.clone(), Value::from(value.as_str()));
            }
        }
        if let Some(sha1) = entry.sha1() {
            fields.insert("SHA1".into(), Value::from(sha1));
        }
        if let Some(size) = entry.size() {
            fields.insert("Size".into(), Value::UInt(size));
        }
        if let Some(name) = application {
            fields.insert("ApplicationName".into(), Value::from(name));
        }
        fields.insert("KeyName".into(), Value::from(entry.key.as_str()));
        let (file_path, summary) = amcache_description(entry);
        record.facets = Facets {
            file_path: file_path.map(str::to_owned),
            service_name: entry.get("Service").map(str::to_owned),
            ..Facets::default()
        };
        record.fields = fields;
        record.summary = summary;
        record
    }

    /// BAM and DAM, in every control set: the last known good one keeps
    /// older runs than the current one.
    fn bam(&mut self, hive: &Hive<'_>) {
        let Ok(root) = hive.root() else {
            return;
        };
        let Ok(keys) = root.subkeys() else {
            return;
        };
        let control_sets = keys.into_iter().map(|k| k.name).filter(|name| {
            name.strip_prefix("ControlSet")
                .is_some_and(|n| n.len() == 3 && n.bytes().all(|b| b.is_ascii_digit()))
        });
        for set in control_sets {
            let entries = match bam::entries(hive, &set) {
                Ok(entries) => entries,
                Err(e) => {
                    self.skip(&set, None, e.to_string());
                    continue;
                }
            };
            for entry in entries {
                let mut record = self.record(BAM, &entry.key, Some(entry.program.clone()));
                if entry.last_run != 0 {
                    record.times.push(RecordTime::new(
                        TimeKind::Executed,
                        "LastRun",
                        Ts::from_filetime(entry.last_run),
                    ));
                }
                record.facets = Facets {
                    process_path: Some(entry.program.clone()),
                    user_sid: Some(entry.sid.clone()),
                    ..Facets::default()
                };
                let mut fields = Fields::new();
                fields.insert("Program".into(), Value::from(entry.program.as_str()));
                fields.insert("SID".into(), Value::from(entry.sid.as_str()));
                fields.insert("Service".into(), Value::from(entry.service));
                fields.insert("ControlSet".into(), Value::from(set.as_str()));
                record.fields = fields;
                record.summary = format!(
                    "{} {} ran (user {})",
                    entry.service.to_uppercase(),
                    entry.program,
                    entry.sid
                );
                self.sink.record(record);
            }
        }
    }
}
