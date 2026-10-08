//! NTUSER.DAT and SOFTWARE: security zones, Explorer's Start menu caches,
//! Outlook's search stores, CCleaner's settings and the applications
//! Windows' memory leak diagnosis watched.

use common::time::Ts;
use model::{Facets, Fields, RecordTime, TimeKind, Value};
use registry::cleaners::{self, CCleaner, DiagnosedApplication};
use registry::office::{self, OutlookSearch};
use registry::programscache::{self, ProgramsCache};
use registry::zones::{self, Zone};
use registry::Hive;

use super::{Out, CCLEANER, DIAGNOSED_APPLICATIONS, OUTLOOK_SEARCH, PROGRAMS_CACHE, ZONES};

/// Zone settings that let content run without a prompt when `0`: ActiveX
/// unsigned, initialise and script unsafe ActiveX, launch programs and
/// unsafe files.
const RISKY_SETTINGS: [&str; 3] = ["1201", "1004", "1806"];

impl Out<'_, '_> {
    /// Zones, Start menu caches, Outlook's search, CCleaner and diagnosed
    /// applications.
    pub(super) fn apps(&mut self, hive: &Hive<'_>) {
        let found = zones::zones(hive);
        self.problems(found.problems);
        for zone in &found.entries {
            self.zone(zone);
        }
        let found = programscache::caches(hive);
        self.problems(found.problems);
        for cache in &found.entries {
            self.programs_cache(cache);
        }
        let found = office::outlook_search(hive);
        self.problems(found.problems);
        for search in &found.entries {
            self.outlook_search(search);
        }
        let found = cleaners::ccleaner(hive);
        self.problems(found.problems);
        for settings in &found.entries {
            self.ccleaner(settings);
        }
        let found = cleaners::diagnosed_applications(hive);
        self.problems(found.problems);
        for application in &found.entries {
            self.diagnosed(application);
        }
    }

    fn zone(&mut self, zone: &Zone) {
        let mut record = self.keyed(ZONES, &zone.key, None, zone.key_last_written);
        let mut fields = Fields::new();
        fields.insert("Zone".into(), Value::from(zone.zone.as_str()));
        if let Some(name) = zone.name {
            fields.insert("ZoneName".into(), Value::from(name));
        }
        fields.insert("Lockdown".into(), Value::Bool(zone.lockdown));
        fields.insert(
            "Scope".into(),
            Value::from(match (zone.user, zone.wow64) {
                (true, _) => "user",
                (false, true) => "machine (32-bit)",
                (false, false) => "machine",
            }),
        );
        for (name, value) in &zone.settings {
            fields.insert(format!("Setting{name}"), Value::from(value.as_str()));
        }
        let risky: Vec<&str> = zone
            .settings
            .iter()
            .filter(|(n, v)| RISKY_SETTINGS.contains(&n.as_str()) && v == "0")
            .map(|(n, _)| n.as_str())
            .collect();
        fields.insert("RiskyAllowed".into(), Value::Bool(!risky.is_empty()));
        record.fields = fields;
        record.summary = format!(
            "Security zone {} ({}){}",
            zone.zone,
            zone.name.unwrap_or("custom"),
            if risky.is_empty() {
                String::new()
            } else {
                format!(": allows {} without a prompt", risky.join(", "))
            }
        );
        self.sink.record(record);
    }

    fn programs_cache(&mut self, cache: &ProgramsCache) {
        let mut record = self.keyed(
            PROGRAMS_CACHE,
            &cache.key,
            Some(&cache.value),
            cache.key_last_written,
        );
        let shortcuts: Vec<String> = cache.entries.iter().map(|names| names.join("\\")).collect();
        let mut fields = Fields::new();
        fields.insert("Value".into(), Value::from(cache.value.as_str()));
        fields.insert("Version".into(), Value::UInt(u64::from(cache.version)));
        if let Some(folder) = &cache.known_folder {
            fields.insert("KnownFolder".into(), Value::from(folder.as_str()));
        }
        fields.insert(
            "Shortcuts".into(),
            Value::from(shortcuts.join("; ").as_str()),
        );
        record.fields = fields;
        record.summary = format!(
            "Start menu cache {}: {} shortcuts",
            cache.value,
            cache.entries.len()
        );
        self.sink.record(record);
    }

    fn outlook_search(&mut self, search: &OutlookSearch) {
        let mut record = self.keyed(OUTLOOK_SEARCH, &search.key, None, search.key_last_written);
        let stores: Vec<&str> = search.stores.iter().map(|(p, _)| p.as_str()).collect();
        let mut fields = Fields::new();
        fields.insert("Version".into(), Value::from(search.version.as_str()));
        fields.insert("Stores".into(), Value::from(stores.join("; ").as_str()));
        record.fields = fields;
        record.facets = Facets {
            file_path: stores.first().map(|s| (*s).to_owned()),
            ..Facets::default()
        };
        record.summary = format!("Outlook search indexed {}", stores.join(", "));
        self.sink.record(record);
    }

    fn ccleaner(&mut self, settings: &CCleaner) {
        let mut record = self.keyed(CCLEANER, &settings.key, None, settings.key_last_written);
        let mut fields = Fields::new();
        for (name, value) in &settings.settings {
            let key: String = name.chars().filter(char::is_ascii_alphanumeric).collect();
            fields.insert(key, Value::from(value.as_str()));
        }
        if let Some(update) = &settings.update_key {
            fields.insert("UpdateKey".into(), Value::from(update.as_str()));
        }
        let wiped: Vec<&str> = settings
            .settings
            .iter()
            .filter(|(n, v)| n.starts_with("(App)") && v.eq_ignore_ascii_case("True"))
            .map(|(n, _)| n.trim_start_matches("(App)"))
            .collect();
        fields.insert("Wipes".into(), Value::from(wiped.join(", ").as_str()));
        record.fields = fields;
        record.summary = format!("CCleaner set to wipe {}", wiped.join(", "));
        self.sink.record(record);
    }

    fn diagnosed(&mut self, application: &DiagnosedApplication) {
        let mut record = self.keyed(
            DIAGNOSED_APPLICATIONS,
            &application.key,
            None,
            application.key_last_written,
        );
        if let Some(time) = application.last_detection {
            record.times.push(RecordTime::new(
                TimeKind::Executed,
                "LastDetectionTime",
                Ts::from_filetime(time),
            ));
        }
        record
            .fields
            .insert("Program".into(), Value::from(application.program.as_str()));
        record.facets = Facets {
            process_path: Some(application.program.clone()),
            ..Facets::default()
        };
        record.summary = format!("Diagnosed application {}", application.program);
        self.sink.record(record);
    }
}
