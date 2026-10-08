//! SYSTEM and SOFTWARE: what the machine is, one record each for its name,
//! time zone, last shutdown, hardware and Windows version, and one per user
//! profile.

use common::time::Ts;
use model::{Facets, Fields, RecordTime, TimeKind, Value};
use registry::system::{self, Hardware, Profile, TimeZone, Version};
use registry::Hive;

use super::{insert_texts, Out, PROFILES, SYSTEM};

impl Out<'_, '_> {
    /// The machine's identity and its profiles.
    pub(super) fn identity(&mut self, hive: &Hive<'_>) {
        let mut found = system::identity(hive);
        self.problems(found.problems);
        let Some(identity) = found.entries.pop() else {
            return;
        };
        if let Some(name) = &identity.computer_name {
            let mut record = self.keyed(
                SYSTEM,
                &name.key,
                Some("ComputerName"),
                name.key_last_written,
            );
            record.facets = Facets {
                host_name: Some(name.name.clone()),
                ..Facets::default()
            };
            record
                .fields
                .insert("ComputerName".into(), Value::from(name.name.as_str()));
            record.summary = format!("Computer name {}", name.name);
            self.sink.record(record);
        }
        if let Some(zone) = &identity.time_zone {
            self.time_zone(zone);
        }
        if let Some(shutdown) = &identity.shutdown {
            let mut record = self.keyed(
                SYSTEM,
                &shutdown.key,
                Some("ShutdownTime"),
                shutdown.key_last_written,
            );
            let ts = Ts::from_filetime(shutdown.time);
            record
                .times
                .push(RecordTime::new(TimeKind::Other, "ShutdownTime", ts));
            record.fields.insert("ShutdownTime".into(), Value::Time(ts));
            record.summary = format!("Last clean shutdown {ts}");
            self.sink.record(record);
        }
        if let Some(version) = &identity.version {
            self.version(version);
        }
        if let Some(hardware) = &identity.hardware {
            self.hardware(hardware);
        }
        for profile in &identity.profiles {
            self.profile(profile);
        }
    }

    fn hardware(&mut self, hardware: &Hardware) {
        let mut record = self.keyed(SYSTEM, &hardware.key, None, hardware.key_last_written);
        let mut fields = Fields::new();
        insert_texts(
            &mut fields,
            &[
                ("SystemManufacturer", hardware.manufacturer.as_ref()),
                ("SystemProductName", hardware.model.as_ref()),
                ("BIOSVersion", hardware.bios_version.as_ref()),
                ("BIOSReleaseDate", hardware.bios_release_date.as_ref()),
            ],
        );
        record.fields = fields;
        record.summary = format!(
            "Hardware: {} {}, BIOS {} ({})",
            hardware.manufacturer.as_deref().unwrap_or("?"),
            hardware.model.as_deref().unwrap_or("?"),
            hardware.bios_version.as_deref().unwrap_or("?"),
            hardware.bios_release_date.as_deref().unwrap_or("?")
        );
        self.sink.record(record);
    }

    fn time_zone(&mut self, zone: &TimeZone) {
        let mut record = self.keyed(SYSTEM, &zone.key, None, zone.key_last_written);
        let mut fields = Fields::new();
        insert_texts(
            &mut fields,
            &[
                ("TimeZoneKeyName", zone.key_name.as_ref()),
                ("StandardName", zone.standard_name.as_ref()),
                ("DaylightName", zone.daylight_name.as_ref()),
            ],
        );
        for (name, bias) in [
            ("Bias", zone.bias),
            ("ActiveTimeBias", zone.active_time_bias),
            ("StandardBias", zone.standard_bias),
            ("DaylightBias", zone.daylight_bias),
        ] {
            if let Some(bias) = bias {
                fields.insert(name.into(), Value::Int(i64::from(bias)));
            }
        }
        if let Some(disabled) = zone.dynamic_daylight_disabled {
            fields.insert("DynamicDaylightTimeDisabled".into(), Value::Bool(disabled));
        }
        record.fields = fields;
        let name = zone
            .key_name
            .as_deref()
            .or(zone.standard_name.as_deref())
            .unwrap_or("unnamed");
        // UTC = local + bias, so local = UTC - bias.
        record.summary = match zone.active_time_bias {
            Some(bias) => {
                let offset = -bias;
                let sign = if offset < 0 { '-' } else { '+' };
                let offset = offset.unsigned_abs();
                format!(
                    "Time zone {name} (UTC{sign}{:02}:{:02} when written)",
                    offset / 60,
                    offset % 60
                )
            }
            None => format!("Time zone {name}"),
        };
        self.sink.record(record);
    }

    fn version(&mut self, version: &Version) {
        let mut record = self.keyed(SYSTEM, &version.key, None, version.key_last_written);
        if let Some(date) = version.install_date {
            record.times.push(RecordTime::new(
                TimeKind::Other,
                "InstallDate",
                Ts::from_unix_seconds(i64::from(date)),
            ));
        }
        if let Some(time) = version.install_time {
            record.times.push(RecordTime::new(
                TimeKind::Other,
                "InstallTime",
                Ts::from_filetime(time),
            ));
        }
        let mut fields = Fields::new();
        insert_texts(
            &mut fields,
            &[
                ("ProductName", version.product_name.as_ref()),
                ("EditionID", version.edition_id.as_ref()),
                ("DisplayVersion", version.display_version.as_ref()),
                ("CurrentVersion", version.current_version.as_ref()),
                ("CurrentBuild", version.current_build.as_ref()),
                ("CSDVersion", version.service_pack.as_ref()),
                ("RegisteredOwner", version.registered_owner.as_ref()),
                (
                    "RegisteredOrganization",
                    version.registered_organization.as_ref(),
                ),
                ("SystemRoot", version.system_root.as_ref()),
            ],
        );
        record.fields = fields;
        let product = version.product_name.as_deref().unwrap_or("Windows");
        record.summary = match (&version.display_version, &version.current_build) {
            (Some(display), Some(build)) => format!("{product} {display} (build {build})"),
            (None, Some(build)) => format!("{product} (build {build})"),
            _ => product.to_owned(),
        };
        self.sink.record(record);
    }

    fn profile(&mut self, profile: &Profile) {
        let mut record = self.keyed(PROFILES, &profile.key, None, profile.key_last_written);
        for (kind, field, time) in [
            (TimeKind::LastSeen, "LocalProfileLoadTime", profile.loaded),
            (
                TimeKind::LastSeen,
                "LocalProfileUnloadTime",
                profile.unloaded,
            ),
        ] {
            if let Some(time) = time {
                record
                    .times
                    .push(RecordTime::new(kind, field, Ts::from_filetime(time)));
            }
        }
        record.facets = Facets {
            user_sid: Some(profile.sid.clone()),
            file_path: profile.image_path.clone(),
            ..Facets::default()
        };
        let mut fields = Fields::new();
        fields.insert("SID".into(), Value::from(profile.sid.as_str()));
        insert_texts(
            &mut fields,
            &[("ProfileImagePath", profile.image_path.as_ref())],
        );
        if let Some(state) = profile.state {
            fields.insert("State".into(), Value::UInt(u64::from(state)));
        }
        record.fields = fields;
        record.summary = format!(
            "Profile {} · {}",
            profile.sid,
            profile.image_path.as_deref().unwrap_or("no folder")
        );
        self.sink.record(record);
    }
}
