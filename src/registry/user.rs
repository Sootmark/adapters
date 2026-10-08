//! NTUSER.DAT: the drives a user mounted (`MountPoints2`, `Network`) and
//! Office's traces (recently opened documents, trusted documents and
//! their macros).

use common::time::Ts;
use model::{Facets, Fields, RecordTime, TimeKind, Value};
use registry::drives::{self, MountKind, MountPoint, NetworkDrive};
use registry::office::{self, MruItem, TrustRecord};
use registry::Hive;

use super::{insert_texts, Out, MOUNT_POINTS, NETWORK_DRIVES, OFFICE_MRU, TRUST_RECORDS};

impl Out<'_, '_> {
    /// Mount points and network drives.
    pub(super) fn drives(&mut self, hive: &Hive<'_>) {
        let points = drives::mount_points(hive);
        self.problems(points.problems);
        for point in &points.entries {
            self.mount_point(point);
        }
        let mapped = drives::network_drives(hive);
        self.problems(mapped.problems);
        for drive in &mapped.entries {
            self.network_drive(drive);
        }
    }

    fn mount_point(&mut self, point: &MountPoint) {
        let mut record = self.keyed(MOUNT_POINTS, &point.key, None, point.key_last_written);
        let mut fields = Fields::new();
        fields.insert("Name".into(), Value::from(point.name.as_str()));
        let (kind, summary) = match &point.kind {
            MountKind::Drive => ("drive", format!("Drive {} seen by Explorer", point.name)),
            MountKind::Volume => ("volume", format!("Volume {} seen by Explorer", point.name)),
            MountKind::Remote { server, share } => {
                fields.insert("Server".into(), Value::from(server.as_str()));
                fields.insert("Share".into(), Value::from(share.as_str()));
                record.facets.destination_ip = Some(server.clone());
                (
                    "share",
                    format!("Share \\\\{server}{share} seen by Explorer"),
                )
            }
        };
        fields.insert("Kind".into(), Value::from(kind));
        insert_texts(&mut fields, &[("Label", point.label.as_ref())]);
        record.fields = fields;
        record.summary = match &point.label {
            Some(label) => format!("{summary} ({label})"),
            None => summary,
        };
        self.sink.record(record);
    }

    fn network_drive(&mut self, drive: &NetworkDrive) {
        let mut record = self.keyed(NETWORK_DRIVES, &drive.key, None, drive.key_last_written);
        let mut fields = Fields::new();
        fields.insert("Letter".into(), Value::from(drive.letter.as_str()));
        insert_texts(
            &mut fields,
            &[
                ("RemotePath", drive.remote_path.as_ref()),
                ("Server", drive.server.as_ref()),
                ("Share", drive.share.as_ref()),
                ("UserName", drive.user_name.as_ref()),
                ("Provider", drive.provider.as_ref()),
            ],
        );
        record.fields = fields;
        record.facets = Facets {
            destination_ip: drive.server.clone(),
            user_name: drive.user_name.clone(),
            ..Facets::default()
        };
        record.summary = format!(
            "Network drive {}: mapped to {}",
            drive.letter,
            drive.remote_path.as_deref().unwrap_or("?")
        );
        self.sink.record(record);
    }

    /// Office's recently opened documents and folders, and trust records.
    pub(super) fn office(&mut self, hive: &Hive<'_>) {
        let items = office::mru(hive);
        self.problems(items.problems);
        for item in &items.entries {
            self.office_item(item);
        }
        let trusted = office::trust_records(hive);
        self.problems(trusted.problems);
        for record in &trusted.entries {
            self.trust_record(record);
        }
    }

    fn office_item(&mut self, item: &MruItem) {
        let mut record = self.record(OFFICE_MRU, &item.key, Some(item.value.clone()));
        if let Some(opened) = item.opened {
            record.times.push(RecordTime::new(
                TimeKind::Accessed,
                "Opened",
                Ts::from_filetime(opened),
            ));
        }
        let mut fields = Fields::new();
        for (name, value) in [
            ("Version", &item.version),
            ("Application", &item.application),
            ("List", &item.list),
            ("Path", &item.path),
        ] {
            fields.insert(name.into(), Value::from(value.as_str()));
        }
        insert_texts(&mut fields, &[("Account", item.account.as_ref())]);
        if let Some(position) = item.position {
            fields.insert("MRUPosition".into(), Value::UInt(position as u64));
        }
        record.fields = fields;
        record.facets.file_path = Some(item.path.clone());
        record.summary = format!("{} opened {}", item.application, item.path);
        self.sink.record(record);
    }

    fn trust_record(&mut self, trust: &TrustRecord) {
        let mut record = self.record(TRUST_RECORDS, &trust.key, Some(trust.path.clone()));
        if let Some(trusted) = trust.trusted {
            record.times.push(RecordTime::new(
                TimeKind::Other,
                "Trusted",
                Ts::from_filetime(trusted),
            ));
        }
        let mut fields = Fields::new();
        fields.insert("Version".into(), Value::from(trust.version.as_str()));
        fields.insert(
            "Application".into(),
            Value::from(trust.application.as_str()),
        );
        fields.insert("Path".into(), Value::from(trust.path.as_str()));
        fields.insert("MacrosEnabled".into(), Value::Bool(trust.macros_enabled));
        record.fields = fields;
        record.facets.file_path = Some(trust.path.clone());
        record.summary = if trust.macros_enabled {
            format!(
                "{} trusted {} and enabled its macros",
                trust.application, trust.path
            )
        } else {
            format!("{} trusted {} (editing)", trust.application, trust.path)
        };
        self.sink.record(record);
    }
}
