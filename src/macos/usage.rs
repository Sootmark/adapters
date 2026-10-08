//! Records of what was used and kept: app launches and quits, document
//! versions, notes and notifications.

use macos::{AppUse, DocumentVersion, Note, Notification};
use model::adapter::Input;
use model::{Facets, Fields, Record, RecordTime, TimeKind, Value};

use super::{text, MacosAdapter, APP_USAGE, DOCUMENT_VERSIONS, NOTES, NOTIFICATIONS};

/// The longest text kept in a summary.
const SUMMARY_TEXT: usize = 200;

impl MacosAdapter {
    pub(super) fn app_use(self, input: &Input<'_>, index: i64, used: &AppUse) -> Record {
        let mut record = self.record(input, APP_USAGE, "application_usage", index);
        if let Some(time) = used.last_time {
            record
                .times
                .push(RecordTime::new(TimeKind::Executed, "LastTime", time));
        }
        let mut fields = Fields::new();
        text(&mut fields, "Event", used.event.as_deref());
        text(&mut fields, "BundleId", used.bundle_id.as_deref());
        text(&mut fields, "Version", used.version.as_deref());
        text(&mut fields, "Path", used.path.as_deref());
        if let Some(count) = used.count {
            fields.insert("Count".into(), Value::Int(count));
        }
        record.fields = fields;
        record.facets = Facets {
            process_path: used.path.clone(),
            ..Facets::default()
        };
        record.summary = format!(
            "App {} {} ({} times)",
            used.event.as_deref().unwrap_or("used"),
            used.path
                .as_deref()
                .or(used.bundle_id.as_deref())
                .unwrap_or("?"),
            used.count.unwrap_or_default()
        );
        record
    }

    pub(super) fn document_version(
        self,
        input: &Input<'_>,
        index: i64,
        version: &DocumentVersion,
    ) -> Record {
        let mut record = self.record(input, DOCUMENT_VERSIONS, "generations", index);
        for (kind, name, time) in [
            (TimeKind::Created, "Saved", version.saved),
            (TimeKind::LastSeen, "LastSeen", version.last_seen),
        ] {
            if let Some(time) = time {
                record.times.push(RecordTime::new(kind, name, time));
            }
        }
        let mut fields = Fields::new();
        text(&mut fields, "Name", version.name.as_deref());
        text(&mut fields, "Path", version.path.as_deref());
        text(&mut fields, "VersionPath", Some(&version.version_path));
        text(&mut fields, "Client", version.client.as_deref());
        if let Some(uid) = version.uid {
            fields.insert("Uid".into(), Value::UInt(u64::from(uid)));
        }
        if let Some(size) = version.size {
            fields.insert("Size".into(), Value::Int(size));
        }
        record.fields = fields;
        record.facets = Facets {
            file_path: version.path.clone(),
            ..Facets::default()
        };
        record.summary = format!(
            "Document version of {} kept at {}",
            version
                .path
                .as_deref()
                .or(version.name.as_deref())
                .unwrap_or("?"),
            version.version_path
        );
        record
    }

    pub(super) fn note(self, input: &Input<'_>, index: i64, note: &Note) -> Record {
        let mut record = self.record(input, NOTES, "ZNOTE", index);
        for (kind, name, time) in [
            (TimeKind::Created, "Created", note.created),
            (TimeKind::Modified, "Edited", note.edited),
        ] {
            if let Some(time) = time {
                record.times.push(RecordTime::new(kind, name, time));
            }
        }
        let mut fields = Fields::new();
        text(&mut fields, "Title", note.title.as_deref());
        text(&mut fields, "Text", Some(&note.text));
        record.fields = fields;
        record.summary = format!(
            "Note {}: {}",
            note.title.as_deref().unwrap_or("?"),
            note.text.chars().take(SUMMARY_TEXT).collect::<String>()
        );
        record
    }

    pub(super) fn notification(
        self,
        input: &Input<'_>,
        index: i64,
        notification: &Notification,
    ) -> Record {
        let mut record = self.record(input, NOTIFICATIONS, "record", index);
        if let Some(time) = notification.delivered {
            record
                .times
                .push(RecordTime::new(TimeKind::Logged, "Delivered", time));
        }
        let mut fields = Fields::new();
        text(&mut fields, "App", notification.app.as_deref());
        text(&mut fields, "Title", notification.title.as_deref());
        text(&mut fields, "Subtitle", notification.subtitle.as_deref());
        text(&mut fields, "Body", notification.body.as_deref());
        if let Some(presented) = notification.presented {
            fields.insert("Presented".into(), Value::Bool(presented));
        }
        record.fields = fields;
        let words: Vec<&str> = [
            notification.title.as_deref(),
            notification.subtitle.as_deref(),
            notification.body.as_deref(),
        ]
        .into_iter()
        .flatten()
        .collect();
        record.summary = format!(
            "Notification from {}: {}",
            notification.app.as_deref().unwrap_or("?"),
            words
                .join(" - ")
                .chars()
                .take(SUMMARY_TEXT)
                .collect::<String>()
        );
        record
    }
}
