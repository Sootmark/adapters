//! The Windows 10 Timeline (`ActivitiesCache.db`), via the `wintimeline`
//! parser, read with its write-ahead log when the caller hands it over:
//! one record per activity (an app in use, a file or page opened, clipboard
//! text), timed when it started and ended, with the app, what it opened and
//! for how long. Activities still waiting to upload are records too,
//! marked so.

use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};
use wintimeline::Activity;

use crate::home::profile_owner;

/// Records of Timeline databases.
pub const NAMESPACE: Namespace = Namespace::new("windows.timeline");

/// One record per activity and pending upload.
#[derive(Debug, Default, Clone, Copy)]
pub struct TimelineAdapter;

impl Adapter for TimelineAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "wintimeline",
            version: wintimeline::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[NAMESPACE]
    }

    /// By name, and the SQLite signature.
    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        if wintimeline::detect(name) && head.starts_with(b"SQLite format 3\0") {
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
        let timeline = wintimeline::read(input.data, log).map_err(|e| ParseError::at(0, e.0))?;
        for reason in timeline.problems {
            sink.skipped(Skipped {
                locator: Locator::ByteOffset(0),
                reason,
            });
        }
        let owner = profile_owner(input.name);
        for (table, activities) in [
            ("Activity", &timeline.activities),
            ("ActivityOperation", &timeline.operations),
        ] {
            for activity in activities {
                sink.record(self.record(input, table, activity, owner.as_deref()));
            }
        }
        Ok(())
    }
}

impl TimelineAdapter {
    fn record(
        self,
        input: &Input<'_>,
        table: &str,
        activity: &Activity,
        owner: Option<&str>,
    ) -> Record {
        let mut record = Record::new(
            input.evidence,
            NAMESPACE,
            Locator::TableRow {
                table: table.to_owned(),
                row: u64::try_from(activity.rowid).unwrap_or_default(),
            },
            self.parser(),
        );
        for (time, kind, name) in [
            (activity.start, TimeKind::FirstSeen, "StartTime"),
            (activity.end, TimeKind::LastSeen, "EndTime"),
        ] {
            if let Some(time) = time {
                record.times.push(RecordTime::new(kind, name, time));
            }
        }
        let app_path = activity.app_path();
        record.facets = Facets {
            user_name: owner.map(str::to_owned),
            process_path: app_path.clone().filter(|p| p.contains('\\')),
            file_path: activity.file_path(),
            ..Facets::default()
        };
        let kind = activity.activity_type.map(|t| format!("{t:?}"));
        let payload = &activity.payload;
        let mut fields = Fields::new();
        text(&mut fields, "App", activity.app());
        text(&mut fields, "Type", kind.as_deref());
        text(&mut fields, "DisplayText", payload.display_text.as_deref());
        text(&mut fields, "Description", payload.description.as_deref());
        text(&mut fields, "ContentUri", payload.content_uri.as_deref());
        text(
            &mut fields,
            "Clipboard",
            activity.clipboard_text().as_deref(),
        );
        text(
            &mut fields,
            "DeviceId",
            activity.platform_device_id.as_deref(),
        );
        if let Some(duration) = activity.duration() {
            fields.insert("DurationSeconds".into(), Value::UInt(duration.as_secs()));
        }
        if activity.is_pending_upload() {
            fields.insert("PendingUpload".into(), Value::Bool(true));
        }
        record.fields = fields;
        let app = activity.app().unwrap_or("an app");
        let what = payload
            .display_text
            .as_deref()
            .or(payload.content_uri.as_deref())
            .map(|w| format!(": {w}"))
            .unwrap_or_default();
        record.summary = format!("{} {app}{what}", kind.as_deref().unwrap_or("Activity"));
        record
    }
}

fn text(fields: &mut Fields, name: &str, value: Option<&str>) {
    if let Some(value) = value.filter(|v| !v.is_empty()) {
        fields.insert(name.into(), Value::from(value));
    }
}
