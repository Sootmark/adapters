//! Windows 10 and 11 notifications (`wpndatabase.db`, one per user), via
//! the `notifications` parser, read with the database's write-ahead log
//! when the caller hands it over: one record per notification (the app,
//! when it arrived and expires, the text the user saw and the payload as
//! the app wrote it), per app registered to notify and per push channel an
//! app opened; the user from the profile's path.

use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};
use notifications::{Handler, Notification, PushChannel};

use crate::home::profile_owner;
use crate::key::field_name;

/// Notifications.
pub const NOTIFICATIONS: Namespace = Namespace::new("windows.notifications");
/// Apps registered to notify.
pub const HANDLERS: Namespace = Namespace::new("windows.notification_handler");
/// Windows Push Notification Service channels.
pub const PUSH_CHANNELS: Namespace = Namespace::new("windows.wns_channel");

/// The longest text kept in a summary.
const SUMMARY_TEXT: usize = 200;

/// One record per notification, handler and push channel.
#[derive(Debug, Default, Clone, Copy)]
pub struct NotificationsAdapter;

impl Adapter for NotificationsAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "notifications",
            version: notifications::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[NOTIFICATIONS, HANDLERS, PUSH_CHANNELS]
    }

    /// By name (`wpndatabase.db`) and the SQLite signature.
    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        let named = name
            .rsplit(['/', '\\'])
            .next()
            .is_some_and(|n| n.eq_ignore_ascii_case("wpndatabase.db"));
        if named && head.starts_with(b"SQLite format 3\0") {
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
        let database = notifications::read(input.data, log).map_err(|e| ParseError::at(0, e.0))?;
        for reason in database.problems {
            sink.skipped(Skipped {
                locator: Locator::ByteOffset(0),
                reason,
            });
        }
        let owner = profile_owner(input.name);
        for notification in &database.notifications {
            sink.record(self.notification(input, notification, owner.as_deref()));
        }
        for handler in &database.handlers {
            sink.record(self.handler(input, handler, owner.as_deref()));
        }
        for (row, channel) in (0u64..).zip(&database.push_channels) {
            sink.record(self.push_channel(input, row, channel, owner.as_deref()));
        }
        Ok(())
    }
}

impl NotificationsAdapter {
    fn new_record(self, input: &Input<'_>, namespace: Namespace, table: &str, row: u64) -> Record {
        Record::new(
            input.evidence,
            namespace,
            Locator::TableRow {
                table: table.to_owned(),
                row,
            },
            self.parser(),
        )
    }

    fn notification(
        self,
        input: &Input<'_>,
        notification: &Notification,
        owner: Option<&str>,
    ) -> Record {
        let row = u64::try_from(notification.order).unwrap_or_default();
        let mut record = self.new_record(input, NOTIFICATIONS, "Notification", row);
        push_times(
            &mut record,
            &[
                (TimeKind::Logged, "ArrivalTime", notification.arrival),
                (TimeKind::Other, "ExpiryTime", notification.expiry),
                (TimeKind::Other, "BootId", notification.boot),
            ],
        );
        let mut fields = Fields::new();
        text(&mut fields, "App", notification.app.as_deref());
        text(&mut fields, "Type", Some(&notification.kind));
        if !notification.texts.is_empty() {
            text(&mut fields, "Text", Some(&notification.texts.join(" | ")));
        }
        text(&mut fields, "Tag", notification.tag.as_deref());
        text(&mut fields, "Group", notification.group.as_deref());
        text(
            &mut fields,
            "ActivityId",
            notification.activity_id.as_deref(),
        );
        text(&mut fields, "PayloadType", Some(&notification.payload_type));
        match notification.payload_text() {
            Some(payload) => text(&mut fields, "Payload", Some(payload)),
            None if !notification.payload.is_empty() => {
                fields.insert("Payload".into(), Value::Bytes(notification.payload.clone()));
            }
            None => {}
        }
        for (name, value) in [
            ("Id", notification.id),
            ("HandlerId", notification.handler_id),
        ] {
            if let Some(value) = value {
                fields.insert(name.into(), Value::Int(value));
            }
        }
        if let Some(flag) = notification.expires_on_reboot {
            fields.insert("ExpiresOnReboot".into(), Value::Bool(flag));
        }
        record.fields = fields;
        record.facets = Facets {
            user_name: owner.map(str::to_owned),
            ..Facets::default()
        };
        let words = notification.texts.join(" - ");
        record.summary = format!(
            "Notification ({}) from {}: {}",
            notification.kind,
            notification.app.as_deref().unwrap_or("?"),
            words.chars().take(SUMMARY_TEXT).collect::<String>()
        );
        record
    }

    fn handler(self, input: &Input<'_>, handler: &Handler, owner: Option<&str>) -> Record {
        let row = u64::try_from(handler.id).unwrap_or_default();
        let mut record = self.new_record(input, HANDLERS, "NotificationHandler", row);
        push_times(
            &mut record,
            &[
                (TimeKind::Created, "CreatedTime", handler.created),
                (TimeKind::Modified, "ModifiedTime", handler.modified),
            ],
        );
        let mut fields = Fields::new();
        for (key, value) in &handler.assets {
            text(
                &mut fields,
                &format!("Asset.{}", field_name(key)),
                Some(value),
            );
        }
        text(&mut fields, "AppId", Some(&handler.app_id));
        text(&mut fields, "HandlerType", handler.kind.as_deref());
        text(&mut fields, "WnsId", handler.wns_id.as_deref());
        text(&mut fields, "ParentId", handler.parent_id.as_deref());
        text(
            &mut fields,
            "ContainerSid",
            handler.container_sid.as_deref(),
        );
        text(&mut fields, "DisplayName", handler.asset("DisplayName"));
        if let Some(name) = handler.wnf_event_name {
            fields.insert("WnfEventName".into(), Value::Int(name));
        }
        record.fields = fields;
        record.facets = Facets {
            user_name: owner.map(str::to_owned),
            ..Facets::default()
        };
        record.summary = format!(
            "Notification handler {} ({})",
            handler.app_id,
            handler.kind.as_deref().unwrap_or("?")
        );
        record
    }

    fn push_channel(
        self,
        input: &Input<'_>,
        row: u64,
        channel: &PushChannel,
        owner: Option<&str>,
    ) -> Record {
        let mut record = self.new_record(input, PUSH_CHANNELS, "WNSPushChannel", row);
        push_times(
            &mut record,
            &[
                (TimeKind::Created, "CreatedTime", channel.created),
                (TimeKind::Other, "ExpiryTime", channel.expiry),
            ],
        );
        let mut fields = Fields::new();
        text(&mut fields, "ChannelId", Some(&channel.id));
        text(&mut fields, "App", channel.app.as_deref());
        text(&mut fields, "Uri", channel.uri.as_deref());
        if let Some(id) = channel.handler_id {
            fields.insert("HandlerId".into(), Value::Int(id));
        }
        record.fields = fields;
        record.facets = Facets {
            user_name: owner.map(str::to_owned),
            ..Facets::default()
        };
        record.summary = format!(
            "Push channel of {}: {}",
            channel.app.as_deref().unwrap_or("?"),
            channel.uri.as_deref().unwrap_or("?")
        );
        record
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
