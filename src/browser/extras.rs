//! Beyond history: cookies, form history, extensions (installed and their
//! activity) and the sites given permissions.

use browser::{
    AutofillEntry, ContentException, Cookie, CookieStore, ExtensionActivity, InstalledExtension,
    Rows,
};
use common::time::Ts;
use model::adapter::{Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, Record, RecordTime, TimeKind, Value};

use super::{
    text, BrowserAdapter, AUTOFILL, COOKIES, EXTENSIONS, EXTENSION_ACTIVITY, SITE_PERMISSIONS,
};

impl BrowserAdapter {
    fn extra(self, input: &Input<'_>, namespace: Namespace, table: &str, row: i64) -> Record {
        Record::new(
            input.evidence,
            namespace,
            Locator::TableRow {
                table: table.to_owned(),
                row: u64::try_from(row).unwrap_or_default(),
            },
            model::adapter::Adapter::parser(&self),
        )
    }

    pub(super) fn cookies(
        self,
        input: &Input<'_>,
        rows: &Rows<Cookie>,
        user: Option<&str>,
        sink: &mut dyn Sink,
    ) {
        report(sink, &rows.problems);
        for cookie in &rows.rows {
            let table = match cookie.store {
                CookieStore::Chromium => "cookies",
                CookieStore::Firefox => "moz_cookies",
            };
            let mut record = self.extra(input, COOKIES, table, cookie.rowid);
            for (kind, name, time) in [
                (TimeKind::Created, "Created", cookie.created),
                (TimeKind::LastSeen, "LastAccessed", cookie.last_accessed),
                (TimeKind::Other, "Expires", cookie.expires),
            ] {
                push(&mut record, kind, name, time);
            }
            let mut fields = Fields::new();
            text(&mut fields, "Host", Some(&cookie.host));
            text(&mut fields, "Name", Some(&cookie.name));
            text(&mut fields, "Value", Some(&cookie.value));
            text(&mut fields, "Path", Some(&cookie.path));
            fields.insert("Secure".into(), Value::Bool(cookie.secure));
            fields.insert("HttpOnly".into(), Value::Bool(cookie.http_only));
            record.fields = fields;
            record.facets = owner(user);
            record.summary = format!("Cookie {} for {}{}", cookie.name, cookie.host, cookie.path);
            sink.record(record);
        }
    }

    pub(super) fn autofill(
        self,
        input: &Input<'_>,
        rows: &Rows<AutofillEntry>,
        user: Option<&str>,
        sink: &mut dyn Sink,
    ) {
        report(sink, &rows.problems);
        for entry in &rows.rows {
            let mut record = self.extra(input, AUTOFILL, "autofill", entry.rowid);
            push(&mut record, TimeKind::Created, "Created", entry.created);
            push(&mut record, TimeKind::LastSeen, "LastUsed", entry.last_used);
            let mut fields = Fields::new();
            text(&mut fields, "Field", Some(&entry.field));
            text(&mut fields, "Value", Some(&entry.value));
            if let Some(count) = entry.count {
                fields.insert("Count".into(), Value::Int(count));
            }
            record.fields = fields;
            record.facets = owner(user);
            record.summary = format!("Typed in form field {}: {}", entry.field, entry.value);
            sink.record(record);
        }
    }

    pub(super) fn extension_activity(
        self,
        input: &Input<'_>,
        rows: &Rows<ExtensionActivity>,
        user: Option<&str>,
        sink: &mut dyn Sink,
    ) {
        report(sink, &rows.problems);
        for action in &rows.rows {
            let mut record = self.extra(
                input,
                EXTENSION_ACTIVITY,
                "activitylog_compressed",
                action.rowid,
            );
            push(&mut record, TimeKind::Logged, "Time", action.time);
            let mut fields = Fields::new();
            text(&mut fields, "ExtensionId", Some(&action.extension_id));
            for (name, value) in [
                ("ApiName", &action.api_name),
                ("Args", &action.args),
                ("PageUrl", &action.page_url),
                ("PageTitle", &action.page_title),
                ("ArgUrl", &action.arg_url),
                ("Other", &action.other),
            ] {
                text(&mut fields, name, value.as_deref());
            }
            if let Some(kind) = action.action_type {
                fields.insert("ActionType".into(), Value::Int(kind));
            }
            record.fields = fields;
            record.facets = owner(user);
            record.summary = format!(
                "Extension {} {}{}",
                action.extension_id,
                action.api_name.as_deref().unwrap_or("acted"),
                action
                    .page_url
                    .as_deref()
                    .map_or_else(String::new, |url| format!(" on {url}"))
            );
            sink.record(record);
        }
    }

    pub(super) fn preferences(
        self,
        input: &Input<'_>,
        user: Option<&str>,
        sink: &mut dyn Sink,
    ) -> Result<(), ParseError> {
        let preferences =
            browser::read_preferences(input.data).map_err(|e| ParseError::at(0, e.0))?;
        for (row, extension) in (0i64..).zip(&preferences.extensions) {
            sink.record(self.installed(input, row, extension, user));
        }
        for (row, exception) in (0i64..).zip(&preferences.content_exceptions) {
            sink.record(self.permission(input, row, exception, user));
        }
        Ok(())
    }

    fn installed(
        self,
        input: &Input<'_>,
        row: i64,
        extension: &InstalledExtension,
        user: Option<&str>,
    ) -> Record {
        let mut record = self.extra(input, EXTENSIONS, "extensions.settings", row);
        push(
            &mut record,
            TimeKind::Created,
            "Installed",
            extension.installed,
        );
        let mut fields = Fields::new();
        text(&mut fields, "ExtensionId", Some(&extension.id));
        text(&mut fields, "Name", extension.name.as_deref());
        text(&mut fields, "Version", extension.version.as_deref());
        text(&mut fields, "Path", extension.path.as_deref());
        for (name, value) in [
            ("FromWebStore", extension.from_webstore),
            ("ByDefault", extension.by_default),
        ] {
            if let Some(value) = value {
                fields.insert(name.into(), Value::Bool(value));
            }
        }
        if let Some(state) = extension.state {
            fields.insert("State".into(), Value::Int(state));
        }
        text(
            &mut fields,
            "Permissions",
            Some(&extension.permissions.join(", ")),
        );
        record.fields = fields;
        record.facets = owner(user);
        record.summary = format!(
            "Extension installed: {} ({})",
            extension.name.as_deref().unwrap_or("?"),
            extension.id
        );
        record
    }

    fn permission(
        self,
        input: &Input<'_>,
        row: i64,
        exception: &ContentException,
        user: Option<&str>,
    ) -> Record {
        let mut record = self.extra(input, SITE_PERMISSIONS, "content_settings", row);
        push(
            &mut record,
            TimeKind::LastSeen,
            "LastUsed",
            exception.last_used,
        );
        let mut fields = Fields::new();
        text(&mut fields, "Permission", Some(&exception.permission));
        text(&mut fields, "Site", Some(&exception.primary_url));
        text(&mut fields, "EmbeddedIn", Some(&exception.secondary_url));
        if let Some(setting) = exception.setting {
            fields.insert("Setting".into(), Value::Int(setting));
        }
        record.fields = fields;
        record.facets = owner(user);
        record.summary = format!(
            "Site permission {} for {}",
            exception.permission,
            if exception.primary_url.is_empty() {
                "any site"
            } else {
                &exception.primary_url
            }
        );
        record
    }
}

fn push(record: &mut Record, kind: TimeKind, name: &str, time: Option<Ts>) {
    if let Some(time) = time {
        record.times.push(RecordTime::new(kind, name, time));
    }
}

fn owner(user: Option<&str>) -> Facets {
    Facets {
        user_name: user.map(str::to_owned),
        ..Facets::default()
    }
}

fn report(sink: &mut dyn Sink, problems: &[String]) {
    for reason in problems {
        sink.skipped(Skipped {
            locator: Locator::ByteOffset(0),
            reason: reason.clone(),
        });
    }
}
