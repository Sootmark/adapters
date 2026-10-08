//! Beyond history: cookies, form history, extensions (installed and their
//! activity), the sites given permissions, Edge's load statistics and
//! Opera's typed history.

use browser::{
    AutofillEntry, ContentException, Cookie, CookieStore, ExtensionActivity, HostRedirect,
    InstalledExtension, LoadStatistics, ResourceLoad, Rows, TypedEntry, TypedUrl,
};
use common::time::Ts;
use model::adapter::{Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, Record, RecordTime, TimeKind, Value};

use super::{
    domain, shorten, text, BrowserAdapter, AUTOFILL, COOKIES, EXTENSIONS, EXTENSION_ACTIVITY,
    LOAD_STATISTICS, REDIRECT_STATISTICS, SITE_PERMISSIONS, TYPED_URLS,
};

impl BrowserAdapter {
    fn extra(self, input: &Input<'_>, namespace: Namespace, table: &str, row: i64) -> Record {
        let locator = Locator::TableRow {
            table: table.to_owned(),
            row: u64::try_from(row).unwrap_or_default(),
        };
        self.located(input, namespace, locator)
    }

    pub(super) fn located(
        self,
        input: &Input<'_>,
        namespace: Namespace,
        locator: Locator,
    ) -> Record {
        Record::new(
            input.evidence,
            namespace,
            locator,
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
            let mut record = match cookie.store {
                CookieStore::Chromium => self.extra(input, COOKIES, "cookies", cookie.rowid),
                CookieStore::Firefox => self.extra(input, COOKIES, "moz_cookies", cookie.rowid),
                // Its record's offset in the file.
                CookieStore::Safari => {
                    let offset = u64::try_from(cookie.rowid).unwrap_or_default();
                    self.located(input, COOKIES, Locator::ByteOffset(offset))
                }
            };
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
            if let Some(persistent) = cookie.persistent {
                fields.insert("Persistent".into(), Value::Bool(persistent));
            }
            let mut decoded = String::new();
            if let Some(analytics) = &cookie.analytics {
                super::analytics::describe(&mut record, &mut fields, analytics);
                decoded = format!(" ({})", super::analytics::summary(analytics));
            }
            record.fields = fields;
            record.facets = owner(user);
            record.summary = format!(
                "Cookie {} for {}{}{decoded}",
                cookie.name, cookie.host, cookie.path
            );
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

    pub(super) fn load_statistics(
        self,
        input: &Input<'_>,
        statistics: &LoadStatistics,
        user: Option<&str>,
        sink: &mut dyn Sink,
    ) {
        report(sink, &statistics.problems);
        for resource in &statistics.resources {
            sink.record(self.resource_load(input, resource, user));
        }
        for redirect in &statistics.redirects {
            sink.record(self.host_redirect(input, redirect, user));
        }
    }

    fn resource_load(
        self,
        input: &Input<'_>,
        resource: &ResourceLoad,
        user: Option<&str>,
    ) -> Record {
        let mut record = self.extra(input, LOAD_STATISTICS, "load_statistics", resource.rowid);
        push(
            &mut record,
            TimeKind::LastSeen,
            "LastUpdate",
            resource.last_update,
        );
        let kind = resource.resource_type.map(resource_type_name);
        let mut fields = Fields::new();
        text(&mut fields, "Browser", Some("edge"));
        text(&mut fields, "Site", Some(&resource.top_level_hostname));
        text(
            &mut fields,
            "ResourceHost",
            Some(&resource.resource_hostname),
        );
        if let Some(number) = resource.resource_type {
            fields.insert("ResourceType".into(), Value::Int(number));
        }
        text(&mut fields, "ResourceTypeName", kind.as_deref());
        record.fields = fields;
        record.facets = owner(user);
        record.summary = format!(
            "{} loaded {} from {}",
            resource.top_level_hostname,
            kind.as_deref().unwrap_or("a resource"),
            resource.resource_hostname
        );
        record
    }

    fn host_redirect(
        self,
        input: &Input<'_>,
        redirect: &HostRedirect,
        user: Option<&str>,
    ) -> Record {
        let mut record = self.extra(
            input,
            REDIRECT_STATISTICS,
            "redirect_statistics",
            redirect.rowid,
        );
        push(
            &mut record,
            TimeKind::LastSeen,
            "LastUpdate",
            redirect.last_update,
        );
        let mut fields = Fields::new();
        text(&mut fields, "Browser", Some("edge"));
        text(&mut fields, "SourceHost", Some(&redirect.source_hostname));
        text(
            &mut fields,
            "DestinationHost",
            Some(&redirect.destination_hostname),
        );
        if let Some(top_level) = redirect.top_level_document {
            fields.insert("TopLevelDocument".into(), Value::Bool(top_level));
        }
        record.fields = fields;
        record.facets = owner(user);
        record.summary = format!(
            "Redirect from {} to {}",
            redirect.source_hostname, redirect.destination_hostname
        );
        record
    }

    pub(super) fn typed_urls(
        self,
        input: &Input<'_>,
        rows: &Rows<TypedUrl>,
        user: Option<&str>,
        sink: &mut dyn Sink,
    ) {
        report(sink, &rows.problems);
        for (row, typed) in (0i64..).zip(&rows.rows) {
            let mut record = self.extra(input, TYPED_URLS, "typed_history", row);
            push(&mut record, TimeKind::LastSeen, "LastTyped", typed.time);
            let how = match &typed.entry {
                TypedEntry::Typed => "typed",
                TypedEntry::Selected => "selected",
                TypedEntry::Other(other) => other,
            };
            let mut fields = Fields::new();
            text(&mut fields, "Browser", Some("opera"));
            text(&mut fields, "Url", Some(&typed.url));
            text(&mut fields, "Domain", domain(&typed.url));
            text(&mut fields, "Entry", Some(how));
            record.fields = fields;
            record.facets = owner(user);
            record.summary = match &typed.entry {
                TypedEntry::Selected => {
                    format!("Picked {} from the suggestions", shorten(&typed.url))
                }
                _ => format!("Typed {} in the address bar", shorten(&typed.url)),
            };
            sink.record(record);
        }
    }
}

/// Blink's `ResourceType`, by name.
fn resource_type_name(number: i64) -> String {
    let name = match number {
        0 => "main resource",
        1 => "image",
        2 => "style sheet",
        3 => "script",
        4 => "font",
        5 => "raw",
        6 => "SVG document",
        7 => "XSL style sheet",
        8 => "link prefetch",
        9 => "text track",
        10 => "audio",
        11 => "video",
        12 => "manifest",
        13 => "speculation rules",
        other => return format!("resource type {other}"),
    };
    name.to_owned()
}

pub(super) fn push(record: &mut Record, kind: TimeKind, name: &str, time: Option<Ts>) {
    if let Some(time) = time {
        record.times.push(RecordTime::new(kind, name, time));
    }
}

pub(super) fn owner(user: Option<&str>) -> Facets {
    Facets {
        user_name: user.map(str::to_owned),
        ..Facets::default()
    }
}

pub(super) fn report(sink: &mut dyn Sink, problems: &[String]) {
    for reason in problems {
        sink.skipped(Skipped {
            locator: Locator::ByteOffset(0),
            reason: reason.clone(),
        });
    }
}
