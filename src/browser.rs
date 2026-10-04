//! Browser history, via the `browser` parser: Chromium-family `History`
//! (Chrome, Edge, Brave, Opera, Vivaldi), Firefox's `places.sqlite` and
//! `downloads.sqlite`, and Internet Explorer and legacy Edge's
//! `WebCacheV01.dat`. One record per visit (the page, how it was reached)
//! and one per download (from where, to where, how it ended), with the
//! account whose profile it is from the path.

use browser::{Download, History, Kind, PageState, Provenance, RecoveredPage, Visit};
use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};

use crate::home::profile_owner;
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};

/// Records of browser history databases.
pub const NAMESPACE: Namespace = Namespace::new("browser.history");

const SUMMARY_URL: usize = 200;

/// One record per visit and per download.
#[derive(Debug, Default, Clone, Copy)]
pub struct BrowserAdapter;

impl Adapter for BrowserAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "browser",
            version: browser::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[NAMESPACE]
    }

    /// An SQLite database with a browser's tables or named as one, or an
    /// ESE database named as a WebCache.
    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        if browser::detect(name, head).is_some() {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        self.parse_with_log(input, &[], sink)
    }

    /// The database with its write-ahead log: the latest history, and the
    /// log's older page versions, where deleted visits survive.
    fn parse_with_log(
        &self,
        input: &Input<'_>,
        log: &[u8],
        sink: &mut dyn Sink,
    ) -> Result<(), ParseError> {
        let history = browser::read(input.data, log).map_err(|e| ParseError::at(0, e.0))?;
        for reason in &history.problems {
            sink.skipped(Skipped {
                locator: Locator::ByteOffset(0),
                reason: reason.clone(),
            });
        }
        let user = profile_owner(input.name);
        for visit in &history.visits {
            sink.record(self.visit(input, &history, visit, user.as_deref()));
        }
        for download in &history.downloads {
            sink.record(self.download(input, &history, download, user.as_deref()));
        }
        for deleted in &history.deleted_visits {
            let mut record = self.visit(input, &history, &deleted.visit, user.as_deref());
            self.mark_deleted(&mut record, input, &deleted.provenance, "visit");
            sink.record(record);
        }
        for deleted in &history.deleted_pages {
            sink.record(self.deleted_page(input, &history, deleted, user.as_deref()));
        }
        for deleted in &history.deleted_downloads {
            let mut record = self.download(input, &history, &deleted.download, user.as_deref());
            self.mark_deleted(&mut record, input, &deleted.provenance, "download");
            sink.record(record);
        }
        Ok(())
    }
}

impl BrowserAdapter {
    fn record(self, input: &Input<'_>, table: &str, row: i64) -> Record {
        self.record_at(
            input,
            Locator::TableRow {
                table: table.to_owned(),
                row: u64::try_from(row).unwrap_or_default(),
            },
        )
    }

    fn record_at(self, input: &Input<'_>, locator: Locator) -> Record {
        Record::new(input.evidence, NAMESPACE, locator, self.parser())
    }

    /// Turn a live-looking record into a recovered one: its own location
    /// (page and offset, and the log frame for an older version), the
    /// provenance as fields, and a summary that says it was deleted.
    fn mark_deleted(self, record: &mut Record, input: &Input<'_>, from: &Provenance, what: &str) {
        let mut marked = self.record_at(input, recovered_locator(from));
        marked.times = std::mem::take(&mut record.times);
        marked.facets = std::mem::take(&mut record.facets);
        marked.fields = std::mem::take(&mut record.fields);
        provenance_fields(&mut marked.fields, from);
        marked.summary = format!(
            "Deleted {what} (recovered, {} confidence): {}",
            confidence_name(from),
            record.summary
        );
        *record = marked;
    }

    fn deleted_page(
        self,
        input: &Input<'_>,
        history: &History,
        deleted: &RecoveredPage,
        user: Option<&str>,
    ) -> Record {
        let page = &deleted.page;
        let mut record = self.record_at(input, recovered_locator(&deleted.provenance));
        if let Some(time) = page.last_visit {
            record
                .times
                .push(RecordTime::new(TimeKind::Logged, "last_visit_time", time));
        }
        record.facets = Facets {
            user_name: user.map(str::to_owned),
            ..Facets::default()
        };
        let mut fields = Fields::new();
        text(&mut fields, "Browser", Some(browser_name(history.kind)));
        text(&mut fields, "Url", Some(&page.url));
        text(&mut fields, "Domain", domain(&page.url));
        text(&mut fields, "Title", Some(&page.title));
        number(&mut fields, "VisitCount", page.visit_count);
        number(&mut fields, "TypedCount", page.typed_count);
        provenance_fields(&mut fields, &deleted.provenance);
        record.fields = fields;
        record.summary = format!(
            "Deleted page (recovered, {} confidence): {}, last visited",
            confidence_name(&deleted.provenance),
            shorten(&page.url)
        );
        record
    }

    fn visit(
        self,
        input: &Input<'_>,
        history: &History,
        visit: &Visit,
        user: Option<&str>,
    ) -> Record {
        let mut record = self.record(input, &visit.table, visit.id);
        if let Some(time) = visit.time {
            record
                .times
                .push(RecordTime::new(TimeKind::Logged, "visit_time", time));
        }
        record.facets = Facets {
            // The account the browser recorded, else the profile's owner.
            user_name: visit.user.as_deref().or(user).map(str::to_owned),
            ..Facets::default()
        };
        let mut fields = Fields::new();
        text(&mut fields, "Browser", Some(browser_name(history.kind)));
        text(&mut fields, "Url", Some(&visit.url));
        text(&mut fields, "Domain", domain(&visit.url));
        text(&mut fields, "Title", Some(&visit.title));
        text(
            &mut fields,
            "Transition",
            Some(&visit.transition.to_string()),
        );
        number(&mut fields, "FromVisit", visit.from_visit);
        number(&mut fields, "VisitCount", visit.visit_count);
        number(&mut fields, "TypedCount", visit.typed_count);
        text(&mut fields, "Account", visit.user.as_deref());
        // WebCache records neither: absent, not false.
        if history.kind != Kind::WebCache {
            fields.insert("Typed".into(), Value::Bool(visit.typed));
            fields.insert("Hidden".into(), Value::Bool(visit.hidden));
        }
        record.fields = fields;
        let title = if visit.title.is_empty() {
            String::new()
        } else {
            format!(" ({})", visit.title)
        };
        let via = match visit.transition.to_string() {
            how if how.is_empty() => String::new(),
            how => format!(" via {how}"),
        };
        record.summary = format!("Visited {}{title}{via}", shorten(&visit.url));
        record
    }

    fn download(
        self,
        input: &Input<'_>,
        history: &History,
        download: &Download,
        user: Option<&str>,
    ) -> Record {
        let mut record = self.record(input, "downloads", download.id);
        for (time, kind, name) in [
            (download.start, TimeKind::Created, "start_time"),
            (download.end, TimeKind::Modified, "end_time"),
        ] {
            if let Some(time) = time {
                record.times.push(RecordTime::new(kind, name, time));
            }
        }
        record.facets = Facets {
            user_name: user.map(str::to_owned),
            file_path: Some(download.target_path.clone()).filter(|p| !p.is_empty()),
            ..Facets::default()
        };
        let state = download.state.map(state_name);
        let mut fields = Fields::new();
        text(&mut fields, "Browser", Some(browser_name(history.kind)));
        text(&mut fields, "Url", Some(&download.url));
        text(&mut fields, "Domain", domain(&download.url));
        text(
            &mut fields,
            "UrlChain",
            Some(&download.url_chain.join(" -> ")),
        );
        text(&mut fields, "TargetPath", Some(&download.target_path));
        text(&mut fields, "State", state.as_deref());
        number(&mut fields, "ReceivedBytes", download.received_bytes);
        number(&mut fields, "TotalBytes", download.total_bytes);
        number(&mut fields, "DangerType", download.danger_type);
        number(&mut fields, "InterruptReason", download.interrupt_reason);
        text(&mut fields, "Referrer", download.referrer.as_deref());
        text(&mut fields, "TabUrl", download.tab_url.as_deref());
        text(&mut fields, "MimeType", download.mime_type.as_deref());
        record.fields = fields;
        let how = state.map(|s| format!(" ({s})")).unwrap_or_default();
        record.summary = format!(
            "Downloaded {} to {}{how}",
            shorten(&download.url),
            download.target_path
        );
        record
    }
}

/// Where a recovered record was: `deleted visits` (or `… wal frame 7`),
/// row = page and offset.
fn recovered_locator(from: &Provenance) -> Locator {
    let version = match from.page_state {
        PageState::Superseded { frame }
        | PageState::Uncommitted { frame }
        | PageState::Invalid { frame } => format!(" wal frame {frame}"),
        PageState::ReplacedInFile => " under the wal".to_owned(),
        _ => String::new(),
    };
    Locator::TableRow {
        table: format!("deleted {}{version}", from.table),
        row: u64::from(from.page) << 32 | from.offset as u64,
    }
}

fn provenance_fields(fields: &mut Fields, from: &Provenance) {
    fields.insert("Deleted".into(), Value::Bool(true));
    let place = format!(
        "{:?} of page {} at offset {} ({:?})",
        from.area, from.page, from.offset, from.page_state
    );
    text(fields, "RecoveredFrom", Some(&place));
    text(fields, "Confidence", Some(confidence_name(from)));
    text(fields, "Evidence", Some(&format!("{:?}", from.evidence)));
    text(fields, "LostValues", Some(&from.lost.join(", ")));
    if from.truncated {
        fields.insert("Truncated".into(), Value::Bool(true));
    }
}

fn confidence_name(from: &Provenance) -> &'static str {
    match from.confidence {
        browser::Confidence::High => "high",
        browser::Confidence::Medium => "medium",
        browser::Confidence::Low => "low",
    }
}

fn browser_name(kind: Kind) -> &'static str {
    match kind {
        Kind::ChromiumHistory => "chromium",
        Kind::FirefoxPlaces | Kind::FirefoxDownloads => "firefox",
        Kind::WebCache => "internet explorer",
    }
}

fn state_name(state: browser::DownloadState) -> String {
    use browser::DownloadState as S;
    match state {
        S::InProgress => "in progress".to_owned(),
        S::Complete => "complete".to_owned(),
        S::Cancelled => "cancelled".to_owned(),
        S::Interrupted => "interrupted".to_owned(),
        S::Paused => "paused".to_owned(),
        S::Blocked => "blocked".to_owned(),
        S::Dirty => "blocked as dangerous".to_owned(),
        S::Other(n) => format!("state {n}"),
    }
}

/// A URL's host: `https://www.example.com:8443/a` is `www.example.com`.
fn domain(url: &str) -> Option<&str> {
    let (_, rest) = url.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?;
    let host = match host.strip_prefix('[') {
        Some(bracketed) => bracketed.split(']').next()?,
        None => host.split(':').next()?,
    };
    (!host.is_empty()).then_some(host)
}

fn shorten(url: &str) -> String {
    match url.char_indices().nth(SUMMARY_URL) {
        Some((at, _)) => format!("{}…", &url[..at]),
        None => url.to_owned(),
    }
}

fn text(fields: &mut Fields, name: &str, value: Option<&str>) {
    if let Some(value) = value.filter(|v| !v.is_empty()) {
        fields.insert(name.into(), Value::from(value));
    }
}

fn number(fields: &mut Fields, name: &str, value: Option<i64>) {
    if let Some(value) = value {
        fields.insert(name.into(), Value::Int(value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains() {
        assert_eq!(
            domain("https://user@www.example.com:8443/a?b"),
            Some("www.example.com")
        );
        assert_eq!(domain("http://[2001:db8::1]:80/"), Some("2001:db8::1"));
        assert_eq!(domain("file:///C:/x"), None);
        assert_eq!(domain("about:blank"), None);
    }
}
