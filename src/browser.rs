//! Browser history, via the `browser` parser: Chromium-family `History`
//! (Chrome, Edge, Brave, Opera, Vivaldi), Firefox's `places.sqlite` and
//! `downloads.sqlite`, and Internet Explorer and legacy Edge's
//! `WebCacheV01.dat`. One record per visit (the page, how it was reached)
//! and one per download (from where, to where, how it ended), with the
//! account whose profile it is from the path. Safari's history and
//! Opera's (12 and older) too; and cookies (Google Analytics' decoded),
//! form history, installed extensions with their activity, the sites given
//! permissions, Edge's load statistics, Opera's typed history, the entries
//! of the Chromium and Firefox disk caches and of Java's deployment cache,
//! each in its own namespace.
//!
//! A Chromium cache's `index` is read with the block files beside it
//! (`data_0` to `data_3`), which the caller hands over as companion files;
//! without them its entries can't be read, and the gap is reported.

mod analytics;
mod cache;
mod extras;

use browser::{Download, History, Kind, PageState, Provenance, RecoveredPage, Visit};
use model::adapter::{Adapter, Companion, Confidence, Input, ParseError, Sink, Skipped};

use crate::home::profile_owner;
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};

/// Records of browser history databases.
pub const NAMESPACE: Namespace = Namespace::new("browser.history");
/// Cookies (Chromium, Firefox).
pub const COOKIES: Namespace = Namespace::new("browser.cookies");
/// Values typed in form fields (Chromium).
pub const AUTOFILL: Namespace = Namespace::new("browser.autofill");
/// Extensions installed (Chromium's `Preferences`).
pub const EXTENSIONS: Namespace = Namespace::new("browser.extensions");
/// What extensions did (Chromium's `Extension Activity`).
pub const EXTENSION_ACTIVITY: Namespace = Namespace::new("browser.extension_activity");
/// Sites given (or refused) permissions (Chromium's `Preferences`).
pub const SITE_PERMISSIONS: Namespace = Namespace::new("browser.site_permissions");
/// Resources pages loaded, by host (Edge's `load_statistics.db`).
pub const LOAD_STATISTICS: Namespace = Namespace::new("browser.load_statistics");
/// Hosts redirected to others (Edge's `load_statistics.db`).
pub const REDIRECT_STATISTICS: Namespace = Namespace::new("browser.redirect_statistics");
/// What was typed in the address bar (Opera's `typed_history.xml`).
pub const TYPED_URLS: Namespace = Namespace::new("browser.typed_urls");
/// Entries of the disk caches (Chromium's block files, Firefox's
/// versions 1 and 2).
pub const CACHE: Namespace = Namespace::new("browser.cache");
/// Files Java downloaded for applets and Web Start (its cache's `.idx`
/// files).
pub const JAVA_CACHE: Namespace = Namespace::new("browser.java_cache");

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
        &[
            NAMESPACE,
            COOKIES,
            AUTOFILL,
            EXTENSIONS,
            EXTENSION_ACTIVITY,
            SITE_PERMISSIONS,
            LOAD_STATISTICS,
            REDIRECT_STATISTICS,
            TYPED_URLS,
            CACHE,
            JAVA_CACHE,
        ]
    }

    /// An SQLite database with a browser's tables or named as one, or an
    /// ESE database named as a WebCache. The files told by a short
    /// signature (Safari's cookies, a Java cache index, a Chromium cache's
    /// `index`, Opera's histories) only under their own names; a Firefox
    /// cache2 entry by its name and folder too, as its metadata is found
    /// from its end, past the head.
    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        let recognised = match browser::detect(name, head) {
            Some(kind) => named_as(kind, name),
            None => cache::is_cache2_entry(name),
        };
        if recognised {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn companions(&self, name: &str) -> Vec<String> {
        cache::companions(name)
    }

    /// A Chromium cache's `index` with its block files; anything else as
    /// [`Adapter::parse`].
    fn parse_with_companions(
        &self,
        input: &Input<'_>,
        companions: &[Companion<'_>],
        sink: &mut dyn Sink,
    ) -> Result<(), ParseError> {
        if browser::detect(input.name, input.data) == Some(Kind::ChromeCache) {
            return self.chrome_cache(input, companions, sink);
        }
        self.parse(input, sink)
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
        let failed = |e: browser::Error| ParseError::at(0, e.0);
        let user = profile_owner(input.name);
        match browser::detect(input.name, input.data) {
            Some(Kind::Cookies) => {
                let rows = browser::read_cookies(input.data, log).map_err(failed)?;
                self.cookies(input, &rows, user.as_deref(), sink);
                return Ok(());
            }
            Some(Kind::SafariCookies) => {
                let rows = browser::read_binary_cookies(input.data).map_err(failed)?;
                self.cookies(input, &rows, user.as_deref(), sink);
                return Ok(());
            }
            Some(Kind::LoadStatistics) => {
                let statistics = browser::read_load_statistics(input.data, log).map_err(failed)?;
                self.load_statistics(input, &statistics, user.as_deref(), sink);
                return Ok(());
            }
            Some(Kind::OperaTypedHistory) => {
                let rows = browser::read_opera_typed_history(input.data).map_err(failed)?;
                self.typed_urls(input, &rows, user.as_deref(), sink);
                return Ok(());
            }
            Some(Kind::JavaIdx) => return self.java_cache(input, user.as_deref(), sink),
            Some(Kind::ChromeCache) => return self.chrome_cache(input, &[], sink),
            Some(kind @ (Kind::FirefoxCache1 | Kind::FirefoxCache2)) => {
                return self.firefox_cache(input, kind, user.as_deref(), sink);
            }
            Some(Kind::Autofill) => {
                let rows = browser::read_autofill(input.data, log).map_err(failed)?;
                self.autofill(input, &rows, user.as_deref(), sink);
                return Ok(());
            }
            Some(Kind::ExtensionActivity) => {
                let rows = browser::read_extension_activity(input.data, log).map_err(failed)?;
                self.extension_activity(input, &rows, user.as_deref(), sink);
                return Ok(());
            }
            Some(Kind::Preferences) => return self.preferences(input, user.as_deref(), sink),
            _ => {}
        }
        let history = browser::read(input.data, log).map_err(failed)?;
        for reason in &history.problems {
            sink.skipped(Skipped {
                locator: Locator::ByteOffset(0),
                reason: reason.clone(),
            });
        }
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
        number(&mut fields, "Frecency", visit.frecency);
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

/// Whether `name` is one a file of `kind` has, for the kinds whose
/// signature is too short to be told by alone.
fn named_as(kind: Kind, name: &str) -> bool {
    match kind {
        Kind::SafariCookies
        | Kind::JavaIdx
        | Kind::OperaGlobalHistory
        | Kind::OperaTypedHistory => Kind::from_name(name) == Some(kind),
        Kind::ChromeCache => cache::is_chrome_cache_index(name),
        _ => true,
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
        Kind::ChromiumHistory
        | Kind::Cookies
        | Kind::Autofill
        | Kind::ExtensionActivity
        | Kind::Preferences
        | Kind::ChromeCache => "chromium",
        Kind::FirefoxPlaces
        | Kind::FirefoxDownloads
        | Kind::FirefoxCache1
        | Kind::FirefoxCache2 => "firefox",
        Kind::WebCache => "internet explorer",
        Kind::LoadStatistics => "edge",
        Kind::SafariHistory
        | Kind::SafariHistoryPlist
        | Kind::SafariDownloads
        | Kind::SafariCookies => "safari",
        Kind::OperaGlobalHistory | Kind::OperaTypedHistory => "opera",
        Kind::JavaIdx => "java",
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
