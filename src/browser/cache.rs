//! Caches: the entries of Chromium's block-file cache and of Firefox's
//! (versions 1 and 2), each with its URL, when it was cached, used and
//! modified, and of Java's deployment cache, each with where its file
//! came from and when.

use browser::{ChromeCacheEntry, FirefoxCacheEntry, JavaCacheEntry, Kind};
use common::time::{Semantic, Ts};
use model::adapter::{Companion, Input, ParseError, Sink};
use model::{Facets, Fields, Locator, Record, TimeKind, Value};

use super::extras::{owner, push, report};
use super::{browser_name, domain, shorten, text, BrowserAdapter, CACHE, JAVA_CACHE};
use crate::home::profile_owner;

/// The block files a Chromium cache's `index` is read with: its rankings,
/// entries and the keys stored apart are in them. The `f_` files beside
/// them hold content alone, past a key rarely.
const BLOCK_FILES: [&str; 4] = ["data_0", "data_1", "data_2", "data_3"];

/// What Chromium names an entry's state.
const STATES: [&str; 3] = ["normal", "evicted", "doomed"];

/// The block files a Chromium cache's `index` is read with.
pub(super) fn companions(name: &str) -> Vec<String> {
    if is_chrome_cache_index(name) {
        BLOCK_FILES.iter().map(|file| (*file).to_owned()).collect()
    } else {
        Vec::new()
    }
}

/// Whether `name` is a Chromium cache's `index`.
pub(super) fn is_chrome_cache_index(name: &str) -> bool {
    base_name(name).eq_ignore_ascii_case("index")
}

/// Whether `name` is a Firefox cache2 entry's: `cache2/entries/<SHA-1>`.
pub(super) fn is_cache2_entry(name: &str) -> bool {
    let mut parts = name.rsplit(['/', '\\']);
    Kind::from_name(name) == Some(Kind::FirefoxCache2)
        && parts.next().is_some()
        && parts
            .next()
            .is_some_and(|p| p.eq_ignore_ascii_case("entries"))
        && parts
            .next()
            .is_some_and(|p| p.eq_ignore_ascii_case("cache2"))
}

impl BrowserAdapter {
    /// A Chromium cache's entries, read from its `index` and the block
    /// files among `companions`.
    pub(super) fn chrome_cache(
        self,
        input: &Input<'_>,
        companions: &[Companion<'_>],
        sink: &mut dyn Sink,
    ) -> Result<(), ParseError> {
        let file = |name: &str| {
            companions
                .iter()
                .find(|c| c.name.eq_ignore_ascii_case(name))
                .map(|c| c.data)
        };
        let cache =
            browser::read_chrome_cache(input.data, file).map_err(|e| ParseError::at(0, e.0))?;
        report(sink, &cache.problems);
        let user = profile_owner(input.name);
        for entry in &cache.entries {
            sink.record(self.chrome_cache_entry(input, &cache.version, entry, user.as_deref()));
        }
        Ok(())
    }

    fn chrome_cache_entry(
        self,
        input: &Input<'_>,
        version: &str,
        entry: &ChromeCacheEntry,
        user: Option<&str>,
    ) -> Record {
        let locator = Locator::TableRow {
            table: "index".to_owned(),
            row: u64::from(entry.address),
        };
        let mut record = self.located(input, CACHE, locator);
        for (kind, name, time) in [
            (TimeKind::Created, "Created", entry.created),
            (TimeKind::LastSeen, "LastUsed", entry.last_used),
            (TimeKind::Modified, "LastModified", entry.last_modified),
        ] {
            push(&mut record, kind, name, time);
        }
        let state = STATES
            .get(entry.state as usize)
            .map_or_else(|| format!("state {}", entry.state), |s| (*s).to_owned());
        let mut fields = cache_fields(Kind::ChromeCache, version, &entry.url, &entry.key);
        text(&mut fields, "State", Some(&state));
        for (name, value) in [
            ("ReuseCount", entry.reuse_count),
            ("RefetchCount", entry.refetch_count),
            ("Flags", entry.flags),
        ] {
            fields.insert(name.into(), Value::Int(i64::from(value)));
        }
        let streams: Vec<String> = entry
            .streams
            .iter()
            .map(|stream| match stream.offset {
                Some(offset) => format!(
                    "{}: {} bytes in {} at {offset}",
                    stream.index, stream.size, stream.file
                ),
                None => format!("{}: {} bytes in {}", stream.index, stream.size, stream.file),
            })
            .collect();
        text(&mut fields, "Streams", Some(&streams.join("; ")));
        // Stream 1 is the content.
        if let Some(content) = entry.streams.iter().find(|s| s.index == 1) {
            fields.insert("ContentSize".into(), Value::Int(i64::from(content.size)));
            text(&mut fields, "ContentFile", Some(&content.file));
        }
        record.fields = fields;
        record.facets = owner(user);
        record.summary = format!("Cached {} (chromium, {state})", shorten(&entry.url));
        record
    }

    /// A Firefox cache's entries: the records of a version 1 block file,
    /// or a version 2 entry file's one.
    pub(super) fn firefox_cache(
        self,
        input: &Input<'_>,
        kind: Kind,
        user: Option<&str>,
        sink: &mut dyn Sink,
    ) -> Result<(), ParseError> {
        let failed = |e: browser::Error| ParseError::at(0, e.0);
        let rows = if kind == Kind::FirefoxCache1 {
            browser::read_firefox_cache1(input.name, input.data).map_err(failed)?
        } else {
            browser::Rows {
                rows: vec![browser::read_firefox_cache2(input.data).map_err(failed)?],
                problems: Vec::new(),
            }
        };
        report(sink, &rows.problems);
        for entry in &rows.rows {
            sink.record(self.firefox_cache_entry(input, entry, user));
        }
        Ok(())
    }

    fn firefox_cache_entry(
        self,
        input: &Input<'_>,
        entry: &FirefoxCacheEntry,
        user: Option<&str>,
    ) -> Record {
        let kind = if entry.cache_version == 1 {
            Kind::FirefoxCache1
        } else {
            Kind::FirefoxCache2
        };
        let mut record = self.located(input, CACHE, Locator::ByteOffset(entry.offset as u64));
        for (kind, name, time) in [
            (TimeKind::LastSeen, "LastFetched", entry.last_fetched),
            (TimeKind::Modified, "LastModified", entry.last_modified),
            (TimeKind::Other, "Expires", unless_never(entry.expires)),
        ] {
            push(&mut record, kind, name, time);
        }
        let version = format!("{} (format {})", entry.cache_version, entry.format_version);
        let mut fields = cache_fields(kind, &version, &entry.url, &entry.key);
        fields.insert(
            "FetchCount".into(),
            Value::Int(i64::from(entry.fetch_count)),
        );
        if let Some(frecency) = entry.frecency {
            fields.insert("Frecency".into(), Value::Int(i64::from(frecency)));
        }
        fields.insert("ContentSize".into(), Value::Int(i64::from(entry.data_size)));
        text(&mut fields, "RequestMethod", entry.request_method());
        text(&mut fields, "ResponseStatus", entry.response_status());
        text(&mut fields, "ResponseHead", entry.element("response-head"));
        record.fields = fields;
        record.facets = owner(user);
        record.summary = format!(
            "Cached {} (firefox, fetched {} times)",
            shorten(&entry.url),
            entry.fetch_count
        );
        record
    }

    /// A Java cache index file's entry: the file it describes is beside
    /// it, named as it without `.idx`.
    pub(super) fn java_cache(
        self,
        input: &Input<'_>,
        user: Option<&str>,
        sink: &mut dyn Sink,
    ) -> Result<(), ParseError> {
        let entry = browser::read_java_idx(input.data).map_err(|e| ParseError::at(0, e.0))?;
        report(sink, &entry.problems);
        sink.record(self.java_cache_entry(input, &entry, user));
        Ok(())
    }

    fn java_cache_entry(
        self,
        input: &Input<'_>,
        entry: &JavaCacheEntry,
        user: Option<&str>,
    ) -> Record {
        let mut record = self.located(input, JAVA_CACHE, Locator::ByteOffset(0));
        for (kind, name, time) in [
            (TimeKind::Created, "Downloaded", entry.downloaded),
            (TimeKind::Modified, "Modified", entry.modified),
            (TimeKind::LastSeen, "Validated", entry.validated),
            (TimeKind::Other, "Expires", entry.expires),
        ] {
            push(&mut record, kind, name, time);
        }
        let mut fields = Fields::new();
        text(&mut fields, "Url", Some(&entry.url));
        text(&mut fields, "Domain", domain(&entry.url));
        fields.insert("Version".into(), Value::Int(i64::from(entry.version)));
        fields.insert(
            "ContentSize".into(),
            Value::Int(i64::from(entry.content_size)),
        );
        for (name, value) in [
            ("Busy", Some(entry.busy)),
            ("Incomplete", Some(entry.incomplete)),
            ("Signed", entry.signed),
        ] {
            if let Some(value) = value {
                fields.insert(name.into(), Value::Bool(value));
            }
        }
        text(
            &mut fields,
            "ResourceVersion",
            Some(&entry.resource_version),
        );
        text(&mut fields, "IpAddress", entry.ip_address.as_deref());
        text(&mut fields, "HttpStatus", entry.status());
        text(&mut fields, "ContentType", entry.header("content-type"));
        let headers: Vec<String> = entry
            .http_headers
            .iter()
            .map(|(name, value)| format!("{name}: {value}"))
            .collect();
        text(&mut fields, "HttpHeaders", Some(&headers.join("\n")));
        record.fields = fields;
        record.facets = Facets {
            file_path: input.name.strip_suffix(".idx").map(str::to_owned),
            destination_ip: entry.ip_address.clone(),
            ..owner(user)
        };
        record.summary = format!(
            "Java downloaded {} ({} bytes)",
            shorten(&entry.url),
            entry.content_size
        );
        record
    }
}

/// The fields every cache entry has: the browser and cache, the URL and
/// its host, and the key when it is more than the URL.
fn cache_fields(kind: Kind, version: &str, url: &str, key: &str) -> Fields {
    let mut fields = Fields::new();
    text(&mut fields, "Browser", Some(browser_name(kind)));
    text(&mut fields, "CacheVersion", Some(version));
    text(&mut fields, "Url", Some(url));
    text(&mut fields, "Domain", domain(url));
    if key != url {
        text(&mut fields, "Key", Some(key));
    }
    fields
}

/// `time`, unless it says the entry never expires.
fn unless_never(time: Option<Ts>) -> Option<Ts> {
    time.filter(|t| t.semantic() != Semantic::Sentinel)
}

fn base_name(name: &str) -> &str {
    name.rsplit(['/', '\\']).next().unwrap_or(name)
}
