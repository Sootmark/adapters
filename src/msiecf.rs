//! Internet Explorer 4 to 9 cache and history files (`index.dat`), via
//! the `msiecf` parser: one record per `URL `, `LEAK` and `REDR` record,
//! deleted ones found in free blocks marked recovered. What its two times
//! mean depends on what it is for (the cache, cookies, the history and its
//! daily and weekly containers, downloads, …), so each is named for it;
//! the account a history or cookie entry was recorded for is split from
//! its URL.

use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};
use msiecf::{Kind, Record as Entry, Usage};

use crate::home::profile_owner;

/// Records of `index.dat` files.
pub const NAMESPACE: Namespace = Namespace::new("windows.ie_cache");

/// The length of a history container's period (`:2013031020130311:`).
const PERIOD_PREFIX: usize = 18;

/// One record per cache record.
#[derive(Debug, Default, Clone, Copy)]
pub struct MsiecfAdapter;

impl Adapter for MsiecfAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "msiecf",
            version: msiecf::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[NAMESPACE]
    }

    /// By the signature (`Client UrlCache MMF Ver `).
    fn probe(&self, _name: &str, head: &[u8]) -> Confidence {
        if msiecf::detect(head) {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let cache = msiecf::read(input.data).map_err(|e| ParseError::at(0, e.0))?;
        for reason in cache.problems {
            sink.skipped(Skipped {
                locator: Locator::ByteOffset(0),
                reason,
            });
        }
        let owner = profile_owner(input.name);
        for entry in &cache.records {
            sink.record(self.record(input, entry, owner.as_deref()));
        }
        Ok(())
    }
}

impl MsiecfAdapter {
    fn record(self, input: &Input<'_>, entry: &Entry, owner: Option<&str>) -> Record {
        let mut record = Record::new(
            input.evidence,
            NAMESPACE,
            Locator::ByteOffset(entry.offset as u64),
            self.parser(),
        );
        record.flags.recovered = entry.recovered;
        let (primary, secondary) = time_names(entry.usage);
        for ((kind, name), time) in [
            (primary, entry.primary_time),
            (secondary, entry.secondary_time),
            ((TimeKind::Other, "Expires"), entry.expires),
            ((TimeKind::Other, "LastChecked"), entry.last_checked),
        ] {
            if let Some(time) = time.filter(|t| t.ticks().is_some()) {
                record.times.push(RecordTime::new(kind, name, time));
            }
        }
        let (user, url) = user_and_url(entry);
        let cached = entry.filename.as_deref().map(|name| {
            entry
                .cache_directory
                .as_deref()
                .map_or_else(|| name.to_owned(), |dir| format!(r"{dir}\{name}"))
        });
        let usage = usage_name(entry.usage);
        let mut fields = Fields::new();
        text(&mut fields, "Location", Some(&entry.location));
        text(&mut fields, "Url", Some(url));
        text(&mut fields, "User", user);
        text(&mut fields, "Usage", Some(usage));
        text(&mut fields, "RecordType", Some(kind_name(entry.kind)));
        text(
            &mut fields,
            "CacheDirectory",
            entry.cache_directory.as_deref(),
        );
        text(&mut fields, "Filename", entry.filename.as_deref());
        text(&mut fields, "CachedFile", cached.as_deref());
        text(&mut fields, "HttpHeaders", entry.http_headers.as_deref());
        if entry.kind != Kind::Redirect {
            fields.insert(
                "CachedFileSize".into(),
                Value::UInt(u64::from(entry.cached_file_size)),
            );
            fields.insert("Hits".into(), Value::UInt(u64::from(entry.hits)));
        }
        record.fields = fields;
        record.facets = Facets {
            user_name: user.or(owner).map(str::to_owned),
            file_path: cached,
            ..Facets::default()
        };
        record.summary = match entry.kind {
            Kind::Redirect => format!("IE redirect: {url}"),
            _ => format!(
                "IE {usage}{}: {url}{}",
                user.map_or_else(String::new, |u| format!(" ({u})")),
                if entry.hits > 0 {
                    format!(" ({} hits)", entry.hits)
                } else {
                    String::new()
                }
            ),
        };
        record
    }
}

/// What the primary and secondary times mean for a record's usage.
fn time_names(usage: Usage) -> ((TimeKind, &'static str), (TimeKind, &'static str)) {
    match usage {
        Usage::Cache | Usage::Cookie => (
            (TimeKind::Accessed, "LastAccessed"),
            (TimeKind::Modified, "LastModified"),
        ),
        Usage::History => (
            (TimeKind::LastSeen, "LastVisited"),
            (TimeKind::Other, "SecondaryTime"),
        ),
        Usage::DailyHistory => (
            (TimeKind::LastSeen, "LastVisited"),
            (TimeKind::Other, "LastVisitedLocal"),
        ),
        Usage::WeeklyHistory => (
            (TimeKind::Created, "Created"),
            (TimeKind::LastSeen, "LastVisitedLocal"),
        ),
        _ => (
            (TimeKind::Other, "PrimaryTime"),
            (TimeKind::Other, "SecondaryTime"),
        ),
    }
}

/// The account and the URL of a history or cookie entry
/// (`Visited: alice@http://…`, `Cookie:alice@host/`); the location as it
/// is otherwise.
fn user_and_url(entry: &Entry) -> (Option<&str>, &str) {
    let location = entry.location.as_str();
    let rest = match entry.usage {
        Usage::History => location.strip_prefix("Visited:"),
        Usage::DailyHistory | Usage::WeeklyHistory => location.get(PERIOD_PREFIX..),
        Usage::Cookie => location.strip_prefix("Cookie:"),
        _ => None,
    };
    match rest.and_then(|r| r.trim_start().split_once('@')) {
        Some((user, url)) if !user.is_empty() && user != "-" => (Some(user), url),
        Some((_, url)) => (None, url),
        _ => (None, location),
    }
}

fn usage_name(usage: Usage) -> &'static str {
    match usage {
        Usage::Cache => "cache",
        Usage::Cookie => "cookie",
        Usage::History => "history",
        Usage::DailyHistory => "daily history",
        Usage::WeeklyHistory => "weekly history",
        Usage::Download => "download",
        Usage::DomStore => "DOM storage",
        Usage::Feed => "feed",
        Usage::Compatibility => "compatibility view",
        Usage::InPrivateFiltering => "InPrivate filtering",
        Usage::Tld => "top-level domain",
        Usage::UserData => "user data",
    }
}

fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Url => "URL",
        Kind::Leak => "LEAK",
        Kind::Redirect => "REDR",
    }
}

fn text(fields: &mut Fields, name: &str, value: Option<&str>) {
    if let Some(value) = value.filter(|v| !v.is_empty()) {
        fields.insert(name.into(), Value::from(value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accounts_split_from_history_and_cookies() {
        let entry = |location: &str| Entry {
            location: location.to_owned(),
            usage: Usage::of(location),
            ..Entry::default()
        };
        let visit = entry("Visited: alice@http://example.com/");
        assert_eq!(user_and_url(&visit), (Some("alice"), "http://example.com/"));
        let daily = entry(":2013031020130311: bob@http://example.com/a");
        assert_eq!(user_and_url(&daily), (Some("bob"), "http://example.com/a"));
        let cookie = entry("Cookie:carol@example.com/");
        assert_eq!(user_and_url(&cookie), (Some("carol"), "example.com/"));
        let unnamed = entry(":2013031020130311: -@http://example.com/b");
        assert_eq!(user_and_url(&unnamed), (None, "http://example.com/b"));
        let cached = entry("http://user@example.com/");
        assert_eq!(user_and_url(&cached), (None, "http://user@example.com/"));
    }
}
