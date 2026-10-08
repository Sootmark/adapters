//! The browser adapter beyond history, on plaso's test files (Apache-2.0,
//! `tests/fixtures/browser/plaso/`, see its NOTICE): cookies (Google
//! Analytics' decoded, Safari's), form history, extensions, site
//! permissions, Safari's and Opera's histories, Edge's load statistics, and
//! the Chromium, Firefox and Java caches as records.

use std::io::Read;

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Companion, Confidence, Input};
use model::{EvidenceId, Record, TimeKind, Value};
use sootmark_adapters::browser::{
    BrowserAdapter, AUTOFILL, CACHE, COOKIES, EXTENSIONS, EXTENSION_ACTIVITY, JAVA_CACHE,
    LOAD_STATISTICS, NAMESPACE, REDIRECT_STATISTICS, SITE_PERMISSIONS, TYPED_URLS,
};

/// A fixture's content, decompressed when stored gzip-compressed.
fn fixture(name: &str) -> Vec<u8> {
    let stored = std::fs::read(format!(
        "{}/tests/fixtures/browser/plaso/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    if !common::gzip::is_gzip(&stored) {
        return stored;
    }
    let mut data = Vec::new();
    common::gzip::Decoder::new(stored.as_slice())
        .read_to_end(&mut data)
        .unwrap();
    data
}

fn collect(name: &str, path: &str) -> Collected {
    let data = fixture(name);
    assert_eq!(
        BrowserAdapter.probe(path, &data),
        Confidence::Certain,
        "{name}"
    );
    assert_conforms(&BrowserAdapter, path, &data);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name: path,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    BrowserAdapter.parse(&input, &mut sink).unwrap();
    assert!(sink.skipped.is_empty(), "{name}: {:?}", sink.skipped);
    sink
}

#[test]
fn cookies_and_form_history() {
    let cookies = collect(
        "firefox_10_cookies.sqlite.gz",
        "Users/alice/AppData/Roaming/Mozilla/Firefox/Profiles/x.default/cookies.sqlite",
    );
    assert_eq!(cookies.records.len(), 13);
    assert!(cookies.records.iter().all(|r| r.namespace() == COOKIES));
    assert_eq!(
        cookies.records[0].facets.user_name.as_deref(),
        Some("alice")
    );
    let autofill = collect(
        "Web Data.gz",
        "Users/alice/AppData/Local/Google/Chrome/User Data/Default/Web Data",
    );
    assert_eq!(autofill.records.len(), 3);
    assert!(autofill.records.iter().all(|r| r.namespace() == AUTOFILL));
    assert!(autofill
        .records
        .iter()
        .any(|r| r.fields.get("Value") == Some(&Value::from("name@example.com"))));
}

#[test]
fn extensions_and_permissions() {
    let preferences = collect(
        "Preferences.gz",
        "Users/alice/AppData/Local/Google/Chrome/User Data/Default/Preferences",
    );
    let installed = preferences
        .records
        .iter()
        .filter(|r| r.namespace() == EXTENSIONS)
        .count();
    let permissions = preferences
        .records
        .iter()
        .filter(|r| r.namespace() == SITE_PERMISSIONS)
        .count();
    assert!(installed >= 20, "{installed}");
    assert!(permissions >= 7, "{permissions}");
    let activity = collect(
        "Extension Activity.gz",
        "Users/alice/AppData/Local/Google/Chrome/User Data/Default/Extension Activity",
    );
    assert_eq!(activity.records.len(), 56);
    assert!(activity
        .records
        .iter()
        .all(|r| r.namespace() == EXTENSION_ACTIVITY));
}

#[test]
fn safari_history() {
    let history = collect("History.db.gz", "Users/alice/Library/Safari/History.db");
    assert_eq!(history.records.len(), 25);
    assert!(history.records.iter().all(|r| r.namespace() == NAMESPACE));
}

#[test]
fn safari_downloads() {
    let downloads = collect(
        "Downloads.plist.gz",
        "Users/alice/Library/Safari/Downloads.plist",
    );
    assert_eq!(downloads.records.len(), 4);
    assert!(downloads.records.iter().all(|r| r.namespace() == NAMESPACE));
}

fn field<'r>(record: &'r Record, name: &str) -> Option<&'r Value> {
    record.fields.get(name)
}

fn in_namespace(collected: &Collected, namespace: model::Namespace) -> usize {
    collected
        .records
        .iter()
        .filter(|r| r.namespace() == namespace)
        .count()
}

#[test]
fn google_analytics_cookies() {
    let cookies = collect(
        "firefox_2_cookies.sqlite.gz",
        "Users/alice/AppData/Roaming/Mozilla/Firefox/Profiles/x.default/cookies.sqlite",
    );
    let decoded = |name: &str| {
        cookies
            .records
            .iter()
            .filter(|r| field(r, "AnalyticsCookie") == Some(&Value::from(name)))
            .count()
    };
    // As plaso decodes them: five of each, the throttle among none.
    assert_eq!(
        (decoded("utma"), decoded("utmb"), decoded("utmz")),
        (5, 5, 5)
    );
    let referral = cookies
        .records
        .iter()
        .find(|r| {
            field(r, "AnalyticsCookie") == Some(&Value::from("utmz"))
                && field(r, "Host") == Some(&Value::from(".theonion.com"))
        })
        .unwrap();
    assert_eq!(
        field(referral, "AnalyticsSource"),
        Some(&Value::from("google"))
    );
    assert_eq!(
        field(referral, "AnalyticsMedium"),
        Some(&Value::from("organic"))
    );
    assert_eq!(
        field(referral, "AnalyticsTerm"),
        Some(&Value::from("(not provided)"))
    );
    assert!(referral
        .summary
        .ends_with("(Google Analytics referral from google, searched for (not provided))"));
    let visitor = cookies
        .records
        .iter()
        .find(|r| field(r, "AnalyticsCookie") == Some(&Value::from("utma")))
        .unwrap();
    assert!(visitor
        .times
        .iter()
        .any(|t| t.field == "AnalyticsFirstVisit" && t.kind == TimeKind::FirstSeen));
    assert_eq!(field(visitor, "AnalyticsSessions"), Some(&Value::Int(1)));
}

#[test]
fn safari_cookies() {
    let cookies = collect(
        "Cookies.binarycookies",
        "Users/alice/Library/Cookies/Cookies.binarycookies",
    );
    // plaso's 182 events: a creation and an expiry each.
    assert_eq!(cookies.records.len(), 91);
    assert!(cookies.records.iter().all(|r| r.namespace() == COOKIES));
    assert_eq!(
        BrowserAdapter.probe(
            "Users/alice/notes/Cookies.txt",
            &fixture("Cookies.binarycookies")
        ),
        Confidence::No
    );
}

#[test]
fn edge_load_statistics() {
    let statistics = collect(
        "load_statistics.db.gz",
        "Users/alice/AppData/Local/Microsoft/Edge/User Data/Default/load_statistics.db",
    );
    assert_eq!(in_namespace(&statistics, LOAD_STATISTICS), 1);
    let redirect = statistics
        .records
        .iter()
        .find(|r| r.namespace() == REDIRECT_STATISTICS)
        .unwrap();
    assert_eq!(
        redirect.summary,
        "Redirect from www.bing.com to www.bing.com"
    );
    assert_eq!(
        field(redirect, "TopLevelDocument"),
        Some(&Value::Bool(false))
    );
    assert_eq!(redirect.facets.user_name.as_deref(), Some("alice"));
}

#[test]
fn opera_histories() {
    let global = collect(
        "global_history.dat",
        "Users/alice/AppData/Roaming/Opera/Opera/global_history.dat",
    );
    assert_eq!(global.records.len(), 37);
    assert!(global.records.iter().all(|r| r.namespace() == NAMESPACE));
    assert_eq!(
        field(&global.records[0], "Browser"),
        Some(&Value::from("opera"))
    );
    let typed = collect(
        "typed_history.xml",
        "Users/alice/AppData/Roaming/Opera/Opera/typed_history.xml",
    );
    assert_eq!(typed.records.len(), 4);
    assert!(typed.records.iter().all(|r| r.namespace() == TYPED_URLS));
    assert_eq!(
        typed.records[0].summary,
        "Picked plaso.kiddaland.net from the suggestions"
    );
    assert_eq!(typed.records[1].summary, "Typed mbl.is in the address bar");
    assert_eq!(
        BrowserAdapter.probe("Users/alice/notes.xml", &fixture("typed_history.xml")),
        Confidence::No
    );
}

#[test]
fn java_cache() {
    const PATH: &str =
        "Users/alice/AppData/LocalLow/Sun/Java/Deployment/cache/6.0/12/4c1f3b4c-5d5a1b2e.idx";
    let java = collect("java.idx", PATH);
    let [entry] = java.records.as_slice() else {
        panic!("{:?}", java.records)
    };
    assert_eq!(entry.namespace(), JAVA_CACHE);
    assert_eq!(field(entry, "Signed"), Some(&Value::Bool(false)));
    assert_eq!(entry.facets.file_path.as_deref(), PATH.strip_suffix(".idx"));
    assert!(entry.times.iter().any(|t| t.field == "Downloaded"));
    assert_eq!(
        BrowserAdapter.probe("Users/alice/x.bin", &fixture("java.idx")),
        Confidence::No
    );
}

#[test]
fn chrome_cache_with_its_block_files() {
    const INDEX: &str = "Users/alice/AppData/Local/Google/Chrome/User Data/Default/Cache/index";
    let index = fixture("chrome_cache/index.gz");
    assert_eq!(BrowserAdapter.probe(INDEX, &index), Confidence::Certain);
    assert_eq!(
        BrowserAdapter.companions(INDEX),
        ["data_0", "data_1", "data_2", "data_3"]
    );
    assert_conforms(&BrowserAdapter, INDEX, &index);
    let files: Vec<(&str, Vec<u8>)> = ["data_0", "data_1", "data_2"]
        .into_iter()
        .map(|name| (name, fixture(&format!("chrome_cache/{name}.gz"))))
        .collect();
    let companions: Vec<Companion<'_>> = files
        .iter()
        .map(|(name, data)| Companion { name, data })
        .collect();
    let input = Input {
        evidence: EvidenceId::of_content(&index),
        name: INDEX,
        data: &index,
        modified: None,
    };
    let mut sink = Collected::default();
    BrowserAdapter
        .parse_with_companions(&input, &companions, &mut sink)
        .unwrap();
    assert!(sink.skipped.is_empty(), "{:?}", sink.skipped);
    // As plaso's chrome_cache parser: 217 entries.
    assert_eq!(sink.records.len(), 217);
    assert!(sink.records.iter().all(|r| r.namespace() == CACHE));
    let entry = &sink.records[0];
    assert_eq!(field(entry, "Browser"), Some(&Value::from("chromium")));
    assert!(matches!(field(entry, "Url"), Some(Value::Text(url)) if url.starts_with("http")));
    assert_eq!(entry.facets.user_name.as_deref(), Some("alice"));
    // Without its block files: nothing read, the gap reported.
    let mut alone = Collected::default();
    BrowserAdapter.parse(&input, &mut alone).unwrap();
    assert!(alone.records.is_empty());
    assert!(!alone.skipped.is_empty());
}

#[test]
fn firefox_caches() {
    const ENTRY_NAME: &str = "1F4B3A4FC81FB19C530758231FA54313BE8F6FA2";
    const PROFILE: &str = "Users/alice/AppData/Local/Mozilla/Firefox/Profiles/x.default";
    let version_1 = collect(
        "firefox_cache/firefox3/_CACHE_001_.gz",
        &format!("{PROFILE}/Cache/_CACHE_001_"),
    );
    // The 25 records plaso reads (73 events: their times).
    assert_eq!(version_1.records.len(), 25);
    assert!(version_1.records.iter().all(|r| r.namespace() == CACHE));
    let path = format!("{PROFILE}/cache2/entries/{ENTRY_NAME}");
    let data = fixture(&format!("firefox_cache/cache2/{ENTRY_NAME}"));
    let version_2 = collect(&format!("firefox_cache/cache2/{ENTRY_NAME}"), &path);
    let [entry] = version_2.records.as_slice() else {
        panic!("{:?}", version_2.records)
    };
    assert_eq!(field(entry, "Browser"), Some(&Value::from("firefox")));
    assert_eq!(field(entry, "RequestMethod"), Some(&Value::from("GET")));
    assert_eq!(
        field(entry, "ResponseStatus"),
        Some(&Value::from("HTTP/1.1 200 OK"))
    );
    // Its metadata is found from its end, past the head: the entry is told
    // by its name and folder.
    assert_eq!(
        BrowserAdapter.probe(&path, &data[..4096]),
        Confidence::Certain
    );
    assert_eq!(
        BrowserAdapter.probe(ENTRY_NAME, &data[..4096]),
        Confidence::No
    );
}
