//! The browser adapter beyond history, on plaso's test files (Apache-2.0,
//! `tests/fixtures/browser/plaso/`): cookies, form history, extensions,
//! site permissions and Safari's history as records.

use std::io::Read;

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, Value};
use sootmark_adapters::browser::{
    BrowserAdapter, AUTOFILL, COOKIES, EXTENSIONS, EXTENSION_ACTIVITY, NAMESPACE, SITE_PERMISSIONS,
};

fn collect(name: &str, path: &str) -> Collected {
    let compressed = std::fs::read(format!(
        "{}/tests/fixtures/browser/plaso/{name}.gz",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let mut data = Vec::new();
    common::gzip::Decoder::new(compressed.as_slice())
        .read_to_end(&mut data)
        .unwrap();
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
        "firefox_10_cookies.sqlite",
        "Users/alice/AppData/Roaming/Mozilla/Firefox/Profiles/x.default/cookies.sqlite",
    );
    assert_eq!(cookies.records.len(), 13);
    assert!(cookies.records.iter().all(|r| r.namespace() == COOKIES));
    assert_eq!(
        cookies.records[0].facets.user_name.as_deref(),
        Some("alice")
    );
    let autofill = collect(
        "Web Data",
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
        "Preferences",
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
        "Extension Activity",
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
    let history = collect("History.db", "Users/alice/Library/Safari/History.db");
    assert_eq!(history.records.len(), 25);
    assert!(history.records.iter().all(|r| r.namespace() == NAMESPACE));
}

#[test]
fn safari_downloads() {
    let downloads = collect(
        "Downloads.plist",
        "Users/alice/Library/Safari/Downloads.plist",
    );
    assert_eq!(downloads.records.len(), 4);
    assert!(downloads.records.iter().all(|r| r.namespace() == NAMESPACE));
}
