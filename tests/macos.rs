//! The macOS adapter on plaso's quarantine and TCC databases, FSEvents log
//! and background items (Apache-2.0)
//! and a synthetic KnowledgeC database with its write-ahead log
//! (`tests/fixtures/macos/`): the contract, recognition, records.

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, Record, Value};
use sootmark_adapters::macos::{
    MacosAdapter, ASL, FSEVENTS, KNOWLEDGEC, LOGIN_ITEMS, QUARANTINE, TCC, USERS, WIFI,
};

fn read(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/macos/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn parse(fixture: &str, path: &str, log: &[u8]) -> Vec<Record> {
    let data = read(fixture);
    assert_eq!(MacosAdapter.probe(path, &data), Confidence::Certain);
    assert_conforms(&MacosAdapter, path, &data);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name: path,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    MacosAdapter.parse_with_log(&input, log, &mut sink).unwrap();
    sink.records
}

#[test]
fn quarantine_events() {
    let path = "Users/alice/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2";
    let records = parse("quarantine.db", path, &[]);
    assert_eq!(records.len(), 14);
    assert!(records.iter().all(|r| r.namespace() == QUARANTINE));
    assert!(records
        .iter()
        .all(|r| r.facets.user_name.as_deref() == Some("alice")));
    assert!(records[0].summary.starts_with("Downloaded by "));
}

#[test]
fn tcc_permissions() {
    let path = "Library/Application Support/com.apple.TCC/TCC.db";
    let records = parse("TCC-test.db", path, &[]);
    assert_eq!(records.len(), 21);
    let weather = &records[0];
    assert_eq!(weather.namespace(), TCC);
    assert_eq!(
        weather.fields.get("Client"),
        Some(&Value::from("com.apple.weather"))
    );
    assert_eq!(weather.fields.get("Scope"), Some(&Value::from("system")));
    assert_eq!(weather.summary, "com.apple.weather allowed for Ubiquity");
    // A system database belongs to no one account.
    assert_eq!(weather.facets.user_name, None);
}

#[test]
fn knowledgec_with_its_log() {
    let path = "Users/alice/Library/Application Support/Knowledge/knowledgeC.db";
    let alone = parse("knowledgeC.db", path, &[]);
    let with_log = parse("knowledgeC.db", path, &read("knowledgeC.db-wal"));
    assert!(with_log.iter().all(|r| r.namespace() == KNOWLEDGEC));
    assert_eq!(with_log.len(), alone.len() + 1, "one event only in the log");
}

#[test]
fn launchd_jobs() {
    use sootmark_adapters::macos::LAUNCHD;
    let daemon = parse(
        "launchd.plist",
        "Library/LaunchDaemons/com.foobar.test.plist",
        &[],
    );
    assert_eq!(daemon.len(), 1);
    let job = &daemon[0];
    assert_eq!(job.namespace(), LAUNCHD);
    assert_eq!(job.facets.user_name.as_deref(), Some("nobody"));
    assert_eq!(
        job.facets.process_command_line.as_deref(),
        Some("/Test --flag arg1")
    );
    assert!(job
        .summary
        .starts_with("launch daemon com.foobar.test: /Test --flag arg1"));

    let agent = parse(
        "com.example.updater.bplist",
        "Users/alice/Library/LaunchAgents/com.example.updater.plist",
        &[],
    );
    assert_eq!(agent[0].facets.user_name.as_deref(), Some("alice"));
    assert_eq!(
        agent[0].fields.get("Kind"),
        Some(&Value::from("launch agent"))
    );
}

#[test]
fn fsevents_logs() {
    let records = parse(
        "fsevents-0000000002d89b58",
        "Volumes/Data/.fseventsd/0000000002d89b58",
        &[],
    );
    assert_eq!(records.len(), 12);
    assert!(records.iter().all(|r| r.namespace() == FSEVENTS));
    let folder = records
        .iter()
        .find(|r| r.facets.file_path.as_deref() == Some("/Test folder"))
        .unwrap();
    assert_eq!(
        folder.summary,
        "FSEvents Renamed, IsDirectory: /Test folder"
    );
}

#[test]
fn login_items() {
    let records = parse(
        "backgrounditems.btm",
        "Users/alice/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm",
        &[],
    );
    let [item] = &records[..] else {
        panic!("{} records", records.len());
    };
    assert_eq!(item.namespace(), LOGIN_ITEMS);
    assert_eq!(
        item.summary,
        "login item iTunesHelper: /Applications/iTunes.app/Contents/MacOS/iTunesHelper.app"
    );
    assert_eq!(item.facets.user_name.as_deref(), Some("alice"));
    assert_eq!(
        item.fields.get("VolumeName"),
        Some(&Value::from("Macintosh HD"))
    );
}

#[test]
fn property_lists() {
    let wifi = parse(
        "com.apple.airport.preferences.plist",
        "Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist",
        &[],
    );
    assert_eq!(wifi.len(), 4);
    assert!(wifi.iter().all(|r| r.namespace() == WIFI));
    assert!(wifi
        .iter()
        .any(|r| r.summary == "macOS Wi-Fi network: europa"));
    let users = parse(
        "user.plist",
        "private/var/db/dslocal/nodes/Default/users/user.plist",
        &[],
    );
    assert_eq!(users[0].namespace(), USERS);
    assert_eq!(users[0].facets.user_name.as_deref(), Some("user"));
    assert!(users[0].fields.contains_key("Home"));
    let items = parse(
        "com.apple.loginitems.plist",
        "Users/alice/Library/Preferences/com.apple.loginitems.plist",
        &[],
    );
    assert_eq!(
        items[0].facets.process_path.as_deref(),
        Some("/Applications/iTunes.app/Contents/MacOS/iTunesHelper.app")
    );
}

#[test]
fn apple_system_log() {
    let records = parse(
        "applesystemlog.asl",
        "private/var/log/asl/applesystemlog.asl",
        &[],
    );
    assert_eq!(records.len(), 2);
    assert!(records.iter().all(|r| r.namespace() == ASL));
    assert!(records.iter().all(|r| !r.times.is_empty()));
}
