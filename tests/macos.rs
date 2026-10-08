//! The macOS adapter on plaso's quarantine and TCC databases, FSEvents log,
//! background items, Spotlight preferences, Messages database, keychain,
//! Wi-Fi and launchd logs (Apache-2.0)
//! and a synthetic KnowledgeC database with its write-ahead log
//! (`tests/fixtures/macos/`): the contract, recognition, records.

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use std::io::Read;

use common::time::Ts;
use model::{EvidenceId, Record, TimeKind, Value};
use sootmark_adapters::macos::{
    MacosAdapter, APP_USAGE, ASL, DOCUMENT_VERSIONS, FSEVENTS, KEYCHAIN, KNOWLEDGEC, LAUNCHD_LOG,
    LOGIN_ITEMS, MESSAGES, NOTES, NOTIFICATIONS, QUARANTINE, SPOTLIGHT_SEARCHES, SPOTLIGHT_VOLUME,
    TCC, USERS, WIFI, WIFI_LOG,
};

fn read(name: &str) -> Vec<u8> {
    let raw = std::fs::read(format!(
        "{}/tests/fixtures/macos/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    if !std::path::Path::new(name)
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("gz"))
    {
        return raw;
    }
    let mut data = Vec::new();
    common::gzip::Decoder::new(raw.as_slice())
        .read_to_end(&mut data)
        .unwrap();
    data
}

fn parse(fixture: &str, path: &str, log: &[u8]) -> Vec<Record> {
    parse_modified(fixture, path, log, None)
}

/// As [`parse`], the file last modified at `modified`.
fn parse_modified(fixture: &str, path: &str, log: &[u8], modified: Option<Ts>) -> Vec<Record> {
    let data = read(fixture);
    assert_eq!(MacosAdapter.probe(path, &data), Confidence::Certain);
    assert_conforms(&MacosAdapter, path, &data);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name: path,
        data: &data,
        modified,
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

#[test]
fn usage_databases() {
    let apps = parse(
        "application_usage.sqlite",
        "private/var/db/application_usage.sqlite",
        &[],
    );
    assert_eq!(apps.len(), 5);
    assert!(apps.iter().all(|r| r.namespace() == APP_USAGE));
    assert_eq!(
        apps[0].summary,
        "App launch /Applications/Safari.app (1 times)"
    );

    let versions = parse(
        "document_versions.sql",
        ".DocumentRevisions-V100/db-V1/db.sqlite",
        &[],
    );
    assert_eq!(versions.len(), 4);
    assert!(versions.iter().all(|r| r.namespace() == DOCUMENT_VERSIONS));
    assert_eq!(
        versions[0].facets.file_path.as_deref(),
        Some("/Users/moxilo/Documents/Spain is beautiful.rtf")
    );
    assert_eq!(versions[0].fields.get("Uid"), Some(&Value::UInt(501)));

    let notes = parse(
        "NotesV7.storedata",
        "Users/a/Library/Containers/com.apple.Notes/Data/Library/Notes/NotesV7.storedata",
        &[],
    );
    assert_eq!(notes.len(), 3);
    assert!(notes.iter().all(|r| r.namespace() == NOTES));

    let notifications = parse(
        "mac_notificationcenter.db",
        "private/var/folders/xy/abc/0/com.apple.notificationcenter/db2/db",
        &[],
    );
    assert_eq!(notifications.len(), 6);
    assert!(notifications.iter().all(|r| r.namespace() == NOTIFICATIONS));
    assert_eq!(
        notifications[0].summary,
        "Notification from com.google.santagui: Santa - KeePassXC can now be run"
    );
}

#[test]
fn spotlight_preferences() {
    let searches = parse(
        "com.apple.spotlight.plist",
        "Users/alice/Library/Preferences/com.apple.spotlight.plist",
        &[],
    );
    assert_eq!(searches.len(), 9);
    assert!(searches.iter().all(|r| r.namespace() == SPOTLIGHT_SEARCHES));
    let wifi = searches
        .iter()
        .find(|r| r.fields.get("Term") == Some(&Value::from("wifi")))
        .unwrap();
    assert_eq!(
        wifi.summary,
        "macOS Spotlight search: wifi -> /Users/moxilo/RHUL/Project/Parsers/wifi/wifi.py"
    );
    assert_eq!(wifi.times[0].kind, TimeKind::LastSeen);
    assert_eq!(wifi.facets.user_name.as_deref(), Some("alice"));
    assert_eq!(
        wifi.facets.file_path.as_deref(),
        Some("/Users/moxilo/RHUL/Project/Parsers/wifi/wifi.py")
    );
    let stores = parse(
        "VolumeConfiguration.plist",
        ".Spotlight-V100/VolumeConfiguration.plist",
        &[],
    );
    assert_eq!(stores.len(), 2);
    assert!(stores.iter().all(|r| r.namespace() == SPOTLIGHT_VOLUME));
    assert!(stores.iter().any(|r| r.summary
        == "macOS Spotlight store: 4D4BFEB5-7FE6-4033-AAAA-AAAABBBBCCCCDDDD -> /.MobileBackups"));
}

#[test]
fn messages() {
    let records = parse(
        "imessage_chat.db.gz",
        "Users/alice/Library/Messages/chat.db",
        &[],
    );
    assert_eq!(records.len(), 10);
    assert!(records.iter().all(|r| r.namespace() == MESSAGES));
    let sent = &records[1];
    assert!(sent
        .summary
        .starts_with("iMessage to 447775455555: Hi Eireanne, I would get one"));
    assert_eq!(sent.fields.get("FromMe"), Some(&Value::Bool(true)));
    assert_eq!(sent.facets.user_name.as_deref(), Some("alice"));
    let received = &records[0];
    assert_eq!(
        received.times.iter().map(|t| t.kind).collect::<Vec<_>>(),
        [TimeKind::Logged, TimeKind::Other, TimeKind::Accessed]
    );
}

#[test]
fn keychain_items_without_secrets() {
    let records = parse(
        "login.keychain",
        "Users/alice/Library/Keychains/login.keychain",
        &[],
    );
    assert_eq!(records.len(), 8);
    assert!(records.iter().all(|r| r.namespace() == KEYCHAIN));
    let gmail = records
        .iter()
        .find(|r| r.fields.get("Server") == Some(&Value::from("imap.gmail.com")))
        .unwrap();
    assert_eq!(
        gmail.summary,
        "Keychain internet password: imap.gmail.com moxilo at imap.gmail.com"
    );
    assert_eq!(gmail.fields.get("Account"), Some(&Value::from("moxilo")));
    assert_eq!(
        gmail.times.iter().map(|t| t.kind).collect::<Vec<_>>(),
        [TimeKind::Created, TimeKind::Modified]
    );
    // A key's binary label is no name.
    assert!(records
        .iter()
        .filter(|r| r.fields.get("Kind") == Some(&Value::from("symmetric key")))
        .all(|r| !r.fields.contains_key("Name")));
}

fn iso(record: &Record) -> Option<String> {
    record.times.first().and_then(|t| t.ts.to_iso8601())
}

#[test]
fn wifi_log_lines_dated_by_the_file() {
    // 2015-01-02T12:00:00Z: the last line is in 2015, and the first,
    // before the turn of the year, in 2014 (as plaso dates them given a
    // file last changed in 2015).
    let modified = Ts::from_unix_seconds(1_420_200_000);
    let path = "private/var/log/wifi.log";
    let records = parse_modified("wifi.log", path, &[], Some(modified));
    assert_eq!(records.len(), 10);
    assert!(records.iter().all(|r| r.namespace() == WIFI_LOG));
    assert_eq!(
        iso(&records[0]).as_deref(),
        Some("2014-11-14T20:14:37.1230000")
    );
    assert_eq!(
        iso(&records[9]).as_deref(),
        Some("2015-01-01T01:12:17.3110000")
    );
    assert!(records
        .iter()
        .all(|r| r.fields.get("YearInferred") == Some(&Value::Bool(true))));
    assert_eq!(
        records[0].fields.get("TimeText"),
        Some(&Value::from("Thu Nov 14 20:14:37.123"))
    );
    let interface = &records[1];
    assert_eq!(
        interface.fields.get("Process"),
        Some(&Value::from("airportd"))
    );
    assert_eq!(interface.fields.get("Pid"), Some(&Value::UInt(88)));
    assert_eq!(interface.facets.process_id, Some(88));
    assert_eq!(
        interface.fields.get("Function"),
        Some(&Value::from("airportdProcessDLILEvent"))
    );
    assert_eq!(interface.fields.get("Interface"), Some(&Value::from("en0")));
    assert_eq!(
        interface.fields.get("InterfaceEvent"),
        Some(&Value::from("attached (up)"))
    );
    assert_eq!(
        records[2].fields.get("Ssid"),
        Some(&Value::from("CampusNet"))
    );
    let joined = &records[6];
    for (name, value) in [
        ("Ssid", "AndroidAP"),
        ("Bssid", "88:30:8a:7a:61:88"),
        ("Security", "WPA2 Personal"),
    ] {
        assert_eq!(joined.fields.get(name), Some(&Value::from(value)), "{name}");
    }
    assert_eq!(joined.fields.get("Rssi"), Some(&Value::Int(-21)));
    assert!(joined
        .summary
        .starts_with("Wi-Fi airportd _processSystemPSKAssoc: No password for network"));
}

#[test]
fn wifi_log_lines_without_the_file_time() {
    let records = parse("wifi.log", "wifi.log", &[]);
    assert_eq!(records.len(), 10);
    assert!(records.iter().all(|r| r.times.is_empty()));
    assert!(records
        .iter()
        .all(|r| r.fields.get("YearInferred") == Some(&Value::Bool(false))));
    assert_eq!(
        records[9].fields.get("TimeText"),
        Some(&Value::from("Wed Jan  1 01:12:17.311"))
    );
    let rotated = parse_modified(
        "wifi_turned_over.log",
        "private/var/log/wifi.log.1",
        &[],
        Some(Ts::from_unix_seconds(1_420_200_000)),
    );
    assert_eq!(rotated.len(), 6);
    assert_eq!(
        rotated[0].facets.host_name.as_deref(),
        Some("test-macbookpro")
    );
    assert_eq!(rotated[0].facets.process_id, Some(50_498));
    assert_eq!(
        iso(&rotated[0]).as_deref(),
        Some("2015-01-02T00:10:15.0000000")
    );
    // Another log by the same name is not Wi-Fi's.
    assert_eq!(
        MacosAdapter.probe("wifi.log", b"2023-06-08 14:51:38.987368 <Notice>: x\n"),
        Confidence::No
    );
}

#[test]
fn launchd_log_lines() {
    let path = "private/var/log/com.apple.xpc.launchd/launchd.log.1";
    let records = parse("macos_launchd.log.gz", path, &[]);
    assert_eq!(records.len(), 36_609);
    assert!(records.iter().all(|r| r.namespace() == LAUNCHD_LOG));
    assert!(records.iter().all(|r| r.times.len() == 1));
    let spawned = &records[861];
    assert_eq!(
        spawned.fields.get("Process"),
        Some(&Value::from("system/com.apple.locationd [117]"))
    );
    assert_eq!(
        spawned.fields.get("Label"),
        Some(&Value::from("com.apple.locationd"))
    );
    assert_eq!(spawned.fields.get("Pid"), Some(&Value::UInt(117)));
    assert_eq!(spawned.fields.get("Level"), Some(&Value::from("Notice")));
    assert_eq!(
        spawned.summary,
        "launchd (system/com.apple.locationd [117]) <Notice>: xpcproxy spawned with pid 117"
    );
    assert_eq!(iso(spawned).as_deref(), Some("2023-06-08T10:51:39.7296030"));
    let audio = &records[2203];
    assert_eq!(audio.facets.process_id, Some(241));
    assert_eq!(audio.fields.get("Label"), None);
    assert_eq!(
        records
            .iter()
            .filter(|r| r.fields.get("Level") == Some(&Value::from("Error")))
            .count(),
        1093
    );
    assert_eq!(
        MacosAdapter.probe(path, b"Thu Nov 14 20:14:37.123 ***Starting Up***\n"),
        Confidence::No
    );
}
