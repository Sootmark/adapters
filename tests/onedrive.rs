//! The OneDrive adapter on plaso's test logs (Apache-2.0,
//! `tests/fixtures/onedrive/`): a sync engine log read with and without
//! its `ObfuscationStringMap.txt`, and SkyDrive's text logs of both
//! layouts.

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Companion, Confidence, Input};
use model::{EvidenceId, Value};
use sootmark_adapters::onedrive::{OneDriveAdapter, NAMESPACE};

const LOGS: &str = r"C\Users\alice\AppData\Local\Microsoft\OneDrive\logs\Personal";

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/onedrive/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn collect(path: &str, data: &[u8], companions: &[Companion<'_>]) -> Collected {
    assert_eq!(
        OneDriveAdapter.probe(path, data),
        Confidence::Certain,
        "{path}"
    );
    assert_conforms(&OneDriveAdapter, path, data);
    let input = Input {
        evidence: EvidenceId::of_content(data),
        name: path,
        data,
        modified: None,
    };
    let mut sink = Collected::default();
    OneDriveAdapter
        .parse_with_companions(&input, companions, &mut sink)
        .unwrap();
    sink
}

#[test]
fn sync_engine_log_deobfuscated_with_its_map() {
    let path = format!(r"{LOGS}\SyncEngine-2022-11-24.2341.10688.1.odlgz");
    assert_eq!(
        OneDriveAdapter.companions(&path),
        ["ObfuscationStringMap.txt"]
    );
    let data = fixture("SyncEngine-2022-11-24.2341.10688.1.odlgz");
    let map = fixture("ObfuscationStringMap.txt");
    let companions = [Companion {
        name: "ObfuscationStringMap.txt",
        data: &map,
    }];
    let sink = collect(&path, &data, &companions);
    assert!(sink.skipped.is_empty(), "{:?}", sink.skipped);
    assert_eq!(sink.records.len(), 3038);
    assert!(sink.records.iter().all(|r| r.namespace() == NAMESPACE));
    assert_eq!(sink.records[0].facets.user_name.as_deref(), Some("alice"));
    assert_eq!(
        sink.records[0].summary,
        r"OneDrive TelemetryProxyConfigurationFile::Initialize: C:\Users\User\AppData\Local\Microsoft\OneDrive\logs\Personal\telemetry-dll-ramp-value.txt"
    );
    let restored = sink
        .records
        .iter()
        .filter(|r| r.fields.contains_key("ParametersAsStored"))
        .count();
    assert!(restored > 0);

    // Without the map, the same records with the words as stored.
    let plain = collect(&path, &data, &[]);
    assert_eq!(plain.records.len(), 3038);
    assert!(plain
        .records
        .iter()
        .all(|r| !r.fields.contains_key("ParametersAsStored")
            && r.fields.get("Deobfuscated") == Some(&Value::Bool(false))));
}

#[test]
fn skydrive_text_logs() {
    let sink = collect(
        r"C\Users\alice\AppData\Local\Microsoft\SkyDrive\logs\SyncDiagnostics.log",
        &fixture("skydrive.log"),
        &[],
    );
    assert_eq!(sink.records.len(), 17);
    assert!(sink
        .records
        .iter()
        .any(|r| r.summary == "SkyDrive VRB telemetry.cpp(158): QoS enabled,"));
    let sink = collect(
        r"C\Users\alice\AppData\Local\Microsoft\SkyDrive\logs\skydrive_v1.log",
        &fixture("skydrive_v1.log"),
        &[],
    );
    // A line with an impossible date: an entry without a time, and a
    // problem.
    assert_eq!(sink.records.len(), 16);
    assert_eq!(sink.skipped.len(), 1);
    assert_eq!(
        sink.records[0].summary,
        "SkyDrive DETAIL global.cpp:626!logVersionInfo: 17.0.2011.0627 (Ship)"
    );
    // A text line alone, outside a OneDrive or SkyDrive folder, isn't taken.
    assert_eq!(
        OneDriveAdapter.probe("var/log/app.log", &fixture("skydrive_v1.log")),
        Confidence::No
    );
}
