//! The persistence adapter on the `persistence` crate's synthetic attack
//! files (`tests/fixtures/persistence/`, laid out as on the host): the
//! contract, recognition by path, entries with what runs and as whom, the
//! file's time, and flags.

use common::time::Ts;
use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, Record, TimeKind, Value};
use sootmark_adapters::persistence::{PersistenceAdapter, NAMESPACE};

fn read(path: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/persistence/{path}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn parse(path: &str) -> Vec<Record> {
    let data = read(path);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name: path,
        data: &data,
        modified: Some(Ts::from_unix_seconds(1_790_000_000)),
    };
    let mut sink = Collected::default();
    PersistenceAdapter
        .parse(&input, &mut sink)
        .expect("entries");
    sink.records
}

#[test]
fn conforms_and_probes_by_path() {
    for path in [
        "etc/crontab",
        "var/spool/cron/crontabs/alice",
        "etc/systemd/system/sysupdate.service",
        "home/alice/.ssh/authorized_keys",
        "etc/ld.so.preload",
        "etc/sudoers.d/90-backdoor",
    ] {
        assert_conforms(&PersistenceAdapter, path, &read(path));
    }
    // The host path, as intake gives it.
    assert_eq!(
        PersistenceAdapter.probe("/var/spool/cron/crontabs/alice", b""),
        Confidence::Certain
    );
    assert_eq!(
        PersistenceAdapter.probe("alice", b""),
        Confidence::No,
        "a bare name says nothing"
    );
    assert_eq!(PersistenceAdapter.probe("/etc/hosts", b""), Confidence::No);
}

#[test]
fn entries_flags_and_times() {
    let cron = parse("etc/cron.d/sysupdate");
    let job = &cron[0];
    assert_eq!(job.namespace(), NAMESPACE);
    assert_eq!(job.facets.user_name.as_deref(), Some("root"));
    assert!(job.summary.contains("flags:"), "{}", job.summary);
    assert!(matches!(job.fields.get("Flags"), Some(Value::Text(f)) if f.contains("base64")));
    assert_eq!(job.times[0].kind, TimeKind::Modified);

    let user = parse("var/spool/cron/crontabs/alice");
    let reboot = user
        .iter()
        .find(|r| r.fields.get("Schedule") == Some(&Value::from("@reboot")))
        .unwrap();
    assert_eq!(
        reboot.facets.user_name.as_deref(),
        Some("alice"),
        "the spool file's name"
    );
    assert!(reboot
        .facets
        .process_command_line
        .as_deref()
        .unwrap()
        .starts_with("nohup /var/tmp/.cache/agent"));

    let keys = parse("home/alice/.ssh/authorized_keys");
    assert!(keys.iter().all(
        |k| matches!(k.fields.get("Fingerprint"), Some(Value::Text(f)) if f.starts_with("SHA256:"))
    ));

    let preload = parse("etc/ld.so.preload");
    assert_eq!(
        preload[0].facets.process_command_line.as_deref(),
        Some("/usr/local/lib/libprocesshider.so")
    );
    assert!(preload[0].summary.contains("flags:"));
}
