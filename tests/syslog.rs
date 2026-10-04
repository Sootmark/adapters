//! The syslog adapter on plaso's test files (Apache-2.0,
//! `tests/fixtures/syslog/`): the contract, what sshd and cron lines become,
//! and the year taken from the file's modification time.

use common::time::Ts;
use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, TimeKind, Value};
use sootmark_adapters::syslog::{SyslogAdapter, NAMESPACE};

fn read(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/syslog/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

/// Modified at noon UTC on 2026-12-01.
fn december_2026() -> Ts {
    Ts::from_unix_seconds(1_796_126_400)
}

fn parse(name: &str, modified: Option<Ts>) -> Collected {
    let data = read(name);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name,
        data: &data,
        modified,
    };
    let mut sink = Collected::default();
    SyslogAdapter
        .parse(&input, &mut sink)
        .expect("syslog entries");
    sink
}

#[test]
fn conforms_and_probes() {
    for name in [
        "syslog",
        "syslog_ssh.log",
        "syslog_cron.log",
        "syslog_rsyslog_SyslogProtocol23Format",
    ] {
        assert_conforms(&SyslogAdapter, name, &read(name));
    }
    let ssh = read("syslog_ssh.log");
    assert_eq!(
        SyslogAdapter.probe("var/log/auth.log", &ssh),
        Confidence::Certain
    );
    assert_eq!(
        SyslogAdapter.probe("var/log/secure.1", &ssh),
        Confidence::Certain
    );
    assert_eq!(SyslogAdapter.probe("notes.txt", &ssh), Confidence::Maybe);
    assert_eq!(SyslogAdapter.probe("auth.log.2.gz", &ssh), Confidence::No);
    assert_eq!(SyslogAdapter.probe("notes.txt", b"hello\n"), Confidence::No);
}

#[test]
fn sshd_lines_name_the_account_and_address() {
    let records = parse("syslog_ssh.log", Some(december_2026())).records;
    assert_eq!(records.len(), 10);
    assert_eq!(records[0].namespace(), NAMESPACE);
    assert_eq!(
        records[0].summary,
        "sshd: Server listening on 0.0.0.0 port 22."
    );
    let login = &records[1];
    assert_eq!(
        login.summary,
        "SSH login plaso from 192.168.0.1 (publickey)"
    );
    assert_eq!(login.facets.user_name.as_deref(), Some("plaso"));
    assert_eq!(login.facets.source_ip.as_deref(), Some("192.168.0.1"));
    assert_eq!(login.facets.host_name.as_deref(), Some("osx-machine"));
    assert_eq!(login.facets.process_id, Some(3));
    assert_eq!(login.fields.get("Action"), Some(&Value::from("ssh login")));
    assert_eq!(login.fields.get("Port"), Some(&Value::UInt(59229)));
    assert_eq!(login.fields.get("YearInferred"), Some(&Value::Bool(true)));
    assert_eq!(login.times[0].kind, TimeKind::Logged);
    assert_eq!(
        records[5].summary,
        "SSH failed login root from 188.124.3.41 (password)"
    );
    assert_eq!(
        records[9].summary,
        "SSH failed login, invalid user admin from 192.168.1.92 (password)"
    );
}

#[test]
fn cron_commands() {
    let records = parse("syslog_cron.log", Some(december_2026())).records;
    assert_eq!(
        records[1].summary,
        "cron (root): sleep $(( 1 * 60 )); touch /tmp/afile.txt"
    );
    assert_eq!(
        records[1].facets.process_command_line.as_deref(),
        Some("sleep $(( 1 * 60 )); touch /tmp/afile.txt")
    );
}

#[test]
fn years_come_from_the_modification_time() {
    let dated = parse("syslog", Some(december_2026()));
    assert_eq!(dated.records.len(), 16);
    assert_eq!(
        dated.records.last().unwrap().times[0]
            .ts
            .to_iso8601()
            .unwrap(),
        "2026-11-18T08:31:20.0000000"
    );
    // Without it, classic lines are untimed and say so.
    let undated = parse("syslog", None).records;
    assert!(undated.iter().all(|r| r.times.is_empty()));
    assert_eq!(
        undated[0].fields.get("YearInferred"),
        Some(&Value::Bool(false))
    );
    assert_eq!(
        undated[0].fields.get("TimeText"),
        Some(&Value::from("Jan 22 07:52:33"))
    );
}

#[test]
fn rfc5424_priority() {
    let records = parse("syslog_rsyslog_SyslogProtocol23Format", None).records;
    let debug = &records[0];
    assert_eq!(debug.fields.get("Facility"), Some(&Value::UInt(1)));
    assert_eq!(debug.fields.get("Severity"), Some(&Value::UInt(7)));
    assert_eq!(debug.fields.get("MessageId"), Some(&Value::from("123")));
    assert_eq!(debug.summary, "log_tag: this is debug");
}

#[test]
fn esxi_shell_commands_and_vsphere_logins() {
    // Synthetic lines in the format ESXi documents.
    let data = b"2023-04-10T08:15:02.123Z In(14) shell[2101]: [root]: vim-cmd vmsvc/power.off 12\n\
2023-04-10T08:16:40.010Z In(166) Hostd[2099566]: [Originator@6876 sub=Vimsvc.ha-eventmgr] Event 112 : User root@198.51.100.7 logged in as VMware-client/6.5.0\n";
    assert_eq!(
        SyslogAdapter.probe("var/log/shell.log", data),
        Confidence::Certain
    );
    let input = Input {
        evidence: EvidenceId::of_content(data),
        name: "var/log/shell.log",
        data,
        modified: None,
    };
    let mut sink = Collected::default();
    SyslogAdapter.parse(&input, &mut sink).unwrap();
    let records = sink.records;
    assert_eq!(
        records[0].summary,
        "ESXi shell (root): vim-cmd vmsvc/power.off 12"
    );
    assert_eq!(
        records[0].facets.process_command_line.as_deref(),
        Some("vim-cmd vmsvc/power.off 12")
    );
    assert_eq!(records[1].summary, "vSphere login root from 198.51.100.7");
}
