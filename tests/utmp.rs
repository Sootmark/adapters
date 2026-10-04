//! The utmp adapter on plaso's test files (Apache-2.0,
//! `tests/fixtures/utmp/`): the contract, what each record becomes, and
//! damage reported.

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, Namespace, TimeKind};
use sootmark_adapters::utmp::{UtmpAdapter, NAMESPACE};

fn read(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/utmp/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn parse(name: &str) -> Collected {
    let data = read(name);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    UtmpAdapter.parse(&input, &mut sink).expect("login records");
    sink
}

#[test]
fn conforms_and_probes() {
    for name in ["utmp", "wtmp.1", "utmp_corrupted"] {
        assert_conforms(&UtmpAdapter, name, &read(name));
    }
    assert_eq!(
        UtmpAdapter.probe("var/log/wtmp", &read("wtmp.1")),
        Confidence::Certain
    );
    assert_eq!(
        UtmpAdapter.probe("btmp-20260901", &read("wtmp.1")),
        Confidence::Certain
    );
    assert_eq!(
        UtmpAdapter.probe("wtmp.1.gz", &read("wtmp.1")),
        Confidence::No
    );
    assert_eq!(UtmpAdapter.probe("passwd", &read("wtmp.1")), Confidence::No);
}

#[test]
fn records_say_what_happened() {
    let wtmp = parse("wtmp.1").records;
    assert_eq!(wtmp.len(), 2, "two unused slots left out");
    let login = &wtmp[0];
    assert_eq!(login.namespace(), NAMESPACE);
    assert_eq!(login.summary, "Login userA from 10.10.122.1 on pts/32");
    assert_eq!(login.facets.user_name.as_deref(), Some("userA"));
    assert_eq!(login.facets.source_ip.as_deref(), Some("10.10.122.1"));
    assert_eq!(login.facets.process_id, Some(20060));
    assert_eq!(login.times[0].kind, TimeKind::Logged);
    assert_eq!(
        login.times[0].ts.to_iso8601().unwrap(),
        "2011-12-01T17:36:38.4329350Z"
    );
    assert_eq!(wtmp[1].summary, "Logout on pts/89 (pid 20060)");

    let utmp = parse("utmp").records;
    assert_eq!(utmp.len(), 14);
    assert_eq!(utmp[0].summary, "Boot, kernel 3.8.0-33-generic");
    assert_eq!(utmp[2].summary, "Login prompt on tty4");
    assert_eq!(utmp[9].summary, "Login moxilo from :0 on pts/0");

    // Read as btmp, a login is a failed one.
    let data = read("wtmp.1");
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name: "btmp.1",
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    UtmpAdapter.parse(&input, &mut sink).unwrap();
    assert_eq!(
        sink.records[0].summary,
        "Failed login userA from 10.10.122.1 on pts/32"
    );
}

#[test]
fn damage_is_reported() {
    let output = parse("utmp_corrupted");
    assert_eq!(output.records.len(), 2);
    assert_eq!(output.skipped.len(), 3, "{:?}", output.skipped);
    assert!(output
        .records
        .iter()
        .all(|r| r.namespace() == Namespace::new("linux.utmp")));
}

/// A `lastlog` with root's login at UID 0 and alice's at 1000, built as
/// x86-64 glibc writes it: 292-byte records, zeros between.
#[test]
fn lastlog_logins() {
    let mut data = vec![0u8; 292 * 1001];
    for (uid, seconds, line, host) in [
        (0, 1_790_000_000u32, "tty1", ""),
        (1000, 1_790_003_600, "pts/0", "198.51.100.7"),
    ] {
        let at = uid * 292;
        data[at..at + 4].copy_from_slice(&seconds.to_le_bytes());
        data[at + 4..at + 4 + line.len()].copy_from_slice(line.as_bytes());
        data[at + 36..at + 36 + host.len()].copy_from_slice(host.as_bytes());
    }
    assert_eq!(
        UtmpAdapter.probe("var/log/lastlog", &data),
        Confidence::Certain
    );
    assert_conforms(&UtmpAdapter, "lastlog", &data);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name: "var/log/lastlog",
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    UtmpAdapter.parse(&input, &mut sink).unwrap();
    let summaries: Vec<_> = sink.records.iter().map(|r| r.summary.as_str()).collect();
    assert_eq!(
        summaries,
        [
            "Last login of uid 0 on tty1",
            "Last login of uid 1000 from 198.51.100.7 on pts/0"
        ]
    );
    assert_eq!(
        sink.records[1].facets.source_ip.as_deref(),
        Some("198.51.100.7")
    );
    assert_eq!(sink.records[1].times[0].kind, TimeKind::Logged);
}

/// wtmpdb and lastlog2 databases (`tests/fixtures/utmp/sqlite/`, from the
/// utmp crate): sessions with their login and logout, last logins.
#[test]
fn wtmpdb_and_lastlog2() {
    let read_db = |name: &str| read(&format!("sqlite/{name}"));
    let wtmp = read_db("wtmp.db");
    assert_eq!(
        UtmpAdapter.probe("var/lib/wtmpdb/wtmp.db", &wtmp),
        Confidence::Certain
    );
    assert_eq!(
        UtmpAdapter.probe("var/lib/wtmpdb/wtmp.db", b"junk"),
        Confidence::No
    );
    assert_conforms(&UtmpAdapter, "wtmp.db", &wtmp);
    let collect = |name: &str, data: &[u8]| {
        let input = Input {
            evidence: EvidenceId::of_content(data),
            name,
            data,
            modified: None,
        };
        let mut sink = Collected::default();
        UtmpAdapter.parse(&input, &mut sink).unwrap();
        sink.records
    };
    let sessions = collect("var/lib/wtmpdb/wtmp.db", &wtmp);
    let summaries: Vec<_> = sessions.iter().map(|r| r.summary.as_str()).collect();
    assert_eq!(
        summaries,
        [
            "Boot, kernel 6.12.48+deb13-amd64",
            "Login alice from 192.0.2.15 on pts/0",
            "Login root on tty1, not logged out",
            "Login deploy from 2001:db8::7 on pts/1",
        ]
    );
    assert_eq!(sessions[1].times.len(), 2);
    assert_eq!(sessions[1].facets.user_name.as_deref(), Some("alice"));
    assert_eq!(sessions[0].facets.user_name, None);

    let lastlog2 = read_db("lastlog2.db");
    assert_conforms(&UtmpAdapter, "lastlog2.db", &lastlog2);
    let logins = collect("var/lib/lastlog/lastlog2.db", &lastlog2);
    assert_eq!(
        logins[1].summary,
        "Last login of alice from 192.0.2.15 on pts/0"
    );
    assert_eq!(logins[1].facets.source_ip.as_deref(), Some("192.0.2.15"));
}
