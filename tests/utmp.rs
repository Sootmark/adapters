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
