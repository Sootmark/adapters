//! The access log adapter on plaso's test logs (Apache-2.0,
//! `tests/fixtures/weblogs/`, stored gzip-compressed): recognition and
//! the records, AWS Elastic Load Balancing's and Azure Application
//! Gateway's too.

use std::io::Read;

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, TimeKind, Value};
use sootmark_adapters::weblogs::{
    WeblogsAdapter, ACCESS, ATLASSIAN, AZURE_GATEWAY, BITBUCKET, ELB,
};

fn fixture(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/tests/fixtures/weblogs/{name}.gz",
        env!("CARGO_MANIFEST_DIR")
    );
    let compressed = std::fs::read(path).unwrap();
    let mut data = Vec::new();
    common::gzip::Decoder::new(compressed.as_slice())
        .read_to_end(&mut data)
        .unwrap();
    data
}

fn collect(name: &str, data: &[u8]) -> Collected {
    assert_eq!(
        WeblogsAdapter.probe(name, data),
        Confidence::Certain,
        "{name}"
    );
    assert_conforms(&WeblogsAdapter, name, data);
    let input = Input {
        evidence: EvidenceId::of_content(data),
        name,
        data,
        modified: None,
    };
    let mut sink = Collected::default();
    WeblogsAdapter.parse(&input, &mut sink).unwrap();
    assert!(sink.skipped.is_empty(), "{:?}", sink.skipped);
    sink
}

#[test]
fn apache_requests() {
    let sink = collect("var/log/apache2/access.log", &fixture("apache_access.log"));
    assert_eq!(sink.records.len(), 15);
    assert!(sink.records.iter().all(|r| r.namespace() == ACCESS));
    let shell = sink
        .records
        .iter()
        .find(|r| {
            r.summary
                == "192.168.0.2 GET /wp-content/themes/darkmode/evil.php?cmd=uname+-a HTTP/1.1 200"
        })
        .unwrap();
    assert_eq!(shell.facets.source_ip.as_deref(), Some("192.168.0.2"));
    assert_eq!(
        shell.fields.get("Uri"),
        Some(&Value::from(
            "/wp-content/themes/darkmode/evil.php?cmd=uname+-a"
        ))
    );
    assert_eq!(shell.fields.get("Status"), Some(&Value::UInt(200)));
}

#[test]
fn atlassian_requests() {
    let sink = collect(
        "atlassian/jira/logs/access_log.2022-10-03",
        &fixture("jira_access_post9.4.log"),
    );
    assert_eq!(sink.records.len(), 2);
    assert_eq!(sink.records[0].namespace(), ATLASSIAN);
    assert_eq!(
        sink.records[0].fields.get("ForwardedFor"),
        Some(&Value::from("10.0.0.5"))
    );
    assert_eq!(sink.records[0].facets.user_name.as_deref(), Some("admin"));
    let sink = collect(
        "atlassian-bitbucket-access.log",
        &fixture("atlassian-bitbucket-access.log"),
    );
    assert_eq!(sink.records.len(), 8);
    assert_eq!(sink.records[0].namespace(), BITBUCKET);
    let ssh = sink
        .records
        .iter()
        .find(|r| r.fields.get("Method") == Some(&Value::from("SSH")))
        .unwrap();
    assert_eq!(
        ssh.fields.get("Repository"),
        Some(&Value::from("/stash/stash.git"))
    );
    assert_eq!(ssh.fields.get("Labels"), Some(&Value::from("push")));
}

#[test]
fn load_balancer_and_gateway_requests() {
    let sink = collect(
        "AWSLogs/123456789012/elasticloadbalancing/us-east-2/aws_elb_access.log",
        &fixture("aws_elb_access.log"),
    );
    assert_eq!(sink.records.len(), 16);
    assert!(sink.records.iter().all(|r| r.namespace() == ELB));
    let first = &sink.records[0];
    assert_eq!(
        first.summary,
        "192.168.1.10 GET https://www.domain.name:443/ HTTP/1.1 200"
    );
    assert_eq!(first.facets.source_ip.as_deref(), Some("192.168.1.10"));
    assert_eq!(first.fields.get("ClientPort"), Some(&Value::from("44325")));
    // An application load balancer says when the request came in.
    assert_eq!(
        first.times.iter().map(|t| t.kind).collect::<Vec<_>>(),
        [TimeKind::Logged, TimeKind::Other]
    );
    assert_eq!(first.times[1].field, "Started");

    let sink = collect(
        "PT1H.json",
        &fixture("azure_application_gateway_access.json"),
    );
    assert_eq!(sink.records.len(), 2);
    assert!(sink.records.iter().all(|r| r.namespace() == AZURE_GATEWAY));
    assert_eq!(sink.records[0].summary, "185.42.129.24 GET / HTTP/1.1 200");
    assert_eq!(
        sink.records[0].fields.get("InstanceId"),
        Some(&Value::from("appgw_2"))
    );
}

#[test]
fn other_text_is_not_an_access_log() {
    assert_eq!(
        WeblogsAdapter.probe("x.log", b"hello\nworld\n"),
        Confidence::No
    );
}
