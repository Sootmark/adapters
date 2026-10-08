//! The access log adapter on plaso's test logs (Apache-2.0,
//! `tests/fixtures/weblogs/`, stored gzip-compressed): recognition and
//! the records, AWS Elastic Load Balancing's and Azure Application
//! Gateway's too, and Atlassian's application and audit logs.

use std::io::Read;

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, TimeKind, Value};
use sootmark_adapters::weblogs::{
    WeblogsAdapter, ACCESS, ATLASSIAN, ATLASSIAN_APPLICATION, ATLASSIAN_AUDIT, AZURE_GATEWAY,
    BITBUCKET, ELB,
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

#[test]
fn atlassian_application_entries() {
    // As many as the weblogs crate reads from each, all as plaso does.
    for (file, name, count, product) in [
        (
            "atlassian-confluence.log",
            "confluence/logs/atlassian-confluence.log",
            4,
            "Confluence",
        ),
        (
            "atlassian-jira.log",
            "jira/log/atlassian-jira.log.1",
            7,
            "Jira",
        ),
        (
            "atlassian-bitbucket.log",
            "bitbucket/log/atlassian-bitbucket.log",
            6,
            "Bitbucket",
        ),
    ] {
        let sink = collect(name, &fixture(file));
        assert_eq!(sink.records.len(), count, "{name}");
        assert!(sink
            .records
            .iter()
            .all(|r| r.namespace() == ATLASSIAN_APPLICATION
                && r.fields.get("Product") == Some(&Value::from(product))));
    }
    let sink = collect(
        "atlassian-confluence.log",
        &fixture("atlassian-confluence.log"),
    );
    let started = &sink.records[0];
    for (name, value) in [
        ("Level", "INFO"),
        ("Thread", "Catalina-utility-1"),
        (
            "Logger",
            "confluence.cluster.hazelcast.HazelcastClusterManager",
        ),
        ("Method", "startCluster"),
        ("Message", "Starting the cluster."),
    ] {
        assert_eq!(
            started.fields.get(name),
            Some(&Value::from(value)),
            "{name}"
        );
    }
    assert_eq!(
        started.summary,
        "Confluence INFO confluence.cluster.hazelcast.HazelcastClusterManager: Starting the cluster."
    );
    assert_eq!(started.times[0].kind, TimeKind::Logged);
    let sink = collect(
        "atlassian-bitbucket.log",
        &fixture("atlassian-bitbucket.log"),
    );
    let created = &sink.records[1];
    assert_eq!(created.facets.user_name.as_deref(), Some("admin"));
    assert_eq!(created.facets.source_ip.as_deref(), Some("10.229.31.195"));
    assert_eq!(
        created.fields.get("Action"),
        Some(&Value::from("TransactionService/Transact"))
    );
    assert_eq!(
        created.fields.get("RequestId"),
        Some(&Value::from("2CM38K4Fx339x113x2"))
    );
    assert_eq!(
        sink.records[5].fields.get("Context"),
        Some(&Value::from("!!!"))
    );
}

#[test]
fn atlassian_audit_events() {
    let sink = collect(
        "bitbucket/log/audit/atlassian-bitbucket-audit.log",
        &fixture("atlassian-bitbucket-audit.log"),
    );
    assert_eq!(sink.records.len(), 5);
    assert!(sink
        .records
        .iter()
        .all(|r| r.namespace() == ATLASSIAN_AUDIT));
    let created = &sink.records[2];
    assert_eq!(
        created.summary,
        "RepositoryCreatedEvent by jsmith on PROJECT/myproject from 63.246.22.199,172.16.1.187"
    );
    assert_eq!(
        created.facets.source_ip.as_deref(),
        Some("63.246.22.199,172.16.1.187")
    );
    assert_eq!(created.facets.user_name.as_deref(), Some("jsmith"));
    for (name, value) in [
        ("Action", "RepositoryCreatedEvent"),
        ("User", "jsmith"),
        ("Object", "PROJECT/myproject"),
        ("RequestId", "@8KJQAGx969x543x0"),
        ("Session", "tmpqqw"),
    ] {
        assert_eq!(
            created.fields.get(name),
            Some(&Value::from(value)),
            "{name}"
        );
    }
    assert_eq!(
        created.times[0].ts.to_iso8601().as_deref(),
        Some("2014-05-21T14:09:33.4330000Z")
    );
    assert_eq!(sink.records[4].summary, "UserLoggedInEvent from 10.1.1.100");

    // The Data Center audit log file, a line as Atlassian documents it.
    let line = br#"{"affectedObjects":[{"id":"10100","name":"jsmith","type":"USER"}],"auditType":{"action":"User created","area":"USER_MANAGEMENT"},"author":{"id":"10000","name":"admin","type":"user"},"source":"192.0.2.10","timestamp":{"epochSecond":1696320045,"nano":317000000}}
"#;
    let sink = collect("jira/log/audit/20231003-00000.audit.log", line);
    let event = &sink.records[0];
    assert_eq!(event.namespace(), ATLASSIAN_AUDIT);
    assert_eq!(
        event.summary,
        "User created by admin on jsmith (USER) from 192.0.2.10"
    );
    assert_eq!(
        event.fields.get("Area"),
        Some(&Value::from("USER_MANAGEMENT"))
    );
    assert_eq!(event.fields.get("AuthorId"), Some(&Value::from("10000")));
    assert_eq!(WeblogsAdapter.probe("events.json", line), Confidence::No);
}

#[test]
fn other_log4j_logs_are_not_atlassian_logs() {
    let data = fixture("atlassian-jira.log");
    assert_eq!(
        WeblogsAdapter.probe("tomcat/logs/catalina.log", &data),
        Confidence::No
    );
    assert_eq!(
        WeblogsAdapter.probe("atlassian-jira-security.log", &data),
        Confidence::No
    );
    let data = fixture("atlassian-bitbucket-audit.log");
    assert_eq!(WeblogsAdapter.probe("pipes.log", &data), Confidence::No);
}
