//! The cloud audit log adapter on export formats written for the
//! sootmark-cloudlogs tests (`tests/fixtures/cloudlogs/`): recognition and
//! the records.

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, Value};
use sootmark_adapters::cloudlogs::{CloudlogsAdapter, CLOUDTRAIL, ENTRA_SIGNIN, M365};

fn collect(name: &str) -> Collected {
    let data = std::fs::read(format!(
        "{}/tests/fixtures/cloudlogs/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    assert_eq!(
        CloudlogsAdapter.probe(name, &data),
        Confidence::Certain,
        "{name}"
    );
    assert_conforms(&CloudlogsAdapter, name, &data);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    CloudlogsAdapter.parse(&input, &mut sink).unwrap();
    assert!(sink.skipped.is_empty(), "{:?}", sink.skipped);
    sink
}

#[test]
fn cloudtrail_files() {
    let sink = collect("cloudtrail-s3.json");
    assert_eq!(sink.records.len(), 3);
    let denied = &sink.records[1];
    assert_eq!(denied.namespace(), CLOUDTRAIL);
    assert_eq!(
        denied.summary,
        "CloudTrail: BackupRole PutBucketPolicy arn:aws:s3:::finance-exports from 198.51.100.23 (AccessDenied)"
    );
    assert_eq!(
        denied.fields.get("userIdentity.arn"),
        Some(&Value::from(
            "arn:aws:sts::111122223333:assumed-role/BackupRole/backup-job"
        ))
    );
    assert_eq!(denied.facets.source_ip.as_deref(), Some("198.51.100.23"));
}

#[test]
fn microsoft_365_and_entra() {
    let sink = collect("m365-purview.csv");
    assert_eq!(sink.records.len(), 3);
    assert_eq!(sink.records[0].namespace(), M365);
    assert_eq!(
        sink.records[0].fields.get("Parameters.2.Value"),
        Some(&Value::from("True"))
    );
    assert_eq!(
        sink.records[2].fields.get("UserAgent"),
        Some(&Value::from("python-requests/2.31.0"))
    );
    let sink = collect("entra-signins.json");
    assert_eq!(sink.records[0].namespace(), ENTRA_SIGNIN);
    assert_eq!(
        sink.records[0].facets.user_name.as_deref(),
        Some("bob@contoso.example")
    );
    assert_eq!(
        sink.records[1].fields.get("Result"),
        Some(&Value::from("Success"))
    );
}

#[test]
fn other_json_is_not_a_cloud_log() {
    assert_eq!(
        CloudlogsAdapter.probe("x.json", br#"{"name":"x"}"#),
        Confidence::No
    );
}
