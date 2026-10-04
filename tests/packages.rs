//! The packages adapter on logs of real installs and removals
//! (`tests/fixtures/packages/`, from the packages crate): the contract,
//! recognition, one record per change, apt's command and user.

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, Record, Value};
use sootmark_adapters::packages::PackagesAdapter;

fn parse(path: &str) -> Vec<Record> {
    let data = std::fs::read(format!(
        "{}/tests/fixtures/packages/{path}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let name = format!("var/log/{}", path.split_once('/').unwrap().1);
    assert_eq!(PackagesAdapter.probe(&name, &data), Confidence::Certain);
    assert_conforms(&PackagesAdapter, &name, &data);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name: &name,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    PackagesAdapter.parse(&input, &mut sink).unwrap();
    sink.records
}

fn field<'r>(record: &'r Record, name: &str) -> Option<&'r Value> {
    record.fields.get(name)
}

#[test]
fn apt_changes_carry_the_command_and_user() {
    let records = parse("debian/apt/history.log");
    let hello = records
        .iter()
        .find(|r| {
            field(r, "Package") == Some(&Value::from("hello"))
                && field(r, "Action") == Some(&Value::from("install"))
        })
        .unwrap();
    assert_eq!(hello.facets.user_name.as_deref(), Some("analyst"));
    assert!(hello
        .facets
        .process_command_line
        .as_deref()
        .is_some_and(|c| c.contains("install") && c.contains("hello")));
    assert!(hello.summary.starts_with("install hello "));
}

#[test]
fn dpkg_and_dnf_changes_without_steps() {
    let dpkg = parse("debian/dpkg.log");
    assert!(!dpkg.is_empty());
    assert!(dpkg.iter().all(|r| !matches!(
        field(r, "Action"),
        Some(Value::Text(a)) if a == "configure" || a == "trigger"
    )));
    let dnf = parse("rocky9/dnf.rpm.log");
    assert!(dnf
        .iter()
        .any(|r| field(r, "Action") == Some(&Value::from("remove"))));
    assert!(dnf
        .iter()
        .all(|r| field(r, "Log") == Some(&Value::from("dnf"))));
}
