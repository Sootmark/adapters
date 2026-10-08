//! The registry adapter on plaso's test SAM (Apache-2.0,
//! `tests/fixtures/sam/`, gzip-compressed): a record per local account and
//! per group membership.

use std::io::Read;

use model::adapter::{Adapter, Collected, Input};
use model::{EvidenceId, TimeKind, Value};
use sootmark_adapters::registry::{RegistryAdapter, SAM_GROUPS, SAM_USERS};

#[test]
fn accounts_and_memberships() {
    let compressed = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/sam/plaso-SAM.gz"
    ))
    .unwrap();
    let mut data = Vec::new();
    common::gzip::Decoder::new(compressed.as_slice())
        .read_to_end(&mut data)
        .unwrap();
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name: "C/Windows/System32/config/SAM",
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    RegistryAdapter.parse(&input, &mut sink).unwrap();
    let users: Vec<_> = sink
        .records
        .iter()
        .filter(|r| r.namespace() == SAM_USERS)
        .collect();
    assert_eq!(users.len(), 3);
    let gold = users
        .iter()
        .find(|r| r.facets.user_name.as_deref() == Some("gold_administrator"))
        .unwrap();
    assert_eq!(
        gold.summary,
        "Local account gold_administrator (RID 1001): 4 logons"
    );
    assert!(gold.times.iter().any(|t| t.kind == TimeKind::Created));
    let guest = users
        .iter()
        .find(|r| r.fields.get("Rid") == Some(&Value::UInt(501)))
        .unwrap();
    assert_eq!(guest.fields.get("Disabled"), Some(&Value::Bool(true)));

    let admins: Vec<_> = sink
        .records
        .iter()
        .filter(|r| {
            r.namespace() == SAM_GROUPS && r.fields.get("GroupRid") == Some(&Value::UInt(544))
        })
        .collect();
    assert!(admins.len() >= 2);
    assert_eq!(
        admins[1].summary,
        "S-1-5-21-4070822719-3404542230-2541167049-1001 is a member of Administrators"
    );
}
