//! The notifications adapter on plaso's `wpndatabase.db` (Apache-2.0,
//! `tests/fixtures/notifications/`, stored gzip-compressed): recognition,
//! the contract, notifications and handlers.

use std::io::Read;

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, TimeKind, Value};
use sootmark_adapters::notifications::{NotificationsAdapter, HANDLERS, NOTIFICATIONS};

const PATH: &str = r"C\Users\alice\AppData\Local\Microsoft\Windows\Notifications\wpndatabase.db";

fn database() -> Vec<u8> {
    let compressed = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/notifications/wpndatabase.db.gz"
    ))
    .unwrap();
    let mut data = Vec::new();
    common::gzip::Decoder::new(compressed.as_slice())
        .read_to_end(&mut data)
        .unwrap();
    data
}

#[test]
fn notifications_and_handlers() {
    let data = database();
    assert_eq!(
        NotificationsAdapter.probe(PATH, &data[..100]),
        Confidence::Certain
    );
    assert_eq!(
        NotificationsAdapter.probe("History", &data[..100]),
        Confidence::No
    );
    assert_conforms(&NotificationsAdapter, PATH, &data);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name: PATH,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    NotificationsAdapter.parse(&input, &mut sink).unwrap();
    assert!(sink.skipped.is_empty(), "{:?}", sink.skipped);
    let count = |namespace| {
        sink.records
            .iter()
            .filter(|r| r.namespace() == namespace)
            .count()
    };
    assert_eq!(count(NOTIFICATIONS), 6);
    assert_eq!(count(HANDLERS), 68);
    let toast = &sink.records[0];
    assert_eq!(
        toast.summary,
        "Notification (toast) from windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel: Setting up a device - We're setting up 'PCI Device'."
    );
    assert_eq!(toast.times[0].kind, TimeKind::Logged);
    assert_eq!(toast.facets.user_name.as_deref(), Some("alice"));
    assert_eq!(toast.fields.get("Type"), Some(&Value::from("toast")));
    assert!(
        matches!(toast.fields.get("Payload"), Some(Value::Text(xml)) if xml.contains("<toast"))
    );
}
