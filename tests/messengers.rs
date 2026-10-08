//! The messengers adapter on plaso's Skype `main.db` (Apache-2.0,
//! `tests/fixtures/messengers/`, stored gzip-compressed): recognition, the
//! contract, and the messages, calls, transfers, SMS, chats, contacts and
//! account as records.

use std::io::Read;

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, Namespace, Value};
use sootmark_adapters::messengers::{
    MessengersAdapter, SKYPE_ACCOUNTS, SKYPE_CALLS, SKYPE_CHATS, SKYPE_CONTACTS, SKYPE_MESSAGES,
    SKYPE_SMS, SKYPE_TRANSFERS,
};

const PATH: &str = "Users/alice/AppData/Roaming/Skype/gen.beringer/main.db";

fn database() -> Vec<u8> {
    let compressed = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/messengers/skype_main.db.gz"
    ))
    .unwrap();
    let mut data = Vec::new();
    common::gzip::Decoder::new(compressed.as_slice())
        .read_to_end(&mut data)
        .unwrap();
    data
}

#[test]
fn skype_records() {
    let data = database();
    assert_eq!(
        MessengersAdapter.probe(PATH, &data[..4096]),
        Confidence::Certain
    );
    assert_eq!(
        MessengersAdapter.probe("Users/alice/AppData/Local/x/data.db", &data[..4096]),
        Confidence::No
    );
    assert_eq!(
        MessengersAdapter.probe(PATH, b"not a database"),
        Confidence::No
    );
    assert_conforms(&MessengersAdapter, PATH, &data);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name: PATH,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    MessengersAdapter.parse(&input, &mut sink).unwrap();
    assert!(sink.skipped.is_empty(), "{:?}", sink.skipped);
    let of = |namespace: Namespace| {
        sink.records
            .iter()
            .filter(|r| r.namespace() == namespace)
            .collect::<Vec<_>>()
    };
    // plaso's 15 chat messages, its call and transfers, its SMS and
    // account; and beyond plaso the chats and contacts.
    assert_eq!(of(SKYPE_MESSAGES).len(), 15);
    assert_eq!(of(SKYPE_SMS).len(), 1);
    assert_eq!(of(SKYPE_ACCOUNTS).len(), 1);
    assert_eq!(of(SKYPE_CHATS).len(), 5);
    assert_eq!(of(SKYPE_CONTACTS).len(), 2);
    assert_eq!(of(SKYPE_TRANSFERS).len(), 2);
    let [call] = of(SKYPE_CALLS)[..] else {
        panic!("{:?}", of(SKYPE_CALLS))
    };
    assert_eq!(
        call.summary,
        "Skype outgoing call with european.bbq.competitor, 646 s"
    );
    let times: Vec<&str> = call.times.iter().map(|t| t.field.as_str()).collect();
    assert_eq!(times, ["Begin", "End"]);
    let sent = of(SKYPE_TRANSFERS)
        .into_iter()
        .find(|r| r.fields.get("Direction") == Some(&Value::from("outgoing")))
        .unwrap();
    assert_eq!(
        sent.facets.file_path.as_deref(),
        Some("/Users/gberinger/Desktop/secret-project.pdf")
    );
    assert_eq!(sent.facets.user_name.as_deref(), Some("alice"));
    let message = of(SKYPE_MESSAGES)
        .into_iter()
        .find(|r| r.fields.get("Body") == Some(&Value::from("yt?")))
        .unwrap();
    assert_eq!(
        message.fields.get("Recipients"),
        Some(&Value::from("european.bbq.competitor"))
    );
    assert_eq!(
        message.fields.get("Author"),
        Some(&Value::from("gen.beringer"))
    );
}
