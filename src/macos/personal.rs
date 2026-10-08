//! Records of what a user said and kept: Messages (iMessage and SMS) and
//! keychain items, their names, accounts and servers without their secrets.

use macos::{Artifact, AttributeValue, ItemKind, KeychainItem, Message};
use model::adapter::Input;
use model::{Facets, Fields, Record, RecordTime, TimeKind, Value};

use super::{text, MacosAdapter, KEYCHAIN, MESSAGES};
use crate::key::field_name;

/// The longest text kept in a summary.
const SUMMARY_TEXT: usize = 200;

impl MacosAdapter {
    /// The records of a Messages database or a keychain, and what couldn't
    /// be read.
    pub(super) fn personal(
        self,
        artifact: Artifact,
        input: &Input<'_>,
        log: &[u8],
        owner: Option<&str>,
    ) -> Result<(Vec<String>, Vec<Record>), macos::Error> {
        Ok(if artifact == Artifact::Messages {
            let parsed = macos::read_messages(input.data, log)?;
            let records = parsed
                .messages
                .iter()
                .map(|message| self.message(input, message, owner))
                .collect();
            (parsed.problems, records)
        } else {
            let parsed = macos::read_keychain(input.data)?;
            let records = parsed
                .items
                .iter()
                .map(|item| self.keychain_item(input, item, owner))
                .collect();
            (parsed.problems, records)
        })
    }

    /// A message: sent or received, when, with whom, in which conversation.
    fn message(self, input: &Input<'_>, message: &Message, owner: Option<&str>) -> Record {
        let mut record = self.record(input, MESSAGES, "message", message.rowid);
        for (kind, name, time) in [
            (TimeKind::Logged, "Date", message.date),
            (TimeKind::Other, "DateDelivered", message.date_delivered),
            (TimeKind::Accessed, "DateRead", message.date_read),
        ] {
            if let Some(time) = time {
                record.times.push(RecordTime::new(kind, name, time));
            }
        }
        let mut fields = Fields::new();
        text(&mut fields, "Guid", message.guid.as_deref());
        text(&mut fields, "Text", message.text.as_deref());
        text(&mut fields, "Handle", message.handle.as_deref());
        text(&mut fields, "Service", message.service.as_deref());
        text(&mut fields, "Account", message.account.as_deref());
        text(&mut fields, "Chat", message.chat.as_deref());
        for (name, flag) in [("FromMe", message.from_me), ("Read", message.read)] {
            if let Some(flag) = flag {
                fields.insert(name.into(), Value::Bool(flag));
            }
        }
        if !message.attachments.is_empty() {
            fields.insert(
                "Attachments".into(),
                Value::List(
                    message
                        .attachments
                        .iter()
                        .map(|path| Value::from(path.as_str()))
                        .collect(),
                ),
            );
        }
        record.fields = fields;
        record.facets = Facets {
            user_name: owner.map(str::to_owned),
            file_path: message.attachments.first().cloned(),
            ..Facets::default()
        };
        let direction = match message.from_me {
            Some(true) => "to",
            _ => "from",
        };
        let body = message.text.as_deref().map_or_else(
            || format!("{} attachment(s)", message.attachments.len()),
            |text| text.chars().take(SUMMARY_TEXT).collect(),
        );
        record.summary = format!(
            "{} {direction} {}: {body}",
            message.service.as_deref().unwrap_or("Message"),
            message
                .handle
                .as_deref()
                .or(message.chat.as_deref())
                .unwrap_or("?"),
        );
        record
    }

    /// A keychain item: what it is for, which account and server, when it
    /// was made and changed. Every attribute is kept under its own name.
    fn keychain_item(self, input: &Input<'_>, item: &KeychainItem, owner: Option<&str>) -> Record {
        let mut record = self.record(
            input,
            KEYCHAIN,
            &relation_table(item.kind),
            i64::from(item.record_number),
        );
        for (kind, name, time) in [
            (TimeKind::Created, "Created", item.created()),
            (TimeKind::Modified, "Modified", item.modified()),
        ] {
            if let Some(time) = time {
                record.times.push(RecordTime::new(kind, name, time));
            }
        }
        let mut fields = Fields::new();
        for (name, value) in &item.attributes {
            fields.insert(format!("Attribute.{}", field_name(name)), attribute(value));
        }
        let label = kind_label(item.kind);
        fields.insert("Kind".into(), Value::from(label));
        text(&mut fields, "Relation", item.relation.as_deref());
        let name = printable(item.name());
        text(&mut fields, "Name", name.as_deref());
        text(&mut fields, "Account", item.account().as_deref());
        text(&mut fields, "Service", item.service().as_deref());
        text(&mut fields, "Server", item.server().as_deref());
        text(&mut fields, "Protocol", item.protocol().as_deref());
        record.fields = fields;
        record.facets = Facets {
            user_name: owner.map(str::to_owned),
            ..Facets::default()
        };
        let account = item.account().map_or_else(String::new, |a| format!(" {a}"));
        let place = item
            .server()
            .or_else(|| item.service())
            .map_or_else(String::new, |s| format!(" at {s}"));
        record.summary = format!(
            "Keychain {label}: {}{account}{place}",
            name.as_deref().unwrap_or("?")
        );
        record
    }
}

/// Text that reads as text: a key's name is often a binary label, its
/// bytes read as UTF-8 only by accident.
fn printable(text: Option<String>) -> Option<String> {
    text.filter(|t| {
        !t.chars()
            .any(|c| c.is_control() || c == char::REPLACEMENT_CHARACTER)
    })
}

/// The locator's table: the item's relation, named by its identifier so
/// two relations' record numbers never meet.
fn relation_table(kind: ItemKind) -> String {
    let id = match kind {
        ItemKind::GenericPassword => 0x8000_0000,
        ItemKind::InternetPassword => 0x8000_0001,
        ItemKind::AppleSharePassword => 0x8000_0002,
        ItemKind::Certificate => 0x8000_1000,
        ItemKind::PublicKey => 0x0F,
        ItemKind::PrivateKey => 0x10,
        ItemKind::SymmetricKey => 0x11,
        ItemKind::Other(id) => id,
    };
    format!("relation 0x{id:08x}")
}

fn kind_label(kind: ItemKind) -> &'static str {
    match kind {
        ItemKind::GenericPassword => "application password",
        ItemKind::InternetPassword => "internet password",
        ItemKind::AppleSharePassword => "AppleShare password",
        ItemKind::Certificate => "certificate",
        ItemKind::PublicKey => "public key",
        ItemKind::PrivateKey => "private key",
        ItemKind::SymmetricKey => "symmetric key",
        ItemKind::Other(_) => "item",
    }
}

/// An attribute's value: text for blobs of UTF-8 (names, accounts and
/// servers are), bytes otherwise.
fn attribute(value: &AttributeValue) -> Value {
    match value {
        AttributeValue::Text(text) => Value::from(text.as_str()),
        AttributeValue::Integer(number) => Value::Int(*number),
        AttributeValue::Bytes(bytes) => match std::str::from_utf8(bytes) {
            Ok(text) if !text.contains('\0') => Value::from(text),
            _ => Value::Bytes(bytes.clone()),
        },
        AttributeValue::Real(number) => Value::Float(*number),
        AttributeValue::Time(time) => Value::Time(*time),
        AttributeValue::Integers(numbers) => {
            Value::List(numbers.iter().map(|n| Value::UInt(u64::from(*n))).collect())
        }
    }
}
