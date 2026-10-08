//! Messaging apps' databases, via the `messengers` parser: Skype's
//! `main.db` (classic Skype, up to version 7), read with its write-ahead
//! log when the caller hands it over. One record per message (who wrote
//! it, in which chat, to whom, what), per call (who hosted it, who was in
//! it, how long), per file transferred (which way, with whom, the file),
//! per SMS, and per chat, contact and account; the user from the
//! profile's path.

use messengers::{Account, Call, CallMember, Chat, Contact, Message, Skype, Sms, Transfer};
use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};

use crate::home::profile_owner;

/// Chat messages.
pub const SKYPE_MESSAGES: Namespace = Namespace::new("messenger.skype_messages");
/// Calls, with their members.
pub const SKYPE_CALLS: Namespace = Namespace::new("messenger.skype_calls");
/// Files sent and received.
pub const SKYPE_TRANSFERS: Namespace = Namespace::new("messenger.skype_transfers");
/// SMS sent through Skype.
pub const SKYPE_SMS: Namespace = Namespace::new("messenger.skype_sms");
/// Chats, with their participants.
pub const SKYPE_CHATS: Namespace = Namespace::new("messenger.skype_chats");
/// The account's contacts.
pub const SKYPE_CONTACTS: Namespace = Namespace::new("messenger.skype_contacts");
/// The accounts signed in.
pub const SKYPE_ACCOUNTS: Namespace = Namespace::new("messenger.skype_accounts");

/// What Skype names its database.
const SKYPE_DATABASE: &str = "main.db";
/// The longest text kept in a summary.
const SUMMARY_TEXT: usize = 200;
/// A call member's video status when its video was on.
const VIDEO_ON: i64 = 3;

/// One record per message, call, transfer, SMS, chat, contact and account.
#[derive(Debug, Default, Clone, Copy)]
pub struct MessengersAdapter;

impl Adapter for MessengersAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "messengers",
            version: messengers::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[
            SKYPE_MESSAGES,
            SKYPE_CALLS,
            SKYPE_TRANSFERS,
            SKYPE_SMS,
            SKYPE_CHATS,
            SKYPE_CONTACTS,
            SKYPE_ACCOUNTS,
        ]
    }

    /// By name (`main.db`) and the SQLite signature; any name when the
    /// head holds Skype's tables.
    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        let named = name
            .rsplit(['/', '\\'])
            .next()
            .is_some_and(|n| n.eq_ignore_ascii_case(SKYPE_DATABASE));
        if (named && head.starts_with(b"SQLite format 3\0")) || messengers::detect(head).is_some() {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        self.parse_with_log(input, &[], sink)
    }

    fn parse_with_log(
        &self,
        input: &Input<'_>,
        log: &[u8],
        sink: &mut dyn Sink,
    ) -> Result<(), ParseError> {
        let skype = messengers::read_skype(input.data, log).map_err(|e| ParseError::at(0, e.0))?;
        for reason in &skype.problems {
            sink.skipped(Skipped {
                locator: Locator::ByteOffset(0),
                reason: reason.clone(),
            });
        }
        let owner = profile_owner(input.name);
        let owner = owner.as_deref();
        for message in &skype.messages {
            sink.record(self.message(input, &skype, message, owner));
        }
        for call in &skype.calls {
            sink.record(self.call(input, call, owner));
        }
        for transfer in &skype.transfers {
            sink.record(self.transfer(input, transfer, owner));
        }
        for sms in &skype.sms {
            sink.record(self.sms(input, sms, owner));
        }
        for chat in &skype.chats {
            sink.record(self.chat(input, chat, owner));
        }
        for contact in &skype.contacts {
            sink.record(self.contact(input, contact, owner));
        }
        for account in &skype.accounts {
            sink.record(self.account(input, account, owner));
        }
        Ok(())
    }
}

impl MessengersAdapter {
    fn new_record(self, input: &Input<'_>, namespace: Namespace, table: &str, row: i64) -> Record {
        Record::new(
            input.evidence,
            namespace,
            Locator::TableRow {
                table: table.to_owned(),
                row: u64::try_from(row).unwrap_or_default(),
            },
            self.parser(),
        )
    }

    /// A chat message; its recipients are its chat's other participants,
    /// else the other party of a one-to-one chat.
    fn message(
        self,
        input: &Input<'_>,
        skype: &Skype,
        message: &Message,
        owner: Option<&str>,
    ) -> Record {
        let mut record = self.new_record(input, SKYPE_MESSAGES, "Messages", message.id);
        push_times(&mut record, &[(TimeKind::Logged, "Sent", message.time)]);
        let chat = message
            .chatname
            .as_deref()
            .and_then(|name| skype.chats.iter().find(|chat| chat.name == name));
        let mut recipients: Vec<&str> = chat
            .map(|chat| {
                chat.participants
                    .iter()
                    .map(String::as_str)
                    .filter(|p| Some(*p) != message.author.as_deref())
                    .collect()
            })
            .unwrap_or_default();
        if recipients.is_empty() {
            recipients.extend(chat.and_then(|c| c.dialog_partner.as_deref()));
        }
        let mut fields = Fields::new();
        text(&mut fields, "App", Some("skype"));
        text(&mut fields, "Chat", message.chatname.as_deref());
        text(
            &mut fields,
            "ChatTitle",
            chat.and_then(|c| c.title.as_deref()),
        );
        text(&mut fields, "Author", message.author.as_deref());
        text(
            &mut fields,
            "AuthorDisplayName",
            message.from_display_name.as_deref(),
        );
        text(&mut fields, "Recipients", Some(&recipients.join(", ")));
        text(&mut fields, "Body", message.body.as_deref());
        record.fields = fields;
        record.facets = owned_by(owner);
        let place = chat
            .and_then(|c| c.title.as_deref())
            .or(message.chatname.as_deref())
            .map_or_else(String::new, |name| format!(" in {name}"));
        record.summary = format!(
            "Skype message from {}{place}: {}",
            message.author.as_deref().unwrap_or("?"),
            shorten(message.body.as_deref().unwrap_or_default())
        );
        record
    }

    fn call(self, input: &Input<'_>, call: &Call, owner: Option<&str>) -> Record {
        let mut record = self.new_record(input, SKYPE_CALLS, "Calls", call.id);
        // In seconds: the call's, else its longest member's.
        let duration = call
            .duration
            .or_else(|| call.members.iter().filter_map(|m| m.duration).max());
        // It ended when its last member left.
        let end = call
            .members
            .iter()
            .filter_map(CallMember::end)
            .max_by_key(model::Ts::ticks);
        push_times(
            &mut record,
            &[
                (TimeKind::Logged, "Begin", call.begin),
                (TimeKind::Other, "End", end),
            ],
        );
        let members: Vec<&str> = call
            .members
            .iter()
            .filter_map(|m| m.identity.as_deref())
            .collect();
        let names: Vec<&str> = call
            .members
            .iter()
            .filter_map(|m| m.display_name.as_deref())
            .collect();
        let mut fields = Fields::new();
        text(&mut fields, "App", Some("skype"));
        if let Some(incoming) = call.incoming {
            fields.insert("Incoming".into(), Value::Bool(incoming));
        }
        text(&mut fields, "Host", call.host_identity.as_deref());
        number(&mut fields, "Duration", duration);
        text(&mut fields, "Members", Some(&members.join(", ")));
        text(&mut fields, "MemberDisplayNames", Some(&names.join(", ")));
        let guids: Vec<&str> = call
            .members
            .iter()
            .filter_map(|m| m.guid.as_deref())
            .collect();
        text(&mut fields, "CallGuids", Some(&guids.join(", ")));
        if call
            .members
            .iter()
            .any(|m| m.video_status == Some(VIDEO_ON))
        {
            fields.insert("Video".into(), Value::Bool(true));
        }
        record.fields = fields;
        record.facets = owned_by(owner);
        let direction = match call.incoming {
            Some(true) => "incoming ",
            Some(false) => "outgoing ",
            None => "",
        };
        let length = duration.map_or_else(String::new, |seconds| format!(", {seconds} s"));
        record.summary = format!(
            "Skype {direction}call with {}{length}",
            if members.is_empty() {
                "?".to_owned()
            } else {
                members.join(", ")
            }
        );
        record
    }

    fn transfer(self, input: &Input<'_>, transfer: &Transfer, owner: Option<&str>) -> Record {
        let mut record = self.new_record(input, SKYPE_TRANSFERS, "Transfers", transfer.id);
        push_times(
            &mut record,
            &[
                (TimeKind::Logged, "Start", transfer.start),
                (TimeKind::Other, "Accepted", transfer.accepted),
                (TimeKind::Other, "Finished", transfer.finished),
            ],
        );
        let direction = match transfer.kind {
            Some(1) => Some("incoming"),
            Some(2) => Some("outgoing"),
            _ => None,
        };
        let mut fields = Fields::new();
        text(&mut fields, "App", Some("skype"));
        text(&mut fields, "Direction", direction);
        number(&mut fields, "Type", transfer.kind);
        text(&mut fields, "Partner", transfer.partner_handle.as_deref());
        text(
            &mut fields,
            "PartnerDisplayName",
            transfer.partner_display_name.as_deref(),
        );
        number(&mut fields, "Status", transfer.status);
        text(&mut fields, "FileName", transfer.filename.as_deref());
        text(&mut fields, "Path", transfer.path.as_deref());
        number(&mut fields, "Size", transfer.size);
        number(&mut fields, "PkId", transfer.pk_id);
        number(&mut fields, "ParentId", transfer.parent_id);
        record.fields = fields;
        record.facets = Facets {
            file_path: transfer.path.clone().filter(|p| !p.is_empty()),
            ..owned_by(owner)
        };
        let way = match direction {
            Some("incoming") => "received from",
            Some("outgoing") => "sent to",
            _ => "transferred with",
        };
        record.summary = format!(
            "Skype file {} {way} {}",
            transfer.filename.as_deref().unwrap_or("?"),
            transfer.partner_handle.as_deref().unwrap_or("?")
        );
        record
    }

    fn sms(self, input: &Input<'_>, sms: &Sms, owner: Option<&str>) -> Record {
        let mut record = self.new_record(input, SKYPE_SMS, "SMSes", sms.id);
        push_times(&mut record, &[(TimeKind::Logged, "Sent", sms.time)]);
        let mut fields = Fields::new();
        text(&mut fields, "App", Some("skype"));
        text(&mut fields, "TargetNumbers", sms.target_numbers.as_deref());
        text(&mut fields, "Body", sms.body.as_deref());
        number(&mut fields, "Status", sms.status);
        record.fields = fields;
        record.facets = owned_by(owner);
        record.summary = format!(
            "Skype SMS to {}: {}",
            sms.target_numbers.as_deref().unwrap_or("?"),
            shorten(sms.body.as_deref().unwrap_or_default())
        );
        record
    }

    fn chat(self, input: &Input<'_>, chat: &Chat, owner: Option<&str>) -> Record {
        let mut record = self.new_record(input, SKYPE_CHATS, "Chats", chat.id);
        push_times(&mut record, &[(TimeKind::Created, "Created", chat.created)]);
        let mut fields = Fields::new();
        text(&mut fields, "App", Some("skype"));
        text(&mut fields, "Chat", Some(&chat.name));
        text(&mut fields, "ChatTitle", chat.title.as_deref());
        text(
            &mut fields,
            "Participants",
            Some(&chat.participants.join(", ")),
        );
        text(&mut fields, "DialogPartner", chat.dialog_partner.as_deref());
        record.fields = fields;
        record.facets = owned_by(owner);
        record.summary = format!(
            "Skype chat {} with {}",
            chat.title.as_deref().unwrap_or(&chat.name),
            chat.participants.join(", ")
        );
        record
    }

    fn contact(self, input: &Input<'_>, contact: &Contact, owner: Option<&str>) -> Record {
        let mut record = self.new_record(input, SKYPE_CONTACTS, "Contacts", contact.id);
        push_times(
            &mut record,
            &[
                (TimeKind::LastSeen, "LastOnline", contact.last_online),
                (
                    TimeKind::Modified,
                    "ProfileChanged",
                    contact.profile_changed,
                ),
            ],
        );
        let mut fields = Fields::new();
        text(&mut fields, "App", Some("skype"));
        text(&mut fields, "SkypeName", contact.skypename.as_deref());
        text(&mut fields, "FullName", contact.fullname.as_deref());
        text(&mut fields, "DisplayName", contact.display_name.as_deref());
        text(&mut fields, "Country", contact.country.as_deref());
        text(&mut fields, "City", contact.city.as_deref());
        text(&mut fields, "Phones", Some(&contact.phones.join(", ")));
        text(&mut fields, "Emails", contact.emails.as_deref());
        record.fields = fields;
        record.facets = owned_by(owner);
        record.summary = format!(
            "Skype contact {}{}",
            contact.skypename.as_deref().unwrap_or("?"),
            contact
                .fullname
                .as_deref()
                .map_or_else(String::new, |name| format!(" ({name})"))
        );
        record
    }

    fn account(self, input: &Input<'_>, account: &Account, owner: Option<&str>) -> Record {
        let mut record = self.new_record(input, SKYPE_ACCOUNTS, "Accounts", account.id);
        push_times(
            &mut record,
            &[
                (TimeKind::LastSeen, "LastUsed", account.last_used),
                (TimeKind::LastSeen, "LastOnline", account.last_online),
                (
                    TimeKind::Modified,
                    "ProfileChanged",
                    account.profile_changed,
                ),
                (TimeKind::Other, "AuthRequested", account.auth_requested),
                (
                    TimeKind::Other,
                    "AuthRequestSent",
                    account.auth_request_sent,
                ),
                (TimeKind::Other, "MoodChanged", account.mood_changed),
            ],
        );
        let mut fields = Fields::new();
        text(&mut fields, "App", Some("skype"));
        text(&mut fields, "SkypeName", account.skypename.as_deref());
        text(&mut fields, "FullName", account.fullname.as_deref());
        text(&mut fields, "DisplayName", account.display_name.as_deref());
        text(&mut fields, "Emails", account.emails.as_deref());
        text(&mut fields, "Country", account.country.as_deref());
        record.fields = fields;
        record.facets = owned_by(owner);
        record.summary = format!(
            "Skype account {}{}",
            account.skypename.as_deref().unwrap_or("?"),
            account
                .fullname
                .as_deref()
                .map_or_else(String::new, |name| format!(" ({name})"))
        );
        record
    }
}

fn owned_by(owner: Option<&str>) -> Facets {
    Facets {
        user_name: owner.map(str::to_owned),
        ..Facets::default()
    }
}

fn push_times(record: &mut Record, times: &[(TimeKind, &str, Option<model::Ts>)]) {
    for &(kind, name, time) in times {
        if let Some(time) = time {
            record.times.push(RecordTime::new(kind, name, time));
        }
    }
}

fn shorten(text: &str) -> String {
    text.chars().take(SUMMARY_TEXT).collect()
}

fn text(fields: &mut Fields, name: &str, value: Option<&str>) {
    if let Some(value) = value.filter(|v| !v.is_empty()) {
        fields.insert(name.into(), Value::from(value));
    }
}

fn number(fields: &mut Fields, name: &str, value: Option<i64>) {
    if let Some(value) = value {
        fields.insert(name.into(), Value::Int(value));
    }
}
