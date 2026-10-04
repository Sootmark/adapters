//! NTUSER.DAT: outbound Remote Desktop history and the most-recently-used
//! lists (`RecentDocs`, `RunMRU`, `TypedPaths`, `WordWheelQuery`).

use std::net::IpAddr;

use common::time::Ts;
use model::{Facets, Fields, Namespace, RecordTime, TimeKind, Value};
use registry::mru::{self, List};
use registry::rdp::{self, Connection};
use registry::Hive;

use super::{insert_texts, Out, RDP, RECENT_DOCS, RUN_MRU, TYPED_PATHS, WORD_WHEEL_QUERY};

fn mru_namespace(list: List) -> Namespace {
    match list {
        List::RecentDocs => RECENT_DOCS,
        List::RunMru => RUN_MRU,
        List::TypedPaths => TYPED_PATHS,
        List::WordWheelQuery => WORD_WHEEL_QUERY,
    }
}

impl Out<'_, '_> {
    /// Remote Desktop hosts the user connected to.
    pub(super) fn remote_desktop(&mut self, hive: &Hive<'_>) {
        let found = rdp::connections(hive);
        self.problems(found.problems);
        for connection in &found.entries {
            self.connection(connection);
        }
    }

    fn connection(&mut self, connection: &Connection) {
        let value = connection
            .username_hint
            .as_ref()
            .map(|_| "UsernameHint")
            .filter(|_| connection.key.contains(r"\Servers\"));
        let mut record = self.keyed(RDP, &connection.key, value, connection.key_last_written);
        if let Some(latest) = connection.mru_last_written {
            record.times.push(RecordTime::new(
                TimeKind::LastSeen,
                "MostRecentConnection",
                Ts::from_filetime(latest),
            ));
        }
        let address = connection.address();
        record.facets = Facets {
            destination_ip: address.parse::<IpAddr>().ok().map(|ip| ip.to_string()),
            ..Facets::default()
        };
        let mut fields = Fields::new();
        fields.insert("Host".into(), Value::from(connection.host.as_str()));
        insert_texts(
            &mut fields,
            &[("UsernameHint", connection.username_hint.as_ref())],
        );
        if let Some(position) = connection.mru_position {
            fields.insert("MRUPosition".into(), Value::UInt(position as u64));
        }
        record.fields = fields;
        record.summary = match &connection.username_hint {
            Some(user) => format!("RDP connection to {} as {user}", connection.host),
            None => format!("RDP connection to {}", connection.host),
        };
        self.sink.record(record);
    }

    /// The four most-recently-used lists: each entry a record, the most
    /// recent of each list dated by its key's last write.
    pub(super) fn recently_used(&mut self, hive: &Hive<'_>) {
        let found = mru::entries(hive);
        self.problems(found.problems);
        for entry in &found.entries {
            self.mru_entry(entry);
        }
    }

    fn mru_entry(&mut self, entry: &mru::Entry) {
        let mut record = self.record(
            mru_namespace(entry.list),
            &entry.key,
            Some(entry.value.clone()),
        );
        let (kind, field) = match entry.list {
            List::RecentDocs => (TimeKind::Accessed, "Opened"),
            List::RunMru => (TimeKind::Executed, "Run"),
            List::TypedPaths | List::WordWheelQuery => (TimeKind::Other, "Typed"),
        };
        if entry.position == Some(0) {
            record.times.push(RecordTime::new(
                kind,
                field,
                Ts::from_filetime(entry.key_last_written),
            ));
        }
        record.facets = match entry.list {
            List::RecentDocs | List::TypedPaths => Facets {
                file_path: Some(entry.text.clone()),
                ..Facets::default()
            },
            List::RunMru => Facets {
                process_command_line: Some(entry.text.clone()),
                ..Facets::default()
            },
            List::WordWheelQuery => Facets::default(),
        };
        let mut fields = Fields::new();
        fields.insert("List".into(), Value::from(entry.list.name()));
        fields.insert("Value".into(), Value::from(entry.value.as_str()));
        let text_field = match entry.list {
            List::RecentDocs => "Name",
            List::RunMru => "Command",
            List::TypedPaths => "Path",
            List::WordWheelQuery => "SearchTerm",
        };
        fields.insert(text_field.into(), Value::from(entry.text.as_str()));
        insert_texts(
            &mut fields,
            &[
                ("Sublist", entry.sublist.as_ref()),
                ("LnkName", entry.lnk_name.as_ref()),
            ],
        );
        if let Some(position) = entry.position {
            fields.insert("MRUPosition".into(), Value::UInt(position as u64));
        }
        record.fields = fields;
        let position = entry
            .position
            .map_or_else(|| "unordered".to_owned(), |p| format!("position {p}"));
        record.summary = match entry.list {
            List::RecentDocs => format!("Recent document {} ({position})", entry.text),
            List::RunMru => format!("Run dialog: {} ({position})", entry.text),
            List::TypedPaths => format!("Typed path {} ({position})", entry.text),
            List::WordWheelQuery => format!("Explorer search \"{}\" ({position})", entry.text),
        };
        self.sink.record(record);
    }
}
