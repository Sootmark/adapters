//! SOFTWARE: network profiles. Their first and last connection times are
//! the machine's local time, zone unknown: they're kept as such
//! (`LocalUnknownZone`), never passed off as UTC.

use common::time::Precision;
use model::{Fields, RecordTime, TimeKind, Value};
use registry::networks::{self, Profile};
use registry::Hive;

use super::{insert_texts, local, Out, NETWORKS};

impl Out<'_, '_> {
    /// Every network profile, with what identified the network.
    pub(super) fn networks(&mut self, hive: &Hive<'_>) {
        let found = networks::profiles(hive);
        self.problems(found.problems);
        for profile in &found.entries {
            self.network(profile);
        }
    }

    fn network(&mut self, profile: &Profile) {
        let signature = profile.signatures.first();
        let (key, written) = match (&profile.key, profile.key_last_written, signature) {
            (Some(key), Some(written), _) => (key.clone(), written),
            (_, _, Some(signature)) => (signature.key.clone(), signature.key_last_written),
            _ => return,
        };
        let mut record = self.keyed(NETWORKS, &key, None, written);
        for (kind, field, time) in [
            (TimeKind::FirstSeen, "DateCreated", profile.created),
            (
                TimeKind::LastSeen,
                "DateLastConnected",
                profile.last_connected,
            ),
        ] {
            if let Some(ts) = time.and_then(|t| local(t, Precision::Millisecond)) {
                record.times.push(RecordTime::new(kind, field, ts));
            }
        }
        let mut fields = Fields::new();
        fields.insert("ProfileGuid".into(), Value::from(profile.guid.as_str()));
        insert_texts(
            &mut fields,
            &[
                ("ProfileName", profile.name.as_ref()),
                ("Description", profile.description.as_ref()),
            ],
        );
        if let Some(kind) = profile.kind() {
            fields.insert("NameType".into(), Value::from(kind));
        }
        if let Some(category) = profile.category_name() {
            fields.insert("Category".into(), Value::from(category));
        }
        if let Some(managed) = profile.managed {
            fields.insert("Managed".into(), Value::Bool(managed));
        }
        if let Some(signature) = signature {
            insert_texts(
                &mut fields,
                &[
                    ("DefaultGatewayMac", signature.gateway_mac.as_ref()),
                    ("DnsSuffix", signature.dns_suffix.as_ref()),
                    ("FirstNetwork", signature.first_network.as_ref()),
                ],
            );
        }
        if profile.signatures.len() > 1 {
            let macs = profile
                .signatures
                .iter()
                .filter_map(|s| s.gateway_mac.as_deref())
                .map(Value::from)
                .collect();
            fields.insert("GatewayMacs".into(), Value::List(macs));
        }
        record.fields = fields;
        let name = profile.name.as_deref().unwrap_or(&profile.guid);
        record.summary = match (
            profile.kind(),
            signature.and_then(|s| s.gateway_mac.as_deref()),
        ) {
            (Some(kind), Some(mac)) => format!("Network {name} ({kind}, gateway {mac})"),
            (Some(kind), None) => format!("Network {name} ({kind})"),
            (None, Some(mac)) => format!("Network {name} (gateway {mac})"),
            (None, None) => format!("Network {name}"),
        };
        self.sink.record(record);
    }
}
