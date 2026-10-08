//! Firewall logs, via the `fwlogs` parser: Palo Alto PAN-OS (syslog and
//! CSV export), Fortinet FortiGate (key=value and CSV) and Cisco ASA
//! syslog; one record per entry, its main fields named alike across makers
//! (`Action`, `Source`, `Destination`, `User`, `Rule`, …) and every value
//! the maker logged kept under its own name.

use std::fmt::Write;

use fwlogs::{Entry, Vendor};
use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};

/// Palo Alto PAN-OS logs.
pub const PANOS: Namespace = Namespace::new("firewall.panos");
/// Fortinet FortiGate logs.
pub const FORTIGATE: Namespace = Namespace::new("firewall.fortigate");
/// Cisco ASA logs.
pub const ASA: Namespace = Namespace::new("firewall.asa");

/// Characters of a message kept in a summary.
const SUMMARY_TEXT: usize = 200;

/// One record per firewall log entry.
#[derive(Debug, Default, Clone, Copy)]
pub struct FwlogsAdapter;

impl Adapter for FwlogsAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "fwlogs",
            version: fwlogs::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[PANOS, FORTIGATE, ASA]
    }

    /// By the first lines: a PAN-OS record or export header, FortiGate's
    /// keys, an `%ASA-` message.
    fn probe(&self, _name: &str, head: &[u8]) -> Confidence {
        if fwlogs::detect(head).is_some() {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let log = fwlogs::read(input.data);
        for reason in log.problems {
            sink.skipped(Skipped {
                locator: Locator::ByteOffset(0),
                reason,
            });
        }
        for entry in &log.entries {
            sink.record(self.record(input, entry));
        }
        Ok(())
    }
}

impl FwlogsAdapter {
    fn record(self, input: &Input<'_>, entry: &Entry) -> Record {
        let (namespace, maker) = match entry.vendor {
            Vendor::PaloAlto => (PANOS, "PAN-OS"),
            Vendor::Fortinet => (FORTIGATE, "FortiGate"),
            Vendor::CiscoAsa => (ASA, "ASA"),
        };
        let mut record = Record::new(
            input.evidence,
            namespace,
            Locator::Line(entry.line as u64),
            self.parser(),
        );
        if let Some(time) = entry.time {
            record
                .times
                .push(RecordTime::new(TimeKind::Logged, "Time", time));
        }
        let mut fields = Fields::new();
        for (name, value) in &entry.fields {
            fields.insert(name.clone(), Value::from(value.as_str()));
        }
        for (name, value) in [
            ("Kind", &entry.kind),
            ("Action", &entry.action),
            ("Source", &entry.source),
            ("Destination", &entry.destination),
            ("Protocol", &entry.protocol),
            ("User", &entry.user),
            ("Application", &entry.application),
            ("Rule", &entry.rule),
            ("Device", &entry.device),
            ("Message", &entry.message),
        ] {
            if let Some(value) = value.as_deref().filter(|v| !v.is_empty()) {
                fields.insert(name.into(), Value::from(value));
            }
        }
        for (name, port) in [
            ("SourcePort", entry.source_port),
            ("DestinationPort", entry.destination_port),
        ] {
            if let Some(port) = port {
                fields.insert(name.into(), Value::UInt(u64::from(port)));
            }
        }
        record.fields = fields;
        record.facets = Facets {
            host_name: entry.device.clone(),
            user_name: entry.user.clone(),
            source_ip: entry.source.clone(),
            destination_ip: entry.destination.clone(),
            ..Facets::default()
        };
        record.summary = summary(maker, entry);
        record
    }
}

/// `PAN-OS TRAFFIC/end allow 10.0.0.2:51234 -> 8.8.8.8:53 (ping)`, or the
/// message for entries without ends.
fn summary(maker: &str, entry: &Entry) -> String {
    let end = |address: &Option<String>, port: Option<u16>| {
        address.as_deref().map(|a| match port {
            Some(port) => format!("{a}:{port}"),
            None => a.to_owned(),
        })
    };
    let mut out = format!("{maker} {}", entry.kind.as_deref().unwrap_or("entry"));
    if let Some(action) = &entry.action {
        out.push(' ');
        out.push_str(action);
    }
    let ends = (
        end(&entry.source, entry.source_port),
        end(&entry.destination, entry.destination_port),
    );
    match ends {
        (Some(from), Some(to)) => {
            let _ = write!(out, " {from} -> {to}");
        }
        _ => {
            if let Some(message) = &entry.message {
                out.push_str(": ");
                out.extend(message.chars().take(SUMMARY_TEXT));
            }
        }
    }
    if let Some(user) = &entry.user {
        let _ = write!(out, " user {user}");
    }
    out
}
