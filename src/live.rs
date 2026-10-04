//! The live state the Sootmark collector's command rules capture on a
//! running Windows host (`live/<name>.json`, PowerShell's `ConvertTo-Json`
//! with times in UTC): processes, TCP connections and UDP endpoints,
//! services, the DNS cache and logon sessions. One record per item.
//!
//! PowerShell writes one item as an object rather than an array of one,
//! nothing at all for none, and an empty object for a missing computed
//! value: all are read as such.

use common::json::{self, Json};
use common::time::Ts;
use model::adapter::{Adapter, Confidence, Input, ParseError, Sink};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};

/// Records of a live host's state.
pub const NAMESPACE: Namespace = Namespace::new("windows.live");

/// The collector's outputs this adapter reads, by file name.
const OUTPUTS: [&str; 6] = [
    "processes.json",
    "connections.json",
    "udp.json",
    "services.json",
    "dns-cache.json",
    "sessions.json",
];
const SUMMARY_COMMAND: usize = 160;

/// One record per item of a live output.
#[derive(Debug, Default, Clone, Copy)]
pub struct LiveAdapter;

/// The output a path names, when it is one of the collector's.
fn output_of(name: &str) -> Option<&'static str> {
    let mut parts = name.rsplit(['/', '\\']);
    let file = parts.next()?;
    let folder = parts.next()?;
    let output = OUTPUTS.iter().find(|o| o.eq_ignore_ascii_case(file))?;
    folder.eq_ignore_ascii_case("live").then_some(*output)
}

impl Adapter for LiveAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "collector-live",
            version: env!("CARGO_PKG_VERSION"),
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[NAMESPACE]
    }

    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        let text = head
            .strip_prefix(b"\xef\xbb\xbf")
            .unwrap_or(head)
            .trim_ascii_start();
        let json = text.is_empty() || text.starts_with(b"[") || text.starts_with(b"{");
        if output_of(name).is_some() && json {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let output =
            output_of(input.name).ok_or_else(|| ParseError::at(0, "not a collector output"))?;
        let text = String::from_utf8_lossy(input.data);
        let text = text.trim_start_matches('\u{feff}').trim();
        if text.is_empty() {
            return Ok(());
        }
        let items = match json::parse(text).map_err(|_| ParseError::at(0, "not JSON"))? {
            Json::Array(items) => items,
            item => vec![item],
        };
        let table = output.trim_end_matches(".json");
        for (row, item) in items.iter().enumerate() {
            let locator = Locator::TableRow {
                table: table.to_owned(),
                row: row as u64,
            };
            let mut record = Record::new(input.evidence, NAMESPACE, locator, self.parser());
            describe(table, item, &mut record);
            record.fields = fields(table, item);
            sink.record(record);
        }
        Ok(())
    }
}

/// Facets, times and summary for one item of `table`.
fn describe(table: &str, item: &Json, record: &mut Record) {
    match table {
        "processes" => process(item, record),
        "connections" | "udp" => endpoint(table, item, record),
        "services" => service(item, record),
        "dns-cache" => {
            record.summary = format!(
                "DNS cache: {} → {} ({})",
                text(item, "Entry")
                    .or_else(|| text(item, "Name"))
                    .unwrap_or("?"),
                text(item, "Data").unwrap_or("?"),
                text(item, "Type").unwrap_or("?")
            );
        }
        _ => session(item, record),
    }
}

fn process(item: &Json, record: &mut Record) {
    created(item, "CreationDate", record);
    let name = text(item, "Name").unwrap_or_default();
    let pid = number(item, "ProcessId").unwrap_or(0);
    let owner = text(item, "Owner");
    let command: String = text(item, "CommandLine")
        .unwrap_or(name)
        .chars()
        .take(SUMMARY_COMMAND)
        .collect();
    record.summary = match owner {
        Some(owner) => format!("Process {name} (pid {pid}) as {owner}: {command}"),
        None => format!("Process {name} (pid {pid}): {command}"),
    };
    record.facets = Facets {
        process_path: text(item, "ExecutablePath").map(str::to_owned),
        process_command_line: text(item, "CommandLine").map(str::to_owned),
        process_id: number(item, "ProcessId"),
        user_name: owner.map(str::to_owned),
        ..Facets::default()
    };
}

/// A TCP connection (`connections`) or a UDP endpoint (`udp`).
fn endpoint(table: &str, item: &Json, record: &mut Record) {
    created(item, "CreationTime", record);
    let address = |host: &str, port: &str| {
        format!(
            "{}:{}",
            text(item, host).unwrap_or("?"),
            number(item, port).unwrap_or(0)
        )
    };
    let local = address("LocalAddress", "LocalPort");
    let pid = number(item, "OwningProcess").unwrap_or(0);
    record.summary = if table == "udp" {
        format!("UDP {local} (pid {pid})")
    } else {
        let remote = address("RemoteAddress", "RemotePort");
        format!(
            "TCP {local} → {remote} {} (pid {pid})",
            text(item, "State").unwrap_or("?")
        )
    };
    record.facets = Facets {
        process_id: number(item, "OwningProcess"),
        destination_ip: text(item, "RemoteAddress")
            .filter(|a| !matches!(*a, "0.0.0.0" | "::" | "127.0.0.1" | "::1"))
            .map(str::to_owned),
        ..Facets::default()
    };
}

fn service(item: &Json, record: &mut Record) {
    let name = text(item, "Name").unwrap_or_default();
    record.summary = format!(
        "Service {name} ({}, {}): {} as {}",
        text(item, "State").unwrap_or("?"),
        text(item, "StartMode").unwrap_or("?"),
        text(item, "PathName").unwrap_or("?"),
        text(item, "StartName").unwrap_or("?")
    );
    record.facets = Facets {
        service_name: Some(name.to_owned()),
        process_command_line: text(item, "PathName").map(str::to_owned),
        process_id: number(item, "ProcessId").filter(|&pid| pid != 0),
        user_name: text(item, "StartName").map(str::to_owned),
        ..Facets::default()
    };
}

fn session(item: &Json, record: &mut Record) {
    created(item, "StartTime", record);
    let kind = match number(item, "LogonType") {
        Some(2) => "interactive",
        Some(10) => "remote desktop",
        Some(11) => "cached",
        _ => "other",
    };
    record.summary = format!(
        "Logon session {} ({kind})",
        text(item, "Account").unwrap_or("?")
    );
    record.facets = Facets {
        user_name: text(item, "Account").map(str::to_owned),
        logon_id: text(item, "LogonId").map(str::to_owned),
        ..Facets::default()
    };
}

/// The item's `name` time, as when it was created or started.
fn created(item: &Json, name: &str, record: &mut Record) {
    if let Some(ts) = text(item, name).and_then(Ts::parse_iso8601_utc) {
        record
            .times
            .push(RecordTime::new(TimeKind::Created, name, ts));
    }
}

fn number(item: &Json, name: &str) -> Option<u64> {
    item.get(name).and_then(Json::as_u64)
}

/// A text member, `None` when missing, null, empty, or PowerShell's empty
/// object for a missing computed value.
fn text<'j>(item: &'j Json, name: &str) -> Option<&'j str> {
    item.get(name)
        .and_then(Json::as_str)
        .filter(|t| !t.is_empty())
}

/// Every member, as written, and which output it came from.
fn fields(table: &str, item: &Json) -> Fields {
    let mut fields = Fields::new();
    fields.insert("Output".into(), Value::from(table));
    if let Json::Object(members) = item {
        for (name, value) in members {
            let value = match value {
                Json::String(text) if !text.is_empty() => Value::from(text.as_str()),
                Json::Int(n) => Value::Int(*n),
                Json::UInt(n) => Value::UInt(*n),
                Json::Bool(b) => Value::Bool(*b),
                _ => continue,
            };
            fields.insert(name.clone(), value);
        }
    }
    fields
}
