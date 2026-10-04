//! Windows' System Resource Usage Monitor (`SRUDB.dat`), via the `srum`
//! parser: one record per provider row, timed when its figures were
//! recorded, with the program and the account's SID: bytes each program
//! sent and received, its CPU and disk use, network connections.

use std::path::Path;

use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};
use srum::{Entry, Kind};

/// Records of SRUM databases.
pub const NAMESPACE: Namespace = Namespace::new("windows.srum");

/// An ESE database's signature, at offset 4 of its header.
const ESE_SIGNATURE: [u8; 4] = [0xef, 0xcd, 0xab, 0x89];

/// One record per provider row.
#[derive(Debug, Default, Clone, Copy)]
pub struct SrumAdapter;

impl Adapter for SrumAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "srum",
            version: srum::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[NAMESPACE]
    }

    /// By name (`SRUDB.dat`) and the ESE signature.
    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        let named = Path::new(name)
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.eq_ignore_ascii_case("SRUDB.dat"));
        if named && head.get(4..8) == Some(&ESE_SIGNATURE[..]) {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let parsed = srum::read(input.data).map_err(|e| ParseError::at(0, e.0))?;
        for reason in parsed.problems {
            sink.skipped(Skipped {
                locator: Locator::ByteOffset(0),
                reason,
            });
        }
        for entry in &parsed.entries {
            sink.record(self.to_record(input, entry));
        }
        Ok(())
    }
}

impl SrumAdapter {
    fn to_record(self, input: &Input<'_>, entry: &Entry) -> Record {
        let mut record = Record::new(
            input.evidence,
            NAMESPACE,
            Locator::TableRow {
                table: entry.table.clone(),
                row: entry
                    .id
                    .and_then(|id| u64::try_from(id).ok())
                    .unwrap_or_default(),
            },
            self.parser(),
        );
        if let Some(time) = entry.time {
            record
                .times
                .push(RecordTime::new(TimeKind::Logged, "TimeStamp", time));
        }
        for (column, time) in entry.times() {
            record
                .times
                .push(RecordTime::new(TimeKind::Other, column, time));
        }
        let app = entry.app.as_deref();
        record.facets = Facets {
            user_sid: entry.user.clone(),
            // A path names the program's file; a service or packaged app's
            // name stays in the fields.
            process_path: app.filter(|a| a.contains('\\')).map(str::to_owned),
            ..Facets::default()
        };
        record.fields = fields(entry);
        record.summary = summary(entry);
        record
    }
}

fn fields(entry: &Entry) -> Fields {
    let mut fields = Fields::new();
    let provider = match entry.kind {
        Some(kind) => kind.name(),
        None => entry.table.as_str(),
    };
    fields.insert("Provider".into(), Value::from(provider));
    if let Some(app) = &entry.app {
        fields.insert("App".into(), Value::from(app.as_str()));
    }
    for (name, id) in [("AppId", entry.app_id), ("UserId", entry.user_id)] {
        if let Some(id) = id {
            fields.insert(name.into(), Value::Int(id));
        }
    }
    for (name, value) in &entry.values {
        if let Some(value) = convert(value) {
            fields.insert(name.clone(), value);
        }
    }
    fields
}

/// An ESE value as a field value; NULL as no field.
fn convert(value: &ese::Value) -> Option<Value> {
    use ese::Value as E;
    Some(match value {
        E::Null => return None,
        E::Bool(b) => Value::Bool(*b),
        E::F32(f) => Value::Float(f64::from(*f)),
        E::F64(f) | E::DateTime(f) => Value::Float(*f),
        E::Guid(bytes) => Value::Bytes(bytes.to_vec()),
        E::Text(text) => Value::from(text.as_str()),
        E::Binary(bytes) => Value::Bytes(bytes.clone()),
        E::MultiValue(values) => Value::Text(format!("{values:?}")),
        other => Value::Int(other.as_i64()?),
    })
}

fn summary(entry: &Entry) -> String {
    let app = entry
        .app
        .clone()
        .or_else(|| entry.app_id.map(|id| format!("app {id}")))
        .unwrap_or_else(|| "?".to_owned());
    let number = |name: &str| {
        entry
            .value(name)
            .and_then(ese::Value::as_i64)
            .unwrap_or_default()
    };
    match entry.kind {
        Some(Kind::NetworkUsage) => format!(
            "{app} sent {} bytes, received {} bytes",
            number("BytesSent"),
            number("BytesRecvd")
        ),
        Some(Kind::ApplicationUsage) => format!(
            "{app} read {} bytes, wrote {} bytes (foreground and background)",
            number("ForegroundBytesRead") + number("BackgroundBytesRead"),
            number("ForegroundBytesWritten") + number("BackgroundBytesWritten")
        ),
        Some(Kind::NetworkConnectivity) => {
            format!("{app} connected for {} s", number("ConnectedTime"))
        }
        Some(kind) => format!("SRUM {}: {app}", kind.name()),
        None => format!("SRUM {}: {app}", entry.table),
    }
}
