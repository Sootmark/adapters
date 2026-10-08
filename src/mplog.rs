//! Microsoft Defender's protection logs (`ProgramData\Microsoft\Windows
//! Defender\Support\MPLog-*.log`), via the `defender` parser: one record
//! per entry read (detections, programs scanned, suspicious command lines,
//! blocked files, exclusions, cloud queries, behaviour monitoring
//! telemetry), its kind in `Kind` and its values under their labels; the
//! program, process, command line and file in facets.

use defender::{Entry, EntryKind};
use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};

/// Records of protection logs.
pub const NAMESPACE: Namespace = Namespace::new("windows.defender_mplog");

/// The labels naming the process, its id, its command line and the file,
/// first found first.
const PROCESS: [&str; 3] = ["ImagePath", "Process", "ProcessImageName"];
const PID: [&str; 3] = ["Pid", "ProcessID", "pid"];
const FILE: [&str; 3] = ["Path", "MaxTimeFile", "Resource Path"];

/// One record per entry.
#[derive(Debug, Default, Clone, Copy)]
pub struct MpLogAdapter;

impl Adapter for MpLogAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "defender-mplog",
            version: defender::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[NAMESPACE]
    }

    /// By name (`MPLog-*.log`); the content is text that may hold nothing
    /// read here.
    fn probe(&self, name: &str, _head: &[u8]) -> Confidence {
        if defender::is_mplog_name(name) {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let log = defender::read_mplog(input.data);
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

impl MpLogAdapter {
    fn record(self, input: &Input<'_>, entry: &Entry) -> Record {
        let mut record = Record::new(
            input.evidence,
            NAMESPACE,
            Locator::Line(entry.line as u64),
            self.parser(),
        );
        if let Some(time) = entry.time {
            let (kind, name) = match entry.kind {
                EntryKind::BmTelemetry => (TimeKind::Created, "ProcessCreationTime"),
                _ => (TimeKind::Logged, "Time"),
            };
            record.times.push(RecordTime::new(kind, name, time));
        }
        let mut fields = Fields::new();
        fields.insert("Kind".into(), Value::from(entry.kind.name()));
        for (label, value) in &entry.fields {
            match fields.get_mut(label.as_str()) {
                Some(Value::Text(existing)) => {
                    existing.push_str("; ");
                    existing.push_str(value);
                }
                _ => {
                    fields.insert(label.clone(), Value::from(value.as_str()));
                }
            }
        }
        record.fields = fields;
        let first = |labels: &[&str]| labels.iter().find_map(|l| entry.get(l)).map(str::to_owned);
        record.facets = Facets {
            process_path: first(&PROCESS),
            process_id: first(&PID).and_then(|p| p.parse().ok()),
            process_command_line: entry.get("CommandLine").map(str::to_owned),
            file_path: first(&FILE),
            ..Facets::default()
        };
        record.summary = summary(entry);
        record
    }
}

/// `Defender MPLog DetectionAdd: HackTool:Win32/X in C:\x.exe`.
fn summary(entry: &Entry) -> String {
    let what = [
        "ThreatName",
        "CommandLine",
        "ProcessImageName",
        "ImagePath",
        "Path",
        "Scan ID",
    ]
    .iter()
    .find_map(|l| entry.get(l));
    let mut out = format!("Defender MPLog {}", entry.kind.name());
    if let Some(what) = what {
        out.push_str(": ");
        out.push_str(what);
    }
    if let (Some(_), Some(path)) = (entry.get("ThreatName"), entry.get("Path")) {
        out.push_str(" in ");
        out.push_str(path);
    }
    out
}
