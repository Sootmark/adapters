//! CUPS print jobs (`/var/spool/cups/c<job>`, macOS and Linux), via the
//! `cups` parser: one record per job, with who printed it from which
//! application and host, the document's name and type, the printer, and
//! when it was created, started and completed.

use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};

/// Records of print jobs.
pub const NAMESPACE: Namespace = Namespace::new("unix.cups_job");

/// The job's text attributes kept, and their field names.
const TEXTS: [(&str, &str); 10] = [
    ("job-name", "JobName"),
    ("job-originating-user-name", "User"),
    ("com.apple.print.JobInfo.PMJobOwner", "Owner"),
    ("job-originating-host-name", "Host"),
    ("com.apple.print.JobInfo.PMApplicationName", "Application"),
    ("document-format", "DocumentFormat"),
    ("printer-uri", "PrinterUri"),
    ("DestinationPrinterID", "Printer"),
    ("job-uuid", "JobUuid"),
    ("job-printer-uri", "JobPrinterUri"),
];

/// One record per control file.
#[derive(Debug, Default, Clone, Copy)]
pub struct CupsAdapter;

impl Adapter for CupsAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "cups",
            version: cups::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[NAMESPACE]
    }

    /// By name (`c` and the job's number, in a `cups` spool) and the IPP
    /// header.
    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        let normalized = name.replace('\\', "/").to_ascii_lowercase();
        let base = normalized.rsplit('/').next().unwrap_or_default();
        let named = normalized.contains("cups/")
            && base
                .strip_prefix('c')
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
        if named && cups::is_control_file(head) {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let job = cups::read(input.data);
        for reason in &job.problems {
            sink.skipped(Skipped {
                locator: Locator::ByteOffset(0),
                reason: reason.clone(),
            });
        }
        let mut record = Record::new(
            input.evidence,
            NAMESPACE,
            Locator::ByteOffset(0),
            self.parser(),
        );
        for (kind, name, time) in [
            (TimeKind::Created, "Created", job.created()),
            (TimeKind::Executed, "Processing", job.processing()),
            (TimeKind::Other, "Completed", job.completed()),
        ] {
            if let Some(time) = time {
                record.times.push(RecordTime::new(kind, name, time));
            }
        }
        let mut fields = Fields::new();
        for (attribute, field) in TEXTS {
            if let Some(text) = job.text(attribute) {
                fields.insert(field.into(), Value::from(text.as_str()));
            }
        }
        if let Some(copies) = job.integer("copies") {
            fields.insert("Copies".into(), Value::Int(i64::from(copies)));
        }
        let user = job.text("job-originating-user-name");
        let name = job.text("job-name");
        record.facets = Facets {
            user_name: user.clone(),
            host_name: job.text("job-originating-host-name"),
            file_path: name.clone(),
            ..Facets::default()
        };
        record.summary = format!(
            "{} printed {} on {}",
            user.as_deref().unwrap_or("?"),
            name.as_deref().unwrap_or("?"),
            job.text("DestinationPrinterID")
                .or_else(|| job.text("printer-uri"))
                .unwrap_or_else(|| "?".to_owned())
        );
        record.fields = fields;
        sink.record(record);
        Ok(())
    }
}
