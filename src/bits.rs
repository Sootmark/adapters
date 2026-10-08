//! Windows BITS (Background Intelligent Transfer Service) job queues, via
//! the `bits` parser: `qmgr.db` (Windows 10 and later) and `qmgr0.dat`,
//! `qmgr1.dat` (XP to 8.1). One record per job (`windows.bits_jobs`), those
//! carved from the queue's free space included, with its owner's SID and
//! the program BITS runs when it completes or fails (`SetNotifyCmdLine`, a
//! known way to persist, flagged in the summary); one per file
//! (`windows.bits_files`): its URL, local and temporary paths and bytes
//! transferred.

use std::collections::HashMap;

use bits::{File, Job, JobType, Origin, Priority, State};
use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};

/// BITS jobs.
pub const JOBS: Namespace = Namespace::new("windows.bits_jobs");
/// The files of BITS jobs.
pub const FILES: Namespace = Namespace::new("windows.bits_files");

/// One record per job and per file.
#[derive(Debug, Default, Clone, Copy)]
pub struct BitsAdapter;

impl Adapter for BitsAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "bits",
            version: bits::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[JOBS, FILES]
    }

    /// `qmgr.db` by name and ESE signature, `qmgr0.dat` and `qmgr1.dat` by
    /// their queue file header.
    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        if bits::detect(name, head).is_some() {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let queue = bits::read(input.data).map_err(|e| ParseError::at(0, e.to_string()))?;
        for reason in queue.problems {
            sink.skipped(Skipped {
                locator: Locator::ByteOffset(0),
                reason,
            });
        }
        let jobs = || queue.jobs.iter().chain(&queue.carved_jobs);
        let mut placed_jobs = Placed::default();
        for job in jobs() {
            let locator = locator("Jobs", job.origin, job.id.as_deref());
            if placed_jobs.is_new(&locator, job, sink) {
                sink.record(self.job(input, locator, job));
            }
        }
        let job_files = jobs().flat_map(|job| job.files.iter().map(move |file| (file, Some(job))));
        let other_files = queue
            .orphan_files
            .iter()
            .chain(&queue.carved_files)
            .map(|file| (file, None));
        let mut placed_files = Placed::default();
        for (file, job) in job_files.chain(other_files) {
            let locator = locator("Files", file.origin, file.id.as_deref());
            if placed_files.is_new(&locator, file, sink) {
                sink.record(self.file(input, locator, file, job));
            }
        }
        Ok(())
    }
}

impl BitsAdapter {
    fn job(self, input: &Input<'_>, locator: Locator, job: &Job) -> Record {
        let mut record = Record::new(input.evidence, JOBS, locator, self.parser());
        record.flags.recovered = is_carved(job.origin);
        for (kind, name, value) in [
            (TimeKind::Created, "Created", job.created),
            (TimeKind::Modified, "Modified", job.modified),
            (TimeKind::Other, "Completed", job.completed),
            (TimeKind::Other, "Expires", job.expires),
        ] {
            if let Some(value) = value {
                record.times.push(RecordTime::new(kind, name, value));
            }
        }
        record.facets = Facets {
            user_sid: job.owner.clone(),
            process_path: non_empty(job.notify_program.as_ref()),
            process_command_line: non_empty(job.notify_arguments.as_ref()),
            ..Facets::default()
        };
        let mut fields = origin_fields(job.origin);
        for (name, value) in [
            ("JobId", &job.id),
            ("Name", &job.name),
            ("Description", &job.description),
            ("Owner", &job.owner),
            ("NotifyProgram", &job.notify_program),
            ("NotifyArguments", &job.notify_arguments),
        ] {
            text(&mut fields, name, value.as_deref());
        }
        for (name, value) in [
            ("Kind", job.kind.map(kind_name)),
            ("State", job.state.map(state_name)),
            ("Priority", job.priority.map(priority_name)),
        ] {
            text(&mut fields, name, value.as_deref());
        }
        for (name, value) in [
            ("NotifyFlags", job.notify_flags),
            ("FileCount", job.file_count),
        ] {
            if let Some(value) = value {
                fields.insert(name.into(), Value::UInt(u64::from(value)));
            }
        }
        for (name, value) in [
            ("ErrorCount", job.error_count),
            ("TransientErrorCount", job.transient_error_count),
            ("RetryDelay", job.retry_delay),
            ("NoProgressTimeout", job.no_progress_timeout),
        ] {
            fields.insert(name.into(), Value::UInt(u64::from(value)));
        }
        if !job.file_ids.is_empty() {
            let ids = job.file_ids.iter().map(|id| Value::from(id.as_str()));
            fields.insert("FileIds".into(), Value::List(ids.collect()));
        }
        record.fields = fields;
        record.summary = job_summary(job);
        record
    }

    fn file(self, input: &Input<'_>, locator: Locator, file: &File, job: Option<&Job>) -> Record {
        let mut record = Record::new(input.evidence, FILES, locator, self.parser());
        record.flags.recovered = is_carved(file.origin);
        record.flags.corrupted = file.damaged;
        if let Some(time) = file.remote_modified {
            record.times.push(RecordTime::new(
                TimeKind::Modified,
                "RemoteLastModified",
                time,
            ));
        }
        record.facets = Facets {
            file_path: non_empty(file.local_path.as_ref()),
            user_sid: job.and_then(|job| job.owner.clone()),
            ..Facets::default()
        };
        let mut fields = origin_fields(file.origin);
        let job_id = job.and_then(|job| job.id.as_ref());
        for (name, value) in [
            ("FileId", file.id.as_ref()),
            ("JobId", job_id),
            ("RemoteUrl", file.remote_url.as_ref()),
            ("LocalPath", file.local_path.as_ref()),
            ("TempPath", file.temp_path.as_ref()),
            ("Drive", Some(&file.drive)),
            ("Volume", Some(&file.volume)),
        ] {
            text(&mut fields, name, value.map(String::as_str));
        }
        fields.insert(
            "BytesTransferred".into(),
            Value::UInt(file.bytes_transferred),
        );
        if let Some(total) = file.bytes_total {
            fields.insert("BytesTotal".into(), Value::UInt(total));
        }
        if let Some(serial) = file.volume_serial {
            let serial = format!("{:04X}-{:04X}", serial >> 16, serial & 0xFFFF);
            fields.insert("VolumeSerial".into(), Value::from(serial));
        }
        if file.damaged {
            fields.insert("Damaged".into(), Value::Bool(true));
        }
        record.fields = fields;
        record.summary = file_summary(file, job.and_then(|job| job.kind));
        record
    }
}

/// Where a job or file is: a database row by its key, its `Id` GUID folded
/// to 64 bits (a row's page is shared with others, and ESE keeps rows in
/// key order); a record read from the file's bytes by its offset.
fn locator(table: &str, origin: Origin, id: Option<&str>) -> Locator {
    match origin {
        Origin::Row { page } => Locator::TableRow {
            table: table.to_owned(),
            row: id.and_then(folded_guid).unwrap_or(u64::from(page)),
        },
        Origin::Listed { offset } | Origin::Carved { offset } => Locator::ByteOffset(offset as u64),
    }
}

/// A GUID folded: its two 64-bit halves combined by exclusive or; `None`
/// for text that isn't one.
fn folded_guid(guid: &str) -> Option<u64> {
    let digits: String = guid.chars().filter(|c| *c != '-').collect();
    if digits.len() != 32 {
        return None;
    }
    let high = u64::from_str_radix(digits.get(..16)?, 16).ok()?;
    let low = u64::from_str_radix(digits.get(16..)?, 16).ok()?;
    Some(high ^ low)
}

/// The records of a namespace by locator, each once: a job's copy of a
/// listed file is the same file; another record at the same place is
/// reported, not emitted.
struct Placed<'q, T> {
    seen: HashMap<Locator, &'q T>,
}

impl<T> Default for Placed<'_, T> {
    fn default() -> Self {
        Self {
            seen: HashMap::new(),
        }
    }
}

impl<'q, T: PartialEq> Placed<'q, T> {
    /// Whether `item` is the first at `locator`.
    fn is_new(&mut self, locator: &Locator, item: &'q T, sink: &mut dyn Sink) -> bool {
        match self.seen.get(locator) {
            None => {
                self.seen.insert(locator.clone(), item);
                true
            }
            Some(first) => {
                if *first != item {
                    sink.skipped(Skipped {
                        locator: locator.clone(),
                        reason: "a second record at the same place, left out".to_owned(),
                    });
                }
                false
            }
        }
    }
}

fn is_carved(origin: Origin) -> bool {
    matches!(origin, Origin::Carved { .. })
}

/// `Origin` (`listed` or `carved`), and the `Page` or `Offset` read at.
fn origin_fields(origin: Origin) -> Fields {
    let mut fields = Fields::new();
    let (origin, place, at) = match origin {
        Origin::Row { page } => ("listed", "Page", u64::from(page)),
        Origin::Listed { offset } => ("listed", "Offset", offset as u64),
        Origin::Carved { offset } => ("carved", "Offset", offset as u64),
    };
    fields.insert("Origin".into(), Value::from(origin));
    fields.insert(place.into(), Value::UInt(at));
    fields
}

/// `BITS download job "Name" (Transferred), 1 file, owner S-1-5-18`, what
/// is known of it, and the notify command BITS runs when it is done.
fn job_summary(job: &Job) -> String {
    let files = job
        .file_count
        .map_or(job.files.len(), |count| count as usize);
    let owner = job
        .owner
        .as_deref()
        .map(|owner| format!(", owner {owner}"))
        .unwrap_or_default();
    let command: Vec<&str> = [&job.notify_program, &job.notify_arguments]
        .into_iter()
        .filter_map(|part| part.as_deref())
        .filter(|part| !part.is_empty())
        .collect();
    let notify = if command.is_empty() {
        String::new()
    } else {
        format!(
            "; runs {} when done (notify command, persistence)",
            command.join(" ")
        )
    };
    let kind = job.kind.map(kind_word).unwrap_or_default();
    let name = job
        .name
        .as_deref()
        .map_or_else(|| "(name lost)".to_owned(), |name| format!("\"{name}\""));
    let state = job
        .state
        .map(|state| format!(" ({})", state_name(state)))
        .unwrap_or_default();
    format!(
        "{}BITS {kind}job {name}{state}, {files} file{}{owner}{notify}",
        if is_carved(job.origin) { "Carved " } else { "" },
        if files == 1 { "" } else { "s" }
    )
}

/// What a job transfers, as a summary's word before `job`.
fn kind_word(kind: JobType) -> String {
    match kind {
        JobType::Download => "download ".to_owned(),
        JobType::Upload => "upload ".to_owned(),
        JobType::UploadReply => "upload-reply ".to_owned(),
        JobType::Other(value) => format!("type {value} "),
    }
}

/// `BITS download <url> -> <path> (975576 of 975576 bytes)`.
fn file_summary(file: &File, kind: Option<JobType>) -> String {
    let remote = file.remote_url.as_deref().unwrap_or("?");
    let local = match (&file.local_path, &file.temp_path) {
        (Some(path), _) => path.clone(),
        (None, Some(temporary)) => format!("? (temporary {temporary})"),
        (None, None) => "?".to_owned(),
    };
    let transfer = if matches!(kind, Some(JobType::Upload | JobType::UploadReply)) {
        format!("upload {local} -> {remote}")
    } else {
        format!("download {remote} -> {local}")
    };
    let bytes = match file.bytes_total {
        Some(total) => format!("{} of {total} bytes", file.bytes_transferred),
        None => format!("{} bytes, size unknown", file.bytes_transferred),
    };
    format!(
        "{}BITS {transfer} ({bytes})",
        if is_carved(file.origin) {
            "Carved "
        } else {
            ""
        }
    )
}

fn kind_name(kind: JobType) -> String {
    match kind {
        JobType::Download => "Download".to_owned(),
        JobType::Upload => "Upload".to_owned(),
        JobType::UploadReply => "UploadReply".to_owned(),
        JobType::Other(value) => value.to_string(),
    }
}

fn state_name(state: State) -> String {
    let name = match state {
        State::Queued => "Queued",
        State::Connecting => "Connecting",
        State::Transferring => "Transferring",
        State::Suspended => "Suspended",
        State::Error => "Error",
        State::TransientError => "TransientError",
        State::Transferred => "Transferred",
        State::Acknowledged => "Acknowledged",
        State::Cancelled => "Cancelled",
        State::Other(value) => return value.to_string(),
    };
    name.to_owned()
}

fn priority_name(priority: Priority) -> String {
    let name = match priority {
        Priority::Foreground => "Foreground",
        Priority::High => "High",
        Priority::Normal => "Normal",
        Priority::Low => "Low",
        Priority::Other(value) => return value.to_string(),
    };
    name.to_owned()
}

fn non_empty(value: Option<&String>) -> Option<String> {
    value.filter(|v| !v.is_empty()).cloned()
}

fn text(fields: &mut Fields, name: &str, value: Option<&str>) {
    if let Some(value) = value.filter(|v| !v.is_empty()) {
        fields.insert(name.into(), Value::from(value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use model::EvidenceId;

    /// A system job that runs a program when done, as `bitsadmin
    /// /SetNotifyCmdLine` leaves it.
    fn persistent_job() -> Job {
        Job {
            origin: Origin::Listed { offset: 68 },
            id: Some("7b403240-d166-4c09-958a-23774df1f57a".to_owned()),
            kind: Some(JobType::Download),
            priority: Some(Priority::Foreground),
            state: Some(State::Error),
            name: Some("update".to_owned()),
            description: Some(String::new()),
            notify_program: Some(r"C:\Windows\System32\cmd.exe".to_owned()),
            notify_arguments: Some(r"cmd.exe /c C:\Users\Public\run.bat".to_owned()),
            owner: Some("S-1-5-18".to_owned()),
            notify_flags: Some(3),
            file_count: Some(0),
            file_ids: Vec::new(),
            files: Vec::new(),
            error_count: 1,
            transient_error_count: 0,
            retry_delay: 600,
            no_progress_timeout: 1_209_600,
            created: None,
            modified: None,
            completed: None,
            expires: None,
        }
    }

    #[test]
    fn notify_commands_are_flagged() {
        let input = Input {
            evidence: EvidenceId::of_content(b""),
            name: "qmgr0.dat",
            data: b"",
            modified: None,
        };
        let job = persistent_job();
        let record = BitsAdapter.job(&input, Locator::ByteOffset(68), &job);
        assert_eq!(
            record.facets.process_path.as_deref(),
            Some(r"C:\Windows\System32\cmd.exe")
        );
        assert_eq!(
            record.facets.process_command_line.as_deref(),
            Some(r"cmd.exe /c C:\Users\Public\run.bat")
        );
        assert_eq!(record.facets.user_sid.as_deref(), Some("S-1-5-18"));
        assert_eq!(
            record.summary,
            r#"BITS download job "update" (Error), 0 files, owner S-1-5-18; runs C:\Windows\System32\cmd.exe cmd.exe /c C:\Users\Public\run.bat when done (notify command, persistence)"#
        );
    }

    #[test]
    fn rows_by_key_records_by_offset() {
        let id = "d387e452-e2b3-472d-b3b3-85c2be33cbb3";
        assert_eq!(
            locator("Jobs", Origin::Row { page: 31 }, Some(id)),
            Locator::TableRow {
                table: "Jobs".to_owned(),
                row: 0xd387_e452_e2b3_472d ^ 0xb3b3_85c2_be33_cbb3,
            }
        );
        assert_eq!(
            locator("Jobs", Origin::Row { page: 31 }, None),
            Locator::TableRow {
                table: "Jobs".to_owned(),
                row: 31,
            }
        );
        assert_eq!(
            locator("Files", Origin::Carved { offset: 136 }, Some(id)),
            Locator::ByteOffset(136)
        );
        assert_eq!(folded_guid("not a guid"), None);
    }

    #[test]
    fn names_of_values_bits_does_not_define() {
        assert_eq!(kind_name(JobType::Other(9)), "9");
        assert_eq!(state_name(State::Other(12)), "12");
        assert_eq!(priority_name(Priority::Other(7)), "7");
    }
}
