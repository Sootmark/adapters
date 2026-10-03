//! The NTFS USN change journal (`$Extend\$UsnJrnl:$J`), via the `usn`
//! parser: one record per change (created, written, renamed, deleted,
//! closed…), with the file's name and the MFT references of the file and
//! its folder; the `windows.mft` records of the same volume give the
//! folder's path.
//!
//! Range-tracking records (version 4) say which byte ranges of a file were
//! written, alongside a version 3 record of the same change: not kept.
//!
//! A journal is read as a stream, so one of many gigabytes (mostly the
//! zeros of its freed pages) is never held in memory.

use std::io::Read;

use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped, StreamInput};
use model::{
    EvidenceId, Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value,
};
use usn::{Entry, Record as UsnRecord};

/// Records of USN change journals.
pub const NAMESPACE: Namespace = Namespace::new("windows.usn");

/// One record per change.
#[derive(Debug, Default, Clone, Copy)]
pub struct UsnAdapter;

impl Adapter for UsnAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "usn",
            version: usn::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[NAMESPACE]
    }

    /// By name: a journal often starts with gigabytes of zeros.
    fn probe(&self, name: &str, _head: &[u8]) -> Confidence {
        let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
        let journal = ["$J", "$UsnJrnl:$J", "$UsnJrnl%3A$J", "$UsnJrnl_$J"]
            .iter()
            .any(|known| base.eq_ignore_ascii_case(known));
        if journal {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let mut content = input.data;
        self.read(input.evidence, &mut content, sink)
    }

    /// Journals are read a megabyte at a time, whatever their size.
    fn parse_stream(
        &self,
        input: &StreamInput<'_>,
        content: &mut dyn Read,
        sink: &mut dyn Sink,
    ) -> Option<Result<(), ParseError>> {
        Some(self.read(input.evidence, content, sink))
    }
}

impl UsnAdapter {
    fn read(
        self,
        evidence: EvidenceId,
        content: &mut dyn Read,
        sink: &mut dyn Sink,
    ) -> Result<(), ParseError> {
        let mut read_to = 0;
        for entry in usn::read(content) {
            match entry.map_err(|error| ParseError::at(read_to, error.to_string()))? {
                Entry::Record(change) => {
                    read_to = change.offset;
                    sink.record(self.to_record(evidence, &change));
                }
                Entry::Problem(problem) => {
                    read_to = problem.offset;
                    sink.skipped(Skipped {
                        locator: Locator::ByteOffset(problem.offset),
                        reason: problem.to_string(),
                    });
                }
                Entry::Ranges(_) => {}
            }
        }
        Ok(())
    }

    fn to_record(self, evidence: EvidenceId, change: &UsnRecord) -> Record {
        let mut record = Record::new(
            evidence,
            NAMESPACE,
            Locator::ByteOffset(change.offset),
            self.parser(),
        );
        record
            .times
            .push(RecordTime::new(TimeKind::Logged, "timestamp", change.time));
        record.facets = Facets {
            file_path: Some(change.name.clone()),
            ..Facets::default()
        };
        let reasons: Vec<&str> = change.reasons.names().collect();
        let mut fields = Fields::new();
        fields.insert("Usn".into(), Value::UInt(change.usn));
        fields.insert("Name".into(), Value::from(change.name.as_str()));
        fields.insert("Reasons".into(), Value::from(reasons.join(" ").as_str()));
        fields.insert("File".into(), Value::from(change.file.to_string().as_str()));
        fields.insert(
            "Parent".into(),
            Value::from(change.parent.to_string().as_str()),
        );
        if change.file.is_ntfs() {
            fields.insert("FileRecord".into(), Value::UInt(change.file.entry()));
            fields.insert("ParentRecord".into(), Value::UInt(change.parent.entry()));
        }
        fields.insert(
            "Attributes".into(),
            Value::from(change.attributes.to_string().as_str()),
        );
        if change.source_info.bits() != 0 {
            fields.insert(
                "SourceInfo".into(),
                Value::from(change.source_info.to_string().as_str()),
            );
        }
        record.fields = fields;
        record.summary = format!(
            "{}: {}",
            change.name,
            reasons.join(", ").to_lowercase().replace('_', " ")
        );
        record
    }
}
