//! Microsoft Defender's detection history (`ProgramData\Microsoft\Windows
//! Defender\Scans\History\Service\DetectionHistory\<n>\<GUID>`), via the
//! `defender` parser: one record per detection, with the threat, the
//! resources it was found in, the user and process involved, the file's
//! hashes, and when it was detected, remediated and last changed.

use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{
    Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Ts, Value,
};

/// Records of Defender detection history files.
pub const NAMESPACE: Namespace = Namespace::new("windows.defender");

/// One record per detection.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefenderAdapter;

impl Adapter for DefenderAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "defender",
            version: defender::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[NAMESPACE]
    }

    /// By content: `Magic.Version:1.2` at offset 0x30.
    fn probe(&self, _name: &str, head: &[u8]) -> Confidence {
        if defender::detect(head) {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let detection = defender::read(input.data).map_err(|e| ParseError::at(0, e.0))?;
        for reason in &detection.problems {
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
            (
                TimeKind::Logged,
                "ThreatTrackingStartTime",
                detection.start_time(),
            ),
            (
                TimeKind::FirstSeen,
                "InitialDetectionTime",
                detection.initial_detection,
            ),
            (TimeKind::Other, "RemediationTime", detection.remediation),
            (
                TimeKind::Modified,
                "LastThreatStatusChangeTime",
                detection.status_changed,
            ),
        ] {
            push_time(&mut record, kind, name, time);
        }
        let file = location(&detection, "file");
        let mut fields = Fields::new();
        text(&mut fields, "DetectionId", detection.id.as_deref());
        text(&mut fields, "ThreatName", detection.threat_name.as_deref());
        if let Some(category) = detection.category {
            fields.insert("Category".into(), Value::UInt(category));
        }
        text(&mut fields, "CategoryName", detection.category_name());
        text(&mut fields, "User", detection.user.as_deref());
        text(&mut fields, "Process", detection.process.as_deref());
        text(&mut fields, "Path", file);
        let resources: Vec<String> = detection
            .resources
            .iter()
            .map(|r| format!("{}: {}", r.kind, r.location))
            .collect();
        text(&mut fields, "Resources", Some(&resources.join("; ")));
        for (name, key) in [
            ("Sha256", "ThreatTrackingSha256"),
            ("Sha1", "ThreatTrackingSha1"),
            ("Md5", "ThreatTrackingMD5"),
            ("Size", "ThreatTrackingSize"),
            ("ThreatId", "ThreatTrackingThreatId"),
            ("ScanSource", "ThreatTrackingScanSource"),
        ] {
            text(&mut fields, name, detection.tracking(key));
        }
        record.fields = fields;
        let process = detection.process.clone().filter(|p| p != "Unknown");
        record.facets = Facets {
            user_name: detection.user.clone(),
            process_path: process,
            file_path: file.map(str::to_owned),
            ..Facets::default()
        };
        record.summary = format!(
            "Defender detected {} in {}",
            detection.threat_name.as_deref().unwrap_or("?"),
            file.or_else(|| detection.resources.first().map(|r| r.location.as_str()))
                .unwrap_or("?")
        );
        sink.record(record);
        Ok(())
    }
}

/// The first resource of `kind`'s location.
fn location<'a>(detection: &'a defender::Detection, kind: &str) -> Option<&'a str> {
    detection
        .resources
        .iter()
        .find(|r| r.kind == kind)
        .map(|r| r.location.as_str())
}

fn push_time(record: &mut Record, kind: TimeKind, name: &str, time: Option<Ts>) {
    if let Some(time) = time {
        record.times.push(RecordTime::new(kind, name, time));
    }
}

fn text(fields: &mut Fields, name: &str, value: Option<&str>) {
    if let Some(value) = value.filter(|v| !v.is_empty()) {
        fields.insert(name.into(), Value::from(value));
    }
}
