//! LNK files, via the `shell` parser: what a shortcut points at, the
//! target's times as they were when the link was saved, and the machine
//! it was made on. Recent-files links (`…\Recent\*.lnk`) show files and
//! folders a user opened.

use std::path::Path;

use common::time::Ts;
use model::adapter::{Adapter, Confidence, Input, ParseError, Sink};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};
use shell::lnk;

/// Records of `.lnk` files.
pub const NAMESPACE: Namespace = Namespace::new("windows.lnk");

const HEADER: &[u8] = &[0x4c, 0, 0, 0, 0x01, 0x14, 0x02, 0];

/// One record per link.
#[derive(Debug, Default, Clone, Copy)]
pub struct LnkAdapter;

impl Adapter for LnkAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "lnk",
            version: shell::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[NAMESPACE]
    }

    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        let has_extension = Path::new(name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("lnk"));
        if head.starts_with(HEADER) {
            Confidence::Certain
        } else if has_extension {
            Confidence::Maybe
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let link = lnk::parse(input.data).map_err(|e| ParseError::at(e.offset as u64, e.reason))?;
        sink.record(self.to_record(input, &link));
        Ok(())
    }
}

/// Where the link points, most specific first.
pub(crate) fn target(link: &lnk::Link) -> String {
    if !link.local_path.is_empty() {
        return link.local_path.clone();
    }
    if !link.network_path.is_empty() {
        return if link.common_path.is_empty() {
            link.network_path.clone()
        } else {
            format!(r"{}\{}", link.network_path, link.common_path)
        };
    }
    if !link.environment_target.is_empty() {
        return link.environment_target.clone();
    }
    link.target_path()
}

impl LnkAdapter {
    fn to_record(self, input: &Input<'_>, link: &lnk::Link) -> Record {
        let mut record = Record::new(
            input.evidence,
            NAMESPACE,
            Locator::ByteOffset(0),
            self.parser(),
        );
        let target = target(link);
        record.times = times(link);
        record.facets = facets(link);
        record.fields = fields(link);
        record.summary = match &link.tracker {
            Some(t) => format!("Link to {target} (made on {})", t.machine_id),
            None => format!("Link to {target}"),
        };
        record
    }
}

/// The target's times as the link saw them, and when its tracker
/// identifier was made.
pub(crate) fn times(link: &lnk::Link) -> Vec<RecordTime> {
    let mut times = Vec::new();
    for (kind, field, time) in [
        (TimeKind::Created, "TargetCreated", link.created),
        (TimeKind::Modified, "TargetModified", link.modified),
        (TimeKind::Accessed, "TargetAccessed", link.accessed),
        (
            TimeKind::Other,
            "TrackerCreatedOn",
            link.tracker.as_ref().map_or(0, |t| t.created),
        ),
    ] {
        if time != 0 {
            times.push(RecordTime::new(kind, field, Ts::from_filetime(time)));
        }
    }
    times
}

/// The target path, and the arguments as a command line.
pub(crate) fn facets(link: &lnk::Link) -> Facets {
    Facets {
        file_path: Some(target(link)),
        process_command_line: (!link.arguments.is_empty()).then(|| link.arguments.clone()),
        ..Facets::default()
    }
}

/// Everything the link records, named as LECmd names it.
pub(crate) fn fields(link: &lnk::Link) -> Fields {
    let mut fields = Fields::new();
    let mut text = |name: &str, value: &str| {
        if !value.is_empty() {
            fields.insert(name.into(), Value::from(value));
        }
    };
    text("LocalPath", &link.local_path);
    text("NetworkPath", &link.network_path);
    text("CommonPath", &link.common_path);
    text("TargetIDAbsolutePath", &link.target_path());
    text("RelativePath", &link.relative_path);
    text("WorkingDirectory", &link.working_dir);
    text("Arguments", &link.arguments);
    text("Name", &link.name);
    text("IconLocation", &link.icon_location);
    text("EnvironmentTarget", &link.environment_target);
    if let Some(volume) = &link.volume {
        text("VolumeLabel", &volume.label);
        fields.insert(
            "VolumeSerialNumber".into(),
            Value::Text(format!("{:08X}", volume.serial)),
        );
        fields.insert(
            "DriveType".into(),
            Value::UInt(u64::from(volume.drive_type)),
        );
    }
    if let Some(tracker) = &link.tracker {
        fields.insert("MachineID".into(), Value::from(tracker.machine_id.as_str()));
        fields.insert(
            "MachineMACAddress".into(),
            Value::from(tracker.mac.as_str()),
        );
        fields.insert("ObjectID".into(), Value::from(tracker.object_id.as_str()));
    }
    if let Some((entry, sequence)) = link.target.iter().rev().find_map(|i| i.mft) {
        fields.insert("TargetMFTEntryNumber".into(), Value::UInt(entry));
        fields.insert(
            "TargetMFTSequenceNumber".into(),
            Value::UInt(u64::from(sequence)),
        );
    }
    fields.insert("FileSize".into(), Value::UInt(u64::from(link.size)));
    fields.insert(
        "FileAttributes".into(),
        Value::UInt(u64::from(link.attributes)),
    );
    fields.insert(
        "HeaderFlags".into(),
        Value::List(link.flag_names().into_iter().map(Value::from).collect()),
    );
    fields
}
