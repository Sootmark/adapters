//! Windows Prefetch files, via the `prefetch` parser: what ran, how often,
//! when, and from where.

use std::path::Path;

use common::time::Ts;
use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};

/// Records of `.pf` files.
pub const NAMESPACE: Namespace = Namespace::new("windows.prefetch");

/// One record per prefetch file: every recorded run as an `Executed` time,
/// the volumes' creation times, and the files and directories it touched.
/// Field names follow `PECmd`'s, so native and imported records line up.
#[derive(Debug, Default, Clone, Copy)]
pub struct PrefetchAdapter;

impl Adapter for PrefetchAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "prefetch",
            version: prefetch::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[NAMESPACE]
    }

    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        let has_extension = Path::new(name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("pf"));
        if head.get(4..8) == Some(b"SCCA") || (has_extension && head.starts_with(b"MAM")) {
            Confidence::Certain
        } else if has_extension {
            Confidence::Maybe
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let parsed =
            prefetch::parse(input.data).map_err(|e| ParseError::at(e.offset as u64, e.reason))?;
        for problem in &parsed.problems {
            sink.skipped(Skipped {
                locator: Locator::ByteOffset(0),
                reason: problem.clone(),
            });
        }
        sink.record(self.to_record(input, &parsed));
        Ok(())
    }
}

impl PrefetchAdapter {
    fn to_record(self, input: &Input<'_>, pf: &prefetch::Prefetch) -> Record {
        let mut record = Record::new(
            input.evidence,
            NAMESPACE,
            Locator::ByteOffset(0),
            self.parser(),
        );
        for (i, &time) in pf.last_runs.iter().enumerate() {
            let field = if i == 0 {
                "LastRun".to_owned()
            } else {
                format!("PreviousRun{}", i - 1)
            };
            record.times.push(RecordTime::new(
                TimeKind::Executed,
                field,
                Ts::from_filetime(time),
            ));
        }
        for (i, volume) in pf.volumes.iter().enumerate() {
            if volume.created != 0 {
                record.times.push(RecordTime::new(
                    TimeKind::Other,
                    format!("Volume{i}Created"),
                    Ts::from_filetime(volume.created),
                ));
            }
        }
        record.facets = Facets {
            process_path: Some(executable_path(pf)),
            ..Facets::default()
        };
        record.fields = fields(pf);
        record.summary = format!(
            "Prefetch {} · run {} {}",
            pf.executable,
            pf.run_count,
            if pf.run_count == 1 { "time" } else { "times" }
        );
        record
    }
}

/// The executable's full path, from the files it loaded (the one whose
/// name is the executable's); its bare name when none is.
fn executable_path(pf: &prefetch::Prefetch) -> String {
    let suffix = format!("\\{}", pf.executable.to_ascii_uppercase());
    pf.files
        .iter()
        .map(|f| f.path.as_str())
        .find(|path| path.to_ascii_uppercase().ends_with(&suffix))
        .unwrap_or(&pf.executable)
        .to_owned()
}

fn fields(pf: &prefetch::Prefetch) -> Fields {
    let texts = |items: Vec<String>| Value::List(items.into_iter().map(Value::Text).collect());
    let mut fields = Fields::new();
    fields.insert("ExecutableName".into(), Value::from(pf.executable.as_str()));
    fields.insert("Hash".into(), Value::Text(format!("{:08X}", pf.hash)));
    fields.insert("RunCount".into(), Value::UInt(u64::from(pf.run_count)));
    fields.insert("Version".into(), Value::UInt(u64::from(pf.version)));
    fields.insert("Compressed".into(), Value::Bool(pf.compressed));
    fields.insert(
        "FilesLoaded".into(),
        texts(pf.files.iter().map(|f| f.path.clone()).collect()),
    );
    fields.insert(
        "Directories".into(),
        texts(
            pf.volumes
                .iter()
                .flat_map(|v| v.directories.iter().cloned())
                .collect(),
        ),
    );
    for (i, volume) in pf.volumes.iter().enumerate() {
        fields.insert(
            format!("Volume{i}Name"),
            Value::from(volume.device_path.as_str()),
        );
        fields.insert(
            format!("Volume{i}Serial"),
            Value::Text(format!("{:08X}", volume.serial)),
        );
    }
    fields
}
