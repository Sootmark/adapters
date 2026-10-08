//! SOFTWARE, NTUSER.DAT and SYSTEM: persistence keys beyond Run and RunOnce, each
//! flagged (`DeviatesFromDefault`) when its data departs from Windows'
//! default.

use common::time::Ts;
use model::{Facets, Fields, RecordTime, TimeKind, Value};
use registry::persistence::{self, Entry, Mechanism};
use registry::Hive;

use super::{insert_texts, Out, PERSISTENCE};

/// What the entry's data names: a program to run, or DLLs to load.
fn facets(entry: &Entry) -> Facets {
    let data = Some(entry.data.clone()).filter(|d| !d.trim().is_empty());
    match entry.mechanism {
        Mechanism::WinlogonShell
        | Mechanism::WinlogonUserinit
        | Mechanism::WinlogonTaskman
        | Mechanism::IfeoDebugger
        | Mechanism::SilentProcessExit
        | Mechanism::ActiveSetup
        | Mechanism::BootExecute
        | Mechanism::BootVerification => Facets {
            process_command_line: data,
            ..Facets::default()
        },
        Mechanism::AppInitDlls => Facets {
            file_path: data,
            ..Facets::default()
        },
        Mechanism::IfeoGlobalFlag | Mechanism::LoadAppInitDlls | Mechanism::StartupApproved => {
            Facets::default()
        }
    }
}

impl Out<'_, '_> {
    /// Every persistence entry the hive holds.
    pub(super) fn persistence(&mut self, hive: &Hive<'_>) {
        let found = persistence::entries(hive);
        self.problems(found.problems);
        for entry in &found.entries {
            self.persistence_entry(entry);
        }
    }

    fn persistence_entry(&mut self, entry: &Entry) {
        let mut record = self.keyed(
            PERSISTENCE,
            &entry.key,
            Some(&entry.value),
            entry.key_last_written,
        );
        if let Some(disabled) = entry.disabled_at {
            record.times.push(RecordTime::new(
                TimeKind::Modified,
                "Disabled",
                Ts::from_filetime(disabled),
            ));
        }
        record.facets = facets(entry);
        let mut fields = Fields::new();
        fields.insert("Mechanism".into(), Value::from(entry.mechanism.name()));
        fields.insert("Value".into(), Value::from(entry.value.as_str()));
        fields.insert("Data".into(), Value::from(entry.data.as_str()));
        fields.insert("DeviatesFromDefault".into(), Value::Bool(entry.deviates));
        fields.insert(
            "Scope".into(),
            Value::from(match (entry.user, entry.wow64) {
                (true, _) => "user",
                (false, true) => "machine (32-bit)",
                (false, false) => "machine",
            }),
        );
        if let Some(default) = entry.default {
            fields.insert("Default".into(), Value::from(default));
        }
        insert_texts(
            &mut fields,
            &[
                ("Target", entry.target.as_ref()),
                ("Label", entry.label.as_ref()),
            ],
        );
        if let Some(enabled) = entry.enabled {
            fields.insert("Enabled".into(), Value::Bool(enabled));
        }
        record.fields = fields;
        let subject = entry
            .target
            .as_deref()
            .map_or_else(String::new, |t| format!(" {t}"));
        record.summary = match (entry.mechanism, entry.enabled) {
            (Mechanism::StartupApproved, Some(false)) => format!("Startup entry{subject} disabled"),
            (Mechanism::StartupApproved, _) => format!("Startup entry{subject} enabled"),
            _ => format!(
                "{}{subject}: {}{}",
                entry.value,
                entry.data,
                if entry.deviates {
                    " (not Windows' default)"
                } else {
                    ""
                }
            ),
        };
        self.sink.record(record);
    }
}
