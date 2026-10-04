//! SOFTWARE and NTUSER.DAT: installed programs. `InstallDate` is a local
//! date: kept to the day, zone unknown.

use common::time::Precision;
use model::{Facets, Fields, RecordTime, TimeKind, Value};
use registry::programs::{self, Program};
use registry::Hive;

use super::{insert_texts, local, Out, PROGRAMS};

impl Out<'_, '_> {
    /// Every `Uninstall` entry.
    pub(super) fn programs(&mut self, hive: &Hive<'_>) {
        let found = programs::programs(hive);
        self.problems(found.problems);
        for program in &found.entries {
            self.program(program);
        }
    }

    fn program(&mut self, program: &Program) {
        let mut record = self.keyed(PROGRAMS, &program.key, None, program.key_last_written);
        if let Some(ts) = program
            .install_date()
            .and_then(|d| local(d, Precision::Day))
        {
            record
                .times
                .push(RecordTime::new(TimeKind::Created, "InstallDate", ts));
        }
        record.facets = Facets {
            file_path: program.install_location.clone(),
            ..Facets::default()
        };
        let mut fields = Fields::new();
        fields.insert("KeyName".into(), Value::from(program.key_name.as_str()));
        fields.insert("Wow64".into(), Value::Bool(program.wow64));
        fields.insert("User".into(), Value::Bool(program.user));
        insert_texts(
            &mut fields,
            &[
                ("DisplayName", program.display_name.as_ref()),
                ("DisplayVersion", program.display_version.as_ref()),
                ("Publisher", program.publisher.as_ref()),
                ("InstallDate", program.install_date_text.as_ref()),
                ("InstallLocation", program.install_location.as_ref()),
                ("InstallSource", program.install_source.as_ref()),
                ("UninstallString", program.uninstall_string.as_ref()),
            ],
        );
        record.fields = fields;
        let name = program.display_name.as_deref().unwrap_or(&program.key_name);
        record.summary = match (&program.display_version, &program.publisher) {
            (Some(version), Some(publisher)) => format!("Installed {name} {version} ({publisher})"),
            (Some(version), None) => format!("Installed {name} {version}"),
            (None, Some(publisher)) => format!("Installed {name} ({publisher})"),
            (None, None) => format!("Installed {name}"),
        };
        self.sink.record(record);
    }
}
