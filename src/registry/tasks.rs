//! SOFTWARE: scheduled tasks from the Task Scheduler's cache. The
//! `DynamicInfo` times keep the names public research gives them
//! (`Registered`, `LastStart`, `LastStop`); their meaning is inferred, not
//! documented (see `registry::tasks`).

use common::time::Ts;
use model::{Facets, Fields, RecordTime, TimeKind, Value};
use registry::tasks::{self, Action, Actions, Task};
use registry::Hive;

use super::{insert_texts, Out, TASKS};

/// An action as text: `program arguments`, `COM {CLSID} data`.
fn action_text(action: &Action) -> String {
    match action {
        Action::Exec {
            command, arguments, ..
        } if arguments.is_empty() => command.clone(),
        Action::Exec {
            command, arguments, ..
        } => format!("{command} {arguments}"),
        Action::ComHandler { clsid, data } if data.is_empty() => format!("COM {clsid}"),
        Action::ComHandler { clsid, data } => format!("COM {clsid} {data}"),
    }
}

impl Out<'_, '_> {
    /// Every cached task, and every `Tree` entry left without one.
    pub(super) fn tasks(&mut self, hive: &Hive<'_>) {
        let found = tasks::tasks(hive);
        self.problems(found.problems);
        for task in &found.entries {
            self.task(task);
        }
    }

    fn task(&mut self, task: &Task) {
        let mut record = self.keyed(TASKS, &task.key, None, task.key_last_written);
        if let Some(dynamic) = task.dynamic {
            for (kind, field, time) in [
                (TimeKind::Created, "Registered", Some(dynamic.registered)),
                (TimeKind::Executed, "LastStart", Some(dynamic.last_start)),
                (TimeKind::Other, "LastStop", dynamic.last_stop),
            ] {
                if let Some(time) = time.filter(|&t| t != 0) {
                    record
                        .times
                        .push(RecordTime::new(kind, field, Ts::from_filetime(time)));
                }
            }
        }
        let mut fields = Fields::new();
        fields.insert("Path".into(), Value::from(task.path.as_str()));
        fields.insert("InTree".into(), Value::Bool(task.in_tree));
        insert_texts(
            &mut fields,
            &[
                ("Id", task.id.as_ref()),
                ("URI", task.uri.as_ref()),
                ("Author", task.author.as_ref()),
                ("Description", task.description.as_ref()),
                ("Source", task.source.as_ref()),
                ("SecurityDescriptor", task.security_descriptor.as_ref()),
            ],
        );
        if let Some(dynamic) = task.dynamic {
            fields.insert("TaskState".into(), Value::UInt(u64::from(dynamic.state)));
            fields.insert(
                "LastResult".into(),
                Value::Text(format!("0x{:08X}", dynamic.last_result)),
            );
        }
        let mut program = None;
        match &task.actions {
            Some(Actions::Decoded {
                principal, actions, ..
            }) => {
                fields.insert("Principal".into(), Value::from(principal.as_str()));
                let texts: Vec<Value> = actions
                    .iter()
                    .map(|a| Value::Text(action_text(a)))
                    .collect();
                fields.insert("Actions".into(), Value::List(texts));
                program = actions.iter().find_map(|a| match a {
                    Action::Exec {
                        command,
                        arguments,
                        working_directory,
                    } => Some((command, arguments, working_directory)),
                    Action::ComHandler { .. } => None,
                });
            }
            Some(Actions::Strings(strings)) => {
                fields.insert(
                    "ActionStrings".into(),
                    Value::List(strings.iter().map(|s| Value::from(s.as_str())).collect()),
                );
                fields.insert(
                    "ActionsNote".into(),
                    Value::from("Actions not decodable: its UTF-16 strings, meaning unknown"),
                );
            }
            None => {}
        }
        if let Some((command, arguments, directory)) = program {
            fields.insert("Command".into(), Value::from(command.as_str()));
            if !arguments.is_empty() {
                fields.insert("Arguments".into(), Value::from(arguments.as_str()));
            }
            if !directory.is_empty() {
                fields.insert("WorkingDirectory".into(), Value::from(directory.as_str()));
            }
        }
        record.facets = Facets {
            task_name: Some(task.path.clone()),
            process_path: program.map(|(command, _, _)| command.clone()),
            process_command_line: program.map(|(command, arguments, _)| {
                if arguments.is_empty() {
                    command.clone()
                } else {
                    format!("{command} {arguments}")
                }
            }),
            ..Facets::default()
        };
        record.fields = fields;
        record.summary = match (&task.actions, task.id.is_some()) {
            (_, false) => format!("Scheduled task {} (Tree entry, no task key)", task.path),
            (Some(Actions::Decoded { actions, .. }), true) if !actions.is_empty() => {
                let first = action_text(&actions[0]);
                format!("Scheduled task {} → {first}", task.path)
            }
            _ => format!("Scheduled task {}", task.path),
        };
        self.sink.record(record);
    }
}
