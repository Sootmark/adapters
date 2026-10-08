//! Scheduled task files, via the `tasks` parser: task XML files
//! (`Windows\System32\Tasks\…`) and `.job` files (`Windows\Tasks\*.job`),
//! one record per task: what runs, as whom, when it triggers, whether it
//! is enabled or hidden, and when it was registered or last ran.

use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{
    Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Ts, Value,
};
use tasks::job::Job;
use tasks::task::{Action, Task};
use tasks::Kind;

/// Records of task XML files.
pub const XML: Namespace = Namespace::new("windows.scheduled_task");
/// Records of `.job` files.
pub const JOB: Namespace = Namespace::new("windows.job");

/// One record per task file.
#[derive(Debug, Default, Clone, Copy)]
pub struct TasksAdapter;

impl Adapter for TasksAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "tasks",
            version: tasks::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[XML, JOB]
    }

    /// By content: a `.job` file's fixed-length part, or a `<Task`
    /// element (certain in a `Tasks` folder, maybe elsewhere).
    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        match tasks::detect(head) {
            Some(Kind::Job) => Confidence::Certain,
            Some(Kind::Xml)
                if name
                    .split(['/', '\\'])
                    .any(|part| part.eq_ignore_ascii_case("Tasks")) =>
            {
                Confidence::Certain
            }
            Some(Kind::Xml) => Confidence::Maybe,
            None => Confidence::No,
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let record = match tasks::detect(input.data) {
            Some(Kind::Xml) => {
                let task = tasks::task::read(input.data);
                report(sink, &task.problems);
                self.xml(input, &task)
            }
            Some(Kind::Job) => {
                let job = tasks::job::read(input.data).map_err(|e| ParseError::at(0, e.0))?;
                report(sink, &job.problems);
                self.job(input, &job)
            }
            None => return Err(ParseError::at(0, "not a task XML or .job file")),
        };
        sink.record(record);
        Ok(())
    }
}

impl TasksAdapter {
    fn record(self, input: &Input<'_>, namespace: Namespace) -> Record {
        Record::new(
            input.evidence,
            namespace,
            Locator::ByteOffset(0),
            self.parser(),
        )
    }

    fn xml(self, input: &Input<'_>, task: &Task) -> Record {
        let mut record = self.record(input, XML);
        push_time(&mut record, TimeKind::Created, "Date", task.registered());
        if let Some(trigger) = task.triggers.iter().find(|t| t.start.is_some()) {
            push_time(
                &mut record,
                TimeKind::Other,
                "StartBoundary",
                trigger.start_time(),
            );
        }
        let principal = task.principal();
        let exec = task.actions.iter().find_map(|action| match action {
            Action::Exec {
                command,
                arguments,
                working_directory,
            } => Some((command, arguments, working_directory)),
            _ => None,
        });
        let mut fields = Fields::new();
        text(&mut fields, "URI", task.uri.as_deref());
        text(&mut fields, "Author", task.author.as_deref());
        text(&mut fields, "Description", task.description.as_deref());
        fields.insert("Enabled".into(), Value::Bool(task.enabled()));
        fields.insert("Hidden".into(), Value::Bool(task.hidden()));
        if let Some(principal) = principal {
            text(&mut fields, "UserId", principal.user_id.as_deref());
            text(&mut fields, "GroupId", principal.group_id.as_deref());
            text(&mut fields, "LogonType", principal.logon_type.as_deref());
            text(&mut fields, "RunLevel", principal.run_level.as_deref());
        }
        let triggers: Vec<Value> = task
            .triggers
            .iter()
            .map(|t| {
                let state = if t.enabled { "" } else { " (disabled)" };
                let every = t
                    .repetition
                    .as_deref()
                    .map_or_else(String::new, |r| format!(" every {r}"));
                Value::from(format!("{}{every}{state}", t.kind))
            })
            .collect();
        fields.insert("Triggers".into(), Value::List(triggers));
        let actions: Vec<Value> = task
            .actions
            .iter()
            .map(|a| Value::from(a.summary()))
            .collect();
        fields.insert("Actions".into(), Value::List(actions));
        if let Some((command, arguments, directory)) = exec {
            text(&mut fields, "Command", Some(command));
            text(&mut fields, "Arguments", arguments.as_deref());
            text(&mut fields, "WorkingDirectory", directory.as_deref());
        }
        if let Some(Action::ComHandler { class_id, .. }) = task
            .actions
            .iter()
            .find(|a| matches!(a, Action::ComHandler { .. }))
        {
            text(&mut fields, "ComClassId", Some(class_id));
        }
        record.fields = fields;
        let name = task.uri.clone().unwrap_or_else(|| input.name.to_owned());
        record.facets = Facets {
            task_name: Some(name.clone()),
            user_name: principal.and_then(|p| p.user_id.clone()),
            process_path: exec.map(|(command, _, _)| command.clone()),
            process_command_line: task
                .actions
                .iter()
                .find(|a| matches!(a, Action::Exec { .. }))
                .map(Action::summary),
            ..Facets::default()
        };
        let hidden = if task.hidden() { ", hidden" } else { "" };
        let disabled = if task.enabled() { "" } else { ", disabled" };
        record.summary = format!(
            "Scheduled task {name}: {}{hidden}{disabled}",
            task.actions
                .first()
                .map_or_else(|| "no action".to_owned(), Action::summary)
        );
        record
    }

    fn job(self, input: &Input<'_>, job: &Job) -> Record {
        let mut record = self.record(input, JOB);
        push_time(&mut record, TimeKind::Executed, "LastRun", job.last_run);
        if let Some(trigger) = job.triggers.iter().find(|t| t.start.is_some()) {
            push_time(&mut record, TimeKind::Other, "TriggerStart", trigger.start);
        }
        let mut fields = Fields::new();
        text(&mut fields, "Id", Some(&job.id));
        text(&mut fields, "Application", job.application.as_deref());
        text(&mut fields, "Parameters", job.parameters.as_deref());
        text(
            &mut fields,
            "WorkingDirectory",
            job.working_directory.as_deref(),
        );
        text(&mut fields, "Author", job.author.as_deref());
        text(&mut fields, "Comment", job.comment.as_deref());
        fields.insert("Status".into(), Value::from(format!("{:#x}", job.status)));
        text(&mut fields, "StatusName", job.status_name());
        fields.insert("ExitCode".into(), Value::UInt(u64::from(job.exit_code)));
        fields.insert("Flags".into(), Value::from(format!("{:#x}", job.flags)));
        fields.insert("Disabled".into(), Value::Bool(job.disabled()));
        fields.insert("Hidden".into(), Value::Bool(job.hidden()));
        let triggers: Vec<Value> = job
            .triggers
            .iter()
            .map(|t| Value::from(t.kind_name()))
            .collect();
        fields.insert("Triggers".into(), Value::List(triggers));
        record.fields = fields;
        let command_line = job.command_line();
        record.facets = Facets {
            task_name: Some(input.name.to_owned()),
            user_name: job.author.clone(),
            process_path: job.application.clone(),
            process_command_line: command_line.clone(),
            ..Facets::default()
        };
        record.summary = format!(
            "Scheduled job {}: {}",
            input.name.rsplit(['/', '\\']).next().unwrap_or(input.name),
            command_line.as_deref().unwrap_or("no program")
        );
        record
    }
}

fn push_time(record: &mut Record, kind: TimeKind, name: &str, time: Option<Ts>) {
    if let Some(time) = time {
        record.times.push(RecordTime::new(kind, name, time));
    }
}

fn report(sink: &mut dyn Sink, problems: &[String]) {
    for reason in problems {
        sink.skipped(Skipped {
            locator: Locator::ByteOffset(0),
            reason: reason.clone(),
        });
    }
}

fn text(fields: &mut Fields, name: &str, value: Option<&str>) {
    if let Some(value) = value.filter(|v| !v.is_empty()) {
        fields.insert(name.into(), Value::from(value));
    }
}
