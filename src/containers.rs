//! Containers, via the `containers` parser: Docker container
//! configurations (one record per container: image, command, user, mounts,
//! ports, created, started, finished), Docker and CRI logs (one record per
//! line written) and Docker image layers (one record per layer, with the
//! command that made it).

use containers::{Container, Content, Kind, Layer, LogLine};
use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};

/// Records of Docker containers.
pub const CONTAINERS: Namespace = Namespace::new("container.docker");
/// Records of container logs (Docker and CRI).
pub const LOGS: Namespace = Namespace::new("container.log");
/// Records of Docker image layers.
pub const LAYERS: Namespace = Namespace::new("container.layer");

const SUMMARY_TEXT: usize = 200;

/// One record per container, log line or layer.
#[derive(Debug, Default, Clone, Copy)]
pub struct ContainersAdapter;

impl Adapter for ContainersAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "containers",
            version: containers::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[CONTAINERS, LOGS, LAYERS]
    }

    /// By path and first line.
    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        if containers::detect(name, head).is_some() {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let kind = containers::detect(input.name, input.data)
            .ok_or_else(|| ParseError::at(0, "not a container file this parser reads"))?;
        let read = containers::read(kind, input.data);
        for reason in read.problems {
            sink.skipped(Skipped {
                locator: Locator::ByteOffset(0),
                reason,
            });
        }
        match read.content {
            Content::Container(container) => sink.record(self.container(input, &container)),
            Content::Layer(layer) => sink.record(self.layer(input, &layer)),
            Content::Log(lines) => {
                let runtime = if kind == Kind::CriLog {
                    "cri"
                } else {
                    "docker"
                };
                for line in &lines {
                    sink.record(self.log_line(input, runtime, line));
                }
            }
        }
        Ok(())
    }
}

impl ContainersAdapter {
    fn record(self, input: &Input<'_>, namespace: Namespace, locator: Locator) -> Record {
        Record::new(input.evidence, namespace, locator, self.parser())
    }

    fn container(self, input: &Input<'_>, container: &Container) -> Record {
        let mut record = self.record(input, CONTAINERS, Locator::ByteOffset(0));
        for (kind, name, time) in [
            (TimeKind::Created, "Created", container.created),
            (TimeKind::Executed, "Started", container.started),
            (TimeKind::Other, "Finished", container.finished),
        ] {
            if let Some(time) = time {
                record.times.push(RecordTime::new(kind, name, time));
            }
        }
        let mut fields = Fields::new();
        for (name, value) in [
            ("Id", &container.id),
            ("Name", &container.name),
            ("Hostname", &container.hostname),
            ("Image", &container.image),
            ("ImageId", &container.image_id),
            ("Command", &container.command),
            ("User", &container.user),
        ] {
            if let Some(value) = value {
                fields.insert(name.into(), Value::from(value.as_str()));
            }
        }
        for (name, values) in [
            ("Env", &container.env),
            ("Mounts", &container.mounts),
            ("Ports", &container.ports),
        ] {
            if !values.is_empty() {
                fields.insert(
                    name.into(),
                    Value::List(values.iter().map(|v| Value::from(v.as_str())).collect()),
                );
            }
        }
        for (name, value) in [
            ("Privileged", container.privileged),
            ("Running", container.running),
        ] {
            if let Some(value) = value {
                fields.insert(name.into(), Value::Bool(value));
            }
        }
        record.fields = fields;
        record.facets = Facets {
            host_name: container.hostname.clone(),
            user_name: container.user.clone(),
            process_command_line: container.command.clone(),
            ..Facets::default()
        };
        record.summary = format!(
            "Container {} ({}): {}",
            container.name.as_deref().unwrap_or("?"),
            container.image.as_deref().unwrap_or("?"),
            container.command.as_deref().unwrap_or("?")
        );
        record
    }

    fn layer(self, input: &Input<'_>, layer: &Layer) -> Record {
        let mut record = self.record(input, LAYERS, Locator::ByteOffset(0));
        if let Some(created) = layer.created {
            record
                .times
                .push(RecordTime::new(TimeKind::Created, "Created", created));
        }
        let mut fields = Fields::new();
        for (name, value) in [
            ("Id", &layer.id),
            ("Command", &layer.command),
            ("Author", &layer.author),
        ] {
            if let Some(value) = value {
                fields.insert(name.into(), Value::from(value.as_str()));
            }
        }
        record.fields = fields;
        record
            .facets
            .process_command_line
            .clone_from(&layer.command);
        record.summary = format!(
            "Image layer made by {}",
            layer.command.as_deref().unwrap_or("?")
        );
        record
    }

    fn log_line(self, input: &Input<'_>, runtime: &str, line: &LogLine) -> Record {
        let mut record = self.record(input, LOGS, Locator::Line(line.line as u64));
        if let Some(time) = line.time {
            record
                .times
                .push(RecordTime::new(TimeKind::Logged, "Time", time));
        }
        let mut fields = Fields::new();
        fields.insert("Runtime".into(), Value::from(runtime));
        fields.insert("Stream".into(), Value::from(line.stream.as_str()));
        fields.insert("Text".into(), Value::from(line.text.as_str()));
        if line.partial {
            fields.insert("Partial".into(), Value::Bool(true));
        }
        record.fields = fields;
        let text: String = line.text.trim().chars().take(SUMMARY_TEXT).collect();
        record.summary = format!("{runtime} {}: {text}", line.stream);
        record
    }
}
