//! The WMI repository (`Windows\System32\wbem\Repository`), via the `wmi`
//! parser: its `OBJECTS.DATA` read with the `INDEX.BTR` and `MAPPING`
//! files beside it. One record per event filter, consumer and binding in
//! every namespace: the subscriptions attackers persist with, a binding
//! saying when (the filter's query) WMI runs what (its consumer's command
//! line or script).

use model::adapter::{Adapter, Companion, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};
use wmi::{Binding, Instance, Repository};

/// Records of WMI repositories.
pub const NAMESPACE: Namespace = Namespace::new("windows.wmi");

/// The files read with `OBJECTS.DATA`.
const COMPANIONS: [&str; 4] = ["INDEX.BTR", "MAPPING1.MAP", "MAPPING2.MAP", "MAPPING3.MAP"];
/// Bytes of a repository page: `OBJECTS.DATA` is made of them.
const PAGE_SIZE: usize = 0x2000;

/// One record per subscription filter, consumer and binding.
#[derive(Debug, Default, Clone, Copy)]
pub struct WmiAdapter;

impl Adapter for WmiAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "wmi",
            version: wmi::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[NAMESPACE]
    }

    /// By name (`OBJECTS.DATA`): the file has no signature, only pages.
    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        if wmi::detect(name) != Some(wmi::File::Objects) {
            Confidence::No
        } else if head.len() < PAGE_SIZE || head.len() % PAGE_SIZE == 0 {
            Confidence::Certain
        } else {
            Confidence::Maybe
        }
    }

    fn companions(&self, name: &str) -> Vec<String> {
        if wmi::detect(name) == Some(wmi::File::Objects) {
            COMPANIONS.iter().map(|&c| c.to_owned()).collect()
        } else {
            Vec::new()
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        self.parse_with_companions(input, &[], sink)
    }

    fn parse_with_companions(
        &self,
        input: &Input<'_>,
        companions: &[Companion<'_>],
        sink: &mut dyn Sink,
    ) -> Result<(), ParseError> {
        let find = |name: &str| {
            companions
                .iter()
                .find(|c| c.name.eq_ignore_ascii_case(name))
                .map(|c| c.data)
        };
        let index = find("INDEX.BTR").ok_or_else(|| {
            ParseError::at(0, "INDEX.BTR not beside it: the repository can't be read")
        })?;
        let maps: Vec<&[u8]> = COMPANIONS[1..].iter().filter_map(|m| find(m)).collect();
        let repository =
            Repository::open(input.data, index, &maps).map_err(|e| ParseError::at(0, e.0))?;
        let subscriptions = wmi::subscriptions(&repository);
        for reason in repository.problems.iter().chain(&subscriptions.problems) {
            sink.skipped(Skipped {
                locator: Locator::ByteOffset(0),
                reason: reason.clone(),
            });
        }
        let instances = subscriptions
            .filters
            .iter()
            .map(|f| ("filter", f))
            .chain(subscriptions.consumers.iter().map(|c| ("consumer", c)));
        for (row, (kind, instance)) in (0u64..).zip(instances) {
            sink.record(self.instance(input, row, kind, instance));
        }
        for (row, binding) in (0u64..).zip(&subscriptions.bindings) {
            sink.record(self.binding(input, row, binding));
        }
        Ok(())
    }
}

impl WmiAdapter {
    fn record(
        self,
        input: &Input<'_>,
        table: &str,
        row: u64,
        times: &[Option<model::Ts>; 2],
    ) -> Record {
        let mut record = Record::new(
            input.evidence,
            NAMESPACE,
            Locator::TableRow {
                table: table.to_owned(),
                row,
            },
            self.parser(),
        );
        for (time, name) in times.iter().zip(["Timestamp1", "Timestamp2"]) {
            if let Some(time) = time {
                record
                    .times
                    .push(RecordTime::new(TimeKind::Other, name, *time));
            }
        }
        record
    }

    fn instance(self, input: &Input<'_>, row: u64, kind: &str, instance: &Instance) -> Record {
        let mut record = self.record(input, kind, row, &instance.times);
        let mut fields = Fields::new();
        fields.insert("Kind".into(), Value::from(kind));
        fields.insert("Namespace".into(), Value::from(instance.namespace.as_str()));
        fields.insert("Class".into(), Value::from(instance.class.as_str()));
        for (name, value) in &instance.properties {
            let Some(value) = value else { continue };
            let text = if name == "CreatorSID" {
                sid(value).unwrap_or_else(|| value.to_string())
            } else {
                value.to_string()
            };
            if !text.is_empty() {
                fields.insert(name.clone(), Value::from(text));
            }
        }
        let name = instance.text("Name").unwrap_or("?");
        let action = consumer_action(instance);
        record.facets = Facets {
            user_sid: instance.get("CreatorSID").and_then(sid),
            process_command_line: action.clone(),
            ..Facets::default()
        };
        record.summary = match kind {
            "filter" => format!(
                "WMI filter {name} ({}): {}",
                instance.namespace,
                instance.text("Query").unwrap_or("?")
            ),
            _ => format!(
                "WMI {} {name} ({}): {}",
                instance.class,
                instance.namespace,
                action.as_deref().unwrap_or("?")
            ),
        };
        record.fields = fields;
        record
    }

    fn binding(self, input: &Input<'_>, row: u64, binding: &Binding) -> Record {
        let mut record = self.record(input, "binding", row, &binding.times);
        let mut fields = Fields::new();
        fields.insert("Kind".into(), Value::from("binding"));
        fields.insert("Namespace".into(), Value::from(binding.namespace.as_str()));
        fields.insert("Filter".into(), Value::from(binding.filter.as_str()));
        fields.insert("Consumer".into(), Value::from(binding.consumer.as_str()));
        for (name, value) in [
            ("ConsumerClass", &binding.consumer_class),
            ("Query", &binding.query),
            ("Action", &binding.action),
        ] {
            if let Some(value) = value {
                fields.insert(name.into(), Value::from(value.as_str()));
            }
        }
        record.facets = Facets {
            process_command_line: binding.action.clone(),
            ..Facets::default()
        };
        record.summary = format!(
            "WMI subscription ({}): when {} run {}: {}",
            binding.namespace,
            binding.query.as_deref().unwrap_or("?"),
            binding.consumer_class.as_deref().unwrap_or("?"),
            binding.action.as_deref().unwrap_or("?")
        );
        record.fields = fields;
        record
    }
}

/// What a consumer runs: its command line or script.
fn consumer_action(instance: &Instance) -> Option<String> {
    [
        "CommandLineTemplate",
        "ExecutablePath",
        "ScriptText",
        "ScriptFileName",
    ]
    .iter()
    .find_map(|name| instance.text(name))
    .map(str::to_owned)
}

/// A SID stored as an array of bytes (`CreatorSID`), as `S-1-5-…`.
fn sid(value: &wmi::Value) -> Option<String> {
    let wmi::Value::Array(items) = value else {
        return None;
    };
    let bytes: Vec<u8> = items
        .iter()
        .map(|item| match item {
            wmi::Value::UInt(byte) => u8::try_from(*byte).ok(),
            _ => None,
        })
        .collect::<Option<_>>()?;
    common::win::sid_to_string(&bytes).ok().map(|(sid, _)| sid)
}
