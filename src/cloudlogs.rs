//! Cloud and SaaS audit logs, via the `cloudlogs` parser: AWS CloudTrail,
//! Microsoft 365's unified audit log, Entra ID sign-ins and audits,
//! Azure's activity log, Google Cloud logging, Google Workspace's audit
//! activities; one record per event, its
//! main fields named alike across providers (`Operation`, `Actor`,
//! `SourceIp`, `Target`, `Result`, …) and every value of the provider's
//! record kept under its dotted path (`userIdentity.arn`).

use cloudlogs::{Event, Source};
use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};

/// Records of AWS CloudTrail.
pub const CLOUDTRAIL: Namespace = Namespace::new("cloud.cloudtrail");
/// Records of Microsoft 365's unified audit log.
pub const M365: Namespace = Namespace::new("cloud.m365");
/// Records of Entra ID sign-ins.
pub const ENTRA_SIGNIN: Namespace = Namespace::new("cloud.entra_signin");
/// Records of Entra ID directory audits.
pub const ENTRA_AUDIT: Namespace = Namespace::new("cloud.entra_audit");
/// Records of Azure's activity log.
pub const AZURE_ACTIVITY: Namespace = Namespace::new("cloud.azure_activity");
/// Records of Google Cloud logging.
pub const GCP: Namespace = Namespace::new("cloud.gcp");
/// Google Workspace audit activities.
pub const WORKSPACE: Namespace = Namespace::new("cloud.workspace");

/// One record per event.
#[derive(Debug, Default, Clone, Copy)]
pub struct CloudlogsAdapter;

impl Adapter for CloudlogsAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "cloudlogs",
            version: cloudlogs::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[
            CLOUDTRAIL,
            M365,
            ENTRA_SIGNIN,
            ENTRA_AUDIT,
            AZURE_ACTIVITY,
            GCP,
            WORKSPACE,
        ]
    }

    /// By the first records' members.
    fn probe(&self, _name: &str, head: &[u8]) -> Confidence {
        if cloudlogs::detect(head).is_some() {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let log = cloudlogs::read(input.data);
        if log.events.is_empty() {
            return Err(ParseError::at(
                0,
                log.problems
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "no cloud audit log record".to_owned()),
            ));
        }
        for event in &log.events {
            sink.record(self.record(input, event));
        }
        for reason in log.problems {
            sink.skipped(Skipped {
                locator: Locator::ByteOffset(0),
                reason,
            });
        }
        Ok(())
    }
}

impl CloudlogsAdapter {
    fn record(self, input: &Input<'_>, event: &Event) -> Record {
        let source = event.source.unwrap_or(Source::CloudTrail);
        let (namespace, label) = match source {
            Source::CloudTrail => (CLOUDTRAIL, "CloudTrail"),
            Source::Microsoft365 => (M365, "Microsoft 365"),
            Source::EntraSignIn => (ENTRA_SIGNIN, "Entra sign-in"),
            Source::EntraAudit => (ENTRA_AUDIT, "Entra audit"),
            Source::AzureActivity => (AZURE_ACTIVITY, "Azure"),
            Source::GoogleCloud => (GCP, "Google Cloud"),
            Source::GoogleWorkspace => (WORKSPACE, "Google Workspace"),
        };
        let mut record = Record::new(
            input.evidence,
            namespace,
            Locator::TableRow {
                table: table(source, event.part),
                row: event.position as u64,
            },
            self.parser(),
        );
        if let Some(time) = event.time {
            record
                .times
                .push(RecordTime::new(TimeKind::Logged, "Time", time));
        }
        let mut fields = Fields::new();
        for (path, value) in &event.fields {
            fields.insert(path.clone(), Value::from(value.as_str()));
        }
        for (name, value) in [
            ("Operation", &event.operation),
            ("Service", &event.service),
            ("Actor", &event.actor),
            ("ActorId", &event.actor_id),
            ("SourceIp", &event.source_ip),
            ("UserAgent", &event.user_agent),
            ("Target", &event.target),
            ("Result", &event.result),
            ("EventId", &event.id),
            ("Location", &event.location),
        ] {
            if let Some(value) = value {
                fields.insert(name.into(), Value::from(value.as_str()));
            }
        }
        record.fields = fields;
        record.facets.user_name.clone_from(&event.actor);
        record.facets.source_ip.clone_from(&event.source_ip);
        let target = event
            .target
            .as_deref()
            .map_or_else(String::new, |t| format!(" {t}"));
        let from = event
            .source_ip
            .as_deref()
            .map_or_else(String::new, |ip| format!(" from {ip}"));
        let result = event
            .result
            .as_deref()
            .map_or_else(String::new, |r| format!(" ({r})"));
        record.summary = format!(
            "{label}: {} {}{target}{from}{result}",
            event.actor.as_deref().unwrap_or("?"),
            event.operation.as_deref().unwrap_or("?"),
        );
        record
    }
}

/// The locator's table: the source's name, and for a record's later
/// events (a Workspace activity's) their place, so each has its own.
fn table(source: Source, part: usize) -> String {
    match part {
        0 => source.name().to_owned(),
        part => format!("{} event {part}", source.name()),
    }
}
