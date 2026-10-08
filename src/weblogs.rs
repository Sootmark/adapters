//! Web server access logs, via the `weblogs` parser: Apache and nginx,
//! Jira and Confluence, Bitbucket, AWS Elastic Load Balancing and Azure
//! Application Gateway; one record per request, with the client, user,
//! request, status, bytes, referer and user agent.
//!
//! And Atlassian's logs of entries, one record each: the application logs
//! of Jira, Confluence and Bitbucket (`atlassian-jira.log`,
//! `atlassian-confluence.log`, `atlassian-bitbucket.log` and their
//! numbered copies: level, thread, logger, method, the request's user and
//! address, message), Bitbucket's audit log
//! (`atlassian-bitbucket-audit.log`) and the audit log file of Jira,
//! Confluence and Bitbucket Data Center (`*.audit.log`): action, author,
//! source address, affected object. Their lines are common Log4j and JSON,
//! so these are recognised by name as well as by shape.

use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};
use weblogs::{Entry, EntryKind, Kind, Request};

use crate::key::field_name;

/// Records of Apache and nginx access logs.
pub const ACCESS: Namespace = Namespace::new("web.access");
/// Records of Jira and Confluence access logs.
pub const ATLASSIAN: Namespace = Namespace::new("web.atlassian");
/// Records of Bitbucket access logs.
pub const BITBUCKET: Namespace = Namespace::new("web.bitbucket");
/// Records of AWS Elastic Load Balancing access logs.
pub const ELB: Namespace = Namespace::new("web.elb");
/// Records of Azure Application Gateway access logs.
pub const AZURE_GATEWAY: Namespace = Namespace::new("web.azure_gateway");
/// Entries of Jira's, Confluence's and Bitbucket's application logs.
pub const ATLASSIAN_APPLICATION: Namespace = Namespace::new("web.atlassian_application");
/// Events of Bitbucket's audit log and of the Data Center audit log file.
pub const ATLASSIAN_AUDIT: Namespace = Namespace::new("web.atlassian_audit");

/// The longest message kept in a summary.
const SUMMARY_TEXT: usize = 200;

/// One record per request, or per application or audit log entry.
#[derive(Debug, Default, Clone, Copy)]
pub struct WeblogsAdapter;

impl Adapter for WeblogsAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "weblogs",
            version: weblogs::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[
            ACCESS,
            ATLASSIAN,
            BITBUCKET,
            ELB,
            AZURE_GATEWAY,
            ATLASSIAN_APPLICATION,
            ATLASSIAN_AUDIT,
        ]
    }

    /// By the first lines' shape; Atlassian's application and audit logs
    /// by their names too.
    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        if weblogs::detect(name, head).is_some() || entry_kind(name, head).is_some() {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        if let Some(kind) = weblogs::detect(input.name, input.data) {
            self.requests(input, kind, sink);
            return Ok(());
        }
        let kind = entry_kind(input.name, input.data).ok_or_else(|| {
            ParseError::at(
                0,
                "not an access, application or audit log this parser reads",
            )
        })?;
        let (namespace, product) = match kind {
            EntryKind::Application => (ATLASSIAN_APPLICATION, product(input.name)),
            EntryKind::BitbucketAudit | EntryKind::Audit => (ATLASSIAN_AUDIT, None),
        };
        let log = weblogs::read_entries(kind, input.data);
        for entry in &log.entries {
            sink.record(self.entry(input, namespace, product, entry));
        }
        skip(sink, log.problems);
        Ok(())
    }
}

impl WeblogsAdapter {
    fn requests(self, input: &Input<'_>, kind: Kind, sink: &mut dyn Sink) {
        let namespace = match kind {
            Kind::Access => ACCESS,
            Kind::Atlassian => ATLASSIAN,
            Kind::Bitbucket => BITBUCKET,
            Kind::Elb => ELB,
            Kind::AzureGateway => AZURE_GATEWAY,
        };
        let log = weblogs::read(kind, input.data);
        for request in &log.requests {
            sink.record(self.record(input, namespace, request));
        }
        skip(sink, log.problems);
    }

    fn record(self, input: &Input<'_>, namespace: Namespace, request: &Request) -> Record {
        let mut record = Record::new(
            input.evidence,
            namespace,
            Locator::Line(request.line as u64),
            self.parser(),
        );
        if let Some(time) = request.time {
            record
                .times
                .push(RecordTime::new(TimeKind::Logged, "Time", time));
        }
        if let Some(started) = request.started {
            record
                .times
                .push(RecordTime::new(TimeKind::Other, "Started", started));
        }
        let mut fields = Fields::new();
        for (name, value) in [
            ("Client", &request.client),
            ("User", &request.user),
            ("Method", &request.method),
            ("Uri", &request.uri),
            ("Protocol", &request.protocol),
            ("Referer", &request.referer),
            ("UserAgent", &request.user_agent),
            ("Host", &request.host),
        ] {
            if let Some(value) = value {
                fields.insert(name.into(), Value::from(value.as_str()));
            }
        }
        for (name, value) in [
            ("Status", request.status.map(u64::from)),
            ("Bytes", request.bytes),
            ("Port", request.port.map(u64::from)),
            ("DurationMs", request.duration_ms),
        ] {
            if let Some(value) = value {
                fields.insert(name.into(), Value::UInt(value));
            }
        }
        for (name, value) in &request.extra {
            fields.insert(pascal(name), Value::from(value.as_str()));
        }
        record.fields = fields;
        record.facets.source_ip.clone_from(&request.client);
        record.facets.user_name.clone_from(&request.user);
        record.summary = format!(
            "{} {} {}",
            request.client.as_deref().unwrap_or("?"),
            request.request(),
            request
                .status
                .map_or_else(|| "-".to_owned(), |s| s.to_string())
        );
        record
    }

    /// An application log's entry (`product`: whose log, from its name) or
    /// an audit event.
    fn entry(
        self,
        input: &Input<'_>,
        namespace: Namespace,
        product: Option<&str>,
        entry: &Entry,
    ) -> Record {
        let mut record = Record::new(
            input.evidence,
            namespace,
            Locator::Line(entry.line as u64),
            self.parser(),
        );
        if let Some(time) = entry.time {
            record
                .times
                .push(RecordTime::new(TimeKind::Logged, "Time", time));
        }
        let mut fields = Fields::new();
        for (name, value) in [
            ("Product", product),
            ("Level", entry.level.as_deref()),
            ("Thread", entry.thread.as_deref()),
            ("Logger", entry.logger.as_deref()),
            ("Method", entry.method.as_deref()),
            ("User", entry.user.as_deref()),
            ("Client", entry.client.as_deref()),
            ("Action", entry.action.as_deref()),
            ("Object", entry.object.as_deref()),
            ("Message", entry.message.as_deref()),
        ] {
            if let Some(value) = value {
                fields.insert(name.into(), Value::from(value));
            }
        }
        for (name, value) in &entry.extra {
            fields.insert(pascal(name), Value::from(value.as_str()));
        }
        record.fields = fields;
        record.facets.source_ip.clone_from(&entry.client);
        record.facets.user_name.clone_from(&entry.user);
        record.summary = if namespace == ATLASSIAN_AUDIT {
            audit_summary(entry)
        } else {
            application_summary(product, entry)
        };
        record
    }
}

/// `Jira ERROR c.a.j.u.i.DefaultIndexManager: Re-index failed`: the
/// message's first line.
fn application_summary(product: Option<&str>, entry: &Entry) -> String {
    let source: Vec<&str> = [
        Some(product.unwrap_or("Atlassian")),
        entry.level.as_deref(),
        entry.logger.as_deref(),
    ]
    .into_iter()
    .flatten()
    .collect();
    let message = entry
        .message
        .as_deref()
        .and_then(|m| m.lines().next())
        .unwrap_or_default();
    format!(
        "{}: {}",
        source.join(" "),
        message.chars().take(SUMMARY_TEXT).collect::<String>()
    )
}

/// `RepositoryCreatedEvent by jsmith on PROJECT/myproject from
/// 63.246.22.199`, as far as known.
fn audit_summary(entry: &Entry) -> String {
    let mut summary = entry
        .action
        .clone()
        .unwrap_or_else(|| "Audit event".to_owned());
    for (joiner, value) in [
        (" by ", &entry.user),
        (" on ", &entry.object),
        (" from ", &entry.client),
    ] {
        if let Some(value) = value {
            summary.push_str(joiner);
            summary.push_str(value);
        }
    }
    summary
}

/// Which Atlassian log of entries a file is: its shape, and a name its
/// kind's files have. Their lines are common Log4j and JSON, so the shape
/// alone would take other applications' logs.
fn entry_kind(name: &str, head: &[u8]) -> Option<EntryKind> {
    let base = base_name(name);
    weblogs::detect_entries(name, head).filter(|kind| match kind {
        EntryKind::Application => product(name).is_some(),
        EntryKind::BitbucketAudit => base.starts_with("atlassian-bitbucket-audit"),
        EntryKind::Audit => base.ends_with(".audit.log"),
    })
}

/// Whose application log a file is, by its name: `atlassian-jira.log`,
/// `atlassian-confluence.log`, `atlassian-bitbucket.log`, or a numbered
/// copy (`atlassian-jira.log.1`).
fn product(name: &str) -> Option<&'static str> {
    let base = base_name(name);
    let rest = base.strip_prefix("atlassian-")?;
    [
        ("jira", "Jira"),
        ("confluence", "Confluence"),
        ("bitbucket", "Bitbucket"),
    ]
    .into_iter()
    .find(|(file, _)| {
        rest.strip_prefix(file)
            .and_then(|after| after.strip_prefix(".log"))
            .is_some_and(|after| after.is_empty() || after.starts_with('.'))
    })
    .map(|(_, product)| product)
}

/// A path's last part, lowercase.
fn base_name(name: &str) -> String {
    name.rsplit(['/', '\\'])
        .next()
        .unwrap_or(name)
        .to_ascii_lowercase()
}

/// Each line that couldn't be read, skipped.
fn skip(sink: &mut dyn Sink, problems: Vec<String>) {
    for reason in problems {
        sink.skipped(Skipped {
            locator: Locator::ByteOffset(0),
            reason,
        });
    }
}

/// `forwarded_for` as `ForwardedFor`, as a field name.
fn pascal(name: &str) -> String {
    let pascal: String = name
        .split('_')
        .map(|word| {
            let mut chars = word.chars();
            chars.next().map_or_else(String::new, |first| {
                first.to_ascii_uppercase().to_string() + chars.as_str()
            })
        })
        .collect();
    field_name(&pascal)
}
