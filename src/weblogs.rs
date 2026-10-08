//! Web server access logs, via the `weblogs` parser: Apache and nginx,
//! Jira and Confluence, Bitbucket, AWS Elastic Load Balancing and Azure
//! Application Gateway; one record per request, with the client, user,
//! request, status, bytes, referer and user agent.

use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};
use weblogs::{Kind, Request};

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

/// One record per request.
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
        &[ACCESS, ATLASSIAN, BITBUCKET, ELB, AZURE_GATEWAY]
    }

    /// By the first lines' shape.
    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        if weblogs::detect(name, head).is_some() {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let kind = weblogs::detect(input.name, input.data)
            .ok_or_else(|| ParseError::at(0, "not an access log this parser reads"))?;
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
        for reason in log.problems {
            sink.skipped(Skipped {
                locator: Locator::ByteOffset(0),
                reason,
            });
        }
        Ok(())
    }
}

impl WeblogsAdapter {
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
