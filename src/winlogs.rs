//! Windows text logs, via the `winlogs` parser: the Program Compatibility
//! Assistant's launches and events (`windows.pca`), IIS requests
//! (`windows.iis`), Windows Firewall entries (`windows.firewall`),
//! PowerShell transcripts (`windows.powershell_transcript`, a record per
//! block of commands), TeamViewer's log and sessions (`windows.teamviewer`),
//! SetupAPI sections (`windows.setupapi`) and Configuration Manager client
//! logs (`windows.sccm`).

use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{
    Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Ts, Value,
};
use winlogs::w3c::Source;
use winlogs::Kind;

/// The Program Compatibility Assistant.
pub const PCA: Namespace = Namespace::new("windows.pca");
/// IIS requests.
pub const IIS: Namespace = Namespace::new("windows.iis");
/// Windows Firewall entries (and other W3C logs).
pub const FIREWALL: Namespace = Namespace::new("windows.firewall");
/// PowerShell transcripts.
pub const TRANSCRIPT: Namespace = Namespace::new("windows.powershell_transcript");
/// TeamViewer.
pub const TEAMVIEWER: Namespace = Namespace::new("windows.teamviewer");
/// SetupAPI.
pub const SETUPAPI: Namespace = Namespace::new("windows.setupapi");
/// Configuration Manager client logs.
pub const SCCM: Namespace = Namespace::new("windows.sccm");

/// Characters of a message kept in a summary.
const SUMMARY_TEXT: usize = 200;

/// One record per entry of a Windows text log.
#[derive(Debug, Default, Clone, Copy)]
pub struct WinlogsAdapter;

impl Adapter for WinlogsAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "winlogs",
            version: winlogs::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[PCA, IIS, FIREWALL, TRANSCRIPT, TEAMVIEWER, SETUPAPI, SCCM]
    }

    /// By name and first lines (`#Fields:`, `<![LOG[`, a transcript's
    /// banner).
    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        if winlogs::detect(name, head).is_some() {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let kind = winlogs::detect(input.name, input.data)
            .ok_or_else(|| ParseError::at(0, "not a Windows text log this parser reads"))?;
        let mut out = Out {
            adapter: *self,
            input,
            sink,
        };
        match kind {
            Kind::PcaLaunches => out.pca_launches(),
            Kind::PcaGeneral => out.pca_general(),
            Kind::W3c => out.w3c(),
            Kind::Transcript => out.transcript(),
            Kind::TeamViewerLog => out.teamviewer_log(),
            Kind::TeamViewerIncoming => out.teamviewer_connections(true),
            Kind::TeamViewerOutgoing => out.teamviewer_connections(false),
            Kind::SetupApi => out.setupapi(),
            Kind::Sccm => out.sccm(),
        }
        Ok(())
    }
}

/// Where records go.
struct Out<'a, 'b> {
    adapter: WinlogsAdapter,
    input: &'a Input<'b>,
    sink: &'a mut dyn Sink,
}

impl Out<'_, '_> {
    fn record(&self, namespace: Namespace, line: usize) -> Record {
        Record::new(
            self.input.evidence,
            namespace,
            Locator::Line(line as u64),
            self.adapter.parser(),
        )
    }

    fn problems(&mut self, problems: Vec<String>) {
        for reason in problems {
            self.sink.skipped(Skipped {
                locator: Locator::ByteOffset(0),
                reason,
            });
        }
    }

    fn pca_launches(&mut self) {
        let parsed = winlogs::pca::launches(self.input.data);
        for launch in &parsed.entries {
            let mut record = self.record(PCA, launch.line);
            time(
                &mut record,
                TimeKind::Executed,
                "LastRun",
                Some(launch.last_run),
            );
            record.facets.process_path = Some(launch.program.clone());
            let mut fields = Fields::new();
            text(&mut fields, "Program", &launch.program);
            text(&mut fields, "File", "PcaAppLaunchDic.txt");
            record.fields = fields;
            record.summary = format!("PCA: ran {}", launch.program);
            self.sink.record(record);
        }
        self.problems(parsed.problems);
    }

    fn pca_general(&mut self) {
        let parsed = winlogs::pca::general(self.input.data);
        for entry in &parsed.entries {
            let mut record = self.record(PCA, entry.line);
            time(&mut record, TimeKind::Executed, "Time", Some(entry.time));
            record.facets.process_path = Some(entry.program.clone());
            let mut fields = Fields::new();
            for (name, value) in [
                ("Program", &entry.program),
                ("RunStatus", &entry.run_status),
                ("Description", &entry.description),
                ("Vendor", &entry.vendor),
                ("Version", &entry.version),
                ("ProgramId", &entry.program_id),
                ("ExitCode", &entry.exit_code),
            ] {
                text(&mut fields, name, value);
            }
            text(&mut fields, "File", "PcaGeneralDb");
            record.fields = fields;
            record.summary = format!("PCA: {} ({})", entry.program, entry.exit_code);
            self.sink.record(record);
        }
        self.problems(parsed.problems);
    }

    fn w3c(&mut self) {
        let log = winlogs::w3c::read(self.input.data);
        let namespace = if log.source == Source::Iis {
            IIS
        } else {
            FIREWALL
        };
        for entry in &log.entries {
            let mut record = self.record(namespace, entry.line);
            time(&mut record, TimeKind::Logged, "time", entry.time);
            let mut fields = Fields::new();
            for (name, value) in &entry.fields {
                text(&mut fields, name, value);
            }
            record.fields = fields;
            let get = |name: &str| entry.get(name).map(str::to_owned);
            if log.source == Source::Iis {
                record.facets = Facets {
                    source_ip: get("c-ip"),
                    destination_ip: get("s-ip"),
                    user_name: get("cs-username"),
                    ..Facets::default()
                };
                let query = get("cs-uri-query")
                    .map(|q| format!("?{q}"))
                    .unwrap_or_default();
                record.summary = format!(
                    "IIS {} {}{query} {} from {}",
                    get("cs-method").unwrap_or_default(),
                    get("cs-uri-stem").unwrap_or_default(),
                    get("sc-status").unwrap_or_default(),
                    get("c-ip").unwrap_or_default()
                );
            } else {
                record.facets = Facets {
                    source_ip: get("src-ip"),
                    destination_ip: get("dst-ip"),
                    process_id: get("pid").and_then(|p| p.parse().ok()),
                    ..Facets::default()
                };
                record.summary = format!(
                    "Firewall {} {} {}:{} -> {}:{}",
                    get("action").unwrap_or_default(),
                    get("protocol").unwrap_or_default(),
                    get("src-ip").unwrap_or_default(),
                    get("src-port").unwrap_or_default(),
                    get("dst-ip").unwrap_or_default(),
                    get("dst-port").unwrap_or_default()
                );
            }
            self.sink.record(record);
        }
        self.problems(log.problems);
    }

    fn transcript(&mut self) {
        let transcript = winlogs::transcript::read(self.input.data);
        let get = |name: &str| {
            transcript
                .get(name)
                .filter(|v| !v.is_empty())
                .map(str::to_owned)
        };
        for block in &transcript.blocks {
            let mut record = self.record(TRANSCRIPT, block.line);
            time(&mut record, TimeKind::Logged, "BlockStart", block.time);
            if record.times.is_empty() {
                time(&mut record, TimeKind::Logged, "StartTime", transcript.start);
            }
            let commands = block.commands().join("; ");
            record.facets = Facets {
                user_name: get("Username"),
                host_name: get("Machine").map(|m| m.split(' ').next().unwrap_or(&m).to_owned()),
                process_path: get("HostApplication"),
                process_id: get("ProcessId").and_then(|p| p.parse().ok()),
                process_command_line: Some(commands.clone()).filter(|c| !c.is_empty()),
                ..Facets::default()
            };
            let mut fields = Fields::new();
            text(&mut fields, "Commands", &commands);
            text(&mut fields, "Lines", &block.lines.join("\n"));
            for (name, value) in &transcript.header {
                text(&mut fields, name, value);
            }
            record.fields = fields;
            record.summary = format!(
                "PowerShell transcript ({}): {}",
                get("Username").unwrap_or_default(),
                shorten(if commands.is_empty() {
                    &block.lines[0]
                } else {
                    &commands
                })
            );
            self.sink.record(record);
        }
        self.problems(transcript.problems);
    }

    fn teamviewer_log(&mut self) {
        let parsed = winlogs::teamviewer::log(self.input.data);
        for line in &parsed.entries {
            let mut record = self.record(TEAMVIEWER, line.line);
            time(&mut record, TimeKind::Logged, "time", Some(line.time));
            record.facets.process_id = Some(u64::from(line.process));
            let mut fields = Fields::new();
            text(&mut fields, "Message", &line.message);
            if let Some(thread) = line.thread {
                fields.insert("Thread".into(), Value::UInt(u64::from(thread)));
            }
            record.fields = fields;
            record.summary = format!(
                "TeamViewer: {}",
                shorten(line.message.lines().next().unwrap_or_default())
            );
            self.sink.record(record);
        }
        self.problems(parsed.problems);
    }

    fn teamviewer_connections(&mut self, incoming: bool) {
        let parsed = winlogs::teamviewer::connections(self.input.data, incoming);
        for session in &parsed.entries {
            let mut record = self.record(TEAMVIEWER, session.line);
            time(&mut record, TimeKind::FirstSeen, "Start", session.start);
            time(&mut record, TimeKind::LastSeen, "End", session.end);
            record.facets.user_name = Some(session.account.clone());
            let mut fields = Fields::new();
            text(
                &mut fields,
                "Direction",
                if incoming { "incoming" } else { "outgoing" },
            );
            text(&mut fields, "RemoteId", &session.remote_id);
            if let Some(name) = &session.remote_name {
                text(&mut fields, "RemoteName", name);
            }
            text(&mut fields, "Account", &session.account);
            text(&mut fields, "Kind", &session.kind);
            text(&mut fields, "SessionId", &session.id);
            record.fields = fields;
            let remote = match &session.remote_name {
                Some(name) => format!("{} ({name})", session.remote_id),
                None => session.remote_id.clone(),
            };
            record.summary = if incoming {
                format!(
                    "TeamViewer session in from {remote} as {}: {}",
                    session.account, session.kind
                )
            } else {
                format!(
                    "TeamViewer session out to {remote} by {}: {}",
                    session.account, session.kind
                )
            };
            self.sink.record(record);
        }
        self.problems(parsed.problems);
    }

    fn setupapi(&mut self) {
        let parsed = winlogs::setupapi::read(self.input.data);
        for section in &parsed.entries {
            let mut record = self.record(SETUPAPI, section.line);
            time(
                &mut record,
                TimeKind::FirstSeen,
                "SectionStart",
                section.start,
            );
            time(&mut record, TimeKind::LastSeen, "SectionEnd", section.end);
            let mut fields = Fields::new();
            text(&mut fields, "Title", &section.title);
            if let Some(status) = &section.exit_status {
                text(&mut fields, "ExitStatus", status);
            }
            record.fields = fields;
            record.summary = format!(
                "SetupAPI: {} ({})",
                section.title,
                section.exit_status.as_deref().unwrap_or("?")
            );
            self.sink.record(record);
        }
        self.problems(parsed.problems);
    }

    fn sccm(&mut self) {
        let parsed = winlogs::sccm::read(self.input.data);
        for entry in &parsed.entries {
            let mut record = self.record(SCCM, entry.line);
            time(&mut record, TimeKind::Logged, "time", entry.time);
            let mut fields = Fields::new();
            text(&mut fields, "Component", &entry.component);
            text(&mut fields, "Text", &entry.text);
            text(&mut fields, "SourceFile", &entry.file);
            if let Some(severity) = entry.severity {
                fields.insert("Severity".into(), Value::UInt(u64::from(severity)));
            }
            if let Some(thread) = entry.thread {
                fields.insert("Thread".into(), Value::UInt(u64::from(thread)));
            }
            record.fields = fields;
            record.summary = format!(
                "SCCM {}: {}",
                entry.component,
                shorten(entry.text.lines().next().unwrap_or_default())
            );
            self.sink.record(record);
        }
        self.problems(parsed.problems);
    }
}

fn time(record: &mut Record, kind: TimeKind, name: &str, value: Option<Ts>) {
    if let Some(value) = value {
        record.times.push(RecordTime::new(kind, name, value));
    }
}

fn text(fields: &mut Fields, name: &str, value: &str) {
    if !value.is_empty() {
        fields.insert(name.into(), Value::from(value));
    }
}

fn shorten(text: &str) -> String {
    match text.char_indices().nth(SUMMARY_TEXT) {
        Some((at, _)) => format!("{}…", &text[..at]),
        None => text.to_owned(),
    }
}
