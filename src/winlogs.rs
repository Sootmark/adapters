//! Windows text logs, via the `winlogs` parser: the Program Compatibility
//! Assistant's launches and events (`windows.pca`), IIS requests
//! (`windows.iis`), Windows Firewall entries (`windows.firewall`),
//! PowerShell transcripts (`windows.powershell_transcript`, a record per
//! block of commands), TeamViewer's log and sessions (`windows.teamviewer`),
//! SetupAPI sections (`windows.setupapi`), Configuration Manager client
//! logs (`windows.sccm`), and ConnectWise ScreenConnect's client settings
//! (`remote.screenconnect_config`) and server session database
//! (`Session.db`, read with its `-wal` file when the caller hands it over:
//! `remote.screenconnect_sessions`, `remote.screenconnect_connections`,
//! `remote.screenconnect_events`, deleted events included).

use std::collections::HashMap;
use std::net::IpAddr;

use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{
    Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Ts, Value,
};
use winlogs::screenconnect::{self, Connection, Event, EventSource, LaunchParameters, Session};
use winlogs::w3c::Source;
use winlogs::Kind;

use crate::home::profile_owner;

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
/// AnyDesk.
pub const ANYDESK: Namespace = Namespace::new("windows.anydesk");
/// Windows Error Reporting reports.
pub const WER: Namespace = Namespace::new("windows.wer");
/// ScreenConnect clients' settings: the relay and session they connect to.
pub const SCREENCONNECT_CONFIG: Namespace = Namespace::new("remote.screenconnect_config");
/// A ScreenConnect server's sessions.
pub const SCREENCONNECT_SESSIONS: Namespace = Namespace::new("remote.screenconnect_sessions");
/// Connections to a ScreenConnect server's sessions.
pub const SCREENCONNECT_CONNECTIONS: Namespace = Namespace::new("remote.screenconnect_connections");
/// Events of a ScreenConnect server's sessions and connections: commands,
/// transfers, messages.
pub const SCREENCONNECT_EVENTS: Namespace = Namespace::new("remote.screenconnect_events");

/// Characters of a message kept in a summary.
const SUMMARY_TEXT: usize = 200;
/// The published name of a ScreenConnect event whose data is a command.
const QUEUED_COMMAND: &str = "QueuedCommand";

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
        &[
            PCA,
            IIS,
            FIREWALL,
            TRANSCRIPT,
            TEAMVIEWER,
            SETUPAPI,
            SCCM,
            ANYDESK,
            WER,
            SCREENCONNECT_CONFIG,
            SCREENCONNECT_SESSIONS,
            SCREENCONNECT_CONNECTIONS,
            SCREENCONNECT_EVENTS,
        ]
    }

    /// By name and first lines (`#Fields:`, `<![LOG[`, a transcript's
    /// banner, ScreenConnect's settings section, `Session.db`'s SQLite
    /// header).
    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        if winlogs::detect(name, head).is_some() {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        self.parse_with_log(input, &[], sink)
    }

    /// ScreenConnect's `Session.db` read with its `-wal` file; the text
    /// logs have none.
    fn parse_with_log(
        &self,
        input: &Input<'_>,
        log: &[u8],
        sink: &mut dyn Sink,
    ) -> Result<(), ParseError> {
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
            Kind::AnyDeskTrace => out.anydesk_trace(),
            Kind::AnyDeskConnections => out.anydesk_connections(),
            Kind::WerReport => out.wer(),
            Kind::ScreenConnectConfig => out.screenconnect_config(),
            Kind::ScreenConnectSessions => out.screenconnect_sessions(log)?,
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
        self.located(namespace, Locator::Line(line as u64))
    }

    fn located(&self, namespace: Namespace, locator: Locator) -> Record {
        Record::new(
            self.input.evidence,
            namespace,
            locator,
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

    fn anydesk_trace(&mut self) {
        let parsed = winlogs::anydesk::trace(self.input.data);
        for line in &parsed.entries {
            let mut record = self.record(ANYDESK, line.line);
            time(&mut record, TimeKind::Logged, "time", Some(line.time));
            record.facets.process_id = Some(u64::from(line.process));
            record.facets.source_ip.clone_from(&line.address);
            let mut fields = Fields::new();
            text(&mut fields, "Level", &line.level);
            text(&mut fields, "Role", &line.role);
            text(&mut fields, "Module", &line.module);
            text(&mut fields, "Message", &line.message);
            fields.insert("Thread".into(), Value::UInt(u64::from(line.thread)));
            for (name, value) in [
                ("RemoteId", &line.remote_id),
                ("RemoteName", &line.remote_name),
                ("Address", &line.address),
            ] {
                if let Some(value) = value {
                    text(&mut fields, name, value);
                }
            }
            record.fields = fields;
            record.summary = format!("AnyDesk {}: {}", line.module, shorten(&line.message));
            self.sink.record(record);
        }
        self.problems(parsed.problems);
    }

    fn wer(&mut self) {
        let parsed = winlogs::wer::report(self.input.data);
        for report in &parsed.entries {
            let mut record = self.record(WER, 1);
            time(&mut record, TimeKind::Executed, "EventTime", report.time);
            time(
                &mut record,
                TimeKind::Logged,
                "UploadTime",
                report.upload_time,
            );
            let mut fields = Fields::new();
            for (name, value) in [
                ("EventType", &report.event_type),
                ("FriendlyEventName", &report.friendly_event_name),
                ("ReportId", &report.report_id),
                ("AppName", &report.app_name),
                ("AppPath", &report.app_path),
                ("NsAppName", &report.ns_app_name),
            ] {
                text(&mut fields, name, value.as_deref().unwrap_or_default());
            }
            for (name, value) in &report.signature {
                let key: String = name.chars().filter(char::is_ascii_alphanumeric).collect();
                text(&mut fields, &key, value);
            }
            text(
                &mut fields,
                "LoadedModules",
                &report.loaded_modules.join(", "),
            );
            record.fields = fields;
            record.facets.process_path = report
                .app_path
                .clone()
                .or_else(|| report.ns_app_name.clone());
            record.summary = format!(
                "WER {}: {}{}",
                report.event_type.as_deref().unwrap_or("report"),
                record.facets.process_path.as_deref().unwrap_or("?"),
                report
                    .signature("Fault Module Name")
                    .map(|m| format!(" (faulting module {m})"))
                    .unwrap_or_default()
            );
            self.sink.record(record);
        }
        self.problems(parsed.problems);
    }

    fn anydesk_connections(&mut self) {
        let parsed = winlogs::anydesk::connections(self.input.data);
        for session in &parsed.entries {
            let mut record = self.record(ANYDESK, session.line);
            time(
                &mut record,
                TimeKind::FirstSeen,
                "Start",
                Some(session.time),
            );
            let remote = session.ids.first().cloned().unwrap_or_default();
            let mut fields = Fields::new();
            text(&mut fields, "Direction", &session.direction);
            text(&mut fields, "Authorisation", &session.authorisation);
            text(&mut fields, "RemoteId", &remote);
            fields.insert(
                "Ids".into(),
                Value::List(
                    session
                        .ids
                        .iter()
                        .map(|id| Value::from(id.as_str()))
                        .collect(),
                ),
            );
            record.fields = fields;
            record.summary = format!(
                "AnyDesk session {} {remote} ({})",
                if session.direction == "Outgoing" {
                    "out to"
                } else {
                    "in from"
                },
                session.authorisation
            );
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

    /// One record per settings file: its relay, session and launch
    /// parameters, and every setting.
    fn screenconnect_config(&mut self) {
        let config = screenconnect::config(self.input.data);
        let mut record = self.located(SCREENCONNECT_CONFIG, Locator::ByteOffset(0));
        record.facets.user_name = profile_owner(self.input.name);
        let mut fields = Fields::new();
        for setting in &config.settings {
            let name = field_name(&setting.name);
            if !name.is_empty() {
                text(&mut fields, &format!("Setting.{name}"), &setting.value);
            }
        }
        record.summary = match &config.launch {
            Some(launch) => {
                launch_fields(&mut fields, launch);
                record.facets.destination_ip = launch
                    .relay_host
                    .clone()
                    .filter(|host| host.parse::<IpAddr>().is_ok());
                launch_summary(launch)
            }
            None => format!(
                "ScreenConnect client settings ({} settings, no launch parameters)",
                config.settings.len()
            ),
        };
        record.fields = fields;
        self.sink.record(record);
        self.problems(config.problems);
    }

    /// One record per session, connection and event (live, then deleted)
    /// of `Session.db`, read with its `-wal` file `log`.
    fn screenconnect_sessions(&mut self, log: &[u8]) -> Result<(), ParseError> {
        let db = screenconnect::sessions(self.input.data, log)
            .map_err(|e| ParseError::at(0, e.to_string()))?;
        let lookup = Lookup::new(&db.sessions, &db.connections);
        for session in &db.sessions {
            let record = self.screenconnect_session(session);
            self.sink.record(record);
        }
        for connection in &db.connections {
            let record = self.screenconnect_connection(&lookup, connection);
            self.sink.record(record);
        }
        for event in &db.events {
            let locator = row_locator(event_table(event), event.rowid.unwrap_or_default());
            let record = self.screenconnect_event(&lookup, event, locator);
            self.sink.record(record);
        }
        // A deleted event's rowid may be a live row's, or another deleted
        // version's: they are numbered in the order recovery found them.
        for (found, event) in (0u64..).zip(&db.deleted_events) {
            let locator = Locator::TableRow {
                table: format!("deleted {}", event_table(event)),
                row: found,
            };
            let mut record = self.screenconnect_event(&lookup, event, locator);
            record.flags.recovered = true;
            record.fields.insert("Deleted".into(), Value::Bool(true));
            record.summary = format!("Deleted {}", record.summary);
            self.sink.record(record);
        }
        self.problems(db.problems);
        Ok(())
    }

    fn screenconnect_session(&self, session: &Session) -> Record {
        let mut record = self.located(
            SCREENCONNECT_SESSIONS,
            row_locator("Session", session.rowid),
        );
        record.facets.user_name.clone_from(&session.host);
        let mut fields = Fields::new();
        optional_texts(
            &mut fields,
            [
                ("SessionId", &session.id),
                ("Name", &session.name),
                ("SessionType", &session.session_type),
                ("Host", &session.host),
            ],
        );
        for (column, value) in &session.custom_properties {
            text(&mut fields, column, value);
        }
        record.fields = fields;
        record.summary = format!(
            "ScreenConnect {} session {} owned by {}",
            session.session_type.as_deref().unwrap_or("?"),
            session
                .name
                .as_deref()
                .or(session.id.as_deref())
                .unwrap_or("?"),
            session.host.as_deref().unwrap_or("?")
        );
        record
    }

    fn screenconnect_connection(&self, lookup: &Lookup<'_>, connection: &Connection) -> Record {
        let mut record = self.located(
            SCREENCONNECT_CONNECTIONS,
            row_locator("SessionConnection", connection.rowid),
        );
        time(
            &mut record,
            TimeKind::FirstSeen,
            "ConnectedTime",
            connection.connected,
        );
        time(
            &mut record,
            TimeKind::LastSeen,
            "DisconnectedTime",
            connection.disconnected,
        );
        record
            .facets
            .user_name
            .clone_from(&connection.participant_name);
        record
            .facets
            .source_ip
            .clone_from(&connection.network_address);
        let session = lookup.session_name(connection.session_id.as_deref());
        let mut fields = Fields::new();
        optional_texts(
            &mut fields,
            [
                ("SessionId", &connection.session_id),
                ("ConnectionId", &connection.id),
                ("ProcessType", &connection.process_type),
                ("ParticipantName", &connection.participant_name),
                ("NetworkAddress", &connection.network_address),
                ("ClientType", &connection.client_type),
                ("ClientVersion", &connection.client_version),
            ],
        );
        if let Some(name) = session {
            text(&mut fields, "SessionName", name);
        }
        record.fields = fields;
        record.summary = format!(
            "ScreenConnect {} {} connected from {} to session {}",
            connection.process_type.as_deref().unwrap_or("participant"),
            connection.participant_name.as_deref().unwrap_or("?"),
            connection.network_address.as_deref().unwrap_or("?"),
            session.or(connection.session_id.as_deref()).unwrap_or("?")
        );
        record
    }

    fn screenconnect_event(&self, lookup: &Lookup<'_>, event: &Event, locator: Locator) -> Record {
        let mut record = self.located(SCREENCONNECT_EVENTS, locator);
        time(&mut record, TimeKind::Logged, "Time", event.time);
        let connection = lookup.connection(event.connection_id.as_deref());
        let session = lookup.session_name(event.session_id.as_deref());
        let command = event.event_name.as_deref() == Some(QUEUED_COMMAND);
        record.facets = Facets {
            user_name: event
                .host
                .clone()
                .or_else(|| connection.and_then(|c| c.participant_name.clone())),
            source_ip: connection.and_then(|c| c.network_address.clone()),
            process_command_line: event.data.clone().filter(|_| command),
            ..Facets::default()
        };
        let mut fields = Fields::new();
        text(&mut fields, "Table", event_table(event));
        optional_texts(
            &mut fields,
            [
                ("SessionId", &event.session_id),
                ("ConnectionId", &event.connection_id),
                ("EventId", &event.id),
                ("EventName", &event.event_name),
                ("Host", &event.host),
                ("Data", &event.data),
            ],
        );
        if let Some(number) = event.event_type {
            fields.insert("EventType".into(), Value::Int(number));
        }
        if let Some(name) = session {
            text(&mut fields, "SessionName", name);
        }
        if let Some(participant) = connection.and_then(|c| c.participant_name.as_deref()) {
            text(&mut fields, "ParticipantName", participant);
        }
        record.fields = fields;
        let what = match (&event.event_name, event.event_type) {
            (Some(name), _) => name.clone(),
            (None, Some(number)) => format!("event {number}"),
            (None, None) => "event".to_owned(),
        };
        let by = record
            .facets
            .user_name
            .as_deref()
            .map(|user| format!(" by {user}"))
            .unwrap_or_default();
        let data = event
            .data
            .as_deref()
            .map(|data| format!(": {}", shorten(&data.replace('\n', " "))))
            .unwrap_or_default();
        record.summary = format!(
            "ScreenConnect {what} in session {}{by}{data}",
            session.or(event.session_id.as_deref()).unwrap_or("?")
        );
        record
    }
}

/// A ScreenConnect database's session names and connections, by id.
struct Lookup<'d> {
    session_names: HashMap<&'d str, &'d str>,
    connections: HashMap<&'d str, &'d Connection>,
}

impl<'d> Lookup<'d> {
    fn new(sessions: &'d [Session], connections: &'d [Connection]) -> Self {
        Self {
            session_names: sessions
                .iter()
                .filter_map(|s| Some((s.id.as_deref()?, s.name.as_deref()?)))
                .collect(),
            connections: connections
                .iter()
                .filter_map(|c| Some((c.id.as_deref()?, c)))
                .collect(),
        }
    }

    fn session_name(&self, id: Option<&str>) -> Option<&'d str> {
        self.session_names.get(id?).copied()
    }

    fn connection(&self, id: Option<&str>) -> Option<&'d Connection> {
        self.connections.get(id?).copied()
    }
}

/// The table an event was read from.
fn event_table(event: &Event) -> &'static str {
    match event.source {
        EventSource::Session => "SessionEvent",
        EventSource::Connection => "SessionConnectionEvent",
    }
}

fn row_locator(table: &str, rowid: i64) -> Locator {
    Locator::TableRow {
        table: table.to_owned(),
        row: rowid as u64,
    }
}

/// The launch parameters as fields: those with a meaning by name, the
/// custom properties in order, and every parameter as `name=value`.
fn launch_fields(fields: &mut Fields, launch: &LaunchParameters) {
    optional_texts(
        fields,
        [
            ("RelayHost", &launch.relay_host),
            ("RelayPort", &launch.relay_port),
            ("SessionId", &launch.session_id),
            ("SessionType", &launch.session_type),
            ("ProcessType", &launch.process_type),
            ("Key", &launch.key),
        ],
    );
    if !launch.custom_properties.is_empty() {
        let values = launch
            .custom_properties
            .iter()
            .map(|v| Value::from(v.as_str()));
        fields.insert("CustomProperties".into(), Value::List(values.collect()));
    }
    let all = launch
        .all
        .iter()
        .map(|(name, value)| Value::from(format!("{name}={value}")));
    fields.insert("LaunchParameters".into(), Value::List(all.collect()));
}

/// `ScreenConnect client relays to relay.example.net:8041, session …
/// (Access, Guest)`.
fn launch_summary(launch: &LaunchParameters) -> String {
    let relay = match (&launch.relay_host, &launch.relay_port) {
        (Some(host), Some(port)) => format!("{host}:{port}"),
        (Some(host), None) => host.clone(),
        (None, _) => "?".to_owned(),
    };
    let session = launch
        .session_id
        .as_deref()
        .map(|id| format!(", session {id}"))
        .unwrap_or_default();
    let kinds: Vec<&str> = [&launch.session_type, &launch.process_type]
        .into_iter()
        .filter_map(Option::as_deref)
        .collect();
    let kinds = if kinds.is_empty() {
        String::new()
    } else {
        format!(" ({})", kinds.join(", "))
    };
    format!("ScreenConnect client relays to {relay}{session}{kinds}")
}

/// `name` with only the characters field names allow (letters, digits,
/// `_`, `-`, `.`).
fn field_name(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        .collect()
}

fn optional_texts<const N: usize>(fields: &mut Fields, values: [(&str, &Option<String>); N]) {
    for (name, value) in values {
        if let Some(value) = value {
            text(fields, name, value);
        }
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
