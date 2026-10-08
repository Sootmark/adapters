//! Records of logs: Apple System Log files' messages (see
//! `MacosAdapter::asl`), and the text logs' lines, one record each:
//! Wi-Fi's (`wifi.log`) and launchd's (`launchd.log`).
//!
//! Wi-Fi's lines have no year. The parser infers it as plaso does, from the
//! years of the file's earliest and latest times and the current year; the
//! only time an adapter is handed is the file's modification time
//! ([`Input::modified`]), so its year stands for all three: the last line
//! is dated in the year the file was last modified and earlier lines back
//! from it, a year less at each turn of the year, as the syslog adapter
//! dates classic lines. Not the clock's year: the same file always gives
//! the same records. Without a modification time the lines are untimed.
//! Either way the time is kept as written (`TimeText`) and an inferred
//! year marked (`YearInferred`).

use std::collections::HashSet;

use common::time::{civil_from_days, Ts, TICKS_PER_DAY};
use macos::{Artifact, LogLine, TextLog, WifiEvent, Years};
use model::adapter::{Adapter, Input};
use model::{Facets, Fields, Locator, Namespace, Record, RecordTime, TimeKind, Value};

use super::{text, MacosAdapter, LAUNCHD_LOG, WIFI_LOG};

/// The longest message kept in a summary.
const SUMMARY_TEXT: usize = 200;

/// The years a Wi-Fi log is read with when the file's are unknown: they
/// only order its lines, whose times are then dropped.
const UNKNOWN_YEARS: Years = Years {
    earliest: 2000,
    latest: 2000,
    current: 2000,
};

/// Whether `head`'s first line reads as a line of `artifact`'s log.
pub(super) fn starts_like(artifact: Artifact, head: &[u8]) -> bool {
    let Some(first) = head
        .split(|&b| b == b'\n')
        .find(|line| !line.trim_ascii().is_empty())
    else {
        return false;
    };
    let log = if artifact == Artifact::WifiLog {
        macos::read_wifi_log(first, UNKNOWN_YEARS)
    } else {
        macos::read_launchd_log(first)
    };
    !log.lines.is_empty()
}

impl MacosAdapter {
    /// The records of a log (an Apple System Log file, Wi-Fi's or
    /// launchd's) and what couldn't be read.
    pub(super) fn logs(self, artifact: Artifact, input: &Input<'_>) -> (Vec<String>, Vec<Record>) {
        match artifact {
            Artifact::Asl => {
                let parsed = macos::read_asl(input.data);
                let records = parsed
                    .records
                    .iter()
                    .map(|message| self.asl(input, message))
                    .collect();
                (parsed.problems, records)
            }
            Artifact::WifiLog => self.wifi_log(input),
            _ => {
                let log = macos::read_launchd_log(input.data);
                let records = log
                    .lines
                    .iter()
                    .map(|line| self.launchd_line(input, line))
                    .collect();
                (log.problems, records)
            }
        }
    }

    fn wifi_log(self, input: &Input<'_>) -> (Vec<String>, Vec<Record>) {
        let years = input.modified.and_then(year).map(|year| Years {
            earliest: year,
            latest: year,
            current: year,
        });
        let mut log = macos::read_wifi_log(input.data, years.unwrap_or(UNKNOWN_YEARS));
        if years.is_none() {
            undate(&mut log);
        }
        let text = String::from_utf8_lossy(input.data);
        let written: Vec<&str> = text.lines().collect();
        let records = log
            .lines
            .iter()
            .map(|line| {
                let time_text = line
                    .line
                    .checked_sub(1)
                    .and_then(|index| written.get(index))
                    .and_then(|raw| time_text(raw));
                self.wifi_line(input, line, time_text)
            })
            .collect();
        (log.problems, records)
    }

    fn wifi_line(self, input: &Input<'_>, line: &LogLine, time_text: Option<&str>) -> Record {
        let mut record = self.log_record(input, WIFI_LOG, line);
        let mut fields = line_fields(line);
        text(&mut fields, "Function", line.function.as_deref());
        text(&mut fields, "Host", line.host.as_deref());
        text(&mut fields, "TimeText", time_text);
        fields.insert(
            "YearInferred".into(),
            Value::Bool(line.year_inferred && line.time.is_some()),
        );
        match &line.wifi {
            Some(WifiEvent::Interface { name, event }) => {
                text(&mut fields, "Interface", Some(name));
                text(&mut fields, "InterfaceEvent", Some(event));
            }
            Some(WifiEvent::Associated { ssid }) => text(&mut fields, "Ssid", Some(ssid)),
            Some(WifiEvent::Network {
                ssid,
                bssid,
                security,
                rssi,
            }) => {
                text(&mut fields, "Ssid", ssid.as_deref());
                text(&mut fields, "Bssid", bssid.as_deref());
                text(&mut fields, "Security", security.as_deref());
                if let Some(rssi) = rssi {
                    fields.insert("Rssi".into(), Value::Int(i64::from(*rssi)));
                }
            }
            None => {}
        }
        record.fields = fields;
        record.facets = Facets {
            host_name: line.host.clone(),
            process_id: line.pid.map(u64::from),
            ..Facets::default()
        };
        let source: Vec<&str> = [line.process.as_deref(), line.function.as_deref()]
            .into_iter()
            .flatten()
            .collect();
        record.summary = format!("Wi-Fi {}: {}", source.join(" "), shortened(&line.message));
        record
    }

    fn launchd_line(self, input: &Input<'_>, line: &LogLine) -> Record {
        let mut record = self.log_record(input, LAUNCHD_LOG, line);
        let mut fields = line_fields(line);
        let (label, pid) = line.process.as_deref().map_or((None, None), job);
        text(&mut fields, "Label", label);
        if let Some(pid) = pid {
            fields.insert("Pid".into(), Value::UInt(pid));
        }
        record.fields = fields;
        record.facets.process_id = pid;
        record.summary = format!(
            "launchd {}<{}>: {}",
            line.process
                .as_deref()
                .map_or_else(String::new, |job| format!("({job}) ")),
            line.level.as_deref().unwrap_or("?"),
            shortened(&line.message)
        );
        record
    }

    /// A line's record, at its line, with its time.
    fn log_record(self, input: &Input<'_>, namespace: Namespace, line: &LogLine) -> Record {
        let mut record = Record::new(
            input.evidence,
            namespace,
            Locator::Line(line.line as u64),
            self.parser(),
        );
        if let Some(time) = line.time {
            record
                .times
                .push(RecordTime::new(TimeKind::Logged, "Time", time));
        }
        record
    }
}

/// The values both logs' lines may have.
fn line_fields(line: &LogLine) -> Fields {
    let mut fields = Fields::new();
    text(&mut fields, "Process", line.process.as_deref());
    if let Some(pid) = line.pid {
        fields.insert("Pid".into(), Value::UInt(u64::from(pid)));
    }
    text(&mut fields, "Level", line.level.as_deref());
    text(&mut fields, "Message", Some(&line.message));
    fields
}

/// The year of a time, when it is one.
fn year(time: Ts) -> Option<i64> {
    let (year, _, _) = civil_from_days(time.ticks()?.div_euclid(TICKS_PER_DAY));
    Some(year)
}

/// A Wi-Fi log read without its file's years: no line dated, and no line
/// reported for a date missing from the stand-in years.
fn undate(log: &mut TextLog) {
    let read: HashSet<usize> = log.lines.iter().map(|line| line.line).collect();
    log.problems
        .retain(|problem| !problem_line(problem).is_some_and(|line| read.contains(&line)));
    for line in &mut log.lines {
        line.time = None;
    }
}

/// The line a problem is about (`line 12: …`).
fn problem_line(problem: &str) -> Option<usize> {
    let (number, _) = problem.strip_prefix("line ")?.split_once(':')?;
    number.parse().ok()
}

/// The time as a Wi-Fi line writes it (`Thu Nov 14 20:14:37.123`,
/// `Jan  2 00:10:15`): up to the end of its first word with a colon.
fn time_text(line: &str) -> Option<&str> {
    let colon = line.find(':')?;
    let end = line[colon..].find(' ').map_or(line.len(), |at| colon + at);
    Some(line[..end].trim_end_matches('\r'))
}

/// A launchd job's service label and process id, from how the log names
/// it: `<domain>[/<label>] [<process id or name>]`
/// (`system/com.apple.locationd [19]`, `pid/1660 [com.apple.audio]`,
/// `com.apple.FileProvider`). The label is the last part when it is
/// dotted (reverse DNS); a labelled job's number in brackets is its
/// process id, a `pid/<n>` domain's `n` the process whose domain it is.
/// A domain's own number in brackets (`gui/501 [100005]`) is its audit
/// session, not a process.
fn job(job: &str) -> (Option<&str>, Option<u64>) {
    let (path, bracketed) = match job.strip_suffix(']').and_then(|j| j.rsplit_once(" [")) {
        Some((path, bracketed)) => (path, Some(bracketed)),
        None => (job, None),
    };
    let label = path.rsplit('/').next().filter(|last| last.contains('.'));
    let pid = match label {
        Some(_) => bracketed.and_then(|b| b.parse().ok()),
        None => path.strip_prefix("pid/").and_then(|rest| rest.parse().ok()),
    };
    (label, pid)
}

/// A message cut to [`SUMMARY_TEXT`] characters.
fn shortened(message: &str) -> String {
    message.chars().take(SUMMARY_TEXT).collect()
}

#[cfg(test)]
mod tests {
    use super::{job, time_text};

    #[test]
    fn launchd_jobs_labels_and_process_ids() {
        assert_eq!(
            job("system/com.apple.locationd [19]"),
            (Some("com.apple.locationd"), Some(19))
        );
        assert_eq!(
            job("pid/1660/com.apple.audio.SandboxHelper [1702]"),
            (Some("com.apple.audio.SandboxHelper"), Some(1702))
        );
        assert_eq!(
            job("pid/1660/com.apple.MTLCompilerService"),
            (Some("com.apple.MTLCompilerService"), None)
        );
        assert_eq!(job("pid/1660 [com.apple.audio]"), (None, Some(1660)));
        assert_eq!(
            job("com.apple.FileProvider"),
            (Some("com.apple.FileProvider"), None)
        );
        assert_eq!(job("gui/501 [100005]"), (None, None));
        assert_eq!(job("system"), (None, None));
        assert_eq!(job("restore-datapartition"), (None, None));
    }

    #[test]
    fn wifi_times_as_written() {
        assert_eq!(
            time_text("Thu Nov 14 20:14:37.123 ***Starting Up***"),
            Some("Thu Nov 14 20:14:37.123")
        );
        assert_eq!(
            time_text("Jan  2 00:10:15 host newsyslog[1]: logfile turned over"),
            Some("Jan  2 00:10:15")
        );
        assert_eq!(time_text("no time"), None);
    }
}
