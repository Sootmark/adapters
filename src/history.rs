//! Unix shell history files, via the `history` parser: one record per
//! command, with its time when the shell wrote one, and the account whose
//! home the file is in.
//!
//! bash writes times only with `HISTTIMEFORMAT` set: commands without one
//! are untimed, never dated by the file.

use std::path::Path;

use history::{Command, Format};
use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};

/// Records of Unix shell history files.
pub const NAMESPACE: Namespace = Namespace::new("unix.shell_history");
/// Records of PowerShell's PSReadLine history.
pub const POWERSHELL: Namespace = Namespace::new("windows.powershell_history");

/// Names shells write their history under.
const NAMES: [&str; 5] = [
    ".bash_history",
    ".zsh_history",
    ".histfile",
    "fish_history",
    ".sh_history",
];
const SUMMARY_COMMAND: usize = 160;

/// One record per command.
#[derive(Debug, Default, Clone, Copy)]
pub struct HistoryAdapter;

impl Adapter for HistoryAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "history",
            version: history::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[NAMESPACE, POWERSHELL]
    }

    /// By name only: any text reads as a bash history. PSReadLine names
    /// its files after the host (`ConsoleHost_history.txt`).
    fn probe(&self, name: &str, _head: &[u8]) -> Confidence {
        let base = Path::new(name)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if NAMES.contains(&base) || base.to_ascii_lowercase().ends_with("host_history.txt") {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let parsed = history::parse(input.data, Some(input.name));
        for problem in parsed.problems {
            sink.skipped(Skipped {
                locator: Locator::ByteOffset(0),
                reason: problem,
            });
        }
        let user = home_owner(input.name);
        for command in &parsed.commands {
            sink.record(self.to_record(input, parsed.format, command, user.as_deref()));
        }
        Ok(())
    }
}

impl HistoryAdapter {
    fn to_record(
        self,
        input: &Input<'_>,
        format: Format,
        command: &Command,
        user: Option<&str>,
    ) -> Record {
        let namespace = match format {
            Format::PowerShell => POWERSHELL,
            Format::Bash | Format::Zsh | Format::Fish => NAMESPACE,
        };
        let mut record = Record::new(
            input.evidence,
            namespace,
            Locator::ByteOffset(command.offset),
            self.parser(),
        );
        if let Some(time) = command.time {
            record
                .times
                .push(RecordTime::new(TimeKind::Executed, "time", time));
        }
        record.facets = Facets {
            user_name: user.map(str::to_owned),
            process_command_line: Some(command.command.clone()),
            ..Facets::default()
        };
        record.fields = fields(format, command);
        let first_line: String = command
            .command
            .lines()
            .next()
            .unwrap_or("")
            .chars()
            .take(SUMMARY_COMMAND)
            .collect();
        // `alice$ ls`, `alice PS> Get-Process`.
        let (gap, prompt) = if format == Format::PowerShell {
            (" ", "PS>")
        } else {
            ("", "$")
        };
        record.summary = match user {
            Some(user) => format!("{user}{gap}{prompt} {first_line}"),
            None => format!("{prompt} {first_line}"),
        };
        record
    }
}

/// The account whose home holds the file: `home/<user>/…`,
/// `Users/<user>/…` (macOS), or `root/…`.
fn home_owner(name: &str) -> Option<String> {
    let parts: Vec<&str> = name.split(['/', '\\']).filter(|p| !p.is_empty()).collect();
    parts
        .iter()
        .enumerate()
        .rev()
        .find_map(|(index, part)| match *part {
            "home" | "Users" => parts
                .get(index + 1)
                .filter(|_| index + 2 < parts.len())
                .map(|u| (*u).to_owned()),
            "root" if index + 1 < parts.len() => Some("root".to_owned()),
            _ => None,
        })
}

fn fields(format: Format, command: &Command) -> Fields {
    let mut fields = Fields::new();
    let shell = match format {
        Format::Bash => "bash",
        Format::Zsh => "zsh",
        Format::Fish => "fish",
        Format::PowerShell => "powershell",
    };
    fields.insert("Shell".into(), Value::from(shell));
    fields.insert("Command".into(), Value::from(command.command.as_str()));
    fields.insert("Line".into(), Value::UInt(command.line as u64));
    if let Some(duration) = command.duration_seconds {
        fields.insert("DurationSeconds".into(), Value::UInt(duration));
    }
    if !command.paths.is_empty() {
        fields.insert(
            "Paths".into(),
            Value::from(command.paths.join("\n").as_str()),
        );
    }
    fields
}

#[cfg(test)]
mod tests {
    use super::home_owner;

    #[test]
    fn owner_from_the_home_folder() {
        assert_eq!(
            home_owner("home/alice/.bash_history").as_deref(),
            Some("alice")
        );
        assert_eq!(
            home_owner("[root]/root/.bash_history").as_deref(),
            Some("root")
        );
        assert_eq!(home_owner("Users/bob/.zsh_history").as_deref(), Some("bob"));
        assert_eq!(
            home_owner("home/carol/.local/share/fish/fish_history").as_deref(),
            Some("carol")
        );
        assert_eq!(home_owner(".bash_history"), None);
        assert_eq!(home_owner("home/.bash_history"), None);
    }
}
