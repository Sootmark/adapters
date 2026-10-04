//! The shell history adapter on plaso's test files (Apache-2.0,
//! `tests/fixtures/history/`): the contract, what commands become, and the
//! account taken from the home folder.

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, TimeKind, Value};
use sootmark_adapters::history::{HistoryAdapter, NAMESPACE};

fn read(file: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/history/{file}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn parse(file: &str, name: &str) -> Collected {
    let data = read(file);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    HistoryAdapter.parse(&input, &mut sink).expect("commands");
    sink
}

#[test]
fn conforms_and_probes() {
    for (file, name) in [
        ("bash_history", "home/alice/.bash_history"),
        ("zsh_extended_history.txt", "home/alice/.zsh_history"),
        ("fish_history", "home/alice/.local/share/fish/fish_history"),
    ] {
        assert_conforms(&HistoryAdapter, name, &read(file));
    }
    let bash = read("bash_history");
    assert_eq!(
        HistoryAdapter.probe("root/.bash_history", &bash),
        Confidence::Certain
    );
    assert_eq!(HistoryAdapter.probe("notes.txt", &bash), Confidence::No);
}

#[test]
fn bash_commands() {
    let records = parse("bash_history", "home/alice/.bash_history").records;
    assert_eq!(records.len(), 4);
    let first = &records[0];
    assert_eq!(first.namespace(), NAMESPACE);
    assert_eq!(first.summary, "alice$ /usr/lib/plaso");
    assert_eq!(first.facets.user_name.as_deref(), Some("alice"));
    assert_eq!(first.times[0].kind, TimeKind::Executed);
    assert_eq!(
        first.times[0].ts.to_iso8601().unwrap(),
        "2013-10-01T12:36:17.0000000Z"
    );
    assert_eq!(first.fields.get("Shell"), Some(&Value::from("bash")));
    // A multi-line command: the summary shows its first line.
    assert_eq!(records[3].summary, "alice$ binary argument1 \"--params=\\");
    assert!(records[3]
        .facets
        .process_command_line
        .as_deref()
        .unwrap()
        .ends_with("\" argument2"));
}

#[test]
fn zsh_and_fish_commands() {
    let zsh = parse("zsh_extended_history.txt", "root/.zsh_history").records;
    assert_eq!(zsh[0].summary, "root$ cd plaso");
    assert_eq!(zsh[0].fields.get("DurationSeconds"), Some(&Value::UInt(0)));

    let fish = parse("fish_history", ".local/share/fish/fish_history").records;
    assert_eq!(fish.len(), 10);
    assert_eq!(fish[0].summary, "$ ll");
    assert_eq!(fish[0].facets.user_name, None);
    assert_eq!(fish[3].fields.get("Paths"), Some(&Value::from("test")));
}

/// A PSReadLine history (`tests/fixtures/history-powershell/`): its own
/// namespace, the account from the profile, backtick continuations joined.
#[test]
fn powershell_history() {
    use sootmark_adapters::history::POWERSHELL;
    let data = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/history-powershell/ConsoleHost_history.txt"
    ))
    .unwrap();
    let path = r"C:\Users\alice\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt";
    assert_eq!(HistoryAdapter.probe(path, &data), Confidence::Certain);
    assert_conforms(&HistoryAdapter, path, &data);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name: path,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    HistoryAdapter.parse(&input, &mut sink).unwrap();
    let records = &sink.records;
    assert_eq!(records.len(), 3);
    assert!(records.iter().all(|r| r.namespace() == POWERSHELL));
    assert_eq!(records[0].summary, "alice PS> Get-Process");
    assert!(records[1]
        .facets
        .process_command_line
        .as_deref()
        .is_some_and(|c| c.contains("-Uri http://192.0.2.4/a.ps1")));
}
