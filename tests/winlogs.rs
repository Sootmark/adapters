//! The Windows text logs adapter on plaso's test logs (Apache-2.0,
//! `tests/fixtures/winlogs/`, gzip-compressed): a record per entry, in the
//! right namespace, with the facets hunts use.

use std::io::Read;

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, Record};
use sootmark_adapters::winlogs::{
    WinlogsAdapter, ANYDESK, FIREWALL, IIS, PCA, SCCM, SETUPAPI, TEAMVIEWER, TRANSCRIPT,
};

fn records(name: &str) -> Vec<Record> {
    let path = format!(
        "{}/tests/fixtures/winlogs/{name}.gz",
        env!("CARGO_MANIFEST_DIR")
    );
    let compressed = std::fs::read(path).unwrap();
    let mut data = Vec::new();
    common::gzip::Decoder::new(compressed.as_slice())
        .read_to_end(&mut data)
        .unwrap();
    assert_eq!(
        WinlogsAdapter.probe(name, &data[..data.len().min(4096)]),
        Confidence::Certain,
        "{name}"
    );
    assert_conforms(&WinlogsAdapter, name, &data);
    let input = Input {
        evidence: EvidenceId::of_content(&data),
        name,
        data: &data,
        modified: None,
    };
    let mut sink = Collected::default();
    WinlogsAdapter.parse(&input, &mut sink).unwrap();
    sink.records
}

#[test]
fn every_log_family() {
    let pca = records("PcaAppLaunchDic.txt");
    assert_eq!(pca.len(), 4);
    assert!(pca.iter().all(|r| r.namespace() == PCA));
    assert!(pca[0]
        .summary
        .starts_with("PCA: ran C:\\Program Files\\WindowsApps\\MicrosoftTeams"));
    assert_eq!(records("PcaGeneralDb0.txt").len(), 3);

    let iis = records("iis6.log");
    assert!(iis.iter().all(|r| r.namespace() == IIS));
    assert_eq!(iis[1].facets.source_ip.as_deref(), Some("22.22.22.200"));
    assert_eq!(
        iis[1].summary,
        "IIS GET /some/image/path/something.htm 404 from 22.22.22.200"
    );

    let firewall = records("windows_firewall.log");
    assert_eq!(firewall.len(), 15);
    assert!(firewall.iter().all(|r| r.namespace() == FIREWALL));
    assert!(firewall[0]
        .summary
        .starts_with("Firewall DROP UDP 123.45.78.90:137 -> 123.156.78.255:137"));

    let transcript = records("powershell_transcript_ger.txt");
    assert_eq!(transcript.len(), 3);
    assert!(transcript.iter().all(|r| r.namespace() == TRANSCRIPT));
    assert_eq!(transcript[0].facets.user_name.as_deref(), Some("DE\\User"));
    assert_eq!(transcript[0].facets.host_name.as_deref(), Some("MySystem"));
    assert_eq!(
        transcript[0].facets.process_command_line.as_deref(),
        Some("whoami; echo $null >> filename; ping 8.8.8.8; Get-Content .\\myfile.txt")
    );

    let sessions = records("connections_incoming.txt");
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].namespace(), TEAMVIEWER);
    assert_eq!(
        sessions[0].summary,
        "TeamViewer session in from 1660360496 (TestUserRedacted) as IEUser: RemoteControl"
    );

    let setup = records("setupapi.setup.log");
    assert_eq!(setup.len(), 16);
    assert!(setup.iter().all(|r| r.namespace() == SETUPAPI));

    let sccm = records("sccm_various.log");
    assert_eq!(sccm.len(), 10);
    assert!(sccm.iter().all(|r| r.namespace() == SCCM));
}

#[test]
fn anydesk_logs() {
    let trace = records("ad_svc.trace");
    assert_eq!(trace.len(), 7);
    assert!(trace.iter().all(|r| r.namespace() == ANYDESK));
    let login = &trace[1];
    assert_eq!(login.facets.source_ip.as_deref(), Some("198.51.100.4"));
    let sessions = records("connection_trace.txt");
    assert_eq!(
        sessions[0].summary,
        "AnyDesk session in from 221436813 (User)"
    );
    assert_eq!(
        sessions[2].summary,
        "AnyDesk session out to 377110044 (Token)"
    );
}
