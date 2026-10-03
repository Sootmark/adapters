//! The LNK adapter on three of Eric Zimmerman's MIT test links (Windows
//! 10, 7 and XP; the whole set is checked against `LECmd` in `sootmark-shell`):
//! the contract, and the target, times and machine LECmd reports.

use std::fs;
use std::path::Path;

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Input};
use model::{EvidenceId, TimeKind, Value};
use sootmark_adapters::lnk::{LnkAdapter, NAMESPACE};

fn parse(name: &str) -> (Vec<u8>, Collected) {
    let bytes = fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/lnk")
            .join(name),
    )
    .unwrap();
    let input = Input {
        evidence: EvidenceId::of_content(&bytes),
        name,
        data: &bytes,
        modified: None,
    };
    let mut sink = Collected::default();
    LnkAdapter.parse(&input, &mut sink).expect("a link");
    (bytes, sink)
}

#[test]
fn maps_links_as_lecmd_reads_them() {
    for (name, target, created, machine) in [
        (
            "winhex.lnk",
            r"C:\xwf18.5\winhex.exe",
            "2015-12-16T16:39:14",
            "win10x86",
        ),
        (
            "iexplore.lnk",
            r"C:\Program Files (x86)\Internet Explorer\iexplore.exe",
            "2010-11-21T03:25:08",
            "win7x64",
        ),
        (
            "msoobe.lnk",
            r"C:\WINDOWS\system32\oobe\msoobe.exe",
            "2016-01-13T18:36:08",
            "xppro",
        ),
    ] {
        let (bytes, output) = parse(name);
        assert_conforms(&LnkAdapter, name, &bytes);
        assert_eq!(output.records.len(), 1, "{name}");
        let record = &output.records[0];
        assert_eq!(record.namespace(), NAMESPACE);
        assert_eq!(record.facets.file_path.as_deref(), Some(target), "{name}");
        let created_at = record
            .times
            .iter()
            .find(|t| t.kind == TimeKind::Created)
            .unwrap();
        assert!(
            created_at.ts.to_string().starts_with(created),
            "{name}: {}",
            created_at.ts
        );
        assert_eq!(
            record.fields.get("MachineID"),
            Some(&Value::from(machine)),
            "{name}"
        );
        assert_eq!(
            record.summary,
            format!("Link to {target} (made on {machine})")
        );
    }
}

#[test]
fn rejects_what_isnt_a_link() {
    let bytes = b"not a link".to_vec();
    let input = Input {
        evidence: EvidenceId::of_content(&bytes),
        name: "x.lnk",
        data: &bytes,
        modified: None,
    };
    assert!(LnkAdapter.parse(&input, &mut Collected::default()).is_err());
}
