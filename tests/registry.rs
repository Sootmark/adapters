//! The registry adapter on Eric Zimmerman's test SYSTEM and NTUSER.DAT
//! (MIT; `tests/fetch-hives.sh`), against RECmd's output for the same
//! hives (`tests/fixtures/ez/RECmd_registry_artifacts.csv`): every
//! ShimCache entry, service, UserAssist entry and Run value. Skipped when
//! the hives aren't fetched.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Input};
use model::TimeKind;
use model::{EvidenceId, Record, Value};
use sootmark_adapters::registry::{
    RegistryAdapter, AMCACHE_FILE, BAM, RUN, SERVICES, SHELLBAGS, SHIMCACHE, USERASSIST,
};

fn hive(name: &str) -> Option<Vec<u8>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/hives")
        .join(name);
    let data = fs::read(&path).ok();
    if data.is_none() {
        eprintln!(
            "skipped: {} not fetched (tests/fetch-hives.sh)",
            path.display()
        );
    }
    data
}

fn parse(name: &str, bytes: &[u8]) -> Collected {
    let input = Input {
        evidence: EvidenceId::of_content(bytes),
        name,
        data: bytes,
        modified: None,
    };
    let mut sink = Collected::default();
    RegistryAdapter
        .parse(&input, &mut sink)
        .expect("a readable hive");
    sink
}

/// RECmd's rows of one description: (value name, data, data 2, data 3).
fn recmd(description: &str) -> Vec<[String; 4]> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/ez/RECmd_registry_artifacts.csv");
    records(&fs::read_to_string(path).unwrap())
        .into_iter()
        .skip(1)
        .filter(|row| row[1] == description)
        .map(|row| {
            [
                row[3].clone(),
                row[4].clone(),
                row[5].clone(),
                row[6].clone(),
            ]
        })
        .collect()
}

/// CSV records: commas and line breaks inside quotes belong to the field.
fn records(text: &str) -> Vec<Vec<String>> {
    let (mut rows, mut row, mut field, mut quoted) = (Vec::new(), Vec::new(), String::new(), false);
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => row.push(std::mem::take(&mut field)),
            '\r' if !quoted => {}
            '\n' if !quoted => {
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
            }
            c => field.push(c),
        }
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    rows
}

/// A record's time as RECmd prints it: `2013-12-04 23:47:23.2417323`.
fn time(record: &Record) -> String {
    record.times.first().map_or_else(String::new, |t| {
        t.ts.to_string()
            .replace('T', " ")
            .trim_end_matches('Z')
            .to_owned()
    })
}

fn text<'r>(record: &'r Record, field: &str) -> &'r str {
    match record.fields.get(field) {
        Some(Value::Text(s)) => s,
        _ => "",
    }
}

#[test]
fn system_matches_recmd() {
    let Some(bytes) = hive("SYSTEM") else { return };
    assert_conforms(&RegistryAdapter, "SYSTEM", &bytes);
    let output = parse("SYSTEM", &bytes);
    // This SYSTEM hive's last write was interrupted: said once, never silent.
    assert_eq!(output.skipped.len(), 1, "{:?}", output.skipped);
    assert!(output.skipped[0].reason.starts_with("dirty hive"));

    // ShimCache, in order; RECmd shows paths without the NT `\??\` prefix.
    let cache: Vec<&Record> = output
        .records
        .iter()
        .filter(|r| r.namespace() == SHIMCACHE)
        .collect();
    let expected = recmd("AppCompatCache");
    assert_eq!(cache.len(), expected.len());
    for (record, row) in cache.iter().zip(&expected) {
        assert_eq!(text(record, "Path").trim_start_matches(r"\??\"), row[1]);
        assert_eq!(format!("Modified: {}", time(record)), row[2], "{}", row[1]);
    }

    // Services: the same names, image paths and DLLs.
    let ours: BTreeMap<String, (String, String)> = output
        .records
        .iter()
        .filter(|r| r.namespace() == SERVICES)
        .map(|r| {
            let name = r.facets.service_name.clone().unwrap();
            (
                name,
                (
                    text(r, "ImagePath").to_owned(),
                    text(r, "ServiceDll").to_owned(),
                ),
            )
        })
        .collect();
    let theirs: BTreeMap<String, (String, String)> = recmd("Services")
        .into_iter()
        .map(|row| {
            let name = row[1]
                .trim_start_matches("Name: ")
                .split(" Desc: ")
                .next()
                .unwrap()
                .to_owned();
            let rest = row[3].trim_start_matches("Image path: ");
            let (image, dll) = rest.split_once(" ServiceDLL: ").unwrap_or((rest, ""));
            // Where a service has ServiceDll in both places, RECmd shows
            // `Services ServiceDll: … / Parameter ServiceDll: …`; the
            // adapter takes Parameters' and falls back to the key's.
            let dll = match dll.split_once(" / Parameter ServiceDll:") {
                Some((_, parameters)) if !parameters.trim().is_empty() => parameters.trim(),
                Some((key, _)) => key.trim_start_matches("Services ServiceDll:").trim(),
                None => dll.trim(),
            };
            (name, (image.trim().to_owned(), dll.to_owned()))
        })
        .collect();
    assert_eq!(
        ours.keys().collect::<Vec<_>>(),
        theirs.keys().collect::<Vec<_>>()
    );
    let differ: Vec<_> = ours
        .iter()
        .filter(|(k, v)| theirs.get(*k) != Some(v))
        .map(|(k, v)| (k, v, &theirs[k]))
        .collect();
    assert!(
        differ.is_empty(),
        "{} services differ: {:#?}",
        differ.len(),
        &differ[..differ.len().min(6)]
    );
}

#[test]
fn ntuser_matches_recmd() {
    let Some(bytes) = hive("NTUSER.DAT") else {
        return;
    };
    assert_conforms(&RegistryAdapter, "NTUSER.DAT", &bytes);
    let output = parse("NTUSER.DAT", &bytes);

    // UserAssist: every entry with counters (RECmd also lists session data).
    let ours: BTreeSet<String> = output
        .records
        .iter()
        .filter(|r| r.namespace() == USERASSIST)
        .map(|r| r.facets.process_path.clone().unwrap())
        .collect();
    let theirs: BTreeSet<String> = recmd("UserAssist")
        .into_iter()
        .filter(|row| row[1] != "UEME_CTLSESSION")
        .map(|row| row[1].replace("Unmapped GUID: ", ""))
        .collect();
    assert_eq!(ours, theirs);

    // Run and RunOnce: names and commands.
    let ours: BTreeSet<(String, String)> = output
        .records
        .iter()
        .filter(|r| r.namespace() == RUN)
        .map(|r| (text(r, "Name").to_owned(), text(r, "Command").to_owned()))
        .collect();
    let theirs: BTreeSet<(String, String)> = recmd("Run (NTUSER)")
        .into_iter()
        .chain(recmd("RunOnce (NTUSER)"))
        .map(|row| (row[0].clone(), row[1].clone()))
        // RECmd lists a Run key without values as an empty row.
        .filter(|(name, command)| !(name.is_empty() && command.is_empty()))
        .collect();
    assert_eq!(ours, theirs);
}

/// ShellBags from the test `UsrClass.dat`: the 523 bags SBECmd finds (every
/// column is checked against it in the registry crate), as records.
#[test]
fn usrclass_shellbags() {
    let Some(bytes) = hive("ERZ_Win81_UsrClass.dat") else {
        return;
    };
    assert_conforms(&RegistryAdapter, "UsrClass.dat", &bytes);
    let output = parse("UsrClass.dat", &bytes);
    let bags: Vec<&Record> = output
        .records
        .iter()
        .filter(|r| r.namespace() == SHELLBAGS)
        .collect();
    assert_eq!(bags.len(), 523);
    let zip = bags
        .iter()
        .find(|r| {
            r.facets.file_path.as_deref()
                == Some(r"Desktop\This PC\Downloads\Samsung_Magician_v43.zip")
        })
        .expect("a file bag");
    assert!(zip.times.iter().any(|t| t.kind == TimeKind::Created));
    assert!(bags
        .iter()
        .any(|r| r.times.iter().any(|t| t.field == "LastInteracted")));
}

/// Amcache on plaso's Windows 10 test hive (Apache-2.0,
/// `tests/fixtures/amcache/`; the parser is checked against `AmcacheParser`
/// and plaso on every entry in `sootmark-registry`): every entry a record,
/// files with their SHA-1, path and program as `AmcacheParser` reports them.
#[test]
fn amcache_entries_as_amcacheparser_reads_them() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/amcache/Amcache.hve");
    let bytes = fs::read(path).unwrap();
    assert_conforms(&RegistryAdapter, "Amcache.hve", &bytes);
    let output = parse("Amcache.hve", &bytes);
    assert!(output.skipped.is_empty(), "{:?}", output.skipped);
    let mut counts = BTreeMap::new();
    for record in &output.records {
        *counts
            .entry(record.namespace().as_str().to_owned())
            .or_insert(0) += 1;
    }
    assert_eq!(
        counts,
        BTreeMap::from([
            ("windows.registry.amcache.device_container".to_owned(), 8),
            ("windows.registry.amcache.device_pnp".to_owned(), 53),
            ("windows.registry.amcache.file".to_owned(), 30),
            ("windows.registry.amcache.program".to_owned(), 75),
        ])
    );
    let file = output
        .records
        .iter()
        .find(|r| r.facets.file_path.as_deref() == Some(r"c:\program files\7-zip\7z.exe"))
        .unwrap();
    assert_eq!(file.namespace(), AMCACHE_FILE);
    assert_eq!(
        text(file, "SHA1"),
        "6c7ea8bbd435163ae3945cbef30ef6b9872a4591"
    );
    assert_eq!(text(file, "ApplicationName"), "7-Zip 19.00 (x64)");
    assert_eq!(file.fields.get("Size"), Some(&Value::UInt(468_992)));
    assert!(
        time(file).starts_with("2019-12-16 21:01:12"),
        "{}",
        time(file)
    );
    let link = file.times.iter().find(|t| t.field == "LinkDate").unwrap();
    assert!(
        link.ts.to_string().starts_with("2019-02-21T16:00:00"),
        "{}",
        link.ts
    );
    assert_eq!(
        file.summary,
        r"Amcache file c:\program files\7-zip\7z.exe (SHA-1 6c7ea8bbd435163ae3945cbef30ef6b9872a4591)"
    );
}

/// BAM on the SYSTEM hive of Andrew Rathbun's Windows 10 VM (MIT, DFIR
/// Artifact Museum, fetched by `tests/fetch-hives.sh`; `sootmark-registry`
/// checks the parser against `RECmd` on it).
#[test]
fn bam_entries_from_every_control_set() {
    let Some(bytes) = hive("rathbun-win10-SYSTEM") else {
        return;
    };
    let output = parse("SYSTEM", &bytes);
    let bam: Vec<&Record> = output
        .records
        .iter()
        .filter(|r| r.namespace() == BAM)
        .collect();
    assert_eq!(bam.len(), 23);
    let explorer = bam
        .iter()
        .find(|r| {
            r.facets.process_path.as_deref()
                == Some(r"\Device\HarddiskVolume3\Windows\explorer.exe")
                && text(r, "SID").ends_with("-1000")
        })
        .unwrap();
    let run = explorer
        .times
        .iter()
        .find(|t| t.kind == TimeKind::Executed)
        .unwrap();
    assert_eq!(run.ts.to_string(), "2022-02-05T19:31:33.5164430Z");
    assert_eq!(text(explorer, "ControlSet"), "ControlSet001");
}
