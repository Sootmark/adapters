//! The registry adapter on Eric Zimmerman's test SYSTEM and NTUSER.DAT
//! (MIT; `tests/fetch-hives.sh`), against RECmd's output for the same
//! hives (`tests/fixtures/ez/RECmd_registry_artifacts.csv`): every
//! ShimCache entry, service, UserAssist entry and Run value. The
//! incident-response artifacts (USB devices, Remote Desktop, MRU lists,
//! networks, tasks, persistence keys, programs, system identity) are checked
//! against RECmd and plaso on every entry in `sootmark-registry`; here, on
//! the same hives and Andrew Rathbun's Windows 10 VM, that each becomes a
//! record with its namespace, times, facets and summary. Skipped when the
//! hives aren't fetched.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use common::time::Semantic;
use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Input};
use model::TimeKind;
use model::{EvidenceId, Record, Value};
use sootmark_adapters::registry::{
    RegistryAdapter, AMCACHE_FILE, BAM, MOUNTED_DEVICES, MOUNT_POINTS, NETWORKS, NETWORK_DRIVES,
    OFFICE_MRU, OUTLOOK_SEARCH, PERSISTENCE, PROFILES, PROGRAMS, PROGRAMS_CACHE, RDP, RECENT_DOCS,
    RUN, RUN_MRU, SERVICES, SHELLBAGS, SHIMCACHE, SYSTEM, TASKS, TYPED_PATHS, TYPED_URLS, USB,
    USERASSIST, WORD_WHEEL_QUERY, ZONES,
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

/// plaso's `NTUSER-WIN7.DAT` (Apache-2.0): zones, the Start menu caches and
/// Outlook's search; Andrew Rathbun's Windows 10 SYSTEM (MIT): the
/// hardware and `BootExecute`.
#[test]
fn zones_caches_outlook_hardware_and_boot() {
    let Some(user) = hive("plaso-NTUSER-WIN7.DAT") else {
        return;
    };
    let output = parse("NTUSER.DAT", &user);
    assert_conforms(&RegistryAdapter, "NTUSER.DAT", &user);
    assert_eq!(of(&output, ZONES).len(), 10);
    let caches = of(&output, PROGRAMS_CACHE);
    assert_eq!(caches.len(), 3);
    assert!(caches
        .iter()
        .any(|r| text(r, "Shortcuts").contains("Google Chrome.lnk")));
    let outlook = of(&output, OUTLOOK_SEARCH);
    assert_eq!(outlook.len(), 1);
    assert!(text(outlook[0], "Stores")
        .to_ascii_lowercase()
        .contains(".pst"));

    let Some(system) = hive("rathbun-win10-SYSTEM") else {
        return;
    };
    let output = parse("SYSTEM", &system);
    assert!(of(&output, SYSTEM)
        .iter()
        .any(|r| r.summary.starts_with("Hardware: VMware, Inc. VMware7,1")));
    assert!(of(&output, PERSISTENCE)
        .iter()
        .any(|r| text(r, "Mechanism") == "boot_execute"
            && r.fields.get("DeviatesFromDefault") == Some(&Value::Bool(false))));
}

fn of(output: &Collected, namespace: model::Namespace) -> Vec<&Record> {
    output
        .records
        .iter()
        .filter(|r| r.namespace() == namespace)
        .collect()
}

/// Nothing skipped but, where the hive is dirty, the notice saying so.
fn assert_only_dirty(output: &Collected) {
    assert!(
        output
            .skipped
            .iter()
            .all(|s| s.reason.starts_with("dirty hive")),
        "{:?}",
        output.skipped
    );
}

fn time_of<'r>(record: &'r Record, field: &str) -> &'r model::RecordTime {
    record
        .times
        .iter()
        .find(|t| t.field == field)
        .unwrap_or_else(|| panic!("{}: no {field}", record.summary))
}

/// SYSTEM: USB devices (with the letters `MountedDevices` binds them to),
/// mounts, computer name, time zone, last shutdown.
#[test]
fn system_incident_response_artifacts() {
    let Some(bytes) = hive("SYSTEM") else { return };
    let output = parse("SYSTEM", &bytes);
    assert_eq!(output.skipped.len(), 1);
    assert_only_dirty(&output);
    let usb = of(&output, USB);
    assert_eq!(usb.len(), 35);
    let adata = usb
        .iter()
        .find(|r| text(r, "Serial") == "2361808400440061&0")
        .unwrap();
    assert_eq!(
        adata.summary,
        "USBSTOR device ADATA USB Flash Drive USB Device (serial 2361808400440061&0) · J:"
    );
    assert_eq!(text(adata, "Vendor"), "ADATA");
    assert_eq!(text(adata, "LastArrivalSource"), "property 0066");
    assert_eq!(
        time_of(adata, "LastArrival").ts.to_string(),
        "2015-02-24T03:23:35.6628693Z"
    );
    assert_eq!(time_of(adata, "FirstInstalled").kind, TimeKind::FirstSeen);
    assert_eq!(adata.facets.service_name.as_deref(), Some("disk"));
    assert_eq!(of(&output, MOUNTED_DEVICES).len(), 65);
    let j = of(&output, MOUNTED_DEVICES)
        .into_iter()
        .find(|r| text(r, "DriveLetter") == "J:")
        .unwrap();
    assert_eq!(text(j, "Serial"), "2361808400440061&0");
    let system = of(&output, SYSTEM);
    assert_eq!(system.len(), 4, "name, time zone, shutdown, hardware");
    let name = system
        .iter()
        .find(|r| r.facets.host_name.is_some())
        .unwrap();
    assert_eq!(name.facets.host_name.as_deref(), Some("HAXOR4"));
    let shutdown = system
        .iter()
        .find(|r| r.summary.starts_with("Last clean"))
        .unwrap();
    assert_eq!(
        time_of(shutdown, "ShutdownTime").ts.to_string(),
        "2015-02-24T03:22:21.7296539Z"
    );
}

/// NTUSER.DAT: Remote Desktop hosts, the MRU lists, Startup Approved and
/// the user's programs.
#[test]
fn ntuser_incident_response_artifacts() {
    let Some(bytes) = hive("NTUSER.DAT") else {
        return;
    };
    let output = parse("NTUSER.DAT", &bytes);
    assert_only_dirty(&output);
    let rdp = of(&output, RDP);
    assert_eq!(rdp.len(), 6);
    let latest = rdp.iter().find(|r| text(r, "Host") == "SU-SVR02").unwrap();
    assert_eq!(
        latest.summary,
        r"RDP connection to SU-SVR02 as SU\administrator"
    );
    assert_eq!(latest.fields.get("MRUPosition"), Some(&Value::UInt(0)));
    assert_eq!(
        time_of(latest, "MostRecentConnection").ts.to_string(),
        "2014-11-29T18:06:33.2835701Z"
    );
    assert_eq!(latest.facets.destination_ip, None, "a name, not an address");
    assert_eq!(of(&output, RECENT_DOCS).len(), 510);
    let typed = of(&output, TYPED_PATHS);
    assert_eq!(typed.len(), 15);
    let first = typed.iter().find(|r| text(r, "Path") == r"D:\").unwrap();
    assert_eq!(first.times.last().unwrap().field, "Typed");
    assert_eq!(of(&output, WORD_WHEEL_QUERY).len(), 7);
    assert_eq!(of(&output, RUN_MRU).len(), 0);
    let startup = of(&output, PERSISTENCE);
    assert_eq!(startup.len(), 15);
    assert!(startup
        .iter()
        .all(|r| r.fields.get("Enabled") == Some(&Value::Bool(true))));
    assert_eq!(of(&output, PROGRAMS).len(), 11);
}

/// SOFTWARE: networks (local times, kept as such), tasks, persistence keys
/// at Windows' defaults, programs, version, profiles.
#[test]
fn software_incident_response_artifacts() {
    let Some(bytes) = hive("SOFTWARE") else {
        return;
    };
    assert_conforms(&RegistryAdapter, "SOFTWARE", &bytes);
    let output = parse("SOFTWARE", &bytes);
    assert_only_dirty(&output);
    let networks = of(&output, NETWORKS);
    assert_eq!(networks.len(), 1);
    assert_eq!(
        networks[0].summary,
        "Network Network (wired, gateway 00-50-56-F6-99-6B)"
    );
    let created = time_of(networks[0], "DateCreated");
    assert_eq!(created.ts.semantic(), Semantic::LocalUnknownZone);
    assert!(
        created
            .ts
            .to_string()
            .starts_with("2013-10-09T20:32:23.241"),
        "{}",
        created.ts
    );
    assert_eq!(of(&output, TASKS).len(), 85);
    let persistence = of(&output, PERSISTENCE);
    assert_eq!(persistence.len(), 19);
    assert!(persistence
        .iter()
        .all(|r| r.fields.get("DeviatesFromDefault") == Some(&Value::Bool(false))));
    assert_eq!(of(&output, PROGRAMS).len(), 31);
    let version = of(&output, SYSTEM);
    assert_eq!(version.len(), 1);
    assert_eq!(version[0].summary, "Windows 7 Professional (build 7601)");
    let profiles = of(&output, PROFILES);
    assert_eq!(profiles.len(), 4);
    assert!(profiles
        .iter()
        .any(|r| r.facets.user_sid.as_deref()
            == Some("S-1-5-21-1246908546-1649523366-531194530-1000")));
}

/// Windows 10's task actions: the program a task runs is its process
/// facets; the task's path is its task name.
#[test]
fn windows_10_tasks_and_networks() {
    let Some(bytes) = hive("rathbun-win10-SOFTWARE") else {
        return;
    };
    assert_conforms(&RegistryAdapter, "SOFTWARE", &bytes);
    let output = parse("SOFTWARE", &bytes);
    assert_only_dirty(&output);
    let tasks = of(&output, TASKS);
    assert_eq!(tasks.len(), 224, "197 tasks, 27 Tree entries without one");
    let scan = tasks
        .iter()
        .find(|r| {
            r.facets.task_name.as_deref()
                == Some(r"\Microsoft\Windows\UpdateOrchestrator\Schedule Scan Static Task")
        })
        .unwrap();
    assert_eq!(
        scan.facets.process_path.as_deref(),
        Some(r"%systemroot%\system32\usoclient.exe")
    );
    assert_eq!(
        scan.facets.process_command_line.as_deref(),
        Some(r"%systemroot%\system32\usoclient.exe StartScan")
    );
    assert_eq!(
        time_of(scan, "LastStart").ts.to_string(),
        "2022-02-08T20:44:02.0808351Z"
    );
    assert_eq!(time_of(scan, "LastStart").kind, TimeKind::Executed);
    let networks = of(&output, NETWORKS);
    assert_eq!(networks.len(), 1);
    let last = time_of(networks[0], "DateLastConnected");
    assert_eq!(last.ts.semantic(), Semantic::LocalUnknownZone);
    assert!(
        last.ts.to_string().starts_with("2022-02-08T15:56:42.234"),
        "{}",
        last.ts
    );
}

/// plaso's NTUSER-WIN7.DAT: mount points, a mapped drive, Office's lists
/// and typed addresses as records (their values are checked against plaso
/// in `sootmark-registry`).
#[test]
fn drives_office_and_typed_addresses() {
    let Some(bytes) = hive("plaso-NTUSER-WIN7.DAT") else {
        return;
    };
    let output = parse("NTUSER.DAT", &bytes);
    let of = |namespace| {
        output
            .records
            .iter()
            .filter(|r| r.namespace() == namespace)
            .collect::<Vec<&Record>>()
    };
    assert_eq!(of(MOUNT_POINTS).len(), 5);
    let share = of(MOUNT_POINTS)
        .into_iter()
        .find(|r| r.fields.get("Name") == Some(&Value::from("##controller#public")))
        .unwrap();
    assert_eq!(
        share.summary,
        r"Share \\controller\public seen by Explorer (Public)"
    );
    let drives = of(NETWORK_DRIVES);
    assert_eq!(drives.len(), 1);
    assert_eq!(
        drives[0].summary,
        r"Network drive p: mapped to \\controller\public"
    );
    let office = of(OFFICE_MRU);
    assert_eq!(office.len(), 7);
    assert!(office
        .iter()
        .all(|r| r.times.iter().any(|t| t.kind == TimeKind::Accessed)));
    assert_eq!(of(TYPED_URLS).len(), 13);
}
