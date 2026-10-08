//! Windows Portable Executable files (`.exe`, `.dll`, `.sys`, whatever
//! their name), via the `pe` parser: one record per file, with when it was
//! linked, what kind of image it is, its import hash, the DLLs it imports,
//! its sections, the version information its publisher wrote and the PDB
//! path its linker left.
//!
//! **Which files.** A disk holds tens of thousands of executables, nearly
//! all of them Windows' and installed programs': a record each would bury
//! the few that matter. The probe takes a PE image (by content: `MZ`, and
//! `PE\0\0` where it points) only where programs are not installed and a
//! user, or malware running as one, can write: under `Users\` (profiles,
//! so `AppData`, `Downloads`, `Desktop` and `Public` too) and XP's
//! `Documents and Settings\`, `ProgramData\`, temporary folders (`Temp\`,
//! `Tmp\`, `Windows\Temp\`), the Recycle Bin (`$Recycle.Bin\`,
//! `RECYCLER\`), `PerfLogs\`, `Windows\Tasks\`, `Windows\Debug\`,
//! `Windows\Fonts\`, `Windows\Tracing\`, `System Volume Information\`,
//! and any `Downloads\` or `Public\` folder. Elsewhere
//! (`Windows\System32\`, `Program Files\`, …) it says no.
//!
//! The certificate table (Authenticode) isn't read: there is no signer,
//! only whether the image carries a signature (`HasSignature`).

use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};
use pe::Pe;

use crate::home::profile_owner;
use crate::key::field_name;

/// Records of PE files.
pub const NAMESPACE: Namespace = Namespace::new("windows.pe");

/// Folders where an executable is worth a record: a lowercase path, `/`
/// separated, that has one of these as a folder (or starts with it).
const WRITABLE_FOLDERS: [&str; 15] = [
    "/users/",
    "/documents and settings/",
    "/programdata/",
    "/temp/",
    "/tmp/",
    "/$recycle.bin/",
    "/recycler/",
    "/perflogs/",
    "/windows/tasks/",
    "/windows/debug/",
    "/windows/fonts/",
    "/windows/tracing/",
    "/system volume information/",
    "/downloads/",
    "/public/",
];

/// The data directory of the certificate table.
const CERTIFICATE_TABLE: usize = 4;
/// The version strings shown in a summary.
const SUMMARY_VERSION_KEYS: [&str; 2] = ["CompanyName", "FileDescription"];

/// One record per PE file in a user-writable folder.
#[derive(Debug, Default, Clone, Copy)]
pub struct PeAdapter;

impl Adapter for PeAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "pe",
            version: pe::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[NAMESPACE]
    }

    /// A PE image in a folder a user can write to (see the module docs);
    /// no elsewhere.
    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        if is_writable_place(name) && pe::detect(head) {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let image = pe::read(input.data).map_err(|e| ParseError::at(e.offset as u64, e.reason))?;
        for reason in &image.problems {
            sink.skipped(Skipped {
                locator: Locator::ByteOffset(0),
                reason: reason.clone(),
            });
        }
        sink.record(self.record(input, &image));
        Ok(())
    }
}

impl PeAdapter {
    fn record(self, input: &Input<'_>, image: &Pe) -> Record {
        let mut record = Record::new(
            input.evidence,
            NAMESPACE,
            Locator::ByteOffset(0),
            self.parser(),
        );
        for (kind, name, time) in [
            (TimeKind::Created, "Compiled", image.compiled),
            (
                TimeKind::Other,
                "ExportTime",
                image.exports.as_ref().and_then(|e| e.timestamp),
            ),
            (
                TimeKind::Other,
                "ResourceTime",
                image.resources.as_ref().and_then(|r| r.timestamp),
            ),
            (
                TimeKind::Other,
                "DebugTime",
                image.debug.iter().find_map(|d| d.timestamp),
            ),
            (TimeKind::Other, "LoadConfigTime", image.load_config_time),
        ] {
            if let Some(time) = time.filter(|t| t.ticks().is_some()) {
                record.times.push(RecordTime::new(kind, name, time));
            }
        }
        let mut fields = Fields::new();
        if let Some(info) = image.version_info.as_ref() {
            for table in info.string_tables.iter().rev() {
                for (key, value) in &table.strings {
                    text(&mut fields, &field_name(key), Some(value));
                }
            }
        }
        insert_header_fields(&mut fields, image);
        record.fields = fields;
        record.facets = Facets {
            user_name: profile_owner(input.name),
            file_path: Some(input.name.to_owned()),
            ..Facets::default()
        };
        let base = input.name.rsplit(['/', '\\']).next().unwrap_or(input.name);
        let publisher: Vec<&str> = SUMMARY_VERSION_KEYS
            .iter()
            .filter_map(|key| image.version_info.as_ref()?.get(key))
            .filter(|value| !value.trim().is_empty())
            .collect();
        record.summary = format!(
            "PE {}: {base}{}{}",
            image.kind.label(),
            if publisher.is_empty() {
                String::new()
            } else {
                format!(" ({})", publisher.join(", "))
            },
            image
                .codeview
                .as_ref()
                .map_or_else(String::new, |pdb| format!(", PDB {}", pdb.path))
        );
        record
    }
}

/// The headers, tables and hashes, under fixed names.
fn insert_header_fields(fields: &mut Fields, image: &Pe) {
    let header = &image.file_header;
    text(fields, "Kind", Some(image.kind.label()));
    text(
        fields,
        "Machine",
        Some(
            &pe::machine_name(header.machine)
                .map_or_else(|| format!("0x{:04x}", header.machine), str::to_owned),
        ),
    );
    fields.insert(
        "Characteristics".into(),
        Value::UInt(u64::from(header.characteristics)),
    );
    text(fields, "Imphash", image.imphash.as_deref());
    if let Some(optional) = &image.optional {
        text(
            fields,
            "Subsystem",
            Some(
                &pe::subsystem_name(optional.subsystem)
                    .map_or_else(|| optional.subsystem.to_string(), str::to_owned),
            ),
        );
        fields.insert(
            "EntryPoint".into(),
            Value::UInt(u64::from(optional.entry_point)),
        );
        fields.insert("ImageBase".into(), Value::UInt(optional.image_base));
        fields.insert("Checksum".into(), Value::UInt(u64::from(optional.checksum)));
        let (major, minor) = optional.linker_version;
        text(fields, "LinkerVersion", Some(&format!("{major}.{minor}")));
        let signed = optional
            .directory(CERTIFICATE_TABLE)
            .is_some_and(|d| d.rva != 0 && d.size != 0);
        fields.insert("HasSignature".into(), Value::Bool(signed));
    }
    if let Some(pdb) = &image.codeview {
        text(fields, "PdbPath", Some(&pdb.path));
        text(fields, "PdbGuid", pdb.guid.as_deref());
        fields.insert("PdbAge".into(), Value::UInt(u64::from(pdb.age)));
    }
    if let Some(exports) = &image.exports {
        text(fields, "ExportDllName", Some(&exports.dll_name));
        fields.insert(
            "ExportCount".into(),
            Value::UInt(exports.functions.len() as u64),
        );
    }
    let dlls: Vec<&str> = image.imports.iter().map(|i| i.dll.as_str()).collect();
    if !dlls.is_empty() {
        text(fields, "Imports", Some(&dlls.join(", ")));
    }
    let functions: usize = image.imports.iter().map(|i| i.functions.len()).sum();
    fields.insert("ImportCount".into(), Value::UInt(functions as u64));
    let sections: Vec<String> = image
        .sections
        .iter()
        .map(|s| format!("{} ({} bytes)", s.name, s.raw_size))
        .collect();
    if !sections.is_empty() {
        text(fields, "Sections", Some(&sections.join(", ")));
    }
    fields.insert(
        "SectionCount".into(),
        Value::UInt(image.sections.len() as u64),
    );
}

/// Whether a file is in a folder a user can write to.
fn is_writable_place(name: &str) -> bool {
    let path = format!("/{}", name.replace('\\', "/").to_ascii_lowercase());
    WRITABLE_FOLDERS.iter().any(|folder| path.contains(folder))
}

fn text(fields: &mut Fields, name: &str, value: Option<&str>) {
    if let Some(value) = value.filter(|v| !v.trim().is_empty()) {
        fields.insert(name.into(), Value::from(value));
    }
}

#[cfg(test)]
mod tests {
    use super::is_writable_place;

    #[test]
    fn only_folders_users_write_to() {
        for path in [
            r"C\Users\alice\AppData\Local\Temp\a.exe",
            "C/Users/Public/x.dll",
            r"C:\ProgramData\updater.exe",
            r"C\$Recycle.Bin\S-1-5-21-1\$RABC.exe",
            r"C\Windows\Temp\svc.exe",
            "Documents and Settings/bob/Desktop/tool.exe",
            "Users/carol/Downloads/setup.exe",
        ] {
            assert!(is_writable_place(path), "{path}");
        }
        for path in [
            r"C\Windows\System32\kernel32.dll",
            r"C\Program Files\App\app.exe",
            r"C\Windows\SysWOW64\ntdll.dll",
            "Windows/WinSxS/x/comctl32.dll",
        ] {
            assert!(!is_writable_place(path), "{path}");
        }
    }
}
