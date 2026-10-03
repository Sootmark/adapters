//! Eric Zimmerman's tools (EZ Tools), imported from their CSV output.
//!
//! Each tool's CSV is recognised by its exact header and mapped by a
//! spec: which columns are times and what they mean, which fill the
//! timeline's facets, and a one-line summary. Every non-empty column is
//! kept as a field under its EZ name, so nothing the tool wrote is lost.
//! The CSV is the evidence, so records are located by CSV line.
//!
//! EZ Tools write times in UTC without a zone (their documented default);
//! .NET's "no date", `0001-01-01 00:00:00`, is read as no time. Imports get
//! their own namespaces (`ez.*`): they're EZ's reading of an artifact, not
//! Sootmark's.
//!
//! Tested on real output of `MFTECmd` (`$MFT`, `$J`), `LECmd`, `JLECmd` (automatic
//! and custom destinations), `RBCmd`, `EvtxECmd`, `AmcacheParser` (file and
//! program entries), `PECmd` (and its run timeline), `AppCompatCacheParser`,
//! `SBECmd` and `RECmd` (batch output), .NET 9 builds.

use std::path::Path;

use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};

use crate::csv;
use crate::timestamp;

/// A CSV row, by column name; empty cells read as absent.
struct Row<'a> {
    header: &'a [String],
    cells: &'a [String],
}

impl Row<'_> {
    fn get(&self, column: &str) -> Option<&str> {
        let index = self.header.iter().position(|c| c == column)?;
        self.cells
            .get(index)
            .map(|cell| cell.trim())
            .filter(|cell| !cell.is_empty())
    }

    fn owned(&self, column: &str) -> Option<String> {
        self.get(column).map(str::to_owned)
    }

    /// `Parent\Name`, the way `MFTECmd` splits paths.
    fn joined(&self, parent: &str, name: &str) -> Option<String> {
        match (self.get(parent), self.get(name)) {
            (Some(parent), Some(name)) => {
                Some(format!("{}\\{name}", parent.trim_end_matches('\\')))
            }
            (None, Some(name)) => Some(name.to_owned()),
            _ => None,
        }
    }
}

/// How one tool's CSV maps into records.
struct Spec {
    /// Tool and table, for messages.
    tool: &'static str,
    namespace: Namespace,
    /// The header's first columns, exactly.
    header: &'static [&'static str],
    /// Time columns and what they mean.
    times: &'static [(&'static str, TimeKind)],
    facets: fn(&Row<'_>) -> Facets,
    summary: fn(&Row<'_>) -> String,
}

const MFT: Namespace = Namespace::new("ez.mft");
const USN: Namespace = Namespace::new("ez.usnjrnl");
const LNK: Namespace = Namespace::new("ez.lnk");
const JUMPLIST_AUTO: Namespace = Namespace::new("ez.jumplist.automatic");
const JUMPLIST_CUSTOM: Namespace = Namespace::new("ez.jumplist.custom");
const RECYCLE_BIN: Namespace = Namespace::new("ez.recyclebin");
const EVTX: Namespace = Namespace::new("ez.evtx");
const AMCACHE_FILE: Namespace = Namespace::new("ez.amcache.file");
const AMCACHE_PROGRAM: Namespace = Namespace::new("ez.amcache.program");
const PREFETCH: Namespace = Namespace::new("ez.prefetch");
const PREFETCH_RUNS: Namespace = Namespace::new("ez.prefetch.runs");
const SHIMCACHE: Namespace = Namespace::new("ez.shimcache");
const SHELLBAGS: Namespace = Namespace::new("ez.shellbags");
const REGISTRY: Namespace = Namespace::new("ez.registry");

/// Every namespace these imports produce.
pub const NAMESPACES: &[Namespace] = &[
    MFT,
    USN,
    LNK,
    JUMPLIST_AUTO,
    JUMPLIST_CUSTOM,
    RECYCLE_BIN,
    EVTX,
    AMCACHE_FILE,
    AMCACHE_PROGRAM,
    PREFETCH,
    PREFETCH_RUNS,
    SHIMCACHE,
    SHELLBAGS,
    REGISTRY,
];

use TimeKind::{
    Accessed, Created, Deleted, Executed, FirstSeen, LastSeen, Logged, MetadataChanged, Modified,
    Other,
};

const SPECS: &[Spec] = &[
    Spec {
        tool: "MFTECmd ($MFT)",
        namespace: MFT,
        header: &[
            "EntryNumber",
            "SequenceNumber",
            "InUse",
            "ParentEntryNumber",
            "ParentSequenceNumber",
            "ParentPath",
            "FileName",
        ],
        times: &[
            ("Created0x10", Created),
            ("Created0x30", Created),
            ("LastModified0x10", Modified),
            ("LastModified0x30", Modified),
            ("LastRecordChange0x10", MetadataChanged),
            ("LastRecordChange0x30", MetadataChanged),
            ("LastAccess0x10", Accessed),
            ("LastAccess0x30", Accessed),
        ],
        facets: |r| Facets {
            file_path: r.joined("ParentPath", "FileName"),
            ..Facets::default()
        },
        summary: |r| {
            let kind = if r.get("IsDirectory") == Some("True") {
                "directory"
            } else {
                "file"
            };
            let state = if r.get("InUse") == Some("False") {
                " (deleted)"
            } else {
                ""
            };
            format!(
                "MFT {kind}{state} · {}",
                r.joined("ParentPath", "FileName").unwrap_or_default()
            )
        },
    },
    Spec {
        tool: "MFTECmd ($J)",
        namespace: USN,
        header: &[
            "Name",
            "Extension",
            "EntryNumber",
            "SequenceNumber",
            "ParentEntryNumber",
            "ParentSequenceNumber",
            "ParentPath",
            "UpdateSequenceNumber",
            "UpdateTimestamp",
            "UpdateReasons",
        ],
        times: &[("UpdateTimestamp", Logged)],
        facets: |r| Facets {
            file_path: r.joined("ParentPath", "Name"),
            ..Facets::default()
        },
        summary: |r| {
            format!(
                "USN {} · {}",
                r.get("UpdateReasons").unwrap_or("?"),
                r.joined("ParentPath", "Name").unwrap_or_default()
            )
        },
    },
    Spec {
        tool: "LECmd",
        namespace: LNK,
        header: &[
            "SourceFile",
            "SourceCreated",
            "SourceModified",
            "SourceAccessed",
            "TargetCreated",
            "TargetModified",
            "TargetAccessed",
            "FileSize",
            "RelativePath",
            "WorkingDirectory",
        ],
        times: &[
            ("SourceCreated", Created),
            ("SourceModified", Modified),
            ("SourceAccessed", Accessed),
            ("TargetCreated", Created),
            ("TargetModified", Modified),
            ("TargetAccessed", Accessed),
            ("TrackerCreatedOn", Other),
        ],
        facets: |r| Facets {
            file_path: lnk_target(r),
            ..Facets::default()
        },
        summary: |r| {
            let mut line = format!(
                "LNK → {}",
                lnk_target(r).unwrap_or_else(|| "(no target path)".to_owned())
            );
            if let Some(arguments) = r.get("Arguments") {
                line.push(' ');
                line.push_str(arguments);
            }
            line
        },
    },
    Spec {
        tool: "JLECmd (automatic destinations)",
        namespace: JUMPLIST_AUTO,
        header: &[
            "SourceFile",
            "SourceCreated",
            "SourceModified",
            "SourceAccessed",
            "AppId",
            "AppIdDescription",
            "HasSps",
            "DestListVersion",
        ],
        times: &[
            ("CreationTime", FirstSeen),
            ("LastModified", LastSeen),
            ("TargetCreated", Created),
            ("TargetModified", Modified),
            ("TargetAccessed", Accessed),
            ("SourceCreated", Created),
            ("SourceModified", Modified),
            ("SourceAccessed", Accessed),
        ],
        facets: |r| Facets {
            file_path: r.owned("Path").or_else(|| r.owned("LocalPath")),
            ..Facets::default()
        },
        summary: |r| {
            format!(
                "Jump list {} · {}",
                r.get("AppIdDescription")
                    .or_else(|| r.get("AppId"))
                    .unwrap_or("?"),
                r.get("Path")
                    .or_else(|| r.get("LocalPath"))
                    .unwrap_or("(no path)")
            )
        },
    },
    Spec {
        tool: "JLECmd (custom destinations)",
        namespace: JUMPLIST_CUSTOM,
        header: &[
            "SourceFile",
            "SourceCreated",
            "SourceModified",
            "SourceAccessed",
            "AppId",
            "AppIdDescription",
            "EntryName",
        ],
        times: &[
            ("TargetCreated", Created),
            ("TargetModified", Modified),
            ("TargetAccessed", Accessed),
            ("SourceCreated", Created),
            ("SourceModified", Modified),
            ("SourceAccessed", Accessed),
        ],
        facets: |r| Facets {
            file_path: lnk_target(r),
            ..Facets::default()
        },
        summary: |r| {
            format!(
                "Jump list {} ({}) · {}",
                r.get("AppIdDescription")
                    .or_else(|| r.get("AppId"))
                    .unwrap_or("?"),
                r.get("EntryName").unwrap_or("?"),
                lnk_target(r).unwrap_or_else(|| "(no path)".to_owned())
            )
        },
    },
    Spec {
        tool: "RBCmd",
        namespace: RECYCLE_BIN,
        header: &[
            "SourceName",
            "FileType",
            "FileName",
            "FileSize",
            "DeletedOn",
        ],
        times: &[("DeletedOn", Deleted)],
        facets: |r| Facets {
            file_path: r.owned("FileName"),
            // $Recycle.Bin\<SID>\$I…: the folder names the user.
            user_sid: r.get("SourceName").and_then(|path| {
                path.split(['\\', '/'])
                    .find(|part| part.starts_with("S-1-"))
                    .map(str::to_owned)
            }),
            ..Facets::default()
        },
        summary: |r| format!("Recycle bin: deleted {}", r.get("FileName").unwrap_or("?")),
    },
    Spec {
        tool: "EvtxECmd",
        namespace: EVTX,
        header: &[
            "RecordNumber",
            "EventRecordId",
            "TimeCreated",
            "EventId",
            "Level",
            "Provider",
            "Channel",
        ],
        times: &[("TimeCreated", Logged)],
        facets: |r| Facets {
            host_name: r.owned("Computer"),
            user_name: r.owned("UserName"),
            event_code: r.get("EventId").and_then(|id| id.parse().ok()),
            channel: r.owned("Channel"),
            provider: r.owned("Provider"),
            process_id: r
                .get("ProcessId")
                .and_then(|id| id.parse().ok())
                .filter(|&id| id != 0),
            ..Facets::default()
        },
        summary: |r| {
            let mut line = format!(
                "{} {}",
                r.get("EventId").unwrap_or("?"),
                r.get("Provider").unwrap_or("?")
            );
            for column in [
                "MapDescription",
                "PayloadData1",
                "PayloadData2",
                "PayloadData3",
            ] {
                if let Some(value) = r.get(column) {
                    line.push_str(" · ");
                    line.push_str(value);
                }
            }
            line
        },
    },
    Spec {
        tool: "AmcacheParser (file entries)",
        namespace: AMCACHE_FILE,
        header: &[
            "ApplicationName",
            "ProgramId",
            "FileKeyLastWriteTimestamp",
            "SHA1",
            "IsOsComponent",
            "FullPath",
        ],
        times: &[("FileKeyLastWriteTimestamp", Other), ("LinkDate", Other)],
        facets: |r| Facets {
            process_path: r.owned("FullPath"),
            ..Facets::default()
        },
        summary: |r| {
            format!(
                "Amcache file {} · SHA-1 {}",
                r.get("FullPath").unwrap_or("?"),
                r.get("SHA1").unwrap_or("?")
            )
        },
    },
    Spec {
        tool: "AmcacheParser (program entries)",
        namespace: AMCACHE_PROGRAM,
        header: &[
            "ProgramId",
            "KeyLastWriteTimestamp",
            "Name",
            "Version",
            "Publisher",
        ],
        times: &[
            ("KeyLastWriteTimestamp", Other),
            ("InstallDate", Other),
            ("InstallDateArpLastModified", Other),
            ("InstallDateMsi", Other),
            ("InstallDateFromLinkFile", Other),
        ],
        facets: |_| Facets::default(),
        summary: |r| {
            format!(
                "Amcache program {} {} ({})",
                r.get("Name").unwrap_or("?"),
                r.get("Version").unwrap_or(""),
                r.get("Publisher").unwrap_or("unknown publisher")
            )
        },
    },
    Spec {
        tool: "PECmd",
        namespace: PREFETCH,
        header: &[
            "Note",
            "SourceFilename",
            "SourceCreated",
            "SourceModified",
            "SourceAccessed",
            "ExecutableName",
            "Hash",
            "Size",
            "Version",
            "RunCount",
            "LastRun",
        ],
        times: &[
            ("LastRun", Executed),
            ("PreviousRun0", Executed),
            ("PreviousRun1", Executed),
            ("PreviousRun2", Executed),
            ("PreviousRun3", Executed),
            ("PreviousRun4", Executed),
            ("PreviousRun5", Executed),
            ("PreviousRun6", Executed),
            ("SourceCreated", Created),
            ("SourceModified", Modified),
            ("SourceAccessed", Accessed),
            ("Volume0Created", Other),
            ("Volume1Created", Other),
        ],
        facets: |r| Facets {
            process_path: r.owned("ExecutableName"),
            ..Facets::default()
        },
        summary: |r| {
            format!(
                "Prefetch {} · run {} times, last {}",
                r.get("ExecutableName").unwrap_or("?"),
                r.get("RunCount").unwrap_or("?"),
                r.get("LastRun").unwrap_or("?")
            )
        },
    },
    Spec {
        tool: "PECmd (timeline)",
        namespace: PREFETCH_RUNS,
        header: &["RunTime", "ExecutableName"],
        times: &[("RunTime", Executed)],
        facets: |r| Facets {
            process_path: r.owned("ExecutableName"),
            ..Facets::default()
        },
        summary: |r| format!("Executed {}", r.get("ExecutableName").unwrap_or("?")),
    },
    Spec {
        tool: "AppCompatCacheParser",
        namespace: SHIMCACHE,
        header: &[
            "ControlSet",
            "CacheEntryPosition",
            "Path",
            "LastModifiedTimeUTC",
            "Executed",
            "Duplicate",
        ],
        // The file's modification time as the cache saw it, not a run time.
        times: &[("LastModifiedTimeUTC", Modified)],
        facets: |r| Facets {
            process_path: r.owned("Path"),
            ..Facets::default()
        },
        summary: |r| {
            format!(
                "ShimCache {} · entry {} · executed flag: {}",
                r.get("Path").unwrap_or("?"),
                r.get("CacheEntryPosition").unwrap_or("?"),
                r.get("Executed").unwrap_or("n/a")
            )
        },
    },
    Spec {
        tool: "SBECmd",
        namespace: SHELLBAGS,
        header: &[
            "BagPath",
            "Slot",
            "NodeSlot",
            "MRUPosition",
            "AbsolutePath",
            "ShellType",
            "Value",
            "ChildBags",
            "CreatedOn",
            "ModifiedOn",
            "AccessedOn",
            "LastWriteTime",
        ],
        times: &[
            ("CreatedOn", Created),
            ("ModifiedOn", Modified),
            ("AccessedOn", Accessed),
            ("LastWriteTime", Other),
            ("FirstInteracted", FirstSeen),
            ("LastInteracted", LastSeen),
        ],
        facets: |r| Facets {
            file_path: r.owned("AbsolutePath"),
            ..Facets::default()
        },
        summary: |r| {
            format!(
                "ShellBag {} ({})",
                r.get("AbsolutePath").unwrap_or("?"),
                r.get("ShellType").unwrap_or("?")
            )
        },
    },
    Spec {
        tool: "RECmd (batch)",
        namespace: REGISTRY,
        header: &[
            "HivePath",
            "HiveType",
            "Description",
            "Category",
            "KeyPath",
            "ValueName",
            "ValueType",
            "ValueData",
        ],
        // Last write time of the key the value lives in.
        times: &[("LastWriteTimestamp", Other)],
        facets: |_| Facets::default(),
        summary: |r| {
            let mut line = format!(
                "{}: {}",
                r.get("Category").unwrap_or("Registry"),
                r.get("Description").unwrap_or("?")
            );
            for column in ["ValueName", "ValueData", "ValueData2"] {
                if let Some(value) = r.get(column) {
                    line.push_str(" · ");
                    line.push_str(value);
                }
            }
            line
        },
    },
];

/// A link's target: local path, else network path (with the common part).
fn lnk_target(r: &Row<'_>) -> Option<String> {
    r.owned("LocalPath")
        .or_else(|| match (r.get("NetworkPath"), r.get("CommonPath")) {
            (Some(share), Some(common)) => {
                Some(format!("{}\\{common}", share.trim_end_matches('\\')))
            }
            (Some(share), None) => Some(share.to_owned()),
            _ => None,
        })
        .or_else(|| r.owned("TargetIDAbsolutePath"))
}

/// The spec whose header `columns` starts with.
fn spec_for(columns: &[String]) -> Option<&'static Spec> {
    SPECS.iter().find(|spec| {
        columns.len() >= spec.header.len()
            && spec
                .header
                .iter()
                .zip(columns)
                .all(|(want, got)| want == got)
    })
}

/// The header line of a CSV, without a byte order mark.
fn header_of(head: &[u8]) -> Option<Vec<String>> {
    let text = String::from_utf8_lossy(head);
    let line = text.trim_start_matches('\u{feff}').lines().next()?;
    let first = csv::records(line).next()?;
    first.ok().map(|record| record.fields)
}

/// Imports EZ Tools' CSV output.
#[derive(Debug, Default, Clone, Copy)]
pub struct EzAdapter;

impl Adapter for EzAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "ez-import",
            version: env!("CARGO_PKG_VERSION"),
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        NAMESPACES
    }

    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        if header_of(head).as_deref().and_then(spec_for).is_some() {
            return Confidence::Certain;
        }
        let file = Path::new(name)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let named = [
            "_MFTECmd_",
            "_LECmd_",
            "_RBCmd_",
            "_EvtxECmd_",
            "_Amcache_",
            "Destinations.csv",
        ]
        .iter()
        .any(|marker| file.contains(marker));
        if named && file.to_ascii_lowercase().ends_with(".csv") {
            Confidence::Maybe
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let text = std::str::from_utf8(input.data).map_err(|e| {
            ParseError::at(
                e.valid_up_to() as u64,
                "not UTF-8 text: not EZ Tools output",
            )
        })?;
        let mut rows = csv::records(text);
        let header = match rows.next() {
            Some(Ok(header)) => header.fields,
            Some(Err(e)) => {
                return Err(ParseError::at(0, format!("line {}: {}", e.line, e.message)))
            }
            None => return Err(ParseError::at(0, "empty file")),
        };
        let spec = spec_for(&header)
            .ok_or_else(|| ParseError::at(0, "header matches no EZ tool this importer knows"))?;
        for row in rows {
            let row = match row {
                Ok(row) => row,
                Err(e) => {
                    sink.skipped(Skipped {
                        locator: Locator::Line(e.line),
                        reason: e.message.to_owned(),
                    });
                    continue;
                }
            };
            if row.fields.len() != header.len() {
                sink.skipped(Skipped {
                    locator: Locator::Line(row.line),
                    reason: format!(
                        "{} fields where the {} header has {}",
                        row.fields.len(),
                        spec.tool,
                        header.len()
                    ),
                });
                continue;
            }
            sink.record(self.record(
                input,
                spec,
                &Row {
                    header: &header,
                    cells: &row.fields,
                },
                row.line,
            ));
        }
        Ok(())
    }
}

impl EzAdapter {
    fn record(self, input: &Input<'_>, spec: &Spec, row: &Row<'_>, line: u64) -> Record {
        let mut record = Record::new(
            input.evidence,
            spec.namespace,
            Locator::Line(line),
            self.parser(),
        );
        for &(column, kind) in spec.times {
            if let Some(ts) = row.get(column).and_then(timestamp::utc) {
                record.times.push(RecordTime::new(kind, column, ts));
            }
        }
        let mut fields = Fields::new();
        for (column, cell) in row.header.iter().zip(row.cells) {
            if !cell.trim().is_empty() {
                fields.insert(column.clone(), Value::from(cell.as_str()));
            }
        }
        record.fields = fields;
        record.facets = (spec.facets)(row);
        record.summary = (spec.summary)(row);
        record
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(columns: &str) -> Vec<String> {
        columns.split(',').map(str::to_owned).collect()
    }

    #[test]
    fn every_spec_is_recognised_by_its_header_only() {
        for spec in SPECS {
            let columns: Vec<String> = spec.header.iter().map(|c| (*c).to_owned()).collect();
            assert_eq!(spec_for(&columns).map(|s| s.tool), Some(spec.tool));
        }
        assert!(spec_for(&header("SourceFile,SourceCreated")).is_none());
        assert!(spec_for(&header("a,b,c")).is_none());
    }

    #[test]
    fn probes_by_header_then_name() {
        let a = EzAdapter;
        assert_eq!(
            a.probe(
                "x.csv",
                "\u{feff}SourceName,FileType,FileName,FileSize,DeletedOn\n".as_bytes()
            ),
            Confidence::Certain
        );
        assert_eq!(
            a.probe("20260929_RBCmd_Output.csv", b"garbage"),
            Confidence::Maybe
        );
        assert_eq!(a.probe("notes.csv", b"a,b\n"), Confidence::No);
    }

    #[test]
    fn joins_mft_paths() {
        let header = header("ParentPath,FileName");
        let cells = vec![".\\Users\\Public".to_owned(), "rclone.exe".to_owned()];
        let row = Row {
            header: &header,
            cells: &cells,
        };
        assert_eq!(
            row.joined("ParentPath", "FileName").as_deref(),
            Some(".\\Users\\Public\\rclone.exe")
        );
    }
}
