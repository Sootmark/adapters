//! Office documents' metadata, via the `office` parser: Office 97–2003
//! files (`.doc`, `.xls`, `.ppt`: their property sets) and Office Open XML
//! (`.docx`, `.xlsx`, `.pptx`: `docProps/`), macro-enabled ones too. One
//! record per document: who wrote it and who saved it last, when it was
//! created, last saved and last printed, how long it was edited, the
//! application and company, its title and counts, and its user-defined
//! properties (`Custom.<name>`).

use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};
use office::{Document, Format, Properties};

use crate::home::profile_owner;
use crate::key::field_name;

/// Records of Office documents.
pub const NAMESPACE: Namespace = Namespace::new("office.document");

/// The extensions of the compound files read.
const OLE_EXTENSIONS: [&str; 5] = ["doc", "dot", "xls", "xlt", "ppt"];
/// The extensions of the packages read.
const OOXML_EXTENSIONS: [&str; 7] = ["docx", "docm", "dotm", "xlsx", "xlsm", "pptx", "pptm"];
/// A compound file's first bytes.
const OLE_SIGNATURE: [u8; 8] = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
/// A zip archive's first bytes.
const ZIP_SIGNATURE: &[u8] = b"PK\x03\x04";

/// One record per document.
#[derive(Debug, Default, Clone, Copy)]
pub struct OfficeAdapter;

impl Adapter for OfficeAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "office",
            version: office::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[NAMESPACE]
    }

    /// By extension and signature: a compound file named `.doc`, `.xls`,
    /// `.ppt` (or a template), a zip package named `.docx`, `.xlsx`,
    /// `.pptx` (or macro-enabled).
    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        let extension = name
            .rsplit_once('.')
            .map(|(_, e)| e.to_ascii_lowercase())
            .unwrap_or_default();
        let ole = OLE_EXTENSIONS.contains(&extension.as_str()) && head.starts_with(&OLE_SIGNATURE);
        let ooxml =
            OOXML_EXTENSIONS.contains(&extension.as_str()) && head.starts_with(ZIP_SIGNATURE);
        if ole || ooxml {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        if !office::detect(input.data) {
            return Err(ParseError::at(
                0,
                "neither a compound file with property sets nor an Office Open XML package",
            ));
        }
        let document = office::read(input.data).map_err(|e| ParseError::at(0, e.0))?;
        for reason in &document.problems {
            sink.skipped(Skipped {
                locator: Locator::ByteOffset(0),
                reason: reason.clone(),
            });
        }
        sink.record(self.record(input, &document));
        Ok(())
    }
}

impl OfficeAdapter {
    fn record(self, input: &Input<'_>, document: &Document) -> Record {
        let p = &document.properties;
        let mut record = Record::new(
            input.evidence,
            NAMESPACE,
            Locator::ByteOffset(0),
            self.parser(),
        );
        for (kind, name, time) in [
            (TimeKind::Created, "Created", p.created),
            (TimeKind::Modified, "LastSaved", p.modified),
            (TimeKind::Other, "LastPrinted", p.last_printed),
        ] {
            if let Some(time) = time.filter(|t| t.ticks().is_some()) {
                record.times.push(RecordTime::new(kind, name, time));
            }
        }
        let mut fields = Fields::new();
        for (name, value) in &document.other {
            text(
                &mut fields,
                &format!("Other.{}", field_name(name)),
                Some(value),
            );
        }
        for (name, value) in &document.custom {
            text(
                &mut fields,
                &format!("Custom.{}", field_name(name)),
                Some(value),
            );
        }
        insert_properties(&mut fields, p);
        text(
            &mut fields,
            "Format",
            Some(match document.format {
                Format::Ole => "OLE",
                Format::OfficeOpenXml => "OOXML",
            }),
        );
        record.fields = fields;
        let who = p.last_saved_by.as_deref().or(p.author.as_deref());
        record.facets = Facets {
            user_name: who
                .filter(|w| !w.trim().is_empty())
                .map(str::to_owned)
                .or_else(|| profile_owner(input.name)),
            file_path: Some(input.name.to_owned()),
            ..Facets::default()
        };
        let base = input.name.rsplit(['/', '\\']).next().unwrap_or(input.name);
        let title = p
            .title
            .as_deref()
            .filter(|t| !t.trim().is_empty())
            .map_or_else(String::new, |t| format!(" \"{t}\""));
        let by = p
            .author
            .as_deref()
            .filter(|a| !a.trim().is_empty())
            .map_or_else(String::new, |a| format!(" by {a}"));
        let saved = p
            .last_saved_by
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .map_or_else(String::new, |s| format!(", last saved by {s}"));
        let application = p
            .application
            .as_deref()
            .filter(|a| !a.trim().is_empty())
            .map_or_else(String::new, |a| format!(" ({a})"));
        record.summary = format!("Office document {base}{title}{by}{saved}{application}");
        record
    }
}

/// The properties read into fields, under fixed names.
fn insert_properties(fields: &mut Fields, p: &Properties) {
    for (name, value) in [
        ("Title", &p.title),
        ("Subject", &p.subject),
        ("Author", &p.author),
        ("Keywords", &p.keywords),
        ("Comments", &p.comments),
        ("Template", &p.template),
        ("LastSavedBy", &p.last_saved_by),
        ("Revision", &p.revision),
        ("Application", &p.application),
        ("AppVersion", &p.app_version),
        ("Company", &p.company),
        ("Manager", &p.manager),
        ("Category", &p.category),
        ("PresentationFormat", &p.presentation_format),
        ("ContentType", &p.content_type),
        ("ContentStatus", &p.content_status),
        ("Language", &p.language),
        ("Identifier", &p.identifier),
        ("Version", &p.version),
        ("HyperlinkBase", &p.hyperlink_base),
    ] {
        text(fields, name, value.as_deref());
    }
    for (name, value) in [
        ("Pages", p.pages),
        ("Words", p.words),
        ("Characters", p.characters),
        ("CharactersWithSpaces", p.characters_with_spaces),
        ("Bytes", p.bytes),
        ("Lines", p.lines),
        ("Paragraphs", p.paragraphs),
        ("Slides", p.slides),
        ("Notes", p.notes),
        ("HiddenSlides", p.hidden_slides),
        ("MultimediaClips", p.multimedia_clips),
        ("Security", p.security),
    ] {
        if let Some(value) = value {
            fields.insert(name.into(), Value::Int(value));
        }
    }
    for (name, value) in [
        ("ScaleCrop", p.scale_crop),
        ("LinksDirty", p.links_dirty),
        ("LinksUpToDate", p.links_up_to_date),
        ("Shared", p.shared),
        ("HyperlinksChanged", p.hyperlinks_changed),
    ] {
        if let Some(value) = value {
            fields.insert(name.into(), Value::Bool(value));
        }
    }
    if let Some(edit) = p.edit_time {
        fields.insert("EditTimeSeconds".into(), Value::UInt(edit.as_secs()));
    }
    if !p.titles_of_parts.is_empty() {
        text(
            fields,
            "TitlesOfParts",
            Some(&p.titles_of_parts.join(" | ")),
        );
    }
}

fn text(fields: &mut Fields, name: &str, value: Option<&str>) {
    if let Some(value) = value.filter(|v| !v.is_empty()) {
        fields.insert(name.into(), Value::from(value));
    }
}
