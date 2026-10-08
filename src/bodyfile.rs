//! The Sleuth Kit's bodyfile (version 3, what `fls -m`, `ils -m` and many
//! collection tools write for `mactime`): one record per file, with its
//! four times.
//!
//! `MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime`, times in
//! Unix seconds (a fraction allowed, `0` meaning none). A name ending
//! ` (deleted)` is a deleted file; a link's name is followed by ` -> ` and
//! its target. Names are escaped as The Sleuth Kit writes them (`\\`,
//! `\|`, `\xNN`), and unescaped here. Lines starting with `#` are comments.

use common::time::{Precision, Ts};
use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};

/// Records of bodyfiles.
pub const NAMESPACE: Namespace = Namespace::new("import.bodyfile");

/// The fields of a line.
const FIELDS: usize = 11;

/// Imports bodyfiles.
#[derive(Debug, Default, Clone, Copy)]
pub struct BodyfileAdapter;

impl Adapter for BodyfileAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "bodyfile-import",
            version: env!("CARGO_PKG_VERSION"),
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[NAMESPACE]
    }

    /// By the first line: eleven `|`-separated fields, the last four
    /// numbers.
    fn probe(&self, _name: &str, head: &[u8]) -> Confidence {
        let text = String::from_utf8_lossy(head);
        let first = text.lines().next().unwrap_or_default();
        if line(first).is_some() {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let text = String::from_utf8_lossy(input.data);
        for (index, text) in text.lines().enumerate() {
            if text.trim().is_empty() || text.starts_with('#') {
                continue;
            }
            match line(text) {
                Some(entry) => sink.record(self.record(input, index + 1, &entry)),
                None => sink.skipped(Skipped {
                    locator: Locator::Line(index as u64 + 1),
                    reason: format!("not a bodyfile line ({FIELDS} fields)"),
                }),
            }
        }
        Ok(())
    }
}

/// A bodyfile line.
struct Entry<'a> {
    md5: &'a str,
    name: String,
    link: Option<String>,
    deleted: bool,
    inode: &'a str,
    mode: &'a str,
    uid: &'a str,
    gid: &'a str,
    size: Option<u64>,
    times: [Option<Ts>; 4],
}

/// A line's fields: split at the `|` not escaped; a name may hold more,
/// so the fields are counted from both ends.
fn line(text: &str) -> Option<Entry<'_>> {
    let fields = split(text);
    if fields.len() < FIELDS {
        return None;
    }
    let tail = &fields[fields.len() - 9..];
    let times = [tail[5], tail[6], tail[7], tail[8]].map(seconds);
    if [tail[5], tail[6], tail[7], tail[8]]
        .iter()
        .any(|t| t.trim().parse::<f64>().is_err())
    {
        return None;
    }
    let full = unescape(&fields[1..fields.len() - 9].join("|"));
    let (full, deleted) = match full.strip_suffix(" (deleted)") {
        Some(name) => (name.to_owned(), true),
        None => (full, false),
    };
    let (name, link) = match full.split_once(" -> ") {
        Some((name, target)) => (name.to_owned(), Some(target.to_owned())),
        None => (full, None),
    };
    Some(Entry {
        md5: fields[0],
        name,
        link,
        deleted,
        inode: tail[0],
        mode: tail[1],
        uid: tail[2],
        gid: tail[3],
        size: tail[4].trim().parse().ok(),
        times,
    })
}

/// `text` split at each `|` a backslash doesn't escape.
fn split(text: &str) -> Vec<&str> {
    let mut fields = Vec::new();
    let mut start = 0;
    let mut escaped = false;
    for (at, c) in text.char_indices() {
        match c {
            '\\' if !escaped => escaped = true,
            '|' if !escaped => {
                fields.push(&text[start..at]);
                start = at + 1;
            }
            _ => escaped = false,
        }
    }
    fields.push(&text[start..]);
    fields
}

/// TSK's escapes undone: `\\` a backslash, `\|` a bar, `\xNN` a byte.
fn unescape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.peek().copied() {
            Some(next @ ('\\' | '|')) => {
                out.push(next);
                chars.next();
            }
            Some('x') => {
                let hex: String = chars.clone().skip(1).take(2).collect();
                match u8::from_str_radix(&hex, 16) {
                    Ok(byte) if hex.len() == 2 => {
                        out.push(char::from(byte));
                        chars.nth(2);
                    }
                    _ => out.push(c),
                }
            }
            _ => out.push(c),
        }
    }
    out
}

/// Unix seconds, a fraction of any length allowed (read as decimal digits,
/// to 100 ns); `0` and negatives as none.
fn seconds(text: &str) -> Option<Ts> {
    let text = text.trim();
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    let whole: i64 = whole.parse().ok().filter(|&s| s > 0)?;
    if !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if fraction.is_empty() {
        return Some(Ts::from_unix_seconds(whole));
    }
    let digits: String = fraction.chars().take(7).collect();
    let ticks: i64 = format!("{digits:0<7}").parse().ok()?;
    Some(Ts::from_ticks(
        whole.checked_mul(10_000_000)? + ticks,
        Precision::Tick,
    ))
}

impl BodyfileAdapter {
    fn record(self, input: &Input<'_>, line: usize, entry: &Entry<'_>) -> Record {
        let mut record = Record::new(
            input.evidence,
            NAMESPACE,
            Locator::Line(line as u64),
            self.parser(),
        );
        for ((kind, name), time) in [
            (TimeKind::Accessed, "atime"),
            (TimeKind::Modified, "mtime"),
            (TimeKind::MetadataChanged, "ctime"),
            (TimeKind::Created, "crtime"),
        ]
        .into_iter()
        .zip(entry.times)
        {
            if let Some(time) = time {
                record.times.push(RecordTime::new(kind, name, time));
            }
        }
        let mut fields = Fields::new();
        for (name, value) in [
            ("Name", entry.name.as_str()),
            ("Inode", entry.inode),
            ("Mode", entry.mode),
            ("Uid", entry.uid),
            ("Gid", entry.gid),
        ] {
            fields.insert(name.into(), Value::from(value));
        }
        if entry.md5 != "0" && !entry.md5.is_empty() {
            fields.insert("Md5".into(), Value::from(entry.md5));
        }
        if let Some(size) = entry.size {
            fields.insert("Size".into(), Value::UInt(size));
        }
        if let Some(link) = &entry.link {
            fields.insert("LinkTarget".into(), Value::from(link.as_str()));
        }
        fields.insert("Deleted".into(), Value::Bool(entry.deleted));
        record.fields = fields;
        record.facets = Facets {
            file_path: Some(entry.name.clone()),
            ..Facets::default()
        };
        record.summary = format!(
            "{}{}",
            entry.name,
            if entry.deleted { " (deleted)" } else { "" }
        );
        record
    }
}
