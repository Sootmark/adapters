//! Every key of any hive, as plaso's `winreg_default` plugin reads it: the
//! key's path under the root Windows mounts the hive at, its last write,
//! and its values in one line (`name: [TYPE] data, …`). The named
//! artifacts say what a key means; this says what every key holds.
//!
//! Values are written as plaso writes them from what libregf hands it,
//! checked on every key of the test hives (`tests/oracle/README`).

use model::{Fields, Value};
use registry::{Error, Hive, Key, Kind};

use super::{Out, KEYS};

/// NTUSER.DAT.
const USER: &str = "HKEY_CURRENT_USER";
/// UsrClass.dat (Vista and later, or 2000 to 2003).
const CLASSES: &str = r"HKEY_CURRENT_USER\Software\Classes";
/// Where Windows mounts a hive, recognised as plaso (dfwinreg) does: the
/// root whose keys are all in the hive. Windows 9x files first, then NT's.
const MAPPINGS: [(&str, &[&str]); 9] = [
    (
        "HKEY_LOCAL_MACHINE",
        &[
            "Config", "Enum", "Hardware", "Network", "Software", "System",
        ],
    ),
    (
        "HKEY_USERS",
        &[
            r".DEFAULT\AppEvents",
            r".DEFAULT\Control Panel",
            r".DEFAULT\Keyboard Layout",
            r".DEFAULT\Network",
            r".DEFAULT\Software",
        ],
    ),
    (
        USER,
        &[
            "AppEvents",
            "Console",
            "Control Panel",
            "Environment",
            "Keyboard Layout",
            "Software",
        ],
    ),
    (
        CLASSES,
        &[r"Local Settings\Software\Microsoft\Windows\CurrentVersion"],
    ),
    (CLASSES, &[r"Software\Microsoft\Windows\CurrentVersion"]),
    (r"HKEY_LOCAL_MACHINE\SAM", &[r"SAM\Domains\Account\Users"]),
    (r"HKEY_LOCAL_MACHINE\Security", &[r"Policy\PolAdtEv"]),
    (
        r"HKEY_LOCAL_MACHINE\Software",
        &[r"Microsoft\Windows\CurrentVersion\App Paths"],
    ),
    (
        r"HKEY_LOCAL_MACHINE\System",
        &["MountedDevices", "Select", "Setup"],
    ),
];
/// U+FEFF, which libregf drops from the start of a string.
const BYTE_ORDER_MARK: u16 = 0xFEFF;

/// A value as plaso lists it: name (`""` for the default value), type,
/// data (`None` when it has none).
type Listed = (String, &'static str, Option<String>);

/// The root the hive is mounted at: `""` when no mapping fits, or mappings
/// of different roots do (but for an NTUSER.DAT that also holds a
/// UsrClass.dat's keys, which is the user's).
fn mount_point(hive: &Hive<'_>) -> &'static str {
    let mut fitting: Vec<&str> = MAPPINGS
        .iter()
        .filter(|(_, keys)| keys.iter().all(|k| matches!(hive.open(k), Ok(Some(_)))))
        .map(|(root, _)| *root)
        .collect();
    fitting.dedup();
    match fitting[..] {
        [root] => root,
        [USER, CLASSES] => USER,
        _ => "",
    }
}

/// A key's path as plaso writes it: the mount point and the key's path in
/// the hive, empty segments dropped, rooted at `\` without a mount point.
fn plaso_path(mount_point: &str, path: &str) -> String {
    let segments: Vec<&str> = mount_point
        .split('\\')
        .chain(path.split('\\'))
        .filter(|s| !s.is_empty())
        .collect();
    let joined = segments.join("\\");
    if joined.starts_with("HKEY_") {
        joined
    } else {
        format!("\\{joined}")
    }
}

/// A walked path as the other registry records locate keys: without its
/// leading `\` (`""` for the root).
fn locator_path(path: &str) -> &str {
    path.strip_prefix('\\').unwrap_or(path)
}

/// A type's name as plaso (dfwinreg) writes it.
fn type_name(kind: Kind) -> &'static str {
    match kind {
        Kind::None => "REG_NONE",
        Kind::String => "REG_SZ",
        Kind::ExpandString => "REG_EXPAND_SZ",
        Kind::Binary => "REG_BINARY",
        Kind::Dword => "REG_DWORD_LE",
        Kind::DwordBigEndian => "REG_DWORD_BE",
        Kind::Link => "REG_LINK",
        Kind::MultiString => "REG_MULTI_SZ",
        Kind::ResourceList => "REG_RESOURCE_LIST",
        Kind::FullResourceDescriptor => "REG_FULL_RESOURCE_DESCRIPTOR",
        Kind::ResourceRequirementsList => "REG_RESOURCE_REQUIREMENTS_LIST",
        Kind::Qword => "REG_QWORD",
        Kind::Other(_) => "UNKNOWN",
    }
}

fn units(bytes: &[u8]) -> impl Iterator<Item = u16> + '_ {
    bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
}

/// UTF-16LE text up to its first NUL, as libregf reads a string: a
/// leading byte order mark dropped; `None` for an odd number of bytes,
/// which it refuses.
fn utf16(bytes: &[u8]) -> Option<String> {
    if bytes.len() % 2 != 0 {
        return None;
    }
    let text: Vec<u16> = units(bytes).take_while(|&u| u != 0).collect();
    let text = text.strip_prefix(&[BYTE_ORDER_MARK]).unwrap_or(&text);
    Some(String::from_utf16_lossy(text))
}

/// A `REG_MULTI_SZ`'s strings, as libregf splits them: those a NUL ends,
/// up to the first empty one, which ends the list (an odd last byte is
/// ignored).
fn strings(bytes: &[u8]) -> Vec<String> {
    let all: Vec<u16> = units(bytes).collect();
    let mut pieces: Vec<&[u16]> = all.split(|&u| u == 0).collect();
    // What follows the last NUL isn't ended by one.
    pieces.pop();
    pieces
        .into_iter()
        .take_while(|s| !s.is_empty())
        .map(String::from_utf16_lossy)
        .collect()
}

/// The first `N` bytes, as libregf reads a number from data at least
/// that long.
fn leading<const N: usize>(bytes: &[u8]) -> Option<[u8; N]> {
    bytes.get(..N)?.try_into().ok()
}

/// A value's data as plaso writes it, `None` when it has none: text,
/// numbers in signed decimal (as libregf hands them to Python), strings as
/// `[a, b]`, anything else (and data its type can't be read as) as its
/// size.
fn data_text(kind: Kind, bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    let size = |n: usize| format!("({n} bytes)");
    let text = match kind {
        Kind::String | Kind::ExpandString => utf16(bytes),
        // Read as text, then (plaso keeps no other form) counted in
        // characters.
        Kind::Link => utf16(bytes).map(|text| size(text.chars().count())),
        Kind::MultiString => Some(format!("[{}]", strings(bytes).join(", "))),
        Kind::Dword => leading(bytes).map(|b| i32::from_le_bytes(b).to_string()),
        Kind::DwordBigEndian => leading(bytes).map(|b| i32::from_be_bytes(b).to_string()),
        Kind::Qword => leading(bytes).map(|b| i64::from_le_bytes(b).to_string()),
        _ => None,
    };
    Some(text.unwrap_or_else(|| size(bytes.len())))
}

/// The values in plaso's one line: sorted by name, type and data, the
/// default value named `(default)`, missing data `(empty)`, joined with
/// `, `; `(empty)` for a key without values.
fn values_line(mut values: Vec<Listed>) -> String {
    if values.is_empty() {
        return "(empty)".to_owned();
    }
    values.sort();
    let parts: Vec<String> = values
        .iter()
        .map(|(name, kind, data)| {
            let name = if name.is_empty() { "(default)" } else { name };
            let data = data
                .as_deref()
                .filter(|d| !d.is_empty())
                .unwrap_or("(empty)");
            format!("{name}: [{kind}] {data}")
        })
        .collect();
    parts.join(", ")
}

/// `1 value`, `2 values`.
fn counted(n: u32, noun: &str) -> String {
    if n == 1 {
        format!("1 {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

impl Out<'_, '_> {
    /// Every key, depth first; below a key whose subkeys can't be read,
    /// nothing, and said so.
    pub(super) fn keys(&mut self, hive: &Hive<'_>) {
        let mount_point = mount_point(hive);
        let mut unreadable: Vec<(String, Error)> = Vec::new();
        let walked = hive.walk(
            |path, key| self.key(mount_point, path, key),
            |path, e| unreadable.push((path.to_owned(), e)),
        );
        if let Err(e) = walked {
            self.skip("", None, e.to_string());
        }
        for (path, e) in unreadable {
            self.skip(locator_path(&path), None, e.to_string());
        }
    }

    fn key(&mut self, mount_point: &str, path: &str, key: &Key<'_>) {
        let at = locator_path(path);
        let key_path = plaso_path(mount_point, path);
        let values = self.listed_values(at, key);
        let class = key.class_name().unwrap_or_else(|e| {
            self.skip(at, None, e.to_string());
            None
        });
        let mut record = self.keyed(KEYS, at, None, key.last_written);
        let mut fields = Fields::new();
        fields.insert("KeyPath".into(), Value::from(key_path.as_str()));
        fields.insert("Values".into(), Value::Text(values_line(values)));
        fields.insert("ValueCount".into(), Value::UInt(u64::from(key.value_count)));
        fields.insert(
            "SubkeyCount".into(),
            Value::UInt(u64::from(key.subkey_count)),
        );
        if let Some(class) = class.filter(|c| !c.is_empty()) {
            fields.insert("ClassName".into(), Value::Text(class));
        }
        record.fields = fields;
        record.summary = format!(
            "Key {key_path} · {} · {}",
            counted(key.value_count, "value"),
            counted(key.subkey_count, "subkey")
        );
        self.sink.record(record);
    }

    /// The values that can be read, as plaso lists them; the others
    /// skipped.
    fn listed_values(&mut self, at: &str, key: &Key<'_>) -> Vec<Listed> {
        let values = match key.values() {
            Ok(values) => values,
            Err(e) => {
                self.skip(at, None, e.to_string());
                return Vec::new();
            }
        };
        let mut listed = Vec::with_capacity(values.len());
        for value in values {
            match value {
                Ok(v) => {
                    let data = data_text(v.kind, &v.bytes);
                    listed.push((v.name, type_name(v.kind), data));
                }
                Err(e) => self.skip(at, None, e.to_string()),
            }
        }
        listed
    }
}
