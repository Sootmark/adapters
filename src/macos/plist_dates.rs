//! Property lists no named artifact reads, as plaso's `plist_default`
//! plugin reads them: one record per key holding a date, located by the
//! path of dictionary keys that leads to it.

use std::collections::HashMap;

use model::adapter::{Adapter, Input};
use model::{Facets, Fields, Locator, Record, RecordTime, TimeKind, Value};
use plist::Ts;

use super::{MacosAdapter, PLIST};

/// How deep plaso follows dictionaries and arrays (the top value counts).
const DEPTH: u32 = 15;

/// A key holding a date: the path of the dictionary keys above it
/// (`/DeviceCache/00-0d-fd-00-00-00`, `""` at the top), its name, the date.
struct DatedKey<'v> {
    root: String,
    key: &'v str,
    date: Ts,
}

/// Every key holding a date, as plaso's `_RecurseKey` walks the tree: a
/// dictionary's keys, then the dictionaries among its values (a dictionary,
/// or an array's elements), one level deeper; arrays at the top are walked
/// into, dates in arrays aren't keys. A key repeated in a dictionary has its
/// last value, as plistlib reads it.
fn dated_keys<'v>(item: &'v plist::Value, depth: u32, root: &str, out: &mut Vec<DatedKey<'v>>) {
    if depth == 0 {
        return;
    }
    match item {
        plist::Value::Array(items) => {
            for item in items {
                dated_keys(item, depth - 1, root, out);
            }
        }
        plist::Value::Dictionary(entries) => {
            let last: HashMap<&str, usize> = entries
                .iter()
                .enumerate()
                .map(|(index, (key, _))| (key.as_str(), index))
                .collect();
            for (index, (key, value)) in entries.iter().enumerate() {
                if last.get(key.as_str()) != Some(&index) {
                    continue;
                }
                if let plist::Value::Date(date) = value {
                    out.push(DatedKey {
                        root: root.to_owned(),
                        key,
                        date: *date,
                    });
                }
                let below = match value {
                    plist::Value::Dictionary(_) => std::slice::from_ref(value),
                    plist::Value::Array(items) => items,
                    _ => &[],
                };
                let mut dictionaries = below
                    .iter()
                    .filter(|child| matches!(child, plist::Value::Dictionary(_)))
                    .peekable();
                if dictionaries.peek().is_some() {
                    let path = format!("{root}/{key}");
                    for child in dictionaries {
                        dated_keys(child, depth - 1, &path, out);
                    }
                }
            }
        }
        _ => {}
    }
}

impl MacosAdapter {
    /// The dated keys of a property list and its damage.
    pub(super) fn plist_dates(
        self,
        input: &Input<'_>,
        owner: Option<&str>,
    ) -> Result<(Vec<String>, Vec<Record>), plist::Error> {
        let parsed = plist::parse(input.data)?;
        let mut keys = Vec::new();
        dated_keys(&parsed.value, DEPTH, "", &mut keys);
        let records = (0u64..)
            .zip(&keys)
            .map(|(index, key)| self.dated_key(input, index, key, owner))
            .collect();
        Ok((parsed.problems, records))
    }

    fn dated_key(
        self,
        input: &Input<'_>,
        index: u64,
        key: &DatedKey<'_>,
        owner: Option<&str>,
    ) -> Record {
        let mut record = Record::new(
            input.evidence,
            PLIST,
            Locator::TableRow {
                table: "plist".to_owned(),
                row: index,
            },
            self.parser(),
        );
        // plaso's message for the key, and the name the time goes by.
        let path = format!("{}/{}", key.root, key.key);
        record
            .times
            .push(RecordTime::new(TimeKind::Modified, path.as_str(), key.date));
        let mut fields = Fields::new();
        fields.insert("Key".into(), Value::from(key.key));
        fields.insert("Root".into(), Value::from(key.root.as_str()));
        fields.insert("Path".into(), Value::from(path.as_str()));
        record.fields = fields;
        record.facets = Facets {
            user_name: owner.map(str::to_owned),
            ..Facets::default()
        };
        record.summary = format!("Property list date {path}");
        record
    }
}

#[cfg(test)]
mod tests {
    use plist::Value;

    use super::*;

    fn date(seconds: i64) -> Value {
        Value::Date(Ts::from_unix_seconds(seconds))
    }

    fn dict(entries: Vec<(&str, Value)>) -> Value {
        Value::Dictionary(
            entries
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v))
                .collect(),
        )
    }

    fn walk(value: &Value) -> Vec<(String, String)> {
        let mut out = Vec::new();
        dated_keys(value, DEPTH, "", &mut out);
        out.into_iter()
            .map(|k| (k.root, k.key.to_owned()))
            .collect()
    }

    #[test]
    fn dictionaries_below_arrays_are_walked_but_dates_in_arrays_are_not() {
        let top = Value::Array(vec![dict(vec![
            ("at", date(1)),
            (
                "list",
                Value::Array(vec![date(2), dict(vec![("inner", date(3))])]),
            ),
            (
                "nested",
                Value::Array(vec![Value::Array(vec![dict(vec![("lost", date(4))])])]),
            ),
        ])]);
        assert_eq!(
            walk(&top),
            [
                (String::new(), "at".into()),
                ("/list".into(), "inner".into())
            ]
        );
    }

    #[test]
    fn a_repeated_key_has_its_last_value() {
        let top = dict(vec![
            ("when", date(1)),
            ("when", Value::Bool(true)),
            ("then", date(2)),
            ("then", date(3)),
        ]);
        let mut out = Vec::new();
        dated_keys(&top, DEPTH, "", &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(
            (out[0].key, out[0].date),
            ("then", Ts::from_unix_seconds(3))
        );
    }

    #[test]
    fn fifteen_levels_are_walked() {
        let mut value = dict(vec![("deepest", date(1))]);
        for level in (1..16).rev() {
            value = dict(vec![(&format!("level{level}"), date(1)), ("next", value)]);
        }
        let keys = walk(&value);
        assert_eq!(keys.len(), 15);
        assert_eq!(keys[14].1, "level15");
        assert!(keys[14].0.ends_with("/next/next"));
    }
}
