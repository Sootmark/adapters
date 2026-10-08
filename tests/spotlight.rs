//! The Spotlight store adapter on plaso's test stores (Apache-2.0,
//! `tests/fixtures/spotlight/`): a CoreSpotlight store, and a macOS 12
//! store read with the streams maps beside it as companion files, and
//! without them.

use std::io::Read;

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Companion, Confidence, Input};
use model::{EvidenceId, TimeKind, Value};
use sootmark_adapters::spotlight::{SpotlightAdapter, NAMESPACE};

fn fixture(name: &str) -> Vec<u8> {
    let raw = std::fs::read(format!(
        "{}/tests/fixtures/spotlight/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    if !std::path::Path::new(name)
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("gz"))
    {
        return raw;
    }
    let mut data = Vec::new();
    common::gzip::Decoder::new(raw.as_slice())
        .read_to_end(&mut data)
        .unwrap();
    data
}

fn collect(path: &str, data: &[u8], companions: &[Companion<'_>]) -> Collected {
    assert_eq!(SpotlightAdapter.probe(path, data), Confidence::Certain);
    assert_conforms(&SpotlightAdapter, path, data);
    let input = Input {
        evidence: EvidenceId::of_content(data),
        name: path,
        data,
        modified: None,
    };
    let mut sink = Collected::default();
    SpotlightAdapter
        .parse_with_companions(&input, companions, &mut sink)
        .unwrap();
    assert!(sink.records.iter().all(|r| r.namespace() == NAMESPACE));
    sink
}

#[test]
fn core_spotlight_store() {
    let path = "Users/alice/Library/Metadata/CoreSpotlight/index.spotlightV3/store.db";
    let sink = collect(path, &fixture("859631-store.db.gz"), &[]);
    assert!(sink.skipped.is_empty(), "{:?}", sink.skipped);
    assert_eq!(sink.records.len(), 1848);
    assert_eq!(sink.records[0].summary, "Spotlight store properties");
    assert!(sink.records.iter().any(|r| r.summary
        == "Spotlight indexed Use your mouse to zoom in to make an image larger on Mac"));
    assert!(sink
        .records
        .iter()
        .all(|r| r.facets.user_name.as_deref() == Some("alice")));
}

#[test]
fn volume_store_with_its_streams_maps() {
    let path = ".Spotlight-V100/Store-V2/B8A60235-5AE9-4A1A-9004-3F40B6FF4C28/store.db";
    let names = SpotlightAdapter.companions(path);
    assert_eq!(names.len(), 12);
    let maps: Vec<(String, Vec<u8>)> = names
        .iter()
        .map(|name| (name.clone(), fixture(&format!("spotlight-12/{name}"))))
        .collect();
    let companions: Vec<Companion<'_>> = maps
        .iter()
        .map(|(name, data)| Companion { name, data })
        .collect();
    let store = fixture("spotlight-12/store.db");
    let sink = collect(path, &store, &companions);
    assert!(sink.skipped.is_empty(), "{:?}", sink.skipped);
    assert_eq!(sink.records.len(), 3);
    let license = &sink.records[2];
    assert_eq!(license.summary, "Spotlight indexed /LICENSE (Document)");
    assert_eq!(license.facets.file_path.as_deref(), Some("/LICENSE"));
    assert_eq!(license.fields.get("Kind"), Some(&Value::from("Document")));
    assert!(license.fields.contains_key("_kMDItemFileName"));
    assert_eq!(license.times[0].kind, TimeKind::FirstSeen);

    // Without the maps: the items, without their attributes, and the gap
    // reported.
    let bare = collect(path, &store, &[]);
    assert_eq!(bare.records.len(), 3);
    assert!(!bare.skipped.is_empty());
    assert!(!bare.records[2].fields.contains_key("Kind"));
}
