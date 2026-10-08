//! The image cache adapter on the synthetic thumbnail caches and `.bmc`
//! file of `sootmark-imagecache` (`tests/fixtures/imagecache/synthetic/`)
//! and tesserae's generated `Cache0001.bin` (MIT,
//! `tests/fixtures/imagecache/tesserae/`, gzip-compressed): the contract,
//! recognition, records, and every index place followed to its entry.

use std::collections::HashMap;
use std::io::Read;

use conformance::assert_conforms;
use model::adapter::{Adapter, Collected, Confidence, Input};
use model::{EvidenceId, Record, TimeKind, Value};
use sootmark_adapters::imagecache::{
    ImageCacheAdapter, RDP_BITMAP_CACHE, RDP_BITMAP_CACHE_FILE, THUMBCACHE, THUMBCACHE_INDEX,
};

const EXPLORER: &str = r"C\Users\alice\AppData\Local\Microsoft\Windows\Explorer";
const RDP_CLIENT: &str = r"C\Users\bob\AppData\Local\Microsoft\Terminal Server Client\Cache";
const VERSIONS: [&str; 5] = ["vista", "windows7", "windows8", "windows81", "windows10"];

fn fixture(path: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/imagecache/{path}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn tesserae() -> Vec<u8> {
    let mut data = Vec::new();
    common::gzip::Decoder::new(fixture("tesserae/Cache0001.bin.gz").as_slice())
        .read_to_end(&mut data)
        .unwrap();
    data
}

/// The records of `data` read as the file at `path`, which the adapter
/// recognises and parses within the contract, without skipping anything.
fn parse(path: &str, data: &[u8]) -> Vec<Record> {
    assert_eq!(ImageCacheAdapter.probe(path, data), Confidence::Certain);
    assert_conforms(&ImageCacheAdapter, path, data);
    let input = Input {
        evidence: EvidenceId::of_content(data),
        name: path,
        data,
        modified: None,
    };
    let mut sink = Collected::default();
    ImageCacheAdapter.parse(&input, &mut sink).unwrap();
    assert!(sink.skipped.is_empty(), "{path}: {:?}", sink.skipped);
    sink.records
}

fn synthetic(version: &str, file: &str) -> Vec<Record> {
    let data = fixture(&format!("synthetic/thumbcache/{version}/{file}"));
    parse(&format!(r"{EXPLORER}\{file}"), &data)
}

fn text<'a>(record: &'a Record, name: &str) -> &'a str {
    match record.fields.get(name) {
        Some(Value::Text(text)) => text,
        other => panic!("{name}: {other:?}"),
    }
}

fn uint(record: &Record, name: &str) -> u64 {
    match record.fields.get(name) {
        Some(Value::UInt(n)) => *n,
        other => panic!("{name}: {other:?}"),
    }
}

fn byte_offset(record: &Record) -> u64 {
    match record.locator() {
        model::Locator::ByteOffset(offset) => *offset,
        other => panic!("{other:?}"),
    }
}

#[test]
fn every_cache_entry_a_record_without_times() {
    let mut entries = 0;
    for version in VERSIONS {
        for file in ["thumbcache_32.db", "thumbcache_256.db"] {
            let records = synthetic(version, file);
            assert_eq!(records.len(), 8, "{version}/{file}");
            for record in &records {
                assert_eq!(record.namespace(), THUMBCACHE);
                assert!(record.times.is_empty());
                assert_eq!(record.facets.user_name.as_deref(), Some("alice"));
                assert_eq!(text(record, "CacheId").len(), 16);
            }
            entries += records.len();
        }
    }
    entries += synthetic("windows10", "iconcache_16.db").len();
    assert_eq!(entries, 88);
}

#[test]
fn cache_entry_fields() {
    let vista = synthetic("vista", "thumbcache_32.db");
    let jpeg = &vista[2];
    assert_eq!(byte_offset(jpeg), 416);
    assert_eq!(text(jpeg, "CacheId"), "3333000000000003");
    assert_eq!(text(jpeg, "Extension"), "jpg");
    assert_eq!(text(jpeg, "ImageFormat"), "JPEG");
    assert_eq!(text(jpeg, "SizeName"), "32");
    assert_eq!(uint(jpeg, "Version"), 20);
    assert_eq!(uint(jpeg, "DataSize"), 672);
    // The 8x8 JPEG the generator stores, by its published SHA-256.
    assert_eq!(
        text(jpeg, "ImageSha256"),
        "68765b3e3b02ad4d6365c05927ee28f351bbd1834cce4925884d77780b65d8b8"
    );
    assert!(!jpeg.fields.contains_key("Width"));
    let empty = &vista[3];
    assert_eq!(
        text(empty, "Identifier"),
        "::{645FF040-5081-101B-9F08-00AA002F954E}"
    );
    assert_eq!(text(empty, "ImageFormat"), "None");
    assert!(!empty.fields.contains_key("ImageSha256"));

    let icons = synthetic("windows10", "iconcache_16.db");
    assert_eq!(text(&icons[0], "CacheId"), "1111000000000203");
    assert_eq!(
        (uint(&icons[1], "Width"), uint(&icons[1], "Height")),
        (5, 3)
    );
    assert!(icons[1].summary.starts_with("iconcache_16.db entry "));
}

#[test]
fn damaged_entries_flagged() {
    let records = synthetic("windows8", "thumbcache_256.db");
    let checks: Vec<(bool, bool, bool)> = records
        .iter()
        .map(|r| {
            let valid = |name: &str| r.fields.get(name) == Some(&Value::Bool(true));
            (
                valid("HeaderChecksumValid"),
                valid("DataChecksumValid"),
                r.flags.corrupted,
            )
        })
        .collect();
    let mut expected = vec![(true, true, false); 8];
    expected[6] = (true, false, true);
    expected[7] = (false, true, true);
    assert_eq!(checks, expected);
    assert!(records[6].summary.ends_with(", checksum mismatch"));
}

#[test]
fn every_index_place_holds_its_entry() {
    for version in VERSIONS {
        let index = synthetic(version, "thumbcache_idx.db");
        assert_eq!(index.len(), 8, "{version}");
        let mut caches: HashMap<String, Vec<Record>> = HashMap::new();
        let mut places = 0;
        for record in &index {
            assert_eq!(record.namespace(), THUMBCACHE_INDEX);
            let Some(Value::List(locations)) = record.fields.get("Locations") else {
                panic!("{version}: no Locations");
            };
            for location in locations {
                let Value::Text(location) = location else {
                    panic!("{location:?}");
                };
                let (file, offset) = location.split_once(':').unwrap();
                let entries = caches
                    .entry(file.to_owned())
                    .or_insert_with(|| synthetic(version, file));
                let entry = entries
                    .iter()
                    .find(|e| byte_offset(e) == offset.parse::<u64>().unwrap())
                    .unwrap_or_else(|| panic!("{version}: nothing at {location}"));
                assert_eq!(text(entry, "CacheId"), text(record, "CacheId"));
                places += 1;
            }
        }
        assert_eq!(places, 16, "{version}");
    }
}

#[test]
fn index_times_only_on_vista() {
    let vista = synthetic("vista", "thumbcache_idx.db");
    assert_eq!(vista[0].times[0].kind, TimeKind::Modified);
    assert_eq!(vista[0].times[0].field, "Modified");
    assert_eq!(text(&vista[0], "CacheId"), "1111000000000001");
    assert_eq!(uint(&vista[0], "Flags"), 134_250_498);
    assert!(synthetic("windows10", "thumbcache_idx.db")
        .iter()
        .all(|r| r.times.is_empty()));
}

#[test]
fn every_distinct_tile_a_record() {
    let records = parse(&format!(r"{RDP_CLIENT}\Cache0001.bin"), &tesserae());
    let (file, tiles) = records.split_first().unwrap();
    assert_eq!(file.namespace(), RDP_BITMAP_CACHE_FILE);
    assert_eq!(text(file, "Container"), "bin");
    assert_eq!((uint(file, "Tiles"), uint(file, "DistinctTiles")), (51, 51));
    assert_eq!(
        file.summary,
        "RDP bitmap cache Cache0001.bin: 51 tiles recovered, 51 distinct"
    );
    assert_eq!(file.facets.user_name.as_deref(), Some("bob"));
    assert_eq!(tiles.len(), 51);
    assert!(tiles
        .iter()
        .all(|t| t.namespace() == RDP_BITMAP_CACHE && t.times.is_empty()));
    // The first piece of the source image, as tesserae's truth file has it.
    let first = &tiles[0];
    assert_eq!(text(first, "Key"), "314a8e9659999450");
    assert_eq!(
        text(first, "PixelSha256"),
        "6624d0073a0d7fcad33565854b534c0e4bc58c8e90ae2d566adf23019e3d132b"
    );
    assert_eq!(uint(first, "BytesPerPixel"), 4);
}

#[test]
fn repeated_tiles_recorded_once() {
    let data = fixture("synthetic/rdp/bcache22.bmc");
    let records = parse(&format!(r"{RDP_CLIENT}\bcache22.bmc"), &data);
    let (file, tiles) = records.split_first().unwrap();
    assert_eq!((uint(file, "Tiles"), uint(file, "DistinctTiles")), (5, 4));
    assert_eq!(uint(file, "BytesPerPixel"), 2);
    let offsets: Vec<u64> = tiles.iter().map(byte_offset).collect();
    assert_eq!(offsets, [0, 8212, 16424, 24636]);
    assert_eq!(text(&tiles[2], "Key"), "2000000300000005");
    assert_eq!(tiles[2].fields.get("Compressed"), Some(&Value::Bool(true)));
}

#[test]
fn recognised_by_name_and_signature() {
    let cache = fixture("synthetic/thumbcache/windows10/thumbcache_256.db");
    let index = fixture("synthetic/thumbcache/windows10/thumbcache_idx.db");
    let bin = tesserae();
    for (path, head, expected) in [
        (
            format!(r"{EXPLORER}\thumbcache_256.db"),
            &index,
            Confidence::No,
        ),
        (
            format!(r"{EXPLORER}\thumbcache_idx.db"),
            &cache,
            Confidence::No,
        ),
        (format!(r"{EXPLORER}\thumbs.db"), &cache, Confidence::No),
        (r"C\Temp\Cache0001.bin".to_owned(), &bin, Confidence::No),
        (
            format!(r"{RDP_CLIENT}\Cache0001.bin"),
            &cache,
            Confidence::No,
        ),
        (
            format!(r"{RDP_CLIENT}\bcache24.bmc"),
            &vec![0; 64],
            Confidence::Maybe,
        ),
    ] {
        assert_eq!(ImageCacheAdapter.probe(&path, head), expected, "{path}");
    }
}
