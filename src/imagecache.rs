//! Windows image caches, via the `imagecache` parser: pictures a system
//! kept of what a user looked at.
//!
//! - Explorer's thumbnail and icon caches (`thumbcache_*.db`,
//!   `iconcache_*.db`, Vista to 11): one record per entry
//!   (`windows.thumbcache`), with its cache id (the
//!   `System_ThumbnailCacheId` Windows Search records for the file, so a
//!   thumbnail can be tied to a file even after the file is gone), size,
//!   image format, whether its checksums match and the image's SHA-256.
//!   And their index (`thumbcache_idx.db`, `iconcache_idx.db`): one record
//!   per entry in use (`windows.thumbcache_index`), with the cache files
//!   holding a thumbnail of it and, on Vista, when it was last modified.
//! - The Remote Desktop client's bitmap cache (`Cache????.bin`,
//!   `bcache*.bmc`, under `Terminal Server Client\Cache\`): one record per
//!   distinct tile (`windows.rdp_bitmap_cache`), with its key, size, depth
//!   and the SHA-256 of its pixels, and one per file
//!   (`windows.rdp_bitmap_cache_file`) telling how many tiles it held.
//!
//! Records keep no image bytes or pixels: the hashes tie a record to the
//! picture the parser extracts. Cache entries and tiles have no times of
//! their own, so their records have none. The account is the profile's
//! owner, from the path.

use common::sha256::{self, Sha256};
use imagecache::rdp::{self, BitmapCache, Container, Tile};
use imagecache::thumbcache::{self, Cache, Entry, ImageFormat, IndexEntry, Version};
use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};

use crate::home::profile_owner;

/// Records of thumbnail and icon cache entries.
pub const THUMBCACHE: Namespace = Namespace::new("windows.thumbcache");
/// Records of thumbnail and icon cache index entries.
pub const THUMBCACHE_INDEX: Namespace = Namespace::new("windows.thumbcache_index");
/// Records of RDP bitmap cache tiles.
pub const RDP_BITMAP_CACHE: Namespace = Namespace::new("windows.rdp_bitmap_cache");
/// Records of RDP bitmap cache files.
pub const RDP_BITMAP_CACHE_FILE: Namespace = Namespace::new("windows.rdp_bitmap_cache_file");

/// The folder the Remote Desktop client keeps its bitmap cache under.
const RDP_CLIENT_FOLDER: &str = "Terminal Server Client";
/// A tile's largest width and height.
const TILE_SIDE: u16 = 64;

/// One record per cache entry, index entry and distinct tile.
#[derive(Debug, Default, Clone, Copy)]
pub struct ImageCacheAdapter;

/// Which cache a file is, from its name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// `thumbcache_*.db`, `iconcache_*.db`.
    Cache,
    /// `thumbcache_idx.db`, `iconcache_idx.db`.
    Index,
    /// `Cache????.bin`.
    Bin,
    /// `bcache*.bmc`.
    Bmc,
}

impl Adapter for ImageCacheAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "imagecache",
            version: imagecache::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[
            THUMBCACHE,
            THUMBCACHE_INDEX,
            RDP_BITMAP_CACHE,
            RDP_BITMAP_CACHE_FILE,
        ]
    }

    /// By name and signature: a cache's `CMMM`, an index's `IMMM`, a
    /// `.bin` file's `RDP8bmp` in a `Terminal Server Client` folder. A
    /// `.bmc` file there has no signature: certain when it starts with a
    /// tile header, maybe otherwise (its first slot may be empty).
    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        let certain = match kind(name) {
            Some(Kind::Cache) => thumbcache::is_cache(head),
            Some(Kind::Index) => thumbcache::is_index(head),
            Some(Kind::Bin) => rdp::is_bin(head),
            Some(Kind::Bmc) if starts_with_tile(head) => true,
            Some(Kind::Bmc) => return Confidence::Maybe,
            None => false,
        };
        if certain {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        match kind(input.name) {
            Some(Kind::Cache) => self.cache(input, sink),
            Some(Kind::Index) => self.index(input, sink),
            Some(Kind::Bin) => self.bitmaps(input, &rdp::read_bin(input.data), sink),
            Some(Kind::Bmc) => {
                let depth = rdp::depth_from_file_name(input.name);
                self.bitmaps(input, &rdp::read_bmc(input.data, depth), sink)
            }
            None => Err(ParseError::at(
                0,
                "not a thumbnail, icon or RDP bitmap cache",
            )),
        }
    }
}

impl ImageCacheAdapter {
    fn cache(self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let cache = thumbcache::read(input.data);
        let Some(version) = cache.version else {
            return Err(unreadable(&cache.problems));
        };
        report(sink, &cache.problems);
        for entry in &cache.entries {
            sink.record(self.entry(input, &cache, version, entry));
        }
        Ok(())
    }

    fn entry(
        self,
        input: &Input<'_>,
        cache: &Cache<'_>,
        version: Version,
        entry: &Entry<'_>,
    ) -> Record {
        let mut record = self.record(input, THUMBCACHE, entry.offset);
        let checksums_valid = entry.data_checksum_valid && entry.header_checksum_valid;
        record.flags.corrupted = !checksums_valid;
        let mut fields = Fields::new();
        let cache_id = entry.cache_id();
        text(&mut fields, "CacheId", Some(&cache_id));
        fields.insert("Version".into(), Value::UInt(u64::from(version.number())));
        fields.insert("CacheType".into(), Value::UInt(u64::from(cache.cache_type)));
        text(&mut fields, "SizeName", cache.size_name());
        text(&mut fields, "Extension", entry.extension.as_deref());
        text(&mut fields, "Identifier", Some(&entry.identifier));
        for (name, side) in [("Width", entry.width), ("Height", entry.height)] {
            if let Some(side) = side {
                fields.insert(name.into(), Value::UInt(u64::from(side)));
            }
        }
        fields.insert("DataSize".into(), Value::UInt(entry.data.len() as u64));
        text(&mut fields, "ImageFormat", Some(format_name(entry.format)));
        fields.insert(
            "DataChecksumValid".into(),
            Value::Bool(entry.data_checksum_valid),
        );
        fields.insert(
            "HeaderChecksumValid".into(),
            Value::Bool(entry.header_checksum_valid),
        );
        if !entry.data.is_empty() {
            text(&mut fields, "ImageSha256", Some(&sha256_hex(entry.data)));
        }
        record.fields = fields;
        let picture = match (entry.format, entry.width.zip(entry.height)) {
            (ImageFormat::Empty, _) => "no thumbnail".to_owned(),
            (format, Some((width, height))) => format!(
                "{} {width}x{height}, {} bytes",
                format_name(format),
                entry.data.len()
            ),
            (format, None) => format!("{}, {} bytes", format_name(format), entry.data.len()),
        };
        record.summary = format!(
            "{} entry {cache_id}: {picture}{}",
            file_name(input.name),
            if checksums_valid {
                ""
            } else {
                ", checksum mismatch"
            }
        );
        record
    }

    fn index(self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let index = thumbcache::read_index(input.data);
        let Some(version) = index.version else {
            return Err(unreadable(&index.problems));
        };
        report(sink, &index.problems);
        for entry in &index.entries {
            sink.record(self.index_entry(input, version, entry));
        }
        Ok(())
    }

    fn index_entry(self, input: &Input<'_>, version: Version, entry: &IndexEntry) -> Record {
        let mut record = self.record(input, THUMBCACHE_INDEX, entry.offset);
        if let Some(modified) = entry.modified {
            record
                .times
                .push(RecordTime::new(TimeKind::Modified, "Modified", modified));
        }
        // The cache files beside the index share its name up to `idx.db`.
        let base = file_name(input.name);
        let prefix = base
            .get(..base.len().saturating_sub("idx.db".len()))
            .unwrap_or_default();
        let size_names: Vec<String> = entry
            .locations
            .iter()
            .map(|location| {
                location
                    .size_name
                    .map_or_else(|| location.cache_type.to_string(), str::to_owned)
            })
            .collect();
        let locations = size_names
            .iter()
            .zip(&entry.locations)
            .map(|(size, location)| Value::from(format!("{prefix}{size}.db:{}", location.offset)))
            .collect();
        let mut fields = Fields::new();
        let hash = entry.cache_id();
        text(&mut fields, "CacheId", Some(&hash));
        fields.insert("Version".into(), Value::UInt(u64::from(version.number())));
        fields.insert("Flags".into(), Value::UInt(u64::from(entry.flags)));
        fields.insert("Locations".into(), Value::List(locations));
        record.fields = fields;
        record.summary = format!(
            "{base} entry {hash}: {}",
            if size_names.is_empty() {
                "in no cache file".to_owned()
            } else {
                format!("in {}", size_names.join(", "))
            }
        );
        record
    }

    fn bitmaps(
        self,
        input: &Input<'_>,
        cache: &BitmapCache,
        sink: &mut dyn Sink,
    ) -> Result<(), ParseError> {
        let Some(container) = cache.container else {
            return Err(unreadable(&cache.problems));
        };
        report(sink, &cache.problems);
        let tiles = rdp::distinct(&cache.tiles);
        sink.record(self.bitmap_file(input, cache, container, tiles.len()));
        for tile in tiles {
            sink.record(self.tile(input, tile));
        }
        Ok(())
    }

    fn bitmap_file(
        self,
        input: &Input<'_>,
        cache: &BitmapCache,
        container: Container,
        distinct: usize,
    ) -> Record {
        let mut record = self.record(input, RDP_BITMAP_CACHE_FILE, 0);
        let mut fields = Fields::new();
        let container = match container {
            Container::Bin => "bin",
            Container::Bmc => "bmc",
        };
        text(&mut fields, "Container", Some(container));
        if let Some(version) = cache.version {
            fields.insert("Version".into(), Value::UInt(u64::from(version)));
        }
        if let Some(depth) = cache.bytes_per_pixel {
            fields.insert("BytesPerPixel".into(), Value::UInt(u64::from(depth)));
        }
        fields.insert("Tiles".into(), Value::UInt(cache.tiles.len() as u64));
        fields.insert("DistinctTiles".into(), Value::UInt(distinct as u64));
        record.fields = fields;
        record.summary = format!(
            "RDP bitmap cache {}: {} tiles recovered, {distinct} distinct",
            file_name(input.name),
            cache.tiles.len()
        );
        record
    }

    fn tile(self, input: &Input<'_>, tile: &Tile) -> Record {
        let mut record = self.record(input, RDP_BITMAP_CACHE, tile.offset);
        let mut fields = Fields::new();
        let key = format!("{:016x}", tile.key);
        text(&mut fields, "Key", Some(&key));
        fields.insert("Width".into(), Value::UInt(u64::from(tile.width)));
        fields.insert("Height".into(), Value::UInt(u64::from(tile.height)));
        fields.insert(
            "BytesPerPixel".into(),
            Value::UInt(u64::from(tile.bytes_per_pixel)),
        );
        fields.insert("Compressed".into(), Value::Bool(tile.compressed));
        text(&mut fields, "PixelSha256", Some(&sha256_hex(&tile.pixels)));
        record.fields = fields;
        record.summary = format!(
            "RDP bitmap tile {key}: {}x{}, {}-bit{}",
            tile.width,
            tile.height,
            u32::from(tile.bytes_per_pixel) * 8,
            if tile.compressed { ", compressed" } else { "" }
        );
        record
    }

    /// A record of the entry at `offset`, the account and file as facets.
    fn record(self, input: &Input<'_>, namespace: Namespace, offset: usize) -> Record {
        let mut record = Record::new(
            input.evidence,
            namespace,
            Locator::ByteOffset(offset as u64),
            self.parser(),
        );
        record.facets = Facets {
            user_name: profile_owner(input.name),
            file_path: Some(input.name.to_owned()),
            ..Facets::default()
        };
        record
    }
}

/// Which cache `path` names: thumbnail and icon caches anywhere, bitmap
/// caches only in a `Terminal Server Client` folder.
fn kind(path: &str) -> Option<Kind> {
    let name = file_name(path).to_ascii_lowercase();
    let (stem, extension) = name.rsplit_once('.')?;
    let in_client_folder = path
        .split(['/', '\\'])
        .any(|folder| folder.eq_ignore_ascii_case(RDP_CLIENT_FOLDER));
    match extension {
        "db" if ["thumbcache_", "iconcache_"]
            .iter()
            .any(|prefix| stem.starts_with(prefix)) =>
        {
            Some(if stem.ends_with("_idx") {
                Kind::Index
            } else {
                Kind::Cache
            })
        }
        "bin" if in_client_folder && is_bin_stem(stem) => Some(Kind::Bin),
        "bmc" if in_client_folder && stem.starts_with("bcache") => Some(Kind::Bmc),
        _ => None,
    }
}

/// Whether a lowercase file name without its extension is `cache` and
/// four digits.
fn is_bin_stem(stem: &str) -> bool {
    stem.strip_prefix("cache")
        .is_some_and(|number| number.len() == 4 && number.bytes().all(|b| b.is_ascii_digit()))
}

/// Whether `head` starts with a `.bmc` tile header: a width and height of
/// 1 to 64 pixels after the 64-bit key.
fn starts_with_tile(head: &[u8]) -> bool {
    let side = |at: usize| {
        head.get(at..at + 2)
            .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
    };
    let sides = 1..=TILE_SIDE;
    side(8).is_some_and(|width| sides.contains(&width))
        && side(10).is_some_and(|height| sides.contains(&height))
}

/// The last component of a path, `/` or `\` separated.
fn file_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

fn format_name(format: ImageFormat) -> &'static str {
    match format {
        ImageFormat::Bmp => "BMP",
        ImageFormat::Jpeg => "JPEG",
        ImageFormat::Png => "PNG",
        ImageFormat::Other => "Other",
        ImageFormat::Empty => "None",
    }
}

fn sha256_hex(data: &[u8]) -> String {
    sha256::hex(&Sha256::digest(data))
}

/// The file as a whole couldn't be read: why.
fn unreadable(problems: &[String]) -> ParseError {
    ParseError::at(0, problems.join("; "))
}

fn report(sink: &mut dyn Sink, problems: &[String]) {
    for reason in problems {
        sink.skipped(Skipped {
            locator: Locator::ByteOffset(0),
            reason: reason.clone(),
        });
    }
}

fn text(fields: &mut Fields, name: &str, value: Option<&str>) {
    if let Some(value) = value.filter(|v| !v.trim().is_empty()) {
        fields.insert(name.into(), Value::from(value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_from_names() {
        let explorer = r"C\Users\alice\AppData\Local\Microsoft\Windows\Explorer";
        assert_eq!(
            kind(&format!(r"{explorer}\thumbcache_256.db")),
            Some(Kind::Cache)
        );
        assert_eq!(
            kind(&format!(r"{explorer}\iconcache_16.db")),
            Some(Kind::Cache)
        );
        assert_eq!(
            kind(&format!(r"{explorer}\thumbcache_idx.db")),
            Some(Kind::Index)
        );
        assert_eq!(kind("ICONCACHE_IDX.DB"), Some(Kind::Index));
        assert_eq!(kind("thumbcache_256.db-journal"), None);

        let client = r"C\Users\bob\AppData\Local\Microsoft\Terminal Server Client\Cache";
        assert_eq!(kind(&format!(r"{client}\Cache0001.bin")), Some(Kind::Bin));
        assert_eq!(kind(&format!(r"{client}\bcache22.bmc")), Some(Kind::Bmc));
        assert_eq!(kind(&format!(r"{client}\Cache01.bin")), None);
        assert_eq!(kind(&format!(r"{client}\CacheABCD.bin")), None);
        assert_eq!(kind(r"C\Temp\Cache0001.bin"), None);
        assert_eq!(kind("bcache22.bmc"), None);
    }

    #[test]
    fn bmc_tile_headers() {
        let header = [1, 0, 0, 0, 2, 0, 0, 0, 64, 0, 32, 0];
        assert!(starts_with_tile(&header));
        assert!(!starts_with_tile(&[0; 20]));
        assert!(!starts_with_tile(&[0, 0, 0, 0, 0, 0, 0, 0, 65, 0, 1, 0]));
        assert!(!starts_with_tile(&header[..11]));
    }
}
