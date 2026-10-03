//! Timestamps as tools write them in text: `YYYY-MM-DD HH:MM:SS[.f]`
//! (space or `T`), with a zone (`Z`, `±HH:MM`) or, for tools documented to
//! write UTC, without one.

use common::time::{days_from_civil, Precision, Ts};

/// A timestamp that carries its zone: `… ±HH:MM`, `…±HH:MM` or `…Z`.
pub fn zoned(text: &str) -> Option<Ts> {
    let text = text.trim();
    if let Some(utc) = text.strip_suffix('Z') {
        return clock(utc, 0);
    }
    let at = text.len().checked_sub(6)?;
    let (clock_text, zone) = text.split_at(at);
    let sign = match zone.as_bytes().first()? {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let (hours, minutes) = zone[1..].split_once(':')?;
    let minutes = number(hours, 2)? * 60 + number(minutes, 2)?;
    clock(clock_text.trim_end(), sign * minutes as i64)
}

/// A timestamp without a zone from a tool that writes UTC. `None` for text
/// that isn't one, and for .NET's "no date" (`0001-01-01 00:00:00`).
pub fn utc(text: &str) -> Option<Ts> {
    let text = text.trim();
    if text.starts_with("0001-01-01") {
        return None;
    }
    clock(text, 0)
}

/// `YYYY-MM-DD HH:MM:SS[.f]` at `offset_minutes` east of UTC.
fn clock(text: &str, offset_minutes: i64) -> Option<Ts> {
    let (date, time) = text.split_once([' ', 'T'])?;
    let mut date_parts = date.split('-');
    let year = number(date_parts.next()?, 4)?;
    let month = number(date_parts.next()?, 2)?;
    let day = number(date_parts.next()?, 2)?;
    if date_parts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let (hms, fraction) = time.split_once('.').unwrap_or((time, ""));
    let mut hms_parts = hms.split(':');
    let (h, m, s) = (
        number(hms_parts.next()?, 2)?,
        number(hms_parts.next()?, 2)?,
        number(hms_parts.next()?, 2)?,
    );
    if hms_parts.next().is_some() || h > 23 || m > 59 || s > 60 {
        return None;
    }
    // Up to nanoseconds (Velociraptor, Go); ticks keep the first seven digits.
    if fraction.len() > 9 || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let fraction = &fraction[..fraction.len().min(7)];
    let precision = match fraction.len() {
        0 => Precision::Second,
        1..=3 => Precision::Millisecond,
        4..=6 => Precision::Microsecond,
        _ => Precision::Tick,
    };
    let ticks_fraction = format!("{fraction:0<7}").parse::<i64>().ok()?;
    let days = days_from_civil(year as i64, month as u32, day as u32);
    let seconds = days * 86_400 + (h * 3_600 + m * 60 + s) as i64 - offset_minutes * 60;
    Some(Ts::from_ticks(
        seconds * 10_000_000 + ticks_fraction,
        precision,
    ))
}

/// Exactly `width` ASCII digits.
fn number(text: &str, width: usize) -> Option<u64> {
    (text.len() == width && text.bytes().all(|b| b.is_ascii_digit())).then(|| text.parse().ok())?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iso(ts: Option<Ts>) -> Option<String> {
        ts.and_then(|ts| ts.to_iso8601())
    }

    #[test]
    fn reads_zoned_timestamps_exactly() {
        assert_eq!(
            iso(zoned("2020-04-03 04:12:06.968 +02:00")).as_deref(),
            Some("2020-04-03T02:12:06.9680000Z")
        );
        assert_eq!(
            iso(zoned("2020-04-03 02:12:06.968 +00:00")).as_deref(),
            Some("2020-04-03T02:12:06.9680000Z")
        );
        assert_eq!(
            iso(zoned("2020-04-03T02:12:06.968687Z")).as_deref(),
            Some("2020-04-03T02:12:06.9686870Z")
        );
        assert_eq!(
            iso(zoned("2022-02-22 22:00:00.123456-06:00")).as_deref(),
            Some("2022-02-23T04:00:00.1234560Z")
        );
        assert_eq!(
            iso(zoned("2020-01-01 00:30:00 +05:45")).as_deref(),
            Some("2019-12-31T18:45:00.0000000Z")
        );
    }

    #[test]
    fn refuses_ambiguous_formats() {
        for text in [
            "22-02-2022 22:00:00.123 +02:00",
            "02-22-2022 10:00:00.123 PM -06:00",
            "Fri, 22 Feb 2022 22:00:00 -0600",
            "2020-04-03 04:12:06.968",
            "2020-13-03 04:12:06 +02:00",
        ] {
            assert_eq!(zoned(text), None, "{text}");
        }
    }

    #[test]
    fn keeps_nanoseconds_to_the_tick() {
        assert_eq!(
            iso(zoned("2026-09-29T08:10:13.591056651Z")).as_deref(),
            Some("2026-09-29T08:10:13.5910566Z")
        );
        assert_eq!(zoned("2026-09-29T08:10:13.5910566511Z"), None);
    }

    #[test]
    fn reads_utc_without_a_zone() {
        assert_eq!(
            iso(utc("2026-08-05 09:12:44.0000000")).as_deref(),
            Some("2026-08-05T09:12:44.0000000Z")
        );
        assert_eq!(
            iso(utc("2026-09-14 10:53:12")).as_deref(),
            Some("2026-09-14T10:53:12.0000000Z")
        );
        assert_eq!(utc("0001-01-01 00:00:00"), None);
        assert_eq!(utc(""), None);
        assert_eq!(utc("09/14/2026 10:53:12"), None);
    }
}
