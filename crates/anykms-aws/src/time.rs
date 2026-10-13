//! UTC calendar arithmetic for SigV4 timestamps and credential expirations (no date crate).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Days since 1970-01-01 → (year, month, day) (Howard Hinnant's `civil_from_days`).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// (year, month, day) → days since 1970-01-01 (`days_from_civil`).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = i64::from(m);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Seconds since the epoch, saturating at zero for times before it.
fn epoch_secs(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// `YYYYMMDDTHHMMSSZ` (the SigV4 `X-Amz-Date`).
pub(crate) fn amz_date(t: SystemTime) -> String {
    let s = epoch_secs(t);
    let (y, mo, d) = civil_from_days(s.div_euclid(86_400));
    let sod = s.rem_euclid(86_400);
    format!(
        "{y:04}{mo:02}{d:02}T{:02}{:02}{:02}Z",
        sod / 3600,
        sod % 3600 / 60,
        sod % 60
    )
}

/// Parses an RFC 3339 UTC timestamp as AWS credential sources write them:
/// `YYYY-MM-DDTHH:MM:SS[.fraction](Z|+00:00|±HH:MM)`. `None` if malformed.
pub(crate) fn parse_rfc3339(s: &str) -> Option<SystemTime> {
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't' | b' ') {
        return None;
    }
    if b[13] != b':' || b[16] != b':' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<u32> {
        let p = s.get(r)?;
        if !p.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        p.parse().ok()
    };
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    let mut rest = &s[19..];
    if let Some(frac) = rest.strip_prefix('.') {
        let n = frac.bytes().take_while(u8::is_ascii_digit).count();
        if n == 0 {
            return None;
        }
        rest = &frac[n..];
    }
    let offset: i64 = match rest {
        "Z" | "z" => 0,
        _ => {
            let rb = rest.as_bytes();
            if rb.len() != 6 || !matches!(rb[0], b'+' | b'-') || rb[3] != b':' {
                return None;
            }
            let oh: i64 = rest.get(1..3)?.parse().ok()?;
            let om: i64 = rest.get(4..6)?.parse().ok()?;
            let o = oh * 3600 + om * 60;
            if rb[0] == b'+' { o } else { -o }
        }
    };
    let secs = days_from_civil(i64::from(y), mo, d) * 86_400
        + i64::from(h) * 3600
        + i64::from(mi) * 60
        + i64::from(sec)
        - offset;
    let secs = u64::try_from(secs).ok()?;
    UNIX_EPOCH.checked_add(Duration::from_secs(secs))
}

/// Seconds since the epoch (possibly fractional, as KMS sends `CreationDate`) as whole seconds.
pub(crate) fn epoch_number(v: f64) -> Option<u64> {
    (0.0..1e15).contains(&v).then_some(v as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_amz_dates() {
        let t = UNIX_EPOCH + Duration::from_secs(1_440_938_160);
        assert_eq!(amz_date(t), "20150830T123600Z");
        assert_eq!(amz_date(UNIX_EPOCH), "19700101T000000Z");
        // A leap day.
        let t = UNIX_EPOCH + Duration::from_secs(951_782_400);
        assert_eq!(amz_date(t), "20000229T000000Z");
    }

    #[test]
    fn parses_rfc3339() {
        let t = UNIX_EPOCH + Duration::from_secs(1_440_938_160);
        assert_eq!(parse_rfc3339("2015-08-30T12:36:00Z"), Some(t));
        assert_eq!(parse_rfc3339("2015-08-30T12:36:00.123Z"), Some(t));
        assert_eq!(parse_rfc3339("2015-08-30T14:36:00+02:00"), Some(t));
        assert_eq!(parse_rfc3339("2015-08-30T10:36:00-02:00"), Some(t));
        for bad in [
            "",
            "2015-08-30",
            "2015-08-30T12:36:00",
            "2015-13-30T12:36:00Z",
            "2015-08-30T25:36:00Z",
            "2015-08-30T12:36:00.Z",
            "2015-08-30T12:36:00+0200",
            "1969-12-31T23:59:59Z",
            "+015-08-30T12:36:00Z",
        ] {
            assert_eq!(parse_rfc3339(bad), None, "{bad}");
        }
        // Round trip over many days.
        for days in (0..30_000).step_by(37) {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
    }

    #[test]
    fn epoch_numbers() {
        assert_eq!(epoch_number(1.5e9), Some(1_500_000_000));
        assert_eq!(epoch_number(-1.0), None);
        assert_eq!(epoch_number(f64::NAN), None);
    }
}
