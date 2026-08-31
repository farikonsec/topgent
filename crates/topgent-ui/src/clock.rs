//! Turning a millisecond stamp into something a reader can compare.
//!
//! No date library. The report carries Unix milliseconds and every table wants
//! the same fixed-width local time, which is arithmetic, not a dependency. A
//! date crate here would be a third-party surface added to a security tool to
//! format six characters.

/// Local wall-clock time as `HH:MM:SS`.
///
/// The date is deliberately absent: every row in these tables comes from the
/// current session, and a repeated date in every row is a column of noise. A
/// stamp from before today shows its day instead, so a row that is older than
/// it looks cannot pass as recent.
#[must_use]
pub fn stamp(at_ms: u64) -> String {
    let (days, seconds) = split(at_ms);
    let today = split(now_ms()).0;
    let (h, m, sec) = (seconds / 3600, (seconds % 3600) / 60, seconds % 60);
    if days == today {
        format!("{h:02}:{m:02}:{sec:02}")
    } else {
        let (_, month, day) = civil(days);
        format!("{day:02}/{month:02} {h:02}:{m:02}")
    }
}

/// Whole days since the epoch, and seconds into the local day.
fn split(at_ms: u64) -> (i64, u64) {
    let local = i64::try_from(at_ms / 1000).unwrap_or(0) + offset_seconds();
    let local = local.max(0);
    (local / 86_400, u64::try_from(local % 86_400).unwrap_or(0))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Seconds between this machine's local time and UTC.
///
/// Taken from the platform rather than assumed, and zero if the platform will
/// not say. A wrong offset shifts every stamp by hours, which is worse than an
/// obviously UTC one.
#[cfg(unix)]
fn offset_seconds() -> i64 {
    // SAFETY-free path: ask the shell's own formatter once per process.
    static OFFSET: std::sync::OnceLock<i64> = std::sync::OnceLock::new();
    *OFFSET.get_or_init(|| {
        std::process::Command::new("date")
            .arg("+%z")
            .output()
            .ok()
            .and_then(|out| String::from_utf8(out.stdout).ok())
            .and_then(|raw| parse_offset(raw.trim()))
            .unwrap_or(0)
    })
}

#[cfg(not(unix))]
fn offset_seconds() -> i64 {
    static OFFSET: std::sync::OnceLock<i64> = std::sync::OnceLock::new();
    *OFFSET.get_or_init(|| {
        std::process::Command::new("cmd")
            .args([
                "/C",
                "powershell -NoProfile -Command \"(Get-Date -UFormat %Z)\"",
            ])
            .output()
            .ok()
            .and_then(|out| String::from_utf8(out.stdout).ok())
            .and_then(|raw| raw.trim().parse::<i64>().ok())
            .map_or(0, |hours| hours * 3600)
    })
}

/// `+0100` and `-0530` into seconds.
///
/// Unix only: Windows reads its offset as a whole number of hours from
/// PowerShell and never sees this form. The Windows build reported it as dead
/// code, which it is there.
#[cfg(unix)]
fn parse_offset(raw: &str) -> Option<i64> {
    let sign = match raw.chars().next()? {
        '+' => 1,
        '-' => -1,
        _ => return None,
    };
    let digits = &raw[1..];
    if digits.len() != 4 || !digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let hours: i64 = digits[..2].parse().ok()?;
    let minutes: i64 = digits[2..].parse().ok()?;
    Some(sign * (hours * 3600 + minutes * 60))
}

/// Days since the epoch into year, month, day. Howard Hinnant's civil-from-days.
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1);
    let m = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1);
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stamp_from_today_is_a_time_and_nothing_else() {
        let now = now_ms();
        let shown = stamp(now);
        assert_eq!(shown.len(), 8, "{shown} is not HH:MM:SS");
        assert_eq!(shown.matches(':').count(), 2);
    }

    #[test]
    fn a_stamp_from_last_week_carries_its_day_so_it_cannot_pass_as_recent() {
        let week = now_ms().saturating_sub(7 * 86_400 * 1000);
        let shown = stamp(week);
        assert!(shown.contains('/'), "{shown} looks like it happened today");
    }

    #[cfg(unix)]
    #[test]
    fn offsets_parse_in_both_directions_and_with_half_hours() {
        assert_eq!(parse_offset("+0100"), Some(3600));
        assert_eq!(parse_offset("-0530"), Some(-19_800));
        assert_eq!(parse_offset("+0000"), Some(0));
        assert_eq!(parse_offset("BST"), None);
        assert_eq!(parse_offset("+01"), None);
    }

    #[test]
    fn the_civil_calendar_agrees_with_known_dates() {
        assert_eq!(civil(0), (1970, 1, 1));
        assert_eq!(civil(19_723), (2024, 1, 1));
        // A leap day, which is where a hand-written calendar goes wrong.
        assert_eq!(civil(19_782), (2024, 2, 29));
        assert_eq!(civil(19_783), (2024, 3, 1));
    }

    #[test]
    fn a_zero_stamp_does_not_panic_or_wrap() {
        let _ = stamp(0);
    }
}
