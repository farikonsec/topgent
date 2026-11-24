//! Numbers in the words a card uses: `313 MB`, `42,411`, `3 minutes`.

/// Human byte counts: `313 MB`, `4.2 KB`.
pub(crate) fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["bytes", "KB", "MB", "GB", "TB"];
    #[allow(clippy::cast_precision_loss)]
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1000.0 && unit + 1 < UNITS.len() {
        value /= 1000.0;
        unit += 1;
    }
    let label = UNITS.get(unit).copied().unwrap_or("bytes");
    if unit == 0 {
        format!("{n} {label}")
    } else if value >= 100.0 {
        format!("{value:.0} {label}")
    } else {
        format!("{value:.1} {label}")
    }
}

/// `42,411`.
pub(crate) fn count(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

pub(crate) fn duration(ms: u64) -> String {
    let secs = ms / 1_000;
    match secs {
        0 => format!("{ms} ms"),
        1..=119 => format!("{secs} seconds"),
        120..=7_199 => format!("{} minutes", secs / 60),
        _ => format!("{} hours", secs / 3_600),
    }
}

pub(super) fn plural(n: u64, one: &str, many: &str) -> String {
    format!("{} {}", count(n), if n == 1 { one } else { many })
}
