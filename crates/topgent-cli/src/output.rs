//! Small shared pieces: argument lookup, timestamps and exit codes.
//!
//! Exit codes are part of the CLI's contract with CI, so they are produced in
//! one place rather than returned ad hoc from each command.

pub(crate) fn option_value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|argument| argument == name)
        .and_then(|index| args.get(index + 1))
        .map(String::as_str)
}

pub(crate) fn print_result(value: &serde_json::Value) -> i32 {
    let ok = value.get("ok") == Some(&serde_json::Value::Bool(true));
    println!("{value}");
    i32::from(!ok)
}

/// A short relative timestamp.
pub(crate) fn stamp(at: u64) -> String {
    let secs = now_ms().saturating_sub(at) / 1000;
    if secs < 60 {
        format!("{secs}s ago")
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86_400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86_400)
    }
}

/// Milliseconds since the epoch.
pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}
