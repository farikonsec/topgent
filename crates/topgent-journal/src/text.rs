//! Turning untrusted text into something safe to keep.
//!
//! Records are read back by the interface, the exports and other people's
//! tools, and much of the text in them originates outside Topgent: process
//! names, log lines, an agent's own claims about itself. Every string that
//! reaches a record passes through here first, so control characters,
//! direction overrides and unbounded input cannot travel with it.

pub(crate) fn sanitize(input: &str, max: usize) -> String {
    let collapsed = input
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let mut redact_next = false;
    let mut words = collapsed
        .split(' ')
        .map(|word| {
            let lower = word.to_ascii_lowercase();
            let secretish = redact_next
                || lower.starts_with("sk-")
                || lower.starts_with("ghp_")
                || lower.contains("password=")
                || lower.contains("token=")
                || lower.contains("secret=")
                || word.starts_with('/')
                || word.starts_with("~/");
            redact_next = lower == "bearer";
            if secretish { "[REDACTED]" } else { word }
        })
        .collect::<Vec<_>>()
        .join(" ");
    if words.chars().count() > max {
        words = words.chars().take(max.saturating_sub(1)).collect();
        words.push('…');
    }
    words
}
pub(crate) fn bounded_metadata(input: &str, max: usize) -> String {
    let mut value = input
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if value.chars().count() > max {
        value = value.chars().take(max.saturating_sub(1)).collect();
        value.push('…');
    }
    value
}
