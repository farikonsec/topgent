//! Reading the parts of one Linux Audit record line.
//!
//! Every Audit reader needs the same four things from a line: the record id,
//! the time in it, a plain field and a quoted one. They were written out once
//! per reader; one copy is the only way they stay the same.

pub(crate) fn audit_id(line: &str) -> Option<&str> {
    line.split_once("msg=audit(")?
        .1
        .split_once("): ")
        .map(|(id, _)| id)
}

pub(crate) fn audit_time_ms(id: &str) -> Option<u64> {
    let timestamp = id.split_once(':')?.0;
    let (seconds, fraction) = timestamp.split_once('.').unwrap_or((timestamp, "0"));
    let seconds = seconds.parse::<u64>().ok()?;
    let mut milliseconds = fraction.chars().take(3).collect::<String>();
    while milliseconds.len() < 3 {
        milliseconds.push('0');
    }
    Some(
        seconds
            .saturating_mul(1_000)
            .saturating_add(milliseconds.parse::<u64>().ok()?),
    )
}

pub(crate) fn field<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    line.split_ascii_whitespace()
        .find_map(|part| part.strip_prefix(name)?.strip_prefix('='))
}

pub(crate) fn quoted_field(line: &str, name: &str) -> Option<String> {
    let marker = format!("{name}=\"");
    let rest = line.split_once(&marker)?.1;
    Some(rest[..rest.find('"')?].replace("\\x20", " "))
}
