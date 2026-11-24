//! What each comparison operator means for one value.

use super::glob::glob;
use super::net;
use crate::lang::{Item, Op, Operand};

/// Whether a field's value satisfies `op` against `value`. `text` and `bytes`
/// are the same value; the byte operators read `bytes`.
pub(super) fn compare(field: &str, text: &str, bytes: &[u8], op: Op, value: &Operand) -> bool {
    let items: &[Item] = match value {
        Operand::One(item) => std::slice::from_ref(item),
        Operand::Set(items) => items,
    };
    if net::is_network_field(field)
        && let Some(inside) = net::compare(text, op, items)
    {
        return inside;
    }
    let actual = text;
    match op {
        Op::In => items.iter().any(|item| equal(actual, item.text())),
        Op::Intersects => {
            // A list-valued field arrives space-separated.
            actual
                .split_whitespace()
                .any(|element| items.iter().any(|item| item.text() == element))
        }
        Op::PMatch => items.iter().any(|item| under(actual, item.text())),
        _ => match items {
            [item] => single(actual, bytes, op, item.text()),
            _ => false,
        },
    }
}

fn single(actual: &str, bytes: &[u8], op: Op, expected: &str) -> bool {
    match op {
        Op::Eq => equal(actual, expected),
        Op::Ne => !equal(actual, expected),
        Op::Lt => numbers(actual, expected).is_some_and(|(a, b)| a < b),
        Op::Le => numbers(actual, expected).is_some_and(|(a, b)| a <= b),
        Op::Gt => numbers(actual, expected).is_some_and(|(a, b)| a > b),
        Op::Ge => numbers(actual, expected).is_some_and(|(a, b)| a >= b),
        Op::Contains => actual.contains(expected),
        Op::IContains => actual.to_lowercase().contains(&expected.to_lowercase()),
        Op::StartsWith => actual.starts_with(expected),
        Op::EndsWith => actual.ends_with(expected),
        Op::Glob => glob(expected, actual),
        Op::BContains => hex(expected).is_some_and(|needle| {
            !needle.is_empty()
                && bytes
                    .windows(needle.len())
                    .any(|window| window == needle.as_slice())
        }),
        Op::BStartsWith => hex(expected).is_some_and(|needle| bytes.starts_with(&needle)),
        Op::In | Op::Intersects | Op::PMatch => false,
    }
}

/// Equal as numbers when both are numbers, otherwise as text.
fn equal(actual: &str, expected: &str) -> bool {
    numbers(actual, expected).map_or(actual == expected, |(a, b)| a == b)
}

fn numbers(actual: &str, expected: &str) -> Option<(i128, i128)> {
    Some((actual.trim().parse().ok()?, expected.trim().parse().ok()?))
}

/// `path` is `prefix`, or lies under it.
fn under(path: &str, prefix: &str) -> bool {
    if prefix.is_empty() {
        return false;
    }
    if prefix.ends_with('/') {
        return path.starts_with(prefix);
    }
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok())
        .collect()
}
