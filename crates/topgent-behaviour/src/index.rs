//! Which event types a rule can fire on, worked out from its condition.
//!
//! Most rules name the calls they react to (`evt.type in (open, openat)`),
//! and evaluating one against any other call can only give not-true. Sorting
//! rules by those types before evaluating means an `openat` meets the
//! twenty rules about files, not all eighty. The answer is conservative: a
//! rule gets a set only when every way its condition could hold requires the
//! type to be in it, and otherwise may fire on anything.

use std::collections::BTreeSet;

use crate::lang::{Expr, Item, Op, Operand};

/// The event types `expr` can be true for, or `None` when it could be true
/// for any. A rule whose set misses an event's type is not true for it.
#[must_use]
pub fn event_types(expr: &Expr) -> Option<BTreeSet<String>> {
    match expr {
        Expr::Compare { field, op, value } if field.name == "evt.type" && field.arg.is_none() => {
            match (op, value) {
                (Op::Eq, Operand::One(item)) => Some(BTreeSet::from([text(item)])),
                (Op::In, Operand::Set(items)) => Some(items.iter().map(text).collect()),
                _ => None,
            }
        }
        // True only if every part is: the type must be in each part's set.
        Expr::And(parts) => parts
            .iter()
            .filter_map(event_types)
            .reduce(|a, b| a.intersection(&b).cloned().collect()),
        // True if any part is: every part must name its types.
        Expr::Or(parts) => parts
            .iter()
            .map(event_types)
            .collect::<Option<Vec<_>>>()
            .map(|sets| sets.into_iter().flatten().collect()),
        _ => None,
    }
}

fn text(item: &Item) -> String {
    match item {
        Item::Quoted(value) | Item::Bare(value) => value.clone(),
    }
}
