//! Three-valued evaluation of a condition against an event.
//!
//! Separate from the operators because the logic here is the safety
//! property: a field Topgent does not collect makes a comparison `Unknown`,
//! and `not`, `and` and `or` carry that honestly (false wins an `and`, true
//! wins an `or`, and `not Unknown` is `Unknown`). A rule fires only on `True`.

mod glob;
mod net;
mod ops;

use crate::event::{Event, Field};
use crate::lang::Expr;

/// The answer a condition gives for one event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Truth {
    /// It holds.
    True,
    /// It does not hold.
    False,
    /// It depends on a field Topgent does not collect.
    Unknown,
}

impl Truth {
    const fn not(self) -> Self {
        match self {
            Self::True => Self::False,
            Self::False => Self::True,
            Self::Unknown => Self::Unknown,
        }
    }
}

const fn from(holds: bool) -> Truth {
    if holds { Truth::True } else { Truth::False }
}

/// Evaluates `expr` against `event`.
///
/// An unresolved macro is `Unknown`: its meaning is not known here.
#[must_use]
pub fn evaluate(expr: &Expr, event: &dyn Event) -> Truth {
    match expr {
        Expr::And(parts) => {
            let mut result = Truth::True;
            for part in parts {
                match evaluate(part, event) {
                    Truth::False => return Truth::False,
                    Truth::Unknown => result = Truth::Unknown,
                    Truth::True => {}
                }
            }
            result
        }
        Expr::Or(parts) => {
            let mut result = Truth::False;
            for part in parts {
                match evaluate(part, event) {
                    Truth::True => return Truth::True,
                    Truth::Unknown => result = Truth::Unknown,
                    Truth::False => {}
                }
            }
            result
        }
        Expr::Not(inner) => evaluate(inner, event).not(),
        Expr::Macro(_) => Truth::Unknown,
        Expr::Exists(field) => match event.field(&field.name, field.arg.as_deref()) {
            Field::Value(_) | Field::Bytes(_) => Truth::True,
            Field::Many(values) => from(!values.is_empty()),
            Field::Partial(values) if !values.is_empty() => Truth::True,
            Field::Absent => Truth::False,
            Field::Partial(_) | Field::Unknown => Truth::Unknown,
        },
        Expr::Compare { field, op, value } => {
            match event.field(&field.name, field.arg.as_deref()) {
                Field::Value(text) => from(ops::compare(
                    &field.name,
                    &text,
                    text.as_bytes(),
                    *op,
                    value,
                )),
                Field::Many(values) => from(
                    values
                        .iter()
                        .any(|one| ops::compare(&field.name, one, one.as_bytes(), *op, value)),
                ),
                Field::Partial(values) => {
                    if values
                        .iter()
                        .any(|one| ops::compare(&field.name, one, one.as_bytes(), *op, value))
                    {
                        Truth::True
                    } else {
                        Truth::Unknown
                    }
                }
                Field::Bytes(bytes) => {
                    let text = String::from_utf8_lossy(&bytes);
                    from(ops::compare(&field.name, &text, &bytes, *op, value))
                }
                // A comparison on a value that is not there does not hold.
                Field::Absent => Truth::False,
                Field::Unknown => Truth::Unknown,
            }
        }
    }
}
