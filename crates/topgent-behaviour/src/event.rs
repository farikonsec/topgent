//! What one event says about one field.
//!
//! Three answers, kept apart because the rules depend on the difference: the
//! field has a value; the field is collected and has no value (a process with
//! no parent has no `proc.pname`); or Topgent does not collect the field at
//! all, in which case nothing can be concluded from it.

use std::collections::BTreeMap;

/// A field's answer for one event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Field {
    /// The field has this value.
    Value(String),
    /// The field holds raw bytes, such as a read buffer.
    Bytes(Vec<u8>),
    /// The field holds several values at once, such as every ancestor's
    /// name for `proc.aname` with no index. A comparison holds if any does.
    Many(Vec<String>),
    /// Some of the field's values, possibly not all: a process history that
    /// stops short of the root. A comparison holds if one of these does, and
    /// is unknown otherwise.
    Partial(Vec<String>),
    /// The field is collected for this event and has no value.
    Absent,
    /// Topgent does not collect this field.
    Unknown,
}

/// Anything the engine can evaluate a rule against.
pub trait Event {
    /// The field `name`, with its bracketed argument if the rule gave one
    /// (`proc.aname[2]` is `("proc.aname", Some("2"))`).
    fn field(&self, name: &str, arg: Option<&str>) -> Field;
}

/// An event held as a map, for fixtures and tests. A field not set is
/// `Unknown`, the same answer a sensor gives for a field it cannot see.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MapEvent {
    fields: BTreeMap<(String, Option<String>), Field>,
}

impl MapEvent {
    /// Sets a field's value.
    pub fn set(&mut self, name: &str, value: &str) {
        self.fields
            .insert((name.to_owned(), None), Field::Value(value.to_owned()));
    }

    /// Sets a field with an argument, such as `proc.aname[2]`.
    pub fn set_arg(&mut self, name: &str, arg: &str, value: &str) {
        self.fields.insert(
            (name.to_owned(), Some(arg.to_owned())),
            Field::Value(value.to_owned()),
        );
    }

    /// Marks a field as collected with no value.
    pub fn set_absent(&mut self, name: &str) {
        self.fields.insert((name.to_owned(), None), Field::Absent);
    }

    /// Marks a field with an argument, such as `proc.aname[2]`, as collected
    /// with no value: the process has no ancestor that far up.
    pub fn set_absent_arg(&mut self, name: &str, arg: &str) {
        self.fields
            .insert((name.to_owned(), Some(arg.to_owned())), Field::Absent);
    }

    /// Sets a field to several values at once.
    pub fn set_many(&mut self, name: &str, values: &[&str]) {
        self.fields.insert(
            (name.to_owned(), None),
            Field::Many(values.iter().map(|v| (*v).to_owned()).collect()),
        );
    }

    /// Sets a field to some of its values, possibly not all.
    pub fn set_partial(&mut self, name: &str, values: &[&str]) {
        self.fields.insert(
            (name.to_owned(), None),
            Field::Partial(values.iter().map(|v| (*v).to_owned()).collect()),
        );
    }

    /// Sets a field to raw bytes.
    pub fn set_bytes(&mut self, name: &str, bytes: &[u8]) {
        self.fields
            .insert((name.to_owned(), None), Field::Bytes(bytes.to_vec()));
    }
}

impl Event for MapEvent {
    fn field(&self, name: &str, arg: Option<&str>) -> Field {
        self.fields
            .get(&(name.to_owned(), arg.map(str::to_owned)))
            .cloned()
            .unwrap_or(Field::Unknown)
    }
}
