//! A bounded hold between two sweeps.
//!
//! Readers push; the sweep takes. Past the bound the oldest items are
//! dropped and counted, so a slow sweep loses measured records rather than
//! memory.

use super::MAX_HELD;

/// Items held for the next sweep, with what did not fit counted.
#[derive(Debug)]
pub struct Held<T> {
    items: Vec<T>,
    /// Items dropped because a sweep had not taken the last ones.
    pub overflowed: u64,
}

impl<T> Default for Held<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Held<T> {
    /// An empty hold.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            items: Vec::new(),
            overflowed: 0,
        }
    }

    /// Adds items, dropping the oldest past [`MAX_HELD`].
    pub fn push(&mut self, items: Vec<T>) {
        self.items.extend(items);
        let excess = self.items.len().saturating_sub(MAX_HELD);
        if excess > 0 {
            self.items.drain(..excess);
            self.overflowed = self
                .overflowed
                .saturating_add(u64::try_from(excess).unwrap_or(u64::MAX));
        }
    }

    /// Everything held, oldest first.
    pub fn take(&mut self) -> Vec<T> {
        std::mem::take(&mut self.items)
    }
}

#[cfg(test)]
mod tests {
    use super::Held;
    use crate::observed::{ActionKind, MAX_HELD, ObservedAction};
    use topgent_facts::{Access, UnixMillis};

    fn action(record: &str, at: u64) -> ObservedAction {
        ObservedAction {
            record: record.to_owned(),
            program: None,
            pid: 7,
            at: UnixMillis(at),
            lineage_at: UnixMillis(at),
            kind: ActionKind::File {
                path: "/tmp/x".to_owned(),
                access: Access::Read,
            },
        }
    }

    #[test]
    fn a_full_hold_drops_the_oldest_and_counts_them() {
        let mut held = Held::default();
        held.push(
            (0..MAX_HELD + 3)
                .map(|n| action(&format!("{n}.000:{n}"), n as u64))
                .collect(),
        );
        assert_eq!(held.overflowed, 3);
        let taken = held.take();
        assert_eq!(taken.len(), MAX_HELD);
        assert_eq!(taken.first().map(|a| a.record.as_str()), Some("3.000:3"));
    }
}
