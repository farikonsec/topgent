//! Which records one reader has already handed over.

use std::collections::BTreeSet;

use super::{FIRST_READ_MS, MAX_HELD};

/// Which records one reader has already handed over.
///
/// A bounded set of record ids tolerates interleaved Audit groups arriving
/// late. Records outside the last minute are intentionally not replayed.
#[derive(Debug, Default)]
pub struct Watermark {
    seen: BTreeSet<(u64, u64)>,
}

impl Watermark {
    /// A reader that has handed nothing over yet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            seen: BTreeSet::new(),
        }
    }

    /// Returns records not seen in a previous read, including delayed groups.
    pub fn fresh<T>(
        &mut self,
        items: Vec<T>,
        now: u64,
        key: impl Fn(&T) -> (Option<u64>, u64),
    ) -> Vec<T> {
        let since = now.saturating_sub(FIRST_READ_MS);
        self.seen.retain(|(at, _)| *at >= since);
        let mut added = BTreeSet::new();
        let fresh = items
            .into_iter()
            .filter(|item| {
                let (Some(serial), at) = key(item) else {
                    return false;
                };
                let id = (at, serial);
                if at < since || at > now || self.seen.contains(&id) {
                    return false;
                }
                added.insert(id);
                true
            })
            .collect();
        self.seen.extend(added);
        while self.seen.len() > MAX_HELD * 4 {
            self.seen.pop_first();
        }
        fresh
    }
}

#[cfg(test)]
mod tests {
    use super::Watermark;
    use crate::observed::{ActionKind, ObservedAction, serial};
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
    fn a_record_id_gives_its_serial() {
        assert_eq!(serial("1700000000.100:41"), Some(41));
        assert_eq!(serial("1700000000.100"), None);
        assert_eq!(serial("1700000000.100:x"), None);
    }

    /// The same tail is read every sweep: a record is handed over once.
    #[test]
    fn a_record_read_again_is_not_handed_over_again() {
        let mut mark = Watermark::default();
        let id = |a: &ObservedAction| (serial(&a.record), a.at.0);
        let first = mark.fresh(
            vec![action("100.000:5", 100_000), action("100.001:6", 100_001)],
            100_500,
            id,
        );
        assert_eq!(first.len(), 2);
        let second = mark.fresh(
            vec![
                action("100.000:5", 100_000),
                action("100.001:6", 100_001),
                action("101.000:7", 101_000),
            ],
            101_500,
            id,
        );
        assert_eq!(
            second.iter().map(|a| a.record.as_str()).collect::<Vec<_>>(),
            ["101.000:7"]
        );
    }

    #[test]
    fn delayed_records_from_an_older_audit_group_are_not_lost() {
        let mut mark = Watermark::default();
        let id = |a: &ObservedAction| (serial(&a.record), a.at.0);
        assert_eq!(
            mark.fresh(vec![action("100.100:6", 100_100)], 101_000, id)
                .len(),
            1
        );
        assert_eq!(
            mark.fresh(vec![action("100.000:5", 100_000)], 102_000, id)
                .len(),
            1
        );
        assert!(
            mark.fresh(
                vec![action("100.100:6", 100_100), action("100.000:5", 100_000)],
                103_000,
                id
            )
            .is_empty()
        );
    }

    /// A day of old log is not news: the first read reaches back a minute.
    #[test]
    fn the_first_read_takes_only_the_last_minute() {
        let mut mark = Watermark::default();
        let id = |a: &ObservedAction| (serial(&a.record), a.at.0);
        let taken = mark.fresh(
            vec![action("1.000:1", 1_000), action("99.000:2", 99_000)],
            100_000,
            id,
        );
        assert_eq!(taken.len(), 1);
        assert_eq!(taken.first().map(|a| a.record.as_str()), Some("99.000:2"));
    }

    /// After a reboot the serials start again from one. Everything newer than
    /// the watermark would otherwise be refused forever.
    #[test]
    fn a_restarted_sequence_is_read_again_from_the_last_minute() {
        let mut mark = Watermark::default();
        let id = |a: &ObservedAction| (serial(&a.record), a.at.0);
        let _ = mark.fresh(vec![action("100.000:900", 100_000)], 100_100, id);
        let after = mark.fresh(vec![action("200.000:3", 200_000)], 200_100, id);
        assert_eq!(after.len(), 1);
    }

    /// A reboot without rotating the log: the tail holds the old boot's high
    /// serials and the new boot's low ones side by side.
    #[test]
    fn a_new_boot_in_the_same_log_is_still_read() {
        let mut mark = Watermark::default();
        let id = |a: &ObservedAction| (serial(&a.record), a.at.0);
        let _ = mark.fresh(vec![action("100.000:900", 100_000)], 100_100, id);
        let after = mark.fresh(
            vec![action("100.000:900", 100_000), action("200.000:3", 200_000)],
            200_100,
            id,
        );
        assert_eq!(
            after.iter().map(|a| a.record.as_str()).collect::<Vec<_>>(),
            ["200.000:3"]
        );
    }
}
