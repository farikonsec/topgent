//! What one interval's coverage claim rests on.
//!
//! Separate from the line format and the supervisor because these are the
//! rules a "Continuous, no loss" label is earned by: loss per interval, losses
//! kept across restarts, and silence that shows a stalled helper.

use std::collections::VecDeque;

use super::line::{HelperHealth, LifecycleEvent, Line, SensorCall};

/// Most events held between two sweeps.
pub const MAX_PENDING: usize = 65_536;

/// The longest the helper may go without a health line before an interval
/// stops counting as continuous. It writes one a second, checked after each
/// receive, whose timeout is also a second: two seconds apart at worst.
pub const STALL_MS: u64 = 3_000;

/// Events held between sweeps, bounded, with what did not fit counted.
#[derive(Debug, Default)]
pub struct Pending {
    events: VecDeque<LifecycleEvent>,
    /// Events dropped here because a sweep had not taken the last ones.
    pub overflowed: u64,
    /// Syscalls, held until the sweep that takes the lifecycle events that
    /// arrived before them: a call must never reach the rules ahead of the
    /// fork and exec of the process that made it.
    calls: VecDeque<SensorCall>,
    /// Syscalls dropped here because a sweep had not taken the last ones.
    calls_overflowed: u64,
    /// The helper's latest health line.
    pub health: Option<HelperHealth>,
    /// Helper sessions seen, in order. More than one is a restart.
    pub sessions: Vec<String>,
    /// Losses reported by helper sessions that have since ended.
    carried: u64,
    /// The running total when the last interval was closed.
    closed_at: u64,
    /// The longest gap between two health lines of one session since the
    /// last interval was closed.
    longest_silence: u64,
}

impl Pending {
    /// Takes one line.
    pub fn push(&mut self, line: Line) {
        match line {
            Line::Event(event) => {
                if self.events.len() >= MAX_PENDING {
                    self.events.pop_front();
                    self.overflowed = self.overflowed.saturating_add(1);
                }
                self.events.push_back(event);
            }
            Line::Syscall(call) => {
                if self.calls.len() >= MAX_PENDING {
                    self.calls.pop_front();
                    self.calls_overflowed = self.calls_overflowed.saturating_add(1);
                }
                self.calls.push_back(*call);
            }
            Line::Health(health) => {
                if self.sessions.last() != Some(&health.session) {
                    // A new session counts from zero. What the last one
                    // reported is kept, not forgotten with it.
                    if let Some(previous) = &self.health {
                        self.carried = self
                            .carried
                            .saturating_add(previous.lost.saturating_add(previous.overflows));
                    }
                    self.sessions.push(health.session.clone());
                } else if let Some(previous) = &self.health {
                    self.longest_silence = self
                        .longest_silence
                        .max(health.at.saturating_sub(previous.at));
                }
                self.health = Some(health);
            }
        }
    }

    /// Everything received since the last drain, in arrival order.
    pub fn drain(&mut self) -> Vec<LifecycleEvent> {
        self.events.drain(..).collect()
    }

    /// Every syscall received since the last drain, in arrival order, and
    /// how many were dropped for want of room. Take it with [`Pending::drain`]:
    /// the helper writes a call only after the lifecycle lines of what came
    /// before it, so the two drained together are consistent.
    pub fn drain_calls(&mut self) -> (Vec<SensorCall>, u64) {
        (
            self.calls.drain(..).collect(),
            std::mem::take(&mut self.calls_overflowed),
        )
    }

    /// Every loss counted so far: the kernel's, the socket's and this side's.
    #[must_use]
    pub fn lost(&self) -> u64 {
        let helper = self
            .health
            .as_ref()
            .map_or(0, |health| health.lost.saturating_add(health.overflows));
        helper
            .saturating_add(self.carried)
            .saturating_add(self.overflowed)
    }

    /// Loss since the last call, closing the interval.
    ///
    /// Coverage is a claim about one interval, so the loss behind it must be
    /// that interval's: a running total would keep one overflow an hour ago
    /// in every later interval's coverage. `None` until the helper has
    /// reported, which is no loss figure rather than zero.
    pub fn take_interval_loss(&mut self) -> Option<u64> {
        self.health.as_ref()?;
        let total = self.lost();
        let interval = total.saturating_sub(self.closed_at);
        self.closed_at = total;
        Some(interval)
    }

    /// The longest the helper went without reporting in the interval ending
    /// `now`, closing it. A frozen or starved helper sends nothing, so
    /// silence is what shows it was not receiving. Zero before any report.
    pub fn take_interval_silence(&mut self, now: u64) -> u64 {
        let Some(health) = &self.health else {
            return 0;
        };
        let silence = self.longest_silence.max(now.saturating_sub(health.at));
        self.longest_silence = 0;
        silence
    }

    /// How many times the helper was restarted.
    #[must_use]
    pub fn restarts(&self) -> usize {
        self.sessions.len().saturating_sub(1)
    }
}

/// Whether the helper was receiving for the whole interval since the
/// previous sweep.
///
/// `None` before there has been a previous sweep: there is no interval yet.
/// An interval is covered only if the helper that is running now was already
/// running at the previous sweep, was not restarted during this one, and did
/// not stall: a helper alive but not reporting was not receiving either.
#[must_use]
pub const fn interval_covered(
    previous_sweep: Option<u64>,
    running_since: Option<u64>,
    restarted_now: bool,
    stalled: bool,
) -> Option<bool> {
    match (previous_sweep, running_since) {
        (None, _) => None,
        (Some(_), _) if restarted_now || stalled => Some(false),
        (Some(previous), Some(since)) => Some(since <= previous),
        (Some(_), None) => Some(false),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::indexing_slicing)]

    use super::{MAX_PENDING, Pending, interval_covered};
    use crate::process_events::parse_line;
    use topgent_facts::UnixMillis;

    /// A call waits for the sweep that takes the exec before it, and the
    /// two leave together.
    #[test]
    fn a_syscall_is_drained_with_the_lifecycle_events_before_it() {
        let mut pending = Pending::default();
        for line in [
            r#"{"e":"exec","pid":7,"name":"cat","at":1}"#,
            r#"{"e":"sys","call":"openat","pid":7,"ret":3,"path":"/etc/shadow","seq":1,"at":2}"#,
        ] {
            pending.push(parse_line(line).expect("a line"));
        }
        let events = pending.drain();
        let (calls, dropped) = pending.drain_calls();
        assert_eq!((events.len(), calls.len(), dropped), (1, 1, 0));
        assert_eq!(calls[0].event.pid_namespace, None, "no pidns, none claimed");
        assert!(pending.drain_calls().0.is_empty(), "each call once");
    }

    #[test]
    fn a_full_buffer_drops_the_oldest_and_counts_them() {
        let mut pending = Pending::default();
        for n in 0..(MAX_PENDING as u64 + 10) {
            let line = format!(r#"{{"e":"exec","pid":7,"at":{n}}}"#);
            pending.push(parse_line(&line).expect("line"));
        }
        assert_eq!(pending.overflowed, 10);
        let drained = pending.drain();
        assert_eq!(drained.len(), MAX_PENDING);
        assert_eq!(drained.first().map(|e| e.at), Some(UnixMillis(10)));
        assert!(pending.drain().is_empty());
    }

    /// Each interval reports its own loss; one overflow does not follow every
    /// later interval around.
    /// The live Kali run caught this: a helper killed and restarted inside
    /// one interval was reported as having covered it.
    #[test]
    fn an_interval_with_a_restart_is_not_covered() {
        assert_eq!(
            interval_covered(None, Some(10), false, false),
            None,
            "no interval yet"
        );
        assert_eq!(
            interval_covered(Some(20), Some(10), false, false),
            Some(true)
        );
        assert_eq!(
            interval_covered(Some(20), Some(10), true, false),
            Some(false),
            "restarted during this interval"
        );
        assert_eq!(
            interval_covered(Some(20), Some(25), false, false),
            Some(false),
            "started after the interval began"
        );
        assert_eq!(interval_covered(Some(20), None, false, false), Some(false));
    }

    #[test]
    fn loss_is_reported_per_interval() {
        let mut pending = Pending::default();
        assert_eq!(pending.take_interval_loss(), None, "no health line yet");
        pending.push(
            parse_line(r#"{"e":"health","session":"a","lost":0,"overflows":0,"at":1}"#).expect("h"),
        );
        assert_eq!(pending.take_interval_loss(), Some(0));
        pending.push(
            parse_line(r#"{"e":"health","session":"a","lost":40,"overflows":2,"at":2}"#)
                .expect("h"),
        );
        assert_eq!(pending.take_interval_loss(), Some(42));
        assert_eq!(
            pending.take_interval_loss(),
            Some(0),
            "the next interval starts clean"
        );
        assert_eq!(pending.lost(), 42, "the running total is kept");
    }

    /// The live overflow run: the sensor was frozen for six seconds and the
    /// intervals it missed still said "Continuous, no loss". It reports once
    /// a second, so a longer silence means it was not receiving.
    #[test]
    fn a_sensor_that_stops_reporting_is_measured_as_silent() {
        let health = |at: u64| {
            parse_line(&format!(
                r#"{{"e":"health","session":"a","lost":0,"overflows":0,"at":{at}}}"#
            ))
            .expect("h")
        };
        let mut pending = Pending::default();
        assert_eq!(
            pending.take_interval_silence(5_000),
            0,
            "nothing to measure yet"
        );
        pending.push(health(1_000));
        pending.push(health(2_000));
        assert_eq!(pending.take_interval_silence(2_500), 1_000);
        // Frozen: nothing arrives, and the silence runs up to the sweep.
        assert_eq!(pending.take_interval_silence(8_000), 6_000);
        // Thawed: the late line shows the silence it ended.
        pending.push(health(9_000));
        assert_eq!(pending.take_interval_silence(9_500), 7_000);
        pending.push(health(10_000));
        assert_eq!(pending.take_interval_silence(11_000), 1_000);
        // A new session is a restart, counted as one; its first line does
        // not measure the silence from the old session's last.
        pending.push(
            parse_line(r#"{"e":"health","session":"b","lost":0,"overflows":0,"at":20000}"#)
                .expect("h"),
        );
        assert_eq!(pending.take_interval_silence(20_500), 500);
    }

    #[test]
    fn a_stalled_interval_is_not_covered() {
        assert_eq!(
            interval_covered(Some(20), Some(10), false, true),
            Some(false)
        );
        assert_eq!(interval_covered(None, Some(10), false, true), None);
    }

    /// Loss is the kernel's, the socket's and this side's together, and a
    /// sensor that has not reported yet has no loss figure rather than zero.
    #[test]
    fn loss_and_restarts_are_counted_from_health_lines() {
        let mut pending = Pending::default();
        assert!(pending.health.is_none());
        for line in [
            r#"{"e":"health","session":"a","lost":2,"overflows":0,"at":1}"#,
            r#"{"e":"health","session":"a","lost":4,"overflows":1,"at":2}"#,
            r#"{"e":"health","session":"b","lost":0,"overflows":0,"at":3}"#,
        ] {
            pending.push(parse_line(line).expect("health"));
        }
        assert_eq!(pending.restarts(), 1, "a new session is a restart");
        assert_eq!(pending.lost(), 5, "the ended session's losses are kept");
    }
}
