//! Syscall events for the behaviour rules, handed to the sweep once each.
//!
//! The same Audit tail is read every sweep, so the same record arrives many
//! times; the watermark passes each on once. Each event carries its time in
//! the start-time base too, which is what its pid is resolved against.
//!
//! Exec arguments travel with the event in memory. Nothing here stores them.
//!
//! Calls also arrive from `topgent-sensor`'s eBPF probe. While it delivers
//! them, the Audit tail is not published, so a host running both never sees
//! one call twice.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};

use topgent_facts::UnixMillis;

use super::Held;
#[cfg(any(target_os = "linux", test))]
use super::{Watermark, serial, to_lineage_base};
use crate::audit_syscalls::SyscallEvent;

/// One syscall event, with its time in the start-time base.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedSyscall {
    /// The call as recorded.
    pub event: SyscallEvent,
    /// When, in the base process start times are kept in.
    pub lineage_at: UnixMillis,
}

/// The events not handed over before, with their start-base time.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn fresh(
    mark: &mut Watermark,
    events: Vec<SyscallEvent>,
    now: u64,
    offset: u64,
) -> Vec<ObservedSyscall> {
    mark.fresh(events, now, |event| (serial(&event.record), event.at))
        .into_iter()
        .map(|event| ObservedSyscall {
            lineage_at: UnixMillis(to_lineage_base(event.at, offset)),
            event,
        })
        .collect()
}

fn held() -> &'static Mutex<Held<ObservedSyscall>> {
    static HELD: Mutex<Held<ObservedSyscall>> = Mutex::new(Held::new());
    &HELD
}

/// Whether the sensor is delivering syscalls, in which case the Audit tail
/// is not their source.
static SENSOR_DELIVERS: AtomicBool = AtomicBool::new(false);

/// Records whether the sensor delivers syscalls, from its health lines; and
/// that it does not, once it stops.
#[cfg(target_os = "linux")]
pub(crate) fn set_sensor_delivers(delivers: bool) {
    SENSOR_DELIVERS.store(delivers, Ordering::Relaxed);
}

/// Whether syscalls come from the sensor rather than the Audit log.
#[must_use]
pub fn sensor_delivers() -> bool {
    SENSOR_DELIVERS.load(Ordering::Relaxed)
}

/// A sensor call with its record id and wall time filled in. `offset` is
/// how far the wall clock runs ahead of the start-time base the sensor
/// stamps calls in.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn from_sensor(call: crate::process_events::SensorCall, offset: u64) -> ObservedSyscall {
    let mut event = call.event;
    let lineage_at = event.at;
    event.at = lineage_at.saturating_add(offset);
    event.record = format!("{}.{:03}:{}", event.at / 1_000, event.at % 1_000, call.seq);
    ObservedSyscall {
        event,
        lineage_at: UnixMillis(lineage_at),
    }
}

/// Hands the sensor's calls to this sweep. `dropped` counts calls the
/// collector could not hold, reported with the queue's own losses.
#[cfg(target_os = "linux")]
pub(crate) fn publish_sensor_calls(calls: Vec<crate::process_events::SensorCall>, dropped: u64) {
    let offset = super::lineage_offset();
    let mut held = held().lock().unwrap_or_else(PoisonError::into_inner);
    held.overflowed = held.overflowed.saturating_add(dropped);
    held.push(
        calls
            .into_iter()
            .map(|call| from_sensor(call, offset))
            .collect(),
    );
}

/// Hands a read of the Audit tail to the next sweep, each record once. Does
/// nothing while the sensor delivers syscalls.
#[cfg(target_os = "linux")]
pub(crate) fn publish_syscalls(text: &str, now: u64) {
    static MARK: Mutex<Watermark> = Mutex::new(Watermark::new());
    if sensor_delivers() {
        return;
    }
    let events = crate::audit_syscalls::parse(text);
    let offset = super::lineage_offset();
    let fresh = fresh(
        &mut MARK.lock().unwrap_or_else(PoisonError::into_inner),
        events,
        now,
        offset,
    );
    for call in &fresh {
        super::tally::add(&call.event, call.lineage_at.0);
    }
    held()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(fresh);
}

/// Every syscall event recorded since the last call, and how many the hold
/// had to drop.
#[must_use]
pub fn take_syscalls() -> (Vec<ObservedSyscall>, u64) {
    let mut held = held().lock().unwrap_or_else(PoisonError::into_inner);
    let dropped = std::mem::take(&mut held.overflowed);
    (held.take(), dropped)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]

    use super::fresh;
    use crate::audit_syscalls::parse;
    use crate::observed::Watermark;

    const LOG: &str = "type=SYSCALL msg=audit(100.200:41): arch=c00000b7 syscall=117 success=yes exit=0 a0=0 ppid=1 pid=7 uid=1000 comm=\"x\" exe=\"/x\"\n\
                       type=SYSCALL msg=audit(100.300:42): arch=c00000b7 syscall=146 success=yes exit=0 a0=3e8 ppid=1 pid=7 uid=1000 comm=\"x\" exe=\"/x\"\n";

    #[test]
    fn a_sensor_call_gets_its_wall_time_and_a_record_id() {
        let Some(crate::process_events::Line::Syscall(call)) = crate::process_events::parse_line(
            r#"{"e":"sys","call":"ptrace","pid":7,"ret":0,"args":[0],"seq":42,"at":99600}"#,
        ) else {
            unreachable!()
        };
        let observed = super::from_sensor(*call, 600);
        assert_eq!(
            observed.lineage_at.0, 99_600,
            "already in the start-time base"
        );
        assert_eq!(observed.event.at, 100_200);
        assert_eq!(observed.event.record, "100.200:42");
        assert_eq!(crate::observed::serial(&observed.event.record), Some(42));
    }

    #[test]
    fn a_record_read_again_is_handed_over_once_with_its_start_base_time() {
        let mut mark = Watermark::new();
        let first = fresh(&mut mark, parse(LOG), 101_000, 600);
        assert_eq!(first.len(), 2);
        assert_eq!(first[0].event.syscall, "ptrace");
        assert_eq!(first[0].lineage_at.0, 99_600);
        assert!(fresh(&mut mark, parse(LOG), 102_000, 600).is_empty());
    }
}
