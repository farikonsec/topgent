//! The time base every line is stated in.
//!
//! Separate because it is the one rule that makes an event time comparable
//! with a process start time read from `/proc`.

pub(super) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

pub(super) fn clock_ns(id: rustix::time::ClockId) -> u64 {
    let now = rustix::time::clock_gettime(id);
    u64::try_from(now.tv_sec)
        .unwrap_or(0)
        .saturating_mul(1_000_000_000)
        .saturating_add(u64::try_from(now.tv_nsec).unwrap_or(0))
}

/// An event's time, in the same base as every process start time.
///
/// Start times are the kernel's boot time plus ticks since boot, and the
/// kernel publishes boot time in whole seconds. Events are timestamped on
/// the monotonic clock. Putting both on the boot clock keeps a parent's
/// exit and a child's start comparable; stating events in wall time while
/// starts sit up to a second earlier would put them in different bases.
/// The price, stated in the boundary, is that both can read up to a
/// second earlier than the wall clock.
pub(super) fn event_ms(boot_seconds: u64, timestamp_ns: u64, boot_minus_monotonic: u64) -> u64 {
    boot_seconds
        .saturating_mul(1_000)
        .saturating_add(timestamp_ns.saturating_add(boot_minus_monotonic) / 1_000_000)
}
