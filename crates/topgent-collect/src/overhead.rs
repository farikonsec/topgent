//! What a sweep costs the machine it runs on.
//!
//! Milestone M9 lists CPU, memory and startup overhead among its metrics, and
//! none of them were measured. This is the memory half, and it is deliberately
//! small: Topgent asks the operating system about its own process, using the
//! same process table it uses for everything else.
//!
//! Measuring ourselves with our own sensor is the honest arrangement. If the
//! process table is wrong about Topgent it is wrong about the agents too, and a
//! separate measurement path would hide that rather than expose it.

/// Resident set size of this process, in bytes.
///
/// `None` where the platform will not say. That is a real answer and not a
/// zero: a monitor that reported no memory use would be claiming something
/// nobody measured, which is the same failure as any other unearned number.
#[must_use]
pub fn resident_bytes() -> Option<u64> {
    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

    let me = Pid::from_u32(std::process::id());
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[me]),
        true,
        ProcessRefreshKind::nothing().with_memory(),
    );
    system.process(me).map(sysinfo::Process::memory)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

    use super::resident_bytes;

    #[test]
    fn this_process_reports_a_plausible_resident_size() {
        // A test binary is at least a megabyte and nothing like a terabyte.
        // The bounds are wide on purpose: the point is to catch a unit mistake
        // or a zero standing in for "unknown", not to pin an allocator.
        let Some(bytes) = resident_bytes() else {
            eprintln!("this platform states no resident size; nothing to check");
            return;
        };
        assert!(
            bytes > 1_000_000 && bytes < 100_000_000_000,
            "{bytes} bytes is not a plausible resident size for a test binary"
        );
    }
}
