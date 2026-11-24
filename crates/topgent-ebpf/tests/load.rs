//! E0: the probe loads, the kernel lists it, and dropping it leaves nothing.
//!
//! Loads a program into the running kernel, so it needs root (`CAP_BPF`) and
//! is ignored by default. On a Linux host with the probe toolchain:
//!
//! ```sh
//! cargo test -p topgent-ebpf --features probe --no-run
//! sudo -E cargo test -p topgent-ebpf --features probe -- --ignored
//! ```

#![cfg(all(target_os = "linux", feature = "probe"))]
#![allow(clippy::expect_used, clippy::panic)]

use std::{
    collections::BTreeSet,
    thread,
    time::{Duration, Instant},
};

/// Every program id the kernel holds right now, from anyone.
fn kernel_program_ids() -> BTreeSet<u32> {
    aya::programs::loaded_programs()
        .map(|program| program.expect("the kernel lists its programs").id())
        .collect()
}

#[test]
#[ignore = "needs root: loads a program into the running kernel"]
fn the_probe_loads_and_leaves_nothing_behind() {
    let probe = topgent_ebpf::load().expect("the probe loads");
    let ids = probe.program_ids().expect("the kernel describes the probe");
    // One per lifecycle tracepoint, plus the syscall enter and exit
    // programs, each attached to every rule syscall.
    assert_eq!(
        ids.len(),
        topgent_ebpf_common::TRACEPOINTS.len() + 3 + topgent_ebpf_common::ARGV_PROGRAMS.len(),
        "one program per lifecycle tracepoint, two for syscalls, one for close, and the exec arguments"
    );

    let listed = kernel_program_ids();
    assert!(
        ids.iter().all(|id| listed.contains(id)),
        "{ids:?} not in {listed:?}"
    );

    drop(probe);
    // The kernel frees a program once its last reference goes, which can
    // trail the close by a moment.
    let deadline = Instant::now() + Duration::from_secs(5);
    while ids.iter().any(|id| kernel_program_ids().contains(id)) {
        assert!(
            Instant::now() < deadline,
            "{ids:?} still loaded 5s after drop"
        );
        thread::sleep(Duration::from_millis(50));
    }
}
