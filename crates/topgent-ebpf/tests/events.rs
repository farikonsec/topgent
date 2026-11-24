//! E1 (O2): every process this test creates is reported, with this test as
//! its creator, the program it ran, and its end.
//!
//! Needs root, like `load.rs`; see there for how to run it.

#![cfg(all(target_os = "linux", feature = "probe"))]
#![allow(clippy::expect_used, clippy::panic, clippy::print_stdout)]

use std::{
    collections::BTreeSet,
    process::Command,
    thread,
    time::{Duration, Instant},
};

use topgent_ebpf::{Kind, Namespace, ProcessEvent, text};

/// Processes created. Enough that one in a thousand missing would show.
const CHILDREN: usize = 1_000;
/// The program each child runs. Absolute, so the exec path is exactly this.
const MARKER: &str = "/bin/true";

/// What the probe said about the children.
#[derive(Default)]
struct Seen {
    spawned: BTreeSet<u32>,
    execed: BTreeSet<u32>,
    exited: BTreeSet<u32>,
    /// Execs the kernel did not place in the host's pid namespace.
    not_host: BTreeSet<u32>,
}

impl Seen {
    fn take(&mut self, events: &mut Vec<ProcessEvent>, children: &BTreeSet<u32>, me: u32) {
        for event in events.drain(..) {
            if !children.contains(&event.pid) {
                continue;
            }
            match event.kind() {
                Some(Kind::Spawn) if event.creator == me => {
                    self.spawned.insert(event.pid);
                }
                Some(Kind::Exec) if text(&event.filename) == MARKER.as_bytes() => {
                    self.execed.insert(event.pid);
                    if event.namespace() != Namespace::Host {
                        self.not_host.insert(event.pid);
                    }
                }
                Some(Kind::Exit) => {
                    self.exited.insert(event.pid);
                }
                _ => {}
            }
        }
    }

    fn complete(&self, children: &BTreeSet<u32>) -> bool {
        [&self.spawned, &self.execed, &self.exited]
            .iter()
            .all(|seen| seen.len() == children.len())
    }
}

#[test]
#[ignore = "needs root: loads a program into the running kernel"]
fn every_child_is_reported_with_its_creator_its_program_and_its_end() {
    let mut probe = topgent_ebpf::load().expect("the probe loads");
    let me = std::process::id();
    let mut children = BTreeSet::new();
    let mut events = Vec::new();
    let mut seen = Seen::default();

    // Created before any child is known, so a spawn event can arrive before
    // its pid is recorded: keep every event until the end.
    let mut kept = Vec::new();
    for _ in 0..CHILDREN {
        let mut child = Command::new(MARKER).spawn().expect("spawn the marker");
        children.insert(child.id());
        child.wait().expect("wait for the marker");
        probe.drain(&mut kept);
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        probe.drain(&mut kept);
        events.append(&mut kept);
        seen.take(&mut events, &children, me);
        if seen.complete(&children) || Instant::now() > deadline {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }

    let lost = probe.lost().expect("the kernel reads the lost counter");
    println!(
        "children {} · spawned {} · execed {} · exited {} · lost {lost} · malformed {}",
        children.len(),
        seen.spawned.len(),
        seen.execed.len(),
        seen.exited.len(),
        probe.malformed(),
    );
    assert_eq!(probe.malformed(), 0, "every record is one whole event");
    assert!(
        probe.host_pid_namespace().is_some(),
        "the host namespace was read"
    );
    // The children run where this test runs, which is the host.
    assert!(
        seen.not_host.is_empty(),
        "{} execs not placed in the host namespace",
        seen.not_host.len()
    );
    // O2: at least 99.9% of each.
    let floor = children.len() - children.len() / 1_000;
    for (what, count) in [
        ("spawned", seen.spawned.len()),
        ("execed", seen.execed.len()),
        ("exited", seen.exited.len()),
    ] {
        assert!(
            count >= floor,
            "{what}: {count} of {} (lost {lost})",
            children.len()
        );
    }
}
