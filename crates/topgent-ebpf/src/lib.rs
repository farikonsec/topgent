//! Topgent's eBPF source on Linux.
//!
//! Loads Topgent's own kernel probe (built from `topgent-ebpf-probe`),
//! attaches its programs, and removes them again when the [`Probe`] is
//! dropped. Where there is no probe to load, [`load`] says why in plain words
//! and loads nothing, and Topgent keeps reading Linux Audit.
//!
//! One interface, two implementations chosen at compile time: `linux` when the
//! target is Linux and the `probe` feature is on, `absent` everywhere else.
//! Nothing in this crate uses `unsafe`; the kernel side lives in its own crate.
//!
//! A loaded probe reports each process's life as [`ProcessEvent`]s: created
//! (with the process that asked for it), ran a program, ended. Read them with
//! [`Probe::drain`]. It also reports the syscalls the behaviour rules read,
//! as [`SyscallRecord`]s, through [`Probe::drain_syscalls`]. See
//! docs/ebpf/PLAN.md for what each phase adds.

use std::fmt;

pub use topgent_ebpf_common::{
    ArgvRecord, CwdRecord, Kind, Namespace, ProcessEvent, SocketKind, SyscallRecord, text,
};

#[cfg(any(all(target_os = "linux", feature = "probe"), test))]
mod btf;
#[cfg(any(all(target_os = "linux", feature = "probe"), test))]
mod format;

#[cfg(all(target_os = "linux", feature = "probe"))]
mod linux;
#[cfg(all(target_os = "linux", feature = "probe"))]
use linux as imp;

#[cfg(not(all(target_os = "linux", feature = "probe")))]
mod absent;
#[cfg(not(all(target_os = "linux", feature = "probe")))]
use absent as imp;

pub use imp::Probe;

/// Loads and attaches the probe.
///
/// # Errors
///
/// [`Unavailable`] says why the probe is not running: the host is not Linux,
/// this build carries no probe, this kernel lacks what it reads, or the
/// kernel refused it.
pub fn load() -> Result<Probe, Unavailable> {
    imp::load()
}

/// Why the probe is not running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unavailable {
    /// eBPF is a Linux kernel facility; this host is not Linux.
    NotLinux,
    /// This build was made without the `probe` feature.
    NotBuilt,
    /// The kernel would not take the probe: most often missing privilege
    /// (`CAP_BPF`), or a kernel that is too old or locked down. Carries the
    /// kernel's reason.
    Refused(String),
    /// This kernel does not offer a tracepoint or field the probe reads.
    /// Carries which.
    Unsupported(String),
    /// The embedded probe does not match what this build expects. A build
    /// fault, never the host's.
    Mismatch(String),
}

impl fmt::Display for Unavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotLinux => f.write_str("eBPF is Linux only; this host is not Linux"),
            Self::NotBuilt => f.write_str("this build of Topgent carries no eBPF probe"),
            Self::Refused(why) => write!(f, "the kernel refused the eBPF probe: {why}"),
            Self::Unsupported(why) => {
                write!(f, "this kernel lacks what the eBPF probe reads: {why}")
            }
            Self::Mismatch(why) => write!(f, "the eBPF probe in this build is faulty: {why}"),
        }
    }
}

impl std::error::Error for Unavailable {}

#[cfg(test)]
mod tests {
    use super::Unavailable;

    /// A build without a probe loads nothing and says why, on every platform.
    #[cfg(not(all(target_os = "linux", feature = "probe")))]
    #[test]
    fn without_a_probe_load_says_why() {
        let expected = if cfg!(target_os = "linux") {
            Unavailable::NotBuilt
        } else {
            Unavailable::NotLinux
        };
        assert_eq!(super::load().err(), Some(expected));
    }

    #[test]
    fn every_reason_reads_as_a_sentence() {
        for (reason, starts) in [
            (Unavailable::NotLinux, "eBPF is Linux only"),
            (Unavailable::NotBuilt, "this build"),
            (
                Unavailable::Refused("Operation not permitted".into()),
                "the kernel refused",
            ),
            (
                Unavailable::Unsupported("task/task_newtask has no field pid".into()),
                "this kernel lacks",
            ),
            (
                Unavailable::Mismatch("no program on_exec".into()),
                "the eBPF probe in this build",
            ),
        ] {
            assert!(reason.to_string().starts_with(starts), "{reason}");
        }
    }
}
