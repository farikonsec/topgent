//! Naming the syscall a Linux Audit record describes.
//!
//! A raw audit log prints the syscall as a number, and the number means
//! nothing without the architecture beside it. On x86-64 `56` is `clone` and
//! `82` is `rename`; on aarch64 `56` is `openat` and `82` is `fsync`. Reading
//! numbers from both tables at once turned an aarch64 `fsync` into a write and
//! missed every aarch64 delete, because `rm` there calls `unlinkat`, number 35,
//! which neither table this crate used to carry contained.
//!
//! So a number is only read together with the record's own `arch` field, and a
//! number from an architecture this build does not model names nothing. A
//! record whose syscall field is already a name (auditd built with its syscall
//! table, or `ausearch -i` output) is read by name on any architecture.

// The readers that use the rest of this module run on Linux only; the
// syscall reader below is plain text handling, built and tested everywhere.
#![cfg_attr(not(any(target_os = "linux", test, fuzzing)), allow(dead_code))]

pub(crate) mod exec;
pub(crate) mod names;
pub(crate) mod record;
pub mod syscalls;

use record::field;

/// An architecture whose syscall numbers this build can read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Arch {
    X86_64,
    Aarch64,
}

impl Arch {
    /// Read the record's `arch` field, the kernel's `AUDIT_ARCH_*` constant.
    pub(super) fn of(line: &str) -> Option<Self> {
        match field(line, "arch")?.to_ascii_lowercase().as_str() {
            "c000003e" | "x86_64" => Some(Self::X86_64),
            "c00000b7" | "aarch64" => Some(Self::Aarch64),
            _ => None,
        }
    }
}

/// The syscalls Topgent's audit readers interpret, and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Syscall {
    Open,
    Openat,
    Close,
    Connect,
    Sendto,
    Sendmsg,
    Execve,
    Execveat,
    Truncate,
    Rename,
    Renameat,
    Renameat2,
    Unlink,
    Unlinkat,
}

impl Syscall {
    fn named(name: &str) -> Option<Self> {
        Some(match name {
            "open" => Self::Open,
            "openat" => Self::Openat,
            "close" => Self::Close,
            "connect" => Self::Connect,
            "sendto" => Self::Sendto,
            "sendmsg" => Self::Sendmsg,
            "execve" => Self::Execve,
            "execveat" => Self::Execveat,
            "truncate" => Self::Truncate,
            "rename" => Self::Rename,
            "renameat" => Self::Renameat,
            "renameat2" => Self::Renameat2,
            "unlink" => Self::Unlink,
            "unlinkat" => Self::Unlinkat,
            _ => return None,
        })
    }

    /// Numbers from `arch/x86/entry/syscalls/syscall_64.tbl` and the generic
    /// `include/uapi/asm-generic/unistd.h` table aarch64 uses. aarch64 has no
    /// `open`, `rename` or `unlink`; only their `*at` forms exist there.
    const fn numbered(arch: Arch, number: u32) -> Option<Self> {
        Some(match (arch, number) {
            (Arch::X86_64, 2) => Self::Open,
            (Arch::X86_64, 257) | (Arch::Aarch64, 56) => Self::Openat,
            (Arch::X86_64, 3) | (Arch::Aarch64, 57) => Self::Close,
            (Arch::X86_64, 42) | (Arch::Aarch64, 203) => Self::Connect,
            (Arch::X86_64, 44) | (Arch::Aarch64, 206) => Self::Sendto,
            (Arch::X86_64, 46) | (Arch::Aarch64, 211) => Self::Sendmsg,
            (Arch::X86_64, 59) | (Arch::Aarch64, 221) => Self::Execve,
            (Arch::X86_64, 322) | (Arch::Aarch64, 281) => Self::Execveat,
            (Arch::X86_64, 76) | (Arch::Aarch64, 45) => Self::Truncate,
            (Arch::X86_64, 82) => Self::Rename,
            (Arch::X86_64, 264) | (Arch::Aarch64, 38) => Self::Renameat,
            (Arch::X86_64, 316) | (Arch::Aarch64, 276) => Self::Renameat2,
            (Arch::X86_64, 87) => Self::Unlink,
            (Arch::X86_64, 263) | (Arch::Aarch64, 35) => Self::Unlinkat,
            _ => return None,
        })
    }
}

/// The syscall a `type=SYSCALL` record names, if it is one Topgent reads.
///
/// `None` for a syscall outside the list above, for a number whose record has
/// no architecture this build models, and for a record with no syscall field.
pub(crate) fn syscall(line: &str) -> Option<Syscall> {
    let raw = field(line, "syscall")?;
    match raw.parse::<u32>() {
        Ok(number) => Syscall::numbered(Arch::of(line)?, number),
        Err(_) => Syscall::named(raw),
    }
}

#[cfg(test)]
mod tests {
    use super::{Syscall, syscall};

    const X86: &str = "arch=c000003e";
    const ARM: &str = "arch=c00000b7";

    fn record(arch: &str, number: &str) -> String {
        format!("type=SYSCALL msg=audit(1.0:1): {arch} syscall={number} success=yes pid=7")
    }

    /// The collisions that made the old mixed table wrong, one per line.
    #[test]
    fn one_number_means_different_syscalls_on_each_architecture() {
        assert_eq!(syscall(&record(X86, "56")), None, "x86-64 56 is clone");
        assert_eq!(syscall(&record(ARM, "56")), Some(Syscall::Openat));
        assert_eq!(syscall(&record(X86, "82")), Some(Syscall::Rename));
        assert_eq!(syscall(&record(ARM, "82")), None, "aarch64 82 is fsync");
        assert_eq!(syscall(&record(X86, "57")), None, "x86-64 57 is fork");
        assert_eq!(syscall(&record(ARM, "57")), Some(Syscall::Close));
        assert_eq!(syscall(&record(ARM, "46")), None, "aarch64 46 is ftruncate");
        assert_eq!(syscall(&record(X86, "46")), Some(Syscall::Sendmsg));
        assert_eq!(
            syscall(&record(X86, "221")),
            None,
            "x86-64 221 is fadvise64"
        );
        assert_eq!(syscall(&record(ARM, "221")), Some(Syscall::Execve));
    }

    /// `rm` on aarch64 calls `unlinkat`, 35. The old table had no entry for
    /// it, so a delete on the lab's own architecture was never seen.
    #[test]
    fn aarch64_deletes_and_renames_are_named() {
        assert_eq!(syscall(&record(ARM, "35")), Some(Syscall::Unlinkat));
        assert_eq!(syscall(&record(ARM, "38")), Some(Syscall::Renameat));
        assert_eq!(syscall(&record(ARM, "276")), Some(Syscall::Renameat2));
        assert_eq!(syscall(&record(ARM, "45")), Some(Syscall::Truncate));
        assert_eq!(syscall(&record(X86, "35")), None, "x86-64 35 is nanosleep");
    }

    #[test]
    fn a_number_without_a_known_architecture_names_nothing() {
        assert_eq!(
            syscall("type=SYSCALL msg=audit(1.0:1): syscall=42 pid=7"),
            None
        );
        assert_eq!(syscall(&record("arch=40000003", "42")), None, "i386");
        assert_eq!(syscall(&record("arch=nonsense", "203")), None);
    }

    #[test]
    fn a_named_syscall_is_read_on_any_architecture() {
        assert_eq!(syscall(&record(ARM, "connect")), Some(Syscall::Connect));
        assert_eq!(syscall("syscall=unlinkat pid=7"), Some(Syscall::Unlinkat));
        assert_eq!(syscall(&record(X86, "fsync")), None);
    }

    /// A real aarch64 record from the Kali lab, including the enriched tail
    /// auditd appends after an ASCII group separator.
    #[test]
    fn reads_a_real_enriched_kali_record() {
        let line = "type=SYSCALL msg=audit(1788813135.247:432356): arch=c00000b7 syscall=203 \
                    success=yes exit=0 a0=3 a1=aaaadaad5c80 a2=10 a3=0 items=0 ppid=1648465 \
                    pid=1648471 comm=\"python\" key=\"topgent\"\u{1d}ARCH=aarch64 SYSCALL=connect";
        assert_eq!(syscall(line), Some(Syscall::Connect));
    }

    #[test]
    fn hostile_numbers_name_nothing() {
        for raw in ["-1", "4294967296", "99999999999999999999", "", "0x2a"] {
            assert_eq!(syscall(&record(X86, raw)), None, "{raw}");
        }
    }
}
