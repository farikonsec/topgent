//! The syscalls the behaviour rules react to, by number, per architecture.
//!
//! Forty-one calls. aarch64 has no legacy `open`, `creat`, `link`, `unlink`,
//! `rename`, `mkdir`, `rmdir`, `symlink`, `chmod` or `dup2`: its programs use
//! the `*at` forms, which is why both tables are needed and neither is
//! guessed from the other.

use super::Arch;
use topgent_ebpf_common::{SYSCALL_NUMBERS_AARCH64 as AARCH64, SYSCALL_NUMBERS_X86_64 as X86_64};

/// Every call name a rule's `evt.type` can test for.
pub(super) const RULE_SYSCALLS: [&str; 43] = [
    "accept",
    "accept4",
    "bpf",
    "chmod",
    "connect",
    "creat",
    "dup",
    "dup2",
    "dup3",
    "execve",
    "execveat",
    "fchmod",
    "fchmodat",
    "finit_module",
    "init_module",
    "link",
    "linkat",
    "listen",
    "mkdir",
    "mkdirat",
    "open",
    "openat",
    "openat2",
    "ptrace",
    "recvfrom",
    "recvmsg",
    "rename",
    "renameat",
    "renameat2",
    "rmdir",
    "sendmsg",
    "sendto",
    "setns",
    "setuid",
    "socket",
    "symlink",
    "symlinkat",
    "unlink",
    "unlinkat",
    "unshare",
    "userfaultfd",
    "write",
    "writev",
];

/// The rule-relevant call a numbered record names on `arch`.
pub(super) fn numbered(arch: Arch, number: u32) -> Option<&'static str> {
    let table: &[(u32, &str)] = match arch {
        Arch::X86_64 => &X86_64,
        Arch::Aarch64 => &AARCH64,
    };
    table
        .iter()
        .find(|(n, _)| *n == number)
        .map(|(_, name)| *name)
}

/// The rule-relevant call a record names by name (`ausearch -i` output,
/// or the eBPF sensor's `sys` line).
pub(crate) fn named(name: &str) -> Option<&'static str> {
    RULE_SYSCALLS.iter().find(|known| **known == name).copied()
}

#[cfg(test)]
mod tests {
    use super::{AARCH64, RULE_SYSCALLS, X86_64};

    /// Every number names a call the rules use, and every such call exists
    /// on x86-64; the ten aarch64 lacks are exactly its legacy calls.
    #[test]
    fn the_tables_cover_the_rule_calls_and_nothing_else() {
        for (_, name) in X86_64.iter().chain(AARCH64.iter()) {
            assert!(RULE_SYSCALLS.contains(name), "{name}");
        }
        let x86: Vec<&str> = X86_64.iter().map(|(_, n)| *n).collect();
        assert!(RULE_SYSCALLS.iter().all(|n| x86.contains(n)));
        let missing: Vec<&str> = RULE_SYSCALLS
            .iter()
            .filter(|n| !AARCH64.iter().any(|(_, a)| a == *n))
            .copied()
            .collect();
        assert_eq!(
            missing,
            [
                "chmod", "creat", "dup2", "link", "mkdir", "open", "rename", "rmdir", "symlink",
                "unlink"
            ]
        );
    }
}
