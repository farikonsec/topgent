//! Syscall arguments as the rules expect to read them.
//!
//! The catalogue was written against a sensor that prints arguments by name:
//! `O_CREAT|O_WRONLY`, `S_IXUSR`, `PTRACE_ATTACH`, `AF_PACKET`, `ENOENT`. The
//! Audit log records the numbers. These turn one into the other, for the
//! values both Linux architectures Topgent reads share.

/// Error numbers the rules and their readers meet, by name.
const ERRORS: [(i64, &str); 22] = [
    (1, "EPERM"),
    (2, "ENOENT"),
    (3, "ESRCH"),
    (4, "EINTR"),
    (9, "EBADF"),
    (11, "EAGAIN"),
    (12, "ENOMEM"),
    (13, "EACCES"),
    (14, "EFAULT"),
    (16, "EBUSY"),
    (17, "EEXIST"),
    (20, "ENOTDIR"),
    (21, "EISDIR"),
    (22, "EINVAL"),
    (30, "EROFS"),
    (38, "ENOSYS"),
    (39, "ENOTEMPTY"),
    (95, "EOPNOTSUPP"),
    (101, "ENETUNREACH"),
    (110, "ETIMEDOUT"),
    (111, "ECONNREFUSED"),
    (115, "EINPROGRESS"),
];

/// `SUCCESS`, or the error's name for a negative return value.
pub(super) fn result(exit: i64) -> String {
    if exit >= 0 {
        return "SUCCESS".to_owned();
    }
    let number = exit.saturating_neg();
    ERRORS
        .iter()
        .find(|(n, _)| *n == number)
        .map_or_else(|| format!("E{number}"), |(_, name)| (*name).to_owned())
}

/// Flags with the same value on x86-64 and aarch64. The ones that differ
/// (`O_DIRECTORY`, `O_NOFOLLOW`, `O_LARGEFILE`) are left out rather than
/// read with the wrong table.
const OPEN_FLAGS: [(u64, &str); 5] = [
    (0o100, "O_CREAT"),
    (0o200, "O_EXCL"),
    (0o1000, "O_TRUNC"),
    (0o2000, "O_APPEND"),
    (0o4000, "O_NONBLOCK"),
];

/// Open flags by name, access mode first.
pub(super) fn open_flags(flags: u64) -> String {
    let access = match flags & 0o3 {
        0 => "O_RDONLY",
        1 => "O_WRONLY",
        _ => "O_RDWR",
    };
    std::iter::once(access)
        .chain(
            OPEN_FLAGS
                .iter()
                .filter(|(bit, _)| flags & bit != 0)
                .map(|(_, name)| *name),
        )
        .collect::<Vec<_>>()
        .join("|")
}

const MODE_BITS: [(u64, &str); 12] = [
    (0o4000, "S_ISUID"),
    (0o2000, "S_ISGID"),
    (0o1000, "S_ISVTX"),
    (0o400, "S_IRUSR"),
    (0o200, "S_IWUSR"),
    (0o100, "S_IXUSR"),
    (0o40, "S_IRGRP"),
    (0o20, "S_IWGRP"),
    (0o10, "S_IXGRP"),
    (0o4, "S_IROTH"),
    (0o2, "S_IWOTH"),
    (0o1, "S_IXOTH"),
];

/// Mode bits by name.
pub(super) fn mode(mode: u64) -> String {
    MODE_BITS
        .iter()
        .filter(|(bit, _)| mode & bit != 0)
        .map(|(_, name)| *name)
        .collect::<Vec<_>>()
        .join("|")
}

const PTRACE: [(u64, &str); 18] = [
    (0, "PTRACE_TRACEME"),
    (1, "PTRACE_PEEKTEXT"),
    (2, "PTRACE_PEEKDATA"),
    (3, "PTRACE_PEEKUSR"),
    (4, "PTRACE_POKETEXT"),
    (5, "PTRACE_POKEDATA"),
    (6, "PTRACE_POKEUSR"),
    (7, "PTRACE_CONT"),
    (8, "PTRACE_KILL"),
    (9, "PTRACE_SINGLESTEP"),
    (12, "PTRACE_GETREGS"),
    (13, "PTRACE_SETREGS"),
    (16, "PTRACE_ATTACH"),
    (17, "PTRACE_DETACH"),
    (0x4204, "PTRACE_GETREGSET"),
    (0x4205, "PTRACE_SETREGSET"),
    (0x4206, "PTRACE_SEIZE"),
    (0x4207, "PTRACE_INTERRUPT"),
];

/// A ptrace request by name, or its number.
pub(super) fn ptrace_request(request: u64) -> String {
    PTRACE
        .iter()
        .find(|(n, _)| *n == request)
        .map_or_else(|| request.to_string(), |(_, name)| (*name).to_owned())
}

const DOMAINS: [(u64, &str); 5] = [
    (1, "AF_UNIX"),
    (2, "AF_INET"),
    (10, "AF_INET6"),
    (16, "AF_NETLINK"),
    (17, "AF_PACKET"),
];

/// A socket domain by name, or its number.
pub(super) fn socket_domain(domain: u64) -> String {
    DOMAINS
        .iter()
        .find(|(n, _)| *n == domain)
        .map_or_else(|| domain.to_string(), |(_, name)| (*name).to_owned())
}

/// A terminal as a device number: 0 for none. Pseudo-terminals are major 136,
/// virtual consoles major 4, as the kernel numbers them.
/// Every Linux capability by bit, up to `CAP_CHECKPOINT_RESTORE` (40). The
/// rules test the set by name (`thread.cap_permitted contains CAP_SYS_MODULE`).
const CAPABILITIES: [&str; 41] = [
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_KILL",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETPCAP",
    "CAP_LINUX_IMMUTABLE",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_BROADCAST",
    "CAP_NET_ADMIN",
    "CAP_NET_RAW",
    "CAP_IPC_LOCK",
    "CAP_IPC_OWNER",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_CHROOT",
    "CAP_SYS_PTRACE",
    "CAP_SYS_PACCT",
    "CAP_SYS_ADMIN",
    "CAP_SYS_BOOT",
    "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE",
    "CAP_SYS_TIME",
    "CAP_SYS_TTY_CONFIG",
    "CAP_MKNOD",
    "CAP_LEASE",
    "CAP_AUDIT_WRITE",
    "CAP_AUDIT_CONTROL",
    "CAP_SETFCAP",
    "CAP_MAC_OVERRIDE",
    "CAP_MAC_ADMIN",
    "CAP_SYSLOG",
    "CAP_WAKE_ALARM",
    "CAP_BLOCK_SUSPEND",
    "CAP_AUDIT_READ",
    "CAP_PERFMON",
    "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE",
];

/// The names of the capabilities set in `mask`, space-separated, so a rule's
/// `contains CAP_SYS_ADMIN` finds one. Empty when none is set. A bit past the
/// known names is shown as `CAP_<n>`, so an added capability is never silently
/// dropped.
pub(super) fn capabilities(mask: u64) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for bit in 0u32..64 {
        if mask & (1u64 << bit) == 0 {
            continue;
        }
        if !out.is_empty() {
            out.push(' ');
        }
        match CAPABILITIES.get(bit as usize) {
            Some(name) => out.push_str(name),
            None => {
                let _ = write!(out, "CAP_{bit}");
            }
        }
    }
    out
}

pub(super) fn tty_number(tty: Option<&str>) -> String {
    let Some(tty) = tty else {
        return "0".to_owned();
    };
    let (major, minor) = if let Some(n) = tty.strip_prefix("pts") {
        (136, n)
    } else if let Some(n) = tty.strip_prefix("tty") {
        (4, n)
    } else {
        (0, "")
    };
    let minor: u64 = minor.parse().unwrap_or(0);
    // Any terminal at all is nonzero.
    ((major << 20) | minor).max(1).to_string()
}

#[cfg(test)]
mod tests {
    use super::{
        capabilities, mode, open_flags, ptrace_request, result, socket_domain, tty_number,
    };

    #[test]
    fn capability_masks_become_the_names_rules_test_for() {
        // CAP_SYS_MODULE is bit 16, CAP_SYS_ADMIN bit 21.
        let mask = (1u64 << 16) | (1u64 << 21);
        let text = capabilities(mask);
        assert!(text.contains("CAP_SYS_MODULE"), "{text}");
        assert!(text.contains("CAP_SYS_ADMIN"), "{text}");
        assert_eq!(capabilities(0), "");
        // A full root set contains a common check without a false hit.
        let full = capabilities(u64::MAX);
        assert!(full.contains("CAP_DAC_OVERRIDE") && full.contains("CAP_BPF"));
        // A bit past the named range is shown, not dropped.
        assert!(capabilities(1u64 << 62).contains("CAP_62"));
    }

    #[test]
    fn results_are_named_like_the_rules_expect() {
        assert_eq!(result(0), "SUCCESS");
        assert_eq!(result(3), "SUCCESS");
        assert_eq!(result(-2), "ENOENT");
        assert_eq!(result(-13), "EACCES");
        assert_eq!(result(-111), "ECONNREFUSED");
        assert_eq!(result(-115), "EINPROGRESS");
        assert!(
            result(-4095).starts_with('E'),
            "an unnamed error is still an error"
        );
    }

    #[test]
    fn open_flags_name_the_access_mode_and_the_shared_flags() {
        assert_eq!(open_flags(0), "O_RDONLY");
        // O_WRONLY | O_CREAT | O_TRUNC, as `echo x > f` opens.
        assert_eq!(open_flags(0o1101), "O_WRONLY|O_CREAT|O_TRUNC");
        assert!(open_flags(0o2002).contains("O_APPEND"));
        assert!(open_flags(0o2002).starts_with("O_RDWR"));
    }

    #[test]
    fn modes_name_every_bit() {
        assert_eq!(mode(0o600), "S_IRUSR|S_IWUSR");
        let setuid = mode(0o4755);
        for bit in ["S_ISUID", "S_IXUSR", "S_IXGRP", "S_IXOTH"] {
            assert!(setuid.contains(bit), "{setuid} lacks {bit}");
        }
    }

    #[test]
    fn requests_and_domains_are_named() {
        assert_eq!(ptrace_request(0), "PTRACE_TRACEME");
        assert_eq!(ptrace_request(16), "PTRACE_ATTACH");
        assert_eq!(ptrace_request(0x4206), "PTRACE_SEIZE");
        // aarch64's register set call contains the name the rules test for.
        assert!(ptrace_request(0x4205).contains("PTRACE_SETREGS"));
        assert_eq!(ptrace_request(99_999), "99999");
        assert_eq!(socket_domain(17), "AF_PACKET");
        assert_eq!(socket_domain(2), "AF_INET");
    }

    #[test]
    fn a_terminal_is_a_nonzero_number_and_none_is_zero() {
        assert_eq!(tty_number(None), "0");
        assert_ne!(tty_number(Some("pts0")), "0");
        assert_ne!(tty_number(Some("pts1")), tty_number(Some("pts0")));
    }
}
