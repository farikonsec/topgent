//! What Topgent's kernel probe tells user space, laid out once for both sides.
//!
//! The probe (`topgent-ebpf-probe`, built for the BPF target) writes
//! [`ProcessEvent`]s into the ring buffer named [`EVENTS_MAP`];
//! `topgent-ebpf` reads them back with [`ProcessEvent::decode`]. Both sides
//! compile this one file, so the layout cannot drift between them.
//!
//! The probe never assumes one kernel's struct layout. It reads only
//! tracepoint records, and where each field sits in a record is looked up by
//! the loader from the kernel's own description and written into the probe
//! before it loads ([`FIELD_SETTINGS`]).

#![cfg_attr(not(test), no_std)]

use core::mem::{offset_of, size_of};

/// Ring buffer the probe writes [`ProcessEvent`]s into.
pub const EVENTS_MAP: &str = "EVENTS";
/// Per-CPU count of events dropped because [`EVENTS_MAP`] was full.
pub const LOST_MAP: &str = "LOST";
/// Size of [`EVENTS_MAP`] in bytes. The kernel requires a power of two and a
/// multiple of the page size.
pub const EVENTS_BYTES: u32 = 1 << 20;

/// Slot of [`LOST_MAP`] counting lost [`ProcessEvent`]s.
pub const LOST_EVENTS: u32 = 0;
/// Slot of [`LOST_MAP`] counting lost [`SyscallRecord`]s.
pub const LOST_SYSCALLS: u32 = 1;

/// Ring buffer the probe writes [`SyscallRecord`]s into. Separate from
/// [`EVENTS_MAP`] so a flood of file opens can never cost a fork or an exec,
/// which attribution depends on.
pub const SYSCALLS_MAP: &str = "SYSCALLS";
/// Size of [`SYSCALLS_MAP`] in bytes: room for about 3,300 records between
/// two drains.
pub const SYSCALLS_BYTES: u32 = 1 << 22;
/// Map from a syscall's number to its [`SyscallSpec`], packed. The loader
/// fills it; a call with no entry is not reported.
///
/// Keyed by number, not by tracepoint id: for a BPF program on a syscall
/// tracepoint the kernel overwrites the record's first 8 bytes, where
/// `common_type` would be, with a register pointer (`perf_call_bpf_enter`).
/// `__syscall_nr` survives.
pub const SPECS_MAP: &str = "SPECS";
/// Most entries [`SPECS_MAP`] holds.
pub const SPECS_MAX: u32 = 64;
/// Map from a thread to the call it is inside, held from enter to exit.
pub const PENDING_MAP: &str = "PENDING";
/// Most threads [`PENDING_MAP`] tracks at once. It is an LRU map, so a
/// thread whose exit never comes is forgotten, not leaked.
pub const PENDING_MAX: u32 = 16_384;

/// Map from a process's descriptor (`tgid << 32 | fd`) to the kind of
/// socket it is ([`SocketKind::pack`]), kept by the probe as sockets are
/// made, copied and closed, so a network call can say whether it is TCP or
/// UDP.
pub const SOCKETS_MAP: &str = "SOCKETS";
/// Most descriptors [`SOCKETS_MAP`] tracks. LRU: an entry whose process
/// ended without closing it is forgotten under pressure, not leaked.
pub const SOCKETS_MAX: u32 = 65_536;
/// Program forgetting a closed descriptor, attached to
/// `syscalls/sys_enter_close`.
pub const CLOSE_PROGRAM: &str = "on_close";
/// Set in [`SyscallRecord::socket`] when the probe knew the call's socket.
pub const SOCKET_KNOWN: u32 = 1 << 31;

/// What a socket is: `socket(domain, type, protocol)`, as it was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketKind {
    /// Address family: 2 IPv4, 10 IPv6, 1 local.
    pub domain: u8,
    /// `SOCK_STREAM` 1, `SOCK_DGRAM` 2, `SOCK_RAW` 3, flags removed.
    pub kind: u8,
    /// The protocol asked for, 0 for the family's default; 255 for any
    /// number above 254 (`IPPROTO_MPTCP` is 262).
    pub protocol: u8,
}

impl SocketKind {
    /// From the arguments of `socket`.
    #[must_use]
    // Each cast is of a value already bounded to fit; `TryFrom` is not
    // `const`, and the probe calls this.
    #[allow(clippy::cast_possible_truncation)]
    pub const fn from_args(domain: u64, kind: u64, protocol: u64) -> Self {
        Self {
            domain: if domain > 255 { 255 } else { domain as u8 },
            // The low four bits; the rest are SOCK_NONBLOCK, SOCK_CLOEXEC.
            kind: (kind & 0xf) as u8,
            protocol: if protocol > 254 { 255 } else { protocol as u8 },
        }
    }

    /// As [`SOCKETS_MAP`] holds it.
    #[must_use]
    pub const fn pack(self) -> u32 {
        ((self.domain as u32) << 16) | ((self.kind as u32) << 8) | self.protocol as u32
    }

    /// From [`SyscallRecord::socket`]: `None` when the probe did not know.
    #[must_use]
    // Truncation intended: each field is one byte of the packed value.
    #[allow(clippy::cast_possible_truncation)]
    pub const fn unpack(value: u32) -> Option<Self> {
        if value & SOCKET_KNOWN == 0 {
            return None;
        }
        Some(Self {
            domain: (value >> 16) as u8,
            kind: (value >> 8) as u8,
            protocol: value as u8,
        })
    }
}

/// What a syscall does to the probe's socket table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SocketRole {
    /// Nothing.
    None = 0,
    /// Makes a socket, returned as the result (`socket`).
    Makes = 1,
    /// Returns a new descriptor for the socket in its first argument
    /// (`accept`, `dup`), which is the same kind.
    Copies = 2,
    /// Acts on the socket in its first argument (`connect`, `sendto`, …).
    Uses = 3,
    /// Receives on the socket in its first argument (`recvfrom`,
    /// `recvmsg`). As [`SocketRole::Uses`], but reported only with an IPv4
    /// or IPv6 sender on a socket not known to be a stream: the only
    /// receive the rules read is inbound UDP from a named peer.
    Receives = 4,
    /// Writes to the descriptor in its first argument (`write`, `writev`),
    /// which may or may not be a socket. Kept only on an IPv4 or IPv6
    /// socket the probe saw made; summed per socket in [`SENT_MAP`] and
    /// reported as one record per [`SEND_REPORT_BYTES`], and once more for
    /// the remainder when the socket is closed. The record's result is the
    /// bytes in that sum, not one call's.
    Sends = 5,
}

/// Bytes a socket's writes add up to before they are reported. Most HTTP
/// requests are one record, at close; a 300 MB upload is about 4,800.
pub const SEND_REPORT_BYTES: u64 = 64 * 1024;
/// The probe's per-socket write sums, keyed as [`SOCKETS_MAP`]. Each value
/// is the syscall number in its top 16 bits and the bytes not yet reported
/// below them.
pub const SENT_MAP: &str = "SENT";

/// Program reporting a syscall's arguments, attached to each
/// `syscalls/sys_enter_<name>` of [`SYSCALL_SPECS`].
pub const SYS_ENTER_PROGRAM: &str = "on_sys_enter";
/// Program reporting its result, attached to each `syscalls/sys_exit_<name>`.
pub const SYS_EXIT_PROGRAM: &str = "on_sys_exit";
/// Tracepoint category of both.
pub const SYSCALLS_CATEGORY: &str = "syscalls";
/// Probe global: offset of `__syscall_nr` in enter and exit records.
pub const SYS_NR: &str = "SYS_NR";
/// Probe global: offset of the first argument in an enter record. Every
/// syscall's enter record has its arguments at this offset and 8 bytes
/// apart; the loader checks that for each call before attaching.
pub const SYS_ARGS: &str = "SYS_ARGS";
/// Probe global: offset of the result in an exit record.
pub const SYS_RET: &str = "SYS_RET";

/// Longest path kept from a syscall, including its terminating NUL. A path
/// that fills the slot may have been cut, and is not passed on as whole.
pub const PATH_LEN: usize = 512;
/// Longest socket address kept: `sizeof(struct sockaddr_storage)`.
pub const ADDR_LEN: usize = 128;
/// Arguments a syscall has at most.
pub const ARGS: usize = 6;
/// An argument slot a [`SyscallSpec`] does not use.
pub const NO_ARG: u8 = 0xff;

/// Most exec arguments the probe reads. An exec with more is reported with
/// no arguments, never with some of them.
pub const ARGV_MAX: usize = 16;
/// Longest exec argument kept, with its NUL. An argument that fills the
/// slot may have been cut, and the exec is then reported with no arguments.
pub const ARG_LEN: usize = 256;

/// Programs reading an exec's arguments, the syscall each attaches to
/// (`syscalls/sys_enter_<name>`), and which argument is `argv`.
pub const ARGV_PROGRAMS: [(&str, &str, u8); 2] = [
    ("on_execve_args", "execve", 1),
    ("on_execveat_args", "execveat", 2),
];

/// Where a call's socket address is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Addr {
    /// None.
    None = 0,
    /// Passed in: a pointer and a length (`connect`, `sendto`).
    In = 1,
    /// Filled in by the kernel: a pointer and a pointer to the length
    /// (`accept`, `recvfrom`). Only read when the call succeeded.
    Out = 2,
    /// In the `msghdr` the argument points to (`sendmsg`, `recvmsg`).
    Msg = 3,
}

/// The rule syscalls by number on x86-64, as the kernel numbers them there.
/// Shared with the Audit reader, which reads the same numbers from its log.
pub const SYSCALL_NUMBERS_X86_64: [(u32, &str); 43] = [
    (1, "write"),
    (2, "open"),
    (20, "writev"),
    (32, "dup"),
    (33, "dup2"),
    (41, "socket"),
    (42, "connect"),
    (43, "accept"),
    (44, "sendto"),
    (45, "recvfrom"),
    (46, "sendmsg"),
    (47, "recvmsg"),
    (50, "listen"),
    (59, "execve"),
    (82, "rename"),
    (83, "mkdir"),
    (84, "rmdir"),
    (85, "creat"),
    (86, "link"),
    (87, "unlink"),
    (88, "symlink"),
    (90, "chmod"),
    (91, "fchmod"),
    (101, "ptrace"),
    (105, "setuid"),
    (175, "init_module"),
    (257, "openat"),
    (258, "mkdirat"),
    (263, "unlinkat"),
    (264, "renameat"),
    (265, "linkat"),
    (266, "symlinkat"),
    (268, "fchmodat"),
    (272, "unshare"),
    (288, "accept4"),
    (292, "dup3"),
    (308, "setns"),
    (313, "finit_module"),
    (316, "renameat2"),
    (321, "bpf"),
    (322, "execveat"),
    (323, "userfaultfd"),
    (437, "openat2"),
];

/// The same on aarch64, which has no `open`, `creat`, `link`, `unlink`,
/// `rename`, `mkdir`, `rmdir`, `symlink`, `chmod` or `dup2`: its programs use
/// the `*at` forms.
pub const SYSCALL_NUMBERS_AARCH64: [(u32, &str); 33] = [
    (23, "dup"),
    (24, "dup3"),
    (34, "mkdirat"),
    (35, "unlinkat"),
    (36, "symlinkat"),
    (37, "linkat"),
    (38, "renameat"),
    (52, "fchmod"),
    (53, "fchmodat"),
    (56, "openat"),
    (64, "write"),
    (66, "writev"),
    (97, "unshare"),
    (105, "init_module"),
    (117, "ptrace"),
    (146, "setuid"),
    (198, "socket"),
    (201, "listen"),
    (202, "accept"),
    (203, "connect"),
    (206, "sendto"),
    (207, "recvfrom"),
    (211, "sendmsg"),
    (212, "recvmsg"),
    (221, "execve"),
    (242, "accept4"),
    (268, "setns"),
    (273, "finit_module"),
    (276, "renameat2"),
    (280, "bpf"),
    (281, "execveat"),
    (282, "userfaultfd"),
    (437, "openat2"),
];

/// The rule syscall numbers of the architecture this was compiled for,
/// which is the architecture the probe runs on. Syscall tracepoints ignore
/// 32-bit compat calls, whose numbers differ, so these are the only numbers
/// they carry.
#[must_use]
pub const fn syscall_numbers() -> &'static [(u32, &'static str)] {
    if cfg!(target_arch = "aarch64") {
        &SYSCALL_NUMBERS_AARCH64
    } else {
        &SYSCALL_NUMBERS_X86_64
    }
}

/// Which of a syscall's arguments the probe reads more than the value of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyscallSpec {
    /// The call's name, as `syscalls/sys_enter_<name>` and the rules have it.
    pub name: &'static str,
    /// Argument holding the path the call acts on, or [`NO_ARG`].
    pub path: u8,
    /// A second path: a rename's or link's new name, a symlink's target.
    pub path2: u8,
    /// How the call carries a socket address.
    pub addr: Addr,
    /// Argument holding the address (or `msghdr`) pointer.
    pub addr_arg: u8,
    /// Argument holding its length, or a pointer to it.
    pub addr_len_arg: u8,
    /// Argument holding an open's flags. When set, a read-only open of a
    /// path under `/proc/` is dropped in the kernel (see `docs/ebpf/PLAN.md`,
    /// E4).
    pub open_flags: u8,
    /// What it does to the socket table.
    pub socket: SocketRole,
    /// What a relative [`SyscallSpec::path`] is looked up from, as a
    /// [`Base`].
    pub path_base: Base,
    /// Likewise for [`SyscallSpec::path2`].
    pub path2_base: Base,
}

/// What a call's relative path is looked up from. The probe sends the
/// working directory only with a call where it is the answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Base {
    /// Nothing: no such path, or a symbolic link's target, which is text.
    Never = 0,
    /// The working directory (`open`, `rename`, …).
    Cwd = 1,
    /// The directory in the argument just before the path, the working
    /// directory when that is `AT_FDCWD` (every `*at` call).
    DirBefore = 2,
}

const fn plain(name: &'static str) -> SyscallSpec {
    SyscallSpec {
        name,
        path: NO_ARG,
        path2: NO_ARG,
        addr: Addr::None,
        addr_arg: NO_ARG,
        addr_len_arg: NO_ARG,
        open_flags: NO_ARG,
        socket: SocketRole::None,
        path_base: Base::Never,
        path2_base: Base::Never,
    }
}

/// An `*at` call: each path is looked up from the directory argument just
/// before it.
const fn at(spec: SyscallSpec) -> SyscallSpec {
    SyscallSpec {
        path_base: if spec.path == NO_ARG {
            Base::Never
        } else {
            Base::DirBefore
        },
        path2_base: if spec.path2 == NO_ARG {
            Base::Never
        } else {
            Base::DirBefore
        },
        ..spec
    }
}

/// A call whose second path is a symbolic link's target: text, never
/// looked up.
const fn target(spec: SyscallSpec) -> SyscallSpec {
    SyscallSpec {
        path2_base: Base::Never,
        ..spec
    }
}

const fn with_socket(spec: SyscallSpec, socket: SocketRole) -> SyscallSpec {
    SyscallSpec { socket, ..spec }
}

const fn paths(name: &'static str, path: u8, path2: u8) -> SyscallSpec {
    SyscallSpec {
        path,
        path2,
        path_base: if path == NO_ARG {
            Base::Never
        } else {
            Base::Cwd
        },
        path2_base: if path2 == NO_ARG {
            Base::Never
        } else {
            Base::Cwd
        },
        ..plain(name)
    }
}

const fn open(name: &'static str, path: u8, flags: u8) -> SyscallSpec {
    SyscallSpec {
        open_flags: flags,
        ..paths(name, path, NO_ARG)
    }
}

const fn addressed(name: &'static str, addr: Addr, at: u8, len: u8) -> SyscallSpec {
    SyscallSpec {
        addr,
        addr_arg: at,
        addr_len_arg: len,
        ..plain(name)
    }
}

/// Every syscall the probe reports: the calls the behaviour rules test for,
/// less `execve` and `execveat`, which the lifecycle `exec` already is, plus
/// `write` and `writev` on sockets, summed (see [`SocketRole::Sends`]).
/// Argument positions are the kernel's (`man 2 <name>`). A call this kernel
/// has no tracepoint for (arm64 has no `open`, `rename`, …) is skipped.
pub const SYSCALL_SPECS: [SyscallSpec; 41] = [
    with_socket(addressed("accept", Addr::Out, 1, 2), SocketRole::Copies),
    with_socket(addressed("accept4", Addr::Out, 1, 2), SocketRole::Copies),
    plain("bpf"),
    paths("chmod", 0, NO_ARG),
    with_socket(addressed("connect", Addr::In, 1, 2), SocketRole::Uses),
    // Always a write, so never dropped.
    paths("creat", 0, NO_ARG),
    with_socket(plain("dup"), SocketRole::Copies),
    with_socket(plain("dup2"), SocketRole::Copies),
    with_socket(plain("dup3"), SocketRole::Copies),
    plain("fchmod"),
    at(paths("fchmodat", 1, NO_ARG)),
    plain("finit_module"),
    plain("init_module"),
    paths("link", 0, 1),
    at(paths("linkat", 1, 3)),
    with_socket(plain("listen"), SocketRole::Uses),
    paths("mkdir", 0, NO_ARG),
    at(paths("mkdirat", 1, NO_ARG)),
    open("open", 0, 1),
    at(open("openat", 1, 2)),
    // Its flags are inside a structure, so it is never dropped.
    at(paths("openat2", 1, NO_ARG)),
    plain("ptrace"),
    with_socket(addressed("recvfrom", Addr::Out, 4, 5), SocketRole::Receives),
    with_socket(
        addressed("recvmsg", Addr::Msg, 1, NO_ARG),
        SocketRole::Receives,
    ),
    paths("rename", 0, 1),
    at(paths("renameat", 1, 3)),
    at(paths("renameat2", 1, 3)),
    paths("rmdir", 0, NO_ARG),
    with_socket(addressed("sendmsg", Addr::Msg, 1, NO_ARG), SocketRole::Uses),
    with_socket(addressed("sendto", Addr::In, 4, 5), SocketRole::Uses),
    plain("setns"),
    plain("setuid"),
    with_socket(plain("socket"), SocketRole::Makes),
    // The link made is the path; what it points to is the second.
    target(paths("symlink", 1, 0)),
    target(at(paths("symlinkat", 2, 0))),
    paths("unlink", 0, NO_ARG),
    at(paths("unlinkat", 1, NO_ARG)),
    plain("unshare"),
    plain("userfaultfd"),
    // Bytes out on a socket the probe saw made, for the workspace
    // exfiltration rule. Every other write is dropped before it is kept.
    with_socket(plain("write"), SocketRole::Sends),
    with_socket(plain("writev"), SocketRole::Sends),
];

impl SyscallSpec {
    /// The spec as the probe's [`SPECS_MAP`] holds it, with the number of
    /// arguments this kernel's tracepoint records: one byte per field,
    /// lowest first, in the order of [`unpack`]. The count byte also holds
    /// each path's [`Base`], in bits 3-4 and 5-6.
    #[must_use]
    pub const fn pack(&self, args: u8) -> u64 {
        u64::from_le_bytes([
            self.path,
            self.path2,
            self.addr as u8,
            self.addr_arg,
            self.addr_len_arg,
            self.open_flags,
            // Three bits of count (at most `ARGS`), then each path's base.
            (args & 0x7) | (self.path_base as u8) << 3 | (self.path2_base as u8) << 5,
            self.socket as u8,
        ])
    }
}

/// A packed spec, read back: `(path, path2, addr, addr_arg, addr_len_arg,
/// open_flags, args and bases, socket)`. The probe reads it this way; there is no struct on
/// the kernel side because user space may not implement aya's `Pod` for one
/// without `unsafe`.
#[must_use]
pub const fn unpack(spec: u64) -> [u8; 8] {
    spec.to_le_bytes()
}

/// A call's arguments, held by the probe from enter to exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Pending {
    /// The syscall number: which call.
    pub call: u32,
    /// Always zero; keeps `args` aligned.
    pub pad: u32,
    /// The arguments, zero past the call's own.
    pub args: [u64; ARGS],
}

/// One syscall, exactly as the probe writes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct SyscallRecord {
    /// Nanoseconds since boot at the call's exit.
    pub boot_ns: u64,
    /// The caller's cgroup, as for [`ProcessEvent::cgroup`].
    pub cgroup: u64,
    /// Its result: a descriptor, zero, or a negated error number.
    pub ret: i64,
    /// Its arguments, zero past the call's own.
    pub args: [u64; ARGS],
    /// The caller's effective and permitted capability sets, read from its
    /// credentials through BTF offsets. Meaningful only when `caps_known`.
    pub cap_effective: u64,
    /// See [`SyscallRecord::cap_effective`].
    pub cap_permitted: u64,
    /// The syscall number: which call. The loader maps it to a name.
    pub call: u32,
    /// The process (thread group id).
    pub pid: u32,
    /// The thread.
    pub tid: u32,
    /// Real user id.
    pub uid: u32,
    /// A [`Namespace`], as its number.
    pub pid_namespace: u32,
    /// What reading [`SyscallRecord::path`] gave: its length with the NUL,
    /// a negated error, or zero when the call has no path.
    pub path_read: i32,
    /// The same for [`SyscallRecord::path2`].
    pub path2_read: i32,
    /// Bytes of [`SyscallRecord::addr`] read, zero for none.
    pub addr_read: u32,
    /// The call's socket, packed as [`SocketKind::pack`] with
    /// [`SOCKET_KNOWN`] set, or zero when the probe did not know it: a
    /// socket made before the probe loaded, or inherited from a parent.
    pub socket: u32,
    /// The caller's audit login id, or [`LOGINUID_UNREAD`] when this kernel
    /// has no `task_struct.loginuid` (built without audit).
    pub loginuid: u32,
    /// 1 when the capability sets were read, 0 when they could not be.
    pub caps_known: u32,
    /// 0 for no controlling terminal, 1 when one is present, or [`ABSENT`]
    /// when this kernel's BTF does not expose the required fields.
    pub tty: u32,
    /// Short name of the task.
    pub comm: [u8; COMM_LEN],
    /// The socket address, as the kernel's `struct sockaddr`. Ahead of the
    /// paths, so a record without them can end here (see
    /// [`SyscallRecord::used_len`]).
    pub addr: [u8; ADDR_LEN],
    /// The path the call acted on, NUL-terminated.
    pub path: [u8; PATH_LEN],
    /// The second path, NUL-terminated.
    pub path2: [u8; PATH_LEN],
}

impl SyscallRecord {
    /// Bytes one record takes in the ring buffer, at most.
    pub const SIZE: usize = size_of::<Self>();
    /// The fewest bytes a record is written with: up to its paths.
    pub const MIN_SIZE: usize = offset_of!(Self, path);

    /// A record with every field zero, for the probe to fill in place.
    pub const EMPTY: Self = Self {
        boot_ns: 0,
        cgroup: 0,
        ret: 0,
        args: [0; ARGS],
        cap_effective: 0,
        cap_permitted: 0,
        call: 0,
        pid: 0,
        tid: 0,
        uid: 0,
        pid_namespace: 0,
        path_read: 0,
        path2_read: 0,
        addr_read: 0,
        socket: 0,
        loginuid: LOGINUID_UNREAD,
        caps_known: 0,
        tty: ABSENT,
        comm: [0; COMM_LEN],
        addr: [0; ADDR_LEN],
        path: [0; PATH_LEN],
        path2: [0; PATH_LEN],
    };

    /// Whether the task was in the host's pid namespace.
    #[must_use]
    pub const fn namespace(&self) -> Namespace {
        Namespace::from_u32(self.pid_namespace)
    }

    /// The path, when it was read whole: `None` for no path, a failed read,
    /// or one that filled the slot and so may have been cut.
    #[must_use]
    pub fn path(&self) -> Option<&[u8]> {
        whole(&self.path, self.path_read)
    }

    /// The second path, on the same terms.
    #[must_use]
    pub fn path2(&self) -> Option<&[u8]> {
        whole(&self.path2, self.path2_read)
    }

    /// The socket address bytes read, if any.
    #[must_use]
    pub fn addr(&self) -> Option<&[u8]> {
        let read = usize::try_from(self.addr_read).ok()?;
        (read > 0).then(|| self.addr.get(..read.min(ADDR_LEN)))?
    }

    /// The effective and permitted capability sets, when they were read.
    #[must_use]
    pub const fn capabilities(&self) -> Option<(u64, u64)> {
        if self.caps_known == 1 {
            Some((self.cap_effective, self.cap_permitted))
        } else {
            None
        }
    }

    /// The audit login id, when this kernel had one to read.
    #[must_use]
    pub const fn login_uid(&self) -> Option<u32> {
        if self.loginuid == LOGINUID_UNREAD {
            None
        } else {
            Some(self.loginuid)
        }
    }

    /// Whether the caller had a controlling terminal.
    #[must_use]
    pub const fn has_tty(&self) -> Option<bool> {
        if self.tty == ABSENT {
            None
        } else {
            Some(self.tty != 0)
        }
    }

    /// Reads one record back from ring-buffer bytes, or `None` when the
    /// bytes are not one whole record.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        // Written only as far as its paths go: the rest is zero.
        if bytes.len() < Self::MIN_SIZE || bytes.len() > Self::SIZE {
            return None;
        }
        let mut whole = [0_u8; Self::SIZE];
        whole.get_mut(..bytes.len())?.copy_from_slice(bytes);
        let record = Self::decode_whole(&whole)?;
        // Every byte a length claims must have been sent.
        (record.used_len() <= bytes.len()).then_some(record)
    }

    /// Bytes of the record the probe writes: through the end of the last
    /// path read, or of the address when there is no path.
    #[must_use]
    pub const fn used_len(&self) -> usize {
        if self.path2_read > 0 {
            offset_of!(Self, path2) + within_path(self.path2_read)
        } else if self.path_read > 0 {
            offset_of!(Self, path) + within_path(self.path_read)
        } else {
            Self::MIN_SIZE
        }
    }

    fn decode_whole(bytes: &[u8; Self::SIZE]) -> Option<Self> {
        let u32_at = |at| array_at(bytes, at).map(u32::from_ne_bytes);
        let i32_at = |at| array_at(bytes, at).map(i32::from_ne_bytes);
        let mut args = [0; ARGS];
        for (i, arg) in args.iter_mut().enumerate() {
            *arg = u64::from_ne_bytes(array_at(bytes, offset_of!(Self, args) + i * 8)?);
        }
        Some(Self {
            boot_ns: u64::from_ne_bytes(array_at(bytes, offset_of!(Self, boot_ns))?),
            cgroup: u64::from_ne_bytes(array_at(bytes, offset_of!(Self, cgroup))?),
            ret: i64::from_ne_bytes(array_at(bytes, offset_of!(Self, ret))?),
            args,
            cap_effective: u64::from_ne_bytes(array_at(bytes, offset_of!(Self, cap_effective))?),
            cap_permitted: u64::from_ne_bytes(array_at(bytes, offset_of!(Self, cap_permitted))?),
            call: u32_at(offset_of!(Self, call))?,
            pid: u32_at(offset_of!(Self, pid))?,
            tid: u32_at(offset_of!(Self, tid))?,
            uid: u32_at(offset_of!(Self, uid))?,
            pid_namespace: u32_at(offset_of!(Self, pid_namespace))?,
            path_read: i32_at(offset_of!(Self, path_read))?,
            path2_read: i32_at(offset_of!(Self, path2_read))?,
            addr_read: u32_at(offset_of!(Self, addr_read))?,
            socket: u32_at(offset_of!(Self, socket))?,
            loginuid: u32_at(offset_of!(Self, loginuid))?,
            caps_known: u32_at(offset_of!(Self, caps_known))?,
            tty: u32_at(offset_of!(Self, tty))?,
            comm: array_at(bytes, offset_of!(Self, comm))?,
            path: array_at(bytes, offset_of!(Self, path))?,
            path2: array_at(bytes, offset_of!(Self, path2))?,
            addr: array_at(bytes, offset_of!(Self, addr))?,
        })
    }
}

/// An exec's arguments, exactly as the probe writes them into [`EVENTS_MAP`]
/// ahead of the exec itself. Both are written by the same task, one after
/// the other, into one ring buffer, so the arguments always come first.
/// Told apart from a [`ProcessEvent`] by size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ArgvRecord {
    /// Nanoseconds since boot at the call.
    pub boot_ns: u64,
    /// The process.
    pub pid: u32,
    /// The thread.
    pub tid: u32,
    /// Arguments read.
    pub count: u32,
    /// 1 when every argument was read whole and the list ended within
    /// [`ARGV_MAX`]; 0 otherwise.
    pub complete: u32,
    /// What reading each argument gave, as for [`SyscallRecord::path_read`].
    pub lens: [i32; ARGV_MAX],
    /// The arguments, each NUL-terminated.
    pub args: [[u8; ARG_LEN]; ARGV_MAX],
}

impl ArgvRecord {
    /// Bytes one record takes in the ring buffer.
    pub const SIZE: usize = size_of::<Self>();

    /// A record with every field zero, for the probe to fill in place.
    pub const EMPTY: Self = Self {
        boot_ns: 0,
        pid: 0,
        tid: 0,
        count: 0,
        complete: 0,
        lens: [0; ARGV_MAX],
        args: [[0; ARG_LEN]; ARGV_MAX],
    };

    /// The arguments, only when all of them were read whole.
    #[must_use]
    pub fn argv(&self) -> Option<impl Iterator<Item = &[u8]>> {
        let count = usize::try_from(self.count).ok()?.min(ARGV_MAX);
        let all = self
            .args
            .iter()
            .zip(self.lens)
            .take(count)
            .all(|(arg, read)| whole(arg, read).is_some());
        (self.complete == 1 && all).then(|| self.args.iter().take(count).map(|arg| text(arg)))
    }

    /// Reads one record back from ring-buffer bytes, or `None` when the
    /// bytes are not one whole record.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::SIZE {
            return None;
        }
        let u32_at = |at| array_at(bytes, at).map(u32::from_ne_bytes);
        let mut lens = [0; ARGV_MAX];
        for (i, len) in lens.iter_mut().enumerate() {
            *len = i32::from_ne_bytes(array_at(bytes, offset_of!(Self, lens) + i * 4)?);
        }
        let mut args = [[0; ARG_LEN]; ARGV_MAX];
        for (i, arg) in args.iter_mut().enumerate() {
            *arg = array_at(bytes, offset_of!(Self, args) + i * ARG_LEN)?;
        }
        Some(Self {
            boot_ns: u64::from_ne_bytes(array_at(bytes, offset_of!(Self, boot_ns))?),
            pid: u32_at(offset_of!(Self, pid))?,
            tid: u32_at(offset_of!(Self, tid))?,
            count: u32_at(offset_of!(Self, count))?,
            complete: u32_at(offset_of!(Self, complete))?,
            lens,
            args,
        })
    }
}

/// Deepest working directory the probe reads, in path components. A deeper
/// one is reported as unread, never cut.
pub const CWD_DEPTH: usize = 16;
/// Longest path component kept, with its NUL.
pub const CWD_NAME: usize = 128;

/// A process's working directory, as the probe walks it in the kernel from
/// `task->fs->pwd` up to the process's own root, crossing mounts. Written
/// into [`EVENTS_MAP`] just ahead of an exec, and into [`SYSCALLS_MAP`] just
/// ahead of a call with a relative path, with that call's `boot_ns` and
/// thread. Told apart from the other records by size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct CwdRecord {
    /// Nanoseconds since boot: the exec's, or the call's it goes with.
    pub boot_ns: u64,
    /// The process.
    pub pid: u32,
    /// The thread.
    pub tid: u32,
    /// Components read, nearest the directory itself first.
    pub count: u32,
    /// 1 when the walk reached the process's root with every component
    /// whole; 0 otherwise.
    pub complete: u32,
    /// What reading each component gave, as for [`SyscallRecord::path_read`].
    pub lens: [i32; CWD_DEPTH],
    /// The components, innermost first, each NUL-terminated.
    pub names: [[u8; CWD_NAME]; CWD_DEPTH],
}

// Told apart from a `SyscallRecord` in the same ring by size.
const _: () = assert!(CwdRecord::SIZE > SyscallRecord::SIZE);

impl CwdRecord {
    /// Bytes one record takes in a ring buffer.
    pub const SIZE: usize = size_of::<Self>();

    /// A record with every field zero, for the probe to fill in place.
    pub const EMPTY: Self = Self {
        boot_ns: 0,
        pid: 0,
        tid: 0,
        count: 0,
        complete: 0,
        lens: [0; CWD_DEPTH],
        names: [[0; CWD_NAME]; CWD_DEPTH],
    };

    /// The components from the root down, only when the walk was whole.
    /// None at all is the root itself.
    #[must_use]
    pub fn components(&self) -> Option<impl Iterator<Item = &[u8]>> {
        let count = usize::try_from(self.count).ok()?.min(CWD_DEPTH);
        let all = self
            .names
            .iter()
            .zip(self.lens)
            .take(count)
            .all(|(name, read)| {
                whole(name, read).is_some_and(|n| !n.is_empty() && !n.contains(&b'/'))
            });
        (self.complete == 1 && all).then(|| self.names.iter().take(count).rev().map(|n| text(n)))
    }

    /// Reads one record back from ring-buffer bytes, or `None` when the
    /// bytes are not one whole record.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::SIZE {
            return None;
        }
        let u32_at = |at| array_at(bytes, at).map(u32::from_ne_bytes);
        let mut lens = [0; CWD_DEPTH];
        for (i, len) in lens.iter_mut().enumerate() {
            *len = i32::from_ne_bytes(array_at(bytes, offset_of!(Self, lens) + i * 4)?);
        }
        let mut names = [[0; CWD_NAME]; CWD_DEPTH];
        for (i, name) in names.iter_mut().enumerate() {
            *name = array_at(bytes, offset_of!(Self, names) + i * CWD_NAME)?;
        }
        Some(Self {
            boot_ns: u64::from_ne_bytes(array_at(bytes, offset_of!(Self, boot_ns))?),
            pid: u32_at(offset_of!(Self, pid))?,
            tid: u32_at(offset_of!(Self, tid))?,
            count: u32_at(offset_of!(Self, count))?,
            complete: u32_at(offset_of!(Self, complete))?,
            lens,
            names,
        })
    }
}

/// Bytes of a path slot a read of `read` filled: none for a failure, the
/// whole slot for one that ran to its end.
// Truncation impossible: `read` is positive and at most `PATH_LEN` here.
#[allow(clippy::cast_sign_loss)]
const fn within_path(read: i32) -> usize {
    if read <= 0 {
        0
    } else if read as usize > PATH_LEN {
        PATH_LEN
    } else {
        read as usize
    }
}

/// A NUL-terminated string field, when the helper said it read it whole.
fn whole(field: &[u8], read: i32) -> Option<&[u8]> {
    let read = usize::try_from(read).ok().filter(|n| *n > 0)?;
    // A read that filled the slot stopped at its end, not at the string's.
    if read >= field.len() {
        return None;
    }
    // Exactly what the helper said it read: the string, then its NUL. A
    // length the bytes disagree with is not one whole string.
    let (last, string) = field.get(..read)?.split_last()?;
    (*last == 0 && !string.contains(&0)).then_some(string)
}

/// A task's short name, as the kernel stores it (`TASK_COMM_LEN`).
pub const COMM_LEN: usize = 16;
/// Longest exec path kept, including its terminating NUL. Longer paths are
/// cut, never dropped.
pub const FILENAME_LEN: usize = 256;

/// Each probe program, and the tracepoint it attaches to, as
/// `(program, category, event)`. The program names are the function names in
/// `topgent-ebpf-probe/src/main.rs`.
pub const TRACEPOINTS: [(&str, &str, &str); 3] = [
    ("on_spawn", "task", "task_newtask"),
    ("on_exec", "sched", "sched_process_exec"),
    ("on_exit", "sched", "sched_process_exit"),
];

/// Written into a setting whose field this kernel does not have.
pub const ABSENT: u32 = u32::MAX;

/// One kernel-struct field the probe reads, and the probe global that holds
/// its byte offset. The loader looks each up in the kernel's BTF
/// (`/sys/kernel/btf/vmlinux`) and writes it in, as it does tracepoint
/// offsets from tracefs. A field this kernel lacks gets [`ABSENT`], and the
/// probe leaves what depends on it unread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BtfField {
    /// Name of the `static` in the probe that receives the offset.
    pub global: &'static str,
    /// The kernel struct, e.g. `task_struct`.
    pub structure: &'static str,
    /// The field within it, found through anonymous members.
    pub field: &'static str,
}

/// Every kernel-struct offset the loader supplies from BTF. `cred` holds the
/// capability sets; `task_struct.cred` points to it; `task_struct.loginuid`
/// is the audit login id; `task_struct.mm` points to the address space whose
/// `arg_start..arg_end` holds the running program's arguments;
/// `task_struct.fs` leads, through `fs_struct`, `path`, `dentry` and
/// `mount`, to the working directory.
pub const BTF_FIELDS: [BtfField; 21] = [
    BtfField {
        global: "TASK_CRED_OFF",
        structure: "task_struct",
        field: "cred",
    },
    BtfField {
        global: "TASK_LOGINUID_OFF",
        structure: "task_struct",
        field: "loginuid",
    },
    BtfField {
        global: "TASK_SIGNAL_OFF",
        structure: "task_struct",
        field: "signal",
    },
    BtfField {
        global: "SIGNAL_TTY_OFF",
        structure: "signal_struct",
        field: "tty",
    },
    BtfField {
        global: "CRED_CAP_EFFECTIVE_OFF",
        structure: "cred",
        field: "cap_effective",
    },
    BtfField {
        global: "CRED_CAP_PERMITTED_OFF",
        structure: "cred",
        field: "cap_permitted",
    },
    BtfField {
        global: "TASK_MM_OFF",
        structure: "task_struct",
        field: "mm",
    },
    BtfField {
        global: "MM_ARG_START_OFF",
        structure: "mm_struct",
        field: "arg_start",
    },
    BtfField {
        global: "MM_ARG_END_OFF",
        structure: "mm_struct",
        field: "arg_end",
    },
    BtfField {
        global: "TASK_FS_OFF",
        structure: "task_struct",
        field: "fs",
    },
    BtfField {
        global: "FS_PWD_OFF",
        structure: "fs_struct",
        field: "pwd",
    },
    BtfField {
        global: "FS_ROOT_OFF",
        structure: "fs_struct",
        field: "root",
    },
    BtfField {
        global: "PATH_MNT_OFF",
        structure: "path",
        field: "mnt",
    },
    BtfField {
        global: "PATH_DENTRY_OFF",
        structure: "path",
        field: "dentry",
    },
    BtfField {
        global: "DENTRY_PARENT_OFF",
        structure: "dentry",
        field: "d_parent",
    },
    BtfField {
        global: "DENTRY_NAME_OFF",
        structure: "dentry",
        field: "d_name",
    },
    BtfField {
        global: "QSTR_NAME_OFF",
        structure: "qstr",
        field: "name",
    },
    BtfField {
        global: "VFSMOUNT_ROOT_OFF",
        structure: "vfsmount",
        field: "mnt_root",
    },
    BtfField {
        global: "MOUNT_MNT_OFF",
        structure: "mount",
        field: "mnt",
    },
    BtfField {
        global: "MOUNT_PARENT_OFF",
        structure: "mount",
        field: "mnt_parent",
    },
    BtfField {
        global: "MOUNT_MOUNTPOINT_OFF",
        structure: "mount",
        field: "mnt_mountpoint",
    },
];

/// The BTF globals the probe needs to walk a working directory. Without all
/// of them, no working directory is read.
pub const CWD_FIELDS: [&str; 12] = [
    "TASK_FS_OFF",
    "FS_PWD_OFF",
    "FS_ROOT_OFF",
    "PATH_MNT_OFF",
    "PATH_DENTRY_OFF",
    "DENTRY_PARENT_OFF",
    "DENTRY_NAME_OFF",
    "QSTR_NAME_OFF",
    "VFSMOUNT_ROOT_OFF",
    "MOUNT_MNT_OFF",
    "MOUNT_PARENT_OFF",
    "MOUNT_MOUNTPOINT_OFF",
];

/// The BTF globals that let the probe read a program's arguments at exec,
/// from its own address space. With all three, the enter-time readers of
/// [`ARGV_PROGRAMS`] are not attached.
pub const ARGV_AT_EXEC_FIELDS: [&str; 3] = ["TASK_MM_OFF", "MM_ARG_START_OFF", "MM_ARG_END_OFF"];

/// A login uid of this value means "unread", as Audit writes -1 for unset.
pub const LOGINUID_UNREAD: u32 = u32::MAX;

/// Probe global holding the device of the host's pid namespace, as `stat`
/// reports it for `/proc/self/ns/pid` in the process that loads the probe.
pub const HOST_PIDNS_DEV: &str = "HOST_PIDNS_DEV";
/// Probe global holding the inode of the host's pid namespace. Zero means
/// the loader could not read it, and every event says [`Namespace::Unknown`].
pub const HOST_PIDNS_INO: &str = "HOST_PIDNS_INO";

/// One tracepoint field the probe reads, and the probe global that holds its
/// offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldSetting {
    /// Name of the `static` in the probe that receives the offset.
    pub global: &'static str,
    /// Tracepoint category, e.g. `task`.
    pub category: &'static str,
    /// Tracepoint event, e.g. `task_newtask`.
    pub event: &'static str,
    /// Field name in the event's format description.
    pub field: &'static str,
    /// Size the probe reads it as, in bytes. A kernel that disagrees is
    /// refused rather than misread.
    pub size: u32,
    /// Whether the probe can work without it. An optional field this kernel
    /// lacks gets [`ABSENT`].
    pub required: bool,
}

/// Every field offset the loader must supply.
pub const FIELD_SETTINGS: [FieldSetting; 4] = [
    FieldSetting {
        global: "NEWTASK_PID",
        category: "task",
        event: "task_newtask",
        field: "pid",
        size: 4,
        required: true,
    },
    FieldSetting {
        global: "NEWTASK_CLONE_FLAGS",
        category: "task",
        event: "task_newtask",
        field: "clone_flags",
        size: 8,
        required: true,
    },
    FieldSetting {
        global: "EXEC_FILENAME",
        category: "sched",
        event: "sched_process_exec",
        field: "filename",
        size: 4,
        required: true,
    },
    // Newer kernels say whether an exiting thread was the last of its
    // process. Without it, the probe takes the leader's exit as the
    // process's.
    FieldSetting {
        global: "EXIT_GROUP_DEAD",
        category: "sched",
        event: "sched_process_exit",
        field: "group_dead",
        size: 1,
        required: false,
    },
];

/// What happened to a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Kind {
    /// A new process was created (`fork`, `vfork`, `clone` without
    /// `CLONE_THREAD`). Threads are not processes and are not reported.
    Spawn = 1,
    /// A process replaced its program (`execve`, `execveat`).
    Exec = 2,
    /// The last thread of a process exited.
    Exit = 3,
}

/// Whether the task an event ran in was in the host's pid namespace, as the
/// kernel answered at the moment of the event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Namespace {
    /// Not established: no host namespace to compare with, or the kernel
    /// could not say.
    Unknown = 0,
    /// In the host's pid namespace.
    Host = 1,
    /// In another pid namespace: a container, or a sandbox of one.
    Other = 2,
}

impl Namespace {
    /// The answer a raw number names; anything unrecognised is unknown.
    #[must_use]
    pub const fn from_u32(value: u32) -> Self {
        match value {
            1 => Self::Host,
            2 => Self::Other,
            _ => Self::Unknown,
        }
    }
}

impl Kind {
    /// The kind a raw number names, if any.
    #[must_use]
    pub const fn from_u32(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::Spawn),
            2 => Some(Self::Exec),
            3 => Some(Self::Exit),
            _ => None,
        }
    }
}

/// One process event, exactly as the probe writes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ProcessEvent {
    /// Nanoseconds since boot, suspend included (`bpf_ktime_get_boot_ns`).
    pub boot_ns: u64,
    /// The cgroup of the task the event ran in (`bpf_get_current_cgroup_id`):
    /// on cgroup v2, the inode of its directory under `/sys/fs/cgroup`,
    /// which is how user space names its container.
    pub cgroup: u64,
    /// A [`Kind`], as its number. Read it with [`ProcessEvent::kind`].
    pub kind: u32,
    /// The process the event is about: its thread group id, which is what
    /// user space calls a pid.
    pub pid: u32,
    /// For [`Kind::Spawn`], the process that asked for the new one: the
    /// caller of `fork`/`clone`, recorded as it happened. Unlike a parent pid
    /// read later, this does not change when the new process is re-parented.
    /// Zero for other kinds.
    pub creator: u32,
    /// Real user id of the task the event ran in.
    pub uid: u32,
    /// For [`Kind::Spawn`], the low 32 bits of the clone flags, where every
    /// flag that shapes a process lives. Zero for other kinds.
    pub clone_flags: u32,
    /// A [`Namespace`], as its number: whether the task the event ran in was
    /// in the host's pid namespace. Read it with [`ProcessEvent::namespace`].
    pub pid_namespace: u32,
    /// Short name of the task the event ran in, NUL-padded.
    pub comm: [u8; COMM_LEN],
    /// For [`Kind::Exec`], the caller's audit login id, or [`LOGINUID_UNREAD`]
    /// when this kernel has no `task_struct.loginuid`. Zero for other kinds.
    pub loginuid: u32,
    /// 0 for no controlling terminal, 1 when one is present, or [`ABSENT`]
    /// when this kernel's BTF cannot read it.
    pub tty: u32,
    /// For [`Kind::Exec`], the path handed to exec, NUL-padded and cut at
    /// `FILENAME_LEN - 1` bytes. Empty for other kinds.
    pub filename: [u8; FILENAME_LEN],
}

impl ProcessEvent {
    /// Bytes one event takes in the ring buffer.
    pub const SIZE: usize = size_of::<Self>();

    /// An event with every field zero, for the probe to fill in place.
    pub const EMPTY: Self = Self {
        boot_ns: 0,
        cgroup: 0,
        kind: 0,
        pid: 0,
        creator: 0,
        uid: 0,
        clone_flags: 0,
        pid_namespace: 0,
        loginuid: 0,
        tty: ABSENT,
        comm: [0; COMM_LEN],
        filename: [0; FILENAME_LEN],
    };

    /// For an exec, the audit login id when this kernel records one.
    #[must_use]
    pub const fn login_uid(&self) -> Option<u32> {
        if self.loginuid == LOGINUID_UNREAD || self.loginuid == 0 {
            None
        } else {
            Some(self.loginuid)
        }
    }

    /// Whether the process had a controlling terminal.
    #[must_use]
    pub const fn has_tty(&self) -> Option<bool> {
        if self.tty == ABSENT {
            None
        } else {
            Some(self.tty != 0)
        }
    }

    /// What happened, or `None` for a number no probe writes.
    #[must_use]
    pub const fn kind(&self) -> Option<Kind> {
        Kind::from_u32(self.kind)
    }

    /// Whether the event ran in the host's pid namespace.
    #[must_use]
    pub const fn namespace(&self) -> Namespace {
        Namespace::from_u32(self.pid_namespace)
    }

    /// Reads one event back from ring-buffer bytes, or `None` when the bytes
    /// are not one whole event.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::SIZE {
            return None;
        }
        Some(Self {
            boot_ns: u64::from_ne_bytes(array_at(bytes, offset_of!(Self, boot_ns))?),
            cgroup: u64::from_ne_bytes(array_at(bytes, offset_of!(Self, cgroup))?),
            kind: u32::from_ne_bytes(array_at(bytes, offset_of!(Self, kind))?),
            pid: u32::from_ne_bytes(array_at(bytes, offset_of!(Self, pid))?),
            creator: u32::from_ne_bytes(array_at(bytes, offset_of!(Self, creator))?),
            uid: u32::from_ne_bytes(array_at(bytes, offset_of!(Self, uid))?),
            clone_flags: u32::from_ne_bytes(array_at(bytes, offset_of!(Self, clone_flags))?),
            pid_namespace: u32::from_ne_bytes(array_at(bytes, offset_of!(Self, pid_namespace))?),
            loginuid: u32::from_ne_bytes(array_at(bytes, offset_of!(Self, loginuid))?),
            tty: u32::from_ne_bytes(array_at(bytes, offset_of!(Self, tty))?),
            comm: array_at(bytes, offset_of!(Self, comm))?,
            filename: array_at(bytes, offset_of!(Self, filename))?,
        })
    }
}

/// The bytes of a NUL-padded field, up to its first NUL.
#[must_use]
pub fn text(field: &[u8]) -> &[u8] {
    field.split(|&b| b == 0).next().unwrap_or(field)
}

fn array_at<const N: usize>(bytes: &[u8], at: usize) -> Option<[u8; N]> {
    bytes.get(at..at.checked_add(N)?)?.try_into().ok()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]

    use super::*;

    /// Lays an event out the way the probe does, field by field.
    fn bytes_of(event: &ProcessEvent) -> Vec<u8> {
        let mut bytes = vec![0; ProcessEvent::SIZE];
        let mut put = |at: usize, value: &[u8]| bytes[at..at + value.len()].copy_from_slice(value);
        put(
            offset_of!(ProcessEvent, boot_ns),
            &event.boot_ns.to_ne_bytes(),
        );
        put(
            offset_of!(ProcessEvent, cgroup),
            &event.cgroup.to_ne_bytes(),
        );
        put(offset_of!(ProcessEvent, kind), &event.kind.to_ne_bytes());
        put(offset_of!(ProcessEvent, pid), &event.pid.to_ne_bytes());
        put(
            offset_of!(ProcessEvent, creator),
            &event.creator.to_ne_bytes(),
        );
        put(offset_of!(ProcessEvent, uid), &event.uid.to_ne_bytes());
        put(
            offset_of!(ProcessEvent, clone_flags),
            &event.clone_flags.to_ne_bytes(),
        );
        put(
            offset_of!(ProcessEvent, pid_namespace),
            &event.pid_namespace.to_ne_bytes(),
        );
        put(
            offset_of!(ProcessEvent, loginuid),
            &event.loginuid.to_ne_bytes(),
        );
        put(offset_of!(ProcessEvent, tty), &event.tty.to_ne_bytes());
        put(offset_of!(ProcessEvent, comm), &event.comm);
        put(offset_of!(ProcessEvent, filename), &event.filename);
        bytes
    }

    fn padded<const N: usize>(text: &[u8]) -> [u8; N] {
        let mut out = [0; N];
        out[..text.len()].copy_from_slice(text);
        out
    }

    #[test]
    fn an_event_reads_back_exactly_as_written() {
        let event = ProcessEvent {
            boot_ns: 123_456_789,
            cgroup: 7_512,
            kind: Kind::Exec as u32,
            pid: 4242,
            creator: 0,
            uid: 1000,
            clone_flags: 0,
            pid_namespace: Namespace::Host as u32,
            loginuid: 1000,
            tty: 1,
            comm: padded(b"true"),
            filename: padded(b"/bin/true"),
        };
        let back = ProcessEvent::decode(&bytes_of(&event));
        assert_eq!(back, Some(event));
        let back = back.unwrap_or(ProcessEvent::EMPTY);
        assert_eq!(back.login_uid(), Some(1000));
        assert_eq!(back.kind(), Some(Kind::Exec));
        assert_eq!(back.namespace(), Namespace::Host);
        assert_eq!(text(&back.filename), b"/bin/true");
        assert_eq!(text(&back.comm), b"true");
    }

    #[test]
    fn anything_but_one_whole_event_is_refused() {
        let whole = bytes_of(&ProcessEvent::EMPTY);
        assert!(ProcessEvent::decode(&whole[..ProcessEvent::SIZE - 1]).is_none());
        assert!(ProcessEvent::decode(&[whole.clone(), vec![0]].concat()).is_none());
        assert!(ProcessEvent::decode(&[]).is_none());
        assert!(ProcessEvent::decode(&whole).is_some());
    }

    #[test]
    fn an_unknown_kind_is_not_guessed() {
        let event = ProcessEvent {
            kind: 9,
            ..ProcessEvent::EMPTY
        };
        assert_eq!(event.kind(), None);
        assert_eq!(Kind::from_u32(0), None);
        for kind in [Kind::Spawn, Kind::Exec, Kind::Exit] {
            assert_eq!(Kind::from_u32(kind as u32), Some(kind));
        }
    }

    #[test]
    fn an_unrecognised_namespace_answer_is_unknown_never_host() {
        assert_eq!(Namespace::from_u32(0), Namespace::Unknown);
        assert_eq!(Namespace::from_u32(7), Namespace::Unknown);
        assert_eq!(Namespace::from_u32(2), Namespace::Other);
    }

    /// Every field is laid out with no padding between, so no byte of an
    /// event is left for the kernel to fill with whatever was there.
    #[test]
    fn the_layout_has_no_padding() {
        let fields = 2 * 8 + 8 * 4 + COMM_LEN + FILENAME_LEN;
        assert_eq!(ProcessEvent::SIZE, fields);
    }

    #[test]
    fn text_stops_at_the_first_nul_and_keeps_a_full_field() {
        assert_eq!(text(b"ls\0\0\0"), b"ls");
        assert_eq!(text(b"\0\0"), b"");
        assert_eq!(text(b"abcd"), b"abcd");
    }

    #[test]
    fn every_program_has_a_distinct_name_and_every_global_is_unique() {
        let mut programs: Vec<_> = TRACEPOINTS.iter().map(|(name, ..)| *name).collect();
        programs.sort_unstable();
        programs.dedup();
        assert_eq!(programs.len(), TRACEPOINTS.len());
        let mut globals: Vec<_> = FIELD_SETTINGS.iter().map(|s| s.global).collect();
        globals.sort_unstable();
        globals.dedup();
        assert_eq!(globals.len(), FIELD_SETTINGS.len());
    }

    #[test]
    fn a_syscall_record_reads_back_exactly_as_written() {
        let mut record = SyscallRecord {
            boot_ns: 9,
            cgroup: 7_512,
            ret: -2,
            args: [1, 2, 3, 4, 5, 6],
            call: 672,
            pid: 7,
            tid: 8,
            uid: 1000,
            pid_namespace: Namespace::Host as u32,
            path_read: 12,
            path2_read: 0,
            addr_read: 16,
            socket: SOCKET_KNOWN | SocketKind::from_args(2, 0x80002, 0).pack(),
            cap_effective: 0x0000_03ff,
            cap_permitted: 0x0000_00ff,
            loginuid: 1000,
            caps_known: 1,
            tty: 0,
            comm: padded(b"cat"),
            path: padded(b"/etc/shadow"),
            path2: [0; PATH_LEN],
            addr: [0; ADDR_LEN],
        };
        record.addr[0] = 2;
        // Laid out by field offset, as the probe writes it in place.
        let mut bytes = vec![0; SyscallRecord::SIZE];
        let mut put = |at: usize, value: &[u8]| bytes[at..at + value.len()].copy_from_slice(value);
        put(offset_of!(SyscallRecord, boot_ns), &9u64.to_ne_bytes());
        put(offset_of!(SyscallRecord, cgroup), &7_512u64.to_ne_bytes());
        put(offset_of!(SyscallRecord, ret), &(-2i64).to_ne_bytes());
        for (i, arg) in record.args.iter().enumerate() {
            put(offset_of!(SyscallRecord, args) + i * 8, &arg.to_ne_bytes());
        }
        put(offset_of!(SyscallRecord, call), &672u32.to_ne_bytes());
        put(offset_of!(SyscallRecord, pid), &7u32.to_ne_bytes());
        put(offset_of!(SyscallRecord, tid), &8u32.to_ne_bytes());
        put(offset_of!(SyscallRecord, uid), &1000u32.to_ne_bytes());
        put(
            offset_of!(SyscallRecord, pid_namespace),
            &1u32.to_ne_bytes(),
        );
        put(offset_of!(SyscallRecord, path_read), &12i32.to_ne_bytes());
        put(offset_of!(SyscallRecord, addr_read), &16u32.to_ne_bytes());
        put(
            offset_of!(SyscallRecord, socket),
            &record.socket.to_ne_bytes(),
        );
        put(
            offset_of!(SyscallRecord, cap_effective),
            &0x03ffu64.to_ne_bytes(),
        );
        put(
            offset_of!(SyscallRecord, cap_permitted),
            &0x00ffu64.to_ne_bytes(),
        );
        put(offset_of!(SyscallRecord, loginuid), &1000u32.to_ne_bytes());
        put(offset_of!(SyscallRecord, caps_known), &1u32.to_ne_bytes());
        put(offset_of!(SyscallRecord, comm), &record.comm);
        put(offset_of!(SyscallRecord, path), &record.path);
        put(offset_of!(SyscallRecord, addr), &record.addr);
        let back = SyscallRecord::decode(&bytes);
        assert_eq!(back, Some(record));
        assert_eq!(record.path(), Some(&b"/etc/shadow"[..]));
        assert_eq!(record.path2(), None);
        assert_eq!(record.addr().map(<[u8]>::len), Some(16));
        let udp = SocketKind::unpack(record.socket);
        assert_eq!(
            udp,
            Some(SocketKind {
                domain: 2,
                kind: 2,
                protocol: 0
            }),
            "SOCK_DGRAM with its flags removed"
        );
        assert_eq!(SocketKind::unpack(0), None, "not known is not a socket");
        assert_eq!(record.capabilities(), Some((0x03ff, 0x00ff)));
        assert_eq!(record.login_uid(), Some(1000));
        assert_eq!(SyscallRecord::EMPTY.capabilities(), None);
        assert_eq!(SyscallRecord::EMPTY.login_uid(), None);
        assert!(SyscallRecord::decode(&bytes[1..]).is_none());
        assert!(SyscallRecord::decode(&[bytes.clone(), vec![0]].concat()).is_none());
    }

    #[test]
    fn a_path_is_passed_on_only_when_read_whole() {
        let mut record = SyscallRecord::EMPTY;
        record.path = padded(b"/tmp/x");
        for (read, kept) in [(7, true), (0, false), (-14, false)] {
            record.path_read = read;
            assert_eq!(record.path().is_some(), kept, "{read}");
        }
        // Filled the slot: the string may go on past it.
        record.path = [b'a'; PATH_LEN];
        record.path_read = 512;
        assert_eq!(record.path(), None);
    }

    #[test]
    fn a_path_is_exactly_the_bytes_read_never_more() {
        let mut record = SyscallRecord {
            path_read: 4,
            ..SyscallRecord::EMPTY
        };
        record.path[..3].copy_from_slice(b"/tm");
        assert_eq!(record.path(), Some(&b"/tm"[..]));
        // Found by the `ebpf_records` fuzz target: bytes past the length,
        // and no NUL where the length puts it.
        record.path[3..8].copy_from_slice(b"p/abc");
        assert_eq!(record.path(), None, "no NUL where the read ended");
        record.path[3] = 0;
        record.path_read = 3;
        assert_eq!(record.path(), None, "a NUL inside what was read");
    }

    #[test]
    fn a_syscall_record_is_sent_only_as_far_as_its_paths_go() {
        let mut record = SyscallRecord {
            pid: 7,
            path_read: 12,
            ..SyscallRecord::EMPTY
        };
        record.path[..11].copy_from_slice(b"/etc/shadow");
        let used = record.used_len();
        assert_eq!(used, offset_of!(SyscallRecord, path) + 12);
        let bytes = call_bytes(&record);
        let Some(back) = SyscallRecord::decode(&bytes[..used]) else {
            unreachable!("a short record decodes")
        };
        assert_eq!((back.pid, back.path()), (7, Some(&b"/etc/shadow"[..])));
        assert!(
            SyscallRecord::decode(&bytes[..used - 1]).is_none(),
            "cut inside its path"
        );
        let none = SyscallRecord::EMPTY;
        assert_eq!(none.used_len(), SyscallRecord::MIN_SIZE);
        assert!(SyscallRecord::decode(&call_bytes(&none)[..SyscallRecord::MIN_SIZE]).is_some());
        assert!(SyscallRecord::decode(&bytes[..SyscallRecord::MIN_SIZE - 1]).is_none());
        record.path2_read = 3;
        assert_eq!(record.used_len(), offset_of!(SyscallRecord, path2) + 3);
        record.path2_read = 9_999;
        assert_eq!(
            record.used_len(),
            SyscallRecord::SIZE,
            "a cut read stops at the slot"
        );
        assert!(SyscallRecord::decode(&vec![0; SyscallRecord::SIZE + 1]).is_none());
    }

    /// A record's bytes, as the probe writes them.
    fn call_bytes(record: &SyscallRecord) -> Vec<u8> {
        let mut bytes = vec![0; SyscallRecord::SIZE];
        let put = |bytes: &mut Vec<u8>, at: usize, value: &[u8]| {
            bytes[at..at + value.len()].copy_from_slice(value);
        };
        put(
            &mut bytes,
            offset_of!(SyscallRecord, pid),
            &record.pid.to_ne_bytes(),
        );
        put(
            &mut bytes,
            offset_of!(SyscallRecord, path_read),
            &record.path_read.to_ne_bytes(),
        );
        put(
            &mut bytes,
            offset_of!(SyscallRecord, path2_read),
            &record.path2_read.to_ne_bytes(),
        );
        put(
            &mut bytes,
            offset_of!(SyscallRecord, loginuid),
            &record.loginuid.to_ne_bytes(),
        );
        put(&mut bytes, offset_of!(SyscallRecord, path), &record.path);
        bytes
    }

    #[test]
    fn the_syscall_record_has_no_padding() {
        let fields = 5 * 8 + ARGS * 8 + 12 * 4 + COMM_LEN + 2 * PATH_LEN + ADDR_LEN;
        assert_eq!(SyscallRecord::SIZE, fields);
        assert_eq!(size_of::<Pending>(), 8 + ARGS * 8);
    }

    #[test]
    fn a_relative_path_is_looked_up_where_the_kernel_looks_it_up() {
        let spec = |name: &str| {
            *SYSCALL_SPECS
                .iter()
                .find(|s| s.name == name)
                .unwrap_or_else(|| unreachable!("{name}"))
        };
        for name in ["open", "creat", "mkdir", "unlink", "rename", "link"] {
            assert_eq!(spec(name).path_base, Base::Cwd, "{name}");
        }
        for name in [
            "openat",
            "openat2",
            "mkdirat",
            "unlinkat",
            "fchmodat",
            "renameat2",
            "linkat",
        ] {
            let s = spec(name);
            assert_eq!(s.path_base, Base::DirBefore, "{name}");
            assert!(s.path > 0, "{name}: a directory argument before the path");
        }
        assert_eq!(spec("renameat").path2_base, Base::DirBefore);
        assert_eq!(spec("rename").path2_base, Base::Cwd);
        for name in ["symlink", "symlinkat"] {
            assert_eq!(
                spec(name).path2_base,
                Base::Never,
                "{name}: a target is text"
            );
        }
        assert_eq!(spec("symlinkat").path, 2, "linkpath, after newdirfd");
        assert_eq!(spec("connect").path_base, Base::Never);
        let packed = unpack(spec("renameat").pack(4))[6];
        assert_eq!((packed & 7, packed >> 3 & 3, packed >> 5 & 3), (4, 2, 2));
    }

    #[test]
    fn every_syscall_spec_is_unique_and_names_real_argument_slots() {
        let mut names: Vec<_> = SYSCALL_SPECS.iter().map(|s| s.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), SYSCALL_SPECS.len());
        for spec in SYSCALL_SPECS {
            for slot in [
                spec.path,
                spec.path2,
                spec.addr_arg,
                spec.addr_len_arg,
                spec.open_flags,
            ] {
                assert!(slot == NO_ARG || usize::from(slot) < ARGS, "{spec:?}");
            }
            assert_eq!(spec.addr == Addr::None, spec.addr_arg == NO_ARG, "{spec:?}");
            assert!(
                !spec.name.starts_with("exec"),
                "exec is the lifecycle event"
            );
        }
    }

    #[test]
    fn a_packed_spec_unpacks_field_for_field() {
        let spec = addressed("recvfrom", Addr::Out, 4, 5);
        assert_eq!(
            unpack(spec.pack(6)),
            [NO_ARG, NO_ARG, Addr::Out as u8, 4, 5, NO_ARG, 6, 0]
        );
        let connect = with_socket(addressed("connect", Addr::In, 1, 2), SocketRole::Uses);
        assert_eq!(unpack(connect.pack(3))[7], SocketRole::Uses as u8);
        assert_eq!(unpack(open("openat", 1, 2).pack(4))[5], 2);
    }

    #[test]
    fn exec_arguments_are_given_only_when_every_one_was_read_whole() {
        let mut record = ArgvRecord {
            boot_ns: 1,
            pid: 7,
            tid: 7,
            count: 2,
            complete: 1,
            lens: [0; ARGV_MAX],
            args: [[0; ARG_LEN]; ARGV_MAX],
        };
        record.args[0] = padded(b"cat");
        record.args[1] = padded(b"/etc/shadow");
        record.lens[0] = 4;
        record.lens[1] = 12;
        let argv: Vec<_> = record.argv().map(Iterator::collect).unwrap_or_default();
        assert_eq!(argv, [&b"cat"[..], &b"/etc/shadow"[..]]);
        record.lens[1] = 256;
        assert!(record.argv().is_none(), "one argument may have been cut");
        record.lens[1] = 12;
        record.complete = 0;
        assert!(record.argv().is_none(), "more arguments than were read");
        assert_ne!(ArgvRecord::SIZE, ProcessEvent::SIZE, "told apart by size");
        assert_eq!(
            ArgvRecord::SIZE,
            8 + 4 * 4 + ARGV_MAX * 4 + ARGV_MAX * ARG_LEN
        );
        let mut bytes = vec![0; ArgvRecord::SIZE];
        bytes[offset_of!(ArgvRecord, pid)..][..4].copy_from_slice(&7u32.to_ne_bytes());
        assert_eq!(ArgvRecord::decode(&bytes).map(|r| r.pid), Some(7));
        assert!(ArgvRecord::decode(&bytes[1..]).is_none());
    }

    #[test]
    fn a_working_directory_reads_from_the_root_down_only_when_whole() {
        let mut record = CwdRecord::EMPTY;
        for (i, name) in [&b"project"[..], b"user", b"home"].iter().enumerate() {
            record.names[i][..name.len()].copy_from_slice(name);
            record.lens[i] = i32::try_from(name.len() + 1).unwrap_or(0);
        }
        record.count = 3;
        record.complete = 1;
        let down: Vec<&[u8]> = record
            .components()
            .map(Iterator::collect)
            .unwrap_or_default();
        assert_eq!(down, [&b"home"[..], b"user", b"project"]);
        record.complete = 0;
        assert!(
            record.components().is_none(),
            "a walk that did not reach the root"
        );
        record.complete = 1;
        record.lens[1] = i32::try_from(CWD_NAME).unwrap_or(0);
        assert!(
            record.components().is_none(),
            "a component that filled its slot"
        );
        let root = CwdRecord {
            complete: 1,
            ..CwdRecord::EMPTY
        };
        assert_eq!(root.components().map(Iterator::count), Some(0), "the root");
        for other in [ArgvRecord::SIZE, ProcessEvent::SIZE, SyscallRecord::SIZE] {
            assert_ne!(CwdRecord::SIZE, other, "told apart by size");
        }
        assert_eq!(
            CwdRecord::SIZE,
            8 + 4 * 4 + CWD_DEPTH * 4 + CWD_DEPTH * CWD_NAME
        );
        let mut bytes = vec![0; CwdRecord::SIZE];
        bytes[offset_of!(CwdRecord, tid)..][..4].copy_from_slice(&9u32.to_ne_bytes());
        assert_eq!(CwdRecord::decode(&bytes).map(|r| r.tid), Some(9));
        assert!(CwdRecord::decode(&bytes[1..]).is_none());
    }

    #[test]
    fn every_field_setting_names_an_attached_tracepoint() {
        for setting in FIELD_SETTINGS {
            assert!(
                TRACEPOINTS
                    .iter()
                    .any(|(_, category, event)| *category == setting.category
                        && *event == setting.event),
                "{setting:?}"
            );
        }
    }
}
