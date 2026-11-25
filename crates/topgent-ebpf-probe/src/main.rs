//! Topgent's kernel-side eBPF programs.
//!
//! Built for the BPF target by `topgent-ebpf`'s build script, never by the
//! workspace. Every program here observes: tracepoint return values are
//! ignored by the kernel, so nothing here can change, block or delay the
//! event it watches.
//!
//! Three programs report a process's life: `on_spawn` when one is created,
//! `on_exec` when it runs a program, `on_exit` when its last thread ends.
//! Each writes one [`ProcessEvent`] to the `EVENTS` ring buffer, or counts it
//! in `LOST` when the buffer is full.
//!
//! Two more report the syscalls the behaviour rules read: `on_sys_enter`
//! keeps a call's arguments, `on_sys_exit` adds its result and the paths and
//! socket address it named, and writes one [`SyscallRecord`] to `SYSCALLS`.
//!
//! None reads a kernel struct: they read their tracepoint's own record, at
//! offsets the loader looked up in the kernel's description of it, the
//! caller's own memory, and what BPF helpers report about the current task.

#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext as _,
    bindings::bpf_pidns_info,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes, bpf_probe_read_user,
        generated::{
            bpf_get_current_cgroup_id, bpf_get_current_task, bpf_get_ns_current_pid_tgid,
            bpf_ktime_get_boot_ns, bpf_probe_read_kernel_str,
            bpf_probe_read_user as read_user_bytes, bpf_probe_read_user_str,
        },
    },
    macros::{map, tracepoint},
    maps::{HashMap, LruHashMap, PerCpuArray, RingBuf, ring_buf::RingBufEntry},
    programs::TracePointContext,
};
use topgent_ebpf_common::{
    ABSENT, ADDR_LEN, ARGS, ARGV_MAX, Addr, ArgvRecord, Base, CwdRecord, EVENTS_BYTES, Kind,
    LOST_EVENTS, LOST_SYSCALLS, Namespace, PENDING_MAX, Pending, ProcessEvent, SEND_REPORT_BYTES,
    SOCKET_KNOWN, SOCKETS_MAX, SPECS_MAX, SYSCALLS_BYTES, SocketKind, SocketRole, SyscallRecord,
    unpack,
};

/// What `bpf_get_ns_current_pid_tgid` returns, negated, when the current
/// task is not in the namespace asked about (include/uapi/asm-generic/errno-base.h).
const EINVAL: i64 = 22;

/// `clone` flag marking a new thread of the caller's process, not a new
/// process (include/uapi/linux/sched.h).
const CLONE_THREAD: u64 = 0x0001_0000;

/// The open flags that make an open more than a read: the access mode bits,
/// `O_CREAT` and `O_TRUNC` (include/uapi/asm-generic/fcntl.h).
const OPEN_BEYOND_READ: u64 = 0o3 | 0o100 | 0o1000;
/// The dynamic linker's cache, with its NUL, as a read path holds it.
const LD_SO_CACHE: &[u8] = b"/etc/ld.so.cache\0";
/// Address families and the stream type (include/linux/socket.h, net.h).
const AF_INET: u16 = 2;
/// As above.
const AF_INET6: u16 = 10;
/// As above.
const SOCK_STREAM: u32 = 1;

/// Events for user space (`EVENTS_MAP` in topgent-ebpf-common).
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(EVENTS_BYTES, 0);

/// Records dropped because a ring buffer was full, per CPU (`LOST_MAP`):
/// `LOST_EVENTS` for `EVENTS`, `LOST_SYSCALLS` for `SYSCALLS`.
#[map]
static LOST: PerCpuArray<u64> = PerCpuArray::with_max_entries(2, 0);

/// Syscalls for user space (`SYSCALLS_MAP`).
#[map]
static SYSCALLS: RingBuf = RingBuf::with_byte_size(SYSCALLS_BYTES, 0);

/// Where `on_sys_exit` builds a record before writing the used part of it
/// to `SYSCALLS`, one per CPU.
#[map]
static SCRATCH: PerCpuArray<SyscallRecord> = PerCpuArray::with_max_entries(1, 0);

/// Syscall number to packed `SyscallSpec` (`SPECS_MAP`), written by the
/// loader.
#[map]
static SPECS: HashMap<u32, u64> = HashMap::with_max_entries(SPECS_MAX, 0);

/// A process's descriptor to the kind of socket it is (`SOCKETS_MAP`).
#[map]
static SOCKETS: LruHashMap<u64, u32> = LruHashMap::with_max_entries(SOCKETS_MAX, 0);

/// A socket's writes not yet reported (`SENT_MAP`): the call's number in the
/// top 16 bits, the bytes below.
#[map]
static SENT: LruHashMap<u64, u64> = LruHashMap::with_max_entries(SOCKETS_MAX, 0);

/// Thread to the call it is inside (`PENDING_MAP`).
#[map]
static PENDING: LruHashMap<u64, Pending> = LruHashMap::with_max_entries(PENDING_MAX, 0);

// Where each field sits in its tracepoint's record. The loader overwrites
// these from `/sys/kernel/tracing/events/*/format` before the kernel sees the
// program (`FIELD_SETTINGS` in topgent-ebpf-common), so the values here are
// placeholders only.

#[unsafe(no_mangle)]
static NEWTASK_PID: u32 = 0;
#[unsafe(no_mangle)]
static NEWTASK_CLONE_FLAGS: u32 = 0;
#[unsafe(no_mangle)]
static EXEC_FILENAME: u32 = 0;
#[unsafe(no_mangle)]
static EXIT_GROUP_DEAD: u32 = ABSENT;
#[unsafe(no_mangle)]
static SYS_NR: u32 = 0;
#[unsafe(no_mangle)]
static SYS_ARGS: u32 = 0;
#[unsafe(no_mangle)]
static SYS_RET: u32 = 0;
/// `close`'s number when this program shares the generic enter tracepoint.
#[unsafe(no_mangle)]
static CLOSE_NR: u32 = ABSENT;

// Byte offsets in kernel structs, read from BTF by the loader (BTF_FIELDS in
// topgent-ebpf-common). ABSENT where this kernel lacks the field.
#[unsafe(no_mangle)]
static TASK_CRED_OFF: u32 = ABSENT;
#[unsafe(no_mangle)]
static TASK_LOGINUID_OFF: u32 = ABSENT;
#[unsafe(no_mangle)]
static TASK_SIGNAL_OFF: u32 = ABSENT;
#[unsafe(no_mangle)]
static SIGNAL_TTY_OFF: u32 = ABSENT;
#[unsafe(no_mangle)]
static CRED_CAP_EFFECTIVE_OFF: u32 = ABSENT;
#[unsafe(no_mangle)]
static CRED_CAP_PERMITTED_OFF: u32 = ABSENT;
#[unsafe(no_mangle)]
static TASK_MM_OFF: u32 = ABSENT;
#[unsafe(no_mangle)]
static MM_ARG_START_OFF: u32 = ABSENT;
#[unsafe(no_mangle)]
static MM_ARG_END_OFF: u32 = ABSENT;
#[unsafe(no_mangle)]
static TASK_FS_OFF: u32 = ABSENT;
#[unsafe(no_mangle)]
static FS_PWD_OFF: u32 = ABSENT;
#[unsafe(no_mangle)]
static FS_ROOT_OFF: u32 = ABSENT;
#[unsafe(no_mangle)]
static PATH_MNT_OFF: u32 = ABSENT;
#[unsafe(no_mangle)]
static PATH_DENTRY_OFF: u32 = ABSENT;
#[unsafe(no_mangle)]
static DENTRY_PARENT_OFF: u32 = ABSENT;
#[unsafe(no_mangle)]
static DENTRY_NAME_OFF: u32 = ABSENT;
#[unsafe(no_mangle)]
static QSTR_NAME_OFF: u32 = ABSENT;
#[unsafe(no_mangle)]
static VFSMOUNT_ROOT_OFF: u32 = ABSENT;
#[unsafe(no_mangle)]
static MOUNT_MNT_OFF: u32 = ABSENT;
#[unsafe(no_mangle)]
static MOUNT_PARENT_OFF: u32 = ABSENT;
#[unsafe(no_mangle)]
static MOUNT_MOUNTPOINT_OFF: u32 = ABSENT;

// The host's pid namespace, as `stat` reports `/proc/self/ns/pid` in the
// loader (`HOST_PIDNS_DEV`/`HOST_PIDNS_INO` in topgent-ebpf-common). An inode
// of zero means the loader could not read it.

#[unsafe(no_mangle)]
static HOST_PIDNS_DEV: u64 = 0;
#[unsafe(no_mangle)]
static HOST_PIDNS_INO: u64 = 0;

/// A new task (`task/task_newtask`), reported in the context of the task
/// that created it, which is what makes it the creator.
#[tracepoint]
pub fn on_spawn(ctx: TracePointContext) -> u32 {
    let _ = spawn(&ctx);
    0
}

/// A process ran a new program (`sched/sched_process_exec`), reported in
/// the context of that process.
#[tracepoint]
pub fn on_exec(ctx: TracePointContext) -> u32 {
    let _ = exec(&ctx);
    0
}

/// A thread ended (`sched/sched_process_exit`). Reported only when it was
/// the last of its process.
#[tracepoint]
pub fn on_exit(ctx: TracePointContext) -> u32 {
    let _ = exit(&ctx);
    0
}

/// A rule syscall began (`syscalls/sys_enter_<name>`): keep its arguments
/// until it returns.
#[tracepoint]
pub fn on_sys_enter(ctx: TracePointContext) -> u32 {
    let _ = sys_enter(&ctx);
    0
}

/// An `execve` began: report its arguments ahead of the exec itself.
#[tracepoint]
pub fn on_execve_args(ctx: TracePointContext) -> u32 {
    let _ = exec_args(&ctx, 1);
    0
}

/// An `execveat` began, whose `argv` is its third argument.
#[tracepoint]
pub fn on_execveat_args(ctx: TracePointContext) -> u32 {
    let _ = exec_args(&ctx, 2);
    0
}

/// A descriptor was closed (`syscalls/sys_enter_close`): it is no longer
/// the socket it may have been. Writes an event only for a socket with
/// written bytes not yet reported, which are reported now.
#[tracepoint]
pub fn on_close(ctx: TracePointContext) -> u32 {
    // On the generic enter tracepoint every syscall arrives; keep `close`.
    let close_nr = setting(&CLOSE_NR);
    if close_nr != ABSENT
        && field::<i32>(&ctx, &SYS_NR).and_then(|n| u32::try_from(n).ok()) != Some(close_nr)
    {
        return 0;
    }
    if let Some(fd) = read::<u64>(&ctx, setting(&SYS_ARGS) as usize) {
        let key = socket_key(current_tgid(), fd);
        let _ = flush_sent(key, fd);
        let _ = SOCKETS.remove(key);
    }
    0
}

/// Reports a closing socket's unreported written bytes, as the write call
/// that wrote them last.
fn flush_sent(key: u64, fd: u64) -> Option<()> {
    // SAFETY: copies taken at once, as in `track_socket`.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage - a BPF helper or map access, which only exists as unsafe; the kernel verifier checks it, and the SAFETY comment states why it holds
    let packed = *unsafe { SENT.get(key) }?;
    let _ = SENT.remove(key);
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage - a BPF helper or map access, which only exists as unsafe; the kernel verifier checks it, and the SAFETY comment states why it holds
    let kind = *unsafe { SOCKETS.get(key) }?;
    let bytes = packed & SENT_BYTES;
    if bytes == 0 {
        return None;
    }
    let mut args = [0_u64; ARGS];
    args[0] = fd;
    emit_call(
        (packed >> 48) as u32,
        args,
        bytes as i64,
        kind | SOCKET_KNOWN,
    )
}

/// A rule syscall returned (`syscalls/sys_exit_<name>`).
#[tracepoint]
pub fn on_sys_exit(ctx: TracePointContext) -> u32 {
    let _ = sys_exit(&ctx);
    0
}

fn spawn(ctx: &TracePointContext) -> Option<()> {
    let flags: u64 = field(ctx, &NEWTASK_CLONE_FLAGS)?;
    if flags & CLONE_THREAD != 0 {
        return None;
    }
    let pid = u32::try_from(field::<i32>(ctx, &NEWTASK_PID)?).ok()?;

    // Everything fallible is read before reserving: a reserved entry must be
    // submitted or discarded on every path, or the verifier rejects the
    // program.
    let mut entry = reserve()?;
    let event = entry.write(ProcessEvent::EMPTY);
    stamp(event, Kind::Spawn);
    event.pid = pid;
    event.creator = current_tgid();
    // Truncation intended: every flag that shapes a process is in the low
    // 32 bits.
    event.clone_flags = flags as u32;
    entry.submit(0);
    Some(())
}

fn exec(ctx: &TracePointContext) -> Option<()> {
    // A `__data_loc` field: the low 16 bits are the path's offset from the
    // start of the record, the high 16 its length.
    let location: u32 = field(ctx, &EXEC_FILENAME)?;
    let path = ctx
        .as_ptr()
        .cast::<u8>()
        .wrapping_add((location & 0xffff) as usize);

    // Ahead of the exec, as the enter-time readers are.
    let _ = argv_at_exec();
    // SAFETY: as in `stamp`.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage - a BPF helper or map access, which only exists as unsafe; the kernel verifier checks it, and the SAFETY comment states why it holds
    let _ = emit_cwd(&EVENTS, LOST_EVENTS, unsafe { bpf_ktime_get_boot_ns() });

    let mut entry = reserve()?;
    let event = entry.write(ProcessEvent::EMPTY);
    stamp(event, Kind::Exec);
    event.pid = current_tgid();
    event.loginuid = current_loginuid();
    // SAFETY: `path` points into this tracepoint's record, where the kernel
    // wrote the exec path. The helper copies at most `filename.len()` bytes,
    // stops at a NUL, and on a bad address fails rather than faulting. On
    // failure the path stays empty and the exec is still reported.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage - a BPF helper or map access, which only exists as unsafe; the kernel verifier checks it, and the SAFETY comment states why it holds
    let _ = unsafe { bpf_probe_read_kernel_str_bytes(path, &mut event.filename) };
    entry.submit(0);
    Some(())
}

/// The new program's arguments, read from its own address space
/// (`mm->arg_start..arg_end`) once the exec has succeeded. The kernel has
/// just copied them there, so they are resident, which they need not be in
/// the caller's memory at `execve` entry (a command run by `sudo`). Nothing
/// is reported when this kernel's BTF lacks one of the offsets; the loader
/// then attaches the enter-time readers instead.
fn argv_at_exec() -> Option<()> {
    let (mm_off, start_off, end_off) = (
        setting(&TASK_MM_OFF),
        setting(&MM_ARG_START_OFF),
        setting(&MM_ARG_END_OFF),
    );
    if mm_off == ABSENT || start_off == ABSENT || end_off == ABSENT {
        return None;
    }
    // SAFETY: returns the current task pointer; no memory behind the call.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage - a BPF helper or map access, which only exists as unsafe; the kernel verifier checks it, and the SAFETY comment states why it holds
    let task = unsafe { bpf_get_current_task() };
    if task == 0 {
        return None;
    }
    let mm = read_kernel::<u64>(task + u64::from(mm_off)).filter(|mm| *mm != 0)?;
    let start = read_kernel::<u64>(mm + u64::from(start_off))?;
    let end = read_kernel::<u64>(mm + u64::from(end_off))?;

    // From here on nothing returns early: the entry is submitted.
    let Some(mut entry) = EVENTS.reserve::<ArgvRecord>(0) else {
        count_lost(LOST_EVENTS);
        return None;
    };
    let record = entry.write(ArgvRecord::EMPTY);
    // SAFETY: as in `stamp`.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage - a BPF helper or map access, which only exists as unsafe; the kernel verifier checks it, and the SAFETY comment states why it holds
    record.boot_ns = unsafe { bpf_ktime_get_boot_ns() };
    let id = bpf_get_current_pid_tgid();
    record.pid = (id >> 32) as u32;
    record.tid = id as u32;
    // The arguments sit end to end, each with its NUL.
    let mut at = start;
    let mut ended = at >= end;
    let mut whole = true;
    for (i, (arg, read)) in record
        .args
        .iter_mut()
        .zip(record.lens.iter_mut())
        .enumerate()
    {
        if at >= end {
            ended = true;
            break;
        }
        *read = read_string(at, arg);
        record.count = i as u32 + 1;
        if *read <= 0 || *read as usize >= arg.len() {
            whole = false;
            break;
        }
        at += *read as u64;
    }
    if whole && !ended {
        // Exactly `ARGV_MAX` arguments, or more.
        ended = at >= end;
    }
    record.complete = u32::from(ended && whole);
    entry.submit(0);
    Some(())
}

/// Whether the call's path or second path is relative and looked up from
/// the working directory: always for a call with no directory argument,
/// and for an `*at` call when that argument is `AT_FDCWD`.
fn relative_path(args: &[u64; ARGS], spec: &[u8; 8]) -> bool {
    for (slot, base) in [(spec[0], (spec[6] >> 3) & 3), (spec[1], (spec[6] >> 5) & 3)] {
        if base == Base::Never as u8 {
            continue;
        }
        let Some(at) = arg(args, slot) else {
            continue;
        };
        let Some(first) = user::<u8>(at) else {
            continue;
        };
        if first == 0 || first == b'/' {
            continue;
        }
        if base == Base::Cwd as u8 {
            return true;
        }
        if base == Base::DirBefore as u8
            && slot > 0
            && let Some(dirfd) = value(args, slot - 1)
            && dirfd & 0xffff_ffff == AT_FDCWD
        {
            return true;
        }
    }
    false
}

/// `AT_FDCWD` in the low 32 bits of a register (include/uapi/linux/fcntl.h).
const AT_FDCWD: u64 = 0xffff_ff9c;

/// Mount roots crossed at most between two path components.
const MOUNT_HOPS: usize = 4;

/// Writes the current process's working directory into `ring`, stamped
/// `boot_ns`. Nothing when this kernel's BTF lacks one of the offsets.
fn emit_cwd(ring: &RingBuf, lost: u32, boot_ns: u64) -> Option<()> {
    let offsets = CwdOffsets::read()?;
    // From here on nothing returns early: the entry is submitted.
    let Some(mut entry) = ring.reserve::<CwdRecord>(0) else {
        count_lost(lost);
        return None;
    };
    let record = entry.write(CwdRecord::EMPTY);
    record.boot_ns = boot_ns;
    let id = bpf_get_current_pid_tgid();
    record.pid = (id >> 32) as u32;
    record.tid = id as u32;
    record.complete = u32::from(walk_cwd(record, &offsets).unwrap_or(false));
    entry.submit(0);
    Some(())
}

/// The struct offsets a working-directory walk needs, from BTF.
struct CwdOffsets {
    task_fs: u64,
    fs_pwd: u64,
    fs_root: u64,
    path_mnt: u64,
    path_dentry: u64,
    dentry_parent: u64,
    dentry_name: u64,
    vfsmount_root: u64,
    mount_mnt: u64,
    mount_parent: u64,
    mount_mountpoint: u64,
}

impl CwdOffsets {
    #[inline(always)]
    fn read() -> Option<Self> {
        let all = [
            setting(&TASK_FS_OFF),
            setting(&FS_PWD_OFF),
            setting(&FS_ROOT_OFF),
            setting(&PATH_MNT_OFF),
            setting(&PATH_DENTRY_OFF),
            setting(&DENTRY_PARENT_OFF),
            setting(&DENTRY_NAME_OFF),
            setting(&QSTR_NAME_OFF),
            setting(&VFSMOUNT_ROOT_OFF),
            setting(&MOUNT_MNT_OFF),
            setting(&MOUNT_PARENT_OFF),
            setting(&MOUNT_MOUNTPOINT_OFF),
        ];
        if all.contains(&ABSENT) {
            return None;
        }
        let [
            task_fs,
            fs_pwd,
            fs_root,
            path_mnt,
            path_dentry,
            parent,
            name,
            qstr_name,
            root,
            mnt,
            mparent,
            mpoint,
        ] = all.map(u64::from);
        Some(Self {
            task_fs,
            fs_pwd,
            fs_root,
            path_mnt,
            path_dentry,
            dentry_parent: parent,
            // The name pointer inside the `qstr` inside the dentry.
            dentry_name: name + qstr_name,
            vfsmount_root: root,
            mount_mnt: mnt,
            mount_parent: mparent,
            mount_mountpoint: mpoint,
        })
    }
}

/// Walks from `task->fs->pwd` up to the process's root (`fs->root`), as
/// `d_path` does: up `d_parent` within a mount, and from a mount's root to
/// where it is mounted in its parent. Returns whether the walk reached the
/// root with every component whole. A deeper directory, a longer name, or a
/// failed read is `false`: unread, never a cut path.
fn walk_cwd(record: &mut CwdRecord, o: &CwdOffsets) -> Option<bool> {
    // SAFETY: returns the current task pointer; no memory behind the call.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage - a BPF helper or map access, which only exists as unsafe; the kernel verifier checks it, and the SAFETY comment states why it holds
    let task = unsafe { bpf_get_current_task() };
    let fs = read_kernel::<u64>(task + o.task_fs).filter(|fs| *fs != 0)?;
    let mut vfsmnt = read_kernel::<u64>(fs + o.fs_pwd + o.path_mnt)?;
    let mut dentry = read_kernel::<u64>(fs + o.fs_pwd + o.path_dentry)?;
    let root_mnt = read_kernel::<u64>(fs + o.fs_root + o.path_mnt)?;
    let root_dentry = read_kernel::<u64>(fs + o.fs_root + o.path_dentry)?;
    for (i, (name, read)) in record
        .names
        .iter_mut()
        .zip(record.lens.iter_mut())
        .enumerate()
    {
        // Cross mount roots until a component, or the root, is reached.
        let mut settled = false;
        for _ in 0..MOUNT_HOPS {
            if dentry == root_dentry && vfsmnt == root_mnt {
                return Some(true);
            }
            let mnt_root = read_kernel::<u64>(vfsmnt + o.vfsmount_root)?;
            if dentry != mnt_root {
                settled = true;
                break;
            }
            // `struct vfsmount` is the `mnt` member of `struct mount`.
            let mount = vfsmnt - o.mount_mnt;
            let parent = read_kernel::<u64>(mount + o.mount_parent)?;
            if parent == mount {
                // The root of the namespace's first mount: above the
                // process's root, which should have stopped the walk.
                return Some(false);
            }
            dentry = read_kernel::<u64>(mount + o.mount_mountpoint)?;
            vfsmnt = parent + o.mount_mnt;
        }
        if !settled {
            return Some(false);
        }
        let parent = read_kernel::<u64>(dentry + o.dentry_parent)?;
        if parent == dentry {
            return Some(false);
        }
        let at = read_kernel::<u64>(dentry + o.dentry_name)?;
        // SAFETY: the helper writes at most `name.len()` bytes into `name`,
        // NUL-terminated, and fails rather than faults on a bad address.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage - a BPF helper or map access, which only exists as unsafe; the kernel verifier checks it, and the SAFETY comment states why it holds
        *read = unsafe {
            bpf_probe_read_kernel_str(
                name.as_mut_ptr().cast(),
                name.len() as u32,
                at as *const core::ffi::c_void,
            )
        } as i32;
        record.count = i as u32 + 1;
        if *read <= 1 || *read as usize >= name.len() {
            return Some(false);
        }
        dentry = parent;
    }
    // Deeper than `CWD_DEPTH`, unless the root is right there.
    Some(dentry == root_dentry && vfsmnt == root_mnt)
}

fn exit(ctx: &TracePointContext) -> Option<()> {
    let id = bpf_get_current_pid_tgid();
    let (tgid, tid) = ((id >> 32) as u32, id as u32);
    let last_of_process = if setting(&EXIT_GROUP_DEAD) == ABSENT {
        tid == tgid
    } else {
        field::<u8>(ctx, &EXIT_GROUP_DEAD)? != 0
    };
    if !last_of_process {
        return None;
    }

    let mut entry = reserve()?;
    let event = entry.write(ProcessEvent::EMPTY);
    stamp(event, Kind::Exit);
    event.pid = tgid;
    entry.submit(0);
    Some(())
}

fn sys_enter(ctx: &TracePointContext) -> Option<()> {
    // The syscall's number. `common_type` cannot say which call: the kernel
    // puts a register pointer over it for BPF (see `SPECS_MAP`).
    let call = u32::try_from(field::<i32>(ctx, &SYS_NR)?).ok()?;
    // SAFETY: a copy is taken at once; the loader writes `SPECS` only
    // before any program is attached, so the entry cannot change under it.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage - a BPF helper or map access, which only exists as unsafe; the kernel verifier checks it, and the SAFETY comment states why it holds
    let spec = unpack(*unsafe { SPECS.get(&call) }?);
    let count = usize::from(spec[6] & 0x7).min(ARGS);
    let base = setting(&SYS_ARGS) as usize;
    // Every write on the host passes here. Only one on an internet socket
    // this probe saw made is kept long enough to see its result.
    if spec[7] == SocketRole::Sends as u8 {
        let fd = read::<u64>(ctx, base)?;
        inet_socket(socket_key(current_tgid(), fd))?;
    }
    let mut pending = Pending {
        call,
        pad: 0,
        args: [0; ARGS],
    };
    for (i, arg) in pending.args.iter_mut().enumerate() {
        if i < count {
            *arg = read::<u64>(ctx, base + i * 8)?;
        }
    }
    PENDING.insert(bpf_get_current_pid_tgid(), pending, 0).ok()
}

fn sys_exit(ctx: &TracePointContext) -> Option<()> {
    let id = bpf_get_current_pid_tgid();
    // SAFETY: a copy is taken at once, and only this thread's own enter and
    // exit touch its entry, one after the other on one CPU.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage - a BPF helper or map access, which only exists as unsafe; the kernel verifier checks it, and the SAFETY comment states why it holds
    let pending = *unsafe { PENDING.get(&id) }?;
    let _ = PENDING.remove(&id);
    // SAFETY: as in `sys_enter`.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage - a BPF helper or map access, which only exists as unsafe; the kernel verifier checks it, and the SAFETY comment states why it holds
    let spec = unpack(*unsafe { SPECS.get(&pending.call) }?);
    let mut ret: i64 = field(ctx, &SYS_RET)?;
    if spec[7] == SocketRole::Sends as u8 {
        ret = sum_sent(&pending, id, ret)?;
    }

    // Before reserving: a discarded entry holds its ring space until the
    // sensor reads past it, so filtering after would still fill the ring.
    if filtered(&pending.args, &spec, ret) {
        return None;
    }
    // SAFETY: as in `stamp`.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage - a BPF helper or map access, which only exists as unsafe; the kernel verifier checks it, and the SAFETY comment states why it holds
    let now = unsafe { bpf_ktime_get_boot_ns() };
    // A relative path is resolved against the working directory by user
    // space, so the directory goes just ahead of the call, with its time.
    if relative_path(&pending.args, &spec) {
        let _ = emit_cwd(&SYSCALLS, LOST_SYSCALLS, now);
    }

    // Built in this CPU's scratch record, then written to the ring only as
    // far as its paths go: most calls use a fraction of the two path slots,
    // and a whole record each filled the ring in container-start bursts.
    let scratch = SCRATCH.get_ptr_mut(0)?;
    // SAFETY: this CPU's slot of a live map. A tracepoint program runs to
    // completion on one CPU and BPF programs do not nest on it, so nothing
    // else touches the slot meanwhile.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage - a BPF helper or map access, which only exists as unsafe; the kernel verifier checks it, and the SAFETY comment states why it holds
    let record = unsafe { &mut *scratch };
    *record = SyscallRecord::EMPTY;
    record.boot_ns = now;
    record.cgroup = cgroup();
    record.ret = ret;
    record.args = pending.args;
    record.call = pending.call;
    record.pid = (id >> 32) as u32;
    record.tid = id as u32;
    record.uid = bpf_get_current_uid_gid() as u32;
    if let Ok(comm) = bpf_get_current_comm() {
        record.comm = comm;
    }
    record.pid_namespace = namespace() as u32;
    record.tty = current_tty();
    read_credentials(record);

    if let Some(at) = arg(&pending.args, spec[0]) {
        record.path_read = read_string(at, &mut record.path);
    }
    if let Some(at) = arg(&pending.args, spec[1]) {
        record.path2_read = read_string(at, &mut record.path2);
    }
    record.socket = track_socket(&pending.args, spec[7], ret, record.pid);
    let (at, len) = address(&pending.args, &spec, ret);
    if at != 0 && len > 0 {
        let len = len.min(ADDR_LEN as u32);
        // SAFETY: the helper writes at most `len` bytes, which is at most
        // `record.addr.len()`, into `record.addr`; a bad user address fails
        // the read rather than faulting.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage - a BPF helper or map access, which only exists as unsafe; the kernel verifier checks it, and the SAFETY comment states why it holds
        let read = unsafe {
            read_user_bytes(
                record.addr.as_mut_ptr().cast(),
                len,
                at as *const core::ffi::c_void,
            )
        };
        if read == 0 {
            record.addr_read = len;
        }
    }
    let len = record.used_len().min(SyscallRecord::SIZE);
    // SAFETY: `scratch` is one whole `SyscallRecord`, and `len` is at most
    // its size.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage - a BPF helper or map access, which only exists as unsafe; the kernel verifier checks it, and the SAFETY comment states why it holds
    let bytes = unsafe { core::slice::from_raw_parts(scratch.cast::<u8>(), len) };
    if SYSCALLS.output::<[u8]>(bytes, 0).is_err() {
        count_lost(LOST_SYSCALLS);
    }
    Some(())
}

/// Writes a record for a call that names no path or address, made by the
/// current task: a socket's write sum, reported at close.
fn emit_call(call: u32, args: [u64; ARGS], ret: i64, socket: u32) -> Option<()> {
    let id = bpf_get_current_pid_tgid();
    let scratch = SCRATCH.get_ptr_mut(0)?;
    // SAFETY: as in `sys_exit`: this CPU's slot, untouched by anything else
    // while this program runs.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage - a BPF helper or map access, which only exists as unsafe; the kernel verifier checks it, and the SAFETY comment states why it holds
    let record = unsafe { &mut *scratch };
    *record = SyscallRecord::EMPTY;
    // SAFETY: as in `stamp`.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage - a BPF helper or map access, which only exists as unsafe; the kernel verifier checks it, and the SAFETY comment states why it holds
    record.boot_ns = unsafe { bpf_ktime_get_boot_ns() };
    record.cgroup = cgroup();
    record.ret = ret;
    record.args = args;
    record.call = call;
    record.pid = (id >> 32) as u32;
    record.tid = id as u32;
    record.uid = bpf_get_current_uid_gid() as u32;
    if let Ok(comm) = bpf_get_current_comm() {
        record.comm = comm;
    }
    record.pid_namespace = namespace() as u32;
    record.tty = current_tty();
    read_credentials(record);
    record.socket = socket;
    let len = record.used_len().min(SyscallRecord::SIZE);
    // SAFETY: as in `sys_exit`.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage - a BPF helper or map access, which only exists as unsafe; the kernel verifier checks it, and the SAFETY comment states why it holds
    let bytes = unsafe { core::slice::from_raw_parts(scratch.cast::<u8>(), len) };
    if SYSCALLS.output::<[u8]>(bytes, 0).is_err() {
        count_lost(LOST_SYSCALLS);
    }
    Some(())
}

fn exec_args(ctx: &TracePointContext, slot: usize) -> Option<()> {
    let argv = read::<u64>(ctx, setting(&SYS_ARGS) as usize + slot * 8)?;

    // From here on nothing returns early: the entry is submitted.
    let Some(mut entry) = EVENTS.reserve::<ArgvRecord>(0) else {
        count_lost(LOST_EVENTS);
        return None;
    };
    let record = entry.write(ArgvRecord::EMPTY);
    // SAFETY: as in `stamp`.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage - a BPF helper or map access, which only exists as unsafe; the kernel verifier checks it, and the SAFETY comment states why it holds
    record.boot_ns = unsafe { bpf_ktime_get_boot_ns() };
    let id = bpf_get_current_pid_tgid();
    record.pid = (id >> 32) as u32;
    record.tid = id as u32;
    // A null `argv` is an empty argument list.
    let mut ended = argv == 0;
    let mut whole = true;
    if !ended {
        for (i, (arg, read)) in record
            .args
            .iter_mut()
            .zip(record.lens.iter_mut())
            .enumerate()
        {
            let Some(at) = user::<u64>(argv + (i as u64) * 8) else {
                whole = false;
                break;
            };
            if at == 0 {
                ended = true;
                break;
            }
            *read = read_string(at, arg);
            record.count = i as u32 + 1;
            if *read <= 0 || *read as usize >= arg.len() {
                whole = false;
                break;
            }
        }
        if whole && !ended {
            // Exactly `ARGV_MAX` arguments, or more.
            ended = user::<u64>(argv + (ARGV_MAX as u64) * 8) == Some(0);
        }
    }
    record.complete = u32::from(ended && whole);
    entry.submit(0);
    Some(())
}

/// Whether a call is dropped here, never reported. Two kinds, both read by
/// no rule and together most of all calls (docs/ebpf/PLAN.md, E4, E9):
///
/// - a read-only open under `/proc/`, or of the dynamic linker's cache,
///   opened once by each program started;
/// - a receive with no IPv4 or IPv6 sender, or on a socket known to be a
///   stream: the only receive the rules read is inbound UDP from a named
///   peer. A socket made before the probe loaded is not known, so kept.
#[inline(always)]
fn filtered(args: &[u64; ARGS], spec: &[u8; 8], ret: i64) -> bool {
    if let Some(flags) = value(args, spec[5])
        && flags & OPEN_BEYOND_READ == 0
        && let Some(at) = arg(args, spec[0])
    {
        let mut head = [0_u8; 24];
        let read = read_string(at, &mut head);
        return head.starts_with(b"/proc/")
            || (read == LD_SO_CACHE.len() as i32 && head.starts_with(LD_SO_CACHE));
    }
    if spec[7] != SocketRole::Receives as u8 {
        return false;
    }
    let (at, len) = address(args, spec, ret);
    if at == 0 || len < 2 {
        return true;
    }
    let Some(family) = user::<u16>(at) else {
        return true;
    };
    if family != AF_INET && family != AF_INET6 {
        return true;
    }
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let first = value(args, 0).unwrap_or(0);
    // SAFETY: a copy is taken at once, as in `track_socket`.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage - a BPF helper or map access, which only exists as unsafe; the kernel verifier checks it, and the SAFETY comment states why it holds
    match unsafe { SOCKETS.get(socket_key(tgid, first)) } {
        Some(kind) => (*kind >> 8) & 0xff == SOCK_STREAM,
        None => false,
    }
}

/// The bytes in [`SENT`]'s packed values.
const SENT_BYTES: u64 = (1 << 48) - 1;

/// The kind of the internet socket at `key`, or `None` when the probe did
/// not see it made or it is not IPv4 or IPv6.
fn inet_socket(key: u64) -> Option<u32> {
    // SAFETY: a copy is taken at once, as in `track_socket`.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage - a BPF helper or map access, which only exists as unsafe; the kernel verifier checks it, and the SAFETY comment states why it holds
    let kind = *unsafe { SOCKETS.get(key) }?;
    let domain = (kind >> 16) & 0xff;
    (domain == u32::from(AF_INET) || domain == u32::from(AF_INET6)).then_some(kind)
}

/// Adds a socket write's bytes to its sum. The sum once it reaches
/// [`SEND_REPORT_BYTES`], to be reported now; `None` until then, and for a
/// write that wrote nothing.
fn sum_sent(pending: &Pending, id: u64, ret: i64) -> Option<i64> {
    if ret <= 0 {
        return None;
    }
    let key = socket_key((id >> 32) as u32, pending.args[0]);
    // SAFETY: a copy is taken at once. Two threads writing one socket at
    // once can lose one addition between them; the count is then low,
    // never invented.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage - a BPF helper or map access, which only exists as unsafe; the kernel verifier checks it, and the SAFETY comment states why it holds
    let before = unsafe { SENT.get(key) }.map_or(0, |packed| *packed & SENT_BYTES);
    let total = (before + ret as u64) & SENT_BYTES;
    if total < SEND_REPORT_BYTES {
        let _ = SENT.insert(key, (u64::from(pending.call) << 48) | total, 0);
        return None;
    }
    let _ = SENT.remove(key);
    Some(total as i64)
}

/// The key of one process's descriptor in `SOCKETS`.
fn socket_key(tgid: u32, fd: u64) -> u64 {
    (u64::from(tgid) << 32) | (fd & 0xffff_ffff)
}

/// Keeps `SOCKETS` in step with a call that makes, copies or uses a socket,
/// and returns the call's socket for its record: packed with
/// `SOCKET_KNOWN`, or zero when not known.
fn track_socket(args: &[u64; ARGS], role: u8, ret: i64, tgid: u32) -> u32 {
    let first = value(args, 0).unwrap_or(0);
    let known = |kind: u32| kind | SOCKET_KNOWN;
    if role == SocketRole::Makes as u8 && ret >= 0 {
        let kind = SocketKind::from_args(
            first,
            value(args, 1).unwrap_or(0),
            value(args, 2).unwrap_or(0),
        )
        .pack();
        let _ = SOCKETS.insert(socket_key(tgid, ret as u64), kind, 0);
        return known(kind);
    }
    // SAFETY: a copy is taken at once; a concurrent update of the same
    // entry by another thread of the process can only give an older kind.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage - a BPF helper or map access, which only exists as unsafe; the kernel verifier checks it, and the SAFETY comment states why it holds
    let Some(kind) = (unsafe { SOCKETS.get(socket_key(tgid, first)) }).copied() else {
        return 0;
    };
    if role == SocketRole::Copies as u8 && ret >= 0 {
        let _ = SOCKETS.insert(socket_key(tgid, ret as u64), kind, 0);
        return known(kind);
    }
    if role == SocketRole::Uses as u8
        || role == SocketRole::Receives as u8
        || role == SocketRole::Sends as u8
    {
        return known(kind);
    }
    0
}

/// Argument `slot` as a pointer: `None` when the spec leaves it unused or
/// the pointer is null.
#[inline(always)]
fn arg(args: &[u64; ARGS], slot: u8) -> Option<u64> {
    value(args, slot).filter(|v| *v != 0)
}

/// Argument `slot` as a value, zero included: `None` only when the spec
/// leaves it unused. Flags of zero are `O_RDONLY`, not "no flags".
#[inline(always)]
fn value(args: &[u64; ARGS], slot: u8) -> Option<u64> {
    // Constant positions only: an index the compiler bounds-checks on one
    // register and then reads through another is a variable stack offset
    // the verifier rejects.
    let [a0, a1, a2, a3, a4, a5] = *args;
    match slot {
        0 => Some(a0),
        1 => Some(a1),
        2 => Some(a2),
        3 => Some(a3),
        4 => Some(a4),
        5 => Some(a5),
        _ => None,
    }
}

/// Copies a NUL-terminated string from the caller's memory. Returns what the
/// helper returned: the length with the NUL, or a negated error.
fn read_string(at: u64, into: &mut [u8]) -> i32 {
    // SAFETY: the helper writes at most `into.len()` bytes into `into`,
    // always NUL-terminated, and on a bad address fails rather than faults.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage - a BPF helper or map access, which only exists as unsafe; the kernel verifier checks it, and the SAFETY comment states why it holds
    let read = unsafe {
        bpf_probe_read_user_str(
            into.as_mut_ptr().cast(),
            into.len() as u32,
            at as *const core::ffi::c_void,
        )
    };
    read as i32
}

/// Where the call's socket address is, and how long: `(0, 0)` for none.
/// Every read here is of the caller's own memory and may fail; a failure is
/// no address, never a guess.
// Inlined: out of line, it returns a pointer into its caller's stack,
// which the verifier refuses.
#[inline(always)]
fn address(args: &[u64; ARGS], spec: &[u8; 8], ret: i64) -> (u64, u32) {
    // Plain early returns, not `Option` combinators: those compiled to a
    // branch reading a register no path had written, which the verifier
    // rejects.
    const NONE: (u64, u32) = (0, 0);
    let kind = spec[2];
    let Some(at) = arg(args, spec[3]) else {
        return NONE;
    };
    if kind == Addr::In as u8 {
        return match value(args, spec[4]) {
            Some(len) => (at, len as u32),
            None => NONE,
        };
    }
    // Written by the kernel, so only there when the call succeeded.
    if kind == Addr::Out as u8 {
        if ret < 0 {
            return NONE;
        }
        let Some(len_at) = arg(args, spec[4]) else {
            return NONE;
        };
        return match user::<u32>(len_at) {
            Some(len) => (at, len),
            None => NONE,
        };
    }
    // `struct msghdr` begins with `msg_name` and `msg_namelen`.
    if kind == Addr::Msg as u8 {
        let Some(name) = user::<u64>(at) else {
            return NONE;
        };
        let Some(len) = user::<u32>(at + 8) else {
            return NONE;
        };
        if name != 0 {
            return (name, len);
        }
    }
    NONE
}

/// A value from the caller's memory.
fn user<T>(at: u64) -> Option<T> {
    // SAFETY: the helper copies `size_of::<T>()` bytes and fails, never
    // faults, on an address the caller cannot read.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage - a BPF helper or map access, which only exists as unsafe; the kernel verifier checks it, and the SAFETY comment states why it holds
    unsafe { bpf_probe_read_user(at as *const T) }.ok()
}

/// A slot in the ring buffer, or `None` (and one more counted in `LOST`)
/// when it is full.
fn reserve() -> Option<RingBufEntry<ProcessEvent>> {
    let entry = EVENTS.reserve::<ProcessEvent>(0);
    if entry.is_none() {
        count_lost(LOST_EVENTS);
    }
    entry
}

fn count_lost(slot: u32) {
    if let Some(count) = LOST.get_ptr_mut(slot) {
        // SAFETY: `count` is this CPU's slot of a live map. The kernel runs a
        // tracepoint program to completion on one CPU and does not nest BPF
        // programs on it, so nothing else touches this slot meanwhile.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage - a BPF helper or map access, which only exists as unsafe; the kernel verifier checks it, and the SAFETY comment states why it holds
        unsafe { *count = (*count).wrapping_add(1) };
    }
}

/// The fields every event carries, taken from the current task.
fn stamp(event: &mut ProcessEvent, kind: Kind) {
    // SAFETY: a helper taking no arguments, available from kernel 5.8, which
    // this probe's ring buffer already requires.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage - a BPF helper or map access, which only exists as unsafe; the kernel verifier checks it, and the SAFETY comment states why it holds
    event.boot_ns = unsafe { bpf_ktime_get_boot_ns() };
    event.cgroup = cgroup();
    event.kind = kind as u32;
    // The low half is the real uid.
    event.uid = bpf_get_current_uid_gid() as u32;
    if let Ok(comm) = bpf_get_current_comm() {
        event.comm = comm;
    }
    event.pid_namespace = namespace() as u32;
    event.tty = current_tty();
}

/// Whether the current task has a controlling terminal. Rules distinguish
/// only zero from nonzero, so no device path or terminal content is read.
fn current_tty() -> u32 {
    let signal_off = setting(&TASK_SIGNAL_OFF);
    let tty_off = setting(&SIGNAL_TTY_OFF);
    if signal_off == ABSENT || tty_off == ABSENT {
        return ABSENT;
    }
    // SAFETY: this kernel helper returns the current task pointer; the guarded
    // reads below use BPF probe-read helpers and never dereference it in Rust.
    let task = unsafe { bpf_get_current_task() }; // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if task == 0 {
        return ABSENT;
    }
    let Some(signal) = read_kernel::<u64>(task + u64::from(signal_off)).filter(|p| *p != 0)
    else {
        return ABSENT;
    };
    read_kernel::<u64>(signal + u64::from(tty_off)).map_or(ABSENT, |tty| u32::from(tty != 0))
}

/// Whether the current task is in the host's pid namespace. Answered by the
/// kernel from the task itself, so it holds for a process that is gone
/// before anything in user space could look.
fn namespace() -> Namespace {
    let (dev, ino) = (setting64(&HOST_PIDNS_DEV), setting64(&HOST_PIDNS_INO));
    if ino == 0 {
        return Namespace::Unknown;
    }
    let mut info = bpf_pidns_info { pid: 0, tgid: 0 };
    // SAFETY: `info` is a live, writable `bpf_pidns_info`, and the size
    // passed is exactly its size, so the helper writes only inside it.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage - a BPF helper or map access, which only exists as unsafe; the kernel verifier checks it, and the SAFETY comment states why it holds
    let answer = unsafe {
        bpf_get_ns_current_pid_tgid(
            dev,
            ino,
            &raw mut info,
            core::mem::size_of::<bpf_pidns_info>() as u32,
        )
    };
    match answer {
        0 => Namespace::Host,
        // Size and device are right by construction, so EINVAL here means
        // the task is in another namespace.
        e if e == -EINVAL => Namespace::Other,
        _ => Namespace::Unknown,
    }
}

/// The caller's capability sets and audit login id, followed from its
/// `task_struct` through the offsets the loader read from BTF. Each read may
/// fail on a kernel that lays these out differently; a failure leaves the
/// field unread, never guessed.
fn read_credentials(record: &mut SyscallRecord) {
    // SAFETY: returns the current task's kernel pointer; no memory behind
    // the call itself.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage - a BPF helper or map access, which only exists as unsafe; the kernel verifier checks it, and the SAFETY comment states why it holds
    let task = unsafe { bpf_get_current_task() };
    if task == 0 {
        return;
    }
    let login_off = setting(&TASK_LOGINUID_OFF);
    if login_off != ABSENT
        && let Some(uid) = read_kernel::<u32>(task + u64::from(login_off))
    {
        record.loginuid = uid;
    }
    let cred_off = setting(&TASK_CRED_OFF);
    let eff_off = setting(&CRED_CAP_EFFECTIVE_OFF);
    let perm_off = setting(&CRED_CAP_PERMITTED_OFF);
    if cred_off == ABSENT || eff_off == ABSENT || perm_off == ABSENT {
        return;
    }
    let Some(cred) = read_kernel::<u64>(task + u64::from(cred_off)).filter(|c| *c != 0) else {
        return;
    };
    // kernel_cap_t is one u64 (6.3+) or two u32 (older); either way eight
    // little-endian bytes hold the whole 64-bit mask.
    if let (Some(eff), Some(perm)) = (
        read_kernel::<u64>(cred + u64::from(eff_off)),
        read_kernel::<u64>(cred + u64::from(perm_off)),
    ) {
        record.cap_effective = eff;
        record.cap_permitted = perm;
        record.caps_known = 1;
    }
}

/// The current task's audit login id, followed from its `task_struct`, or
/// [`ABSENT`] when this kernel has no such field. Read at exec so the
/// lifecycle event carries it, as the syscall records do.
fn current_loginuid() -> u32 {
    let off = setting(&TASK_LOGINUID_OFF);
    if off == ABSENT {
        return ABSENT;
    }
    // SAFETY: returns the current task pointer; no memory behind the call.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage - a BPF helper or map access, which only exists as unsafe; the kernel verifier checks it, and the SAFETY comment states why it holds
    let task = unsafe { bpf_get_current_task() };
    if task == 0 {
        return ABSENT;
    }
    read_kernel::<u32>(task + u64::from(off)).unwrap_or(ABSENT)
}

/// A value at a kernel address, or `None` when it cannot be read.
fn read_kernel<T>(addr: u64) -> Option<T> {
    // SAFETY: the helper copies `size_of::<T>()` bytes and fails, never
    // faults, on an address the program may not read.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage - a BPF helper or map access, which only exists as unsafe; the kernel verifier checks it, and the SAFETY comment states why it holds
    unsafe { bpf_probe_read_kernel(addr as *const T) }.ok()
}

/// The current task's cgroup id: which container, if any, user space works
/// out from it. Zero where the kernel has no cgroup v2 to report.
fn cgroup() -> u64 {
    // SAFETY: a helper taking no arguments (kernel 4.18), with no memory
    // behind its result.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage - a BPF helper or map access, which only exists as unsafe; the kernel verifier checks it, and the SAFETY comment states why it holds
    unsafe { bpf_get_current_cgroup_id() }
}

/// The current task's process id (its thread group id).
fn current_tgid() -> u32 {
    (bpf_get_current_pid_tgid() >> 32) as u32
}

/// Reads one field of this tracepoint's record, at the offset the loader
/// wrote into `offset`.
fn field<T>(ctx: &TracePointContext, offset: &'static u32) -> Option<T> {
    read(ctx, setting(offset) as usize)
}

/// Reads a value of this tracepoint's record at `offset`.
fn read<T>(ctx: &TracePointContext, offset: usize) -> Option<T> {
    // SAFETY: the offset is the kernel's own description of this record, and
    // `read_at` copies through `bpf_probe_read`, so an offset that were
    // somehow wrong would fail the read, never fault.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage - a BPF helper or map access, which only exists as unsafe; the kernel verifier checks it, and the SAFETY comment states why it holds
    unsafe { ctx.read_at::<T>(offset) }.ok()
}

/// Reads a loader-written global.
#[inline(always)]
fn setting(value: &'static u32) -> u32 {
    // SAFETY: `value` is a valid, aligned static. The read is volatile so the
    // compiler keeps the load: the loader rewrites these statics after
    // compilation, so the value compiled in is not the real one.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage - a BPF helper or map access, which only exists as unsafe; the kernel verifier checks it, and the SAFETY comment states why it holds
    unsafe { core::ptr::read_volatile(value) }
}

/// Reads a loader-written 64-bit global.
#[inline(always)]
fn setting64(value: &'static u64) -> u64 {
    // SAFETY: as for `setting`.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage - a BPF helper or map access, which only exists as unsafe; the kernel verifier checks it, and the SAFETY comment states why it holds
    unsafe { core::ptr::read_volatile(value) }
}

/// Required by `no_std`. If any path could reach it, the verifier would reject
/// the program for this unbounded loop, so a probe that loads never panics.
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// The licence declared to the kernel. It must be GPL-compatible for the
/// kernel to allow GPL-only helpers; see this crate's `Cargo.toml`.
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
