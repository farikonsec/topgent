//! The probe on Linux: embedded at build time, loaded and attached at runtime.

use std::{collections::BTreeMap, fs, io, os::unix::fs::MetadataExt as _};

use aya::{
    Ebpf, EbpfLoader,
    maps::{HashMap, MapData, PerCpuArray, RingBuf},
    programs::TracePoint,
};
use topgent_ebpf_common::{
    ABSENT, ARGV_AT_EXEC_FIELDS, ARGV_PROGRAMS, ArgvRecord, BTF_FIELDS, CLOSE_PROGRAM, CWD_FIELDS,
    CwdRecord, EVENTS_MAP, FIELD_SETTINGS, FieldSetting, HOST_PIDNS_DEV, HOST_PIDNS_INO,
    LOST_EVENTS, LOST_MAP, LOST_SYSCALLS, ProcessEvent, SPECS_MAP, SYS_ARGS, SYS_ENTER_PROGRAM,
    SYS_EXIT_PROGRAM, SYS_NR, SYS_RET, SYSCALL_SPECS, SYSCALLS_CATEGORY, SYSCALLS_MAP,
    SyscallRecord, TRACEPOINTS, syscall_numbers,
};

use crate::{Unavailable, format};

/// Where tracefs is mounted: its own mount first, then the older place
/// under debugfs.
const TRACEFS: [&str; 2] = ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"];

/// The probe, loaded and attached, with the maps user space reads.
///
/// Dropping it detaches and unloads every program: nothing Topgent put into
/// the kernel outlives this value.
pub struct Probe {
    ebpf: Ebpf,
    events: RingBuf<MapData>,
    syscalls: RingBuf<MapData>,
    lost: PerCpuArray<MapData, u64>,
    malformed: u64,
    host_pid_namespace: Option<u64>,
    /// Syscall number to the call's name, for every call traced.
    names: BTreeMap<u32, &'static str>,
    /// Rule syscalls this kernel has no usable tracepoint for, and why.
    untraced: Vec<(&'static str, String)>,
    /// Exec arguments drained with the process events, not yet taken.
    argv: Vec<ArgvRecord>,
    /// Whether exec arguments are read on this kernel.
    reads_argv: bool,
    /// Working directories drained with execs, not yet taken.
    cwds: Vec<CwdRecord>,
    /// Working directories drained with calls, not yet taken.
    call_cwds: Vec<CwdRecord>,
    /// Whether working directories are read on this kernel.
    reads_cwd: bool,
}

// By hand: aya's map handles do not implement `Debug`.
impl std::fmt::Debug for Probe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Probe")
            .field("ebpf", &self.ebpf)
            .field("malformed", &self.malformed)
            .finish_non_exhaustive()
    }
}

impl Probe {
    /// Kernel ids of the loaded programs, as `bpftool prog` lists them.
    ///
    /// # Errors
    ///
    /// [`Unavailable::Refused`] when the kernel will not describe a program.
    pub fn program_ids(&self) -> Result<Vec<u32>, Unavailable> {
        self.ebpf
            .programs()
            .map(|(_, program)| program.info().map(|info| info.id()).map_err(refused))
            .collect()
    }

    /// Moves every event waiting in the ring buffer into `into`, oldest
    /// first, without blocking. Returns how many it moved. Exec arguments
    /// found on the way are kept for [`Probe::take_argv`].
    ///
    /// A record that is not one whole event is not guessed at; it is counted
    /// in [`Probe::malformed`].
    pub fn drain(&mut self, into: &mut Vec<ProcessEvent>) -> usize {
        let before = into.len();
        while let Some(record) = self.events.next() {
            if let Some(event) = ProcessEvent::decode(&record) {
                into.push(event);
            } else if let Some(argv) = ArgvRecord::decode(&record) {
                self.argv.push(argv);
            } else if let Some(cwd) = CwdRecord::decode(&record) {
                self.cwds.push(cwd);
            } else {
                self.malformed = self.malformed.saturating_add(1);
            }
        }
        into.len().saturating_sub(before)
    }

    /// Moves the exec arguments the last drains found into `into`, oldest
    /// first. Each came before the exec it belongs to, so taking them right
    /// after a drain and before handling its events keeps them in order.
    pub fn take_argv(&mut self, into: &mut Vec<ArgvRecord>) {
        into.append(&mut self.argv);
    }

    /// Whether exec arguments are read on this kernel.
    #[must_use]
    pub const fn reads_argv(&self) -> bool {
        self.reads_argv
    }

    /// Moves the working directories sent with execs, which the last drains
    /// found, into `into`, oldest first. Each came just before its exec, as
    /// exec arguments do.
    pub fn take_cwds(&mut self, into: &mut Vec<CwdRecord>) {
        into.append(&mut self.cwds);
    }

    /// Moves the working directories sent with calls that had a relative
    /// path into `into`. Each carries its call's `boot_ns` and thread, so it
    /// is matched to the call by those, not by its place in the order.
    pub fn take_call_cwds(&mut self, into: &mut Vec<CwdRecord>) {
        into.append(&mut self.call_cwds);
    }

    /// Whether working directories are read on this kernel.
    #[must_use]
    pub const fn reads_cwd(&self) -> bool {
        self.reads_cwd
    }

    /// Moves every syscall waiting in its ring buffer into `into`, oldest
    /// first, without blocking. Returns how many it moved. A record that is
    /// not one whole record is counted in [`Probe::malformed`].
    pub fn drain_syscalls(&mut self, into: &mut Vec<SyscallRecord>) -> usize {
        let before = into.len();
        while let Some(record) = self.syscalls.next() {
            if let Some(record) = SyscallRecord::decode(&record) {
                into.push(record);
            } else if let Some(cwd) = CwdRecord::decode(&record) {
                self.call_cwds.push(cwd);
            } else {
                self.malformed = self.malformed.saturating_add(1);
            }
        }
        into.len().saturating_sub(before)
    }

    /// The name of the call a record's `call` id is, if the probe traces it.
    #[must_use]
    pub fn syscall_name(&self, call: u32) -> Option<&'static str> {
        self.names.get(&call).copied()
    }

    /// Every syscall traced, by name.
    #[must_use]
    pub fn traced(&self) -> Vec<&'static str> {
        self.names.values().copied().collect()
    }

    /// Rule syscalls not traced on this kernel, each with why: most often
    /// that the architecture has no such call (arm64 has no `open`).
    #[must_use]
    pub fn untraced(&self) -> &[(&'static str, String)] {
        &self.untraced
    }

    /// Process events the kernel dropped because their ring buffer was
    /// full, since load.
    ///
    /// # Errors
    ///
    /// [`Unavailable::Refused`] when the kernel will not read the counter.
    pub fn lost(&self) -> Result<u64, Unavailable> {
        self.lost_in(LOST_EVENTS)
    }

    /// Syscalls the kernel dropped because their ring buffer was full.
    ///
    /// # Errors
    ///
    /// As for [`Probe::lost`].
    pub fn syscalls_lost(&self) -> Result<u64, Unavailable> {
        self.lost_in(LOST_SYSCALLS)
    }

    fn lost_in(&self, slot: u32) -> Result<u64, Unavailable> {
        let per_cpu = self.lost.get(&slot, 0).map_err(refused)?;
        Ok(per_cpu.iter().fold(0, |sum, n| sum.saturating_add(*n)))
    }

    /// The inode of the pid namespace events were compared with: the one
    /// this process runs in. `None` when it could not be read, and then
    /// every event's namespace is unknown.
    #[must_use]
    pub const fn host_pid_namespace(&self) -> Option<u64> {
        self.host_pid_namespace
    }

    /// Records read from the ring buffer that were not one whole event.
    /// Should stay zero; anything else is a build fault.
    #[must_use]
    pub const fn malformed(&self) -> u64 {
        self.malformed
    }
}

pub(crate) fn load() -> Result<Probe, Unavailable> {
    let offsets = field_offsets()?;
    let plan = syscall_plan()?;
    // The namespace every event is compared with: this process's own. Unread,
    // it stays zero and the probe answers "unknown" rather than guess.
    let (pidns_dev, pidns_ino) =
        fs::metadata("/proc/self/ns/pid").map_or((0, 0), |ns| (ns.dev(), ns.ino()));
    let btf_offsets = btf_offsets();
    let mut loader = EbpfLoader::new();
    for (global, offset) in offsets.iter().chain(&btf_offsets) {
        loader.override_global(global, offset, true);
    }
    loader.override_global(HOST_PIDNS_DEV, &pidns_dev, true);
    loader.override_global(HOST_PIDNS_INO, &pidns_ino, true);
    loader.override_global(SYS_NR, &plan.nr_at, true);
    loader.override_global(SYS_ARGS, &plan.args_at, true);
    loader.override_global(SYS_RET, &plan.ret_at, true);
    // The object the build script compiled for this host's byte order.
    let object = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/topgent-probe"));
    let mut ebpf = loader.load(object).map_err(refused)?;

    for (name, category, event) in TRACEPOINTS {
        let program = tracepoint(&mut ebpf, name)?;
        program.load().map_err(refused)?;
        program.attach(category, event).map_err(refused)?;
    }

    // Closing a descriptor must be seen for the socket table to be kept;
    // without it no call is given a socket kind (see below).
    let close_at = tracepoint_format(SYSCALLS_CATEGORY, "sys_enter_close")
        .ok()
        .and_then(|text| format::syscall_args(&text))
        .and_then(|args| args.first().map(|first| first.offset));
    let knows_sockets = plan.args_at != ABSENT && close_at == Some(plan.args_at);
    // Every spec is in place before a program that reads them is attached.
    let mut specs: HashMap<_, u32, u64> = HashMap::try_from(
        ebpf.map_mut(SPECS_MAP)
            .ok_or_else(|| Unavailable::Mismatch(format!("no map {SPECS_MAP}")))?,
    )
    .map_err(|e| Unavailable::Mismatch(format!("{SPECS_MAP}: {e}")))?;
    for call in &plan.calls {
        // The socket role is the top byte of a packed spec.
        let spec = if knows_sockets {
            call.spec
        } else {
            call.spec & !(0xff << 56)
        };
        specs.insert(call.number, spec, 0).map_err(refused)?;
    }
    let reads_argv = attach_argv(&mut ebpf, &plan, &btf_offsets)?;
    let reads_cwd = resolved(&CWD_FIELDS, &btf_offsets);
    // Closing a descriptor forgets the socket it was. Without it the table
    // could name a reused descriptor by an old kind, so no close, no kinds.
    let program = tracepoint(&mut ebpf, CLOSE_PROGRAM)?;
    program.load().map_err(refused)?;
    if knows_sockets {
        program
            .attach(SYSCALLS_CATEGORY, "sys_enter_close")
            .map_err(refused)?;
    }
    for (program, side) in [(SYS_ENTER_PROGRAM, "enter"), (SYS_EXIT_PROGRAM, "exit")] {
        let program = tracepoint(&mut ebpf, program)?;
        program.load().map_err(refused)?;
        for call in &plan.calls {
            let tracepoint = format!("sys_{side}_{}", call.name);
            program
                .attach(SYSCALLS_CATEGORY, &tracepoint)
                .map_err(refused)?;
        }
    }

    let events = RingBuf::try_from(take_map(&mut ebpf, EVENTS_MAP)?)
        .map_err(|e| Unavailable::Mismatch(format!("{EVENTS_MAP}: {e}")))?;
    let syscalls = RingBuf::try_from(take_map(&mut ebpf, SYSCALLS_MAP)?)
        .map_err(|e| Unavailable::Mismatch(format!("{SYSCALLS_MAP}: {e}")))?;
    let lost = PerCpuArray::try_from(take_map(&mut ebpf, LOST_MAP)?)
        .map_err(|e| Unavailable::Mismatch(format!("{LOST_MAP}: {e}")))?;
    Ok(Probe {
        ebpf,
        events,
        syscalls,
        lost,
        malformed: 0,
        host_pid_namespace: (pidns_ino != 0).then_some(pidns_ino),
        names: plan.calls.iter().map(|c| (c.number, c.name)).collect(),
        untraced: plan.untraced,
        argv: Vec::new(),
        reads_argv,
        cwds: Vec::new(),
        call_cwds: Vec::new(),
        reads_cwd,
    })
}

/// One syscall to trace, as this kernel describes it.
struct Traced {
    name: &'static str,
    /// Its number on this architecture.
    number: u32,
    /// Its `SyscallSpec`, packed with its argument count.
    spec: u64,
}

/// Which rule syscalls this kernel can trace, and where every one of them
/// keeps its number, arguments and result.
struct SyscallPlan {
    calls: Vec<Traced>,
    untraced: Vec<(&'static str, String)>,
    nr_at: u32,
    args_at: u32,
    ret_at: u32,
}

/// Reads every rule syscall's enter and exit description. A call this kernel
/// lacks, or lays out unlike the others, is left untraced with the reason; a
/// description that cannot be read for want of privilege refuses the whole
/// probe, as for the lifecycle tracepoints.
fn syscall_plan() -> Result<SyscallPlan, Unavailable> {
    let mut plan = SyscallPlan {
        calls: Vec::new(),
        untraced: Vec::new(),
        nr_at: ABSENT,
        args_at: ABSENT,
        ret_at: ABSENT,
    };
    for spec in SYSCALL_SPECS {
        let name = spec.name;
        let Some(number) = syscall_numbers()
            .iter()
            .find(|(_, known)| *known == name)
            .map(|(n, _)| *n)
        else {
            plan.untraced
                .push((name, "this architecture has no such call".into()));
            continue;
        };
        let mut described = |side: &str| match tracepoint_format(
            SYSCALLS_CATEGORY,
            &format!("sys_{side}_{name}"),
        ) {
            Ok(text) => Ok(Some(text)),
            Err(Unavailable::Unsupported(why)) => {
                plan.untraced.push((name, why));
                Ok(None)
            }
            Err(other) => Err(other),
        };
        let Some(enter) = described("enter")? else {
            continue;
        };
        let Some(exit) = described("exit")? else {
            continue;
        };
        let (nr, exit_nr, args, ret) = (
            format::field(&enter, "__syscall_nr"),
            format::field(&exit, "__syscall_nr"),
            format::syscall_args(&enter),
            format::field(&exit, "ret"),
        );
        let (Some(nr), Some(args), Some(ret)) = (nr, args, ret) else {
            plan.untraced.push((
                name,
                "its tracepoint has no number, arguments or result".into(),
            ));
            continue;
        };
        let args_at = args.first().map_or(plan.args_at, |first| first.offset);
        let evenly = args
            .iter()
            .zip(0u32..)
            .all(|(arg, i)| arg.size == 8 && arg.offset == args_at + 8 * i);
        let agrees = |seen: u32, here: u32| seen == ABSENT || seen == here;
        if !evenly
            || nr.size != 4
            || exit_nr != Some(nr)
            || ret.size != 8
            || !agrees(plan.nr_at, nr.offset)
            || !agrees(plan.args_at, args_at)
            || !agrees(plan.ret_at, ret.offset)
        {
            plan.untraced
                .push((name, "its tracepoint is laid out unlike the others".into()));
            continue;
        }
        (plan.nr_at, plan.args_at, plan.ret_at) = (nr.offset, args_at, ret.offset);
        let count = u8::try_from(args.len().min(topgent_ebpf_common::ARGS)).unwrap_or(0);
        plan.calls.push(Traced {
            name,
            number,
            spec: spec.pack(count),
        });
    }
    Ok(plan)
}

/// One of the probe's programs, as a tracepoint program.
fn tracepoint<'a>(ebpf: &'a mut Ebpf, name: &str) -> Result<&'a mut TracePoint, Unavailable> {
    ebpf.program_mut(name)
        .ok_or_else(|| Unavailable::Mismatch(format!("no program {name}")))?
        .try_into()
        .map_err(|e| Unavailable::Mismatch(format!("{name}: {e}")))
}

fn take_map(ebpf: &mut Ebpf, name: &str) -> Result<aya::maps::Map, Unavailable> {
    ebpf.take_map(name)
        .ok_or_else(|| Unavailable::Mismatch(format!("no map {name}")))
}

/// Whether BTF gave every one of `globals` an offset.
fn resolved(globals: &[&str], btf_offsets: &[(&'static str, u32)]) -> bool {
    globals.iter().all(|global| {
        btf_offsets
            .iter()
            .any(|(name, offset)| name == global && *offset != ABSENT)
    })
}

/// Loads the enter-time exec argument readers, attaching them only when the
/// arguments cannot be read at exec. Returns whether arguments are read.
fn attach_argv(
    ebpf: &mut Ebpf,
    plan: &SyscallPlan,
    btf_offsets: &[(&'static str, u32)],
) -> Result<bool, Unavailable> {
    // Exec arguments are read at exec from the new program's own memory
    // when BTF gives the offsets. Otherwise they ride on the enter of
    // `execve` and `execveat`, whose records share the syscall layout
    // checked above, and miss arguments not resident then (`sudo`).
    let at_exec = resolved(&ARGV_AT_EXEC_FIELDS, btf_offsets);
    let mut reads_argv = at_exec || plan.args_at != ABSENT;
    for (program, call, _) in ARGV_PROGRAMS {
        let program = tracepoint(ebpf, program)?;
        program.load().map_err(refused)?;
        if at_exec {
            continue;
        }
        let tracepoint = format!("sys_enter_{call}");
        let described = tracepoint_format(SYSCALLS_CATEGORY, &tracepoint)
            .ok()
            .and_then(|text| format::syscall_args(&text))
            .and_then(|args| args.first().map(|first| first.offset));
        if reads_argv && described == Some(plan.args_at) {
            program
                .attach(SYSCALLS_CATEGORY, &tracepoint)
                .map_err(refused)?;
        } else {
            reads_argv = false;
        }
    }
    Ok(reads_argv)
}

/// Each BTF-derived probe global and the byte offset this kernel gives its
/// field, from `/sys/kernel/btf/vmlinux`. A field this kernel lacks, or a BTF
/// file that cannot be read or parsed, leaves the global [`ABSENT`], and the
/// probe leaves what depends on it unread. Never an error: capabilities and
/// the login id are added detail, not the probe's reason to exist.
fn btf_offsets() -> Vec<(&'static str, u32)> {
    let btf = std::fs::read("/sys/kernel/btf/vmlinux")
        .ok()
        .and_then(|bytes| crate::btf::Btf::parse(&bytes));
    BTF_FIELDS
        .iter()
        .map(|field| {
            let offset = btf
                .as_ref()
                .and_then(|btf| btf.offset(field.structure, field.field))
                .unwrap_or(ABSENT);
            (field.global, offset)
        })
        .collect()
}

/// Each probe global and the offset this kernel gives its field.
fn field_offsets() -> Result<Vec<(&'static str, u32)>, Unavailable> {
    FIELD_SETTINGS
        .iter()
        .map(|setting| Ok((setting.global, offset_of(setting)?)))
        .collect()
}

fn offset_of(setting: &FieldSetting) -> Result<u32, Unavailable> {
    let FieldSetting {
        category,
        event,
        field,
        size,
        required,
        ..
    } = *setting;
    match format::field(&tracepoint_format(category, event)?, field) {
        Some(found) if found.size == size => Ok(found.offset),
        Some(found) => Err(Unavailable::Unsupported(format!(
            "{category}/{event} field {field} is {} bytes here, the probe reads {size}",
            found.size
        ))),
        None if required => Err(Unavailable::Unsupported(format!(
            "{category}/{event} has no field {field}"
        ))),
        None => Ok(ABSENT),
    }
}

/// The kernel's description of one tracepoint. Unreadable for want of
/// privilege is a refusal, not a missing tracepoint: the two need different
/// fixes, so they must not read the same.
fn tracepoint_format(category: &str, event: &str) -> Result<String, Unavailable> {
    let mut denied = None;
    for root in TRACEFS {
        let path = format!("{root}/events/{category}/{event}/format");
        match fs::read_to_string(&path) {
            Ok(format) => return Ok(format),
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                denied.get_or_insert(path);
            }
            Err(_) => {}
        }
    }
    Err(match denied {
        Some(path) => Unavailable::Refused(format!("reading {path} needs root")),
        None => Unavailable::Unsupported(format!("no tracepoint {category}/{event}")),
    })
}

/// The kernel's reason, with every cause in the chain: aya's top-level
/// message alone ("error loading program") hides the useful part. A cause
/// already spelled out by an earlier one is not repeated.
fn refused(error: impl std::error::Error) -> Unavailable {
    let mut why = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        let cause_text = cause.to_string();
        if !why.contains(&cause_text) {
            why = format!("{why}: {cause_text}");
        }
        source = cause.source();
    }
    Unavailable::Refused(why)
}
