//! One process, and the sweep that reads them all.
//!
//! A process is identified by the pair `(pid, started_at)` and never by the pid
//! alone. The kernel reuses pids, and anything that acts on a pid without the
//! start time it was authorised against can act on a different process than the
//! one someone looked at.

use super::launcher::launcher_path;
use super::launcher::resolve_windows_launchers;
use super::owner::Owner;
use sysinfo::{ProcessRefreshKind, ProcessStatus, ProcessesToUpdate, System, Users};
use topgent_facts::Subject;
use topgent_facts::UnixMillis;

/// What one process looks like to Topgent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcInfo {
    /// Process id.
    pub pid: u32,
    /// Start time, milliseconds since the epoch.
    pub started_at: UnixMillis,
    /// Executable path, or the process name when the path is not readable.
    pub exe: String,
    /// Whether the operating system gave up the executable path.
    ///
    /// Family recognition reads the path, so a process whose path was refused
    /// has not been ruled out as an agent; it has not been examined.
    pub exe_path_known: bool,
    /// Short name, as it appears in a process listing.
    pub name: String,
    /// Numeric owner.
    pub uid: u32,
    /// Resolved owner name, or the numeric id as a string.
    pub user: String,
    /// Parent process, when there is one.
    pub parent: Option<u32>,
    /// Its pid namespace, where the platform names one.
    pub pid_namespace: Option<u64>,
    /// Recognised agent family, when the executable is one we know.
    pub family: Option<&'static str>,
    /// Who the process runs as, in the platform's own terms.
    ///
    /// Filled in cheaply where the sweep already knows it, and left `Unknown`
    /// where establishing it costs a separate query. Anything that decides
    /// whether a response may proceed resolves it deliberately first, so an
    /// unresolved owner is never mistaken for a matching one.
    pub owner: Owner,
}

impl ProcInfo {
    /// The subject every fact about this process uses.
    #[must_use]
    pub fn subject(&self) -> Subject {
        Subject::Process {
            pid: self.pid,
            started_at: self.started_at,
        }
    }
}

/// Recognise an agent family from an executable name.
///
/// Matching is on the executable's file name, lowercased. Deliberately narrow:
/// a wrong family name is worse than no family name, because the whole point of
/// the confidence column is that Topgent does not overclaim.
#[must_use]
pub fn family_of(exe_name: &str) -> Option<&'static str> {
    crate::signatures::recognise(exe_name).map(|family| family.id.as_str())
}

/// The start time field of a `/proc/<pid>/stat` line, in clock ticks since
/// boot.
///
/// The command name sits in parentheses and may itself contain spaces and
/// parentheses, so fields are counted from the last `)`. Field 22 overall is
/// the 20th after it.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn stat_start_ticks(stat: &str) -> Option<u64> {
    stat.rsplit_once(')')?
        .1
        .split_ascii_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

/// Wall-clock start from boot time and ticks. `None` for a zero tick rate.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn start_millis(boot_seconds: u64, ticks: u64, per_second: u64) -> Option<u64> {
    let since_boot = ticks.checked_mul(1_000)?.checked_div(per_second)?;
    boot_seconds.checked_mul(1_000)?.checked_add(since_boot)
}

/// The inode in a `pid:[4026531836]` namespace link.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn namespace_inode(link: &str) -> Option<u64> {
    link.strip_prefix("pid:[")?.strip_suffix(']')?.parse().ok()
}

/// When the system booted, in Unix seconds, from `/proc/stat`.
#[cfg(target_os = "linux")]
#[must_use]
pub fn boot_seconds() -> Option<u64> {
    std::fs::read_to_string("/proc/stat")
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("btime "))?
        .trim()
        .parse()
        .ok()
}

#[cfg(not(target_os = "linux"))]
const fn boot_seconds() -> Option<u64> {
    None
}

/// The start `/proc` would have given a process created at `at`, for one
/// that was gone before its start could be read.
///
/// `/proc` states a start in whole clock ticks since boot, so every start
/// read from it sits on a 10 ms grid (at the usual 100 ticks a second).
/// Event times do not. A process keyed by its precise event time would sort
/// after a child keyed by `/proc`'s rounded one, and the child would appear
/// to start before its parent and be dropped. Putting both on the same grid
/// keeps parent before child. `at` must be in the same base as
/// [`kernel_start`]: boot seconds in milliseconds plus time since boot.
#[cfg(target_os = "linux")]
#[must_use]
pub fn start_from_event(at: u64, boot: Option<u64>) -> u64 {
    boot.and_then(|boot| on_tick_grid(at, boot, rustix::param::clock_ticks_per_second()))
        .unwrap_or(at)
}

/// `at` floored to the tick grid [`start_millis`] produces.
#[cfg(any(target_os = "linux", test))]
fn on_tick_grid(at: u64, boot_seconds: u64, per_second: u64) -> Option<u64> {
    let since_boot = at.checked_sub(boot_seconds.checked_mul(1_000)?)?;
    let ticks = since_boot.checked_mul(per_second)?.checked_div(1_000)?;
    start_millis(boot_seconds, ticks, per_second)
}

/// A process's start time to the clock tick, from `/proc/<pid>/stat`.
#[cfg(target_os = "linux")]
#[must_use]
pub fn kernel_start(pid: u32, boot: Option<u64>) -> Option<UnixMillis> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let millis = start_millis(
        boot?,
        stat_start_ticks(&stat)?,
        rustix::param::clock_ticks_per_second(),
    )?;
    Some(UnixMillis(millis))
}

#[cfg(not(target_os = "linux"))]
const fn kernel_start(_pid: u32, _boot: Option<u64>) -> Option<UnixMillis> {
    None
}

#[cfg(target_os = "linux")]
fn pid_namespace(pid: u32) -> Option<u64> {
    namespace_inode(
        std::fs::read_link(format!("/proc/{pid}/ns/pid"))
            .ok()?
            .to_str()?,
    )
}

#[cfg(not(target_os = "linux"))]
const fn pid_namespace(_pid: u32) -> Option<u64> {
    None
}

/// What is printed where the operating system named no owner.
///
/// Never a number. `0` is root's uid, and an unanswerable question rendering as
/// the most privileged account on the machine is the worst available default.
pub const UNKNOWN_OWNER: &str = "unknown";

/// The executable path with symlinks followed, where that is possible.
///
/// Package managers install a link in a `bin` directory pointing at the real
/// file: npm, Homebrew and pipx all do. macOS reports the path the process was
/// launched with, which is that link, while Linux `/proc/<pid>/exe` reports the
/// target. So the same agent installed the same way was recognised on Linux and
/// missed on macOS, because a family that requires path provenance matches
/// against `.../node_modules/opencode-ai/bin/opencode.exe` and never against
/// `~/.local/bin/opencode`.
///
/// Measured 2026-09-03: launched through the link, not detected; launched by
/// the target path, detected at once. Every agent installed by a package
/// manager on macOS was in the first case.
///
/// Falls back to the path as given when it cannot be resolved. A path that no
/// longer exists is still the best thing known about a process that has since
/// exited, and losing it would trade a false negative for a blank.
fn resolved(path: &std::path::Path) -> String {
    std::fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .to_string()
}

thread_local! {
    static WALKS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static SHARED: std::cell::RefCell<Shared> = const { std::cell::RefCell::new(Shared::Outside) };
}

/// The walk shared by one sweep.
enum Shared {
    /// No sweep is running; every caller walks.
    Outside,
    /// A sweep is running and nothing has asked yet.
    Unwalked,
    /// A sweep is running and this is its walk.
    Walked(Vec<ProcInfo>),
}

/// Runs one sweep with a single, shared walk of the process table.
///
/// Every collector used to walk the table for itself: about eight walks per
/// sweep, each of a slightly different moment, so one collector could attribute
/// to a process another had not seen. Inside this scope the first caller walks
/// and the rest are handed the same view. The scope ends with the sweep, even
/// on a panic, so nothing outside it, and in particular no response deciding
/// whether a process may be signalled, is ever handed a stale table.
pub(crate) fn within_sweep<T>(run: impl FnOnce() -> T) -> T {
    struct Scope;
    impl Drop for Scope {
        fn drop(&mut self) {
            SHARED.with(|shared| *shared.borrow_mut() = Shared::Outside);
        }
    }
    SHARED.with(|shared| *shared.borrow_mut() = Shared::Unwalked);
    let _scope = Scope;
    run()
}

/// How many times this thread has walked the process table. For tests and the
/// sweep benchmark; it counts, and changes nothing.
#[must_use]
pub fn walks() -> usize {
    WALKS.with(std::cell::Cell::get)
}

/// Every process this user can see, as Topgent models it.
///
/// Shared by the collectors that need process context, so the machine is walked
/// once rather than once per collector.
#[must_use]
pub fn snapshot() -> Vec<ProcInfo> {
    let reused = SHARED.with(|shared| match &*shared.borrow() {
        Shared::Walked(processes) => Some(processes.clone()),
        Shared::Outside | Shared::Unwalked => None,
    });
    if let Some(processes) = reused {
        return processes;
    }
    let walked = walk();
    SHARED.with(|shared| {
        let mut shared = shared.borrow_mut();
        if matches!(*shared, Shared::Unwalked) {
            *shared = Shared::Walked(walked.clone());
        }
    });
    walked
}

fn walk() -> Vec<ProcInfo> {
    WALKS.with(|walks| walks.set(walks.get() + 1));
    let mut sys = System::new();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        // The owner has to be asked for. Without it Linux reports no user id
        // at all, and a missing id read as zero is indistinguishable from root,
        // which made every process on the host look like Topgent's own to stop.
        ProcessRefreshKind::nothing()
            .with_exe(sysinfo::UpdateKind::Always)
            .with_user(sysinfo::UpdateKind::Always),
    );
    let users = Users::new_with_refreshed_list();
    let boot = boot_seconds();

    let mut out: Vec<ProcInfo> = sys
        .processes()
        .iter()
        // A zombie has exited and cannot perform agent activity. Linux keeps
        // the pid visible until its parent reaps it; treating that shell as a
        // live identity makes guarded termination falsely escalate to SIGKILL.
        .filter(|(_, p)| !matches!(p.status(), ProcessStatus::Dead | ProcessStatus::Zombie))
        // A thread is not a child process. Linux exposes both through the same
        // interface and sysinfo returns both, so without this every agent built
        // on a threaded runtime looks like a fork bomb: one OpenCode agent
        // reported 48 descendants, of which 47 were its own `HeapHelper`
        // threads and exactly one was a real child. `PROCESS_EXPLOSION` then
        // fired on every agent on the host, including the ones doing nothing,
        // which is worse than the factor not existing.
        .filter(|(_, p)| p.thread_kind().is_none())
        .map(|(pid, p)| {
            let name = p.name().to_string_lossy().to_string();
            let system_path = p.exe().map(resolved);
            let exe_path_known = system_path.is_some();
            let system_exe = system_path.unwrap_or_else(|| name.clone());
            // On Windows the command line is fetched for the whole batch
            // afterwards, because a query per process would put a shell spawn
            // in the sweep for every language runtime on the machine.
            let launcher = launcher_path(pid.as_u32());
            let launcher_family = launcher.as_deref().and_then(family_of);
            let family = family_of(&system_exe)
                .or(launcher_family)
                .or_else(|| family_of(&name));
            let exe = match launcher {
                // The script identifies the run, so it is what the report
                // shows: a row saying `node.exe` names the runtime and not the
                // agent, which is the thing anyone reading it needs.
                Some(launcher) if launcher_family.is_some() => launcher,
                _ => system_exe,
            };
            // Zero is the fact vocabulary's "no numeric owner available", and
            // it is also root's real user id. The two are told apart by the
            // typed owner below, which is what authorises anything.
            #[cfg(unix)]
            let reported_uid = p.user_id().map(|u| **u);
            #[cfg(unix)]
            let uid = reported_uid.unwrap_or(0);
            // The shared fact contract currently carries a Unix numeric uid.
            // Windows exposes an SID instead; zero means "numeric owner
            // unavailable" and must never be treated as SYSTEM/root or used to
            // authorize a response. The resolved account name remains visible.
            #[cfg(windows)]
            let uid = 0;
            // The same reasoning the typed owner below already carried, applied
            // to the string a person reads. An owner the operating system did
            // not state used to render as `0`, which is root's uid, so a
            // process Topgent could learn nothing about was displayed as the
            // most privileged account on the machine.
            //
            // Found 2026-09-03: macOS does not disclose the owning uid of a
            // process belonging to another account to an unprivileged reader,
            // so every such process was labelled `0`.
            //
            // A uid that was reported but has no name is still worth printing:
            // `498` says which account, even when nothing can map it to a name.
            let named = p.user_id().and_then(|u| users.get_user_by_id(u));
            #[cfg(unix)]
            let user = named.map_or_else(
                || reported_uid.map_or_else(|| UNKNOWN_OWNER.to_owned(), |id| id.to_string()),
                |u| u.name().to_owned(),
            );
            #[cfg(windows)]
            let user = named.map_or_else(|| UNKNOWN_OWNER.to_owned(), |u| u.name().to_owned());
            ProcInfo {
                pid: pid.as_u32(),
                // sysinfo reports start time in whole seconds, which makes two
                // runs of one pid inside the same second a single identity.
                // Linux states it to the clock tick, and that is used where it
                // can be read.
                started_at: kernel_start(pid.as_u32(), boot)
                    .unwrap_or(UnixMillis(p.start_time().saturating_mul(1_000))),
                pid_namespace: pid_namespace(pid.as_u32()),
                family,
                // An owner the operating system did not state is unknown, not
                // root. Reading absence as uid zero made a host that reports no
                // user ids look like a machine where Topgent owns everything.
                #[cfg(unix)]
                owner: reported_uid.map_or(Owner::Unknown, Owner::Uid),
                // Windows identifies accounts by security identifier, and
                // asking for one costs a query per process. The response path
                // resolves it for its own targets instead.
                #[cfg(windows)]
                owner: Owner::Unknown,
                exe,
                // A launcher path resolved from the command line is a real
                // path, so it counts; falling back to the bare name does not.
                exe_path_known: exe_path_known || launcher_family.is_some(),
                name,
                uid,
                user,
                parent: p.parent().map(sysinfo::Pid::as_u32),
            }
        })
        .collect();

    resolve_windows_launchers(&mut out);

    // A container entrypoint has no useful host ancestry. Linux cgroup identity
    // plus exact image provenance supplies the missing boundary link without
    // trusting entrypoint names such as `uvicorn` or `entrypoint.sh`.
    let containers = crate::container::snapshot(&out);
    for container in containers {
        for process in &mut out {
            #[cfg(target_os = "linux")]
            let in_container = std::fs::read_to_string(format!("/proc/{}/cgroup", process.pid))
                .ok()
                .and_then(|text| crate::container::container_id_from_cgroup(&text))
                .is_some_and(|id| id == container.id);
            #[cfg(not(target_os = "linux"))]
            let in_container = false;
            if in_container {
                process.family = Some(container.family);
            }
        }
    }

    out.sort_by_key(|p| (p.pid, p.started_at));
    out
}

pub(super) fn descendants_of(root: u32, procs: &[ProcInfo]) -> Vec<(&ProcInfo, u16)> {
    let mut out = Vec::new();
    let mut frontier = vec![(root, 0_u16)];
    while let Some((parent, depth)) = frontier.pop() {
        for child in procs.iter().filter(|p| p.parent == Some(parent)) {
            let child_depth = depth.saturating_add(1);
            out.push((child, child_depth));
            // A process tree cannot legitimately be deeper than the number of
            // processes. This guard also makes a hostile cyclic fixture finite.
            if usize::from(child_depth) < procs.len() {
                frontier.push((child.pid, child_depth));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    /// A real Kali stat line, and one whose command name is built to confuse
    /// a parser that splits on the first `)`.
    #[test]
    fn the_start_time_is_read_to_the_clock_tick() {
        use super::{namespace_inode, start_millis, stat_start_ticks};
        let kali = "1648471 (python) S 1648465 1648471 1648465 0 -1 4194560 3082 0 0 0 5 2 0 0 20 0 1 0 186734203 25415680 3044 18446744073709551615 1 1 0 0 0 0 0 16781312 2 0 0 0 17 3 0 0 0 0 0";
        assert_eq!(stat_start_ticks(kali), Some(186_734_203));
        let hostile = "42 (a) S 1 (b) c) R 1 42 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 777 0 0";
        assert_eq!(stat_start_ticks(hostile), Some(777));
        assert_eq!(stat_start_ticks("42 (no fields)"), None);
        // Ten milliseconds per tick at the usual 100 Hz: two starts one tick
        // apart are two identities, where whole seconds made them one.
        assert_eq!(
            start_millis(1_790_000_000, 186_734_203, 100),
            Some(1_791_867_342_030)
        );
        assert_ne!(
            start_millis(1_790_000_000, 101, 100),
            start_millis(1_790_000_000, 102, 100)
        );
        assert_eq!(start_millis(1, 1, 0), None);
        assert_eq!(namespace_inode("pid:[4026531836]"), Some(4_026_531_836));
        assert_eq!(namespace_inode("net:[4026531836]"), None);
    }

    #[test]
    fn a_refused_executable_path_is_recorded_as_refused_not_as_a_verdict() {
        // Family recognition reads the path. A process whose path the system
        // refuses has not been ruled out as an agent, it has not been looked
        // at, and the report has to be able to tell those apart.
        let processes = super::snapshot();
        let current = processes
            .iter()
            .find(|process| process.pid == std::process::id())
            .expect("this process is in the process table");
        assert!(
            current.exe_path_known,
            "the running test binary's own path is readable"
        );
        assert!(
            current.exe.contains(std::path::MAIN_SEPARATOR),
            "a known path is a path, not a bare name: {}",
            current.exe
        );

        // Never claimed the other way round: if the path was refused, what is
        // carried is the reported name and nothing invented around it.
        for process in processes.iter().filter(|p| !p.exe_path_known) {
            assert_eq!(
                process.exe, process.name,
                "a refused path falls back to the name and invents nothing"
            );
        }
    }

    #[test]
    fn an_event_time_lands_on_the_same_tick_grid_as_proc_starts() {
        use super::{on_tick_grid, start_millis};
        let boot = 1_790_000_000;
        // 12.345 s after boot, at 100 ticks a second, is tick 1234: 12.340 s.
        assert_eq!(
            on_tick_grid(boot * 1_000 + 12_345, boot, 100),
            Some(boot * 1_000 + 12_340)
        );
        // Already on the grid: unchanged.
        assert_eq!(
            on_tick_grid(boot * 1_000 + 12_340, boot, 100),
            Some(boot * 1_000 + 12_340)
        );
        // Every result is a start `start_millis` could have produced.
        for at in (boot * 1_000..boot * 1_000 + 50).step_by(3) {
            let floored = on_tick_grid(at, boot, 100).expect("on the grid");
            let ticks = (floored - boot * 1_000) / 10;
            assert_eq!(start_millis(boot, ticks, 100), Some(floored));
            assert!(floored <= at);
        }
        assert_eq!(on_tick_grid(5, boot, 100), None, "before boot");
    }
}
