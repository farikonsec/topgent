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

/// Every process this user can see, as Topgent models it.
///
/// Shared by the collectors that need process context, so the machine is walked
/// once rather than once per collector.
#[must_use]
pub fn snapshot() -> Vec<ProcInfo> {
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

    let mut out: Vec<ProcInfo> = sys
        .processes()
        .iter()
        // A zombie has exited and cannot perform agent activity. Linux keeps
        // the pid visible until its parent reaps it; treating that shell as a
        // live identity makes guarded termination falsely escalate to SIGKILL.
        .filter(|(_, p)| !matches!(p.status(), ProcessStatus::Dead | ProcessStatus::Zombie))
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
                // sysinfo reports start time in whole seconds.
                started_at: UnixMillis(p.start_time().saturating_mul(1_000)),
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
}
