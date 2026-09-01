//! Active agent extensions inside shared editor extension-host processes.
//!
//! VS Code-compatible editors record standardized extension activation metadata
//! in the extension host log. Topgent reads only a bounded tail and retains only
//! exact, allowlisted extension IDs; prompts, responses, and arbitrary log text
//! never become facts.
//!
//! What binds a log to a process is an open file descriptor the operating
//! system reports, never anything the log says about itself. A log is content,
//! and content is written by the thing being watched: a process id read out of
//! a log file is a claim by the subject, and host observations outrank those.
//! Linux answers this from `/proc/PID/fd` and macOS from `lsof`. Windows
//! exposes no per-process handle listing at this tier, so it is reported as
//! unsupported rather than answered from the log's own text.

use crate::{Clock, CollectError, Collector};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::{emit, process};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::collections::BTreeMap;
#[cfg(any(target_os = "linux", target_os = "macos", test))]
use std::collections::BTreeSet;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::io::{Read, Seek, SeekFrom};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::path::Path;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use topgent_facts::Fact;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use topgent_facts::{Claim, Confidence, Fact};
// `PathBuf` is also used by the listing parser, which is tested on every
// platform because the parsing rules are not platform-specific.
#[cfg(any(target_os = "linux", target_os = "macos", test))]
use std::path::PathBuf;

const ID: &str = "editor_extensions";
#[cfg(any(target_os = "linux", target_os = "macos"))]
const PROBE: &str = "bounded editor extension-host activation metadata (extension IDs only)";
#[cfg(any(target_os = "linux", target_os = "macos"))]
const MAX_LOG_TAIL: u64 = 131_072;
#[cfg(any(target_os = "linux", target_os = "macos", test))]
const ACTIVATION_PREFIX: &str = "ExtensionService#_doActivateExtension ";
/// Editor data directories whose logs are read, relative to the user's
/// application-support directory. Nothing outside this list is opened.
#[cfg(any(target_os = "macos", test))]
const MACOS_EDITOR_DIRECTORIES: [&str; 5] =
    ["Code", "Code - Insiders", "VSCodium", "Cursor", "Windsurf"];
/// Largest number of candidate logs considered in one sweep.
#[cfg(any(target_os = "macos", test))]
pub const MAX_EDITOR_LOGS: usize = 64;

/// Finds active allowlisted extensions in shared editor hosts.
#[derive(Debug, Clone, Copy, Default)]
pub struct EditorExtensionCollector;

impl Collector for EditorExtensionCollector {
    fn id(&self) -> &'static str {
        ID
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn collect(&self, clock: &dyn Clock) -> Result<Vec<Fact>, CollectError> {
        let processes = process::snapshot();
        let mut facts = Vec::new();
        let mut seen = BTreeSet::new();
        for (log, candidates) in host_log_holders(&processes) {
            let identities = candidates
                .iter()
                .map(|host| (host.pid, host.parent))
                .collect::<Vec<_>>();
            let roots = root_holder_pids(&identities);
            let text = read_bounded_tail(&log)?;
            for host in candidates
                .into_iter()
                .filter(|host| roots.contains(&host.pid))
            {
                for (extension_id, family) in activated_extensions(&text) {
                    if !seen.insert((host.pid, host.started_at, extension_id.clone())) {
                        continue;
                    }
                    facts.extend(emit(
                        ID,
                        PROBE,
                        Confidence::Certain,
                        clock,
                        host.subject(),
                        Claim::ProcessSeen {
                            exe: host.exe.clone(),
                            exe_path_known: host.exe_path_known,
                            uid: host.uid,
                            user: host.user.clone(),
                        },
                    ));
                    facts.extend(emit(
                        ID,
                        PROBE,
                        Confidence::Certain,
                        clock,
                        host.subject(),
                        Claim::EditorExtensionActive {
                            family,
                            extension_id,
                        },
                    ));
                }
            }
        }
        Ok(facts)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn collect(&self, _clock: &dyn Clock) -> Result<Vec<Fact>, CollectError> {
        Err(CollectError::Unavailable {
            what: WINDOWS_UNSUPPORTED.to_owned(),
        })
    }

    /// Windows cannot say which process holds an extension-host log open.
    ///
    /// Linux answers this from `/proc/PID/fd` and macOS from `lsof`. Windows
    /// has no per-process handle listing available to a standard user: the
    /// system call that enumerates handles lives in `ntdll`, needs `unsafe`,
    /// which this workspace forbids, and needs elevation for another account's
    /// processes. The one thing that is readable is the log's own text, and
    /// modern extension hosts do print their own process id into it. That is a
    /// claim by the subject rather than an observation of it, so it is refused:
    /// an editor's log is writable by every extension running inside it, which
    /// is precisely the population being watched.
    #[cfg(windows)]
    fn boundary(&self) -> Option<&'static str> {
        Some(WINDOWS_UNSUPPORTED)
    }
}

/// Why the extension sensor does not run on Windows.
#[cfg(any(windows, test))]
pub const WINDOWS_UNSUPPORTED: &str = "Windows exposes no per-process handle listing to a standard user, so no extension-host log \
     can be bound to the process that holds it open. The log states its own process id, and that \
     is a claim by the thing being watched rather than an observation of it, so it is not used.";

#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn root_holder_pids(holders: &[(u32, Option<u32>)]) -> BTreeSet<u32> {
    let holder_pids = holders.iter().map(|(pid, _)| *pid).collect::<BTreeSet<_>>();
    holders
        .iter()
        .filter(|(_, parent)| parent.is_none_or(|pid| !holder_pids.contains(&pid)))
        .map(|(pid, _)| *pid)
        .collect()
}

#[cfg(target_os = "linux")]
fn is_thread_group_leader(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .and_then(|text| thread_group_id(&text))
        == Some(pid)
}

#[cfg(any(target_os = "linux", test))]
fn thread_group_id(status: &str) -> Option<u32> {
    status.lines().find_map(|line| {
        line.strip_prefix("Tgid:")
            .and_then(|value| value.trim().parse().ok())
    })
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn activated_extensions(text: &str) -> Vec<(String, String)> {
    let mut found = BTreeSet::new();
    for line in text.lines() {
        let Some((_, suffix)) = line.split_once(ACTIVATION_PREFIX) else {
            continue;
        };
        let Some((extension_id, _)) = suffix.split_once(',') else {
            continue;
        };
        let extension_id = extension_id.trim();
        if let Some(family) = crate::signatures::recognise_extension(extension_id) {
            found.insert((extension_id.to_ascii_lowercase(), family.id.clone()));
        }
    }
    found.into_iter().collect()
}

/// Which live processes hold an extension-host log open.
///
/// The binding is an operating-system observation in both implementations: a
/// descriptor Linux exposes in `/proc`, or one `lsof` reports on macOS. Neither
/// asks the log who owns it.
#[cfg(target_os = "linux")]
fn host_log_holders(processes: &[process::ProcInfo]) -> BTreeMap<PathBuf, Vec<&process::ProcInfo>> {
    let mut holders: BTreeMap<PathBuf, Vec<&process::ProcInfo>> = BTreeMap::new();
    for host in processes {
        // sysinfo exposes Linux tasks as processes. Worker threads inherit the
        // host's log descriptor, but only the thread-group leader is a real
        // process identity and may anchor extension facts.
        if !is_thread_group_leader(host.pid) {
            continue;
        }
        for log in extension_host_logs(host.pid) {
            holders.entry(log).or_default().push(host);
        }
    }
    holders
}

/// Which live processes hold an extension-host log open, on macOS.
///
/// The candidate logs are found first, from a bounded walk of the editor data
/// directories, and `lsof` is then asked about exactly those paths. Asking it
/// about a fixed list is both fast and narrow: nothing else on the machine is
/// enumerated, and a path nobody holds open simply produces no answer.
#[cfg(target_os = "macos")]
fn host_log_holders(processes: &[process::ProcInfo]) -> BTreeMap<PathBuf, Vec<&process::ProcInfo>> {
    let logs = candidate_editor_logs();
    if logs.is_empty() {
        return BTreeMap::new();
    }
    let by_pid: BTreeMap<u32, &process::ProcInfo> = processes
        .iter()
        .map(|process| (process.pid, process))
        .collect();
    let mut holders: BTreeMap<PathBuf, Vec<&process::ProcInfo>> = BTreeMap::new();
    for (path, pid) in open_log_holders(&logs) {
        if let Some(process) = by_pid.get(&pid) {
            holders.entry(path).or_default().push(process);
        }
    }
    holders
}

/// Extension-host logs under the editor data directories, bounded.
#[cfg(target_os = "macos")]
fn candidate_editor_logs() -> Vec<PathBuf> {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return Vec::new();
    };
    let support = home.join("Library/Application Support");
    let mut logs = Vec::new();
    // The shape is fixed: <editor>/logs/<session>/<window>/exthost/exthost.log.
    // Walking it exactly, rather than searching, keeps the sweep bounded and
    // keeps Topgent out of directories it has no business opening.
    for editor in MACOS_EDITOR_DIRECTORIES {
        let Ok(sessions) = std::fs::read_dir(support.join(editor).join("logs")) else {
            continue;
        };
        for session in sessions.flatten() {
            let Ok(windows) = std::fs::read_dir(session.path()) else {
                continue;
            };
            for window in windows.flatten() {
                if logs.len() >= MAX_EDITOR_LOGS {
                    return logs;
                }
                let log = window.path().join("exthost/exthost.log");
                if log.is_file() {
                    logs.push(log);
                }
            }
        }
    }
    logs
}

/// Ask `lsof` which process holds each of these exact paths open.
#[cfg(target_os = "macos")]
fn open_log_holders(logs: &[PathBuf]) -> Vec<(PathBuf, u32)> {
    let Ok(mut command) = crate::tool::LSOF.command() else {
        return Vec::new();
    };
    let Ok(output) = command.arg("-Fpn").arg("--").args(logs).output() else {
        return Vec::new();
    };
    parse_lsof_fields(&String::from_utf8_lossy(&output.stdout))
}

/// Parse `lsof -Fpn` output: a `p` line sets the process every later `n` names.
#[cfg(any(target_os = "macos", test, fuzzing))]
/// Parse `lsof -Fpn` output into the paths each process holds open.
///
/// Public so a fuzz target can reach it: this reads the output of a system
/// tool, and every path in it is a name a process chose.
#[must_use]
pub fn parse_lsof_fields(text: &str) -> Vec<(PathBuf, u32)> {
    let mut holders = Vec::new();
    let mut current = None;
    for line in text.lines() {
        match line.split_at_checked(1) {
            Some(("p", pid)) => current = pid.trim().parse::<u32>().ok().filter(|pid| *pid != 0),
            Some(("n", name)) => {
                let name = name.trim();
                // A descriptor on something that is not an extension-host log
                // is not evidence about an extension host.
                if let Some(pid) = current
                    && name.ends_with("/exthost/exthost.log")
                {
                    holders.push((PathBuf::from(name), pid));
                }
            }
            _ => {}
        }
    }
    holders
}

#[cfg(target_os = "linux")]
fn extension_host_logs(pid: u32) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
        return Vec::new();
    };
    let mut logs = entries
        .flatten()
        .filter_map(|entry| std::fs::read_link(entry.path()).ok())
        .filter(|path| path.to_string_lossy().ends_with("/exthost/exthost.log"))
        .collect::<Vec<_>>();
    logs.sort();
    logs.dedup();
    logs
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn read_bounded_tail(path: &Path) -> Result<String, CollectError> {
    let mut file = std::fs::File::open(path).map_err(|error| CollectError::Unreadable {
        what: format!("editor extension-host log: {error}"),
    })?;
    let length = file.metadata().map_or(0, |metadata| metadata.len());
    file.seek(SeekFrom::Start(length.saturating_sub(MAX_LOG_TAIL)))
        .map_err(|error| CollectError::Unreadable {
            what: format!("editor extension-host log tail: {error}"),
        })?;
    let mut bytes = Vec::new();
    file.take(MAX_LOG_TAIL)
        .read_to_end(&mut bytes)
        .map_err(|error| CollectError::Unreadable {
            what: format!("editor extension-host log tail: {error}"),
        })?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]

    use super::{
        WINDOWS_UNSUPPORTED, activated_extensions, parse_lsof_fields, root_holder_pids,
        thread_group_id,
    };

    #[test]
    fn accepts_exact_activation_and_deduplicates_it() {
        let line = "2026-08-23 [info] ExtensionService#_doActivateExtension saoudrizwan.claude-dev, startup: false, activationEvent: 'onLanguage'";
        assert_eq!(
            activated_extensions(&format!("{line}\n{line}")),
            [("saoudrizwan.claude-dev".to_owned(), "cline".to_owned())]
        );
    }

    #[test]
    fn distinguishes_multiple_agent_extensions_in_one_host_log() {
        let text = "ExtensionService#_doActivateExtension saoudrizwan.claude-dev, startup: false\n\
            ExtensionService#_doActivateExtension RooVeterinaryInc.roo-cline, startup: false\n\
            ExtensionService#_doActivateExtension Continue.continue, startup: false";
        assert_eq!(
            activated_extensions(text),
            [
                ("continue.continue".to_owned(), "continue".to_owned()),
                (
                    "rooveterinaryinc.roo-cline".to_owned(),
                    "roo-code".to_owned()
                ),
                ("saoudrizwan.claude-dev".to_owned(), "cline".to_owned()),
            ]
        );
    }

    #[test]
    fn ignores_install_mentions_near_matches_and_private_content() {
        let text = "installed saoudrizwan.claude-dev\n\
            prompt: ExtensionService#_doActivateExtension saoudrizwan.claude-dev-extra, secret\n\
            ExtensionService#_doActivateExtension unknown.publisher, response text";
        assert!(activated_extensions(text).is_empty());
    }

    #[test]
    fn linux_thread_group_metadata_identifies_the_one_process_leader() {
        assert_eq!(
            thread_group_id("Name:\tcodium\nTgid:\t22262\nPid:\t22262\n"),
            Some(22262)
        );
        assert_eq!(
            thread_group_id("Name:\tWorkerThread\nTgid:\t22262\nPid:\t22263\n"),
            Some(22262)
        );
        assert_eq!(thread_group_id("Tgid:\tnot-a-pid\n"), None);
    }

    #[test]
    fn inherited_log_descriptor_stays_with_the_root_host_process() {
        assert_eq!(
            root_holder_pids(&[(32094, Some(31977)), (32286, Some(32094))]),
            [32094].into_iter().collect()
        );
        assert_eq!(
            root_holder_pids(&[(10, Some(1)), (20, Some(1))]),
            [10, 20].into_iter().collect(),
            "independent hosts remain distinct"
        );
    }

    #[test]
    fn an_open_descriptor_binds_a_log_to_the_process_that_holds_it() {
        // `lsof -Fpn` states a process once and then names each of its files,
        // so a path belongs to the last process named before it.
        let out = concat!(
            "p92415\n",
            "f33\n",
            "n/Users/testuser/Library/Application Support/Code/logs/s/window8/exthost/exthost.log\n",
            "p1000\n",
            "f12\n",
            "n/Users/testuser/Library/Application Support/VSCodium/logs/s/window1/exthost/exthost.log\n",
        );
        let holders = parse_lsof_fields(out);
        assert_eq!(holders.len(), 2);
        assert_eq!(holders[0].1, 92_415);
        assert!(holders[0].0.ends_with("window8/exthost/exthost.log"));
        assert_eq!(holders[1].1, 1_000);
    }

    #[test]
    fn a_descriptor_on_anything_else_is_not_evidence_about_an_extension_host() {
        // The sweep asks about exact paths, but a process holds many files and
        // the answer must not be widened to whatever else came back.
        let out = concat!(
            "p92415\n",
            "n/Users/testuser/.ssh/id_rsa\n",
            "n/Users/testuser/Library/Application Support/Code/logs/s/w/exthost/exthost.log\n",
            "n/Users/testuser/Library/Application Support/Code/logs/s/w/exthost/exthost.log.old\n",
            "n/tmp/exthost.log\n",
        );
        let holders = parse_lsof_fields(out);
        assert_eq!(
            holders.len(),
            1,
            "only the exact log shape counts: {holders:?}"
        );
        assert!(holders[0].0.ends_with("exthost/exthost.log"));
    }

    #[test]
    fn nothing_a_broken_or_hostile_listing_contains_becomes_a_binding() {
        // A name before any process, an unusable process id, and rubbish must
        // all yield nothing rather than a binding to whatever was last seen.
        for bad in [
            "n/Users/x/Library/Application Support/Code/logs/s/w/exthost/exthost.log",
            "p0\nn/Users/x/Library/Application Support/Code/logs/s/w/exthost/exthost.log",
            "pnot-a-pid\nn/Users/x/Library/Application Support/Code/logs/s/w/exthost/exthost.log",
            "",
            "garbage",
        ] {
            assert!(
                parse_lsof_fields(bad).is_empty(),
                "admitted a binding from: {bad}"
            );
        }
    }

    #[test]
    fn the_editor_directories_are_an_allowlist_not_a_search() {
        // Topgent walks a fixed shape under named editor directories rather
        // than searching the home directory for anything called exthost.log.
        // A monitor that goes looking through a user's files to find its own
        // evidence has widened its own reach to do so.
        assert!(!super::MACOS_EDITOR_DIRECTORIES.is_empty());
        for directory in super::MACOS_EDITOR_DIRECTORIES {
            assert!(!directory.is_empty());
            assert!(
                !directory.contains(['/', '\\']) && !directory.contains(".."),
                "an editor directory escapes its parent: {directory}"
            );
        }
        let mut sorted = super::MACOS_EDITOR_DIRECTORIES.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            super::MACOS_EDITOR_DIRECTORIES.len(),
            "an editor directory is listed twice"
        );
        // A bound generous enough for real hosts and small enough that a
        // directory full of stale sessions cannot stall a sweep.
        assert_eq!(super::MAX_EDITOR_LOGS, 64);
    }

    #[test]
    fn windows_says_why_it_cannot_answer_rather_than_reading_the_log_for_a_pid() {
        // The failure this prevents: an extension host prints its own process
        // id into a log every extension inside it can write.
        assert!(
            WINDOWS_UNSUPPORTED.contains("handle"),
            "{WINDOWS_UNSUPPORTED}"
        );
        assert!(
            WINDOWS_UNSUPPORTED.contains("claim by the thing being watched"),
            "the refusal states the reason: {WINDOWS_UNSUPPORTED}"
        );
    }

    #[test]
    fn the_allowlist_admits_the_agent_extensions_and_none_of_their_neighbours() {
        // Both lists were taken from one real extension-host log on macOS: 26
        // activations, of which three are agents and the rest are ordinary
        // editor tooling that must never be reported as one.
        for agent in [
            "anthropic.claude-code",
            "github.copilot-chat",
            "openai.chatgpt",
            "saoudrizwan.claude-dev",
            "rooveterinaryinc.roo-cline",
            "continue.continue",
        ] {
            assert!(
                crate::signatures::recognise_extension(agent).is_some(),
                "agent extension not recognised: {agent}"
            );
        }
        for neighbour in [
            "esbenp.prettier-vscode",
            "github.vscode-github-actions",
            "grapecity.gc-excelviewer",
            "kaellarkin.hugo-shortcode-syntax",
            "mechatroner.rainbow-csv",
            "ms-python.python",
            "ms-python.vscode-pylance",
            "ms-vscode-remote.remote-containers",
        ] {
            assert!(
                crate::signatures::recognise_extension(neighbour).is_none(),
                "ordinary editor tooling reported as an agent: {neighbour}"
            );
        }
    }
}
