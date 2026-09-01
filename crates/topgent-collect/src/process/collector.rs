//! Turning the process table into facts.
//!
//! Also decides what counts as a new agent. A process that re-executes itself
//! is one agent, not two, and the test is the direct parent: walking further up
//! folded genuinely separate agents into whichever ancestor happened to share a
//! family, which is how a real process once disappeared from the estate.

use super::table::ProcInfo;
use super::table::descendants_of;
use super::table::snapshot;
use crate::Clock;
use crate::CollectError;
use crate::Collector;
use crate::emit;
use topgent_facts::Claim;
use topgent_facts::Confidence;
use topgent_facts::Fact;

/// Emits one process fact per recognised agent, plus its family and parentage.
#[derive(Debug, Default)]
pub struct ProcessCollector {
    /// When true, every process is reported rather than only recognised agents.
    pub include_unrecognised: bool,
}

const ID: &str = "process";

const PROBE: &str = "process table (sysinfo, unprivileged)";

impl Collector for ProcessCollector {
    fn id(&self) -> &'static str {
        ID
    }

    fn collect(&self, clock: &dyn Clock) -> Result<Vec<Fact>, CollectError> {
        let procs = snapshot();
        if procs.is_empty() {
            return Err(CollectError::Denied {
                what: "the process table returned nothing".to_owned(),
            });
        }

        let mut facts = Vec::new();
        for p in procs.iter().filter(|p| {
            self.include_unrecognised || (p.family.is_some() && !is_same_family_relaunch(p, &procs))
        }) {
            facts.extend(emit(
                ID,
                PROBE,
                Confidence::Certain,
                clock,
                p.subject(),
                Claim::ProcessSeen {
                    exe: p.exe.clone(),
                    exe_path_known: p.exe_path_known,
                    uid: p.uid,
                    user: p.user.clone(),
                },
            ));
            if let Some(family) = p.family {
                facts.extend(emit(
                    ID,
                    PROBE,
                    Confidence::Certain,
                    clock,
                    p.subject(),
                    Claim::AgentFamily {
                        family: family.to_owned(),
                    },
                ));
            }
            if let Some(parent) = p.parent {
                facts.extend(emit(
                    ID,
                    PROBE,
                    Confidence::Certain,
                    clock,
                    p.subject(),
                    Claim::ProcessParent { parent_pid: parent },
                ));
            }

            // Attribute descendants to the recognised agent without turning
            // every helper process into a top-level agent. Arguments are
            // deliberately not retained: they routinely contain credentials.
            for child in descendants_of(p.pid, &procs) {
                facts.extend(emit(
                    ID,
                    PROBE,
                    Confidence::Certain,
                    clock,
                    p.subject(),
                    Claim::ChildProcessSeen {
                        pid: child.0.pid,
                        name: child.0.name.clone(),
                        depth: child.1,
                    },
                ));
            }
        }
        Ok(facts)
    }
}

/// Whether a same-family launcher spawned this process directly.
///
/// A launcher wrapper spawns the real binary as its immediate child, so
/// reporting both would count one agent run twice. The relationship has to be
/// parent-to-child to mean that: an agent reached through any intervening
/// process was launched through a shell, a build tool, or another program, and
/// is a separate run with its own identity, risk, and termination target.
/// Walking past unrecognised ancestors hid exactly that case, so a genuine
/// second agent under a first one never reached the inventory.
fn is_same_family_relaunch(process: &ProcInfo, procs: &[ProcInfo]) -> bool {
    let Some(family) = process.family else {
        return false;
    };
    process
        .parent
        .and_then(|pid| procs.iter().find(|item| item.pid == pid))
        .and_then(|parent| parent.family)
        .is_some_and(|parent_family| parent_family == family)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Owner;
    use topgent_facts::UnixMillis;

    fn process(pid: u32, parent: Option<u32>, family: Option<&'static str>) -> ProcInfo {
        ProcInfo {
            owner: Owner::Uid(501),
            pid,
            started_at: UnixMillis(u64::from(pid) * 1_000),
            exe: format!("/bin/p{pid}"),
            exe_path_known: true,
            name: format!("p{pid}"),
            uid: 501,
            user: "test".to_owned(),
            parent,
            family,
        }
    }

    #[test]
    fn a_same_family_reexec_is_not_a_second_top_level_agent() {
        let processes = [
            process(10, None, Some("opencode")),
            process(11, Some(10), Some("opencode")),
            process(12, Some(11), None),
            process(20, Some(10), Some("aider")),
        ];
        assert!(!is_same_family_relaunch(&processes[0], &processes));
        assert!(is_same_family_relaunch(&processes[1], &processes));
        assert!(!is_same_family_relaunch(&processes[2], &processes));
        assert!(!is_same_family_relaunch(&processes[3], &processes));
    }

    #[test]
    fn an_agent_launched_through_another_process_is_its_own_top_level_agent() {
        // A shell, build tool, or helper between two same-family agents means
        // the second was launched, not re-executed. Suppressing it hides a
        // real agent run: a second Claude Code started from inside a first one
        // has its own pid, start time, risk, and termination target.
        let processes = [
            process(10, None, Some("claude-code")),
            process(11, Some(10), None),
            process(12, Some(11), Some("claude-code")),
        ];
        assert!(!is_same_family_relaunch(&processes[0], &processes));
        assert!(!is_same_family_relaunch(&processes[2], &processes));
    }

    #[test]
    fn a_bundled_agent_runtime_keeps_one_identity_whatever_its_ancestry() {
        // The 2026-08-26 macOS incident, as observed live. ChatGPT's bundled
        // `Contents/Resources/codex` app-servers run under a node helper whose
        // own ancestor is the separately installed Codex CLI:
        //
        //   17255 codex (npm install)  ->  17365 node_repl  ->  18242 codex
        //
        // Walking past the unrecognised helper made those app-servers look like
        // relaunches of the CLI, so the process collector withheld their
        // executable and family and the UI drew an evidence-free
        // `unclassified` card. A sibling app-server whose parent chain reached
        // no CLI was classified normally in the same sweep, and the record
        // oscillated as the CLI came and went. Ancestry beyond the parent must
        // not change what a process is.
        let with_cli_ancestor = [
            process(17255, None, Some("codex-cli")),
            process(17365, Some(17255), None),
            process(18242, Some(17365), Some("codex-cli")),
        ];
        let without_cli_ancestor = [
            process(17365, None, None),
            process(18242, Some(17365), Some("codex-cli")),
        ];
        assert!(!is_same_family_relaunch(
            &with_cli_ancestor[2],
            &with_cli_ancestor
        ));
        assert!(!is_same_family_relaunch(
            &without_cli_ancestor[1],
            &without_cli_ancestor
        ));
    }

    #[test]
    fn relaunch_suppression_needs_a_resolvable_same_family_parent() {
        // A missing parent, a reaped parent, and a different family all leave
        // the process visible. Only an exact live same-family parent suppresses.
        let processes = [
            process(10, None, Some("claude-code")),
            process(11, Some(999), Some("claude-code")),
            process(12, Some(10), Some("opencode")),
            process(13, None, None),
        ];
        assert!(!is_same_family_relaunch(&processes[1], &processes));
        assert!(!is_same_family_relaunch(&processes[2], &processes));
        assert!(!is_same_family_relaunch(&processes[3], &processes));
    }

    #[test]
    fn a_parent_cycle_cannot_hang_relaunch_detection() {
        let processes = [
            process(10, Some(11), Some("claude-code")),
            process(11, Some(10), Some("claude-code")),
        ];
        assert!(is_same_family_relaunch(&processes[0], &processes));
        assert!(is_same_family_relaunch(&processes[1], &processes));
    }
}
