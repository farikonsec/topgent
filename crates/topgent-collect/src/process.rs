//! The process collector.
//!
//! Everything else anchors to a process, so this runs first. It needs no
//! privileges: on macOS an unprivileged process can enumerate every process on
//! the box, and can read the executable path, owner, start time and parent of
//! any process belonging to the same user. That covers every local coding agent,
//! because they all run as you.
//!
//! # Layout
//!
//! | Module | What lives there |
//! |---|---|
//! | [`table`] | One process as Topgent sees it, and the sweep that reads them all. |
//! | [`owner`] | Who a process runs as, in each platform's own terms. |
//! | [`launcher`] | Recovering the real program when a runtime is running someone else's script. |
//! | [`collector`] | Turning the table into facts, and deciding what counts as a new agent. |

mod collector;
mod launcher;
mod owner;
mod table;

pub use collector::ProcessCollector;
// The launcher work only exists where a runtime is launched that way, and in
// tests, which exercise the parser on every platform.
#[cfg(any(windows, test))]
pub use launcher::{SCRIPT_RUNTIMES, is_script_runtime, parse_windows_launchers};
#[cfg(any(windows, test))]
pub use owner::valid_windows_sid;
pub use owner::{Owner, current_owner, owned_by, owner_of, with_resolved_owner};
pub use table::{ProcInfo, family_of, snapshot};

/// Maps every process to the nearest recognised agent above it.
///
/// An agent does its work through helpers: a shell it spawned, a `ping`, a
/// short-lived child. Those hold the sockets and send the packets, and none of
/// them is an agent, so a fact anchored to one is a fact about nobody and the
/// fold rejects it. Walking up to the nearest ancestor with a family is what
/// makes a helper's behaviour count as its agent's.
///
/// The walk stops where two different families meet, because a process under
/// two agents belongs to neither in particular and guessing would put one
/// agent's behaviour on another's row.
#[must_use]
pub fn agent_owners(
    processes: &[ProcInfo],
) -> std::collections::BTreeMap<u32, topgent_facts::Subject> {
    let by_pid: std::collections::BTreeMap<u32, &ProcInfo> = processes
        .iter()
        .map(|process| (process.pid, process))
        .collect();
    processes
        .iter()
        .filter_map(|process| {
            let mut current = Some(process.pid);
            let mut owner = None;
            for _ in 0..processes.len() {
                let Some(pid) = current else { break };
                let Some(candidate) = by_pid.get(&pid) else {
                    break;
                };
                if let Some(family) = candidate.family {
                    match owner {
                        None => owner = Some((family, candidate.subject())),
                        Some((owned_family, _)) if owned_family == family => {
                            owner = Some((family, candidate.subject()));
                        }
                        Some(_) => break,
                    }
                }
                current = candidate.parent;
            }
            owner.map(|(_, subject)| (process.pid, subject))
        })
        .collect()
}
