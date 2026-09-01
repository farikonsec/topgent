//! Running the platform's tool, and deciding whose socket it is.
//!
//! A helper process — a shell, a downloaded utility, a browser helper — is
//! attributed to the nearest recognised agent ancestor, so its behaviour counts
//! as the agent's without it becoming a noisy top-level agent of its own. A
//! socket whose process was never seen is attributed to nobody.

#[cfg(target_os = "linux")]
use super::linux::parse_ss;
#[cfg(target_os = "macos")]
use super::macos::parse_lsof;
#[cfg(windows)]
use super::windows::{
    parse_windows_netstat, parse_windows_tcp_connections, read_windows_tcp_connections,
};
use crate::Clock;
use crate::CollectError;
use crate::Collector;
use crate::emit;
use std::collections::BTreeMap;
use topgent_facts::Claim;
use topgent_facts::Confidence;
use topgent_facts::Direction;
use topgent_facts::Fact;
use topgent_facts::Subject;

/// Emits one socket fact per open connection belonging to a known process.
#[derive(Debug, Default)]
pub struct SocketCollector;

const ID: &str = "socket";

#[cfg(target_os = "macos")]
const PROBE: &str = "lsof -i -n -P (unprivileged, own user)";

#[cfg(target_os = "linux")]
const PROBE: &str = "ss -H -t -a -n -p (unprivileged, pid-attributed rows)";

#[cfg(windows)]
const PROBE: &str = "netstat -ano -p tcp (owner PID, standard user)";

impl Collector for SocketCollector {
    fn id(&self) -> &'static str {
        ID
    }

    /// What a healthy socket listing still cannot see here.
    ///
    /// Stated because it was not, and the cost of that was measurable: an agent
    /// resolved a name and pinged a host on the other side of the world, and
    /// this collector produced no evidence while reporting itself available.
    fn boundary(&self) -> Option<&'static str> {
        #[cfg(target_os = "macos")]
        {
            Some(
                "TCP, UDP, and ICMP sockets are listed. macOS does not expose an ICMP \
                 destination to a socket listing, so a raw ICMP socket is recorded without \
                 the host it reached.",
            )
        }
        #[cfg(target_os = "linux")]
        {
            Some(
                "TCP sockets only. UDP and ICMP are not in this listing. On this platform \
                 they come from network_events, which reads `connect`, `sendto`, and \
                 `sendmsg` from the audit log and names the destination, provided those \
                 syscalls are in the audit rules. If they are not, nothing here sees a \
                 raw-socket send.",
            )
        }
        #[cfg(windows)]
        {
            Some(
                "TCP sockets only. UDP and ICMP are not in this listing, and Windows has no \
                 equivalent that names an ICMP destination to an unprivileged process.",
            )
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
        {
            None
        }
    }

    fn collect(&self, clock: &dyn Clock) -> Result<Vec<Fact>, CollectError> {
        // The tool is resolved to a path the operating system owns, never
        // through PATH: a monitor that lets anything running as the user
        // choose its own sensors can be handed fabricated telemetry.
        #[cfg(target_os = "linux")]
        let (tool, args): (crate::tool::SystemTool, &[&str]) =
            // `-i` adds the kernel's own tcp_info counters on a continuation
            // line under each socket, which is the only truthful source of how
            // much a connection has carried: counting how often a snapshot saw
            // an endpoint is counting sweeps, not traffic.
            (crate::tool::SS, &["-H", "-t", "-a", "-n", "-p", "-i"]);
        #[cfg(target_os = "macos")]
        let (tool, args): (crate::tool::SystemTool, &[&str]) =
            (crate::tool::LSOF, &["-i", "-n", "-P"]);
        #[cfg(windows)]
        let (tool, args): (crate::tool::SystemTool, &[&str]) =
            (crate::tool::NETSTAT, &["-ano", "-p", "tcp"]);

        // Windows keeps a creation timestamp per connection, which netstat does
        // not print. Preferred when the structured query works; netstat stays
        // the fallback so a sweep never loses sockets over a missing age.
        #[cfg(windows)]
        let timed_rows = read_windows_tcp_connections()
            .ok()
            .map(|text| parse_windows_tcp_connections(&text, clock.now()))
            .filter(|rows| !rows.is_empty());

        // Fixed arguments. Nothing discovered anywhere in Topgent is ever
        // interpolated into a command line.
        let out = tool
            .command()?
            .args(args)
            .output()
            .map_err(|e| CollectError::Unavailable {
                what: format!("{}: {e}", tool.name),
            })?;
        let text = String::from_utf8_lossy(&out.stdout);
        if text.trim().is_empty() {
            return Err(CollectError::Denied {
                what: format!("{} returned no rows", tool.name),
            });
        }

        // Attribute helper sockets to the nearest recognised agent ancestor.
        // A shell, browser helper, or downloaded utility remains part of the
        // agent's behaviour without becoming a noisy top-level agent itself.
        let processes = crate::process::snapshot();
        let owners = agent_owners(&processes);
        let containers = crate::container::snapshot(&processes);

        let mut facts = Vec::new();
        #[cfg(target_os = "linux")]
        let rows = parse_ss(&text);
        #[cfg(target_os = "macos")]
        let rows = parse_lsof(&text);
        #[cfg(windows)]
        let rows = timed_rows.unwrap_or_else(|| parse_windows_netstat(&text));
        for row in rows {
            // A socket whose process we never saw has no agent to attach to.
            let Some(subject) = owners.get(&row.pid).cloned() else {
                continue;
            };
            facts.extend(emit(
                ID,
                PROBE,
                Confidence::Certain,
                clock,
                subject,
                Claim::SocketOpen {
                    protocol: row.protocol,
                    host: row.host,
                    port: row.port,
                    direction: row.direction,
                    opened_at: row.opened_at,
                    bytes: row.bytes,
                },
            ));
        }
        // Docker's host proxy is deliberately not recognised as an agent. An
        // active published port is attributed only through cgroup identity,
        // exact image provenance, and the inspected container init process.
        for container in containers {
            let subject = Subject::Process {
                pid: container.init_pid,
                started_at: container.started_at,
            };
            for port in container.published_ports {
                facts.extend(emit(
                    ID,
                    "Linux cgroup identity + Docker active port binding",
                    Confidence::Certain,
                    clock,
                    subject.clone(),
                    Claim::SocketOpen {
                        protocol: topgent_facts::Protocol::Tcp,
                        host: port.host,
                        port: port.port,
                        direction: Direction::Listening,
                        // Docker reports an active published binding, not when
                        // it was created, and counts nothing.
                        opened_at: None,
                        bytes: None,
                    },
                ));
            }
        }
        Ok(facts)
    }
}

fn agent_owners(processes: &[crate::process::ProcInfo]) -> BTreeMap<u32, Subject> {
    let by_pid: BTreeMap<u32, &crate::process::ProcInfo> = processes
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

#[cfg(test)]
mod tests {
    // Test code asserts and indexes; production code does neither.
    #![allow(clippy::indexing_slicing, clippy::panic, clippy::expect_used)]

    use super::*;
    use crate::process::ProcInfo;
    use topgent_facts::{Subject, UnixMillis};

    #[test]
    fn descendant_sockets_belong_to_the_nearest_agent_ancestor() {
        let process = |pid, parent, family| ProcInfo {
            owner: crate::process::Owner::Uid(501),
            exe_path_known: true,
            pid,
            started_at: UnixMillis(u64::from(pid) * 1_000),
            exe: format!("/bin/p{pid}"),
            name: format!("p{pid}"),
            uid: 501,
            user: "testuser".to_owned(),
            parent,
            family,
        };
        let owners = agent_owners(&[
            process(10, None, Some("codex-cli")),
            process(11, Some(10), None),
            process(12, Some(11), None),
            process(20, Some(10), Some("ollama")),
            process(21, Some(20), None),
            process(30, None, None),
        ]);

        assert_eq!(
            owners.get(&12),
            Some(&Subject::Process {
                pid: 10,
                started_at: UnixMillis(10_000),
            })
        );
        assert_eq!(
            owners.get(&21),
            Some(&Subject::Process {
                pid: 20,
                started_at: UnixMillis(20_000),
            })
        );
        assert!(!owners.contains_key(&30));
    }
}
