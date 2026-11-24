//! What one kernel event becomes as an output line.
//!
//! Separate from the receive loops because this is where the sensor decides
//! what it says about a process: the key it is filed under, the name it had,
//! and what is left out when the process is already gone. Both sources, eBPF
//! and the process connector, describe what they saw as a [`Happened`] and
//! share this one writer, so a line means the same whichever source made it.

use std::collections::HashMap;

use serde_json::json;
use topgent_collect::process::{kernel_start, start_from_event};

/// Processes whose start time and name are remembered until they exit.
const MAX_KNOWN: usize = 65_536;
/// Longest exec argument list written, as JSON. Longer lists are left out
/// whole, so the line stays within what the collector reads.
const MAX_ARGV_JSON: usize = 12_000;

/// One process-level event, with what its source could say at the time.
pub(super) enum Happened {
    /// `child` was created by `parent`. `name` is the child's, when the
    /// source had it; `pid_namespace`, when the kernel placed it in the
    /// host's pid namespace at the moment of the event.
    Fork {
        parent: u32,
        child: u32,
        name: Option<String>,
        pid_namespace: Option<u64>,
    },
    /// `pid` replaced its program. `program` is the file name; `path` the
    /// full path, when the source read it at the moment of the exec;
    /// `pid_namespace` as for a fork; `argv` its arguments, when the source
    /// read all of them.
    Exec {
        pid: u32,
        name: Option<String>,
        program: Option<String>,
        path: Option<String>,
        pid_namespace: Option<u64>,
        argv: Option<Vec<String>>,
        /// The audit login id, when the eBPF source read it.
        loginuid: Option<u32>,
        /// Whether the process had a controlling terminal.
        tty: Option<bool>,
    },
    /// `pid`'s last thread ended. `code` when the source reports one.
    Exit { pid: u32, code: Option<u32> },
    /// The kernel renamed `pid`.
    Rename { pid: u32, name: String },
}

/// Adds a field to a line built with `json!({..})`, which is always an
/// object; for anything else it does nothing.
pub(super) fn add(line: &mut serde_json::Value, key: &str, value: impl Into<serde_json::Value>) {
    if let Some(fields) = line.as_object_mut() {
        fields.insert(key.to_owned(), value.into());
    }
}

/// A process's name from `/proc`, while it is still there.
pub(super) fn comm(pid: u32) -> Option<String> {
    let name = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    Some(name.trim_end().chars().take(64).collect())
}

/// A process's program file name from `/proc`, while it is still there.
pub(super) fn program(pid: u32) -> Option<String> {
    let path = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    Some(
        path.file_name()?
            .to_string_lossy()
            .chars()
            .take(64)
            .collect(),
    )
}

pub(super) struct Known {
    start: Option<u64>,
    name: Option<String>,
    /// The process that created it, when a fork was seen.
    parent: Option<u32>,
}

/// Most ancestors written with a syscall.
const MAX_ANCESTORS: usize = 16;

/// A running process's parent and name from `/proc/<pid>/stat`, for one the
/// sensor never saw created: it started before the sensor did.
fn stat(pid: u32) -> Option<(u32, String)> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // `pid (comm) state ppid …`; the name may itself hold ") ".
    let (head, tail) = text.rsplit_once(") ")?;
    let name = head.split_once(" (")?.1.chars().take(64).collect();
    let parent = tail.split_whitespace().nth(1)?.parse().ok()?;
    Some((parent, name))
}

/// A process's parent: from the fork the sensor saw, else read once from
/// `/proc` and kept, so a busy process's hundredth call costs no read.
fn parent_of(known: &mut HashMap<u32, Known>, pid: u32) -> Option<u32> {
    if let Some(parent) = known.get(&pid).and_then(|k| k.parent) {
        return Some(parent);
    }
    let (parent, name) = stat(pid)?;
    let room = known.len() < MAX_KNOWN;
    match known.get_mut(&pid) {
        Some(entry) => {
            entry.parent = Some(parent);
            entry.name.get_or_insert(name);
        }
        None if room => {
            known.insert(
                pid,
                Known {
                    start: None,
                    name: Some(name),
                    parent: Some(parent),
                },
            );
        }
        None => {}
    }
    Some(parent)
}

/// The process's ancestors at the moment of a call, nearest first, as
/// `(pid, name)`: from the forks the sensor saw, else from `/proc` for a
/// process that started before it. Stops at pid 1, at a pid it cannot
/// place, or at [`MAX_ANCESTORS`]. Audit records carried a `ppid` for this;
/// without it, a short-lived process outside any agent's tree has no
/// ancestry, and every rule that allows a named parent stays undecided.
pub(super) fn ancestry(known: &mut HashMap<u32, Known>, pid: u32) -> Vec<(u32, Option<String>)> {
    let mut chain = Vec::new();
    let mut current = pid;
    while chain.len() < MAX_ANCESTORS {
        let Some(mut parent) = parent_of(known, current).filter(|p| *p != 0 && *p != current)
        else {
            break;
        };
        // Reading the parent's own parent also fills in its name.
        let _ = parent_of(known, parent);
        // A creator that is gone and was never named ends the chain. The
        // kernel's own parent can go on: `runc` makes a container's init with
        // CLONE_PARENT and exits, and the real parent, `containerd-shim`,
        // lives (found in E7).
        if known.get(&parent).and_then(|k| k.name.as_ref()).is_none()
            && let Some((real, _)) = stat(current).filter(|(real, _)| *real != 0 && *real != parent)
        {
            parent = real;
            let _ = parent_of(known, parent);
        }
        chain.push((parent, known.get(&parent).and_then(|k| k.name.clone())));
        if parent == 1 {
            break;
        }
        current = parent;
    }
    chain
}

/// Keeps a process's start and latest name for the events that follow.
/// The first start recorded for a pid stays its key.
fn remember(known: &mut HashMap<u32, Known>, pid: u32, start: Option<u64>, name: Option<String>) {
    if let Some(entry) = known.get_mut(&pid) {
        if name.is_some() {
            entry.name = name;
        }
        if entry.start.is_none() {
            entry.start = start;
        }
    } else if known.len() < MAX_KNOWN {
        known.insert(
            pid,
            Known {
                start,
                name,
                parent: None,
            },
        );
    }
}

/// The start a pid is filed under: the one already fixed for it, else the
/// kernel's, while `/proc` still has it.
fn start_of(known: &HashMap<u32, Known>, pid: u32, boot: Option<u64>) -> Option<u64> {
    known
        .get(&pid)
        .and_then(|k| k.start)
        .or_else(|| kernel_start(pid, boot).map(|start| start.0))
}

/// Forgets an ended process. Called once its last line is written.
pub(super) fn forget(known: &mut HashMap<u32, Known>, pid: u32) {
    known.remove(&pid);
}

/// One event as its output line.
pub(super) fn describe(
    happened: Happened,
    known: &mut HashMap<u32, Known>,
    boot: Option<u64>,
    at: u64,
) -> serde_json::Value {
    match happened {
        Happened::Fork {
            parent,
            child,
            name,
            pid_namespace,
        } => {
            // A child that is gone before its start time can be read is
            // keyed by the fork's own time, and every later event about
            // it reuses that key, so its rename, exec and exit still land
            // on the same record.
            //
            // Events from different CPUs can arrive out of order: the
            // child's rename or exec, reported on its own CPU, may come
            // before its fork. Whichever arrived first fixed the key.
            // Unreadable, the start is the fork's own time on `/proc`'s tick
            // grid, so a parent that died too fast to read still sorts
            // before a child whose start was read.
            let start = start_of(known, child, boot).or(Some(start_from_event(at, boot)));
            let name = name.or_else(|| known.get(&parent).and_then(|p| p.name.clone()));
            if known.len() < MAX_KNOWN {
                known.insert(
                    child,
                    Known {
                        start,
                        name: name.clone(),
                        parent: Some(parent),
                    },
                );
            }
            let mut line = json!({"e": "fork", "pid": child, "ppid": parent,
                                  "start": start, "name": name, "at": at});
            if let Some(namespace) = pid_namespace {
                add(&mut line, "pidns", namespace);
            }
            line
        }
        Happened::Exec {
            pid,
            name,
            program,
            path,
            pid_namespace,
            argv,
            loginuid,
            tty,
        } => {
            let start = start_of(known, pid, boot);
            remember(known, pid, start, name.clone());
            let mut line = json!({"e": "exec", "pid": pid, "start": start, "name": name,
                                  "program": program, "at": at});
            if let Some(path) = path {
                add(&mut line, "path", path);
            }
            if let Some(namespace) = pid_namespace {
                add(&mut line, "pidns", namespace);
            }
            if let Some(auid) = loginuid {
                add(&mut line, "auid", auid);
            }
            if let Some(tty) = tty {
                add(&mut line, "tty", u8::from(tty));
            }
            // In memory on the other side only, as Audit's are.
            if let Some(argv) = argv.map(serde_json::Value::from)
                && argv.to_string().len() <= MAX_ARGV_JSON
            {
                add(&mut line, "argv", argv);
            }
            line
        }
        Happened::Exit { pid, code } => {
            // Forgotten by the caller, with `forget`: the eBPF source still
            // needs the process for the calls it made just before it ended.
            let remembered = known.get(&pid);
            let start = remembered
                .as_ref()
                .and_then(|k| k.start)
                .or_else(|| kernel_start(pid, boot).map(|start| start.0));
            let mut line = json!({"e": "exit", "pid": pid, "start": start,
                                  "name": remembered.and_then(|k| k.name.clone()), "at": at});
            // No code is written as no code: never as a made-up zero.
            if let Some(code) = code {
                add(&mut line, "code", code);
            }
            line
        }
        Happened::Rename { pid, name } => {
            let start = start_of(known, pid, boot);
            remember(known, pid, start, Some(name.clone()));
            json!({"e": "comm", "pid": pid, "start": start, "name": name, "at": at})
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]

    use std::collections::HashMap;

    use topgent_collect::process_events::{LifecycleKind, Line, parse_line};

    use super::{Happened, describe};

    /// A pid no test host is running, so `/proc` has nothing for it.
    const GONE: u32 = 4_000_000;

    fn parsed(happened: Happened, known: &mut HashMap<u32, super::Known>) -> Line {
        let line = describe(happened, known, None, 1_000).to_string();
        parse_line(&line).unwrap_or_else(|| unreachable!("the reader refused {line}"))
    }

    /// Every line this writer makes is one the reader accepts, with the same
    /// facts: the two sides of the pipe cannot drift.
    #[test]
    fn every_line_is_read_back_by_the_collector() {
        let mut known = HashMap::new();
        let Line::Event(fork) = parsed(
            Happened::Fork {
                parent: GONE - 1,
                child: GONE,
                name: Some("sh".into()),
                pid_namespace: Some(4_026_531_836),
            },
            &mut known,
        ) else {
            unreachable!()
        };
        assert_eq!(fork.kind, LifecycleKind::Fork { parent: GONE - 1 });
        assert_eq!(fork.name.as_deref(), Some("sh"));

        let Line::Event(exec) = parsed(
            Happened::Exec {
                pid: GONE,
                name: Some("nmap".into()),
                program: Some("nmap".into()),
                path: Some("/usr/bin/nmap".into()),
                pid_namespace: Some(4_026_531_836),
                argv: Some(vec!["nmap".into(), "--version".into()]),
                loginuid: Some(1000),
                tty: Some(true),
            },
            &mut known,
        ) else {
            unreachable!()
        };
        assert_eq!(exec.kind, LifecycleKind::Exec);
        assert_eq!(exec.tty, Some(true));
        assert_eq!(
            exec.argv.as_deref(),
            Some(&["nmap".to_owned(), "--version".to_owned()][..])
        );
        assert_eq!(exec.path.as_deref(), Some("/usr/bin/nmap"));
        assert_eq!(exec.pid_namespace, Some(4_026_531_836));
        assert_eq!(fork.pid_namespace, Some(4_026_531_836));
        assert_eq!(
            exec.started_at, fork.started_at,
            "the exec lands on the fork's key"
        );

        let Line::Event(exit) = parsed(
            Happened::Exit {
                pid: GONE,
                code: None,
            },
            &mut known,
        ) else {
            unreachable!()
        };
        assert_eq!(exit.kind, LifecycleKind::Exit { code: None });
        assert_eq!(exit.name.as_deref(), Some("nmap"), "the name it last had");
    }

    #[test]
    fn an_exit_code_is_written_only_when_the_source_had_one() {
        let mut known = HashMap::new();
        let with = describe(
            Happened::Exit {
                pid: GONE,
                code: Some(256),
            },
            &mut known,
            None,
            1,
        );
        let without = describe(
            Happened::Exit {
                pid: GONE,
                code: None,
            },
            &mut known,
            None,
            1,
        );
        assert_eq!(with["code"], 256);
        assert!(without.get("code").is_none(), "{without}");
    }

    #[test]
    fn a_fork_without_a_name_takes_its_parents() {
        let mut known = HashMap::new();
        parsed(
            Happened::Rename {
                pid: GONE - 1,
                name: "codex".into(),
            },
            &mut known,
        );
        let Line::Event(fork) = parsed(
            Happened::Fork {
                parent: GONE - 1,
                child: GONE,
                name: None,
                pid_namespace: None,
            },
            &mut known,
        ) else {
            unreachable!()
        };
        assert_eq!(fork.name.as_deref(), Some("codex"));
    }
}
