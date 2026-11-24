//! How each process was invoked: program path and arguments, in memory only.
//!
//! Several rules read the command line (`proc.cmdline`, `proc.args`,
//! `proc.exe`, the parent's `proc.pcmdline`). Arguments can hold secrets, so
//! they are kept here, in this process's memory, for rule evaluation, and
//! nowhere else: not in the journal, not in the report, not in a finding. A
//! restart forgets them, which costs only rules on processes started before
//! it.

use std::collections::BTreeMap;

use topgent_core::lineage::ProcessKey;
use topgent_facts::UnixMillis;

/// Most processes whose invocation is remembered.
pub(crate) const MAX_INVOCATIONS: usize = 8_192;

/// One exec: the program and its arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Invocation {
    /// The program's full path.
    pub exe: Option<String>,
    /// Its arguments, the first as the program was invoked.
    pub argv: Vec<String>,
    /// When, in the start-time base.
    pub at: UnixMillis,
}

/// Execs remembered per pid: a process can exec again and again, and each
/// earlier event must read the exec that preceded it.
const PER_PID: usize = 8;

/// Recent execs of each pid, oldest first, bounded.
#[derive(Debug, Default)]
pub(crate) struct Invocations {
    by_pid: BTreeMap<u32, Vec<Invocation>>,
}

impl Invocations {
    /// None remembered.
    pub(crate) const fn new() -> Self {
        Self {
            by_pid: BTreeMap::new(),
        }
    }

    /// Records an exec.
    pub(crate) fn record(&mut self, pid: u32, invocation: Invocation) {
        let execs = self.by_pid.entry(pid).or_default();
        if execs.iter().any(|known| known.at == invocation.at) {
            return;
        }
        let at = execs.partition_point(|known| known.at < invocation.at);
        execs.insert(at, invocation);
        if execs.len() > PER_PID {
            execs.remove(0);
        }
        while self.by_pid.len() > MAX_INVOCATIONS {
            // Drop the pid whose latest exec is oldest: the least likely to
            // be asked about.
            let oldest = self
                .by_pid
                .iter()
                .min_by_key(|(_, execs)| execs.last().map(|e| e.at))
                .map(|(pid, _)| *pid);
            match oldest {
                Some(pid) => {
                    self.by_pid.remove(&pid);
                }
                None => break,
            }
        }
    }

    /// The invocation of this run of the process as of `at`: its latest exec
    /// at or before `at`, made while this run held the pid.
    pub(crate) fn of(&self, process: ProcessKey, at: UnixMillis) -> Option<&Invocation> {
        self.by_pid
            .get(&process.pid)?
            .iter()
            .rev()
            .find(|known| known.at <= at)
            .filter(|known| known.at >= process.started_at)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]

    use super::{Invocation, Invocations, MAX_INVOCATIONS};
    use topgent_core::lineage::ProcessKey;
    use topgent_facts::UnixMillis;

    fn exec(at: u64, arg: &str) -> Invocation {
        Invocation {
            exe: Some("/usr/bin/x".to_owned()),
            argv: vec!["x".to_owned(), arg.to_owned()],
            at: UnixMillis(at),
        }
    }

    fn key(pid: u32, started_at: u64) -> ProcessKey {
        ProcessKey {
            pid,
            started_at: UnixMillis(started_at),
        }
    }

    #[test]
    fn a_reused_pid_never_gets_the_previous_runs_arguments() {
        let mut known = Invocations::default();
        known.record(7, exec(100, "--token"));
        assert!(known.of(key(7, 90), UnixMillis(150)).is_some());
        assert!(
            known.of(key(7, 200), UnixMillis(250)).is_none(),
            "a later run of pid 7"
        );
        assert!(
            known.of(key(7, 90), UnixMillis(99)).is_none(),
            "before the exec"
        );
    }

    /// One process can exec several times inside one sweep. Each earlier
    /// event must still read the exec that preceded it, not the latest one.
    #[test]
    fn an_event_reads_the_exec_before_it_not_the_latest() {
        let mut known = Invocations::default();
        known.record(11, exec(4_999, "cat"));
        known.record(11, exec(5_002, "nc"));
        known.record(11, exec(5_005, "x"));
        let run = key(11, 2_000);
        assert_eq!(
            known.of(run, UnixMillis(5_000)).map(|i| i.argv[1].as_str()),
            Some("cat")
        );
        assert_eq!(
            known.of(run, UnixMillis(5_003)).map(|i| i.argv[1].as_str()),
            Some("nc")
        );
        assert_eq!(
            known.of(run, UnixMillis(9_000)).map(|i| i.argv[1].as_str()),
            Some("x")
        );
    }

    #[test]
    fn a_later_exec_replaces_an_earlier_one_and_the_store_is_bounded() {
        let mut known = Invocations::default();
        known.record(7, exec(100, "a"));
        known.record(7, exec(200, "b"));
        known.record(7, exec(150, "stale"));
        assert_eq!(
            known
                .of(key(7, 90), UnixMillis(300))
                .map(|i| i.argv[1].as_str()),
            Some("b")
        );
        for pid in 0..u32::try_from(MAX_INVOCATIONS).unwrap_or(0) + 10 {
            known.record(pid + 100, exec(u64::from(pid) + 1_000, "z"));
        }
        assert!(known.by_pid.len() <= MAX_INVOCATIONS);
    }
}
