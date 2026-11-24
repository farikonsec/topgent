//! Process history that outlives the processes.
//!
//! A snapshot of the process table answers "what is running", and an agent is
//! judged by what it did. The two part company the moment a process exits: a
//! shell the agent started, and every child that shell started, drop out of
//! the table, and a worker the shell left behind is adopted by init and stops
//! looking like the agent's at all. This module keeps the record.
//!
//! # What it promises
//!
//! - **Identity is pid plus start time.** A reused pid is a different process
//!   and inherits nothing. The start time is the kernel's own, so two
//!   processes that held one pid inside the same second are still two.
//! - **A parent is resolved as of the child's start.** The parent is the
//!   process that held the parent pid when the child started, never whichever
//!   one holds it now.
//! - **Nothing is guessed while waiting.** A child seen before its parent, or
//!   an exit before the process, stays unresolved until the missing record
//!   arrives. There is no timeout after which a guess becomes a fact.
//! - **The first parent is kept.** Reparenting to init or a subreaper is
//!   recorded and does not rewrite where the process came from.
//! - **Gone is not exited.** A process a snapshot no longer sees has gone some
//!   time after it was last seen. Only an exit record carries an exit time.
//!
//! Records come from snapshots today and from a kernel event stream later;
//! the rules do not depend on which.

use std::collections::{BTreeMap, BTreeSet};

use topgent_facts::UnixMillis;

/// Deepest ancestry walked. Bounds a walk over corrupt or hostile input.
const MAX_DEPTH: usize = 64;
/// Programs kept from earlier generations of one process.
const MAX_PREVIOUS_EXES: usize = 8;

/// Exact identity of one process run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcessKey {
    /// Process id, as the host sees it.
    pub pid: u32,
    /// When the kernel started it.
    pub started_at: UnixMillis,
}

/// One sighting of a process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// Which run.
    pub key: ProcessKey,
    /// Its parent pid at the moment of the sighting.
    pub parent_pid: Option<u32>,
    /// Its name.
    pub name: String,
    /// Its executable, where readable.
    pub exe: Option<String>,
    /// Its pid namespace, where readable.
    pub pid_namespace: Option<u64>,
    /// When it was seen.
    pub at: UnixMillis,
    /// Whether the kernel reported it as it happened, rather than a sweep
    /// finding it running.
    pub from_event: bool,
}

/// Whether a recorded process is still there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    /// Seen in the latest sighting.
    Running,
    /// No longer seen. When it ended is not known, only that it was after
    /// `last_seen`.
    Gone,
    /// An exit record gave the time it ended.
    Exited,
}

impl ProcessState {
    /// Stable report label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Gone => "gone",
            Self::Exited => "exited",
        }
    }
}

/// The history of one process run.
// Adoption, namespace, unread exec and kernel sighting are independent
// facts; any combination can hold, so they are not one state.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessRecord {
    /// Which run.
    pub key: ProcessKey,
    /// Its name at the latest sighting.
    pub name: String,
    /// The parent it had when it started, once resolved.
    pub parent: Option<ProcessKey>,
    /// The parent pid it reported, kept until the parent resolves.
    pub parent_pid: Option<u32>,
    /// Whether it was later adopted by another process.
    pub reparented: bool,
    /// Whether it runs in a different pid namespace from its parent.
    pub crossed_namespace: bool,
    /// Its pid namespace, where readable.
    pub pid_namespace: Option<u64>,
    /// Its current program.
    pub exe: Option<String>,
    /// Programs it ran before an `exec`, oldest first, bounded.
    pub previous_exes: Vec<String>,
    /// How many times it replaced its program.
    pub exec_generation: u32,
    /// Whether it exec'd into a program that was gone before it could be
    /// read, so the current program is unknown.
    pub program_unread: bool,
    /// First sighting.
    pub first_seen: UnixMillis,
    /// Latest sighting.
    pub last_seen: UnixMillis,
    /// The first sighting that no longer found it.
    pub gone_after: Option<UnixMillis>,
    /// When it exited, from an exit record.
    pub exited_at: Option<UnixMillis>,
    /// Its exit status, from an exit record.
    pub exit_code: Option<u32>,
    /// Whether any record of it came from the kernel as it happened.
    pub from_event: bool,
}

impl ProcessRecord {
    /// Whether it is still there.
    #[must_use]
    pub const fn state(&self) -> ProcessState {
        if self.exited_at.is_some() {
            ProcessState::Exited
        } else if self.gone_after.is_some() {
            ProcessState::Gone
        } else {
            ProcessState::Running
        }
    }

    /// The latest moment it can have been running, if it has ended.
    const fn ended_by(&self) -> Option<UnixMillis> {
        match (self.exited_at, self.gone_after) {
            (Some(exited), _) => Some(exited),
            (None, gone) => gone,
        }
    }

    fn from(observation: Observation) -> Self {
        Self {
            key: observation.key,
            name: observation.name,
            parent: None,
            parent_pid: observation.parent_pid,
            reparented: false,
            crossed_namespace: false,
            pid_namespace: observation.pid_namespace,
            exe: observation.exe,
            previous_exes: Vec::new(),
            exec_generation: 0,
            program_unread: false,
            first_seen: observation.at,
            last_seen: observation.at,
            gone_after: None,
            exited_at: None,
            exit_code: None,
            from_event: observation.from_event,
        }
    }
}

/// A bounded history of process runs.
#[derive(Debug, Clone, Default)]
pub struct Lineage {
    records: BTreeMap<ProcessKey, ProcessRecord>,
    /// Exits recorded for a process not yet seen.
    pending_exits: BTreeMap<ProcessKey, UnixMillis>,
    cap: usize,
}

impl Lineage {
    /// An empty history holding at most `cap` records.
    #[must_use]
    pub const fn new(cap: usize) -> Self {
        Self {
            records: BTreeMap::new(),
            pending_exits: BTreeMap::new(),
            cap,
        }
    }

    /// Records one sighting.
    pub fn observe(&mut self, observation: Observation) {
        let key = observation.key;
        if let Some(record) = self.records.get_mut(&key) {
            if observation.exe.is_some() && observation.exe != record.exe {
                if let Some(previous) = record.exe.take() {
                    record.previous_exes.push(previous);
                    if record.previous_exes.len() > MAX_PREVIOUS_EXES {
                        record.previous_exes.remove(0);
                    }
                }
                record.exe = observation.exe;
                // The unread exec and this readable one may be the same.
                if !record.program_unread {
                    record.exec_generation = record.exec_generation.saturating_add(1);
                }
                record.program_unread = false;
            }
            record.name = observation.name;
            record.from_event |= observation.from_event;
            record.last_seen = record.last_seen.max(observation.at);
            // Seen again after a snapshot missed it: it was running all
            // along. An exit record is not undone by a stale sighting.
            record.gone_after = None;
            match (record.parent, observation.parent_pid) {
                (Some(parent), Some(now)) if parent.pid != now => record.reparented = true,
                (None, Some(_)) => record.parent_pid = observation.parent_pid,
                _ => {}
            }
        } else {
            let mut record = ProcessRecord::from(observation);
            record.exited_at = self.pending_exits.remove(&key);
            self.records.insert(key, record);
            // A new record can be someone's missing parent, or be missing
            // its own. Updating a known one changes neither.
            self.resolve_parents();
        }
        self.evict();
    }

    /// Recover the program of a single unread exec from a successful Audit
    /// record. Multiple recorded execs remain ambiguous and are not rewritten.
    pub fn recover_exec_name(&mut self, key: ProcessKey, program: &str) {
        if let Some(record) = self.records.get_mut(&key)
            && record.program_unread
            && record.exec_generation == 1
        {
            record.exe = Some(program.to_owned());
            program.clone_into(&mut record.name);
            record.program_unread = false;
        }
    }

    /// Records an exec whose new program could not be read: the process was
    /// gone first. The old program moves to the history and the current one
    /// is unknown, rather than left looking as though it still ran.
    pub fn exec_unread(&mut self, key: ProcessKey, at: UnixMillis) {
        let Some(record) = self.records.get_mut(&key) else {
            return;
        };
        if let Some(previous) = record.exe.take() {
            record.previous_exes.push(previous);
            if record.previous_exes.len() > MAX_PREVIOUS_EXES {
                record.previous_exes.remove(0);
            }
        }
        record.exec_generation = record.exec_generation.saturating_add(1);
        record.program_unread = true;
        record.from_event = true;
        record.last_seen = record.last_seen.max(at);
    }

    /// Records that a process exited, at the time the exit record gives.
    pub fn exited(&mut self, key: ProcessKey, at: UnixMillis) {
        self.exited_with(key, at, None);
    }

    /// Records an exit with the status the kernel gave.
    pub fn exited_with(&mut self, key: ProcessKey, at: UnixMillis, code: Option<u32>) {
        if let Some(record) = self.records.get_mut(&key) {
            record.exited_at = Some(at);
            record.exit_code = code.or(record.exit_code);
            record.from_event |= code.is_some();
        } else {
            self.pending_exits.insert(key, at);
            // Pending exits are bounded like records.
            while self.pending_exits.len() > self.cap {
                self.pending_exits.pop_first();
            }
        }
        self.evict();
    }

    /// Marks every recorded process a snapshot at `at` did not find as gone.
    pub fn missing(&mut self, live: &BTreeSet<ProcessKey>, at: UnixMillis) {
        for record in self.records.values_mut() {
            if !live.contains(&record.key) && record.state() == ProcessState::Running {
                record.gone_after = Some(at);
            }
        }
        self.evict();
    }

    /// One recorded process.
    #[must_use]
    pub fn get(&self, key: ProcessKey) -> Option<&ProcessRecord> {
        self.records.get(&key)
    }

    /// Its parents, nearest first, as far as they are recorded.
    #[must_use]
    pub fn ancestry(&self, key: ProcessKey) -> Vec<ProcessKey> {
        let mut chain = Vec::new();
        let mut seen = BTreeSet::from([key]);
        let mut current = self.records.get(&key).and_then(|record| record.parent);
        while let Some(parent) = current {
            if chain.len() >= MAX_DEPTH || !seen.insert(parent) {
                break;
            }
            chain.push(parent);
            current = self.records.get(&parent).and_then(|record| record.parent);
        }
        chain
    }

    /// Every recorded process descended from `root`, running or not.
    #[must_use]
    pub fn descendants(&self, root: ProcessKey) -> Vec<&ProcessRecord> {
        self.records
            .values()
            .filter(|record| record.key != root && self.ancestry(record.key).contains(&root))
            .collect()
    }

    /// Every record, in key order.
    pub fn records(&self) -> impl Iterator<Item = &ProcessRecord> {
        self.records.values()
    }

    /// How many processes are recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether nothing is recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Restores a record, as a journal reads one back. Call [`Self::settle`]
    /// once every record is restored.
    pub fn restore(&mut self, record: ProcessRecord) {
        self.records.insert(record.key, record);
    }

    /// Resolves what restored records left open and applies the bound.
    pub fn settle(&mut self) {
        self.resolve_parents();
        self.evict();
    }

    /// The recorded process that held `pid` at `at`, if any.
    #[must_use]
    pub fn resolve(&self, pid: u32, at: UnixMillis) -> Option<ProcessKey> {
        self.holder_at(pid, at)
    }

    /// The process that held `pid` when a child started at `child_start`.
    ///
    /// Pids are unique among running processes, so of the recorded holders
    /// that had started by then and had not ended before it, the latest to
    /// start is the one. No holder, no parent.
    fn holder_at(&self, pid: u32, child_start: UnixMillis) -> Option<ProcessKey> {
        self.records
            .values()
            .filter(|candidate| {
                candidate.key.pid == pid
                    && candidate.key.started_at <= child_start
                    && candidate
                        .ended_by()
                        .is_none_or(|ended| ended >= child_start)
            })
            .map(|candidate| candidate.key)
            .max_by_key(|candidate| candidate.started_at)
    }

    fn resolve_parents(&mut self) {
        let waiting: Vec<(ProcessKey, u32)> = self
            .records
            .values()
            .filter(|record| record.parent.is_none())
            .filter_map(|record| Some((record.key, record.parent_pid?)))
            .collect();
        for (child, parent_pid) in waiting {
            let Some(parent) = self.holder_at(parent_pid, child.started_at) else {
                continue;
            };
            if parent == child {
                continue;
            }
            let parent_namespace = self.records.get(&parent).and_then(|p| p.pid_namespace);
            if let Some(record) = self.records.get_mut(&child) {
                record.parent = Some(parent);
                record.crossed_namespace = matches!(
                    (parent_namespace, record.pid_namespace),
                    (Some(a), Some(b)) if a != b
                );
            }
        }
    }

    /// Drops finished processes, oldest ending first, until within the bound.
    /// A running process is never dropped.
    fn evict(&mut self) {
        while self.records.len() > self.cap {
            let oldest = self
                .records
                .values()
                .filter_map(|record| Some((record.ended_by()?, record.key)))
                .min();
            let Some((_, key)) = oldest else {
                break;
            };
            self.records.remove(&key);
        }
    }
}
