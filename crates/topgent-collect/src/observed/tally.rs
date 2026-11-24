//! Running totals per process, counted before anything is dropped.
//!
//! Every other path from the kernel to a rule is bounded: 65,536 lines
//! between sweeps, 16,384 calls handed to a sweep, 2,048 actions retained.
//! A process that reads 42,000 files in a few seconds overflows all three,
//! and a rule that counts rows then counts what survived, not what happened.
//!
//! So the sensor's reader thread adds each call here as it parses it, before
//! any of those bounds. What is kept is counts, not rows: per process, the
//! distinct files read under each workspace root and how many of them were
//! version-control history; per destination, connection attempts by outcome
//! and the bytes written to it. A sweep takes a copy of the totals; they
//! keep running until the process has been quiet for [`QUIET_MS`].
//!
//! The totals say what a process did, never what the bytes were. Nothing
//! here reads a file or a payload.

use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::hash::{Hash as _, Hasher as _};
use std::path::Path;
use std::sync::{Mutex, PoisonError};

use crate::audit_syscalls::SyscallEvent;

/// How long a process's totals outlive its last call.
pub const QUIET_MS: u64 = 30 * 60 * 1_000;
/// How long they outlive it when the process read a workspace (at least
/// [`REPORT_FILES`] under one root). The whole-run egress test compares what a
/// run sends later with that read, so the read must outlast a wait: a process
/// that read a repository, slept past [`QUIET_MS`] and then uploaded was a new
/// process with no read behind it, and the upload went unreported. Uploads more
/// than this long after a process's last call are not linked to its read.
pub const READER_QUIET_MS: u64 = 6 * 60 * 60 * 1_000;
/// Most processes tracked. Past it the one quiet longest is forgotten and
/// counted in [`Totals::forgotten`].
pub const MAX_PROCESSES: usize = 4_096;
/// Most distinct file names remembered across all processes. Past it, reads
/// are still counted, as [`RootTotals::uncounted`], but no longer told apart.
pub const MAX_DISTINCT: usize = 2_000_000;
/// Most destinations and descriptors tracked for one process.
const MAX_PER_PROCESS: usize = 4_096;
/// Most recent file reads kept by name per process, newest last: enough to
/// say what was read in the minute before a burst of sending.
const RECENT_READS: usize = 256;
/// Most sensitive-looking files kept by name per process.
const SENSITIVE_READS: usize = 64;
/// The window a burst of sending is measured over.
pub const BURST_WINDOW_MS: u64 = 5 * 60 * 1_000;
/// Minute buckets kept per destination, to find the largest burst.
const BURST_BUCKETS: usize = 30;
/// Most workspace roots tracked for one process.
const MAX_ROOTS: usize = 256;
/// Most remembered directory-to-root answers.
const MAX_ROOT_CACHE: usize = 65_536;
/// Most subdirectories counted per root, for the "where" in a finding.
const MAX_CHILDREN: usize = 64;
/// A process is reported only once it has read this many distinct files
/// under one root, or tried a connection.
const REPORT_FILES: u32 = 20;

/// `EINPROGRESS`, as a negated result.
const EINPROGRESS: i64 = -115;

/// What one process read under one workspace root.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RootTotals {
    /// The root: a repository, the process's working directory, or a
    /// directory two levels below a home directory.
    pub root: String,
    /// Distinct files read under it.
    pub files: u32,
    /// Of those, files under its `.git`.
    pub history_files: u32,
    /// Reads past [`MAX_DISTINCT`], counted but not told apart.
    pub uncounted: u32,
    /// The size of the distinct files read, as they were when first read.
    /// What a burst of sending is compared with: an agent that writes 60 MB
    /// into its workspace has still only read what it read.
    pub read_bytes: u64,
    /// Distinct files that could not be sized when read: gone by then, or
    /// named by a path that does not resolve here (another mount namespace).
    /// While any are unsized, `read_bytes` is a floor, not the read.
    pub unsized_files: u32,
    /// The subdirectories read most, with their distinct-file counts.
    pub top: Vec<(String, u32)>,
    /// What the process later did to the files it read here.
    pub changes: super::changes::ChangeTotals,
    /// First and last read, in the start-time base.
    pub first_at: u64,
    /// As above.
    pub last_at: u64,
}

/// What one process sent to one destination.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DestTotals {
    /// Address literal, or empty for a socket whose connect was not seen.
    pub host: String,
    /// Port, zero when unknown.
    pub port: u16,
    /// Connection attempts.
    pub attempts: u32,
    /// Of those, completed at once.
    pub connected: u32,
    /// Of those, still in progress when the call returned.
    pub in_progress: u32,
    /// Of those, refused or otherwise failed.
    pub failed: u32,
    /// Bytes written to it, as the kernel reported them.
    pub bytes: u64,
    /// The most bytes written to it within any [`BURST_WINDOW_MS`]: an upload
    /// is a burst, a conversation is a trickle.
    pub burst_bytes: u64,
    /// When that burst ended, in the start-time base.
    pub burst_at: u64,
    /// Bytes per minute for the last [`BURST_BUCKETS`] minutes, as
    /// `(minute, bytes)` with the minute in the start-time base: enough to say
    /// what was sent in the minutes after a given read.
    pub minutes: Vec<(u64, u64)>,
    /// First and last activity, in the start-time base.
    pub first_at: u64,
    /// As above.
    pub last_at: u64,
}

/// One process's totals.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcessTotals {
    /// The process.
    pub pid: u32,
    /// Its name, as the kernel had it at its first counted call.
    pub name: Option<String>,
    /// Its first and last counted call, in the start-time base. The pid is
    /// resolved to a process at `first_at`.
    pub first_at: u64,
    /// As above.
    pub last_at: u64,
    /// Whether it has exited.
    pub ended: bool,
    /// Workspace roots read, most files first.
    pub roots: Vec<RootTotals>,
    /// Destinations, most bytes first.
    pub destinations: Vec<DestTotals>,
    /// The last files it read, by path, oldest first, with when.
    pub recent_reads: Vec<(String, u64)>,
    /// Files it read that look like credentials or keys: the path, when,
    /// the size it had then (zero when it could not be sized), and the class
    /// id of secret (see [`crate::sensitive`]).
    pub sensitive_reads: Vec<(String, u64, u64, String)>,
}

/// Everything a sweep takes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Totals {
    /// Processes worth reporting.
    pub processes: Vec<ProcessTotals>,
    /// Processes forgotten under [`MAX_PROCESSES`] since this collector
    /// started: totals that were lost, said rather than hidden.
    pub forgotten: u64,
    /// Whether [`MAX_DISTINCT`] has been reached.
    pub saturated: bool,
}

#[derive(Debug, Default)]
struct Root {
    files: HashSet<u64>,
    /// What the process later did to files in `files`.
    changes: super::changes::Changes,
    history: HashSet<u64>,
    uncounted: u32,
    read_bytes: u64,
    unsized_files: u32,
    children: HashMap<String, u32>,
    first_at: u64,
    last_at: u64,
}

#[derive(Debug, Default)]
struct Dest {
    attempts: u32,
    connected: u32,
    in_progress: u32,
    failed: u32,
    bytes: u64,
    /// Bytes per minute, oldest first, for the last [`BURST_BUCKETS`] minutes.
    minutes: std::collections::VecDeque<(u64, u64)>,
    burst_bytes: u64,
    burst_at: u64,
    first_at: u64,
    last_at: u64,
}

impl Dest {
    /// Adds bytes written at `at` and keeps the largest windowed burst.
    fn sent(&mut self, bytes: u64, at: u64) {
        self.bytes = self.bytes.saturating_add(bytes);
        let minute = at / 60_000;
        match self.minutes.back_mut() {
            Some((m, b)) if *m == minute => *b = b.saturating_add(bytes),
            _ => self.minutes.push_back((minute, bytes)),
        }
        while self
            .minutes
            .front()
            .is_some_and(|(m, _)| minute.saturating_sub(*m) >= BURST_BUCKETS as u64)
        {
            self.minutes.pop_front();
        }
        let span = BURST_WINDOW_MS / 60_000;
        let window: u64 = self
            .minutes
            .iter()
            .filter(|(m, _)| minute.saturating_sub(*m) < span)
            .map(|(_, b)| *b)
            .sum();
        if window > self.burst_bytes {
            self.burst_bytes = window;
            self.burst_at = at;
        }
    }
}

#[derive(Debug, Default)]
struct Process {
    name: Option<String>,
    first_at: u64,
    last_at: u64,
    ended: bool,
    roots: HashMap<String, Root>,
    destinations: HashMap<(String, u16), Dest>,
    recent: std::collections::VecDeque<(String, u64)>,
    sensitive: Vec<(String, u64, u64, String)>,
    /// Where each connected descriptor goes; `None` for a local peer, whose
    /// writes are not counted.
    descriptors: HashMap<u64, Option<(String, u16)>>,
}

/// The running totals.
#[derive(Debug, Default)]
pub struct Tally {
    processes: HashMap<u32, Process>,
    distinct: usize,
    forgotten: u64,
    roots: HashMap<String, Option<String>>,
    /// Child pid to its parent, from fork events, so a short-lived tool's
    /// run can be found without the process history, which may evict it.
    parents: HashMap<u32, u32>,
    /// Parent pid to the encryption tools its children exec'd. Keyed by
    /// parent because the tool itself reads and sends nothing, so it is not
    /// an actor; its parent is.
    tools_by_parent: HashMap<u32, BTreeSet<String>>,
}

/// Encryption tools worth naming when one runs between reading and sending.
const CRYPTO_TOOLS: [&str; 7] = ["openssl", "gpg", "gpg2", "age", "ccrypt", "scrypt", "7z"];

/// The tool basename, lowercased, when `program` is one.
fn crypto_tool(program: &str) -> Option<String> {
    let base = program
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(program)
        .to_ascii_lowercase();
    CRYPTO_TOOLS.contains(&base.as_str()).then_some(base)
}

fn hash(text: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    text.hash(&mut hasher);
    hasher.finish()
}

/// Paths that belong to the system or to a program's own installation, not
/// to anybody's work.
const SYSTEM: [&str; 16] = [
    "/usr/",
    "/lib/",
    "/lib64/",
    "/lib32/",
    "/bin/",
    "/sbin/",
    "/etc/",
    "/proc/",
    "/sys/",
    "/dev/",
    "/run/",
    "/var/lib/",
    "/var/cache/",
    "/snap/",
    "/nix/",
    "/opt/",
];

/// `/home/u`, `/Users/u` or `/root`, when `path` is under one.
fn home_of(path: &str) -> Option<&str> {
    if path == "/root" || path.starts_with("/root/") {
        return Some("/root");
    }
    for base in ["/home/", "/Users/"] {
        if let Some(rest) = path.strip_prefix(base) {
            let user = rest.split('/').next().filter(|u| !u.is_empty())?;
            return path.get(..base.len() + user.len());
        }
    }
    None
}

/// Whether a read of `path` could be a read of somebody's work: not the
/// system, not an application's mounted image, and not a tool's cache or
/// configuration directly under a home directory.
fn workspace_path(path: &str) -> bool {
    if !path.starts_with('/') || SYSTEM.iter().any(|p| path.starts_with(p)) {
        return false;
    }
    if path.starts_with("/tmp/.mount_") || path.starts_with("/var/tmp/.mount_") {
        return false;
    }
    if path.contains("/.git/") {
        return true;
    }
    if let Some(home) = home_of(path)
        && let Some(rest) = path.get(home.len()..).and_then(|r| r.strip_prefix('/'))
        && (rest.starts_with('.') || rest.starts_with("Library/"))
    {
        return false;
    }
    true
}

impl Tally {
    /// Adds one call. `at` is in the start-time base.
    pub fn add(&mut self, event: &SyscallEvent, at: u64) {
        match event.syscall {
            "open" | "openat" | "openat2" => {
                self.read(event, at);
                self.change(event, at);
            }
            "unlink" | "unlinkat" | "rename" | "renameat" | "renameat2" => self.change(event, at),
            "connect" => self.connect(event, at),
            "sendto" | "sendmsg" | "write" | "writev" => self.sent(event, at),
            "dup" | "dup2" | "dup3" => self.dup(event),
            _ => {}
        }
    }

    /// The process is gone. Its totals stay until they go quiet, so trailing
    /// syscalls delivered after the exit still land on the run that made
    /// them. A genuinely reused pid is signalled by [`Tally::started`], not
    /// by a late syscall.
    pub fn exited(&mut self, pid: u32) {
        if let Some(process) = self.processes.get_mut(&pid) {
            process.ended = true;
        }
    }

    /// A new process took this pid (a fork or exec). Any totals held under it
    /// belong to an earlier run and are dropped, so the pid starts clean.
    pub fn started(&mut self, pid: u32) {
        if let Some(old) = self.processes.remove(&pid) {
            self.distinct = self.distinct.saturating_sub(
                old.roots
                    .values()
                    .map(|r| r.files.len() + r.history.len())
                    .sum(),
            );
        }
    }

    /// A process was created by `parent`. Remembered so a tool it later runs
    /// can be tied back to the run, and the pid starts clean.
    pub fn forked(&mut self, pid: u32, parent: u32) {
        self.started(pid);
        if self.parents.len() >= MAX_PROCESSES * 4 {
            self.parents.clear();
        }
        self.parents.insert(pid, parent);
    }

    /// A process ran `program`. When it is an encryption tool, record it
    /// against its parent, which is the process that reads and sends.
    pub fn exec(&mut self, pid: u32, program: &str) {
        self.started(pid);
        if let Some(tool) = crypto_tool(program) {
            let owner = self.parents.get(&pid).copied().unwrap_or(pid);
            if self.tools_by_parent.len() < MAX_PROCESSES * 4 {
                self.tools_by_parent.entry(owner).or_default().insert(tool);
            }
        }
    }

    /// The encryption tools any of `actors` ran a child to perform.
    #[must_use]
    pub fn tools_for(&self, actors: &BTreeSet<u32>) -> Vec<String> {
        let mut names: BTreeSet<String> = BTreeSet::new();
        for pid in actors {
            if let Some(tools) = self.tools_by_parent.get(pid) {
                names.extend(tools.iter().cloned());
            }
        }
        names.into_iter().collect()
    }

    fn process(&mut self, event: &SyscallEvent, at: u64) -> &mut Process {
        if !self.processes.contains_key(&event.pid) && self.processes.len() >= MAX_PROCESSES {
            self.forget_quietest();
        }
        let process = self.processes.entry(event.pid).or_insert_with(|| Process {
            name: event.comm.clone(),
            first_at: at,
            ..Process::default()
        });
        process.first_at = process.first_at.min(at);
        process.last_at = process.last_at.max(at);
        process
    }

    fn forget_quietest(&mut self) {
        // Processes that read no workspace go first: a reader waiting to
        // upload is the quietest of all, and the one worth keeping.
        let Some(pid) = self
            .processes
            .iter()
            .min_by_key(|(_, p)| (p.read_workspace(), p.last_at))
            .map(|(pid, _)| *pid)
        else {
            return;
        };
        if let Some(old) = self.processes.remove(&pid) {
            self.distinct = self.distinct.saturating_sub(
                old.roots
                    .values()
                    .map(|r| r.files.len() + r.history.len())
                    .sum(),
            );
        }
        self.forgotten = self.forgotten.saturating_add(1);
    }

    fn read(&mut self, event: &SyscallEvent, at: u64) {
        if !event.success || !read_only(event) {
            return;
        }
        let Some(path) = event.paths.first().map(|p| p.name.as_str()) else {
            return;
        };
        // A key or credential matters wherever it lives, and the ones that
        // matter most (`~/.ssh`, `~/.aws`) are outside any workspace.
        if path.starts_with('/')
            && !SYSTEM.iter().any(|p| path.starts_with(p))
            && let Some(class) = crate::sensitive::classify(path)
        {
            let process = self.process(event, at);
            if process.sensitive.len() < SENSITIVE_READS
                && !process.sensitive.iter().any(|(seen, _, _, _)| seen == path)
            {
                let size = std::fs::metadata(path).map_or(0, |m| m.len());
                process
                    .sensitive
                    .push((path.to_owned(), at, size, class.to_owned()));
            }
        }
        if !workspace_path(path) {
            return;
        }
        let (root, history) = self.root_of(path, event.cwd.as_deref());
        let child = path
            .get(root.len()..)
            .and_then(|rest| rest.strip_prefix('/'))
            .and_then(|rest| rest.split_once('/'))
            .map(|(dir, _)| dir.to_owned());
        let key = hash(path);
        let has_space = self.distinct < MAX_DISTINCT;
        let process = self.process(event, at);
        if !process.roots.contains_key(&root) && process.roots.len() >= MAX_ROOTS {
            return;
        }
        let entry = process.roots.entry(root).or_insert_with(|| Root {
            first_at: at,
            ..Root::default()
        });
        entry.first_at = entry.first_at.min(at);
        entry.last_at = entry.last_at.max(at);
        let set = if history {
            &mut entry.history
        } else {
            &mut entry.files
        };
        let added = if has_space {
            set.insert(key)
        } else {
            if !set.contains(&key) {
                entry.uncounted = entry.uncounted.saturating_add(1);
            }
            false
        };
        if added {
            if let Some(child) = child
                && (entry.children.len() < MAX_CHILDREN || entry.children.contains_key(&child))
            {
                *entry.children.entry(child).or_default() += 1;
            }
            // One stat per distinct file, never per read.
            match std::fs::metadata(path) {
                Ok(meta) if meta.is_file() => {
                    entry.read_bytes = entry.read_bytes.saturating_add(meta.len());
                }
                _ => entry.unsized_files = entry.unsized_files.saturating_add(1),
            }
            if process.recent.len() >= RECENT_READS {
                process.recent.pop_front();
            }
            process.recent.push_back((path.to_owned(), at));
            self.distinct += 1;
        }
    }

    /// Counts a delete, rename or truncating rewrite of a file this process
    /// read before, on that file's root. Files it never read, and anything
    /// under `.git` (which renames its own lock files all day), are left out.
    fn change(&mut self, event: &SyscallEvent, at: u64) {
        use super::changes::{Change, classify};
        let Some(change) = classify(event) else {
            return;
        };
        let path = match &change {
            Change::Deleted { path } | Change::Rewritten { path } => *path,
            Change::Renamed { from, .. } => *from,
        };
        if !workspace_path(path) || !self.processes.contains_key(&event.pid) {
            return;
        }
        let (root, history) = self.root_of(path, event.cwd.as_deref());
        if history {
            return;
        }
        let key = hash(path);
        let Some(entry) = self
            .processes
            .get_mut(&event.pid)
            .and_then(|p| p.roots.get_mut(&root))
            .filter(|r| r.files.contains(&key))
        else {
            return;
        };
        match change {
            Change::Deleted { .. } => entry.changes.deleted(key, at),
            Change::Renamed { from, to } => entry.changes.renamed(key, from, to, at),
            Change::Rewritten { .. } => entry.changes.rewritten(key),
        }
    }

    /// The workspace root a read falls under, and whether it is under that
    /// root's `.git`.
    fn root_of(&mut self, path: &str, cwd: Option<&str>) -> (String, bool) {
        if let Some((root, _)) = path.split_once("/.git/") {
            return (root.to_owned(), true);
        }
        let dir = path.rsplit_once('/').map_or("/", |(dir, _)| dir);
        if let Some(Some(root)) = self.roots.get(dir) {
            return (root.clone(), false);
        }
        let found = repository(dir);
        if self.roots.len() >= MAX_ROOT_CACHE {
            self.roots.clear();
        }
        self.roots.insert(dir.to_owned(), found.clone());
        if let Some(root) = found {
            return (root, false);
        }
        if let Some(cwd) = cwd.filter(|c| *c != "/" && home_of(c) != Some(c))
            && path.starts_with(cwd)
            && path.as_bytes().get(cwd.len()) == Some(&b'/')
        {
            return (cwd.to_owned(), false);
        }
        (two_below(path), false)
    }

    fn connect(&mut self, event: &SyscallEvent, at: u64) {
        let Some(fd) = event.args.first().copied().flatten() else {
            return;
        };
        let Some(dest) = remote(event) else {
            // A local peer: later writes on this descriptor go nowhere new.
            if internet_socket(event) {
                let process = self.process(event, at);
                if process.descriptors.len() < MAX_PER_PROCESS {
                    process.descriptors.insert(fd, None);
                }
            }
            return;
        };
        let ret = event.exit.unwrap_or(-1);
        let process = self.process(event, at);
        if process.descriptors.len() < MAX_PER_PROCESS || process.descriptors.contains_key(&fd) {
            process.descriptors.insert(fd, Some(dest.clone()));
        }
        let Some(totals) = destination(process, dest, at) else {
            return;
        };
        totals.attempts = totals.attempts.saturating_add(1);
        match ret {
            0 => totals.connected = totals.connected.saturating_add(1),
            EINPROGRESS => totals.in_progress = totals.in_progress.saturating_add(1),
            _ => totals.failed = totals.failed.saturating_add(1),
        }
    }

    fn sent(&mut self, event: &SyscallEvent, at: u64) {
        let Some(bytes) = event
            .exit
            .and_then(|r| u64::try_from(r).ok())
            .filter(|b| *b > 0)
        else {
            return;
        };
        // A datagram named its peer; anything else goes where its connect went.
        let named = event.sockaddr.as_ref().map(|_| remote(event));
        let fd = event.args.first().copied().flatten();
        if named == Some(None) {
            return; // loopback or local
        }
        let known = self
            .processes
            .get(&event.pid)
            .and_then(|p| fd.and_then(|fd| p.descriptors.get(&fd)).cloned());
        let dest = match (named.flatten(), known) {
            (Some(dest), _) | (None, Some(Some(dest))) => dest,
            // A stream socket whose connect this collector did not see.
            (None, None) if internet_socket(event) => (String::new(), 0),
            // A local peer, or not an internet socket.
            (None, Some(None) | None) => return,
        };
        let process = self.process(event, at);
        if let Some(totals) = destination(process, dest, at) {
            totals.sent(bytes, at);
        }
    }

    fn dup(&mut self, event: &SyscallEvent) {
        let (Some(old), Some(new)) = (
            event.args.first().copied().flatten(),
            event.exit.and_then(|r| u64::try_from(r).ok()),
        ) else {
            return;
        };
        if let Some(process) = self.processes.get_mut(&event.pid)
            && let Some(dest) = process.descriptors.get(&old).cloned()
            && process.descriptors.len() < MAX_PER_PROCESS
        {
            process.descriptors.insert(new, dest);
        }
    }

    /// Forgets processes quiet for [`QUIET_MS`] before `now`, and returns a
    /// copy of what is worth reporting.
    pub fn totals(&mut self, now: u64) -> Totals {
        let stale: Vec<u32> = self
            .processes
            .iter()
            .filter(|(_, p)| {
                let keep = if p.read_workspace() {
                    READER_QUIET_MS
                } else {
                    QUIET_MS
                };
                now.saturating_sub(p.last_at) > keep
            })
            .map(|(pid, _)| *pid)
            .collect();
        for pid in stale {
            if let Some(old) = self.processes.remove(&pid) {
                self.distinct = self.distinct.saturating_sub(
                    old.roots
                        .values()
                        .map(|r| r.files.len() + r.history.len())
                        .sum(),
                );
            }
        }
        let mut processes: Vec<ProcessTotals> = self
            .processes
            .iter()
            // A lone read of a key or a decoy matters too: `cat ~/.aws/credentials`
            // opens one file and connects nowhere.
            .filter(|(_, p)| {
                p.read_workspace() || !p.destinations.is_empty() || !p.sensitive.is_empty()
            })
            .map(|(pid, p)| summary(*pid, p))
            .collect();
        processes.sort_by_key(|p| (p.first_at, p.pid));
        Totals {
            processes,
            forgotten: self.forgotten,
            saturated: self.distinct >= MAX_DISTINCT,
        }
    }
}

impl Process {
    /// Whether it read at least [`REPORT_FILES`] distinct files under one root.
    fn read_workspace(&self) -> bool {
        self.roots
            .values()
            .any(|r| r.files.len() + r.history.len() >= REPORT_FILES as usize)
    }
}

fn summary(pid: u32, p: &Process) -> ProcessTotals {
    let mut roots: Vec<RootTotals> = p
        .roots
        .iter()
        .map(|(root, r)| {
            let mut top: Vec<(String, u32)> =
                r.children.iter().map(|(d, n)| (d.clone(), *n)).collect();
            top.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            top.truncate(5);
            RootTotals {
                root: root.clone(),
                files: u32::try_from(r.files.len() + r.history.len()).unwrap_or(u32::MAX),
                history_files: u32::try_from(r.history.len()).unwrap_or(u32::MAX),
                uncounted: r.uncounted,
                read_bytes: r.read_bytes,
                unsized_files: r.unsized_files,
                top,
                changes: r.changes.totals(),
                first_at: r.first_at,
                last_at: r.last_at,
            }
        })
        .collect();
    roots.sort_by(|a, b| b.files.cmp(&a.files).then_with(|| a.root.cmp(&b.root)));
    let mut destinations: Vec<DestTotals> = p
        .destinations
        .iter()
        .map(|((host, port), d)| DestTotals {
            host: host.clone(),
            port: *port,
            attempts: d.attempts,
            connected: d.connected,
            in_progress: d.in_progress,
            failed: d.failed,
            bytes: d.bytes,
            burst_bytes: d.burst_bytes,
            burst_at: d.burst_at,
            minutes: d.minutes.iter().copied().collect(),
            first_at: d.first_at,
            last_at: d.last_at,
        })
        .collect();
    destinations.sort_by(|a, b| {
        b.bytes
            .cmp(&a.bytes)
            .then_with(|| b.attempts.cmp(&a.attempts))
            .then_with(|| a.host.cmp(&b.host))
    });
    ProcessTotals {
        pid,
        name: p.name.clone(),
        first_at: p.first_at,
        last_at: p.last_at,
        ended: p.ended,
        roots,
        destinations,
        recent_reads: p.recent.iter().cloned().collect(),
        sensitive_reads: p.sensitive.clone(),
    }
}

fn destination(process: &mut Process, dest: (String, u16), at: u64) -> Option<&mut Dest> {
    if !process.destinations.contains_key(&dest) && process.destinations.len() >= MAX_PER_PROCESS {
        return None;
    }
    let totals = process.destinations.entry(dest).or_insert_with(|| Dest {
        first_at: at,
        ..Dest::default()
    });
    totals.first_at = totals.first_at.min(at);
    totals.last_at = totals.last_at.max(at);
    Some(totals)
}

/// An open for reading only: no write access, no create, no truncate. A
/// directory listing is not a file read.
fn read_only(event: &SyscallEvent) -> bool {
    const ACCESS: u64 = 0o3;
    const CREATE_OR_TRUNCATE: u64 = 0o100 | 0o1000;
    // O_DIRECTORY differs by architecture (include/uapi/asm-generic/fcntl.h
    // and arch/arm64/include/uapi/asm/fcntl.h).
    const DIRECTORY: u64 = if cfg!(target_arch = "aarch64") {
        0o40_000
    } else {
        0o200_000
    };
    let flags_at = match event.syscall {
        "open" => 1,
        "openat" => 2,
        // Its flags are inside a structure the record does not carry.
        _ => return false,
    };
    event
        .args
        .get(flags_at)
        .copied()
        .flatten()
        .is_some_and(|flags| flags & (ACCESS | CREATE_OR_TRUNCATE | DIRECTORY) == 0)
}

/// The non-loopback internet peer a call named.
fn remote(event: &SyscallEvent) -> Option<(String, u16)> {
    let addr = event.sockaddr.as_ref()?;
    if addr.family != 2 && addr.family != 10 {
        return None;
    }
    let ip: std::net::IpAddr = addr.host.parse().ok()?;
    let mapped_loopback = match ip {
        std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback()),
        std::net::IpAddr::V4(_) => false,
    };
    if ip.is_loopback() || ip.is_unspecified() || mapped_loopback {
        return None;
    }
    Some((addr.host.clone(), addr.port))
}

fn internet_socket(event: &SyscallEvent) -> bool {
    event
        .socket
        .is_some_and(|(domain, _, _)| domain == 2 || domain == 10)
}

/// The nearest directory at or above `dir` holding `.git`, stopping at a
/// home directory or the root. A read of a file is a read of the
/// repository it is in.
fn repository(dir: &str) -> Option<String> {
    let stop = home_of(dir);
    let mut at = Path::new(dir);
    loop {
        let text = at.to_str()?;
        if text == "/" || Some(text) == stop {
            return None;
        }
        if at.join(".git").exists() {
            return Some(text.to_owned());
        }
        at = at.parent()?;
    }
}

/// `/home/u/a/b` for anything under it; `/srv/x` for `/srv/x/...`.
fn two_below(path: &str) -> String {
    let (base, rest) = home_of(path).map_or(("", path), |home| {
        (home, path.get(home.len()..).unwrap_or(""))
    });
    let parts: Vec<&str> = rest.split('/').filter(|p| !p.is_empty()).collect();
    // Never the file itself.
    let keep = parts.len().saturating_sub(1).min(2);
    let mut root = base.to_owned();
    for part in parts.iter().take(keep) {
        root.push('/');
        root.push_str(part);
    }
    if root.is_empty() {
        "/".to_owned()
    } else {
        root
    }
}

fn tally() -> &'static Mutex<Tally> {
    static TALLY: std::sync::OnceLock<Mutex<Tally>> = std::sync::OnceLock::new();
    TALLY.get_or_init(|| Mutex::new(Tally::default()))
}

/// Adds one call from any source.
pub fn add(event: &SyscallEvent, at: u64) {
    tally()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .add(event, at);
}

/// A process ended.
pub fn exited(pid: u32) {
    tally()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .exited(pid);
}

/// A new process took `pid`.
pub fn started(pid: u32) {
    tally()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .started(pid);
}

/// A process was created by `parent`.
pub fn forked(pid: u32, parent: u32) {
    tally()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .forked(pid, parent);
}

/// A process ran `program`.
pub fn exec(pid: u32, program: &str) {
    tally()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .exec(pid, program);
}

/// The encryption tools `actors` ran.
#[must_use]
pub fn tools_for(actors: &std::collections::BTreeSet<u32>) -> Vec<String> {
    tally()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .tools_for(actors)
}

/// The totals as of `now`, in the start-time base.
#[must_use]
pub fn totals(now: u64) -> Totals {
    tally()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .totals(now)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::unwrap_used)]

    use super::*;
    use crate::audit_syscalls::{AuditPath, CallSource, SocketAddress};

    fn call(pid: u32, syscall: &'static str, ret: i64) -> SyscallEvent {
        SyscallEvent {
            source: CallSource::Ebpf,
            record: String::new(),
            at: 0,
            pid,
            ppid: None,
            syscall,
            success: ret >= 0,
            exit: Some(ret),
            args: [None; 4],
            uid: None,
            auid: None,
            tty: None,
            comm: Some("zcode".into()),
            exe: None,
            cwd: None,
            paths: Vec::new(),
            sockaddr: None,
            argv: Vec::new(),
            pid_namespace: None,
            socket: None,
            container: None,
            ancestors: Vec::new(),
            capabilities: None,
        }
    }

    fn open(pid: u32, path: &str, flags: u64) -> SyscallEvent {
        let mut event = call(pid, "openat", 3);
        event.args = [Some(u64::MAX - 99), Some(1), Some(flags), Some(0)];
        event.paths = vec![AuditPath {
            name: path.into(),
            raw: path.into(),
            nametype: "NORMAL".into(),
        }];
        event
    }

    fn connect(pid: u32, fd: u64, host: &str, ret: i64) -> SyscallEvent {
        let mut event = call(pid, "connect", ret);
        event.args = [Some(fd), Some(0), Some(16), None];
        event.sockaddr = Some(SocketAddress {
            family: 2,
            host: host.into(),
            port: 443,
        });
        event.socket = Some((2, 1, 6));
        event
    }

    fn write(pid: u32, fd: u64, bytes: i64) -> SyscallEvent {
        let mut event = call(pid, "write", bytes);
        event.args = [Some(fd), None, None, None];
        event.socket = Some((2, 1, 6));
        event
    }

    #[test]
    fn every_distinct_read_is_counted_however_many_there_are() {
        let mut tally = Tally::default();
        for n in 0..42_411 {
            tally.add(&open(7, &format!("/srv/acme/src/f{n}.rs"), 0), 1_000 + n);
        }
        for n in 0..100 {
            tally.add(&open(7, &format!("/srv/acme/.git/objects/{n}"), 0), 50_000);
        }
        // Reading the same file again is not another file.
        tally.add(&open(7, "/srv/acme/src/f0.rs", 0), 60_000);
        let totals = tally.totals(60_000);
        let root = &totals.processes[0].roots[0];
        assert_eq!(root.root, "/srv/acme");
        assert_eq!(root.files, 42_511);
        assert_eq!(root.history_files, 100);
        assert_eq!(root.top[0], ("src".to_owned(), 42_411));
    }

    #[test]
    fn writes_creates_directories_and_system_files_are_not_reads() {
        let mut tally = Tally::default();
        for n in 0..50 {
            tally.add(&open(7, &format!("/srv/acme/w{n}"), 0o1), 1);
            tally.add(&open(7, &format!("/srv/acme/c{n}"), 0o100), 1);
            tally.add(&open(7, &format!("/usr/lib/x{n}.so"), 0), 1);
            tally.add(&open(7, &format!("/home/u/.cache/x{n}"), 0), 1);
            tally.add(&open(7, &format!("/tmp/.mount_ZCode-ab/r{n}"), 0), 1);
        }
        let dir = if cfg!(target_arch = "aarch64") {
            0o40_000
        } else {
            0o200_000
        };
        for n in 0..50 {
            tally.add(&open(7, &format!("/srv/acme/d{n}"), dir), 1);
        }
        assert!(tally.totals(1).processes.is_empty());
    }

    #[test]
    fn attempts_and_bytes_are_kept_per_destination_and_loopback_is_not() {
        let mut tally = Tally::default();
        for n in 0..564 {
            tally.add(
                &connect(
                    7,
                    30,
                    "203.0.113.9",
                    if n % 2 == 0 { -111 } else { EINPROGRESS },
                ),
                n,
            );
            tally.add(&write(7, 30, 65_536), n);
        }
        tally.add(&connect(7, 31, "127.0.0.1", 0), 1);
        tally.add(&write(7, 31, 999), 1);
        let totals = tally.totals(600);
        let dest = &totals.processes[0].destinations;
        assert_eq!(dest.len(), 1, "{dest:?}");
        assert_eq!(dest[0].attempts, 564);
        assert_eq!((dest[0].failed, dest[0].in_progress), (282, 282));
        assert_eq!(dest[0].bytes, 564 * 65_536);
    }

    fn path_call(pid: u32, syscall: &'static str, paths: &[&str]) -> SyscallEvent {
        let mut event = call(pid, syscall, 0);
        event.args = [Some(u64::MAX - 99), None, Some(0), None];
        event.paths = paths
            .iter()
            .map(|p| AuditPath {
                name: (*p).into(),
                raw: (*p).into(),
                nametype: "NORMAL".into(),
            })
            .collect();
        event
    }

    #[test]
    fn only_files_it_read_count_as_destroyed_and_git_is_left_out() {
        let mut tally = Tally::default();
        for n in 0..60 {
            tally.add(&open(7, &format!("/srv/acme/src/f{n}.txt"), 0), 1_000);
        }
        // Encrypt-and-replace: rename 40 read files, delete 20 more.
        for n in 0..40 {
            let from = format!("/srv/acme/src/f{n}.txt");
            let to = format!("{from}.locked");
            tally.add(&path_call(7, "renameat2", &[&from, &to]), 2_000 + n);
        }
        for n in 40..60 {
            tally.add(
                &path_call(7, "unlink", &[&format!("/srv/acme/src/f{n}.txt")]),
                3_000,
            );
        }
        // Rewrites: O_WRONLY|O_TRUNC on 10 read files.
        for n in 0..10 {
            tally.add(
                &open(7, &format!("/srv/acme/src/f{n}.txt"), 0o1 | 0o1000),
                4_000,
            );
        }
        // Files it never read, and git's own lock-file renames.
        for n in 0..30 {
            tally.add(
                &path_call(7, "unlink", &[&format!("/srv/acme/build/o{n}")]),
                3_000,
            );
        }
        tally.add(
            &path_call(
                7,
                "rename",
                &["/srv/acme/.git/index.lock", "/srv/acme/.git/index"],
            ),
            3_000,
        );
        let totals = tally.totals(5_000);
        let c = &totals.processes[0].roots[0].changes;
        assert_eq!((c.renamed, c.deleted, c.rewritten), (40, 20, 10));
        assert_eq!(c.times.len(), 60);
        assert_eq!(c.suffixes, vec![(".locked".to_owned(), 40)]);
    }

    #[test]
    fn a_reader_that_waits_out_the_quiet_period_keeps_its_read() {
        let mut tally = Tally::default();
        // Reads a workspace, then goes silent.
        for n in 0..600 {
            tally.add(&open(7, &format!("/srv/acme/src/f{n}.rs"), 0), 1_000);
        }
        // A process that only connected, silent as long.
        tally.add(&connect(8, 30, "203.0.113.9", 0), 1_000);
        let later = 1_000 + QUIET_MS + 2 * 60_000;
        // It wakes after 32 minutes and uploads.
        tally.add(&connect(7, 31, "203.0.113.9", 0), later);
        tally.add(&write(7, 31, 733_334), later);
        let totals = tally.totals(later);
        let reader = totals.processes.iter().find(|p| p.pid == 7).unwrap();
        assert_eq!(reader.roots[0].files, 600, "the read survived the wait");
        assert_eq!(reader.destinations[0].bytes, 733_334);
        assert!(
            totals.processes.iter().all(|p| p.pid != 8),
            "non-reader forgotten"
        );
        // Past the reader's own limit it is forgotten too.
        let much_later = later + READER_QUIET_MS + 1;
        assert!(tally.totals(much_later).processes.is_empty());
    }

    #[test]
    fn under_pressure_a_quiet_reader_outlives_quiet_non_readers() {
        let mut tally = Tally::default();
        for n in 0..30 {
            tally.add(&open(7, &format!("/srv/acme/src/f{n}.rs"), 0), 1_000);
        }
        for pid in 0..u32::try_from(MAX_PROCESSES).unwrap() {
            tally.add(
                &connect(10_000 + pid, 30, "203.0.113.9", 0),
                2_000 + u64::from(pid),
            );
        }
        let totals = tally.totals(10_000);
        assert!(totals.forgotten > 0);
        assert!(totals.processes.iter().any(|p| p.pid == 7));
    }

    #[test]
    fn a_burst_is_the_most_sent_within_five_minutes_not_the_total() {
        let mut tally = Tally::default();
        tally.add(&connect(7, 30, "203.0.113.9", 0), 0);
        // A trickle: 100 KB a minute for 20 minutes.
        for minute in 0..20 {
            tally.add(&write(7, 30, 100_000), minute * 60_000);
        }
        // Then 2 MB within two minutes.
        tally.add(&write(7, 30, 1_000_000), 25 * 60_000);
        tally.add(&write(7, 30, 1_000_000), 26 * 60_000);
        let d = &tally.totals(26 * 60_000).processes[0].destinations[0];
        assert_eq!(d.bytes, 4_000_000);
        // The burst window covers minutes 22-26: the 2 MB, and none of the
        // trickle, which stopped at minute 19.
        assert_eq!(d.burst_bytes, 2_000_000);
        assert_eq!(d.burst_at, 26 * 60_000);
    }

    #[test]
    fn reads_keep_their_size_their_names_and_which_look_like_secrets() {
        // Test scratch space, named by pid; nothing security-relevant is written.
        // nosemgrep: rust.lang.security.temp-dir.temp-dir
        let dir = std::env::temp_dir().join(format!("tally-read-{}", std::process::id()));
        let src = dir.join("src");
        std::fs::create_dir_all(&src).unwrap();
        for n in 0..30 {
            std::fs::write(src.join(format!("f{n}.ts")), vec![b'x'; 1_000]).unwrap();
        }
        std::fs::write(dir.join(".env"), b"KEY=decoy").unwrap();
        let mut tally = Tally::default();
        for n in 0..30 {
            tally.add(
                &open(7, &format!("{}/f{n}.ts", src.display()), 0),
                1_000 + n,
            );
        }
        tally.add(&open(7, &format!("{}/.env", dir.display()), 0), 2_000);
        // A second read of the same file adds nothing.
        tally.add(&open(7, &format!("{}/f0.ts", src.display()), 0), 3_000);
        let p = &tally.totals(3_000).processes[0];
        let total: u64 = p.roots.iter().map(|r| r.read_bytes).sum();
        assert_eq!(total, 30 * 1_000 + 9);
        assert_eq!(p.recent_reads.len(), 31);
        assert!(p.recent_reads.last().unwrap().0.ends_with("/.env"));
        assert_eq!(p.sensitive_reads.len(), 1);
        // Sized when read: "KEY=decoy" is nine bytes.
        assert_eq!(p.sensitive_reads[0].2, 9);
        assert_eq!(p.roots.iter().map(|r| r.unsized_files).sum::<u32>(), 0);
        // A key outside any workspace is still named, once.
        tally.add(&open(7, "/home/u/.ssh/id_ed25519", 0), 4_000);
        tally.add(&open(7, "/home/u/.ssh/id_ed25519", 0), 4_100);
        // A path that does not resolve here is counted, not sized.
        tally.add(&open(7, &format!("{}/gone.ts", src.display()), 0), 4_200);
        let p = &tally.totals(4_200).processes[0];
        assert_eq!(p.sensitive_reads.len(), 2, "{:?}", p.sensitive_reads);
        assert!(
            p.sensitive_reads
                .iter()
                .any(|(s, _, _, _)| s.ends_with("/.ssh/id_ed25519"))
        );
        assert_eq!(p.roots.iter().map(|r| r.unsized_files).sum::<u32>(), 1);
        let _ = std::fs::remove_dir_all(&dir);
        for (path, yes) in [
            ("/w/.env", true),
            ("/w/.env.local", true),
            ("/h/.ssh/id_ed25519", true),
            ("/w/certs/server.key", true),
            ("/w/config", false),
            ("/w/src/env.ts", false),
            ("/w/keyboard.ts", false),
            ("/h/.aws/credentials", true),
            ("/h/.kube/config", true),
            (
                "/w/venv/lib/python3.12/site-packages/certifi/cacert.pem",
                false,
            ),
            ("/w/node_modules/x/test/key.pem", false),
            ("/w/certs/ca-bundle.pem", false),
        ] {
            assert_eq!(crate::sensitive::classify(path).is_some(), yes, "{path}");
        }
    }

    #[test]
    fn a_write_on_a_socket_whose_connect_was_not_seen_is_kept_as_unknown() {
        let mut tally = Tally::default();
        tally.add(&write(7, 9, 4_096), 1);
        let totals = tally.totals(1);
        assert_eq!(totals.processes[0].destinations[0].host, "");
        assert_eq!(totals.processes[0].destinations[0].bytes, 4_096);
    }

    #[test]
    fn a_reused_pid_starts_its_own_totals_and_quiet_ones_are_forgotten() {
        let mut tally = Tally::default();
        tally.add(&connect(7, 3, "203.0.113.9", 0), 10);
        tally.exited(7);
        tally.add(&connect(7, 3, "198.51.100.1", 0), 20);
        let totals = tally.totals(20);
        assert_eq!(totals.processes.len(), 1);
        assert_eq!(totals.processes[0].destinations[0].host, "198.51.100.1");
        assert!(tally.totals(20 + QUIET_MS + 1).processes.is_empty());
    }

    #[test]
    fn malformed_calls_are_ignored() {
        let mut tally = Tally::default();
        let mut no_path = call(7, "openat", 3);
        no_path.args = [None, None, Some(0), None];
        tally.add(&no_path, 1);
        let mut failed = open(7, "/srv/a/x", 0);
        failed.success = false;
        tally.add(&failed, 1);
        let mut relative = open(7, "x", 0);
        relative.paths[0].name = "x".into();
        tally.add(&relative, 1);
        let mut bad = connect(7, 3, "not-an-ip", 0);
        bad.sockaddr.as_mut().unwrap().family = 1;
        tally.add(&bad, 1);
        tally.add(&write(7, 3, -9), 1);
        assert!(tally.totals(1).processes.is_empty());
    }

    #[test]
    fn an_encryption_tool_is_tied_to_the_parent_that_ran_it() {
        let mut tally = Tally::default();
        tally.forked(400, 101); // agent 101 forks 400
        tally.exec(400, "/usr/bin/openssl"); // 400 execs openssl
        tally.forked(401, 101);
        tally.exec(401, "/usr/bin/cat"); // not a crypto tool
        let actors: BTreeSet<u32> = [101u32].into_iter().collect();
        assert_eq!(tally.tools_for(&actors), vec!["openssl".to_owned()]);
        let others: BTreeSet<u32> = [999u32].into_iter().collect();
        assert!(tally.tools_for(&others).is_empty());
    }

    #[test]
    fn roots_fall_back_to_the_working_directory_then_two_below_home() {
        assert_eq!(two_below("/home/u/work/acme/src/a.rs"), "/home/u/work/acme");
        assert_eq!(two_below("/home/u/notes.txt"), "/home/u");
        assert_eq!(two_below("/srv/x/y/z"), "/srv/x");
        let mut tally = Tally::default();
        let (root, _) = tally.root_of("/nonexistent-ws/a/b/c.txt", Some("/nonexistent-ws"));
        assert_eq!(root, "/nonexistent-ws");
        let (root, history) = tally.root_of("/x/repo/.git/HEAD", None);
        assert_eq!((root.as_str(), history), ("/x/repo", true));
    }
}
