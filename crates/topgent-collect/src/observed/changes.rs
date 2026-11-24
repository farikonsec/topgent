//! What a process did to files it had read: deleted them, renamed them away,
//! or rewrote them in place.
//!
//! Ransomware reads a file before it encrypts it, then replaces it: writes a
//! new copy and deletes the original, or rewrites it and renames it. Bulk
//! clean-ups (`rm -rf node_modules`, `cargo clean`, `git checkout`) delete
//! without reading the contents first. So a change counts here only when the
//! same process read that file earlier, which the tally already knows by path.
//!
//! This counts. It decides nothing: the report's rule holds the thresholds.

use std::collections::{BTreeMap, HashSet};

use crate::audit_syscalls::SyscallEvent;

/// Most distinct files counted per root for each kind of change.
const MAX_CHANGED: usize = 8_192;
/// Most change times kept per root, oldest dropped first: enough to find the
/// densest few minutes of a large run.
const MAX_TIMES: usize = 4_096;
/// Most distinct new suffixes kept per root.
const MAX_SUFFIXES: usize = 16;

/// One change, as the tally classifies a call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Change<'a> {
    /// `unlink`/`unlinkat` of `path`.
    Deleted { path: &'a str },
    /// `rename*` of `from` to `to`.
    Renamed { from: &'a str, to: &'a str },
    /// An open for writing with truncation of `path`.
    Rewritten { path: &'a str },
}

/// The change a successful call made, if it is one this counts.
pub(crate) fn classify(event: &SyscallEvent) -> Option<Change<'_>> {
    if !event.success {
        return None;
    }
    let first = event.paths.first().map(|p| p.name.as_str());
    match event.syscall {
        "unlink" | "unlinkat" => {
            // `unlinkat` with AT_REMOVEDIR removes a directory, not a file.
            const AT_REMOVEDIR: u64 = 0x200;
            let removes_dir = event.syscall == "unlinkat"
                && event
                    .args
                    .get(2)
                    .copied()
                    .flatten()
                    .is_some_and(|f| f & AT_REMOVEDIR != 0);
            (!removes_dir).then_some(Change::Deleted { path: first? })
        }
        "rename" | "renameat" | "renameat2" => Some(Change::Renamed {
            from: first?,
            to: event.paths.get(1).map(|p| p.name.as_str())?,
        }),
        "open" | "openat" => {
            const WRITE: u64 = 0o1 | 0o2;
            const TRUNCATE: u64 = 0o1000;
            let flags_at = if event.syscall == "open" { 1 } else { 2 };
            let flags = event.args.get(flags_at).copied().flatten()?;
            (flags & WRITE != 0 && flags & TRUNCATE != 0)
                .then_some(Change::Rewritten { path: first? })
        }
        _ => None,
    }
}

/// The new suffix a rename gave a file, when it changed: `.locked` for
/// `a.txt` → `a.txt.locked`, `.enc` for `a.txt` → `a.enc`.
fn new_suffix(from: &str, to: &str) -> Option<String> {
    let name = |p: &str| p.rsplit('/').next().unwrap_or(p).to_owned();
    let (from, to) = (name(from), name(to));
    // Same name, or a name with something taken off (`.a.txt.swp` → `a.txt`):
    // nothing was added.
    if from == to || from.contains(to.as_str()) {
        return None;
    }
    if let Some(added) = to.strip_prefix(from.as_str()) {
        return (!added.is_empty()).then(|| added.to_owned());
    }
    let ext = |n: &str| n.rsplit_once('.').map(|(_, e)| format!(".{e}"));
    let (a, b) = (ext(&from), ext(&to));
    (b.is_some() && a != b).then_some(b).flatten()
}

/// Changes to read files under one root, as counters.
#[derive(Debug, Default)]
pub(crate) struct Changes {
    deleted: HashSet<u64>,
    renamed: HashSet<u64>,
    rewritten: HashSet<u64>,
    /// When each destroying change (delete or rename away) happened.
    times: std::collections::VecDeque<u64>,
    suffixes: BTreeMap<String, u32>,
}

impl Changes {
    /// Records a delete of a read file, keyed by `key` (the path's hash).
    pub(crate) fn deleted(&mut self, key: u64, at: u64) {
        if self.deleted.len() < MAX_CHANGED && self.deleted.insert(key) {
            self.at(at);
        }
    }

    /// Records a read file renamed from `from` to `to`.
    pub(crate) fn renamed(&mut self, key: u64, from: &str, to: &str, at: u64) {
        if self.renamed.len() < MAX_CHANGED && self.renamed.insert(key) {
            self.at(at);
            if let Some(suffix) = new_suffix(from, to)
                && (self.suffixes.len() < MAX_SUFFIXES || self.suffixes.contains_key(&suffix))
            {
                *self.suffixes.entry(suffix).or_default() += 1;
            }
        }
    }

    /// Records a read file reopened for writing with truncation.
    pub(crate) fn rewritten(&mut self, key: u64) {
        if self.rewritten.len() < MAX_CHANGED {
            self.rewritten.insert(key);
        }
    }

    fn at(&mut self, at: u64) {
        if self.times.len() >= MAX_TIMES {
            self.times.pop_front();
        }
        self.times.push_back(at);
    }

    /// The counts, for a sweep.
    pub(crate) fn totals(&self) -> ChangeTotals {
        let mut suffixes: Vec<(String, u32)> =
            self.suffixes.iter().map(|(s, n)| (s.clone(), *n)).collect();
        suffixes.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let mut times: Vec<u64> = self.times.iter().copied().collect();
        times.sort_unstable();
        ChangeTotals {
            deleted: u32::try_from(self.deleted.len()).unwrap_or(u32::MAX),
            renamed: u32::try_from(self.renamed.len()).unwrap_or(u32::MAX),
            rewritten: u32::try_from(self.rewritten.len()).unwrap_or(u32::MAX),
            times,
            suffixes,
        }
    }
}

/// What one process did to files it had read under one root.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangeTotals {
    /// Distinct read files it deleted.
    pub deleted: u32,
    /// Distinct read files it renamed to another name.
    pub renamed: u32,
    /// Distinct read files it reopened for writing with truncation.
    pub rewritten: u32,
    /// When each delete or rename happened, oldest first, in the start-time
    /// base. Bounded: the most recent are kept.
    pub times: Vec<u64>,
    /// New suffixes renames gave files, most common first: `(".locked", 200)`.
    pub suffixes: Vec<(String, u32)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffixes_read_the_way_ransomware_renames() {
        assert_eq!(
            new_suffix("/r/a.txt", "/r/a.txt.locked").as_deref(),
            Some(".locked")
        );
        assert_eq!(new_suffix("/r/a.txt", "/r/a.enc").as_deref(), Some(".enc"));
        assert_eq!(new_suffix("/r/.a.txt.swp", "/r/a.txt"), None);
        assert_eq!(new_suffix("/r/a.txt", "/r/b.txt"), None);
        assert_eq!(new_suffix("/r/a.txt", "/old/a.txt"), None);
    }

    #[test]
    fn each_file_counts_once_and_times_stay_bounded() {
        let mut c = Changes::default();
        for n in 0..(MAX_TIMES as u64 + 10) {
            c.deleted(n, n);
            c.deleted(n, n + 1);
        }
        let t = c.totals();
        assert_eq!(t.deleted as usize, MAX_TIMES + 10);
        assert_eq!(t.times.len(), MAX_TIMES);
        assert_eq!(t.times.first(), Some(&10));
    }
}
