//! Which container a cgroup id names.
//!
//! The probe stamps every event with the kernel's cgroup id, which on
//! cgroup v2 is the inode of the cgroup's directory under `/sys/fs/cgroup`.
//! A container runtime puts the container's full id in that directory's
//! name (`docker-<64 hex>.scope`, `/docker/<64 hex>`), so the id names the
//! container without reading any kernel structure. Read at the moment of
//! the event, it holds for a process that is gone before a sweep could read
//! its `/proc/<pid>/cgroup`.

use std::collections::HashMap;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::time::{Duration, Instant};

use topgent_collect::container::container_id_from_cgroup;

const ROOT: &str = "/sys/fs/cgroup";
/// The least time between two walks of the tree: an id no walk has seen is
/// usually a cgroup made since the last one, but a flood of them must not
/// turn into a flood of walks.
const RESCAN: Duration = Duration::from_millis(250);
/// Deepest and most directories one walk visits.
const MAX_DEPTH: usize = 16;
const MAX_DIRS: usize = 50_000;

/// Cgroup ids and the container each is, from the last walk of the tree.
#[derive(Default)]
pub(crate) struct Cgroups {
    /// `None` for a cgroup that is no container.
    known: HashMap<u64, Option<String>>,
    walked: Option<Instant>,
}

impl Cgroups {
    /// The full container id `cgroup` names, if it is a container's.
    pub(crate) fn container(&mut self, cgroup: u64) -> Option<String> {
        if cgroup == 0 {
            return None;
        }
        if !self.known.contains_key(&cgroup) && self.walked.is_none_or(|at| at.elapsed() >= RESCAN)
        {
            self.walked = Some(Instant::now());
            self.known = walk(Path::new(ROOT));
        }
        self.known.get(&cgroup).cloned().flatten()
    }
}

/// Every cgroup directory under `root`, by inode, with the container its
/// path names. Replaces the last walk whole, so a removed cgroup is not
/// kept to name a later one with a reused inode.
fn walk(root: &Path) -> HashMap<u64, Option<String>> {
    let mut found = HashMap::new();
    let mut pending = vec![(root.to_path_buf(), 0)];
    while let Some((dir, depth)) = pending.pop() {
        if found.len() >= MAX_DIRS {
            break;
        }
        let Ok(meta) = std::fs::symlink_metadata(&dir) else {
            continue;
        };
        found.insert(meta.ino(), container_id_from_cgroup(&dir.to_string_lossy()));
        if depth >= MAX_DEPTH {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                pending.push((entry.path(), depth + 1));
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::os::unix::fs::MetadataExt as _;

    use super::walk;

    #[test]
    fn a_container_cgroup_is_named_by_its_directory_and_others_are_not() {
        // nosemgrep: rust.lang.security.temp-dir.temp-dir - test fixture, per-process name, created fresh below so an existing path fails the test instead of being followed
        let root = std::env::temp_dir().join(format!("topgent-cgroups-{}", std::process::id()));
        std::fs::create_dir(&root).expect("a fresh scratch directory");
        let id = "ab".repeat(32);
        let container = root.join("system.slice").join(format!("docker-{id}.scope"));
        let host = root.join("user.slice");
        std::fs::create_dir_all(&container).expect("a container directory");
        std::fs::create_dir_all(&host).expect("a host directory");
        let found = walk(&root);
        let ino = |p: &std::path::Path| std::fs::metadata(p).expect("stat").ino();
        assert_eq!(found.get(&ino(&container)).cloned().flatten(), Some(id));
        assert_eq!(found.get(&ino(&host)).cloned().flatten(), None);
        std::fs::remove_dir_all(&root).expect("clean up");
    }
}
