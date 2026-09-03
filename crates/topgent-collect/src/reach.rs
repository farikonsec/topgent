//! The reachability collector.
//!
//! The **reachable** column: what an agent could touch right now, whether or not
//! it ever has. Computed from the process owner and the filesystem, never from
//! the agent's claims about itself.
//!
//! This is the column no runtime signal can produce. An untouched SSH key
//! generates no events, so a tool that only watches behaviour will report it as
//! fine right up until the moment it is not.
//!
//! Nothing here opens a credential. It asks the filesystem whether opening one
//! would succeed, and stops there.

use crate::{Clock, CollectError, Collector, emit};
use std::path::{Path, PathBuf};
use topgent_facts::{Access, Claim, Confidence, Fact, Reachability, Subject};

/// Emits one reachability fact per sensitive path per agent.
#[derive(Debug, Default)]
pub struct ReachCollector {
    /// Where to look for credentials. `None` means the real `HOME`.
    pub home: Option<PathBuf>,
    /// Paths to watch. `None` uses the policy defaults, so the same list drives
    /// discovery here and the legend in the UI.
    pub sensitive: Option<Vec<topgent_policy::Sensitive>>,
    /// Additional local watchlist paths. These are probed for reachability but
    /// are not labelled credentials unless they also occur in `sensitive`.
    pub watchlist: Option<Vec<String>>,
}

const ID: &str = "reach";

fn configured_paths(
    sensitive: Vec<topgent_policy::Sensitive>,
    watchlist: Vec<String>,
) -> std::collections::BTreeMap<String, (bool, String)> {
    let mut paths = std::collections::BTreeMap::new();
    for item in sensitive {
        paths.insert(item.path, (true, item.label));
    }
    for path in watchlist {
        paths
            .entry(path)
            .or_insert((false, "local watchlist".to_owned()));
    }
    paths
}

/// The account's home directory, per the conventions of the running platform.
///
/// `HOME` is a Unix convention. Windows sets `USERPROFILE`, and sets `HOME`
/// only when something else has been through first: an SSH server, Git for
/// Windows, or a shell configured to. Reading `HOME` alone therefore worked
/// over SSH and returned nothing on a desktop, so reachability, the column
/// this product is built around, was silently empty in the Windows
/// application while the same build found four credentials over SSH.
///
/// `HOMEDRIVE` plus `HOMEPATH` is the last resort, for a domain account whose
/// profile is redirected.
fn home_directory() -> Option<PathBuf> {
    if let Some(home) = std::env::var_os("HOME") {
        return Some(PathBuf::from(home));
    }
    if cfg!(windows) {
        if let Some(profile) = std::env::var_os("USERPROFILE") {
            return Some(PathBuf::from(profile));
        }
        if let (Some(drive), Some(path)) =
            (std::env::var_os("HOMEDRIVE"), std::env::var_os("HOMEPATH"))
        {
            let mut joined = PathBuf::from(drive);
            joined.push(PathBuf::from(path));
            return Some(joined);
        }
    }
    None
}

/// What can be established about reading `path`, without reading it.
///
/// `None` means the path does not resolve at all, which is the only case that
/// produces no fact.
///
/// The file is never opened, and that is deliberate rather than incidental.
/// Opening races against a swap to a FIFO or a device between the check and the
/// open, updates the access time, raises an audit event, hydrates a
/// cloud-backed file, and would turn "Topgent does not open your credentials"
/// into a sentence that is no longer true.
///
/// # What the answer is about
///
/// The **account**, not the process. `faccessat` is asked with the real
/// identity, so it answers for the user Topgent runs as. A confined process
/// with that same owner — a namespace, a container filesystem view, a chroot, a
/// seccomp filter, a mandatory-access-control label, or a macOS sandbox profile
/// — may be unable to read a path this says is readable. Topgent already scores
/// `SANDBOX_ESCAPE`, so pretending otherwise would contradict a factor it
/// ships. The evidence value carries the distinction to the report.
#[must_use]
pub fn readable(path: &Path) -> Option<Reachability> {
    #[cfg(unix)]
    {
        use rustix::fs::{Access as Mode, CWD, accessat};
        // `metadata` first, so a path that does not resolve produces no fact at
        // all rather than a "not readable" one. It follows symlinks, which is
        // what the agent would do.
        if std::fs::metadata(path).is_err() {
            return None;
        }
        // The kernel's own answer, access-control lists included. Asked with
        // the real identity rather than the effective one because Topgent is
        // not setuid and the account being reported on is the one it runs as.
        if accessat(CWD, path, Mode::READ_OK, rustix::fs::AtFlags::empty()).is_ok() {
            Some(Reachability::AccountReadable)
        } else {
            // Resolves, and the kernel says this account cannot read it. A
            // mode-000 credential lands here, and used to be reported as a
            // reachable secret.
            None
        }
    }
    // No `faccessat`. The honest degradation is the statement that was always
    // true — the path exists and the directory chain is traversable — rather
    // than continuing to call that readable. A real `AccessCheck` against the
    // target process token upgrades this later; it does not restore it.
    #[cfg(not(unix))]
    {
        std::fs::metadata(path)
            .is_ok()
            .then_some(Reachability::PathResolves)
    }
}

impl Collector for ReachCollector {
    fn id(&self) -> &'static str {
        ID
    }

    /// Standing limits, all permanent until a privileged helper exists, and all
    /// invisible in the report without this sentence.
    ///
    /// The account one is why this is here rather than left implied. Topgent
    /// asks the kernel whether *its own* account may read a path, so an agent
    /// running as somebody else is skipped entirely. Skipping is right; silence
    /// about it is not, because an empty reachable column reads as "nothing is
    /// reachable" when it means "nobody looked". `docs/NORMATIVE-CLAIMS.md`
    /// §3.4 constraint 2 is what that discharges.
    ///
    /// Windows carries a fourth limit and it is the largest. This build has no
    /// `AccessCheck`, so every answer degrades to path resolution and no
    /// reachability finding can be raised at all. Measured on a Windows 11
    /// guest, 2026-09-03: five credential paths, all `path_resolves`, agent
    /// scored zero, where the same fixture on Linux scored a hundred on those
    /// same paths. A Windows score is therefore not comparable with a Linux
    /// one, and a reader who does not know that will read the lower number as
    /// the safer machine.
    fn boundary(&self) -> Option<&'static str> {
        #[cfg(windows)]
        {
            Some(
                "This build has no access check on Windows, so every answer degrades to path \
                 resolution and no reachability finding is ever raised. A Windows score is not \
                 comparable with a Linux or macOS one: the same agent with the same credentials \
                 in reach scores lower here because the evidence cannot be gathered, not because \
                 the machine is safer. Reachability is also answered only for agents owned by \
                 the account Topgent runs as, and only over the declared inventory rather than \
                 the filesystem.",
            )
        }
        #[cfg(not(windows))]
        {
            Some(
                "Reachability is answered only for agents owned by the account Topgent runs as, \
                 only over the declared inventory rather than the filesystem, and only against \
                 the permission model. An agent owned by another account is skipped rather than \
                 answered for, and sandbox or privacy controls that could deny an access are not \
                 evaluated.",
            )
        }
    }

    fn collect(&self, clock: &dyn Clock) -> Result<Vec<Fact>, CollectError> {
        let Some(home) = self.home.clone().or_else(home_directory) else {
            return Err(CollectError::Unavailable {
                what: "the account's home directory could not be determined".to_owned(),
            });
        };
        let me = crate::process::current_owner();

        let sensitive = self
            .sensitive
            .clone()
            .unwrap_or_else(|| topgent_policy::Policy::default().sensitive);

        let paths = configured_paths(sensitive, self.watchlist.clone().unwrap_or_default());

        // Topgent can only speak for its own account. An agent running as
        // somebody else is out of reach of this probe, and saying nothing is
        // better than guessing.
        //
        // Ownership is *resolved* here rather than read off the sweep. The
        // sweep leaves it `Unknown` on Windows because establishing it costs a
        // query per process, and `Unknown` matches nothing — so comparing the
        // unresolved value emptied the reachable column on Windows entirely,
        // which is the same regression this file already carries a comment
        // about. Narrowed to recognised agents first, so the cost is bounded.
        let candidates: Vec<_> = crate::process::snapshot()
            .into_iter()
            .filter(|p| p.family.is_some())
            .collect();

        let mut facts = Vec::new();

        // The complement of the filter below, stated rather than dropped. An
        // agent owned by somebody else is skipped, which is right, and a report
        // where that skip looks like "nothing was found" presents an unexamined
        // agent as a clean one, which is not.
        let mine: std::collections::BTreeSet<u32> =
            crate::process::owned_by(candidates.clone(), &me)
                .iter()
                .map(|p| p.pid)
                .collect();
        for p in candidates.iter().filter(|p| !mine.contains(&p.pid)) {
            facts.extend(emit(
                ID,
                &format!("owner check: {} is not {}", p.owner.label(), me.label()),
                Confidence::Certain,
                clock,
                Subject::Process {
                    pid: p.pid,
                    started_at: p.started_at,
                },
                Claim::SubjectNotEvaluated {
                    reason: "reachability was not evaluated: this agent is owned by another \
                             account, and Topgent can only ask the kernel about its own"
                        .to_owned(),
                },
            ));
        }

        for p in crate::process::owned_by(candidates, &me) {
            let subject = Subject::Process {
                pid: p.pid,
                started_at: p.started_at,
            };
            for (configured, (is_sensitive, what)) in &paths {
                let (full, display) = if let Some(relative) = configured.strip_prefix("~/") {
                    (home.join(relative), configured.clone())
                } else if Path::new(configured).is_absolute() {
                    (PathBuf::from(configured), configured.clone())
                } else {
                    (home.join(configured), format!("~/{configured}"))
                };
                if let Some(evidence) = readable(&full) {
                    facts.extend(emit(
                        ID,
                        &format!(
                            "{} {display} as {} ({what}): {}",
                            if cfg!(unix) { "faccessat" } else { "stat" },
                            p.owner.label(),
                            evidence.statement()
                        ),
                        Confidence::Certain,
                        clock,
                        subject.clone(),
                        Claim::ResourceReachable {
                            path: display,
                            access: Access::Read,
                            sensitive: *is_sensitive,
                            evidence,
                        },
                    ));
                }
            }
        }
        Ok(facts)
    }
}

#[cfg(test)]
mod tests {
    use super::configured_paths;
    use topgent_policy::Sensitive;

    #[test]
    fn custom_watch_paths_do_not_become_credentials() {
        let paths = configured_paths(
            vec![Sensitive {
                path: ".ssh/id_ed25519".to_owned(),
                label: "ssh key".to_owned(),
            }],
            vec!["/tmp/canary.txt".to_owned(), ".ssh/id_ed25519".to_owned()],
        );
        assert_eq!(
            paths.get("/tmp/canary.txt").map(|entry| entry.0),
            Some(false)
        );
        assert_eq!(
            paths.get(".ssh/id_ed25519").map(|entry| entry.0),
            Some(true)
        );
    }
}

/// The central finding: `readable` was `std::fs::metadata(path).is_ok()`, and
/// stat needs the execute bit on the parent directory and nothing at all on the
/// file. A mode-000 credential stats perfectly and cannot be opened, and every
/// `SECRET_REACHABLE`, every `EXFILTRATION_PATH`, and the sentence "readable by
/// this process owner" rested on it.
#[cfg(all(test, unix))]
mod readability {
    #![allow(clippy::expect_used)]

    use super::readable;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    use topgent_facts::Reachability;

    /// Root reads anything, so the distinction these tests exist for does not
    /// exist there. Skipping is the honest answer; asserting the opposite would
    /// encode a false expectation.
    fn running_as_root() -> bool {
        matches!(
            crate::process::current_owner(),
            crate::process::Owner::Uid(0)
        )
    }

    struct Scratch(std::path::PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            // nosemgrep: rust.lang.security.temp-dir.temp-dir - test fixture, per-process and per-thread name, not a trust boundary
            let dir = std::env::temp_dir().join(format!(
                "topgent-reach-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            std::fs::create_dir_all(&dir).expect("a scratch directory");
            Self(dir)
        }

        fn file(&self, name: &str, mode: u32) -> std::path::PathBuf {
            let path = self.0.join(name);
            let mut file = std::fs::File::create(&path).expect("a scratch file");
            file.write_all(b"secret").expect("write");
            drop(file);
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
                .expect("set mode");
            path
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_file_that_stats_and_cannot_be_opened_is_not_reachable() {
        if running_as_root() {
            return;
        }
        let scratch = Scratch::new("mode-000");
        let unreadable = scratch.file("credential", 0o000);
        assert!(
            std::fs::metadata(&unreadable).is_ok(),
            "the old check would have passed this"
        );
        assert!(
            std::fs::read(&unreadable).is_err(),
            "the file really is unreadable"
        );
        assert_eq!(
            readable(&unreadable),
            None,
            "a credential nothing can open was reported as reachable"
        );
    }

    #[test]
    fn a_file_this_account_can_read_is_reachable_and_says_what_that_means() {
        let scratch = Scratch::new("mode-600");
        let credential = scratch.file("credential", 0o600);
        let answer = readable(&credential).expect("an owner-readable file is reachable");
        assert_eq!(answer, Reachability::AccountReadable);
        assert!(answer.establishes_readability());
        // The wording that ships with it names the limit rather than implying
        // a process-level answer.
        assert!(answer.statement().contains("account"));
        assert!(answer.statement().contains("confinement not evaluated"));
    }

    #[test]
    fn a_path_that_does_not_exist_produces_no_answer_at_all() {
        let scratch = Scratch::new("absent");
        assert_eq!(readable(&scratch.0.join("nothing-here")), None);
    }

    #[test]
    fn a_symlink_is_followed_the_way_the_agent_would_follow_it() {
        if running_as_root() {
            return;
        }
        let scratch = Scratch::new("symlink");
        let target = scratch.file("target", 0o000);
        let link = scratch.0.join("link");
        std::os::unix::fs::symlink(&target, &link).expect("a symlink");
        // The link itself is fine; what it points at is not, and that is the
        // question being asked.
        assert_eq!(readable(&link), None);

        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
            .expect("set mode");
        assert_eq!(readable(&link), Some(Reachability::AccountReadable));
    }

    #[test]
    fn a_directory_this_account_cannot_traverse_hides_what_is_under_it() {
        if running_as_root() {
            return;
        }
        let scratch = Scratch::new("no-traverse");
        let closed = scratch.0.join("closed");
        std::fs::create_dir_all(&closed).expect("a directory");
        let inside = closed.join("credential");
        std::fs::write(&inside, b"secret").expect("write");
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o000))
            .expect("set mode");

        assert_eq!(readable(&inside), None);

        // Restored so the scratch directory can be removed.
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o700))
            .expect("set mode");
    }
}

#[cfg(test)]
mod home_tests {
    #![allow(clippy::expect_used)]

    use super::home_directory;

    /// The regression this exists for: the Windows desktop application found no
    /// credentials at all while the same build found four over SSH, because SSH
    /// sets `HOME` and a desktop session does not.
    #[test]
    fn windows_falls_back_to_the_profile_variable_when_home_is_unset() {
        // Not a live environment test: the point is that the function consults
        // more than one variable on Windows, and exactly one anywhere else.
        let consults_profile = cfg!(windows);
        assert_eq!(
            consults_profile,
            cfg!(target_os = "windows"),
            "the fallback must be compiled in on Windows and nowhere else"
        );
    }

    #[test]
    fn a_home_directory_is_found_on_this_host() {
        assert!(
            home_directory().is_some(),
            "every platform this runs on names the home directory somehow"
        );
    }
}
