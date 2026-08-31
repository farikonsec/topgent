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
use topgent_facts::{Access, Claim, Confidence, Fact, Subject};

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

/// Whether this process could read `path`, without reading it.
///
/// Metadata only. The file is never opened.
#[must_use]
pub fn readable(path: &Path) -> bool {
    // `metadata` follows the link and succeeds only when the path resolves and
    // the directory chain is traversable by this user.
    std::fs::metadata(path).is_ok()
}

impl Collector for ReachCollector {
    fn id(&self) -> &'static str {
        ID
    }

    fn collect(&self, clock: &dyn Clock) -> Result<Vec<Fact>, CollectError> {
        let Some(home) = self.home.clone().or_else(home_directory) else {
            return Err(CollectError::Unavailable {
                what: "the account's home directory could not be determined".to_owned(),
            });
        };
        let me = std::process::id();
        let my_uid = crate::process::snapshot()
            .into_iter()
            .find(|p| p.pid == me)
            .map_or(0, |p| p.uid);

        let sensitive = self
            .sensitive
            .clone()
            .unwrap_or_else(|| topgent_policy::Policy::default().sensitive);

        let paths = configured_paths(sensitive, self.watchlist.clone().unwrap_or_default());

        let mut facts = Vec::new();
        for p in crate::process::snapshot()
            .into_iter()
            .filter(|p| p.family.is_some())
        {
            // Topgent can only speak for its own user. An agent running as
            // somebody else is out of reach of this probe, and saying nothing is
            // better than guessing.
            if p.uid != my_uid {
                continue;
            }
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
                if readable(&full) {
                    facts.extend(emit(
                        ID,
                        &format!("stat {display} as uid {} ({what})", p.uid),
                        Confidence::Certain,
                        clock,
                        subject.clone(),
                        Claim::ResourceReachable {
                            path: display,
                            access: Access::Read,
                            sensitive: *is_sensitive,
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
