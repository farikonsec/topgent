//! Telling a destination apart: the agent's own model service, a name for an
//! address, and how big a workspace is. Live lookups here; tests supply their
//! own [`Destinations`].

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, ToSocketAddrs as _};
use std::sync::{Mutex, OnceLock, PoisonError};

use super::config;

/// How long a resolved list of model-service addresses is trusted.
const MODEL_ADDRESSES_TTL_MS: u64 = 10 * 60 * 1_000;
/// Most files counted when sizing a workspace root.
const MAX_ROOT_WALK: u64 = 200_000;

/// How a destination is told apart from a model service. Implemented by the
/// live resolver and by tests.
pub(crate) trait Destinations {
    /// Whether this address is one of the model services' addresses.
    fn model_service(&mut self, host: &str) -> bool;
    /// A name for the address, when one is known.
    fn name(&mut self, host: &str) -> Option<String>;
    /// How many files are under `root` and their total size in bytes, up to
    /// a bound, when it can be read.
    fn workspace(&mut self, root: &str) -> Option<(u64, u64)>;
}

/// Resolves the configured model services and names addresses by reverse
/// DNS, both cached.
pub(crate) struct Live;

fn model_addresses() -> &'static Mutex<(u64, BTreeSet<IpAddr>)> {
    static ADDRESSES: OnceLock<Mutex<(u64, BTreeSet<IpAddr>)>> = OnceLock::new();
    ADDRESSES.get_or_init(|| Mutex::new((0, BTreeSet::new())))
}

pub(super) fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(0))
}

/// Addresses that have matched an agent's own service in this process. Kept
/// once matched: a resolver that times out later must not turn a vendor's
/// address into a stranger's.
fn known_own() -> &'static Mutex<BTreeSet<IpAddr>> {
    static KNOWN: OnceLock<Mutex<BTreeSet<IpAddr>>> = OnceLock::new();
    KNOWN.get_or_init(|| Mutex::new(BTreeSet::new()))
}

impl Destinations for Live {
    fn model_service(&mut self, host: &str) -> bool {
        let Ok(ip) = host.parse::<IpAddr>() else {
            return false;
        };
        if known_own()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(&ip)
        {
            return true;
        }
        let mut cached = model_addresses()
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let now = wall_ms();
        if now.saturating_sub(cached.0) > MODEL_ADDRESSES_TTL_MS {
            let mut set = BTreeSet::new();
            for service in &config().model_services {
                if let Ok(found) = (service.as_str(), 443).to_socket_addrs() {
                    set.extend(found.map(|a| a.ip()));
                }
            }
            *cached = (now, set);
        }
        let own = cached.1.contains(&ip);
        if own {
            known_own()
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(ip);
        }
        own
    }

    fn name(&mut self, host: &str) -> Option<String> {
        topgent_collect::resolve::reverse(host)
    }

    fn workspace(&mut self, root: &str) -> Option<(u64, u64)> {
        type Sizes = BTreeMap<String, (u64, Option<(u64, u64)>)>;
        static SIZES: OnceLock<Mutex<Sizes>> = OnceLock::new();
        let sizes = SIZES.get_or_init(|| Mutex::new(BTreeMap::new()));
        let now = wall_ms();
        if let Some((at, hit)) = sizes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(root)
            && now.saturating_sub(*at) < MODEL_ADDRESSES_TTL_MS
        {
            return *hit;
        }
        // Measured again every few minutes: an agent writing into the
        // workspace changes its size.
        let measured = count_files(std::path::Path::new(root));
        sizes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(root.to_owned(), (now, measured));
        measured
    }
}

/// Regular files under `root` and their total bytes, not following links,
/// up to [`MAX_ROOT_WALK`] entries.
fn count_files(root: &std::path::Path) -> Option<(u64, u64)> {
    let mut stack = vec![root.to_path_buf()];
    let mut files = 0_u64;
    let mut total = 0_u64;
    let mut seen = 0_u64;
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            if dir == root {
                return None;
            }
            continue;
        };
        for entry in entries.flatten() {
            seen += 1;
            if seen > MAX_ROOT_WALK {
                return None;
            }
            match entry.file_type() {
                Ok(kind) if kind.is_dir() => stack.push(entry.path()),
                Ok(kind) if kind.is_file() => {
                    files += 1;
                    total = total.saturating_add(entry.metadata().map_or(0, |m| m.len()));
                }
                _ => {}
            }
        }
    }
    Some((files, total))
}
