//! Small questions about hosts, paths and executable names.
//!
//! Each is a plain predicate with no policy in it, kept together so the
//! judgement in `factors` reads as judgement rather than string handling.

pub(super) fn is_loopback(host: &str) -> bool {
    host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

pub(super) fn is_private_peer(host: &str) -> bool {
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => ip.is_private(),
        Ok(std::net::IpAddr::V6(ip)) => ip.is_unique_local(),
        Err(_) => false,
    }
}

pub(super) fn executable_name(name: &str) -> &str {
    name.rsplit('/').next().unwrap_or(name)
}

pub(super) fn offensive_tool(name: &str) -> bool {
    topgent_policy::signals::builtin()
        .is_ok_and(|signals| signals.is_offensive_tool(&executable_name(name).to_ascii_lowercase()))
}

/// Whether a port is one shells and implants habitually use.
///
/// The caller pairs this with a raw address. The list is the same one the
/// network verdict consults, so the finding and the verdict it explains cannot
/// name different ports.
pub(super) fn suspicious_port(port: u16) -> bool {
    topgent_policy::signals::builtin().is_ok_and(|signals| signals.is_suspicious_port(port))
}

pub(super) fn persistence_path(path: &str) -> bool {
    let lowercased = path.to_ascii_lowercase();
    topgent_policy::signals::builtin().is_ok_and(|signals| signals.is_persistence_path(&lowercased))
}

/// Topgent's own files.
///
/// Deliberately not in the signals file. A data file able to remove an entry
/// here would be a data file able to make the monitor stop noticing that it is
/// being modified, and self-protection is the one list that must not be
/// editable by anything an agent could reach.
pub(super) fn topgent_path(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    p.ends_with("/.config/topgent/policy.json")
        || p.ends_with("/bin/topgent")
        || p.ends_with("/topgent.app/contents/macos/topgent-app")
}
