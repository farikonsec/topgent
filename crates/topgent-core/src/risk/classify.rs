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

/// One agent's items, as the catalogue's per-item conditions see them.
///
/// Every classification a condition can ask about is made here and handed over
/// as a flag. That boundary is the design: `10.0.0.5` being a private address
/// is a fact about addressing, and `~/.zshrc` being a persistence location is a
/// fact about how programs start. Neither is a rule anybody should be editing
/// in a policy file, and a condition language able to derive them would be a
/// program rather than data.
pub fn items_of(
    agent: &crate::graph::Agent,
    kind: topgent_policy::ItemKind,
) -> Vec<topgent_policy::Item> {
    use topgent_policy::{Flag, Item, ItemKind};

    let mut out = Vec::new();
    match kind {
        ItemKind::Endpoints => {
            for endpoint in &agent.endpoints {
                let mut flags = Vec::new();
                if matches!(endpoint.direction, topgent_facts::Direction::Listening) {
                    flags.push(Flag::Listening);
                }
                if matches!(endpoint.direction, topgent_facts::Direction::Outbound) {
                    flags.push(Flag::Outbound);
                }
                if is_loopback(&endpoint.host) {
                    flags.push(Flag::Loopback);
                }
                if is_private_peer(&endpoint.host) {
                    flags.push(Flag::PrivatePeer);
                }
                if endpoint.host.parse::<std::net::IpAddr>().is_ok() {
                    flags.push(Flag::RawAddress);
                }
                if crate::network::is_metadata_service(&endpoint.host) {
                    flags.push(Flag::MetadataService);
                }
                // How the destination was seen, so a condition can fire on a
                // connection that has already gone rather than only on one a
                // sweep happened to catch open.
                for sighting in &endpoint.sightings {
                    flags.push(match sighting {
                        crate::graph::Sighting::Held => Flag::Held,
                        crate::graph::Sighting::Attempted => Flag::Attempted,
                        crate::graph::Sighting::Closed => Flag::Closed,
                        crate::graph::Sighting::Captured => Flag::Captured,
                    });
                }
                flags.sort_unstable();
                out.push(Item {
                    kind: Some(kind),
                    text: endpoint.host.clone(),
                    port: u32::from(endpoint.port),
                    flags,
                    ..Item::default()
                });
            }
        }
        ItemKind::Children => {
            for child in &agent.children {
                let mut flags = Vec::new();
                if offensive_tool(&child.name) {
                    flags.push(Flag::OffensiveTool);
                }
                out.push(Item {
                    kind: Some(kind),
                    // The short executable name, not the command line. The
                    // vocabulary keeps arguments out of the fact stream and this
                    // must not be the place they come back.
                    text: executable_name(&child.name).to_owned(),
                    pid: child.pid,
                    depth: u32::from(child.depth),
                    flags,
                    ..Item::default()
                });
            }
        }
        ItemKind::Resources => {
            for resource in &agent.resources {
                let mut flags = Vec::new();
                if resource.observed.is_yes() {
                    flags.push(Flag::Observed);
                }
                if resource.declared.is_yes() {
                    flags.push(Flag::Declared);
                }
                if resource.reachable.is_yes() {
                    flags.push(Flag::Reachable);
                }
                if resource.sensitive {
                    flags.push(Flag::Sensitive);
                }
                if resource
                    .access
                    .is_some_and(topgent_facts::Access::is_mutating)
                {
                    flags.push(Flag::Mutating);
                }
                if persistence_path(&resource.path) {
                    flags.push(Flag::PersistenceLocation);
                }
                if topgent_path(&resource.path) {
                    flags.push(Flag::TopgentOwned);
                }
                flags.sort_unstable();
                out.push(Item {
                    kind: Some(kind),
                    text: resource.path.clone(),
                    flags,
                    ..Item::default()
                });
            }
        }
    }
    out
}
