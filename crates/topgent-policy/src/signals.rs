//! Detection signals: the names, paths and endpoints worth noticing.
//!
//! Four lists that were literals inside the scorer. All four are open-ended by
//! nature — offensive tooling is named by whoever wrote it, persistence
//! locations differ per platform and per distribution, implants pick whatever
//! port their author liked, and every cloud vendor ships its own metadata
//! address — so they belong in a file that can be extended without touching
//! scoring logic.
//!
//! The two endpoint lists were also the worst kind of duplication: the same
//! five ports appeared in the network verdict and again in the factor that
//! explains the verdict, with nothing keeping them equal. A machine could have
//! shown a suspicious-endpoint verdict beside a report that declined to say
//! why.
//!
//! # What is not here
//!
//! Topgent's own paths. `topgent-core` still recognises those in code, because
//! a data file able to remove an entry would be a data file able to make the
//! monitor stop noticing that it is being modified. The rule holds generally:
//! data may say what else to look at, and never what to stop looking at.
//!
//! Every list here is additive in the safe direction. Adding a name, a port or
//! a metadata address produces more findings, never fewer, so the worst an
//! edited file can do is make Topgent noisier — and it is compiled in with
//! `include_str!` regardless.

use serde::Deserialize;
use std::sync::OnceLock;

const SCHEMA_VERSION: u16 = 2;
const BUILTIN_JSON: &str = include_str!("../data/detection-signals.json");
static BUILTIN: OnceLock<Result<Signals, String>> = OnceLock::new();

/// How a path marker is compared.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "match", rename_all = "snake_case", deny_unknown_fields)]
pub enum PathMatch {
    /// The lowercased path contains this anywhere.
    Contains {
        /// Lowercase fragment.
        value: String,
    },
    /// The lowercased path ends with this.
    Suffix {
        /// Lowercase suffix.
        value: String,
    },
}

impl PathMatch {
    /// Whether an already-lowercased path matches.
    #[must_use]
    pub fn matches(&self, lowercased: &str) -> bool {
        match self {
            Self::Contains { value } => lowercased.contains(value.as_str()),
            Self::Suffix { value } => lowercased.ends_with(value.as_str()),
        }
    }

    fn value(&self) -> &str {
        match self {
            Self::Contains { value } | Self::Suffix { value } => value,
        }
    }
}

/// The signal lists compiled into this build.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signals {
    /// Schema version this file claims to be.
    pub schema_version: u16,
    /// Where the lists came from.
    pub source: String,
    /// Executable basenames that are offensive tooling, lowercased.
    pub offensive_tools: Vec<String>,
    /// Ports commonly used by shells and implants, noticed on a raw address.
    pub suspicious_ports: Vec<u16>,
    /// Cloud instance metadata addresses and names, lowercased.
    pub metadata_hosts: Vec<String>,
    /// Path markers for locations that survive a reboot.
    pub persistence_markers: Vec<PathMatch>,
}

impl Signals {
    /// Whether an already-lowercased executable basename is offensive tooling.
    #[must_use]
    pub fn is_offensive_tool(&self, basename: &str) -> bool {
        self.offensive_tools.iter().any(|name| name == basename)
    }

    /// Whether an already-lowercased path is a persistence location.
    #[must_use]
    pub fn is_persistence_path(&self, lowercased: &str) -> bool {
        self.persistence_markers
            .iter()
            .any(|marker| marker.matches(lowercased))
    }

    /// Whether a port is one commonly used by shells and implants.
    ///
    /// A port alone says nothing. The caller pairs this with a raw address,
    /// because a named host on 4444 is far more often a developer's own
    /// service than an implant.
    #[must_use]
    pub fn is_suspicious_port(&self, port: u16) -> bool {
        self.suspicious_ports.contains(&port)
    }

    /// Whether a host label is a cloud instance metadata endpoint.
    ///
    /// Compared exactly, not by substring: a name that merely contains a
    /// metadata address is a different host.
    #[must_use]
    pub fn is_metadata_host(&self, host: &str) -> bool {
        self.metadata_hosts.iter().any(|known| known == host)
    }
}

/// The signal lists compiled into this build.
///
/// # Errors
///
/// Returns the validation failure if the built-in lists are malformed. That is
/// a build-time mistake: the file is part of the binary.
pub fn builtin() -> Result<&'static Signals, &'static str> {
    match BUILTIN.get_or_init(|| parse_and_validate(BUILTIN_JSON)) {
        Ok(signals) => Ok(signals),
        Err(error) => Err(error.as_str()),
    }
}

fn parse_and_validate(source: &str) -> Result<Signals, String> {
    let signals: Signals = serde_json::from_str(source)
        .map_err(|error| format!("detection signals are invalid: {error}"))?;
    if signals.schema_version != SCHEMA_VERSION {
        return Err(format!(
            "detection signals schema {} is not the {SCHEMA_VERSION} this build understands",
            signals.schema_version
        ));
    }
    if signals.source.trim().is_empty() {
        return Err("detection signals name no source".to_owned());
    }
    if signals.offensive_tools.is_empty()
        || signals.persistence_markers.is_empty()
        || signals.suspicious_ports.is_empty()
        || signals.metadata_hosts.is_empty()
    {
        return Err("detection signals are empty".to_owned());
    }
    // Port 0 is not a port. It would match nothing on a real socket and would
    // read, to anyone auditing the list, as a rule that had been thought about.
    if signals.suspicious_ports.contains(&0) {
        return Err("port 0 could never match".to_owned());
    }
    for host in &signals.metadata_hosts {
        if host.trim().is_empty() || host.to_ascii_lowercase() != *host {
            return Err(format!("metadata host {host} could never match"));
        }
    }
    // Matching is done against lowercased input, so an entry with an uppercase
    // letter can never match. It would look like a rule and behave like a
    // comment, which is the worst thing a detection list can do.
    for name in &signals.offensive_tools {
        if name.trim().is_empty() || name.to_ascii_lowercase() != *name {
            return Err(format!("offensive tool {name} could never match"));
        }
    }
    for marker in &signals.persistence_markers {
        let value = marker.value();
        if value.trim().is_empty() || value.to_ascii_lowercase() != value {
            return Err(format!("persistence marker {value} could never match"));
        }
    }
    Ok(signals)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn the_built_in_signals_recognise_what_they_did_before_they_were_a_file() {
        let signals = builtin().expect("the built-in signals must validate");
        for name in [
            "nmap", "nc", "ncat", "netcat", "masscan", "sqlmap", "hydra", "medusa",
        ] {
            assert!(signals.is_offensive_tool(name), "{name} is not recognised");
        }
        assert!(!signals.is_offensive_tool("node"));
        for path in [
            "/users/a/library/launchagents/x.plist",
            "/library/launchdaemons/y.plist",
            "/home/a/.zshrc",
            "/home/a/.bashrc",
            "/etc/cron.d/z",
            "/etc/systemd/system/w.service",
        ] {
            assert!(
                signals.is_persistence_path(path),
                "{path} is not recognised"
            );
        }
        assert!(!signals.is_persistence_path("/home/a/notes.md"));
        for port in [1337, 4444, 5555, 6666, 9001] {
            assert!(signals.is_suspicious_port(port), "{port} is not recognised");
        }
        assert!(!signals.is_suspicious_port(443));
        for host in ["169.254.169.254", "metadata.google.internal"] {
            assert!(signals.is_metadata_host(host), "{host} is not recognised");
        }
        assert!(!signals.is_metadata_host("169.254.169.253"));
    }

    #[test]
    fn a_metadata_host_matches_the_whole_name_and_not_a_fragment_of_one() {
        // Substring matching here would have let an attacker-controlled name
        // ending in the metadata address raise the finding, and a host merely
        // named after it escape one.
        let signals = builtin().expect("the built-in signals must validate");
        assert!(!signals.is_metadata_host("not-169.254.169.254"));
        assert!(!signals.is_metadata_host("metadata.google.internal.example.com"));
    }

    #[test]
    fn port_zero_is_refused_because_no_socket_could_ever_carry_it() {
        let source = BUILTIN_JSON.replace("[1337, 4444", "[0, 1337, 4444");
        let error = parse_and_validate(&source).expect_err("port 0 is refused");
        assert!(error.contains("could never match"), "{error}");
    }

    #[test]
    fn an_uppercased_metadata_host_is_refused() {
        let source = BUILTIN_JSON.replace(
            r#""metadata.google.internal""#,
            r#""Metadata.Google.Internal""#,
        );
        let error = parse_and_validate(&source).expect_err("an unmatchable host is refused");
        assert!(error.contains("could never match"), "{error}");
    }

    #[test]
    fn an_entry_that_could_never_match_is_refused_rather_than_shipped() {
        // Matching is case-folded before it gets here, so an uppercase entry
        // looks like a rule and behaves like a comment.
        let source = BUILTIN_JSON.replace(r#""nmap""#, r#""Nmap""#);
        let error = parse_and_validate(&source).expect_err("an unmatchable entry is refused");
        assert!(error.contains("could never match"), "{error}");
    }

    #[test]
    fn empty_lists_are_refused() {
        let source = BUILTIN_JSON.replace(
            r#""offensive_tools": ["#,
            r#""offensive_tools": [] , "unused": ["#,
        );
        assert!(parse_and_validate(&source).is_err());
    }
}
