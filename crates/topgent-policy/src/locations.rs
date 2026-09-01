//! Credential locations: the paths worth asking about.
//!
//! The shipped answer to "what counts as a credential" was a Rust literal, so
//! adding a cloud provider's token file meant a recompile, and a reviewer who
//! wanted to know what Topgent watches had to read the constructor of a
//! default. It is a list of facts about where software stores secrets, which
//! changes with the software and not with Topgent.
//!
//! # Why an edit here is safe
//!
//! These paths drive two things: the reachability probe, which asks the
//! filesystem whether opening a path would succeed, and the `sensitive` flag
//! that turns an observed file access into a credential finding. Adding an
//! entry produces more findings. The list is compiled in with `include_str!`,
//! so nothing on a running machine can shorten it.
//!
//! The user's own `policy.json` may override the list outright, and always
//! could — that is a local decision made by the person the tool reports to, not
//! by anything an agent can reach. This file is what a fresh install ships.

use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

const SCHEMA_VERSION: u16 = 1;
const BUILTIN_JSON: &str = include_str!("../data/sensitive-paths.json");
static BUILTIN: OnceLock<Result<Locations, String>> = OnceLock::new();

/// A path worth watching for reachability, and what it holds.
/// Deliberately tolerant of unknown fields: this type is also what a user's
/// own `policy.json` deserialises into, and one stray key in a hand-edited
/// file should not throw away the whole policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sensitive {
    /// Path, relative to the home directory unless absolute or `~/`-prefixed.
    pub path: String,
    /// What it holds, shown to the user.
    pub label: String,
}

/// The credential locations compiled into this build.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Locations {
    /// Schema version this file claims to be.
    pub schema_version: u16,
    /// Where the list came from.
    pub source: String,
    /// The paths themselves, in the order a fresh policy will hold them.
    pub sensitive_paths: Vec<Sensitive>,
}

/// The credential locations compiled into this build.
///
/// # Errors
///
/// Returns the validation failure if the built-in list is malformed. That is a
/// build-time mistake: the file is part of the binary, and the tests below
/// refuse to let one ship.
pub fn builtin() -> Result<&'static Locations, &'static str> {
    match BUILTIN.get_or_init(|| parse_and_validate(BUILTIN_JSON)) {
        Ok(locations) => Ok(locations),
        Err(error) => Err(error.as_str()),
    }
}

fn parse_and_validate(source: &str) -> Result<Locations, String> {
    let locations: Locations = serde_json::from_str(source)
        .map_err(|error| format!("sensitive paths are invalid: {error}"))?;
    if locations.schema_version != SCHEMA_VERSION {
        return Err(format!(
            "sensitive paths schema {} is not the {SCHEMA_VERSION} this build understands",
            locations.schema_version
        ));
    }
    if locations.source.trim().is_empty() {
        return Err("sensitive paths name no source".to_owned());
    }
    if locations.sensitive_paths.is_empty() {
        return Err("sensitive paths are empty".to_owned());
    }
    let mut seen = std::collections::BTreeSet::new();
    for entry in &locations.sensitive_paths {
        if entry.path.trim().is_empty() {
            return Err("a sensitive path is blank".to_owned());
        }
        if entry.label.trim().is_empty() {
            // The label is what the user reads when the finding fires. An
            // unlabelled credential is a row saying a file was opened, with no
            // statement of why that matters.
            return Err(format!("sensitive path {} has no label", entry.path));
        }
        if !seen.insert(entry.path.as_str()) {
            // A duplicate is not harmful — the probe folds by path — but it is
            // always a mistake, and the folding hides which label won.
            return Err(format!("sensitive path {} is listed twice", entry.path));
        }
    }
    Ok(locations)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::{BUILTIN_JSON, builtin, parse_and_validate};

    #[test]
    fn the_built_in_list_still_watches_what_it_watched_before_it_was_a_file() {
        let locations = builtin().expect("the built-in credential locations must validate");
        let paths: Vec<&str> = locations
            .sensitive_paths
            .iter()
            .map(|entry| entry.path.as_str())
            .collect();
        for expected in [
            ".ssh/id_ed25519",
            ".ssh/id_rsa",
            ".aws/credentials",
            ".config/gcloud/credentials.db",
            ".kube/config",
            ".npmrc",
            ".netrc",
            ".config/gh/hosts.yml",
        ] {
            assert!(paths.contains(&expected), "{expected} is no longer watched");
        }
    }

    #[test]
    fn every_entry_says_what_it_holds() {
        let locations = builtin().expect("the built-in credential locations must validate");
        assert!(
            locations
                .sensitive_paths
                .iter()
                .all(|entry| !entry.label.trim().is_empty()),
            "a credential finding with no label explains nothing"
        );
    }

    #[test]
    fn a_duplicated_path_is_refused_rather_than_silently_folded() {
        let source = BUILTIN_JSON.replace(
            r#"{"path": ".npmrc", "label": "registry token"}"#,
            r#"{"path": ".npmrc", "label": "registry token"},
    {"path": ".npmrc", "label": "something else"}"#,
        );
        let error = parse_and_validate(&source).expect_err("a duplicate is refused");
        assert!(error.contains("listed twice"), "{error}");
    }

    #[test]
    fn an_empty_list_is_refused() {
        // Written out rather than edited from the built-in file: an empty list
        // has to be refused for being empty, not for some incidental damage
        // done while making it empty.
        let source = r#"{"schema_version": 1, "source": "test", "sensitive_paths": []}"#;
        let error = parse_and_validate(source).expect_err("an empty list is refused");
        assert!(error.contains("empty"), "{error}");
    }

    #[test]
    fn a_list_this_build_does_not_understand_is_refused() {
        let source = r#"{"schema_version": 99, "source": "test",
            "sensitive_paths": [{"path": ".netrc", "label": "stored logins"}]}"#;
        let error = parse_and_validate(source).expect_err("a future schema is refused");
        assert!(error.contains("schema"), "{error}");
    }

    #[test]
    fn an_unlabelled_path_is_refused() {
        let source = r#"{"schema_version": 1, "source": "test",
            "sensitive_paths": [{"path": ".netrc", "label": "  "}]}"#;
        let error = parse_and_validate(source).expect_err("a blank label is refused");
        assert!(error.contains("no label"), "{error}");
    }
}
