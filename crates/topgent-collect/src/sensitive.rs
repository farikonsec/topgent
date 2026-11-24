//! Sensitive-file detection signatures.
//!
//! A monitor needs to say when an agent read a credential, a key or a saved
//! password, and which kind. The patterns are data (`data/sensitive-files.json`)
//! so the list can grow without code changes, and so a reader can see exactly
//! what is matched. Matching is on the path alone: Topgent never opens a file
//! to decide whether it is sensitive.
//!
//! This classifies a path. It does not read, copy or move anything.

use std::sync::OnceLock;

use serde::Deserialize;

const CATALOGUE_JSON: &str = include_str!("../data/sensitive-files.json");

/// One class of sensitive file, with its matchers.
#[derive(Debug, Deserialize)]
struct Class {
    id: String,
    name: String,
    #[serde(default)]
    store: bool,
    matchers: Vec<Matcher>,
}

/// One pattern. A matcher holds when every field it carries holds.
#[derive(Debug, Default, Deserialize)]
struct Matcher {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    prefix: Option<String>,
    #[serde(default)]
    suffix: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    within: Vec<String>,
}

impl Matcher {
    fn holds(&self, name: &str, path: &str) -> bool {
        self.name.as_deref().is_none_or(|n| n == name)
            && self.prefix.as_deref().is_none_or(|p| name.starts_with(p))
            && self.suffix.as_deref().is_none_or(|s| name.ends_with(s))
            && self.path.as_deref().is_none_or(|p| path.contains(p))
            && (self.within.is_empty() || self.within.iter().any(|w| path.contains(w)))
    }
}

/// What never counts, however its name looks: vendored trees, public CA
/// bundles, example env files, public keys.
#[derive(Debug, Default, Deserialize)]
struct Exclude {
    #[serde(default)]
    path: Vec<String>,
    #[serde(default)]
    name_contains: Vec<String>,
    #[serde(default)]
    name: Vec<String>,
    #[serde(default)]
    suffix: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Catalogue {
    #[serde(default)]
    exclude: Exclude,
    classes: Vec<Class>,
}

fn catalogue() -> &'static Catalogue {
    static CATALOGUE: OnceLock<Catalogue> = OnceLock::new();
    CATALOGUE.get_or_init(|| {
        // Shipped with the binary and checked by a test; a parse failure is a
        // build defect, and an empty catalogue is the safe degradation.
        serde_json::from_str(CATALOGUE_JSON).unwrap_or(Catalogue {
            exclude: Exclude::default(),
            classes: Vec::new(),
        })
    })
}

fn excluded(name: &str, path: &str) -> bool {
    let e = &catalogue().exclude;
    e.path.iter().any(|p| path.contains(p))
        || e.name_contains.iter().any(|n| name.contains(n))
        || e.name.iter().any(|n| n == name)
        || e.suffix.iter().any(|s| name.ends_with(s))
}

/// The class id of a sensitive path, or `None`. The id is stable and is what
/// an incident keys on; [`display`] turns it into words.
#[must_use]
pub fn classify(path: &str) -> Option<&'static str> {
    let lower = path.to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    if excluded(name, &lower) {
        return None;
    }
    catalogue()
        .classes
        .iter()
        .find(|c| c.matchers.iter().any(|m| m.holds(name, &lower)))
        .map(|c| c.id.as_str())
}

/// The plain name of a class id, or the id unchanged if it is unknown.
#[must_use]
pub fn display(id: &str) -> &'static str {
    catalogue()
        .classes
        .iter()
        .find(|c| c.id == id)
        .map_or("sensitive file", |c| c.name.as_str())
}

/// Whether a class holds many credentials at once, so reading one is worth
/// reporting even if nothing leaves.
#[must_use]
pub fn is_store(id: &str) -> bool {
    catalogue()
        .classes
        .iter()
        .find(|c| c.id == id)
        .is_some_and(|c| c.store)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shipped_catalogue_parses_and_classes_are_distinct() {
        let classes = &catalogue().classes;
        assert!(classes.len() >= 10, "{classes:?}");
        let mut ids = std::collections::BTreeSet::new();
        for class in classes {
            assert!(!class.name.is_empty());
            assert!(!class.matchers.is_empty(), "{} has no matchers", class.id);
            assert!(ids.insert(&class.id), "duplicate class {}", class.id);
            assert_eq!(display(&class.id), class.name);
        }
    }

    #[test]
    fn known_paths_land_in_the_right_class_and_noise_is_excluded() {
        for (path, class) in [
            ("/home/u/.ssh/id_ed25519", "private_key"),
            ("/home/u/work/deploy/server.key", "private_key"),
            ("/home/u/Passwords.kdbx", "password_manager"),
            (
                "/home/u/.config/google-chrome/Default/Login Data",
                "browser_store",
            ),
            ("/home/u/.mozilla/firefox/p/key4.db", "browser_store"),
            ("/home/u/Library/Keychains/login.keychain-db", "os_keychain"),
            ("/home/u/.electrum/wallets/default", "crypto_wallet"),
            ("/home/u/.aws/credentials", "cloud_credential"),
            ("/home/u/project/.env", "app_secret"),
            ("/home/u/.bash_history", "shell_history"),
            // Borrowed filename signatures, and .git/config (remote URLs can
            // carry a token).
            ("/home/u/project/.git/config", "cloud_credential"),
            ("/home/u/.s3cfg", "cloud_credential"),
            ("/home/u/work/client.ovpn", "vpn_or_remote"),
            ("/home/u/keys/server.pkcs12", "private_key"),
            ("/home/u/backup/dump.sqldump", "database_dump"),
            ("/home/u/.irb_history", "shell_history"),
            (
                "/home/u/.ethereum/keystore/UTC--2024-01-01T00-00-00Z--abc",
                "crypto_wallet",
            ),
        ] {
            assert_eq!(classify(path), Some(class), "{path}");
        }
        for path in [
            "/home/u/project/.env.example",
            "/home/u/project/node_modules/x/key.pem",
            "/etc/ssl/certs/ca-bundle.pem",
            "/home/u/project/src/main.rs",
            "/home/u/.ssh/id_ed25519.pub",
        ] {
            assert_eq!(classify(path), None, "{path}");
        }
        assert!(is_store("password_manager"));
        assert!(is_store("browser_store"));
        assert!(!is_store("app_secret"));
    }
}
