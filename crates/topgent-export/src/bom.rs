//! The `CycloneDX` bill of materials.
//!
//! Deterministic: the same estate produces the same document, so a diff between
//! two exports is a change in the estate and never a change in serialisation
//! order. The validator is here rather than in a test because a malformed
//! document reaching a pipeline is worse than no document at all.

use crate::contract::CYCLONEDX_SPEC_VERSION;
use serde_json::Value;
use serde_json::json;
use std::collections::BTreeSet;
use topgent_core::AssetKind;
use topgent_core::Inventory;
use topgent_policy::Policy;

/// Build a deterministic `CycloneDX` AI-BOM from the same inventory used by the UI.
///
/// `timestamp_ms` is explicit so tests and callers can reproduce the document.
#[must_use]
pub fn cyclonedx(inventory: &Inventory, policy: &Policy, timestamp_ms: u64) -> Value {
    let components = inventory
        .assets
        .iter()
        .filter(|asset| asset.kind != AssetKind::Endpoint)
        .map(|asset| {
            json!({
                "type": component_type(asset.kind),
                "bom-ref": asset.id.0,
                "name": asset.name,
                "properties": properties([
                    ("topgent:asset-kind", asset.kind.as_str()),
                    ("topgent:confidence", asset.confidence.label()),
                    ("topgent:source", asset.source),
                    ("topgent:disposition", policy.asset_disposition(&asset.id.0, None).label()),
                ]),
            })
        })
        .collect::<Vec<_>>();
    let services = inventory
        .assets
        .iter()
        .filter(|asset| asset.kind == AssetKind::Endpoint)
        .map(|asset| {
            json!({
                "bom-ref": asset.id.0,
                "name": asset.name,
                "properties": properties([
                    ("topgent:asset-kind", asset.kind.as_str()),
                    ("topgent:confidence", asset.confidence.label()),
                    ("topgent:source", asset.source),
                    ("topgent:disposition", policy.asset_disposition(&asset.id.0, None).label()),
                ]),
            })
        })
        .collect::<Vec<_>>();
    let dependencies = inventory
        .assets
        .iter()
        .map(|asset| {
            let depends_on = inventory
                .relationships
                .iter()
                .filter(|relationship| relationship.from == asset.id)
                .map(|relationship| relationship.to.0.clone())
                .collect::<BTreeSet<_>>();
            json!({ "ref": asset.id.0, "dependsOn": depends_on })
        })
        .collect::<Vec<_>>();
    json!({
        "$schema": "https://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "serialNumber": serial_number(timestamp_ms, inventory),
        "version": 1,
        "metadata": {
            "timestamp": rfc3339(timestamp_ms),
            "tools": { "components": [{
                "type": "application", "name": "Topgent", "version": env!("CARGO_PKG_VERSION")
            }]},
            "properties": [
                { "name": "topgent:privacy", "value": "metadata-only; no prompt, file-content, credential-content, or TLS payload export" },
                { "name": "topgent:unresolved-identities", "value": inventory.assets.iter().filter(|asset| asset.name == "unclassified").count().to_string() },
            ]
        },
        "components": components,
        "services": services,
        "dependencies": dependencies,
    })
}

pub(crate) fn component_type(kind: AssetKind) -> &'static str {
    match kind {
        AssetKind::Agent | AssetKind::Endpoint => "application",
        AssetKind::AgentExtension
        | AssetKind::Model
        | AssetKind::Connector
        | AssetKind::Tool
        | AssetKind::Skill
        | AssetKind::Plugin
        | AssetKind::LocalModel => "library",
    }
}

pub(crate) fn properties<const N: usize>(values: [(&str, &str); N]) -> Vec<Value> {
    values
        .into_iter()
        .map(|(name, value)| json!({ "name": name, "value": value }))
        .collect()
}

pub(crate) fn serial_number(timestamp_ms: u64, inventory: &Inventory) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64 ^ timestamp_ms;
    for byte in inventory.assets.iter().flat_map(|asset| asset.id.0.bytes()) {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!(
        "urn:uuid:00000000-0000-4000-8000-{hash:012x}",
        hash = hash & 0xffff_ffff_ffff
    )
}

// Gregorian civil date conversion by Howard Hinnant, expressed with checked
// domain assumptions: Unix timestamps supplied as u64 milliseconds.
pub(crate) fn rfc3339(timestamp_ms: u64) -> String {
    let seconds = timestamp_ms / 1_000;
    let days = i64::try_from(seconds / 86_400).unwrap_or(i64::MAX);
    let day_seconds = seconds % 86_400;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        day_seconds / 3_600,
        day_seconds % 3_600 / 60,
        day_seconds % 60,
        timestamp_ms % 1_000
    )
}

/// Validate the pinned subset of `CycloneDX` 1.6 emitted by [`cyclonedx`].
///
/// This validates required fields and reference integrity without downloading a
/// schema at runtime. It is intentionally strict about this crate's projection.
///
/// # Errors
///
/// Returns an explanation when a required field or dependency reference is invalid.
pub fn validate_cyclonedx(document: &Value) -> Result<(), String> {
    if document["bomFormat"] != "CycloneDX" || document["specVersion"] != CYCLONEDX_SPEC_VERSION {
        return Err("document is not CycloneDX 1.6".to_owned());
    }
    if !document["serialNumber"]
        .as_str()
        .is_some_and(|value| value.starts_with("urn:uuid:"))
    {
        return Err("serialNumber is not a UUID URN".to_owned());
    }
    let mut references = BTreeSet::new();
    for collection in ["components", "services"] {
        let Some(entries) = document[collection].as_array() else {
            return Err(format!("{collection} is not an array"));
        };
        for entry in entries {
            let Some(reference) = entry["bom-ref"].as_str() else {
                return Err(format!("{collection} entry has no bom-ref"));
            };
            if !references.insert(reference) {
                return Err(format!("duplicate bom-ref {reference}"));
            }
        }
    }
    for dependency in document["dependencies"]
        .as_array()
        .ok_or("dependencies is not an array")?
    {
        let reference = dependency["ref"].as_str().ok_or("dependency has no ref")?;
        if !references.contains(reference) {
            return Err(format!("unresolved dependency ref {reference}"));
        }
        for target in dependency["dependsOn"]
            .as_array()
            .ok_or("dependsOn is not an array")?
        {
            let target = target.as_str().ok_or("dependsOn value is not a string")?;
            if !references.contains(target) {
                return Err(format!("unresolved dependency target {target}"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::unwrap_used
    )]
    use super::*;
    use crate::html::cyclonedx_html;
    use topgent_core::{Asset, AssetId, Relationship};
    use topgent_facts::Confidence;
    use topgent_policy::Disposition;
    fn inventory() -> Inventory {
        Inventory {
            assets: vec![
                Asset {
                    id: AssetId("urn:topgent:agent:codex".into()),
                    kind: AssetKind::Agent,
                    name: "Codex 🦀".into(),
                    confidence: Confidence::Certain,
                    source: "agent_family",
                    version: None,
                    digest: None,
                    installed: false,
                    active: true,
                    first_seen: None,
                    last_seen: None,
                },
                Asset {
                    id: AssetId("urn:topgent:endpoint:example.com%3A443".into()),
                    kind: AssetKind::Endpoint,
                    name: "example.com:443".into(),
                    confidence: Confidence::Likely,
                    source: "socket",
                    version: None,
                    digest: None,
                    installed: false,
                    active: true,
                    first_seen: None,
                    last_seen: None,
                },
            ],
            relationships: vec![Relationship {
                from: AssetId("urn:topgent:agent:codex".into()),
                to: AssetId("urn:topgent:endpoint:example.com%3A443".into()),
                kind: "connects_to",
                agent_pid: 7,
                agent_family: "codex-cli".into(),
                disposition: Disposition::Unreviewed,
            }],
        }
    }

    #[test]
    fn export_is_deterministic_valid_and_preserves_every_reference() {
        let document = cyclonedx(&inventory(), &Policy::default(), 1_700_000_000_123);
        assert_eq!(
            document,
            cyclonedx(&inventory(), &Policy::default(), 1_700_000_000_123)
        );
        assert!(validate_cyclonedx(&document).is_ok());
        assert_eq!(document["components"][0]["name"], "Codex 🦀");
        assert_eq!(
            document["metadata"]["timestamp"],
            "2023-11-14T22:13:20.123Z"
        );
    }

    #[test]
    fn validator_rejects_dangling_references() {
        let mut document = cyclonedx(&inventory(), &Policy::default(), 1);
        document["dependencies"][0]["dependsOn"] = json!(["missing"]);
        assert!(validate_cyclonedx(&document).is_err());
    }

    #[test]
    fn empty_and_large_exports_remain_valid_and_bounded_to_local_markup() {
        let empty = Inventory {
            assets: Vec::new(),
            relationships: Vec::new(),
        };
        let empty_html = cyclonedx_html(&cyclonedx(&empty, &Policy::default(), 1))
            .expect("empty inventory is valid");
        assert!(empty_html.contains("No AI assets were detected"));

        let mut large = Inventory {
            assets: Vec::new(),
            relationships: Vec::new(),
        };
        for index in 0..512 {
            large.assets.push(Asset {
                id: AssetId(format!("urn:topgent:tool:{index:04}")),
                kind: AssetKind::Tool,
                name: format!("Tool {index:04}"),
                confidence: Confidence::Likely,
                source: "release-fixture",
                version: None,
                digest: None,
                installed: true,
                active: false,
                first_seen: None,
                last_seen: None,
            });
        }
        let document = cyclonedx(&large, &Policy::default(), 1);
        validate_cyclonedx(&document).expect("large document is valid");
        let html = cyclonedx_html(&document).expect("large HTML renders");
        assert_eq!(html.matches("<tr><td>").count(), 512);
        assert!(!html.contains("<script"));
        assert!(!html.contains("http://"));
        assert!(!html.contains("https://"));
    }
}
