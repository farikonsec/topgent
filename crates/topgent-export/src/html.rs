//! The bill of materials as a page someone can read.
//!
//! Self-contained, with no scripts and no external requests, because it is
//! routinely attached to a ticket or an email. Every value an agent supplied
//! is escaped: this document names executables, hosts and paths that a hostile
//! process chose, and it must not become a way to run something in a reader's
//! browser.

use crate::bom::validate_cyclonedx;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt::Write as _;

/// Render a validated `CycloneDX` AI-BOM as a self-contained, human-readable HTML report.
///
/// The report embeds no remote assets or executable script. Every displayed value is
/// HTML-escaped, so inventory evidence cannot introduce markup into the export.
///
/// # Errors
///
/// Returns the `CycloneDX` validation error when `document` is outside Topgent's
/// pinned 1.6 projection.
pub fn cyclonedx_html(document: &Value) -> Result<String, String> {
    validate_cyclonedx(document)?;
    let components = document["components"]
        .as_array()
        .ok_or("components is not an array")?;
    let services = document["services"]
        .as_array()
        .ok_or("services is not an array")?;
    let dependencies = document["dependencies"]
        .as_array()
        .ok_or("dependencies is not an array")?;
    let timestamp = escape_html(
        document
            .get("metadata")
            .and_then(|metadata| metadata.get("timestamp"))
            .and_then(Value::as_str)
            .unwrap_or("unknown"),
    );
    let serial = escape_html(document["serialNumber"].as_str().unwrap_or("unknown"));
    let unresolved = document
        .get("metadata")
        .and_then(|metadata| metadata.get("properties"))
        .and_then(Value::as_array)
        .and_then(|items| {
            items
                .iter()
                .find(|item| item["name"] == "topgent:unresolved-identities")
        })
        .and_then(|item| item["value"].as_str())
        .unwrap_or("0");
    let names = components
        .iter()
        .chain(services)
        .filter_map(|entry| Some((entry["bom-ref"].as_str()?, entry["name"].as_str()?)))
        .collect::<BTreeMap<_, _>>();

    let mut rows = String::new();
    for entry in components.iter().chain(services) {
        let name = escape_html(entry["name"].as_str().unwrap_or("Unnamed asset"));
        let reference = escape_html(entry["bom-ref"].as_str().unwrap_or(""));
        let property = |wanted: &str| {
            entry["properties"]
                .as_array()
                .and_then(|items| items.iter().find(|item| item["name"] == wanted))
                .and_then(|item| item["value"].as_str())
                .unwrap_or("unknown")
        };
        let kind_raw = property("topgent:asset-kind");
        let kind = escape_html(kind_raw);
        let confidence = escape_html(property("topgent:confidence"));
        let source = escape_html(property("topgent:source"));
        let disposition_raw = property("topgent:disposition");
        let disposition = escape_html(disposition_raw);
        let icon = asset_icon(kind_raw, entry["name"].as_str().unwrap_or(""));
        let _ = write!(
            rows,
            "<tr><td><span class=\"asset-icon kind-{kind}\" aria-hidden=\"true\">{icon}</span><span class=\"asset-name\">{name}<small>{reference}</small></span></td><td><span class=\"kind\">{kind}</span></td><td>{confidence}<small>{source}</small></td><td><span class=\"state state-{disposition}\">{disposition}</span></td></tr>"
        );
    }
    if rows.is_empty() {
        rows.push_str("<tr><td colspan=\"4\" class=\"empty\">No AI assets were detected in this scan.</td></tr>");
    }
    let mut relationship_rows = String::new();
    for dependency in dependencies {
        let from_ref = dependency["ref"].as_str().unwrap_or("");
        for target in dependency["dependsOn"].as_array().into_iter().flatten() {
            let to_ref = target.as_str().unwrap_or("");
            let _ = write!(
                relationship_rows,
                "<tr><td>{}<small>{}</small></td><td>→</td><td>{}<small>{}</small></td></tr>",
                escape_html(names.get(from_ref).copied().unwrap_or(from_ref)),
                escape_html(from_ref),
                escape_html(names.get(to_ref).copied().unwrap_or(to_ref)),
                escape_html(to_ref)
            );
        }
    }
    if relationship_rows.is_empty() {
        relationship_rows.push_str(
            "<tr><td colspan=\"3\" class=\"empty\">No asset relationships were observed.</td></tr>",
        );
    }

    Ok(format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Topgent AI-BOM</title><style>
:root{{--ink:#13181f;--paper:#f5f1e8;--panel:#fffdf7;--line:#c9c1b1;--muted:#5e6670;--accent:#b86b18;--ok:#176b61;--bad:#a52e25}}*{{box-sizing:border-box}}body{{margin:0;background:var(--paper);color:var(--ink);font:15px/1.5 ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}}main{{max-width:1120px;margin:auto;padding:48px 28px 70px}}header{{display:grid;grid-template-columns:1fr auto;gap:24px;align-items:end;border-top:8px solid var(--accent);border-bottom:1px solid var(--line);padding:24px 0}}.eyebrow,.label,th{{font:700 11px/1.2 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.11em;text-transform:uppercase}}h1{{font-size:clamp(38px,7vw,72px);line-height:.95;letter-spacing:-.055em;margin:8px 0}}.subtitle{{color:var(--muted);max-width:620px}}.stamp{{border:1px solid var(--accent);padding:12px 15px;color:var(--accent);font-weight:700}}.metrics{{display:grid;grid-template-columns:repeat(3,1fr);margin:28px 0;border:1px solid var(--line)}}.metric{{padding:19px;border-right:1px solid var(--line)}}.metric:last-child{{border:0}}.metric b{{display:block;font-size:30px}}section{{background:var(--panel);border:1px solid var(--line);margin-top:28px}}section h2{{margin:0;padding:17px 20px;border-bottom:1px solid var(--line);font-size:17px}}table{{width:100%;border-collapse:collapse}}th,td{{padding:13px 16px;text-align:left;border-bottom:1px solid var(--line);vertical-align:middle}}th{{color:var(--muted)}}tr:last-child td{{border:0}}td:first-child{{display:flex;align-items:center;gap:12px}}small{{display:block;color:var(--muted);font:11px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}}.asset-icon{{width:34px;height:34px;display:grid;place-items:center;flex:0 0 auto;background:var(--ink);color:var(--panel);font:700 13px ui-monospace,SFMono-Regular,Menlo,monospace}}.kind-agent,.kind-agent_extension{{background:var(--accent)}}.kind-endpoint{{background:var(--ok)}}.kind,.state{{display:inline-block;border:1px solid var(--line);padding:2px 7px;text-transform:capitalize;font-size:12px}}.state-approved{{color:var(--ok);border-color:var(--ok)}}.state-disallowed{{color:var(--bad);border-color:var(--bad)}}.note{{padding:18px 20px;color:var(--muted)}}footer{{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-top:25px;color:var(--muted);font-size:12px}}@media(max-width:700px){{header{{grid-template-columns:1fr}}.stamp{{justify-self:start}}.metrics{{grid-template-columns:1fr}}.metric{{border-right:0;border-bottom:1px solid var(--line)}}table{{font-size:12px}}th,td{{padding:10px 8px}}footer{{grid-template-columns:1fr}}}}@media print{{body{{background:white}}main{{padding:18px}}section{{break-inside:avoid}}}}
</style></head><body><main aria-labelledby="report-title"><header><div><div class="eyebrow">Local AI inventory · CycloneDX 1.6</div><h1 id="report-title">AI-BOM</h1><div class="subtitle">A human-readable inventory of the AI agents, extensions, models, connectors, tools and endpoints observed by Topgent.</div></div><div class="stamp">METADATA ONLY</div></header><div class="metrics" aria-label="Inventory summary"><div class="metric"><span class="label">Components</span><b>{}</b></div><div class="metric"><span class="label">Services</span><b>{}</b></div><div class="metric"><span class="label">Relationships</span><b>{}</b></div></div><section aria-labelledby="assets-heading"><h2 id="assets-heading">Detected AI estate</h2><table><caption>Detected AI assets and their evidence and policy status</caption><thead><tr><th scope="col">Asset</th><th scope="col">Kind</th><th scope="col">Evidence</th><th scope="col">Policy</th></tr></thead><tbody>{rows}</tbody></table></section><section aria-labelledby="relationships-heading"><h2 id="relationships-heading">Observed relationships</h2><table><caption>Observed dependencies between AI assets</caption><thead><tr><th scope="col">From</th><th scope="col">Direction</th><th scope="col">To</th></tr></thead><tbody>{relationship_rows}</tbody></table></section><section aria-labelledby="privacy-heading"><h2 id="privacy-heading">Privacy boundary</h2><div class="note">This export contains metadata only. It excludes prompts, file contents, credential contents and TLS payloads. Unresolved identities: <strong>{}</strong>.</div></section><footer><div><span class="label">Generated</span><br>{timestamp}</div><div><span class="label">Document ID</span><br><small>{serial}</small></div></footer></main></body></html>"#,
        components.len(),
        services.len(),
        dependencies
            .iter()
            .map(|item| item["dependsOn"].as_array().map_or(0, Vec::len))
            .sum::<usize>(),
        escape_html(unresolved)
    ))
}

fn asset_icon(kind: &str, name: &str) -> String {
    if matches!(kind, "agent" | "agent_extension") {
        name.chars()
            .filter(char::is_ascii_alphanumeric)
            .take(2)
            .flat_map(char::to_uppercase)
            .collect::<String>()
    } else {
        match kind {
            "model" => "M",
            "connector" => "↗",
            "tool" => "T",
            "endpoint" => "●",
            _ => "AI",
        }
        .to_owned()
    }
}

fn escape_html(value: &str) -> String {
    value.chars().fold(
        String::with_capacity(value.len()),
        |mut output, character| {
            match character {
                '&' => output.push_str("&amp;"),
                '<' => output.push_str("&lt;"),
                '>' => output.push_str("&gt;"),
                '"' => output.push_str("&quot;"),
                '\'' => output.push_str("&#39;"),
                '\u{0000}'..='\u{001f}'
                | '\u{007f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}' => {
                    let _ = write!(output, "\\u{{{:04X}}}", u32::from(character));
                }
                _ => output.push(character),
            }
            output
        },
    )
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
    use crate::bom::cyclonedx;
    use topgent_core::{Asset, AssetId, Relationship};
    use topgent_core::{AssetKind, Inventory};
    use topgent_facts::Confidence;
    use topgent_policy::Disposition;
    use topgent_policy::Policy;
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
    fn html_export_is_readable_self_contained_and_escapes_inventory_values() {
        let mut inventory = inventory();
        inventory.assets[0].name = "Codex <script>alert('x')</script>".into();
        let document = cyclonedx(&inventory, &Policy::default(), 1_700_000_000_123);
        let html = cyclonedx_html(&document).expect("valid human-readable export");
        assert!(html.starts_with("<!doctype html>"));
        assert!(html.contains("Detected AI estate"));
        assert!(html.contains("Codex &lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;"));
        assert!(!html.contains("<script>"));
        assert!(!html.contains("http://"));
        assert!(!html.contains("https://"));
    }

    #[test]
    fn html_export_has_accessible_landmarks_and_neutralizes_direction_controls() {
        let mut inventory = inventory();
        inventory.assets[0].name = "safe\u{202e}<img src=x>\nname".into();
        let document = cyclonedx(&inventory, &Policy::default(), 1_700_000_000_123);
        let html = cyclonedx_html(&document).expect("valid accessible export");
        assert!(html.contains("<main aria-labelledby=\"report-title\">"));
        assert_eq!(html.matches("<caption>").count(), 2);
        assert_eq!(html.matches("scope=\"col\"").count(), 7);
        assert!(html.contains("safe\\u{202E}&lt;img src=x&gt;\\u{000A}name"));
        assert!(!html.contains('\u{202e}'));
        assert!(!html.contains("<script"));
        assert!(!html.contains("<img"));
    }
}
