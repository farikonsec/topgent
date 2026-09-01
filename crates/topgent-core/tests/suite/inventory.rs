use crate::fixtures::Stream;
use topgent_core::{
    AssetKind, build_inventory, build_inventory_with_installed, extension_asset_id, fold,
};
use topgent_facts::{
    Access, AssetDigest, Claim, Direction, InstalledAsset, InstalledAssetKind, Subject, UnixMillis,
};
use topgent_policy::{AssetPolicy, Disposition, Policy};

#[test]
fn inventory_deduplicates_assets_relates_them_and_applies_scoped_policy() {
    let mut facts = Stream::new(10)
        .seen("/opt/codex", 501, "testuser")
        .family("codex-cli")
        .model("openai", "gpt-5")
        .connector(
            "https://user:secret@mcp.example/tools?token=hidden",
            Access::Execute,
        )
        .socket("API.OPENAI.COM", 443, Direction::Outbound)
        .child(11, "NC", 1)
        .invokes(20, "child-process")
        .build();
    facts.extend(
        Stream::new(20)
            .seen("/opt/ollama", 501, "testuser")
            .family("ollama")
            .model("local", "gpt-5")
            .socket("api.openai.com", 443, Direction::Outbound)
            .build(),
    );

    let graph = fold(&facts);
    let endpoint_id = "urn:topgent:endpoint:api.openai.com%3A443";
    let mut policy = Policy::default();
    policy.set_asset_disposition(AssetPolicy {
        asset_id: endpoint_id.to_owned(),
        agent_family: None,
        disposition: Disposition::Approved,
    });
    policy.set_asset_disposition(AssetPolicy {
        asset_id: endpoint_id.to_owned(),
        agent_family: Some("codex-cli".to_owned()),
        disposition: Disposition::Restricted,
    });

    let inventory = build_inventory(&graph.agents, &policy);
    assert_eq!(
        inventory
            .assets
            .iter()
            .filter(|asset| asset.kind == AssetKind::Endpoint)
            .count(),
        1
    );
    assert!(inventory.assets.iter().all(|asset| {
        !asset.name.contains("secret")
            && !asset.id.0.contains("secret")
            && !asset.name.contains("hidden")
    }));
    assert!(inventory.relationships.iter().any(|relationship| {
        relationship.kind == "connects_to"
            && relationship.agent_family == "codex-cli"
            && relationship.disposition == Disposition::Restricted
    }));
    assert!(inventory.relationships.iter().any(|relationship| {
        relationship.kind == "connects_to"
            && relationship.agent_family == "ollama"
            && relationship.disposition == Disposition::Approved
    }));
    assert!(
        inventory
            .relationships
            .iter()
            .any(|relationship| { relationship.kind == "invokes" && relationship.agent_pid == 10 })
    );
}

#[test]
fn inventory_is_stable_when_fact_order_changes() {
    let facts = Stream::new(10)
        .seen("/opt/codex", 501, "testuser")
        .family("codex-cli")
        .model("openai", "gpt-5")
        .socket("api.openai.com", 443, Direction::Outbound)
        .build();
    let forward = build_inventory(&fold(&facts).agents, &Policy::default());
    let mut reversed = facts;
    reversed.reverse();
    let backward = build_inventory(&fold(&reversed).agents, &Policy::default());
    assert_eq!(forward, backward);
}

#[test]
fn shared_host_extensions_are_distinct_policy_assets_with_honest_relationships() {
    let subject = Subject::Process {
        pid: 42,
        started_at: crate::fixtures::at(100),
    };
    let facts = vec![
        crate::fixtures::fact(
            subject.clone(),
            Claim::EditorExtensionActive {
                family: "continue".to_owned(),
                extension_id: "continue.continue".to_owned(),
            },
        ),
        crate::fixtures::fact(
            subject,
            Claim::EditorExtensionActive {
                family: "cline".to_owned(),
                extension_id: "saoudrizwan.claude-dev".to_owned(),
            },
        ),
    ];
    let continue_id = extension_asset_id("continue", "continue.continue");
    let mut policy = Policy::default();
    policy.set_asset_disposition(AssetPolicy {
        asset_id: continue_id.0.clone(),
        agent_family: Some("continue".to_owned()),
        disposition: Disposition::Disallowed,
    });

    let inventory = build_inventory(&fold(&facts).agents, &policy);
    let extensions = inventory
        .assets
        .iter()
        .filter(|asset| asset.kind == AssetKind::AgentExtension)
        .collect::<Vec<_>>();
    assert_eq!(extensions.len(), 2);
    assert!(inventory.relationships.iter().any(|relationship| {
        relationship.kind == "hosts_extension"
            && relationship.to == continue_id
            && relationship.agent_pid == 42
            && relationship.agent_family == "continue"
            && relationship.disposition == Disposition::Disallowed
    }));
    assert!(inventory.relationships.iter().all(|relationship| {
        relationship.kind != "hosts_extension" || relationship.from.0.contains("unclassified")
    }));
}

#[test]
fn installed_assets_are_stable_metadata_rich_and_not_claimed_active() -> Result<(), String> {
    let evidence = vec![
        InstalledAsset {
            kind: InstalledAssetKind::LocalModel,
            identity: "ollama:registry.ollama.ai/library/qwen3/latest".to_owned(),
            name: "registry.ollama.ai/library/qwen3/latest".to_owned(),
            version: Some("latest".to_owned()),
            digest: Some(AssetDigest {
                algorithm: "sha256".to_owned(),
                value: "ab".repeat(32),
            }),
            source: "ollama-manifest".to_owned(),
            observed_at: UnixMillis(2_000),
        },
        InstalledAsset {
            kind: InstalledAssetKind::LocalModel,
            identity: "ollama:registry.ollama.ai/library/qwen3/latest".to_owned(),
            name: "qwen3".to_owned(),
            version: None,
            digest: None,
            source: "ollama-manifest".to_owned(),
            observed_at: UnixMillis(1_000),
        },
        InstalledAsset {
            kind: InstalledAssetKind::Skill,
            identity: "codex-skill-manifest:security review".to_owned(),
            name: "Security Review".to_owned(),
            version: Some("1".to_owned()),
            digest: None,
            source: "codex-skill-manifest".to_owned(),
            observed_at: UnixMillis(1_500),
        },
    ];

    let inventory = build_inventory_with_installed(&[], &Policy::default(), &evidence);
    assert_eq!(inventory.assets.len(), 2);
    assert!(inventory.relationships.is_empty());
    let model = inventory
        .assets
        .iter()
        .find(|asset| asset.kind == AssetKind::LocalModel)
        .ok_or_else(|| "local model missing".to_owned())?;
    assert_eq!(
        model.id.0,
        "urn:topgent:local_model:ollama%3Aregistry.ollama.ai%2Flibrary%2Fqwen3%2Flatest"
    );
    assert!(model.installed);
    assert!(!model.active);
    assert_eq!(model.first_seen, Some(UnixMillis(1_000)));
    assert_eq!(model.last_seen, Some(UnixMillis(2_000)));
    assert_eq!(model.version.as_deref(), Some("latest"));
    assert_eq!(
        model
            .digest
            .as_ref()
            .map(|digest| digest.algorithm.as_str()),
        Some("sha256")
    );
    Ok(())
}
