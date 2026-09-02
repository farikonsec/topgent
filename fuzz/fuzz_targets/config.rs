//! Files and tool output read off the host: agent configuration, permission
//! rules, the policy, and the open-file listing.
//!
//! Every one of these is written by something other than Topgent. The policy is
//! edited by hand, an agent's configuration is written by the agent, and the
//! listing is the output of a tool reporting names processes chose.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };

    // A permission rule out of an agent's own configuration.
    if let Some((path, _access)) = topgent_collect::config::parse_permission_rule(text) {
        assert!(!path.is_empty(), "an empty path was accepted as a rule");
    }

    // The same rule read as a grant to run another agent. A second hop is
    // scored at 12 points, so a rule that names no agent must never produce a
    // family, and one that does must name a family the catalogue knows.
    if let Some(family) = topgent_collect::config::invoked_agent_family(text) {
        assert!(!family.is_empty(), "an empty family was returned as a hop");
        let known = topgent_collect::signatures::builtin()
            .map(|c| c.families.iter().any(|f| f.id == family))
            .unwrap_or(false);
        assert!(known, "a family outside the catalogue was returned: {family}");
    }

    // The open-file listing, which names paths a process chose.
    let _ = topgent_collect::editor::parse_lsof_fields(text);

    // The policy file, read as the bytes that actually arrive off disk: a hand
    // edit, a crash mid-write, PowerShell's byte-order mark, or a truncation.
    // Whatever comes back has to be usable, because losing the operator's rules
    // silently is the failure this boundary exists to prevent.
    if let Ok(policy) = topgent_policy::Policy::parse(data) {
        for rule in &policy.watchlist {
            let _ = rule.condition.label();
            let _ = rule.response.as_str();
        }
        // A policy is an object. Serde will otherwise fill a struct from a
        // JSON array positionally, and `[[0]]` produced a policy whose every
        // weight was zero, scoring every agent on the host at zero.
        let normalized = text.strip_prefix('\u{feff}').unwrap_or(text);
        assert!(
            serde_json::from_str::<serde_json::Value>(normalized)
                .is_ok_and(|value| value.is_object()),
            "a policy was parsed out of something that is not an object"
        );
    }

    // The policy file, which a person edits by hand.
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(text) {
        if let Ok(policy) = serde_json::from_value::<topgent_policy::Policy>(value.clone()) {
            // Whatever was in the file, what comes out has to be usable.
            for rule in &policy.watchlist {
                let _ = rule.condition.label();
                let _ = rule.response.as_str();
            }
        }
        // And the CI gate, which reads a report written by another build. The
        // coverage table it validates is the thing that decides whether a
        // pipeline opens, and `all()` on an empty array used to say yes.
        for floor in [
            topgent_export::SeverityFloor::Low,
            topgent_export::SeverityFloor::Critical,
        ] {
            if let Ok(result) = topgent_export::evaluate_report(&value, floor, true) {
                assert!(
                    !result.passed || result.coverage_complete,
                    "the gate passed a report whose coverage it could not complete"
                );
            }
        }
        // The same document with a coverage table spliced in, so the validator
        // is driven by input rather than only by the shape a real report has.
        if let Some(coverage) = value.get("coverage").cloned() {
            let spliced = serde_json::json!({
                "agents": [], "assets": [], "coverage": coverage
            });
            let _ = topgent_export::evaluate_report(
                &spliced,
                topgent_export::SeverityFloor::Critical,
                true,
            );
        }
    }
});
