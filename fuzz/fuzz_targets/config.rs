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

    // The open-file listing, which names paths a process chose.
    let _ = topgent_collect::editor::parse_lsof_fields(text);

    // The policy file, which a person edits by hand.
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(text) {
        if let Ok(policy) = serde_json::from_value::<topgent_policy::Policy>(value.clone()) {
            // Whatever was in the file, what comes out has to be usable.
            for rule in &policy.watchlist {
                let _ = rule.condition.label();
                let _ = rule.response.as_str();
            }
        }
        // And the CI gate, which reads a report written by another build.
        for floor in [
            topgent_export::SeverityFloor::Low,
            topgent_export::SeverityFloor::Critical,
        ] {
            let _ = topgent_export::evaluate_report(&value, floor, true);
        }
    }
});
