//! `topgent replay` — score a bundle without touching the host it came from.
//!
//! A report describes a machine at a moment. A bundle *is* that moment, kept.
//! Replay folds the recorded facts through the same risk model the live path
//! uses and prints the findings, so a decision can be re-examined on another
//! machine, weeks later, by someone who does not have access to the original
//! host and should not need it.
//!
//! No collector runs here and no sensor is opened. The only inputs are the
//! bundle and the policy, and both are named in the output, because a finding
//! that cannot say which rules produced it is not reproducible.

use topgent_evidence::{Bundle, Reader};
use topgent_policy::Policy;

use crate::output::option_value;

const USAGE: &str = "\
topgent replay <bundle>                  score a bundle with the policy in force
topgent replay <bundle> --policy PATH    score it with a specific policy

topgent replay <bundle> --candidate PATH
    what a candidate policy would have decided differently, against the same
    evidence. No sensor is opened and no response is executed.

Exit codes: 0 replayed, 1 the candidate changes something, 2 unusable input.
";

pub(crate) fn replay_command(args: &[String]) -> i32 {
    let Some(path) = args.get(1).filter(|value| !value.starts_with("--")) else {
        eprint!("{USAGE}");
        return 2;
    };
    let bundle = match load(path) {
        Ok(bundle) => bundle,
        Err(error) => {
            eprintln!("topgent replay: {error}");
            return 2;
        }
    };
    let policy_path =
        option_value(args, "--policy").map_or_else(Policy::path, std::path::PathBuf::from);
    let (policy, _health) = Policy::load_checked(&policy_path);

    let Some(candidate_path) = option_value(args, "--candidate") else {
        println!("{}", topgent_report::replay(&bundle, &policy));
        return 0;
    };
    let candidate = match load_policy(candidate_path) {
        Ok(candidate) => candidate,
        Err(error) => {
            eprintln!("topgent replay: --candidate: {error}");
            return 2;
        }
    };
    let diff = topgent_report::simulate(&bundle, &policy, &candidate);
    let changed = diff
        .get("agents_changed")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    println!("{diff}");
    // A candidate that changes nothing and a candidate that changes something
    // are different answers, and a script needs to tell them apart without
    // parsing the output.
    i32::from(changed > 0)
}

/// Reads a candidate policy, validating its exceptions rather than trusting them.
fn load_policy(path: &str) -> Result<Policy, String> {
    let text = std::fs::read_to_string(path).map_err(|error| format!("{path}: {error}"))?;
    let policy: Policy = serde_json::from_str(&text).map_err(|error| format!("{path}: {error}"))?;
    for exception in &policy.exceptions {
        exception
            .validate()
            .map_err(|error| format!("{path}: {error}"))?;
    }
    Ok(policy)
}

/// Reads a bundle, running every construction rule again on the way in.
fn load(path: &str) -> Result<Bundle, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("{path}: {error}"))?;
    Reader::read::<Bundle>(&bytes).map_err(|error| format!("{path}: {error}"))
}
