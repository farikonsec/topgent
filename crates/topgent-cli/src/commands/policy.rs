//! `topgent policy` — the CI gate. Exit codes are the contract; see USAGE.

use crate::output::option_value;

pub(crate) fn policy_command(args: &[String]) -> i32 {
    if args.get(1).map(String::as_str) != Some("check") {
        eprintln!(
            "topgent policy check [--input REPORT] [--policy POLICY] [--threshold critical|high|medium|low] [--require-coverage] [--json]"
        );
        return 2;
    }
    let floor_text = option_value(args, "--threshold").unwrap_or("critical");
    let Some(floor) = topgent_export::SeverityFloor::parse(floor_text) else {
        eprintln!("topgent policy check: invalid threshold {floor_text}");
        return 2;
    };
    let mut report = match policy_input(args) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("topgent policy check: {error}");
            return 2;
        }
    };
    if let Some(path) = option_value(args, "--policy") {
        let policy = match std::fs::read_to_string(path)
            .map_err(|error| error.to_string())
            .and_then(|text| {
                serde_json::from_str::<topgent_policy::Policy>(
                    topgent_export::without_byte_order_mark(&text),
                )
                .map_err(|error| error.to_string())
            }) {
            Ok(policy) => policy,
            Err(error) => {
                eprintln!("topgent policy check: invalid policy: {error}");
                return 2;
            }
        };
        let Some(assets) = report
            .get_mut("assets")
            .and_then(serde_json::Value::as_array_mut)
        else {
            eprintln!("topgent policy check: input has no assets array");
            return 2;
        };
        for asset in assets {
            let Some(id) = asset
                .get("id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
            else {
                eprintln!("topgent policy check: asset has no valid id");
                return 2;
            };
            asset["disposition"] =
                serde_json::Value::String(policy.asset_disposition(&id, None).label().to_owned());
        }
    }
    let require_coverage = args.iter().any(|argument| argument == "--require-coverage");
    let result = match topgent_export::evaluate_report(&report, floor, require_coverage) {
        Ok(result) => result,
        Err(error) => {
            eprintln!("topgent policy check: {error}");
            return 2;
        }
    };
    if args.iter().any(|argument| argument == "--json") {
        match serde_json::to_string(&result) {
            Ok(value) => println!("{value}"),
            Err(error) => {
                eprintln!("topgent policy check: {error}");
                return 2;
            }
        }
    } else if result.violations.is_empty() {
        println!("Policy check passed: no violations found.");
    } else {
        println!(
            "Policy check found {} violation(s):",
            result.violations.len()
        );
        for violation in &result.violations {
            println!(
                "  {} {} — {}",
                violation.code, violation.subject, violation.message
            );
        }
    }
    if require_coverage && !result.coverage_complete {
        if !args.iter().any(|argument| argument == "--json") {
            eprintln!("Required detection coverage is unavailable.");
        }
        3
    } else {
        i32::from(!result.violations.is_empty())
    }
}

/// The report a policy check runs against: a named file, a discovered one, or
/// a fresh scan of this host.
pub(crate) fn policy_input(args: &[String]) -> Result<serde_json::Value, String> {
    let discovered = std::path::Path::new("topgent-report.json");
    let path = option_value(args, "--input")
        .map(std::path::Path::new)
        .or_else(|| discovered.is_file().then_some(discovered));
    let Some(path) = path else {
        return Ok(topgent_report::scan());
    };
    let text = std::fs::read_to_string(path).map_err(|error| error.to_string())?;
    serde_json::from_str(topgent_export::without_byte_order_mark(&text))
        .map_err(|error| error.to_string())
}
