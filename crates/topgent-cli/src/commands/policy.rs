//! `topgent policy` — the CI gate. Exit codes are the contract; see USAGE.

use crate::output::option_value;

pub(crate) fn policy_command(args: &[String]) -> i32 {
    if args.get(1).map(String::as_str) == Some("lint") {
        return lint_command(args);
    }
    if args.get(1).map(String::as_str) != Some("check") {
        eprintln!(
            "topgent policy check [--input REPORT] [--policy POLICY] [--threshold critical|high|medium|low] [--require-coverage] [--json]"
        );
        eprintln!("topgent policy lint [--sensors NAME,NAME] [--json]");
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

/// Reports what is wrong with the rule catalogue short of refusing to load it.
///
/// Deliberately a separate subcommand from `check`. `check` is the CI gate and
/// its exit codes are a contract; a new class of complaint must not start
/// failing somebody's pipeline because they upgraded. This one reports and
/// exits zero unless a warning was found.
///
/// Exit codes: `0` nothing to report, `1` warnings found, `2` the catalogue
/// would not load at all.
fn lint_command(args: &[String]) -> i32 {
    let catalogue = match topgent_policy::catalogue::builtin() {
        Ok(catalogue) => catalogue,
        Err(error) => {
            eprintln!("topgent policy lint: the built-in catalogue is unusable: {error}");
            return 2;
        }
    };
    // Absent means "not checked", never "everything works". A sensor list that
    // defaulted to empty would report every factor as unavailable, and one that
    // defaulted to full would report none.
    let sensors: Option<Vec<String>> = option_value(args, "--sensors").map(|value| {
        value
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_owned)
            .collect()
    });
    let policy = topgent_policy::Policy::default();
    let warnings = topgent_policy::lint::lint(catalogue, &policy.thresholds, sensors.as_deref());

    if args.iter().any(|argument| argument == "--json") {
        let rows: Vec<serde_json::Value> = warnings
            .iter()
            .map(|warning| {
                serde_json::json!({
                    "code": warning.code.as_str(),
                    "factor": warning.factor,
                    "index": warning.index,
                    "label": warning.code.label(),
                    "detail": warning.detail,
                    "impact": warning.code.impact(),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::json!({
                "catalogue_source": catalogue.source,
                "schema_version": catalogue.schema_version,
                "factor_count": catalogue.factors.len(),
                "sensors_checked": sensors.is_some(),
                "warnings": rows,
            })
        );
    } else if warnings.is_empty() {
        println!("{} factors, nothing to report", catalogue.factors.len());
        if sensors.is_none() {
            println!("sensor availability was not checked; pass --sensors to include it");
        }
    } else {
        for warning in &warnings {
            println!("{warning}");
            println!("    {}", warning.code.impact());
        }
        println!();
        println!(
            "{} warning(s) across {} factors",
            warnings.len(),
            catalogue.factors.len()
        );
    }

    i32::from(!warnings.is_empty())
}
