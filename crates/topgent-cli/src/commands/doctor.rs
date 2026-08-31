//! `topgent doctor` — what each sensor can see on this machine, and what it cannot.

/// Probe sensor health using the same report contract as the dashboard.
pub(crate) fn doctor_command(args: &[String]) -> i32 {
    let report = topgent_report::scan();
    let platform = report.get("platform");
    let sensors = report.get("sensors").and_then(serde_json::Value::as_array);
    let coverage = report.get("coverage").and_then(serde_json::Value::as_array);
    if args.iter().any(|argument| argument == "--json") {
        println!(
            "{}",
            serde_json::json!({
                "platform": platform,
                "sensors": sensors,
                "coverage": coverage,
            })
        );
    } else {
        let os = platform
            .and_then(|value| value.get("os"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        let arch = platform
            .and_then(|value| value.get("arch"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        println!("Topgent sensor health — {os}/{arch}\n");
        for sensor in sensors.into_iter().flatten() {
            println!(
                "  {:<20} {:<20} {}",
                sensor
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown"),
                sensor
                    .get("state")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("error")
                    .replace('_', " "),
                sensor
                    .get("detail")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("")
            );
        }
        let covered = coverage.map_or(0, |items| {
            items
                .iter()
                .filter(|item| {
                    item.get("state").and_then(serde_json::Value::as_str) == Some("available")
                })
                .count()
        });
        let total = coverage.map_or(0, Vec::len);
        println!("\n  {covered}/{total} rules have their required current sensor.");
    }
    let essential = ["process", "socket", "config", "reach"];
    let unhealthy = sensors.is_none_or(|sensors| {
        essential.iter().any(|required| {
            !sensors.iter().any(|sensor| {
                sensor.get("id").and_then(serde_json::Value::as_str) == Some(*required)
                    && sensor.get("state").and_then(serde_json::Value::as_str) == Some("available")
            })
        })
    });
    i32::from(unhealthy)
}
