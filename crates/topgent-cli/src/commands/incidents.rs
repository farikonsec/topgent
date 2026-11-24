//! `topgent incidents` — what an agent did that a person needs to know about,
//! in sentences.
//!
//!   topgent incidents                      one sweep, then the incidents
//!   topgent incidents --watch [--every MS] keep sweeping; print each new or
//!                                          grown incident as it appears
//!   topgent incidents --json               the incidents as JSON
//!
//! Each incident is printed the way it should be read: what happened, why it
//! matters, what to do, then the numbers behind it and what they cannot show.

use serde_json::Value;
use std::collections::BTreeMap;

use crate::style::Ink;

/// Print the incidents.
pub(crate) fn incidents_command(args: &[String]) -> i32 {
    let every: u64 = args
        .iter()
        .position(|a| a == "--every")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(1_000);
    let json = args.iter().any(|a| a == "--json");
    let ink = Ink::decide();
    if !args.iter().any(|a| a == "--watch") {
        let report = topgent_report::scan();
        if json {
            println!("{}", report.get("incidents").unwrap_or(&Value::Null));
        } else {
            print_all(&report, ink);
        }
        return 0;
    }
    // One process across sweeps, so one running sensor: the totals behind an
    // incident are kept by it.
    let mut shown: BTreeMap<String, String> = BTreeMap::new();
    let mut coverage_state = String::new();
    loop {
        let report = topgent_report::scan();
        // Reprint coverage whenever it changes, so the shift from degraded
        // (sensor warming up) to available is visible, not just sweep one.
        let state = report
            .get("incident_coverage")
            .and_then(|c| c.get("state"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        if state != coverage_state {
            print_coverage(&report, ink);
            coverage_state = state;
        }
        for incident in rows(&report) {
            let id = text(incident, "id").to_owned();
            let headline = text(incident, "headline").to_owned();
            if shown.get(&id) == Some(&headline) {
                continue;
            }
            if json {
                println!("{incident}");
            } else {
                print_incident(incident, ink, shown.contains_key(&id));
            }
            shown.insert(id, headline);
        }
        std::thread::sleep(std::time::Duration::from_millis(every.max(200)));
    }
}

fn rows(report: &Value) -> Vec<&Value> {
    let mut rows: Vec<&Value> = report
        .get("incidents")
        .and_then(Value::as_array)
        .map(|r| r.iter().collect())
        .unwrap_or_default();
    rows.sort_by_key(|r| r.get("first_seen").and_then(Value::as_u64).unwrap_or(0));
    rows
}

fn text<'a>(value: &'a Value, field: &str) -> &'a str {
    value.get(field).and_then(Value::as_str).unwrap_or("")
}

fn print_coverage(report: &Value, ink: Ink) {
    let coverage = report.get("incident_coverage").unwrap_or(&Value::Null);
    let state = text(coverage, "state");
    let line = format!(
        "  Workspace exfiltration: {state}. {}",
        text(coverage, "detail")
    );
    println!(
        "{}",
        if state == "available" {
            ink.faint(&line)
        } else {
            ink.warn(&line)
        }
    );
}

fn print_all(report: &Value, ink: Ink) {
    print_coverage(report, ink);
    let rows = rows(report);
    if rows.is_empty() {
        println!("\n  No incidents.\n");
        return;
    }
    for incident in rows {
        print_incident(incident, ink, false);
    }
}

fn print_incident(incident: &Value, ink: Ink, grown: bool) {
    let severity = text(incident, "severity").to_ascii_uppercase();
    let label = if grown {
        "STILL GOING"
    } else {
        severity.as_str()
    };
    println!();
    println!(
        "  {}  {}",
        ink.as_grade(&severity, &format!("[{label}]")),
        ink.heading(text(incident, "headline"))
    );
    for why in incident
        .get("why")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        println!("      {why}");
    }
    let actions: Vec<&Value> = incident
        .get("actions")
        .and_then(Value::as_array)
        .map(|a| a.iter().collect())
        .unwrap_or_default();
    if !actions.is_empty() {
        println!("\n    {}", ink.heading("What to do"));
        for (n, action) in actions.iter().enumerate() {
            let command = text(action, "command");
            if command.is_empty() {
                println!("      {}. {}", n + 1, text(action, "label"));
            } else {
                println!(
                    "      {}. {}   {}",
                    n + 1,
                    text(action, "label"),
                    ink.faint(command)
                );
            }
        }
    }
    print_evidence(incident, ink);
    for limit in incident
        .get("limits")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        println!("      {}", ink.faint(&format!("limit: {limit}")));
    }
}

fn print_evidence(incident: &Value, ink: Ink) {
    let agent = incident.get("agent").unwrap_or(&Value::Null);
    let pid = agent.get("pid").and_then(Value::as_u64).unwrap_or(0);
    let evidence = incident.get("evidence").unwrap_or(&Value::Null);
    println!("\n    {}", ink.heading("Evidence"));
    if let Some(ws) = evidence.get("workspace") {
        let top: Vec<String> = ws
            .get("top_directories")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|d| {
                format!(
                    "{} ({})",
                    text(d, "directory"),
                    d.get("files").and_then(Value::as_u64).unwrap_or(0)
                )
            })
            .collect();
        println!(
            "      read      {} files under {}{}",
            ws.get("files").and_then(Value::as_u64).unwrap_or(0),
            text(ws, "root"),
            if top.is_empty() {
                String::new()
            } else {
                format!(", most from {}", top.join(", "))
            }
        );
    }
    for dest in evidence
        .get("destinations")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(5)
    {
        let n = |f: &str| dest.get(f).and_then(Value::as_u64).unwrap_or(0);
        let name = dest.get("name").and_then(Value::as_str).unwrap_or("");
        println!(
            "      sent to   {}:{}{}  {} attempts ({} failed), {} bytes",
            text(dest, "address"),
            n("port"),
            if name.is_empty() {
                String::new()
            } else {
                format!(" ({name})")
            },
            n("attempts"),
            n("failed"),
            n("bytes"),
        );
    }
    for finding in evidence
        .get("findings")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(8)
    {
        let times = finding.get("count").and_then(Value::as_u64).unwrap_or(1);
        println!(
            "      rule      {}: {} by {} ({}){}",
            text(finding, "rule"),
            text(finding, "target"),
            text(finding, "actor_name"),
            finding
                .get("actor_pid")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            if times > 1 {
                format!(", {times} times")
            } else {
                String::new()
            }
        );
    }
    let numbers = incident.get("numbers").unwrap_or(&Value::Null);
    println!(
        "      over      {}, by {} {} pid {pid}, processes {}",
        text(numbers, "duration"),
        text(agent, "name"),
        if agent.get("recognised").and_then(Value::as_bool) == Some(true) {
            "agent"
        } else {
            "(not a recognised agent)"
        },
        evidence
            .get("processes")
            .and_then(Value::as_array)
            .map(|p| p
                .iter()
                .filter_map(Value::as_u64)
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", "))
            .unwrap_or_default()
    );
}
