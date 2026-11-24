//! The Behaviour panel: runtime rules that held, and on which process.
//!
//! Separate because its wording rules are its own: a finding says a rule's
//! condition held on one event, not that an attack happened; a rule this host
//! cannot feed belongs in Coverage; and a finding with no agent above it is a
//! host finding, not nobody's.

use crate::{
    Message,
    report::{Finding, Report, RuleState},
    table::{self, Tables},
    theme::Style,
};
use iced::{Element, widget::column};

pub(super) fn view<'a>(
    report: &'a Report,
    selected: Option<u32>,
    t: &'a Tables,
    s: Style,
) -> Element<'a, Message> {
    let behaviour = &report.behaviour;
    let agent = selected.and_then(|pid| report.find_agent(pid));
    let findings = behaviour
        .findings
        .iter()
        .filter(|f| agent.is_none_or(|a| f.belongs_to(a.pid, a.started_at)))
        .map(|f| finding_row(report, f, rule_of(report, &f.rule), s))
        .collect();
    column![
        super::note(summary(report), limits(report), s),
        table::view(
            table::Id::Findings,
            &FINDINGS,
            findings,
            &table::state_of(t, table::Id::Findings),
            if agent.is_some() {
                "No behaviour rule has held on this agent or its descendants."
            } else {
                "No behaviour rule has held on this host."
            },
            s
        ),
    ]
    .into()
}

pub(super) static FINDINGS: [table::Column2; 7] = [
    table::Column2::text("LAST SEEN", 3),
    table::Column2::text("RULE", 5),
    table::Column2::text("PRIORITY", 2),
    table::Column2::text("TARGET", 3).mono(),
    table::Column2::text("AGENT", 3),
    table::Column2::text("DIRECT ACTOR", 3),
    table::Column2::text("COUNT", 1).number(),
];

pub(super) static RULES: [table::Column2; 4] = [
    table::Column2::text("RULE", 7),
    table::Column2::text("MATURITY", 2),
    table::Column2::text("PRIORITY", 2),
    table::Column2::text("STATE", 4),
];

fn rule_of<'a>(report: &'a Report, name: &str) -> Option<&'a RuleState> {
    report
        .behaviour
        .catalogue
        .coverage
        .iter()
        .find(|r| r.rule == name)
}

/// The heading: what happened, without mixing in capability counts.
fn summary(report: &Report) -> String {
    let count = report.behaviour.findings.len();
    format!(
        "{count} behaviour finding{} on this host",
        if count == 1 { "" } else { "s" }
    )
}

/// The sentence under it: what was read this sweep and the limits of the stream.
fn limits(report: &Report) -> String {
    let b = &report.behaviour;
    format!(
        "{} rules enabled \u{b7} {} syscall events this sweep \u{b7} {} dropped \u{b7} {} evicted",
        b.catalogue.enabled, b.syscall_events, b.syscall_queue_losses, b.evicted,
    )
}

fn finding_row(report: &Report, f: &Finding, rule: Option<&RuleState>, s: Style) -> table::Row {
    let owner = owner(report, f);
    // The short plain line: the finding's own summary, then the rule's, then
    // any longer explanation, then the technical description.
    let plain = [
        f.summary.as_str(),
        rule.map_or("", |r| r.summary.as_str()),
        f.explanation.as_str(),
    ]
    .into_iter()
    .find(|t| !t.is_empty())
    .unwrap_or_else(|| rule.map_or("Not in this build's catalogue.", |r| r.desc.as_str()))
    .to_owned();
    let mut detail = vec![("what it means".into(), plain.clone())];
    // The honest longer context (e.g. "does not establish…"), when it adds to
    // the short line rather than repeating it.
    if !f.explanation.is_empty() && f.explanation != plain {
        detail.push(("context".into(), f.explanation.clone()));
    }
    detail.extend([
        ("tags".into(), f.tags.join(", ")),
        ("where".into(), where_it_ran(&f.container)),
        ("event".into(), event(f)),
        ("first seen".into(), crate::clock::stamp(f.at)),
        ("actor identity".into(), identity(f)),
        ("attribution".into(), chain(f, owner.as_deref())),
    ]);
    table::Row::new(vec![
        table::Cell::new(crate::clock::stamp(f.last_at.max(f.at))),
        table::Cell::new(f.rule.clone()),
        table::Cell::tinted(f.priority.clone(), tone(&f.priority, s)),
        table::Cell::path(f.target.clone()),
        owner.map_or_else(
            || table::Cell::tinted("host", s.palette.faint),
            table::Cell::new,
        ),
        table::Cell::new(actor(f)),
        table::Cell::new(f.count.max(1).to_string()),
    ])
    .detailed(detail)
}

pub(super) fn rule_row(r: &RuleState, s: Style) -> table::Row {
    let p = s.palette;
    let state = state(r);
    table::Row::new(vec![
        table::Cell::new(r.rule.clone()),
        table::Cell::new(r.maturity.clone()),
        table::Cell::tinted(r.priority.clone(), tone(&r.priority, s)),
        if r.live && r.enabled {
            table::Cell::tinted(state, p.low)
        } else {
            table::Cell::tinted(state, p.faint)
        },
    ])
    .detailed(vec![
        (
            "what it means".into(),
            if r.summary.is_empty() {
                r.desc.clone()
            } else {
                r.summary.clone()
            },
        ),
        (
            "fields this host lacks".into(),
            if r.needs.is_empty() {
                "None".to_owned()
            } else {
                r.needs.join(", ")
            },
        ),
    ])
}

/// Whether a rule can fire here, and if not, the first thing it lacks.
fn state(r: &RuleState) -> String {
    match (r.live, r.enabled, r.needs.as_slice()) {
        (true, true, _) => "Live".to_owned(),
        (true, false, _) => "Live, off as shipped".to_owned(),
        (false, _, []) => "Cannot fire here".to_owned(),
        (false, _, [one]) => format!("Needs {one}"),
        (false, _, [first, rest @ ..]) => format!("Needs {first} +{}", rest.len()),
    }
}

fn actor(f: &Finding) -> String {
    format!(
        "{} ({})",
        if f.actor_name.is_empty() {
            "unknown"
        } else {
            &f.actor_name
        },
        f.actor_pid
    )
}

/// Whether a finding happened on the host or inside a container.
fn where_it_ran(container: &str) -> String {
    match container {
        "" => "not established".to_owned(),
        "host" => "host".to_owned(),
        id => format!("container {id}"),
    }
}

fn event(f: &Finding) -> String {
    match f.source.as_str() {
        "audit" => format!("Linux Audit {}", f.record),
        "ebpf" => format!("A syscall Topgent's eBPF probe saw, {}", f.record),
        _ => "An exec the process sensor saw".to_owned(),
    }
}

fn identity(f: &Finding) -> String {
    f.actor_started_at.map_or_else(
        || format!("pid {} (run unknown)", f.actor_pid),
        |started| {
            format!(
                "pid {}, started {}",
                f.actor_pid,
                crate::clock::stamp(started)
            )
        },
    )
}

/// The chain from the agent down to the process that acted.
/// The agent a finding belongs to, with its model: `opencode ·
/// glm-4.7-flash`. `None` for a host finding, whose actor no agent started.
fn owner(report: &Report, f: &Finding) -> Option<String> {
    let pid = f.agent_pid?;
    Some(report.run_name(pid, f.agent_started_at, &f.agent_name))
}

fn chain(f: &Finding, owner: Option<&str>) -> String {
    f.agent_pid.map_or_else(
        || "Host finding: no agent in the actor's ancestry".into(),
        |pid| {
            let agent = format!("{} {pid}", owner.unwrap_or("agent"));
            let mut parts = vec![agent];
            parts.extend(f.chain.iter().map(u32::to_string));
            parts.join(" → ")
        },
    )
}

/// Worst first.
pub(super) fn rank(priority: &str) -> u8 {
    match priority {
        "EMERGENCY" => 0,
        "ALERT" => 1,
        "CRITICAL" => 2,
        "ERROR" => 3,
        "WARNING" => 4,
        "NOTICE" => 5,
        "INFORMATIONAL" | "INFO" => 6,
        _ => 7,
    }
}

fn tone(priority: &str, s: Style) -> iced::Color {
    let p = s.palette;
    match rank(priority) {
        0..=2 => p.critical,
        3 => p.high,
        4 => p.medium,
        5 => p.low,
        _ => p.faint,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(live: bool, enabled: bool, needs: &[&str]) -> RuleState {
        RuleState {
            live,
            enabled,
            needs: needs.iter().map(|n| (*n).to_owned()).collect(),
            ..RuleState::default()
        }
    }

    /// A rule this host cannot feed is never shown as watching.
    #[test]
    fn a_rule_is_live_only_when_every_field_is_supplied() {
        assert_eq!(state(&rule(true, true, &[])), "Live");
        assert_eq!(state(&rule(true, false, &[])), "Live, off as shipped");
        assert_eq!(
            state(&rule(false, true, &["container.id"])),
            "Needs container.id"
        );
        assert_eq!(
            state(&rule(
                false,
                true,
                &["proc.vpid", "fd.l4proto", "k8s.ns.name"]
            )),
            "Needs proc.vpid +2"
        );
    }

    #[test]
    fn a_finding_without_an_agent_is_a_host_finding() {
        let report = Report::default();
        let host = Finding::default();
        assert!(chain(&host, owner(&report, &host).as_deref()).starts_with("Host finding"));
        assert_eq!(owner(&report, &host), None);
        let placed = Finding {
            agent_pid: Some(10),
            chain: vec![11, 12],
            ..Finding::default()
        };
        assert_eq!(
            chain(&placed, owner(&report, &placed).as_deref()),
            "agent 10 → 11 → 12"
        );
        let named = Finding {
            agent_name: "opencode".into(),
            agent_started_at: Some(5),
            ..placed
        };
        assert_eq!(
            chain(&named, owner(&report, &named).as_deref()),
            "OpenCode 10 → 11 → 12"
        );
        // With the run in the report, its model is named too.
        let report = Report {
            ended_agents: vec![crate::report::Agent {
                pid: 10,
                started_at: 5,
                family: Some("opencode".into()),
                model: Some("openrouter/z-ai/glm-4.7-flash".into()),
                ..crate::report::Agent::default()
            }],
            ..Report::default()
        };
        assert_eq!(
            owner(&report, &named).as_deref(),
            Some("OpenCode \u{b7} glm-4.7-flash")
        );
    }

    #[test]
    fn priorities_order_worst_first_and_unknown_last() {
        let mut p = ["NOTICE", "CRITICAL", "whatever", "WARNING", "ERROR"];
        p.sort_by_key(|x| rank(x));
        assert_eq!(p, ["CRITICAL", "ERROR", "WARNING", "NOTICE", "whatever"]);
    }

    #[test]
    fn the_heading_counts_findings_not_capabilities() {
        let mut report = Report::default();
        assert_eq!(summary(&report), "0 behaviour findings on this host");
        report.behaviour.findings.push(Finding::default());
        assert_eq!(summary(&report), "1 behaviour finding on this host");
    }

    #[test]
    fn an_actor_is_named_by_pid_and_readable_start() {
        let f = Finding {
            actor_pid: 11,
            actor_started_at: Some(0),
            ..Finding::default()
        };
        assert!(identity(&f).starts_with("pid 11, started "));
        assert!(!identity(&f).contains("Some"));
        assert_eq!(actor(&Finding::default()), "unknown (0)");
    }
}
