//! The Actions panel: files an agent's processes opened and addresses they
//! connected to, each with the process that did it.
//!
//! Separate because its wording rules (a successful open is not bytes read, a
//! connect result is not an open socket, an unplaced record is nobody's) are
//! read and changed on their own.
use crate::{
    Message,
    report::{ActionRow, Report},
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
    let agent = selected.and_then(|pid| report.find_agent(pid));
    let rows = report
        .observed_actions
        .iter()
        .filter(|row| shown(row) && agent.is_none_or(|a| belongs(row, a.pid, a.started_at)))
        .map(|row| {
            table::Row::new(vec![
                table::Cell::new(crate::clock::stamp(row.at)),
                table::Cell::new(action_label(&row.action)),
                table::Cell::new(row.target.clone()),
                table::Cell::new(row.result.clone()),
                table::Cell::new(format!(
                    "{} ({})",
                    if row.actor_name.is_empty() {
                        "unknown"
                    } else {
                        &row.actor_name
                    },
                    row.actor_pid
                )),
                table::Cell::new(if row.actor_state.is_empty() {
                    "unresolved"
                } else {
                    &row.actor_state
                }),
            ])
            .detailed(vec![
                ("record".into(), format!("Linux Audit {}", row.record)),
                ("actor identity".into(), identity(row)),
                ("attribution".into(), chain(row)),
                ("meaning".into(), meaning(row).to_owned()),
            ])
        })
        .collect();
    // This tab lists Linux Audit records only. Where the eBPF sensor is the
    // source there is no Audit stream, so point to the tabs that carry what
    // eBPF saw for this agent rather than imply nothing happened.
    let has_flow = agent.is_some_and(|a| {
        report
            .agent_flows
            .iter()
            .any(|f| f.agent.pid == a.pid && f.agent.started_at == a.started_at)
    });
    let empty = if has_flow {
        "No Linux Audit records. File and network activity is in the Files and Network tabs."
    } else {
        "No Audit actions attributed to this agent. Check Audit rules and sensor coverage."
    };
    column![
        super::note(
            "Observed actions",
            format!(
                "{} Retention evictions: {}; measured queue losses this sweep: {}.",
                report.action_coverage.detail,
                report.action_coverage.evicted,
                report.action_coverage.queue_losses
            ),
            s
        ),
        table::view(
            table::Id::Actions,
            &ACTIONS,
            rows,
            &table::state_of(t, table::Id::Actions),
            empty,
            s
        ),
    ]
    .into()
}

pub(super) static ACTIONS: [table::Column2; 6] = [
    table::Column2::text("TIME", 3),
    table::Column2::text("ACTION", 3),
    table::Column2::text("TARGET", 6),
    table::Column2::text("RESULT", 2),
    table::Column2::text("DIRECT ACTOR", 3),
    table::Column2::text("STATE", 2),
];
/// Which process acted: its pid, and the run of it the action was pinned on.
fn identity(row: &ActionRow) -> String {
    row.actor_started_at.map_or_else(
        || format!("pid {} (run unknown)", row.actor_pid),
        |started| {
            format!(
                "pid {}, started {}",
                row.actor_pid,
                crate::clock::stamp(started)
            )
        },
    )
}

/// Whether a row is shown. An exec's Audit record also lists the program and
/// the dynamic loader as executed paths; the exec row already says it.
fn shown(row: &ActionRow) -> bool {
    row.action != "execute"
}

fn belongs(row: &ActionRow, pid: u32, started: u64) -> bool {
    row.agent_pid == Some(pid) && row.agent_started_at == Some(started)
}

fn action_label(action: &str) -> &str {
    match action {
        "read" => "open/read",
        "write" => "open/write",
        "read_write" => "open/read-write",
        other => other,
    }
}

/// The chain from the agent down to the process that acted.
fn chain(row: &ActionRow) -> String {
    row.agent_pid.map_or_else(
        || "Unattributed".into(),
        |pid| {
            let mut parts = vec![format!("agent {pid}")];
            parts.extend(row.chain.iter().map(u32::to_string));
            parts.join(" → ")
        },
    )
}

/// What the row does and does not establish.
fn meaning(row: &ActionRow) -> &'static str {
    match row.action.as_str() {
        "read" | "write" | "read_write" => "File opened. Contents and bytes not recorded.",
        "connect" | "send" => "Syscall result only. Delivery not confirmed.",
        _ => "Recorded by a Linux Audit rule.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reused_agent_pid_cannot_select_the_old_agents_actions() {
        let row = ActionRow {
            agent_pid: Some(4),
            agent_started_at: Some(10),
            ..ActionRow::default()
        };
        assert!(belongs(&row, 4, 10));
        assert!(!belongs(&row, 4, 11));
    }
    /// The expanded row read `start Some(1790176453840)`.
    #[test]
    fn an_actor_is_named_by_pid_and_readable_start() {
        let resolved = ActionRow {
            actor_pid: 11,
            actor_started_at: Some(0),
            ..ActionRow::default()
        };
        assert!(
            !identity(&resolved).contains("Some"),
            "{}",
            identity(&resolved)
        );
        assert!(identity(&resolved).starts_with("pid 11, started "));
        let unresolved = ActionRow {
            actor_pid: 11,
            ..ActionRow::default()
        };
        assert_eq!(identity(&unresolved), "pid 11 (run unknown)");
    }

    /// One exec is one row: the program and loader path records of the same
    /// syscall are not shown again as separate executes.
    #[test]
    fn an_exec_is_listed_once() {
        let execute = ActionRow {
            action: "execute".into(),
            ..ActionRow::default()
        };
        let exec = ActionRow {
            action: "exec".into(),
            ..ActionRow::default()
        };
        assert!(!shown(&execute));
        assert!(shown(&exec));
    }

    #[test]
    fn unknown_attribution_and_syscall_limits_are_visible() {
        let row = ActionRow {
            action: "connect".into(),
            result: "failed".into(),
            ..ActionRow::default()
        };
        assert!(chain(&row).starts_with("Unattributed"));
        assert!(meaning(&row).contains("Delivery not confirmed"));
        assert_eq!(action_label("read"), "open/read");
    }
}
