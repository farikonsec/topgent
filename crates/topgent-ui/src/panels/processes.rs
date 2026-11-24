//! The Processes panel: every process an agent started, including those that
//! have exited.
//!
//! Separate because its wording rules (gone against exited, what the kernel
//! saw, an exec whose program could not be read) are read and changed on
//! their own.

use crate::Message;
use crate::report::{ProcessRow, Report};
use crate::table::{self, Tables};
use crate::theme::Style;
use iced::Element;

pub(super) fn view<'a>(
    report: &'a Report,
    selected: Option<u32>,
    t: &'a Tables,
    s: Style,
) -> Element<'a, Message> {
    let mine: Vec<&ProcessRow> = report
        .process_history
        .iter()
        .filter(|row| selected.is_none_or(|pid| row.agent_pid == pid))
        .collect();
    let rows = tree_order(&mine)
        .into_iter()
        .map(|row| {
            let findings = findings_of(report, row);
            let state = match row.state.as_str() {
                "running" => table::Cell::new("running"),
                _ => table::Cell::tinted(state_word(row), s.palette.muted),
            };
            table::Row::new(vec![
                // Indented under its parent, so the list reads as the tree the
                // agent grew rather than a heap of pids.
                table::Cell::new(format!(
                    "{}{}",
                    "  ".repeat(row.depth.saturating_sub(1) as usize),
                    if row.depth > 0 {
                        format!("\u{2514} {}", name_cell(row))
                    } else {
                        name_cell(row)
                    }
                )),
                table::Cell::new(row.pid.to_string()),
                row.parent_pid.map_or_else(
                    || table::Cell::tinted("-", s.palette.faint),
                    |parent| table::Cell::new(parent_label(&mine, parent)),
                ),
                state,
                table::Cell::new(crate::clock::stamp(row.started_at)),
                table::Cell::new(ran_for(row)),
                if findings.is_empty() {
                    table::Cell::tinted("-", s.palette.faint)
                } else {
                    table::Cell::tinted(findings.len().to_string(), s.palette.high)
                },
            ])
            .detailed(vec![
                (
                    "program".to_owned(),
                    row.exe.clone().unwrap_or_else(|| program_line(row)),
                ),
                (
                    "identity".to_owned(),
                    format!(
                        "pid {} started {}",
                        row.pid,
                        crate::clock::stamp(row.started_at)
                    ),
                ),
                ("lineage".to_owned(), lineage_line(row)),
                ("state".to_owned(), state_meaning(row)),
                (
                    "behaviour".to_owned(),
                    if findings.is_empty() {
                        "no behaviour rule held on this process".to_owned()
                    } else {
                        findings.join("; ")
                    },
                ),
                (
                    "adopted".to_owned(),
                    if row.reparented {
                        "yes: re-parented after its parent ended; still attributed to it".to_owned()
                    } else {
                        "no".to_owned()
                    },
                ),
                (
                    "namespace".to_owned(),
                    if row.crossed_namespace {
                        "runs in a different pid namespace from its parent".to_owned()
                    } else {
                        "same as its parent, or not readable".to_owned()
                    },
                ),
                ("seen by".to_owned(), seen_by(row)),
            ])
        })
        .collect();
    table::view(
        table::Id::Processes,
        &PROCESSES,
        rows,
        &table::state_of(t, table::Id::Processes),
        "No process history recorded for this agent yet.",
        s,
    )
}

pub(super) static PROCESSES: [table::Column2; 7] = [
    table::Column2::text("PROCESS", 5),
    table::Column2::text("PID", 2).number().mono(),
    table::Column2::text("PARENT", 3),
    table::Column2::text("STATE", 3),
    table::Column2::text("STARTED", 3),
    table::Column2::text("RAN FOR", 2).number(),
    table::Column2::text("FINDINGS", 2).number(),
];

/// Each agent's processes as a tree: every process after its parent, the
/// earliest started first at each level.
fn tree_order<'a>(rows: &[&'a ProcessRow]) -> Vec<&'a ProcessRow> {
    let mut ordered = Vec::with_capacity(rows.len());
    let mut placed = std::collections::HashSet::new();
    let mut roots: Vec<&ProcessRow> = rows
        .iter()
        .copied()
        .filter(|r| {
            r.parent_pid.is_none_or(|parent| {
                !rows
                    .iter()
                    .any(|o| o.pid == parent && o.agent_pid == r.agent_pid)
            })
        })
        .collect();
    roots.sort_by_key(|r| (r.agent_pid, r.started_at, r.pid));
    let mut stack: Vec<&ProcessRow> = roots.into_iter().rev().collect();
    while let Some(row) = stack.pop() {
        if !placed.insert((row.pid, row.started_at)) {
            continue;
        }
        ordered.push(row);
        let mut children: Vec<&ProcessRow> = rows
            .iter()
            .copied()
            .filter(|c| c.parent_pid == Some(row.pid) && c.agent_pid == row.agent_pid)
            .filter(|c| !placed.contains(&(c.pid, c.started_at)))
            .collect();
        children.sort_by_key(|c| std::cmp::Reverse((c.started_at, c.pid)));
        stack.extend(children);
    }
    // Anything a cycle or a gap left out, at the end rather than lost.
    ordered.extend(
        rows.iter()
            .copied()
            .filter(|r| !placed.contains(&(r.pid, r.started_at))),
    );
    ordered
}

/// The parent by name when this agent's history has it, with its pid.
fn parent_label(rows: &[&ProcessRow], parent: u32) -> String {
    rows.iter()
        .find(|r| r.pid == parent)
        .filter(|r| !r.name.is_empty())
        .map_or_else(|| parent.to_string(), |r| format!("{} ({parent})", r.name))
}

/// The rules that held on exactly this process: its pid and its start.
fn findings_of(report: &Report, row: &ProcessRow) -> Vec<String> {
    let mut rules: Vec<String> = report
        .behaviour
        .findings
        .iter()
        .filter(|f| {
            f.actor_pid == row.pid && f.actor_started_at.is_none_or(|at| at == row.started_at)
        })
        .map(|f| f.rule.clone())
        .collect();
    rules.sort();
    rules.dedup();
    rules
}

/// One word or two for how it stands: running, exited with its status, gone.
fn state_word(row: &ProcessRow) -> String {
    match (row.state.as_str(), row.exit_code) {
        ("exited", Some(code)) => format!("exited {code}"),
        (other, _) => other.to_owned(),
    }
}

/// How long it ran: to its exit, or to when it was last seen.
fn ran_for(row: &ProcessRow) -> String {
    let end = row.exited_at.unwrap_or(row.last_seen);
    let ms = end.saturating_sub(row.started_at);
    let prefix = if row.state == "running" {
        "\u{2265} "
    } else {
        ""
    };
    if ms < 1_000 {
        format!("{prefix}{ms} ms")
    } else if ms < 60_000 {
        format!("{prefix}{} s", ms / 1_000)
    } else {
        format!("{prefix}{} min", ms / 60_000)
    }
}

/// The chain from the agent down to this process.
fn lineage_line(row: &ProcessRow) -> String {
    let mut parts = vec![format!("agent {}", row.agent_pid)];
    parts.extend(row.chain.iter().rev().map(u32::to_string));
    parts.push(row.pid.to_string());
    parts.join(" → ")
}

/// Which sensor saw it, which decides what its times mean.
fn seen_by(row: &ProcessRow) -> String {
    match row.observed_by.as_deref() {
        Some("kernel_event") => "the kernel, as it happened (process connector)".to_owned(),
        Some("sweep") => "a sweep; times accurate to one sweep interval".to_owned(),
        _ => "not recorded by this report's build".to_owned(),
    }
}

/// What the state claims, and what it does not.
fn state_meaning(row: &ProcessRow) -> String {
    match (row.state.as_str(), row.exited_at, row.gone_after) {
        ("exited", Some(at), _) => {
            let lived = at.saturating_sub(row.started_at);
            let code = row
                .exit_code
                .map_or_else(String::new, |code| format!(", status {code}"));
            format!(
                "exited at {}{code}; lived about {lived} ms",
                crate::clock::stamp(at)
            )
        }
        ("gone", _, Some(after)) => format!(
            "gone: last seen {}, missing at {}",
            crate::clock::stamp(row.last_seen),
            crate::clock::stamp(after)
        ),
        ("running", _, _) => "running at the latest sweep".to_owned(),
        (other, _, _) => other.to_owned(),
    }
}

/// The name, marked when an exec replaced it with a program that could not
/// be read: the old name is not what the process ended as.
fn name_cell(row: &ProcessRow) -> String {
    let name = if row.name.is_empty() { "?" } else { &row.name };
    if row.program_unread {
        format!("{name} → ?")
    } else {
        name.to_owned()
    }
}

fn program_line(row: &ProcessRow) -> String {
    let current = match (&row.program, row.program_unread) {
        (Some(program), _) => program.clone(),
        (None, true) => "exec'd, then gone before the new program could be read".to_owned(),
        (None, false) => "not readable".to_owned(),
    };
    if row.previous_programs.is_empty() {
        current
    } else {
        format!(
            "{current}, after exec from {} ({} exec)",
            row.previous_programs.join(", "),
            row.exec_generation
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row() -> crate::report::ProcessRow {
        crate::report::ProcessRow {
            agent_pid: 100,
            pid: 201,
            name: "sleep".to_owned(),
            parent_pid: Some(200),
            state: "gone".to_owned(),
            last_seen: 5_000,
            gone_after: Some(9_000),
            chain: vec![200],
            program: Some("sleep".to_owned()),
            ..crate::report::ProcessRow::default()
        }
    }

    #[test]
    fn a_process_row_names_its_chain_from_the_agent_down() {
        assert_eq!(lineage_line(&row()), "agent 100 → 200 → 201");
    }

    #[test]
    fn gone_says_the_exit_was_not_observed_and_exited_gives_its_time() {
        let gone = state_meaning(&row());
        assert!(gone.starts_with("gone: last seen"), "{gone}");
        assert!(gone.contains("missing at"), "{gone}");
        let mut exited = row();
        exited.state = "exited".to_owned();
        exited.started_at = 6_994;
        exited.exited_at = Some(7_000);
        exited.exit_code = Some(0);
        let meaning = state_meaning(&exited);
        assert!(meaning.starts_with("exited at "), "{meaning}");
        assert!(
            meaning.ends_with(", status 0; lived about 6 ms"),
            "{meaning}"
        );
        exited.observed_by = Some("kernel_event".to_owned());
        assert!(seen_by(&exited).starts_with("the kernel"));
        exited.observed_by = None;
        assert!(
            seen_by(&exited).starts_with("not recorded"),
            "an older report"
        );
    }

    #[test]
    fn an_unread_exec_never_shows_the_old_name_as_current() {
        let mut unread = row();
        unread.name = "sh".to_owned();
        unread.program = None;
        unread.previous_programs = vec!["sh".to_owned()];
        unread.exec_generation = 1;
        unread.program_unread = true;
        assert_eq!(name_cell(&unread), "sh → ?");
        assert_eq!(
            program_line(&unread),
            "exec'd, then gone before the new program could be read, after exec from sh (1 exec)"
        );
        assert_eq!(name_cell(&row()), "sleep");
        unread.name = String::new();
        assert_eq!(name_cell(&unread), "? → ?", "never a bare arrow");
    }

    #[test]
    fn an_exec_names_the_program_it_replaced() {
        let mut execd = row();
        execd.program = Some("python3".to_owned());
        execd.previous_programs = vec!["sh".to_owned()];
        execd.exec_generation = 1;
        assert_eq!(program_line(&execd), "python3, after exec from sh (1 exec)");
        assert_eq!(program_line(&row()), "sleep");
    }
}

#[cfg(test)]
mod tree_tests {
    use super::{ran_for, tree_order};
    use crate::report::ProcessRow;

    fn row(pid: u32, parent: Option<u32>, started: u64) -> ProcessRow {
        ProcessRow {
            agent_pid: 1,
            pid,
            parent_pid: parent,
            started_at: started,
            last_seen: started + 2_500,
            state: "running".to_owned(),
            ..ProcessRow::default()
        }
    }

    #[test]
    fn every_process_follows_its_parent_earliest_first() {
        let rows = [
            row(30, Some(10), 3),
            row(10, None, 1),
            row(20, Some(10), 2),
            row(40, Some(20), 4),
        ];
        let refs: Vec<&ProcessRow> = rows.iter().collect();
        let order: Vec<u32> = tree_order(&refs).iter().map(|r| r.pid).collect();
        assert_eq!(order, [10, 20, 40, 30]);
    }

    #[test]
    fn a_running_process_ran_at_least_as_long_as_it_has_been_seen() {
        assert_eq!(ran_for(&row(1, None, 0)), "\u{2265} 2 s");
        let mut done = row(1, None, 0);
        done.state = "exited".to_owned();
        done.exited_at = Some(40);
        assert_eq!(ran_for(&done), "40 ms");
    }
}
