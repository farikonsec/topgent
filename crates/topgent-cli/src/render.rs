//! The human-readable scan.
//!
//! The same report the desktop app renders and `--json` prints, laid out for a
//! terminal. Nothing is computed here that is not already in the report: if a
//! column has no value, the sensor did not supply one, and the table says so
//! rather than leaving a blank that reads as zero.

use crate::output::now_ms;
use crate::style::{Column, table};
use topgent_collect::SystemClock;
use topgent_collect::default_collectors;
use topgent_collect::sweep;
use topgent_core::Agent;
use topgent_core::Risk;
use topgent_core::analyse;
use topgent_facts::Tri;
use topgent_journal::Journal;

/// One pass: collect, fold, score, print.
pub(crate) fn render(show_facts: bool) {
    let collectors = default_collectors();
    let clock = SystemClock;
    let result = sweep(&collectors, &clock);
    let scored = analyse(&result.facts);
    journal_sweep(&scored);

    let ink = crate::style::Ink::decide();

    println!();
    println!(
        "  {}  {}",
        ink.heading(&format!("{} agents", scored.len())),
        ink.faint(&format!(
            "topgent {} · {} facts · {} of {} sensors",
            env!("CARGO_PKG_VERSION"),
            result.facts.len(),
            collectors.len() - result.failures.len(),
            collectors.len()
        ))
    );

    // A sensor that cannot run here is a rule that cannot fire here. Printed
    // before the table, once, and never as a warning about something that just
    // happened: it is a permanent property of the platform.
    for (collector, err) in &result.failures {
        println!(
            "  {} {}",
            ink.warn("!"),
            ink.faint(&format!("{collector}: {err}"))
        );
    }
    println!();

    let mut ranked: Vec<&(Agent, Risk)> = scored.iter().collect();
    ranked.sort_by(|a, b| {
        b.1.score
            .cmp(&a.1.score)
            .then_with(|| a.0.id.pid.cmp(&b.0.id.pid))
    });

    let columns = [
        Column::text("AGENT"),
        Column::text("RISK"),
        Column::number("SCORE"),
        Column::text("IDENTITY"),
        Column::text("DETECTION"),
        Column::number("PID"),
        Column::text("TOP FINDING"),
    ];
    let rows: Vec<Vec<String>> = ranked
        .iter()
        .map(|(agent, risk)| {
            vec![
                ink.paint("1", &name(agent)),
                ink.grade(risk.grade.label()),
                // Coloured by the grade, not by its own text: the score is a
                // number and matches no grade name, so colouring it by itself
                // printed every score faint whatever it said.
                ink.as_grade(risk.grade.label(), &risk.score.to_string()),
                agent.identity.label().to_owned(),
                agent.discovery_confidence.label().to_owned(),
                agent.id.pid.to_string(),
                risk.factors
                    .first()
                    .map_or_else(|| standing_state(agent), |f| f.title.clone()),
            ]
        })
        .collect();
    if rows.is_empty() {
        println!(
            "  {}",
            ink.faint("No AI agents are running on this machine.")
        );
    } else {
        print!("{}", table(&columns, &rows, ink));
    }

    if let Some((agent, risk)) = ranked.first() {
        print!("{}", why(agent, risk, ink));
    }

    if show_facts {
        println!("\n  {}\n", ink.heading("facts"));
        let columns = [
            Column::text("CLAIM"),
            Column::text("SENSOR"),
            Column::text("PROBE"),
        ];
        let rows: Vec<Vec<String>> = result
            .facts
            .iter()
            .take(40)
            .map(|f| {
                vec![
                    f.claim().kind().to_owned(),
                    f.provenance().collector.clone(),
                    ink.faint(&f.provenance().probe),
                ]
            })
            .collect();
        print!("{}", table(&columns, &rows, ink));
    }
    println!();
}

/// Why the worst agent scores what it does, and what it can reach.
///
/// Its own function because it is a different question from the table above:
/// that one says what is running, this one says why the top row is the top row.
/// What the row is, when no factor scored.
///
/// A dash is right for a process with nothing against it and wrong for an
/// editor host with three agent extensions loaded, which is what the machine
/// this was written on had: `Code Helper (Plugin)  LOW  0  -`, the least
/// alarming row in the table for arguably its most interesting process.
///
/// Topgent already knows. It declines to say *which* extension caused a
/// host-level event, correctly, and that refusal had been turning into saying
/// nothing at all.
fn standing_state(agent: &Agent) -> String {
    match agent.extensions.len() {
        0 => "-".to_owned(),
        1 => "1 agent extension active in a shared editor host".to_owned(),
        many => format!("{many} agent extensions active in a shared editor host"),
    }
}

fn why(agent: &Agent, risk: &Risk, ink: crate::style::Ink) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    println!(
        "\n  {}\n",
        ink.heading(&format!("{} — why it scores {}", name(agent), risk.score))
    );
    let why = [
        Column::number("POINTS"),
        Column::text("FINDING"),
        Column::text("EVIDENCE"),
        Column::text("CONFIDENCE"),
    ];
    let rows: Vec<Vec<String>> = risk
        .factors
        .iter()
        .map(|f| {
            vec![
                ink.as_grade(risk.grade.label(), &format!("+{}", f.points)),
                f.title.clone(),
                ink.faint(&f.source),
                ink.faint(f.confidence.label()),
            ]
        })
        .collect();
    let _ = write!(out, "{}", table(&why, &rows, ink));

    let interesting: Vec<_> = agent
        .resources
        .iter()
        .filter(|r| r.is_drift() || r.is_latent_secret())
        .collect();
    if !interesting.is_empty() {
        let _ = writeln!(out, "\n  {}\n", ink.heading("what it can reach"));
        let access = [
            Column::text("RESOURCE"),
            Column::text("SECRET"),
            Column::text("DECLARED"),
            Column::text("OBSERVED"),
            Column::text("REACHABLE"),
        ];
        let rows: Vec<Vec<String>> = interesting
            .iter()
            .map(|r| {
                let reachable = matches!(r.reachable, Tri::Yes) && r.sensitive;
                vec![
                    r.path.clone(),
                    if r.is_latent_secret() {
                        ink.paint("31", "credential")
                    } else {
                        "-".to_owned()
                    },
                    r.declared.label().to_owned(),
                    r.observed.label().to_owned(),
                    if reachable {
                        ink.paint("1;31", "YES")
                    } else {
                        r.reachable.label().to_owned()
                    },
                ]
            })
            .collect();
        let _ = write!(out, "{}", table(&access, &rows, ink));
    }
    out
}

/// What to call an agent whose family was not recognised.
///
/// Its executable's own name, never `unclassified`. The process was examined;
/// the interface said the opposite for months and this is the same fix.
fn name(agent: &Agent) -> String {
    if let Some(family) = &agent.family {
        return family.clone();
    }
    agent
        .exe
        .as_deref()
        .and_then(|path| path.rsplit(['/', '\\']).next())
        .filter(|name| !name.is_empty())
        .map_or_else(|| format!("pid {}", agent.id.pid), ToOwned::to_owned)
}

/// Compare this sweep with the last and write down what moved.
///
/// A journal that cannot be written is reported rather than swallowed: a
/// security log that fails quietly is worse than none, because it is trusted.
pub(crate) fn journal_sweep(scored: &[(Agent, Risk)]) {
    let journal = Journal::open_default();
    if let Err(e) = journal.advance_sweep(scored, now_ms()) {
        eprintln!("topgent: could not write the event log: {e}");
    }
}
