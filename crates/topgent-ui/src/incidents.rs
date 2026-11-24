//! The incidents page: the human-first surface of the desktop app.
//!
//! One card per agent run, read top to bottom the way a person reads it — the
//! headline, why it matters, what to do, the evidence, and what the evidence
//! does not establish. No table and no jargon: the core has already written
//! the sentences, so this renders them and re-derives nothing. The per-event
//! detail still lives in the other workspaces.

#![allow(clippy::elidable_lifetime_names)]

use iced::widget::{button, column, container, row, scrollable, text};
use iced::{Element, Length};

use crate::Message;
use crate::brand::{self, Subject};
use crate::overview::{Tone, dot, pill};
use crate::report::{Incident, Report};
use crate::theme::{self, Region, Style, size, space};

/// The whole page for the current report. `open` holds the ids of incidents
/// whose evidence is showing.
pub fn page<'a>(
    report: &'a Report,
    open: &std::collections::BTreeSet<String>,
    s: Style,
) -> Element<'a, Message> {
    let p = s.palette;
    let mut body = column![].spacing(s.pad(space::WIDE)).width(Length::Fill);

    if let Some(note) = coverage(report, s) {
        body = body.push(note);
    }

    if report.incidents.is_empty() {
        body = body.push(
            container(
                column![
                    text("No incidents")
                        .font(theme::STRONG)
                        .size(s.type_size(size::SECTION))
                        .color(p.text),
                    text("Monitoring is active.")
                        .size(s.type_size(size::READING))
                        .color(p.muted),
                ]
                .spacing(s.pad(space::TIGHT))
                .align_x(iced::Alignment::Center)
                .width(Length::Fill),
            )
            .padding(s.pad(space::LOOSE))
            .width(Length::Fill)
            .style(theme::region(Region::Panel, p)),
        );
    } else {
        for incident in &report.incidents {
            body = body.push(card(report, incident, open.contains(&incident.id), s));
        }
    }

    scrollable(body.padding([0.0, s.pad(space::TIGHT)]))
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

fn tone(severity: &str) -> Tone {
    if severity.eq_ignore_ascii_case("critical") {
        Tone::Bad
    } else {
        Tone::Warn
    }
}

/// A short note when this host cannot see everything an incident needs.
/// Nothing when it can: a working sensor needs no banner.
fn coverage<'a>(report: &'a Report, s: Style) -> Option<Element<'a, Message>> {
    let p = s.palette;
    let c = &report.incident_coverage;
    if c.state.is_empty() || c.state == "available" {
        return None;
    }
    let (live, total) = report
        .incident_kinds
        .iter()
        .fold((0, 0), |(live, total), k| {
            (
                live + k.rules.iter().filter(|r| r.live).count(),
                total + k.rules.len(),
            )
        });
    let note = if total > 0 {
        format!("Limited detection: {live} of {total} incident rules run on this host.")
    } else {
        "Limited detection on this host.".to_owned()
    };
    let lines = text(note).size(s.type_size(size::BODY)).color(p.muted);
    Some(
        container(
            row![dot(Tone::Warn, s), lines]
                .spacing(s.pad(space::SNUG))
                .align_y(iced::Alignment::Center),
        )
        .padding([s.pad(space::SNUG), s.pad(space::WIDE)])
        .width(Length::Fill)
        .style(theme::region(Region::Panel, p))
        .into(),
    )
}

fn heading<'a>(label: &'a str, s: Style) -> Element<'a, Message> {
    text(label)
        .size(s.type_size(size::MICRO))
        .color(s.palette.faint)
        .into()
}

fn bullet<'a>(line: &'a str, s: Style, colour: iced::Color) -> Element<'a, Message> {
    row![
        text("•").size(s.type_size(size::READING)).color(colour),
        text(line).size(s.type_size(size::READING)).color(colour),
    ]
    .spacing(s.pad(space::TIGHT))
    .into()
}

fn evidence_row<'a>(key: &'a str, value: String, s: Style) -> Element<'a, Message> {
    let p = s.palette;
    row![
        container(text(key).size(s.type_size(size::BODY)).color(p.muted))
            .width(Length::Fixed(130.0)),
        text(value).size(s.type_size(size::BODY)).color(p.text),
    ]
    .spacing(s.pad(space::TIGHT))
    .into()
}

#[allow(clippy::too_many_lines)]
fn card<'a>(
    report: &'a Report,
    incident: &'a Incident,
    open: bool,
    s: Style,
) -> Element<'a, Message> {
    let p = s.palette;
    let tone = tone(&incident.severity);
    let colour = if matches!(tone, Tone::Bad) {
        p.critical
    } else {
        p.high
    };

    // Kind, when, how long, which process, severity: one line to scan.
    let mut meta: Vec<String> = Vec::new();
    if incident.first_seen > 0 {
        meta.push(crate::clock::stamp(incident.first_seen));
    }
    if !incident.numbers.duration.is_empty() {
        meta.push(format!("lasted {}", incident.numbers.duration));
    }
    if let Some(pid) = incident.process_pid {
        meta.push(format!("PID {pid}"));
    }
    let kind = if incident.name.is_empty() {
        "Incident".to_owned()
    } else {
        incident.name.clone()
    };
    let head = row![
        dot(tone, s),
        text(kind.to_uppercase())
            .font(theme::STRONG)
            .size(s.type_size(size::MICRO))
            .color(colour),
        iced::widget::space().width(Length::Fill),
        text(meta.join(" \u{b7} "))
            .size(s.type_size(size::MICRO))
            .color(p.faint),
        pill(sev_word(&incident.severity), tone, s),
    ]
    .spacing(s.pad(space::SNUG))
    .align_y(iced::Alignment::Center);

    // Who did what. A tool incident reads "Claude Code ran nmap", with each
    // tool in a chip so the name is the first thing the eye lands on.
    let agent = report.find_agent(incident.agent.pid);
    let family = agent
        .and_then(|a| a.family.as_deref())
        .or(incident.agent.family.as_deref());
    let who = if family.is_some() {
        brand::agent_name(family)
    } else if incident.agent.name.is_empty() {
        "An agent".to_owned()
    } else {
        incident.agent.name.clone()
    };
    let tools = incident.tool_names();
    let line: Element<'a, Message> = if incident.kind == "offensive_tool" && !tools.is_empty() {
        let mut r = row![
            text(who.clone())
                .font(theme::STRONG)
                .size(s.type_size(size::SECTION))
                .color(p.text),
            text("ran").size(s.type_size(size::SECTION)).color(p.muted),
        ]
        .spacing(s.pad(space::SNUG))
        .align_y(iced::Alignment::Center);
        for tool in tools {
            r = r.push(
                container(
                    text(tool.to_owned())
                        .font(theme::MONO)
                        .size(s.type_size(size::HEADING))
                        .color(p.surface),
                )
                .padding([s.pad(space::HAIR), s.pad(space::SNUG)])
                .style(theme::chip(p.text)),
            );
        }
        r.wrap().into()
    } else {
        text(incident.headline.clone())
            .size(s.type_size(size::SECTION))
            .color(p.text)
            .into()
    };
    let what = row![brand::logo(Subject::Family(family), &who, 36.0, p), line]
        .spacing(s.pad(space::BASE))
        .align_y(iced::Alignment::Center);

    let mut impact = column![heading("IMPACT", s)].spacing(s.pad(space::TIGHT));
    for w in &incident.why {
        impact = impact.push(bullet(w, s, p.text));
    }
    let mut actions = column![heading("ACTION", s)].spacing(s.pad(space::TIGHT));
    for action in &incident.actions {
        let mut line = row![bullet(&action.label, s, p.text)].spacing(s.pad(space::TIGHT));
        if !action.command.is_empty() {
            line = line.push(
                container(
                    text(action.command.clone())
                        .size(s.type_size(size::BODY))
                        .font(theme::MONO)
                        .color(p.text),
                )
                .padding([1.0, 6.0])
                .style(theme::region(Region::Tooltip, p)),
            );
        }
        actions = actions.push(line);
    }
    let cols = row![
        impact.width(Length::FillPortion(1)),
        actions.width(Length::FillPortion(1))
    ]
    .spacing(s.pad(space::LOOSE));

    let control = |label: &'static str, message: Message| -> Element<'a, Message> {
        button(
            text(label)
                .font(theme::STRONG)
                .size(s.type_size(size::BODY))
                .color(p.text),
        )
        .on_press(message)
        .padding([s.pad(space::TIGHT), s.pad(space::BASE)])
        .style(move |_, status| crate::shell::utility_style(status, p))
        .into()
    };
    let mut foot = row![]
        .spacing(s.pad(space::SNUG))
        .align_y(iced::Alignment::Center);
    if incident.agent.pid != 0 {
        foot = foot.push(control(
            "Open agent",
            Message::OpenAgent(incident.agent.pid),
        ));
        if let Some(pid) = incident.process_pid {
            foot = foot.push(control(
                "Show process",
                Message::ShowProcess(incident.agent.pid, pid),
            ));
        }
    }
    foot = foot.push(iced::widget::space().width(Length::Fill)).push(
        button(
            text(if open { "Hide evidence" } else { "Evidence" })
                .size(s.type_size(size::BODY))
                .color(p.muted),
        )
        .on_press(Message::ToggleEvidence(incident.id.clone()))
        .padding([s.pad(space::TIGHT), s.pad(space::SNUG)])
        .style(|_, _| button::Style::default()),
    );

    let ev = &incident.evidence;
    let n = &incident.numbers;
    let mut rows = column![heading("EVIDENCE", s)].spacing(s.pad(space::HAIR));
    // A behaviour incident: the rules that matched, on what, by which process.
    for f in &ev.findings {
        let times = if f.count > 1 {
            format!(", {} times", count(f.count))
        } else {
            String::new()
        };
        rows = rows.push(evidence_row(
            "rule",
            format!(
                "{}: {} by {} ({}){times}",
                f.rule, f.target, f.actor_name, f.actor_pid
            ),
            s,
        ));
    }
    // A secret incident: which secret files were read, and where data went.
    for sec in &ev.secrets {
        let size = if sec.bytes > 0 {
            format!(" ({})", bytes(sec.bytes))
        } else {
            String::new()
        };
        let label = if sec.class_name.is_empty() {
            "secret"
        } else {
            &sec.class_name
        };
        rows = rows.push(evidence_row(label, format!("{}{size}", sec.path), s));
    }
    for d in &ev.sent_to {
        let name = if d.name.is_empty() {
            String::new()
        } else {
            format!(" ({})", d.name)
        };
        let own = if d.own_service {
            ", its own service"
        } else {
            ""
        };
        rows = rows.push(evidence_row(
            "then sent to",
            format!("{}:{}{name}{own}, {}", d.address, d.port, bytes(d.bytes)),
            s,
        ));
    }
    if !ev.workspace.root.is_empty() {
        rows = rows.push(evidence_row(
            "read",
            format!(
                "{} files under {}",
                count(ev.workspace.files),
                ev.workspace.root
            ),
            s,
        ));
    }
    if ev.workspace.history_files > 0 {
        rows = rows.push(evidence_row(
            "git history",
            format!("{} objects read", count(ev.workspace.history_files)),
            s,
        ));
    }
    let tops: Vec<String> = ev
        .workspace
        .top_directories
        .iter()
        .map(|d| format!("{} ({})", d.directory, count(d.files)))
        .collect();
    if !tops.is_empty() {
        rows = rows.push(evidence_row("most from", tops.join(", "), s));
    }
    for d in &ev.destinations {
        let name = if d.name.is_empty() {
            String::new()
        } else {
            format!(" ({})", d.name)
        };
        let store = if d.object_storage {
            "  · object storage"
        } else {
            ""
        };
        rows = rows.push(evidence_row(
            "sent to",
            format!("{}:{}{name}{store}", d.address, d.port),
            s,
        ));
        rows = rows.push(evidence_row(
            "",
            format!(
                "{} attempts, {} failed, {}",
                count(d.attempts),
                count(d.failed),
                bytes(d.bytes)
            ),
            s,
        ));
    }
    if n.encrypted {
        rows = rows.push(evidence_row(
            "encrypted",
            format!("yes — ran {}", ev.encryption_tools.join(", ")),
            s,
        ));
    }
    rows = rows.push(evidence_row("duration", n.duration.clone(), s));
    let recognised = if incident.agent.recognised {
        "recognised agent"
    } else {
        "not a recognised agent"
    };
    rows = rows.push(evidence_row(
        "by",
        format!(
            "{} pid {} ({recognised})",
            incident.agent.name, incident.agent.pid
        ),
        s,
    ));

    let mut inner = column![head, what, rule(s), cols, foot].spacing(s.pad(space::BASE));
    if open {
        let mut limits = column![heading("LIMITS", s)].spacing(s.pad(space::HAIR));
        for l in &incident.limits {
            limits = limits.push(bullet(l, s, p.muted));
        }
        inner = inner.push(rule(s)).push(rows).push(limits);
    }

    container(inner)
        .padding([s.pad(space::WIDE), s.pad(space::LOOSE)])
        .width(Length::Fill)
        .style(theme::incident_card(colour, p))
        .into()
}

fn rule<'a>(s: Style) -> Element<'a, Message> {
    let line = s.palette.border;
    container(iced::widget::space())
        .width(Length::Fill)
        .height(Length::Fixed(1.0))
        .style(move |_| container::Style {
            background: Some(line.into()),
            ..container::Style::default()
        })
        .into()
}

fn sev_word(severity: &str) -> String {
    let mut chars = severity.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().collect::<String>() + chars.as_str()
    })
}

/// `42,411`.
fn count(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// `313 MB`.
fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["bytes", "KB", "MB", "GB", "TB"];
    #[allow(clippy::cast_precision_loss)]
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1000.0 && unit + 1 < UNITS.len() {
        value /= 1000.0;
        unit += 1;
    }
    let label = UNITS.get(unit).copied().unwrap_or("bytes");
    if unit == 0 {
        format!("{n} {label}")
    } else if value >= 100.0 {
        format!("{value:.0} {label}")
    } else {
        format!("{value:.1} {label}")
    }
}
