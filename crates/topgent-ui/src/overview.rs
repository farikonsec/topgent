//! The overview: the first page in the simple view, for people who are not
//! security engineers.
//!
//! It answers one question first: is any AI agent running here, and does any
//! of them need a decision? Four figures, one table of agents, the programs
//! they ran, and a side column of destinations, findings and recent activity.
//! The web viewer's overview (`viewer/ui/simple.mjs`) is the same page; the
//! words come from the report's plain-words summary, so this file arranges
//! sentences and writes no translation of a risk.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;

use iced::widget::{Column, Row, button, column, container, row, scrollable, text};
use iced::{Alignment, Color, Element, Length};

use crate::Message;
use crate::brand::{self, Subject};
use crate::report::{Agent, Event, ProcessRow, Report, Summary};
use crate::shell::Workspace;
use crate::theme::{self, Region, Style, size, space};

/// Narrower than this, the side column moves under the main one.
pub const SIDE_BY_SIDE: f32 = 1080.0;
/// Width of the side column when it sits beside the main one.
const SIDE_WIDTH: f32 = 320.0;
/// Program tiles per row.
const TILE_COLUMNS: usize = 3;

/// How a pill, a dot or a figure reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tone {
    /// Needs a decision.
    Bad,
    /// Worth a look.
    Warn,
    /// Fine.
    Calm,
    /// Not running, or not about anything.
    Quiet,
}

impl Tone {
    fn colour(self, p: theme::Palette) -> Color {
        match self {
            Self::Bad => p.critical,
            Self::Warn => p.high,
            Self::Calm => p.low,
            Self::Quiet => p.faint,
        }
    }

    /// The tone of a summary level.
    #[must_use]
    pub fn of_level(level: &str) -> Self {
        match level {
            "act" => Self::Bad,
            "watch" => Self::Warn,
            _ => Self::Calm,
        }
    }
}

fn level_rank(level: &str) -> u8 {
    match level {
        "act" => 0,
        "watch" => 1,
        "info" => 2,
        _ => 3,
    }
}

/// One overview row: an agent and the model servers folded into it.
#[derive(Debug, Clone)]
pub struct Line<'a> {
    /// The agent.
    pub agent: &'a Agent,
    /// Model runtimes it started, shown as part of it.
    pub servers: Vec<&'a Agent>,
}

impl Line<'_> {
    /// The pids this row speaks for.
    fn pids(&self) -> BTreeSet<u32> {
        std::iter::once(self.agent.pid)
            .chain(self.servers.iter().map(|s| s.pid))
            .collect()
    }

    /// The more urgent of the agent's summary and its servers'.
    fn summary(&self) -> Option<&Summary> {
        std::iter::once(self.agent)
            .chain(self.servers.iter().copied())
            .filter_map(|a| a.summary.as_ref())
            .min_by_key(|s| level_rank(&s.level))
    }
}

/// Model servers folded into the app that started them.
///
/// Unsloth Studio runs its model in a llama.cpp server below it, and the
/// catalogue recognises that server on its own, so a plain list shows one
/// product as two agents. A model runtime found among another agent's
/// children moves under that agent. Only model runtimes fold: a Claude Code
/// session started from Claude Desktop is an agent in its own right.
#[must_use]
pub fn fold_servers(agents: &[Agent]) -> Vec<Line<'_>> {
    let mut parent_of: HashMap<u32, u32> = HashMap::new();
    for a in agents {
        for c in &a.children {
            if c.pid != a.pid {
                parent_of.insert(c.pid, a.pid);
            }
        }
    }
    let by_pid: HashMap<u32, &Agent> = agents.iter().map(|a| (a.pid, a)).collect();
    let mut servers: HashMap<u32, Vec<&Agent>> = HashMap::new();
    let mut top = Vec::new();
    for a in agents {
        let parent = parent_of.get(&a.pid).and_then(|p| by_pid.get(p));
        match parent {
            Some(parent)
                if a.kind.as_deref() == Some("model_runtime")
                    && parent_of.get(&parent.pid) != Some(&a.pid) =>
            {
                servers.entry(parent.pid).or_default().push(a);
            }
            _ => top.push(a),
        }
    }
    top.into_iter()
        .map(|agent| Line {
            agent,
            servers: servers.remove(&agent.pid).unwrap_or_default(),
        })
        .collect()
}

/// Every model an agent used recently, current first, without routes.
#[must_use]
pub fn models_of(agent: &Agent) -> Vec<&str> {
    let mut out: Vec<&str> = Vec::new();
    for m in agent.model.iter().chain(agent.models_seen.iter()) {
        let name = brand::model_name(m);
        if !name.is_empty() && !out.contains(&name) {
            out.push(name);
        }
    }
    out
}

/// The model line: the model, or what kind of thing has none of its own.
#[must_use]
pub fn model_line(line: &Line<'_>) -> String {
    if let Some(model) = line.agent.model.as_deref() {
        return brand::model_name(model).to_owned();
    }
    if let Some(server) = line.servers.iter().find(|s| s.model.is_some()) {
        let model = server
            .model
            .as_deref()
            .map(brand::model_name)
            .unwrap_or_default();
        return format!(
            "{model} via {}",
            brand::agent_name(server.family.as_deref())
        );
    }
    match line.agent.kind.as_deref() {
        Some("model_runtime") => "Model runtime".to_owned(),
        Some("agent_editor") => "Desktop app".to_owned(),
        _ => "Unknown model".to_owned(),
    }
}

/// Outbound connections to the internet, by the company at the other end.
#[derive(Debug, Clone, Default)]
pub struct Company {
    /// The company, as a person reads it.
    pub name: String,
    /// Agents that connected there.
    pub agents: BTreeSet<u32>,
    /// Connections seen.
    pub connections: usize,
}

/// Companies the given agents (or every agent, for `None`) connected to, most
/// connections first.
#[must_use]
pub fn companies(report: &Report, pids: Option<&BTreeSet<u32>>) -> Vec<Company> {
    let mut groups: BTreeMap<String, Company> = BTreeMap::new();
    for row in &report.network {
        if row.direction == "listening" || brand::is_local_owner(&row.network_owner) {
            continue;
        }
        if pids.is_some_and(|p| !p.contains(&row.agent_pid)) {
            continue;
        }
        let name = brand::owner_name(&row.network_owner);
        let group = groups.entry(name.clone()).or_insert_with(|| Company {
            name,
            ..Company::default()
        });
        group.connections += 1;
        group.agents.insert(row.agent_pid);
    }
    let mut out: Vec<Company> = groups.into_values().collect();
    out.sort_by(|a, b| {
        b.connections
            .cmp(&a.connections)
            .then_with(|| a.name.cmp(&b.name))
    });
    out
}

/// What an agent is doing, in one word.
fn activity(report: &Report, agent: &Agent) -> (&'static str, Tone) {
    if agent.live == Some(false) {
        return ("Stopped", Tone::Quiet);
    }
    if report.incidents.iter().any(|i| i.agent.pid == agent.pid) {
        return ("Incident", Tone::Bad);
    }
    if agent.summary.as_ref().is_some_and(|s| s.did_something) {
        return ("Suspicious", Tone::Warn);
    }
    ("Normal", Tone::Calm)
}

/// One timeline event in short words, with its tone.
#[must_use]
pub fn event_label(event: &Event) -> (String, Tone) {
    let rank = |g: &str| match g.trim() {
        "LOW" => 0,
        "MEDIUM" => 1,
        "HIGH" => 2,
        "CRITICAL" => 3,
        _ => -1,
    };
    match event.kind.as_str() {
        "started" => ("Started".to_owned(), Tone::Calm),
        "stopped" => ("Stopped".to_owned(), Tone::Quiet),
        "recon" => ("Network scanning".to_owned(), Tone::Bad),
        "grade_changed" => {
            let up = event.direction.as_deref().map_or_else(
                || {
                    let mut parts = event.detail.split(" to ");
                    let from = parts.next().map_or(-1, rank);
                    let to = parts.next().map_or(-1, rank);
                    to > from
                },
                |d| d == "escalated",
            );
            if up {
                ("Risk raised".to_owned(), Tone::Warn)
            } else {
                ("Risk lowered".to_owned(), Tone::Calm)
            }
        }
        other => {
            let words = other.replace('_', " ");
            let mut chars = words.chars();
            let label = chars.next().map_or_else(
                || "Event".to_owned(),
                |c| c.to_uppercase().chain(chars).collect(),
            );
            (label, Tone::Quiet)
        }
    }
}

/// A child process program and every run of it.
#[derive(Debug, Clone)]
pub struct Program<'a> {
    /// Its name.
    pub name: &'a str,
    /// Every run, each listed once under its nearest agent.
    pub runs: Vec<&'a ProcessRow>,
    /// Agents that ran it.
    pub agents: BTreeSet<u32>,
}

/// Child processes grouped by program name, most runs first.
///
/// The history lists a process under every agent above it, so a command run
/// by Claude Code inside Claude Desktop appears twice. Each run is counted
/// once, under its nearest agent.
#[must_use]
pub fn programs(history: &[ProcessRow]) -> Vec<Program<'_>> {
    let mut nearest: BTreeMap<(u32, u64), &ProcessRow> = BTreeMap::new();
    for row in history {
        let slot = nearest.entry((row.pid, row.started_at)).or_insert(row);
        if row.depth < slot.depth {
            *slot = row;
        }
    }
    let mut by_name: BTreeMap<&str, Program<'_>> = BTreeMap::new();
    for row in nearest.into_values() {
        let name = if row.name.is_empty() {
            "unknown"
        } else {
            row.name.as_str()
        };
        let entry = by_name.entry(name).or_insert_with(|| Program {
            name,
            runs: Vec::new(),
            agents: BTreeSet::new(),
        });
        entry.runs.push(row);
        entry.agents.insert(row.agent_pid);
    }
    let last = |p: &Program<'_>| {
        p.runs
            .iter()
            .map(|r| r.last_seen.max(r.first_seen))
            .max()
            .unwrap_or(0)
    };
    let mut out: Vec<Program<'_>> = by_name.into_values().collect();
    out.sort_by(|a, b| {
        b.runs
            .len()
            .cmp(&a.runs.len())
            .then_with(|| last(b).cmp(&last(a)))
    });
    out
}

/// A path with the home folder as `~`, so the account name stays off the screen.
#[must_use]
pub fn short_path(path: &str) -> String {
    for root in ["/Users/", "/home/"] {
        if let Some(rest) = path.strip_prefix(root) {
            return rest
                .find('/')
                .map_or_else(|| "~".to_owned(), |i| format!("~{}", &rest[i..]));
        }
    }
    path.to_owned()
}

/// A time to the minute.
fn minute(at_ms: u64) -> String {
    let stamp = crate::clock::stamp(at_ms);
    if stamp.len() == 8 {
        stamp.get(..5).unwrap_or(&stamp).to_owned()
    } else {
        stamp
    }
}

fn find_agent(report: &Report, pid: u32) -> Option<&Agent> {
    report
        .agents
        .iter()
        .chain(report.ended_agents.iter())
        .find(|a| a.pid == pid)
}

// ---- drawing ----

pub(crate) fn pill<'a>(label: impl Into<String>, tone: Tone, s: Style) -> Element<'a, Message> {
    let p = s.palette;
    let colour = tone.colour(p);
    container(
        text(label.into())
            .font(theme::STRONG)
            .size(s.type_size(size::MICRO))
            .color(colour),
    )
    .padding([s.pad(space::HAIR), s.pad(space::SNUG)])
    .style(move |_| container::Style {
        background: Some(theme::blend(p.surface, colour, 0.14).into()),
        border: iced::Border {
            color: Color::TRANSPARENT,
            width: 0.0,
            radius: theme::radius::PILL.into(),
        },
        ..container::Style::default()
    })
    .into()
}

pub(crate) fn dot<'a>(tone: Tone, s: Style) -> Element<'a, Message> {
    let colour = tone.colour(s.palette);
    container(iced::widget::space())
        .width(Length::Fixed(8.0))
        .height(Length::Fixed(8.0))
        .style(move |_| container::Style {
            background: Some(colour.into()),
            border: iced::Border {
                radius: 4.0.into(),
                ..iced::Border::default()
            },
            ..container::Style::default()
        })
        .into()
}

fn card<'a>(content: impl Into<Element<'a, Message>>, s: Style) -> Element<'a, Message> {
    container(content)
        .padding(s.pad(space::WIDE))
        .width(Length::Fill)
        .style(theme::region(Region::Panel, s.palette))
        .into()
}

fn heading<'a>(title: &str, s: Style) -> Element<'a, Message> {
    text(title.to_owned())
        .font(theme::STRONG)
        .size(s.type_size(size::HEADING))
        .color(s.palette.text)
        .into()
}

fn small<'a>(words: impl Into<String>, s: Style) -> iced::widget::Text<'a> {
    text(words.into())
        .size(s.type_size(size::MICRO))
        .color(s.palette.faint)
}

fn count<'a>(n: usize, s: Style) -> Element<'a, Message> {
    text(n.to_string())
        .font(theme::MONO)
        .size(s.type_size(size::BODY))
        .color(s.palette.muted)
        .into()
}

/// A row that can be pressed, highlighted under the pointer.
fn pressable<'a>(
    content: impl Into<Element<'a, Message>>,
    on: Message,
    selected: bool,
    s: Style,
) -> Element<'a, Message> {
    let p = s.palette;
    button(content)
        .on_press(on)
        .width(Length::Fill)
        .padding([s.pad(space::SNUG), s.pad(space::SNUG)])
        .style(move |_, status| button::Style {
            background: Some(
                if selected {
                    p.selection()
                } else if matches!(status, button::Status::Hovered) {
                    p.hover()
                } else {
                    Color::TRANSPARENT
                }
                .into(),
            ),
            text_color: p.text,
            border: iced::Border {
                color: Color::TRANSPARENT,
                width: 0.0,
                radius: theme::radius::CONTROL.into(),
            },
            ..button::Style::default()
        })
        .into()
}

/// The whole page. `width` is the space the page has.
pub fn page<'a>(
    report: &'a Report,
    program: Option<&'a str>,
    width: f32,
    s: Style,
) -> Element<'a, Message> {
    let mut running: Vec<Line<'a>> = fold_servers(&report.agents)
        .into_iter()
        .filter(|l| l.agent.live != Some(false))
        .collect();
    running.sort_by(|a, b| {
        let rank = |l: &Line<'_>| l.summary().map_or(3, |s| level_rank(&s.level));
        rank(a)
            .cmp(&rank(b))
            .then(b.agent.score.cmp(&a.agent.score))
            .then(a.agent.pid.cmp(&b.agent.pid))
    });

    let body: Element<'a, Message> = if running.is_empty() {
        card(
            column![
                text("No agents running")
                    .font(theme::STRONG)
                    .size(s.type_size(size::SECTION))
                    .color(s.palette.text),
                small("Monitoring is active.", s),
            ]
            .spacing(s.pad(space::TIGHT))
            .align_x(Alignment::Center)
            .width(Length::Fill),
            s,
        )
    } else {
        let main = column![
            agent_table(report, &running, s),
            programs_card(report, program, s)
        ]
        .spacing(s.pad(space::WIDE))
        .width(Length::Fill);
        let side = column![
            destinations_card(report, s),
            findings_card(&running, s),
            activity_card(report, s)
        ]
        .spacing(s.pad(space::WIDE));
        if width >= SIDE_BY_SIDE {
            row![main, side.width(Length::Fixed(SIDE_WIDTH))]
                .spacing(s.pad(space::WIDE))
                .into()
        } else {
            column![main, side.width(Length::Fill)]
                .spacing(s.pad(space::WIDE))
                .into()
        }
    };

    scrollable(
        column![figures(report, &running, s), body]
            .spacing(s.pad(space::WIDE))
            .padding([0.0, s.pad(space::LOOSE)]),
    )
    .height(Length::Fill)
    .into()
}

fn figures<'a>(report: &'a Report, running: &[Line<'a>], s: Style) -> Element<'a, Message> {
    let p = s.palette;
    let critical = running
        .iter()
        .filter(|l| l.summary().is_some_and(|s| s.level == "act"))
        .count();
    let incidents = report.incidents.len();
    let destinations = companies(report, None).len();
    let tile = |value: usize,
                label: &'static str,
                alarm: bool,
                go: Option<Workspace>|
     -> Element<'a, Message> {
        let colour = if alarm && value > 0 {
            p.critical
        } else {
            p.text
        };
        let inner = column![
            text(value.to_string())
                .font(theme::STRONG)
                .size(s.type_size(size::METRIC))
                .color(colour),
            text(label).size(s.type_size(size::LABEL)).color(p.muted),
        ]
        .spacing(s.pad(space::HAIR));
        let boxed = container(inner)
            .padding([s.pad(space::BASE), s.pad(space::WIDE)])
            .width(Length::Fill);
        let element: Element<'a, Message> = match go {
            Some(workspace) => button(boxed)
                .on_press(Message::Go(workspace))
                .padding(0)
                .width(Length::Fill)
                .style(move |_, status| button::Style {
                    background: Some(
                        if matches!(status, button::Status::Hovered) {
                            p.hover()
                        } else {
                            p.surface
                        }
                        .into(),
                    ),
                    text_color: p.text,
                    border: iced::Border {
                        color: p.border,
                        width: 1.0,
                        radius: theme::radius::PANEL.into(),
                    },
                    ..button::Style::default()
                })
                .into(),
            None => container(boxed)
                .width(Length::Fill)
                .style(theme::region(Region::Panel, p))
                .into(),
        };
        element
    };
    row![
        tile(running.len(), "Running", false, None),
        tile(critical, "Critical", true, None),
        tile(destinations, "Destinations", false, None),
        tile(incidents, "Incidents", true, Some(Workspace::Incidents)),
    ]
    .spacing(s.pad(space::WIDE))
    .into()
}

const COLUMNS: [(&str, u16); 4] = [
    ("Agent", 34),
    ("Risk", 20),
    ("Destinations", 34),
    ("Status", 12),
];

fn agent_table<'a>(report: &'a Report, running: &[Line<'a>], s: Style) -> Element<'a, Message> {
    let p = s.palette;
    let header = COLUMNS.iter().fold(Row::new(), |r, (label, share)| {
        r.push(
            text(*label)
                .font(theme::STRONG)
                .size(s.type_size(size::MICRO))
                .color(p.faint)
                .width(Length::FillPortion(*share)),
        )
    });
    let mut rows = Column::new().spacing(s.pad(space::HAIR)).push(
        container(header.spacing(s.pad(space::BASE)))
            .padding([s.pad(space::TIGHT), s.pad(space::SNUG)]),
    );
    for line in running {
        rows = rows.push(agent_row(report, line, s));
    }
    card(rows, s)
}

fn agent_row<'a>(report: &'a Report, line: &Line<'a>, s: Style) -> Element<'a, Message> {
    let p = s.palette;
    let agent = line.agent;
    let name = brand::agent_name(agent.family.as_deref());
    let models = models_of(agent);
    let mut detail = model_line(line);
    if models.len() > 1 {
        let _ = write!(detail, " +{}", models.len() - 1);
    }
    if agent.started_at > 0 {
        let _ = write!(detail, " \u{b7} started {}", minute(agent.started_at));
    }
    let who = row![
        brand::logo(Subject::Family(agent.family.as_deref()), &name, 32.0, p),
        column![
            text(name.clone())
                .font(theme::STRONG)
                .size(s.type_size(size::EMPHASIS))
                .color(p.text),
            small(detail, s),
        ]
        .spacing(s.pad(space::HAIR)),
    ]
    .spacing(s.pad(space::SNUG))
    .align_y(Alignment::Center)
    .width(Length::FillPortion(COLUMNS[0].1));

    let risk: Element<'a, Message> = match line.summary() {
        Some(summary) if summary.level == "act" || summary.level == "watch" => column![
            pill(summary.label.clone(), Tone::of_level(&summary.level), s),
            small(summary.headline.clone(), s),
        ]
        .spacing(s.pad(space::HAIR))
        .into(),
        Some(summary) => pill(summary.label.clone(), Tone::Calm, s),
        None => pill("OK", Tone::Calm, s),
    };

    let talking = companies(report, Some(&line.pids()));
    let destinations: Element<'a, Message> = if talking.is_empty() {
        small("\u{2014}", s).into()
    } else {
        let mut r = Row::new()
            .spacing(s.pad(space::BASE))
            .align_y(Alignment::Center);
        for c in talking.iter().take(4) {
            r = r.push(
                row![
                    brand::logo(Subject::Company(&c.name), &c.name, 18.0, p),
                    text(c.name.clone())
                        .size(s.type_size(size::BODY))
                        .color(p.muted),
                ]
                .spacing(s.pad(space::TIGHT))
                .align_y(Alignment::Center),
            );
        }
        if talking.len() > 4 {
            r = r.push(small(format!("+{}", talking.len() - 4), s));
        }
        r.wrap().into()
    };

    let (status, tone) = std::iter::once(agent)
        .chain(line.servers.iter().copied())
        .map(|a| activity(report, a))
        .min_by_key(|(_, t)| *t)
        .unwrap_or(("Normal", Tone::Calm));

    let cells = row![
        who,
        container(risk).width(Length::FillPortion(COLUMNS[1].1)),
        container(destinations).width(Length::FillPortion(COLUMNS[2].1)),
        container(pill(status, tone, s)).width(Length::FillPortion(COLUMNS[3].1)),
    ]
    .spacing(s.pad(space::BASE))
    .align_y(Alignment::Center);
    pressable(cells, Message::OpenAgent(agent.pid), false, s)
}

fn side_head<'a>(title: &str, more: Option<Workspace>, s: Style) -> Element<'a, Message> {
    let p = s.palette;
    let mut r = row![heading(title, s), iced::widget::space().width(Length::Fill)]
        .align_y(Alignment::Center);
    if let Some(workspace) = more {
        r = r.push(
            button(
                text("View all")
                    .size(s.type_size(size::MICRO))
                    .color(p.muted),
            )
            .on_press(Message::Go(workspace))
            .padding(0)
            .style(|_, _| button::Style::default()),
        );
    }
    r.into()
}

fn side_row<'a>(
    lead: Element<'a, Message>,
    title: String,
    sub: String,
    trail: Element<'a, Message>,
    s: Style,
) -> Element<'a, Message> {
    row![
        lead,
        column![
            text(title)
                .font(theme::STRONG)
                .size(s.type_size(size::BODY))
                .color(s.palette.text),
            small(sub, s),
        ]
        .spacing(s.pad(space::HAIR))
        .width(Length::Fill),
        trail,
    ]
    .spacing(s.pad(space::SNUG))
    .align_y(Alignment::Center)
    .into()
}

fn empty<'a>(words: &'static str, s: Style) -> Element<'a, Message> {
    small(words, s).into()
}

fn destinations_card(report: &Report, s: Style) -> Element<'_, Message> {
    let p = s.palette;
    let groups = companies(report, None);
    let mut list = Column::new().spacing(s.pad(space::BASE)).push(side_head(
        "Destinations",
        Some(Workspace::Network),
        s,
    ));
    if groups.is_empty() {
        list = list.push(empty("No outbound connections.", s));
    }
    for g in groups.iter().take(6) {
        let agents = g.agents.len();
        list = list.push(side_row(
            brand::logo(Subject::Company(&g.name), &g.name, 26.0, p),
            g.name.clone(),
            format!("{agents} agent{}", if agents == 1 { "" } else { "s" }),
            count(g.connections, s),
            s,
        ));
    }
    card(list, s)
}

fn findings_card<'a>(running: &[Line<'a>], s: Style) -> Element<'a, Message> {
    let mut counts: BTreeMap<&str, (&crate::report::SummaryRisk, usize)> = BTreeMap::new();
    for line in running {
        for agent in std::iter::once(line.agent).chain(line.servers.iter().copied()) {
            for risk in agent
                .summary
                .iter()
                .flat_map(|s| s.risks.iter())
                .filter(|r| r.level != "info")
            {
                counts.entry(risk.id.as_str()).or_insert((risk, 0)).1 += 1;
            }
        }
    }
    let mut found: Vec<_> = counts.into_values().collect();
    found.sort_by(|a, b| {
        level_rank(&a.0.level)
            .cmp(&level_rank(&b.0.level))
            .then(b.1.cmp(&a.1))
    });
    let mut list = Column::new()
        .spacing(s.pad(space::BASE))
        .push(side_head("Findings", None, s));
    if found.is_empty() {
        list = list.push(empty("No findings.", s));
    }
    for (risk, n) in found {
        list = list.push(side_row(
            dot(Tone::of_level(&risk.level), s),
            risk.headline.clone(),
            risk.label.clone(),
            count(n, s),
            s,
        ));
    }
    card(list, s)
}

fn activity_card(report: &Report, s: Style) -> Element<'_, Message> {
    let p = s.palette;
    let mut events: Vec<&Event> = report.events.iter().collect();
    events.sort_by_key(|e| std::cmp::Reverse(e.at));
    let mut list = Column::new().spacing(s.pad(space::HAIR)).push(side_head(
        "Recent activity",
        Some(Workspace::Events),
        s,
    ));
    if events.is_empty() {
        list = list.push(empty("No activity yet.", s));
    }
    for e in events.into_iter().take(8) {
        let (label, tone) = event_label(e);
        let agent = find_agent(report, e.pid);
        let family = agent
            .and_then(|a| a.family.as_deref())
            .or(Some(e.agent.as_str()));
        let name = brand::agent_name(family);
        let content = side_row(
            brand::logo(Subject::Family(family), &name, 22.0, p),
            name,
            crate::clock::stamp(e.at),
            pill(label, tone, s),
            s,
        );
        list = list.push(if agent.is_some() {
            pressable(content, Message::OpenAgent(e.pid), false, s)
        } else {
            content
        });
    }
    card(list, s)
}

fn programs_card<'a>(
    report: &'a Report,
    picked: Option<&'a str>,
    s: Style,
) -> Element<'a, Message> {
    let p = s.palette;
    let groups = programs(&report.process_history);
    let mut list =
        Column::new()
            .spacing(s.pad(space::BASE))
            .push(side_head("Programs run", None, s));
    if groups.is_empty() {
        list = list.push(empty("No child processes seen.", s));
    }
    let tiles: Vec<Element<'a, Message>> = groups
        .iter()
        .take(12)
        .map(|g| {
            let mut owners: Vec<String> = g
                .agents
                .iter()
                .filter_map(|pid| find_agent(report, *pid))
                .map(|a| brand::agent_name(a.family.as_deref()))
                .collect();
            owners.dedup();
            let open = picked == Some(g.name);
            let prompt = container(
                text(">_")
                    .font(theme::MONO)
                    .size(s.type_size(size::MICRO))
                    .color(p.muted),
            )
            .center_x(Length::Fixed(26.0))
            .center_y(Length::Fixed(26.0))
            .style(theme::chip(p.raised));
            let content = row![
                prompt,
                column![
                    text(g.name.to_owned())
                        .font(theme::MONO)
                        .size(s.type_size(size::BODY))
                        .color(p.text),
                    small(
                        if owners.is_empty() {
                            "\u{2014}".to_owned()
                        } else {
                            owners.join(", ")
                        },
                        s
                    ),
                ]
                .spacing(s.pad(space::HAIR))
                .width(Length::Fill),
                text(format!("{}\u{d7}", g.runs.len()))
                    .font(theme::MONO)
                    .size(s.type_size(size::BODY))
                    .color(p.muted),
            ]
            .spacing(s.pad(space::SNUG))
            .align_y(Alignment::Center);
            let toggle = if open { None } else { Some(g.name.to_owned()) };
            pressable(content, Message::PickProgram(toggle), open, s)
        })
        .collect();
    let mut tiles = tiles.into_iter();
    loop {
        let chunk: Vec<Element<'a, Message>> = tiles.by_ref().take(TILE_COLUMNS).collect();
        if chunk.is_empty() {
            break;
        }
        let filled = chunk.len();
        let mut r = Row::with_children(chunk).spacing(s.pad(space::SNUG));
        for _ in filled..TILE_COLUMNS {
            r = r.push(iced::widget::space().width(Length::Fill));
        }
        list = list.push(r);
    }
    if let Some(group) = picked.and_then(|name| groups.iter().find(|g| g.name == name)) {
        list = list.push(program_runs(report, group, s));
    }
    card(list, s)
}

const RUN_COLUMNS: [(&str, u16); 5] = [
    ("Agent", 22),
    ("PID", 10),
    ("Started", 12),
    ("Status", 16),
    ("Path", 40),
];

fn program_runs<'a>(report: &'a Report, group: &Program<'a>, s: Style) -> Element<'a, Message> {
    let p = s.palette;
    let mut runs = group.runs.clone();
    runs.sort_by_key(|r| std::cmp::Reverse(r.started_at));
    let head = row![
        heading(
            &format!("{} \u{b7} {} runs", group.name, group.runs.len()),
            s
        ),
        iced::widget::space().width(Length::Fill),
        button(text("Close").size(s.type_size(size::MICRO)).color(p.muted))
            .on_press(Message::PickProgram(None))
            .padding(0)
            .style(|_, _| button::Style::default()),
    ]
    .align_y(Alignment::Center);
    let header = RUN_COLUMNS.iter().fold(Row::new(), |r, (label, share)| {
        r.push(
            text(*label)
                .font(theme::STRONG)
                .size(s.type_size(size::MICRO))
                .color(p.faint)
                .width(Length::FillPortion(*share)),
        )
    });
    let mut table = Column::new().spacing(s.pad(space::HAIR)).push(
        container(header.spacing(s.pad(space::BASE)))
            .padding([s.pad(space::TIGHT), s.pad(space::SNUG)]),
    );
    for run in runs.into_iter().take(25) {
        let agent = find_agent(report, run.agent_pid);
        let name = agent.map_or_else(
            || "\u{2014}".to_owned(),
            |a| brand::agent_name(a.family.as_deref()),
        );
        let running = run.state == "running";
        let status = if running {
            "Running".to_owned()
        } else if let Some(code) = run.exit_code {
            format!("Ended \u{b7} code {code}")
        } else {
            "Ended".to_owned()
        };
        let path = short_path(
            run.exe
                .as_deref()
                .or(run.program.as_deref())
                .unwrap_or(&run.name),
        );
        let cells = row![
            row![
                brand::logo(
                    Subject::Family(agent.and_then(|a| a.family.as_deref())),
                    &name,
                    18.0,
                    p
                ),
                text(name.clone())
                    .size(s.type_size(size::BODY))
                    .color(p.text),
            ]
            .spacing(s.pad(space::TIGHT))
            .align_y(Alignment::Center)
            .width(Length::FillPortion(RUN_COLUMNS[0].1)),
            text(run.pid.to_string())
                .font(theme::MONO)
                .size(s.type_size(size::BODY))
                .color(p.muted)
                .width(Length::FillPortion(RUN_COLUMNS[1].1)),
            text(minute(if run.started_at > 0 {
                run.started_at
            } else {
                run.first_seen
            }))
            .size(s.type_size(size::BODY))
            .color(p.faint)
            .width(Length::FillPortion(RUN_COLUMNS[2].1)),
            container(pill(
                status,
                if running { Tone::Calm } else { Tone::Quiet },
                s
            ))
            .width(Length::FillPortion(RUN_COLUMNS[3].1)),
            text(path)
                .font(theme::MONO)
                .size(s.type_size(size::MICRO))
                .color(p.faint)
                .width(Length::FillPortion(RUN_COLUMNS[4].1)),
        ]
        .spacing(s.pad(space::BASE))
        .align_y(Alignment::Center);
        table = table.push(if agent.is_some() {
            pressable(cells, Message::OpenAgent(run.agent_pid), false, s)
        } else {
            cells.into()
        });
    }
    container(column![head, table].spacing(s.pad(space::SNUG)))
        .padding([s.pad(space::SNUG), 0.0])
        .into()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::report::Child;

    fn agent(pid: u32, family: &str, kind: &str, children: &[u32]) -> Agent {
        Agent {
            pid,
            family: Some(family.to_owned()),
            kind: Some(kind.to_owned()),
            children: children
                .iter()
                .map(|&pid| Child {
                    pid,
                    name: String::new(),
                    depth: 1,
                })
                .collect(),
            ..Agent::default()
        }
    }

    #[test]
    fn a_model_server_folds_into_the_app_that_started_it() {
        let agents = vec![
            agent(10, "unsloth", "model_runtime", &[20]),
            agent(20, "llama-cpp", "model_runtime", &[]),
        ];
        let lines = fold_servers(&agents);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].agent.pid, 10);
        assert_eq!(lines[0].servers[0].pid, 20);
    }

    #[test]
    fn an_agent_started_by_another_agent_stays_its_own_row() {
        let agents = vec![
            agent(1, "claude-desktop", "agent_editor", &[2]),
            agent(2, "claude-code", "agent", &[]),
        ];
        assert_eq!(fold_servers(&agents).len(), 2);
    }

    #[test]
    fn the_model_line_names_the_server_when_the_app_has_no_model() {
        let mut server = agent(20, "llama-cpp", "model_runtime", &[]);
        server.model = Some("unsloth/Qwen3-8B-GGUF".to_owned());
        let app = agent(10, "unsloth", "model_runtime", &[20]);
        let line = Line {
            agent: &app,
            servers: vec![&server],
        };
        assert_eq!(model_line(&line), "Qwen3-8B-GGUF via llama.cpp");
        let desktop = agent(1, "claude-desktop", "agent_editor", &[]);
        assert_eq!(
            model_line(&Line {
                agent: &desktop,
                servers: vec![]
            }),
            "Desktop app"
        );
    }

    #[test]
    fn models_are_listed_once_current_first() {
        let mut a = agent(1, "codex-cli", "agent", &[]);
        a.model = Some("openai/gpt-6.1-terra".to_owned());
        a.models_seen = vec!["openai/gpt-6-luna".to_owned(), "gpt-6.1-terra".to_owned()];
        assert_eq!(models_of(&a), vec!["gpt-6.1-terra", "gpt-6-luna"]);
    }

    #[test]
    fn a_run_listed_under_two_agents_is_counted_once() {
        let run = |agent_pid, depth| ProcessRow {
            pid: 5,
            started_at: 1,
            name: "nmap".to_owned(),
            agent_pid,
            depth,
            ..ProcessRow::default()
        };
        let history = vec![
            run(1, 4),
            run(2, 2),
            ProcessRow {
                pid: 6,
                started_at: 1,
                name: "git".to_owned(),
                agent_pid: 2,
                ..ProcessRow::default()
            },
        ];
        let groups = programs(&history);
        let nmap = groups.iter().find(|g| g.name == "nmap").unwrap();
        assert_eq!(nmap.runs.len(), 1);
        assert_eq!(nmap.runs[0].agent_pid, 2);
    }

    #[test]
    fn home_folders_are_shortened() {
        assert_eq!(short_path("/Users/someone/bin/x"), "~/bin/x");
        assert_eq!(short_path("/home/someone"), "~");
        assert_eq!(short_path("/usr/bin/git"), "/usr/bin/git");
    }

    #[test]
    fn events_read_in_short_words() {
        let e = |kind: &str, detail: &str| Event {
            kind: kind.to_owned(),
            detail: detail.to_owned(),
            ..Event::default()
        };
        assert_eq!(event_label(&e("recon", "")).0, "Network scanning");
        assert_eq!(
            event_label(&e("grade_changed", "HIGH to CRITICAL")).0,
            "Risk raised"
        );
        assert_eq!(
            event_label(&e("grade_changed", "CRITICAL to LOW")).0,
            "Risk lowered"
        );
        assert_eq!(event_label(&e("model_changed", "")).0, "Model changed");
    }
}
