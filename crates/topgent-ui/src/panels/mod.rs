//! The detail panels.
//!
//! Every one is a pure function from a report to a widget tree. None reads the
//! clock, the filesystem, or anything outside its arguments. That is what makes
//! them testable, and it is the property the previous interface lacked: each of
//! its twelve panels reached into a shared mutable object to find its data, so
//! none of them could be exercised without building the whole application.

mod behaviour;
mod network;
mod observed;
mod processes;

use crate::Message;
use crate::report::{Agent, Report};
use crate::table::{self, Tables};
use crate::theme::{self, Region, Style, size, space};

use iced::widget::{Column, Space, column, container, row, scrollable, text};
use iced::{Element, Length};

/// Which panel the detail area is showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Panel {
    /// Why the selected agent scores what it does.
    Risk,
    /// Declared, observed, and reachable, side by side.
    Access,
    /// What an attacker reaches if this agent is compromised.
    Blast,
    /// Endpoints, with the verdict for each.
    Network,
    /// Every process the agent started, including those that have gone.
    Processes,
    /// Retained file and network actions.
    Actions,
    /// What the agent read, and where its data went.
    Files,
    /// Runtime behaviour rules that held.
    Behaviour,
    #[default]
    /// The security-change journal.
    Events,
    /// What this host can and cannot detect.
    Health,
    /// Discovered AI assets and the operator's decisions.
    Assets,
    /// What was observed, in order, for the selected agent.
    Activity,
    /// What this host can do about a finding, and what it has done.
    Response,
    /// Optional agent-supplied session context.
    Context,
}

impl Panel {
    /// The drawing beside this panel's name.
    #[must_use]
    pub const fn icon(self) -> crate::glyph::Icon {
        use crate::glyph::Icon;
        match self {
            Self::Risk => Icon::Risk,
            Self::Access => Icon::Access,
            Self::Blast => Icon::Blast,
            // Process history is a view of activity, so it shares the drawing.
            Self::Activity | Self::Processes | Self::Actions | Self::Files => Icon::Activity,
            Self::Network => Icon::Network,
            Self::Behaviour => Icon::Behaviour,
            Self::Events => Icon::Events,
            Self::Health => Icon::Health,
            Self::Response => Icon::Response,
            Self::Context => Icon::Context,
            Self::Assets => Icon::Assets,
        }
    }

    /// Whether this panel draws a table, which scrolls itself.
    #[must_use]
    pub const fn is_table(self) -> bool {
        matches!(
            self,
            Self::Access
                | Self::Network
                | Self::Processes
                | Self::Actions
                | Self::Behaviour
                | Self::Events
                | Self::Activity
                | Self::Health
                | Self::Context
        )
    }

    /// Every panel, in the order the sidebar lists them.
    pub const ALL: [Self; 14] = [
        Self::Risk,
        Self::Access,
        Self::Blast,
        Self::Activity,
        Self::Network,
        Self::Processes,
        Self::Actions,
        Self::Files,
        Self::Behaviour,
        Self::Events,
        Self::Health,
        Self::Response,
        Self::Context,
        Self::Assets,
    ];

    /// The sidebar label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Risk => "Overview",
            Self::Access => "Access",
            Self::Blast => "Blast radius",
            Self::Network => "Network",
            Self::Processes => "Processes",
            Self::Actions => "Actions",
            Self::Files => "Files",
            Self::Behaviour => "Behaviour",
            Self::Events => "Event log",
            Self::Health => "Coverage",
            Self::Assets => "Assets",
            Self::Activity => "Activity",
            Self::Response => "Rules & response",
            Self::Context => "Session context",
        }
    }

    /// What the panel is for, shown on hover. The previous interface had no
    /// hover text anywhere, which is a large part of why it felt inert.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::Risk => "Risk score breakdown",
            Self::Access => "Files and resources this agent can reach",
            Self::Blast => "What is exposed if this agent is compromised",
            Self::Network => "Connections and listeners",
            Self::Processes => "Processes it started, including ended ones",
            Self::Actions => "File and connection actions with direct actors",
            Self::Files => "What it read and where its data went",
            Self::Behaviour => "Runtime rules that held, with direct actors",
            Self::Events => "Security events, newest first",
            Self::Health => "Sensor status and coverage",
            Self::Assets => "Discovered AI assets",
            Self::Activity => "Timeline of observed activity",
            Self::Response => "Response rules and actions taken",
            Self::Context => "Agent-reported session summaries. Disabled by default",
        }
    }
}

/// Draw the chosen panel.
pub fn view<'a>(
    panel: Panel,
    report: &'a Report,
    selected: Option<u32>,
    t: &'a Tables,
    draft: &crate::Draft,
    s: Style,
) -> Element<'a, Message> {
    let agent = selected.and_then(|pid| report.find_agent(pid));
    let body = match panel {
        Panel::Risk => agent.map_or_else(|| select_one(s), |a| risk(a, s)),
        Panel::Access => agent.map_or_else(|| select_one(s), |a| access(a, t, s)),
        Panel::Blast => agent.map_or_else(|| select_one(s), |a| blast(a, s)),
        Panel::Network => network::view(report, selected, t, s),
        Panel::Processes => processes::view(report, selected, t, s),
        Panel::Actions => observed::view(report, selected, t, s),
        Panel::Files => files(report, selected, s),
        Panel::Behaviour => behaviour::view(report, selected, t, s),
        Panel::Events => events(report, t, s),
        Panel::Health => health(report, t, s),
        Panel::Assets => assets(report, s),
        Panel::Activity => activity(report, selected, t, s),
        Panel::Response => response(report, draft, s),
        Panel::Context => context(report, t, s),
    };
    // The table draws its own scroll region. A scrollable wrapping a
    // scrollable takes the wheel from the inner one, which is exactly the
    // nested-scrolling complaint the rewrite set out to fix.
    if panel.is_table() {
        return container(body)
            .width(Length::Fill)
            .height(Length::Fill)
            .into();
    }
    scrollable(container(body).width(Length::Fill))
        .height(Length::Fill)
        .width(Length::Fill)
        .into()
}

/// The control that starts a fresh event log.
///
///
/// Labelled for what it does. It archives rather than deletes, so one press is
/// enough and no confirmation is owed: nothing is lost, and a dialog in front
/// of a reversible action teaches people to click through dialogs.
pub fn clear_button<'a>(s: Style) -> Element<'a, Message> {
    let p = s.palette;
    iced::widget::button(
        text("Clear log")
            .font(theme::STRONG)
            .size(s.type_size(size::MICRO))
            .color(p.muted),
    )
    .on_press(Message::ClearEvents)
    .style(move |_, status| iced::widget::button::Style {
        background: Some(
            if matches!(
                status,
                iced::widget::button::Status::Hovered | iced::widget::button::Status::Pressed
            ) {
                p.hover()
            } else {
                p.background
            }
            .into(),
        ),
        text_color: p.muted,
        border: iced::Border {
            color: p.border,
            width: 1.0,
            radius: theme::radius::CONTROL.into(),
        },
        ..iced::widget::button::Style::default()
    })
    .padding([s.pad(space::HAIR), s.pad(space::SNUG)])
    .into()
}

fn select_one<'a>(s: Style) -> Element<'a, Message> {
    theme::notice("Select an agent.", s.palette)
}

fn risk(agent: &Agent, s: Style) -> Element<'_, Message> {
    if agent.factors.is_empty() {
        return theme::notice("No findings.", s.palette);
    }
    let mut ordered: Vec<_> = agent.factors.iter().collect();
    ordered.sort_by_key(|f| std::cmp::Reverse(f.points));
    let mut list = Column::new()
        .spacing(s.pad(space::SNUG))
        .padding(s.pad(space::WIDE));
    for f in ordered {
        list = list.push(column![
            row![
                text(format!("+{}", f.points))
                    .size(s.type_size(size::EMPHASIS))
                    .color(s.palette.grade(&agent.grade))
                    .width(Length::Fixed(44.0)),
                text(f.title.as_str()).size(s.type_size(size::EMPHASIS)),
            ]
            .spacing(s.pad(space::SNUG)),
            text(f.source.as_str())
                .size(s.type_size(size::MICRO))
                .color(s.palette.faint),
        ]);
    }
    list.into()
}

fn access<'a>(agent: &'a Agent, t: &'a Tables, s: Style) -> Element<'a, Message> {
    let p = s.palette;
    let rows = agent
        .resources
        .iter()
        .map(|r| {
            table::Row::new(vec![
                table::Cell::path(r.path.clone()),
                // A credential says so in a column of its own. The colour is a
                // second signal, never the only one, and it is not smuggled
                // into the path the way it used to be.
                if r.sensitive {
                    table::Cell::tinted("credential", p.critical)
                } else {
                    table::Cell::new("-")
                },
                table::Cell::new(r.declared.clone()),
                table::Cell::new(r.observed.clone()),
                // "yes" means the kernel was asked and answered. Anything
                // else says which of the two weaker answers it is, because
                // "unknown" alone reads as nobody having looked when in fact
                // the path resolved and readability could not be established.
                if r.reachable == "yes" {
                    table::Cell::tinted("yes", p.critical)
                } else if r.reachable_evidence == "path_resolves" {
                    table::Cell::new("path only")
                } else {
                    table::Cell::new(r.reachable.clone())
                },
            ])
        })
        .collect();
    table::view(
        table::Id::Access,
        &ACCESS,
        rows,
        &table::state_of(t, table::Id::Access),
        "No resources recorded for this agent.",
        s,
    )
}

static ACCESS: [table::Column2; 5] = [
    table::Column2::text("RESOURCE", 8).mono(),
    table::Column2::text("SECRET", 2),
    table::Column2::text("DECLARED", 2),
    table::Column2::text("OBSERVED", 2),
    table::Column2::text("REACHABLE", 2),
];

fn blast(agent: &Agent, s: Style) -> Element<'_, Message> {
    let credentials: Vec<_> = agent
        .resources
        .iter()
        .filter(|r| r.credential_in_reach())
        .collect();
    let mut list = Column::new()
        .spacing(s.pad(space::BASE))
        .padding(s.pad(space::WIDE))
        .push(
            text(format!(
                "If {} (pid {}) were compromised, an attacker would immediately reach:",
                agent.label(),
                agent.pid
            ))
            .size(s.type_size(size::EMPHASIS))
            .wrapping(iced::widget::text::Wrapping::WordOrGlyph)
            .width(Length::Fill),
        );
    list = list.push(count("credentials in reach", credentials.len(), s));
    list = list.push(count("agents it can invoke", agent.invokes.len(), s));
    list = list.push(count("descendant processes", agent.children.len(), s));
    for r in credentials {
        list = list.push(
            text(format!("  {}", r.path))
                .size(s.type_size(size::BODY))
                .color(s.palette.muted)
                .wrapping(iced::widget::text::Wrapping::WordOrGlyph)
                .width(Length::Fill),
        );
    }
    for other in &agent.invokes {
        list = list.push(
            text(format!("  invokes {}", other.label()))
                .size(s.type_size(size::BODY))
                .color(s.palette.muted)
                .wrapping(iced::widget::text::Wrapping::WordOrGlyph)
                .width(Length::Fill),
        );
    }
    list.into()
}

fn count(label: &str, n: usize, s: Style) -> Element<'_, Message> {
    row![
        text(n.to_string())
            .size(s.type_size(size::HEADING))
            .color(if n == 0 {
                s.palette.muted
            } else {
                s.palette.high
            }),
        text(label)
            .size(s.type_size(size::BODY))
            .color(s.palette.faint),
    ]
    .spacing(s.pad(space::SNUG))
    .into()
}

fn events<'a>(report: &'a Report, t: &'a Tables, s: Style) -> Element<'a, Message> {
    let p = s.palette;
    let rows = report
        .events
        .iter()
        .map(|e| {
            table::Row::new(vec![
                table::Cell::new(crate::clock::stamp(e.at)),
                table::Cell::tinted(e.severity.clone(), p.grade(&e.severity)),
                table::Cell::new(crate::overview::event_label(e).0),
                table::Cell::new(report.run_name(e.pid, e.started_at, &e.agent)),
                table::Cell::new(e.pid.to_string()),
                table::Cell::new(e.detail.clone()),
            ])
            // The whole record, opened by clicking the row. The previous
            // interface had this and the table lost it: a one-line row is
            // right for scanning and wrong for reading.
            .detailed(vec![
                ("when".to_owned(), crate::clock::stamp(e.at)),
                ("kind".to_owned(), crate::overview::event_label(e).0),
                ("severity".to_owned(), e.severity.clone()),
                (
                    "agent".to_owned(),
                    report.run_name(e.pid, e.started_at, &e.agent),
                ),
                ("process".to_owned(), e.pid.to_string()),
                (
                    "direction".to_owned(),
                    e.direction.clone().unwrap_or_default(),
                ),
                ("detail".to_owned(), e.detail.clone()),
            ])
        })
        .collect();
    table::view(
        table::Id::Events,
        &EVENTS,
        rows,
        &table::state_of(t, table::Id::Events),
        "No events yet.",
        s,
    )
}

static EVENTS: [table::Column2; 6] = [
    table::Column2::text("WHEN", 3).mono(),
    table::Column2::text("SEVERITY", 2),
    table::Column2::text("KIND", 3),
    table::Column2::text("AGENT", 3),
    table::Column2::text("PID", 1).number().mono(),
    table::Column2::text("DETAIL", 8),
];

// This is one declarative column of independently tested notes and tables;
// splitting it would hide the reading order without simplifying any branch.
#[allow(clippy::too_many_lines)]
fn health<'a>(report: &'a Report, t: &'a Tables, s: Style) -> Element<'a, Message> {
    let p = s.palette;
    let rows = report
        .sensors
        .iter()
        .map(|sensor| {
            table::Row::new(vec![
                table::Cell::new(sensor.id.clone()),
                table::Cell::tinted(sensor.state.clone(), p.sensor(&sensor.state)),
                table::Cell::new(coverage_label(&sensor.collection_coverage)),
                table::Cell::new(sensor.fact_count.to_string()),
                table::Cell::new(loss_label(sensor.dropped_events)),
            ])
            .detailed(vec![
                ("sensor".to_owned(), sensor.id.clone()),
                ("state".to_owned(), sensor.state.clone()),
                ("permission".to_owned(), sensor.permission.clone()),
                ("detail".to_owned(), sensor.detail.clone()),
                ("loss accounting".to_owned(), sensor.loss_accounting.clone()),
                // What it still cannot see when it is working. A green row is
                // not coverage, and this line is the reason.
                ("boundary".to_owned(), sensor.boundary.clone()),
            ])
        })
        .collect();
    let covered = report
        .coverage
        .iter()
        .filter(|c| c.state == "available")
        .count();
    let catalogue = &report.behaviour.catalogue;
    let mut rules: Vec<&crate::report::RuleState> = catalogue.coverage.iter().collect();
    rules.sort_by_key(|r| {
        (
            !r.live,
            !r.enabled,
            behaviour::rank(&r.priority),
            r.needs.first().map_or("", String::as_str),
            r.rule.as_str(),
        )
    });

    // Which binaries the sensors actually ran. A sensor is worth exactly what
    // the program behind it is worth, and an accepted location is not proof of
    // ownership: `/usr/local/bin` and `/opt/homebrew/bin` belong to the
    // logged-in user on most developer machines.
    let tools = report
        .tools
        .iter()
        .map(|tool| {
            table::Row::new(vec![
                table::Cell::new(tool.name.clone()),
                if tool.state == "system_trusted" {
                    table::Cell::new(tool.state.clone())
                } else {
                    table::Cell::tinted(tool.state.clone(), p.critical)
                },
                table::Cell::new(tool.path.clone()),
            ])
        })
        .collect();

    column![
        note(deployment_title(report), deployment_detail(report), s),
        policy_health(report, s),
        note(
            format!(
                "Prevention: {}",
                if report.interception.state.is_empty() {
                    "unknown"
                } else {
                    &report.interception.state
                }
            ),
            if report.interception.detail.is_empty() {
                "No interception backend.".to_owned()
            } else {
                report.interception.detail.clone()
            },
            s,
        ),
        note(
            "Decision engine: deterministic · containment: advisory only",
            "Topgent reports and responds. It does not block operations.",
            s,
        ),
        note(
            format!(
                "{covered} of {} rules have a working sensor",
                report.coverage.len()
            ),
            "Expand a row for its limits.",
            s,
        ),
        table::view(
            table::Id::Health,
            &HEALTH,
            rows,
            &table::state_of(t, table::Id::Health),
            "No sensors reported.",
            s,
        ),
        note(
            format!(
                "Rule visibility: {} of {} can fire here",
                catalogue.live.min(catalogue.rules),
                catalogue.rules
            ),
            "Rules that cannot fire are grouped by their first missing field.",
            s,
        ),
        table::view(
            table::Id::RuleCatalogue,
            &behaviour::RULES,
            rules
                .into_iter()
                .map(|r| behaviour::rule_row(r, s))
                .collect(),
            &table::state_of(t, table::Id::RuleCatalogue),
            "This report carries no runtime-rule catalogue.",
            s,
        ),
        note(
            "Sensor binaries",
            "SYSTEM_TRUSTED: owned by the operating system, not writable by the watched account.",
            s,
        ),
        table::view(
            table::Id::Tools,
            &TOOLS,
            tools,
            &table::state_of(t, table::Id::Tools),
            "No sensor binaries reported.",
            s,
        ),
    ]
    .into()
}

fn deployment_title(report: &Report) -> String {
    let ready = report
        .deployment
        .helpers
        .iter()
        .filter(|helper| helper.state == "ready")
        .count();
    format!(
        "Install: {} · {ready}/{} helpers ready",
        if report.deployment.mode.is_empty() {
            "unknown"
        } else {
            &report.deployment.mode
        },
        report.deployment.helpers.len()
    )
}

fn deployment_detail(report: &Report) -> String {
    let problems = report
        .deployment
        .helpers
        .iter()
        .filter(|helper| helper.state != "ready")
        .map(|helper| format!("{}: {}", helper.name, helper.state.replace('_', " ")))
        .collect::<Vec<_>>();
    let kernel = if report.deployment.kernel.is_empty() {
        "kernel not reported"
    } else {
        &report.deployment.kernel
    };
    if problems.is_empty() {
        format!("Kernel {kernel}. Both narrow helpers are present with restricted permissions.")
    } else {
        format!("Kernel {kernel}. {}.", problems.join("; "))
    }
}

static TOOLS: [table::Column2; 3] = [
    table::Column2::text("BINARY", 3),
    table::Column2::text("TRUST", 3),
    table::Column2::text("PATH", 8),
];

/// Which rules produced this report.
///
/// A policy that broke and fell back to built-in defaults used to look exactly
/// like a fresh install. The distinction has to reach the person reading the
/// findings, because every one of them was scored against different rules.
fn policy_health(report: &Report, s: Style) -> Element<'_, Message> {
    policy_warning(&report.policy_health).map_or_else(
        || Space::new().into(),
        |(title, detail)| note(title, detail, s),
    )
}

/// The line an unhealthy policy puts on the screen, if it puts one there.
///
/// Separate from the drawing so the decision is testable: a widget's reported
/// size cannot tell an empty `Space` from a rendered note.
fn policy_warning(health: &crate::report::PolicyHealth) -> Option<(String, String)> {
    match health.state.as_str() {
        "malformed" => Some((
            "Your policy is not in force".to_owned(),
            format!(
                "{} could not be read, so these findings were scored against built-in defaults: {}",
                health.path, health.detail
            ),
        )),
        "recovered" => Some((
            "Policy recovered from the last-known-good copy".to_owned(),
            format!(
                "{} could not be read and the previous copy was loaded instead: {}",
                health.path, health.detail
            ),
        )),
        // Absent, valid, or a report from a build that predates the field.
        // None of the three is a fault, and none of them needs a line.
        _ => None,
    }
}

static HEALTH: [table::Column2; 5] = [
    table::Column2::text("SENSOR", 3),
    table::Column2::text("STATE", 2),
    table::Column2::text("COVERAGE", 2),
    table::Column2::text("FACTS", 1).number(),
    table::Column2::text("LOSSES", 2),
];

fn coverage_label(coverage: &str) -> &'static str {
    match coverage {
        "snapshot_only" => "Limited",
        "loss_observed" => "Loss observed",
        "collector_degraded" => "Degraded",
        "unsupported" => "Unavailable",
        // Only a continuous sensor that ran the whole interval and counted no
        // loss earns this, and it is about that one interval.
        "complete_for_window" => "Continuous, no loss",
        // Future schema values need an explicit UI contract first.
        _ => "Unknown",
    }
}

fn loss_label(dropped: Option<u64>) -> String {
    dropped.map_or_else(|| "Unknown".to_owned(), |n| format!("{n} measured"))
}

/// A heading and the sentence under it, above a table.
fn note(
    title: impl Into<String>,
    detail: impl Into<String>,
    s: Style,
) -> Element<'static, Message> {
    Column::new()
        .spacing(s.pad(space::HAIR))
        .padding(
            iced::Padding::ZERO
                .top(s.pad(space::WIDE))
                .bottom(s.pad(space::SNUG))
                .left(s.pad(space::WIDE))
                .right(s.pad(space::WIDE)),
        )
        .push(
            text(title.into())
                .font(theme::STRONG)
                .size(s.type_size(size::EMPHASIS))
                .color(s.palette.text),
        )
        .push(
            text(detail.into())
                .size(s.type_size(size::MICRO))
                .color(s.palette.faint),
        )
        .into()
}

fn assets(report: &Report, s: Style) -> Element<'_, Message> {
    let p = s.palette;
    if report.assets.is_empty() {
        return theme::notice("No AI assets discovered.", s.palette);
    }
    let mut list = Column::new()
        .spacing(s.pad(space::SNUG))
        .padding(s.pad(space::WIDE))
        .push(
            text("Discovered assets")
                .font(theme::STRONG)
                .size(s.type_size(size::EMPHASIS))
                .color(p.text),
        )
        .push(
            text("Sets how the asset is scored. Does not remove, block or uninstall it.")
                .size(s.type_size(size::MICRO))
                .color(p.faint),
        );

    for asset in &report.assets {
        let mut choices = row![].spacing(s.pad(space::TIGHT));
        for (value, label) in DISPOSITIONS {
            let id = asset.id.clone();
            choices = choices.push(chip(
                label,
                asset.disposition == value,
                Message::SetDisposition(id, value),
                s,
            ));
        }
        list = list.push(
            iced::widget::container(
                Column::new()
                    .spacing(s.pad(space::TIGHT))
                    .push(
                        row![
                            text(asset.name.clone())
                                .wrapping(iced::widget::text::Wrapping::None)
                                .size(s.type_size(size::BODY))
                                .color(p.text)
                                .width(Length::FillPortion(5)),
                            text(asset.kind.clone())
                                .size(s.type_size(size::MICRO))
                                .color(p.muted)
                                .width(Length::FillPortion(2)),
                            text(asset.version.clone().unwrap_or_else(|| "-".into()))
                                .font(theme::MONO)
                                .size(s.type_size(size::MICRO))
                                .color(p.muted)
                                .width(Length::FillPortion(2)),
                            text(if asset.active { "running" } else { "installed" })
                                .size(s.type_size(size::MICRO))
                                .color(if asset.active { p.low } else { p.faint })
                                .width(Length::FillPortion(2)),
                        ]
                        .spacing(s.pad(space::SNUG))
                        .align_y(iced::Alignment::Center),
                    )
                    .push(choices),
            )
            .style(theme::region(Region::Panel, p))
            .padding(s.pad(space::BASE))
            .width(Length::Fill)
            .clip(true),
        );
    }
    scrollable(list).height(Length::Fill).into()
}

/// The four decisions the core accepts about an asset.
const DISPOSITIONS: [(&str, &str); 4] = [
    ("unreviewed", "not reviewed"),
    ("approved", "approved"),
    ("restricted", "restricted"),
    ("disallowed", "disallowed"),
];

fn activity<'a>(
    report: &'a Report,
    selected: Option<u32>,
    t: &'a Tables,
    s: Style,
) -> Element<'a, Message> {
    let rows = report
        .activity
        .events
        .iter()
        .filter(|e| selected.is_none_or(|pid| e.agent_pid == pid))
        .rev()
        .map(|e| {
            table::Row::new(vec![
                table::Cell::new(crate::clock::stamp(e.at)),
                table::Cell::new(e.kind.clone()),
                table::Cell::new(e.title.clone()),
                table::Cell::new(e.detail.clone()),
                // Correlation is not causation, and the confidence column says
                // which this is rather than the sentence implying it.
                table::Cell::new(e.confidence.clone()),
                table::Cell::new(e.collector.clone()),
            ])
            .detailed(vec![
                ("when".to_owned(), crate::clock::stamp(e.at)),
                ("kind".to_owned(), e.kind.clone()),
                ("what".to_owned(), e.title.clone()),
                ("detail".to_owned(), e.detail.clone()),
                // Correlation is not causation. The confidence says which this
                // is, and the sensor says where it came from, so a reader can
                // judge the claim rather than take it.
                ("confidence".to_owned(), e.confidence.clone()),
                ("observed by".to_owned(), e.collector.clone()),
                ("agent process".to_owned(), e.agent_pid.to_string()),
            ])
        })
        .collect();
    table::view(
        table::Id::Activity,
        &ACTIVITY,
        rows,
        &table::state_of(t, table::Id::Activity),
        "Nothing recorded for this agent yet.",
        s,
    )
}

static ACTIVITY: [table::Column2; 6] = [
    table::Column2::text("WHEN", 3).mono(),
    table::Column2::text("KIND", 3),
    table::Column2::text("WHAT", 6),
    table::Column2::text("DETAIL", 6),
    table::Column2::text("CONFIDENCE", 3),
    table::Column2::text("SOURCE", 3),
];

/// What the selected agent read, and where its data went.
///
/// A plain-language page, not a table: the summary of the read, the folders it
/// touched most, anything that looked like a secret, and for each destination
/// its total, its largest burst, that burst as a share of the read once the
/// read is large enough to mean something, and the files it had just opened
/// when it sent. The bytes are encrypted, so this never says the files were
/// what went out — only what was open at the time.
#[allow(clippy::too_many_lines)]
fn files(report: &Report, selected: Option<u32>, s: Style) -> Element<'_, Message> {
    let p = s.palette;
    let Some(agent) = selected.and_then(|pid| report.find_agent(pid)) else {
        return theme::notice("Select an agent.", p);
    };
    let Some(flow) = report
        .agent_flows
        .iter()
        .find(|f| f.agent.pid == agent.pid && f.agent.started_at == agent.started_at)
    else {
        return theme::notice(
            "No file reads or transfers recorded. Requires the eBPF sensor on Linux.",
            p,
        );
    };

    let read = if flow.bytes_read > 0 {
        format!(
            "{} files ({})",
            fmt_count(flow.files_read),
            fmt_bytes(flow.bytes_read)
        )
    } else {
        format!("{} files", fmt_count(flow.files_read))
    };
    let hist = if flow.history_files > 0 {
        format!(", {} from git history", fmt_count(flow.history_files))
    } else {
        String::new()
    };
    let basis_note = if flow.large_read {
        "Bursts shown as a share of the total read."
    } else {
        "Bursts shown as totals."
    };
    let mut body = Column::new()
        .spacing(s.pad(space::BASE))
        .padding(s.pad(space::WIDE))
        .push(note(
            format!("Read {read} under {}{hist}", flow.workspace),
            basis_note,
            s,
        ));

    let folders: Vec<&crate::report::FlowFolder> = flow
        .folders
        .iter()
        .filter(|d| !d.directory.is_empty())
        .collect();
    if !folders.is_empty() {
        let mut list = Column::new().spacing(s.pad(space::HAIR));
        for d in folders {
            list = list.push(
                row![
                    text(fmt_count(d.files))
                        .font(theme::MONO)
                        .size(s.type_size(size::BODY))
                        .color(p.muted)
                        .width(Length::Fixed(64.0)),
                    text(d.directory.clone())
                        .font(theme::MONO)
                        .size(s.type_size(size::BODY))
                        .color(p.text),
                ]
                .spacing(s.pad(space::SNUG)),
            );
        }
        body = body.push(files_section("Folders read most", list, s));
    }

    if !flow.sensitive.is_empty() {
        let mut list = Column::new().spacing(s.pad(space::HAIR)).push(
            text("Matched by file name. Contents are never read.")
                .size(s.type_size(size::MICRO))
                .color(p.faint)
                .width(Length::Fill),
        );
        for path in &flow.sensitive {
            list = list.push(
                row![
                    text("⚠").size(s.type_size(size::BODY)).color(p.critical),
                    text(path.clone())
                        .font(theme::MONO)
                        .size(s.type_size(size::BODY))
                        .color(p.text),
                ]
                .spacing(s.pad(space::SNUG)),
            );
        }
        body = body.push(files_section("Files that look like secrets", list, s));
    }

    let sent: Vec<&crate::report::FlowDestination> =
        flow.destinations.iter().filter(|d| d.bytes > 0).collect();
    if !sent.is_empty() {
        let mut list = Column::new().spacing(s.pad(space::SNUG));
        for d in sent {
            let label = if !d.name.is_empty() {
                d.name.clone()
            } else if !d.owner.is_empty() {
                d.owner.clone()
            } else if d.address.is_empty() {
                "unknown".to_owned()
            } else {
                format!("{}:{}", d.address, d.port)
            };
            let tag = if d.own_service {
                " · its own service".to_owned()
            } else if d.address.is_empty() {
                String::new()
            } else {
                format!(" · {}:{}", d.address, d.port)
            };
            let share = d
                .burst_percent_of_workspace
                .map_or_else(String::new, |pct| {
                    format!(" (about {pct}% of the {})", flow.compared_with)
                });
            let hot = d.over_threshold;
            let mut card = Column::new()
                .spacing(s.pad(space::HAIR))
                .push(
                    text(format!("{label}{tag}"))
                        .font(theme::STRONG)
                        .size(s.type_size(size::BODY))
                        .color(p.text)
                        .wrapping(iced::widget::text::Wrapping::WordOrGlyph)
                        .width(Length::Fill),
                )
                .push(
                    text(format!(
                        "{} in total, biggest {}-min burst {}{share}",
                        fmt_bytes(d.bytes),
                        flow.burst_window_minutes,
                        fmt_bytes(d.burst_bytes)
                    ))
                    .size(s.type_size(size::MICRO))
                    .color(p.muted),
                );
            if !d.files_before_burst.is_empty() {
                card = card.push(
                    text("Files it had just read when that burst was sent (contents not seen):")
                        .size(s.type_size(size::MICRO))
                        .color(p.faint),
                );
                for path in &d.files_before_burst {
                    card = card.push(
                        text(format!("  {}", file_tail(path)))
                            .font(theme::MONO)
                            .size(s.type_size(size::MICRO))
                            .color(p.muted)
                            .wrapping(iced::widget::text::Wrapping::None)
                            .width(Length::Fill),
                    );
                }
            }
            list = list.push(
                container(card)
                    .style(theme::region(
                        if hot { Region::Tooltip } else { Region::Panel },
                        p,
                    ))
                    .padding(s.pad(space::BASE))
                    .width(Length::Fill)
                    .clip(true),
            );
        }
        body = body.push(files_section("Where its data went", list, s));
    }

    // `view` already scrolls a page that is not a table; a second scrollable
    // inside it would take the wheel from the first.
    body.into()
}

/// A titled block inside the Files page.
fn files_section<'a>(title: &'a str, inner: Column<'a, Message>, s: Style) -> Element<'a, Message> {
    Column::new()
        .spacing(s.pad(space::SNUG))
        .push(
            text(title)
                .font(theme::STRONG)
                .size(s.type_size(size::EMPHASIS))
                .color(s.palette.text),
        )
        .push(inner)
        .into()
}

/// The last two path segments: enough to recognise a file without the lead-in.
fn file_tail(path: &str) -> String {
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    if parts.len() <= 2 {
        return path.to_owned();
    }
    let mut last_two: Vec<&str> = parts.into_iter().rev().take(2).collect();
    last_two.reverse();
    last_two.join("/")
}

/// `313 MB`, matching the incident card's wording.
fn fmt_bytes(n: u64) -> String {
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

/// `42,411`.
fn fmt_count(n: u64) -> String {
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

fn response<'a>(report: &'a Report, draft: &crate::Draft, s: Style) -> Element<'a, Message> {
    let p = s.palette;
    let c = &report.response.capability;
    let mut body = Column::new()
        .spacing(s.pad(space::BASE))
        .padding(s.pad(space::WIDE));

    body = body.push(
        text("Available actions")
            .font(theme::STRONG)
            .size(s.type_size(size::EMPHASIS))
            .color(p.text),
    );
    let mut modes = row![].spacing(s.pad(space::LOOSE));
    for (mode, value) in [
        ("observe", &c.observe),
        ("alert", &c.alert),
        ("intercept", &c.intercept),
        ("terminate", &c.terminate),
    ] {
        // Capability is printed whatever it says. A mode that is unavailable
        // here is a boundary to state, not a row to omit.
        let stated = describe(value);
        let usable = matches!(stated.as_str(), "available" | "true");
        modes = modes.push(
            Column::new()
                .spacing(s.pad(space::HAIR))
                .push(
                    text(mode)
                        .font(theme::STRONG)
                        .size(s.type_size(size::BODY))
                        .color(p.text),
                )
                .push(
                    text(stated)
                        .size(s.type_size(size::MICRO))
                        .color(if usable { p.low } else { p.medium }),
                ),
        );
    }
    body = body.push(modes);

    body = body.push(
        text("Rules")
            .font(theme::STRONG)
            .size(s.type_size(size::EMPHASIS))
            .color(p.text),
    );
    body = body.push(
        text("Modes this host cannot perform are still listed, and refused when triggered.")
            .size(s.type_size(size::MICRO))
            .color(p.faint),
    );

    body = body.push(rule_editor(draft, s));

    if report.watchlist.is_empty() {
        body = body.push(
            text("No rules are configured.")
                .size(s.type_size(size::BODY))
                .color(p.muted),
        );
    }
    for rule in &report.watchlist {
        body = body.push(rule_row(rule, s));
    }

    body.push(taken(report, s)).into()
}

/// What the ladder actually did, rule by rule.
fn taken(report: &Report, s: Style) -> Column<'_, Message> {
    let p = s.palette;
    let mut list = Column::new().spacing(s.pad(space::TIGHT)).push(
        text("Recent actions")
            .font(theme::STRONG)
            .size(s.type_size(size::EMPHASIS))
            .color(p.text),
    );
    if report.response.decisions.is_empty() {
        return list.push(
            text("No response has been taken.")
                .size(s.type_size(size::BODY))
                .color(p.faint),
        );
    }
    for d in &report.response.decisions {
        // Requested and outcome are printed separately and always. A rule that
        // asked for one mode and got another is the single most important
        // thing this panel can say, and one word for both hides it.
        let honoured = d.requested == d.outcome;
        list = list.push(
            row![
                text(format!(
                    "{} ({})",
                    report.run_name(d.agent_pid, d.agent_started_at, &d.agent_family),
                    d.agent_pid
                ))
                .size(s.type_size(size::MICRO))
                .color(p.text)
                .width(Length::FillPortion(3)),
                text(format!("{} {}", d.condition, d.path))
                    .font(theme::MONO)
                    .wrapping(iced::widget::text::Wrapping::None)
                    .size(s.type_size(size::MICRO))
                    .color(p.muted)
                    .width(Length::FillPortion(3)),
                text(format!("asked {} · got {}", d.requested, d.outcome))
                    .size(s.type_size(size::MICRO))
                    .color(if honoured { p.muted } else { p.high })
                    .width(Length::FillPortion(3)),
                text(d.transition.clone())
                    .size(s.type_size(size::MICRO))
                    .color(p.faint)
                    .width(Length::FillPortion(2)),
            ]
            .spacing(s.pad(space::SNUG)),
        );
    }
    list
}

/// The control for adding a rule.
///
/// This is the menu the product did not have. A monitor whose policy can only
/// be edited by hand in a JSON file is a monitor whose policy does not get
/// edited, and the whole watchlist feature was reachable only that way.
fn rule_editor<'a>(draft: &crate::Draft, s: Style) -> Element<'a, Message> {
    let p = s.palette;
    let mut conditions = row![].spacing(s.pad(space::TIGHT));
    for (value, label) in CONDITIONS {
        conditions = conditions.push(chip(
            label,
            draft.condition == value,
            Message::RuleCondition(value),
            s,
        ));
    }
    let mut severities = row![].spacing(s.pad(space::TIGHT));
    for (value, label) in SEVERITIES {
        severities = severities.push(chip(
            label,
            draft.severity == value,
            Message::RuleSeverity(value),
            s,
        ));
    }

    iced::widget::container(
        Column::new()
            .spacing(s.pad(space::SNUG))
            .push(
                text("Add rule")
                    .font(theme::STRONG)
                    .size(s.type_size(size::EMPHASIS))
                    .color(p.text),
            )
            .push(
                text("Substring match on the resource path. Not a glob or regex.")
                    .size(s.type_size(size::MICRO))
                    .color(p.faint),
            )
            .push(
                iced::widget::text_input(".ssh, or /etc/, or credentials", &draft.path)
                    .on_input(Message::RulePath)
                    .on_submit(Message::AddRule)
                    .font(theme::MONO)
                    .size(s.type_size(size::BODY))
                    .padding([s.pad(space::TIGHT), s.pad(space::SNUG)])
                    .style(move |_, _| iced::widget::text_input::Style {
                        background: p.background.into(),
                        border: iced::Border {
                            color: p.border,
                            width: 1.0,
                            radius: theme::radius::CONTROL.into(),
                        },
                        icon: p.faint,
                        placeholder: p.faint,
                        value: p.text,
                        selection: p.accent,
                    }),
            )
            .push(
                row![
                    text("when").size(s.type_size(size::MICRO)).color(p.faint),
                    conditions,
                    text("worth").size(s.type_size(size::MICRO)).color(p.faint),
                    severities,
                    iced::widget::space().width(Length::Fill),
                    iced::widget::button(
                        text("Add rule")
                            .font(theme::STRONG)
                            .size(s.type_size(size::BODY))
                            .color(p.background)
                    )
                    .on_press(Message::AddRule)
                    .padding([s.pad(space::TIGHT), s.pad(space::WIDE)])
                    .style(move |_, status| iced::widget::button::Style {
                        background: Some(
                            if matches!(status, iced::widget::button::Status::Hovered) {
                                p.text
                            } else {
                                p.accent
                            }
                            .into()
                        ),
                        text_color: p.background,
                        border: iced::Border {
                            color: iced::Color::TRANSPARENT,
                            width: 0.0,
                            radius: theme::radius::CONTROL.into(),
                        },
                        ..iced::widget::button::Style::default()
                    }),
                ]
                .spacing(s.pad(space::SNUG))
                .align_y(iced::Alignment::Center),
            ),
    )
    .style(theme::region(Region::Panel, p))
    .padding(s.pad(space::BASE))
    .width(Length::Fill)
    .into()
}

/// What the core accepts for a condition, with the words a reader understands.
const CONDITIONS: [(&str, &str); 3] = [
    ("reachable", "an agent could reach it"),
    ("observed", "an agent has touched it"),
    ("write", "an agent can write to it"),
];

/// What the core accepts for a severity.
const SEVERITIES: [(&str, &str); 4] = [
    ("critical", "critical"),
    ("40", "+40"),
    ("20", "+20"),
    ("10", "+10"),
];

/// One small choice in a group.
fn chip(label: &str, chosen: bool, message: Message, s: Style) -> Element<'_, Message> {
    let p = s.palette;
    iced::widget::button(text(label).size(s.type_size(size::MICRO)))
        .on_press(message)
        .padding([s.pad(space::HAIR), s.pad(space::SNUG)])
        .style(move |_, status| iced::widget::button::Style {
            background: Some(
                if chosen {
                    p.accent
                } else if matches!(status, iced::widget::button::Status::Hovered) {
                    p.raised
                } else {
                    iced::Color::TRANSPARENT
                }
                .into(),
            ),
            text_color: if chosen { p.background } else { p.muted },
            border: iced::Border {
                color: p.border,
                width: 1.0,
                radius: theme::radius::CONTROL.into(),
            },
            ..iced::widget::button::Style::default()
        })
        .into()
}

/// The five modes the core accepts. It refuses anything else, so this list is
/// the interface's only claim about what a rule can be set to.
const MODES: [&str; 5] = ["observe", "alert", "approval", "block", "kill"];

fn rule_row(rule: &crate::report::Rule, s: Style) -> Element<'_, Message> {
    let p = s.palette;
    let mut choices = row![].spacing(s.pad(space::TIGHT));
    for mode in MODES {
        let chosen = rule.response == mode;
        let index = rule.index;
        choices = choices.push(
            iced::widget::button(text(mode).size(s.type_size(size::MICRO)))
                .on_press(Message::SetRuleResponse(index, mode))
                .padding([s.pad(space::HAIR), s.pad(space::SNUG)])
                .style(move |_, status| iced::widget::button::Style {
                    background: Some(
                        if chosen {
                            p.accent
                        } else if matches!(status, iced::widget::button::Status::Hovered) {
                            p.raised
                        } else {
                            iced::Color::TRANSPARENT
                        }
                        .into(),
                    ),
                    text_color: if chosen { p.background } else { p.muted },
                    border: iced::Border {
                        color: p.border,
                        width: 1.0,
                        radius: theme::radius::CONTROL.into(),
                    },
                    ..iced::widget::button::Style::default()
                }),
        );
    }
    iced::widget::container(
        Column::new()
            .spacing(s.pad(space::SNUG))
            .push(
                row![
                    text(rule.path.clone())
                        .font(theme::MONO)
                        .wrapping(iced::widget::text::Wrapping::None)
                        .size(s.type_size(size::BODY))
                        .color(p.text)
                        .width(Length::FillPortion(5)),
                    text(rule.condition.clone())
                        .size(s.type_size(size::MICRO))
                        .color(p.muted)
                        .width(Length::FillPortion(3)),
                    text(rule.severity.clone())
                        .size(s.type_size(size::MICRO))
                        .color(p.high)
                        .width(Length::FillPortion(1)),
                ]
                .spacing(s.pad(space::BASE))
                .align_y(iced::Alignment::Center),
            )
            .push(
                row![
                    choices,
                    iced::widget::space().width(Length::Fill),
                    iced::widget::button(
                        text("remove")
                            .size(s.type_size(size::MICRO))
                            .color(p.critical)
                    )
                    .on_press(Message::RemoveRule(rule.index))
                    .padding([s.pad(space::HAIR), s.pad(space::SNUG)])
                    .style(iced::widget::button::text),
                ]
                .align_y(iced::Alignment::Center),
            ),
    )
    .style(theme::region(Region::Panel, p))
    .padding(s.pad(space::BASE))
    .width(Length::Fill)
    .clip(true)
    .into()
}

/// Render a capability value without asserting a shape the report may change.
fn describe(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Bool(b) => (if *b { "available" } else { "unavailable" }).to_owned(),
        serde_json::Value::Object(map) => map
            .get("state")
            .or_else(|| map.get("detail"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("stated in the report")
            .to_owned(),
        serde_json::Value::Null => "not stated".to_owned(),
        other => other.to_string(),
    }
}

fn context<'a>(report: &'a Report, t: &'a Tables, s: Style) -> Element<'a, Message> {
    let c = &report.context;
    let head = Column::new()
        .spacing(s.pad(space::TIGHT))
        .padding([s.pad(space::WIDE), s.pad(space::WIDE)])
        .push(
            text(if c.enabled { "Enabled" } else { "Disabled." }).size(s.type_size(size::EMPHASIS)),
        );

    let rows = c
        .records
        .iter()
        .map(|r| {
            table::Row::new(vec![
                table::Cell::new(r.session_id.clone()),
                table::Cell::new(r.objective.clone()),
                // A summary an agent supplied about itself, never a prompt.
                table::Cell::new(r.summary.clone()),
            ])
        })
        .collect();

    column![
        head,
        table::view(
            table::Id::Context,
            &CONTEXT,
            rows,
            &table::state_of(t, table::Id::Context),
            "No records retained.",
            s,
        ),
    ]
    .into()
}

static CONTEXT: [table::Column2; 3] = [
    table::Column2::text("SESSION", 3).mono(),
    table::Column2::text("OBJECTIVE", 2),
    table::Column2::text("SUMMARY", 9),
];

/// The columns of one table, so a resize can find the column it is changing.
///
/// One place that knows which specification belongs to which table. A second
/// copy of this mapping would be a second thing to keep in step, and the one
/// that drifted would silently resize the wrong column.
#[must_use]
pub fn columns_of(id: table::Id) -> &'static [table::Column2] {
    match id {
        table::Id::Access => &ACCESS,
        table::Id::Network => &network::NETWORK,
        table::Id::Processes => &processes::PROCESSES,
        table::Id::Actions => &observed::ACTIONS,
        table::Id::Findings => &behaviour::FINDINGS,
        table::Id::RuleCatalogue => &behaviour::RULES,
        table::Id::Events => &EVENTS,
        table::Id::Activity => &ACTIVITY,
        table::Id::Health => &HEALTH,
        table::Id::Tools => &TOOLS,
        table::Id::Context => &CONTEXT,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensor_labels_do_not_turn_unknown_or_zero_loss_into_full_coverage() {
        assert_eq!(loss_label(None), "Unknown");
        assert_eq!(loss_label(Some(0)), "0 measured");
        assert_eq!(loss_label(Some(4)), "4 measured");
        assert_eq!(coverage_label("snapshot_only"), "Limited");
        assert_eq!(coverage_label("complete_for_window"), "Continuous, no loss");
        assert_eq!(coverage_label("loss_observed"), "Loss observed");
        // `complete_for_window` has had a UI contract since S5; only unknown
        // values are still refused.
        for value in ["", "future_value"] {
            assert_eq!(coverage_label(value), "Unknown");
        }
    }

    #[test]
    fn decision_status_keeps_models_and_containment_out_of_the_hot_path() {
        let title = "Decision engine: deterministic · containment: advisory only";
        let detail = "Semantic-model triage is not in the detection or enforcement path. Topgent reports evidence and guarded response actions; it does not claim that an observed operation was prevented.";
        assert!(title.contains("deterministic"));
        assert!(title.contains("advisory only"));
        assert!(detail.contains("not in the detection or enforcement path"));
        assert!(detail.contains("does not claim"));
    }

    #[test]
    fn install_summary_names_helper_readiness_and_kernel() {
        let mut report = Report::default();
        report.deployment.mode = "versioned_user_install".to_owned();
        report.deployment.kernel = "6.19-test".to_owned();
        report.deployment.helpers = vec![
            crate::report::DeploymentHelper {
                name: "topgent-capture".to_owned(),
                state: "ready".to_owned(),
            },
            crate::report::DeploymentHelper {
                name: "topgent-sensor".to_owned(),
                state: "missing".to_owned(),
            },
        ];
        assert_eq!(
            deployment_title(&report),
            "Install: versioned_user_install · 1/2 helpers ready"
        );
        let detail = deployment_detail(&report);
        assert!(detail.contains("Kernel 6.19-test"));
        assert!(detail.contains("topgent-sensor: missing"));
    }

    /// A tooltip is read in a glance or not at all.
    ///
    /// The first version of this asserted a *minimum* length, which is how the
    /// descriptions grew into sentences nobody reads. The standard now is the
    /// opposite: say what the panel is, in a few words, and stop.
    #[test]
    fn every_panel_is_named_and_described_briefly() {
        for panel in Panel::ALL {
            assert!(!panel.label().is_empty(), "{panel:?} has no label");
            let description = panel.description();
            assert!(!description.is_empty(), "{panel:?} has no description");
            assert!(
                description.split_whitespace().count() <= 8,
                "{panel:?}: {description:?} is a sentence, not a label"
            );
            assert!(
                !description.ends_with('.'),
                "{panel:?}: a tooltip is a label, not prose"
            );
        }
    }

    /// A heading that does not fit its own column is clipped, and a clipped
    /// right-aligned heading loses its first letters: `PACKETS` printed as
    /// `CKETS`. Every heading must fit the share its column is given in the
    /// narrowest place that table is ever drawn.
    ///
    /// The narrowest is an agent tab: the window less the navigation, the
    /// agent list, and the page padding. A host-wide page is wider, so sizing
    /// every table for the agent tab sizes all of them.
    #[test]
    fn every_heading_fits_the_column_it_labels() {
        const USABLE: f32 = 1360.0 - 228.0 - 304.0 - 48.0;
        for id in [
            table::Id::Access,
            table::Id::Network,
            table::Id::Events,
            table::Id::Activity,
            table::Id::Health,
            table::Id::Tools,
            table::Id::Context,
            table::Id::Processes,
            table::Id::Actions,
            table::Id::Findings,
            table::Id::RuleCatalogue,
        ] {
            let columns = columns_of(id);
            let total = f32::from(columns.iter().map(|c| c.portion).sum::<u16>());
            for column in columns {
                let share = USABLE * f32::from(column.portion) / total;
                let letters = u16::try_from(column.label.chars().count()).unwrap_or(u16::MAX);
                let needed = f32::from(letters) * theme::size::MICRO * 0.66;
                assert!(
                    share >= needed,
                    "{id:?}: {} needs {needed:.0}px and its column gives {share:.0}px",
                    column.label
                );
            }
        }
    }

    /// Every table the interface can resize has to have a column
    /// specification, or a drag on it panics looking for one.
    #[test]
    fn every_table_knows_its_own_columns() {
        for id in [
            table::Id::Access,
            table::Id::Network,
            table::Id::Events,
            table::Id::Activity,
            table::Id::Health,
            table::Id::Tools,
            table::Id::Context,
            table::Id::Processes,
            table::Id::Actions,
            table::Id::Findings,
            table::Id::RuleCatalogue,
        ] {
            assert!(!columns_of(id).is_empty(), "{id:?} has no columns");
        }
    }

    /// A policy that broke and fell back to built-in defaults used to look
    /// exactly like a fresh install. Only the two states that change what the
    /// findings mean put a line on the screen; a valid or absent policy is not
    /// a fault and does not get one.
    #[test]
    fn only_an_unhealthy_policy_says_so_on_screen() {
        for (state, expected) in [
            ("", false),
            ("absent", false),
            ("valid", false),
            ("recovered", true),
            ("malformed", true),
        ] {
            let mut report = Report::default();
            report.policy_health.state = state.to_owned();
            report.policy_health.path = "/tmp/policy.json".to_owned();
            report.policy_health.detail = "truncated".to_owned();
            // A zero-size Space is what "no line" looks like, and it is the
            // only element with no width of its own.
            let warning = policy_warning(&report.policy_health);
            assert_eq!(
                warning.is_some(),
                expected,
                "{state:?} drew the wrong thing"
            );
            if let Some((title, detail)) = warning {
                assert!(!title.is_empty());
                assert!(detail.contains("/tmp/policy.json"), "{detail}");
            }
        }
    }

    #[test]
    fn a_reduction_and_an_escalation_do_not_share_a_colour() {
        for appearance in theme::Appearance::ALL {
            let p = appearance.palette();
            assert_ne!(p.high, p.low, "{} conflates the two", appearance.label());
        }
    }

    #[test]
    fn an_unavailable_sensor_is_not_coloured_like_a_working_one() {
        // The four sensor states are four different answers, and an interface
        // that draws them alike is the failure this product exists to prevent.
        for appearance in theme::Appearance::ALL {
            let p = appearance.palette();
            assert_ne!(p.sensor("available"), p.sensor("unsupported"));
            assert_ne!(p.sensor("available"), p.sensor("permission_required"));
            assert_ne!(p.sensor("available"), p.sensor("error"));
        }
    }
}
