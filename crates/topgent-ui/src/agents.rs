//! The agent list and one agent's investigation.
//!
//! The investigation is the point of this window, so it gets the shape: a
//! stable list on the left that never moves under the pointer, the selected
//! agent's identity above the evidence rather than in a strip at the bottom of
//! the window, and five tabs that are all about the same entity. An operator
//! answers four questions in order — which agent needs attention, what is the
//! strongest reason, what can it reach versus what did it do, and what can I do
//! about it — and each of those questions is answered without leaving this
//! region.
//!
//! Every function here is pure: a report and a style in, a widget tree out.
//! Nothing reads the clock, the filesystem, or anything outside its arguments.

use crate::Message;
use crate::report::{Agent, Report};
use crate::theme::{self, Region, Style, size, space};

use iced::widget::{Column, button, column, container, row, scrollable, text, text_input};
use iced::{Element, Length};

/// Which evidence about the selected agent is showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tab {
    /// Why it scores what it does, and what that means.
    #[default]
    Overview,
    /// What it declared, what was observed, what it can reach.
    Access,
    /// What an attacker reaches if it is compromised.
    Blast,
    /// What was observed, in order.
    Activity,
    /// Its own connections and listeners.
    Network,
    /// Every process it started, including those that have gone.
    Processes,
    /// Direct file and connection actions, retained after exit.
    Actions,
    /// What it read, and where its data went.
    Files,
    /// Behaviour rules that held on this agent's processes.
    Behaviour,
}

impl Tab {
    /// Every tab, in the order they are drawn.
    pub const ALL: [Self; 9] = [
        Self::Overview,
        Self::Access,
        Self::Blast,
        Self::Activity,
        Self::Network,
        Self::Processes,
        Self::Actions,
        Self::Files,
        Self::Behaviour,
    ];

    /// The tab's label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Access => "Access",
            Self::Blast => "Blast radius",
            Self::Activity => "Activity",
            Self::Network => "Network",
            Self::Processes => "Processes",
            Self::Actions => "Actions",
            Self::Files => "Files",
            Self::Behaviour => "Behaviour",
        }
    }

    /// Which panel draws this tab's evidence. `Overview` draws its own, because
    /// it is the only one that interprets rather than lists.
    #[must_use]
    pub const fn panel(self) -> Option<crate::panels::Panel> {
        use crate::panels::Panel;
        match self {
            Self::Overview => None,
            Self::Access => Some(Panel::Access),
            Self::Blast => Some(Panel::Blast),
            Self::Activity => Some(Panel::Activity),
            Self::Network => Some(Panel::Network),
            Self::Processes => Some(Panel::Processes),
            Self::Actions => Some(Panel::Actions),
            Self::Files => Some(Panel::Files),
            Self::Behaviour => Some(Panel::Behaviour),
        }
    }
}

/// Which agents the list is showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Scope {
    /// Everything found.
    #[default]
    All,
    /// Critical and high only.
    AtRisk,
    /// Anything the scoring rules have not reached.
    Unscored,
}

impl Scope {
    /// Every scope, in the order the filter row lists them.
    pub const ALL: [Self; 3] = [Self::All, Self::AtRisk, Self::Unscored];

    /// The chip's label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::All => "All agents",
            Self::AtRisk => "At risk",
            Self::Unscored => "Not evaluated",
        }
    }

    /// Whether one agent belongs in this scope.
    #[must_use]
    pub fn holds(self, agent: &Agent) -> bool {
        let grade = agent.grade.to_ascii_uppercase();
        match self {
            Self::All => true,
            Self::AtRisk => matches!(grade.as_str(), "CRITICAL" | "HIGH"),
            Self::Unscored => !matches!(grade.as_str(), "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"),
        }
    }
}

/// The agents this list is showing, worst first.
///
/// Ordering is by score and then pid, so the list is stable across sweeps: a
/// list that reorders while it is being read is one nobody can click.
#[must_use]
pub fn shortlist<'a>(report: &'a Report, filter: &str, scope: Scope) -> Vec<&'a Agent> {
    let needle = filter.trim().to_ascii_lowercase();
    let mut ordered: Vec<&Agent> = report
        .agents
        .iter()
        .chain(&report.ended_agents)
        .filter(|a| scope.holds(a))
        .filter(|a| {
            needle.is_empty()
                || a.label().to_ascii_lowercase().contains(&needle)
                || a.pid.to_string().contains(&needle)
                || a.exe
                    .as_deref()
                    .is_some_and(|e| e.to_ascii_lowercase().contains(&needle))
        })
        .collect();
    // Running first, then ended; each worst first.
    ordered.sort_by_key(|a| (a.has_ended(), std::cmp::Reverse(a.score), a.pid));
    ordered
}

/// The list an investigation starts from.
pub fn list<'a>(
    report: &'a Report,
    selected: Option<u32>,
    filter: &str,
    scope: Scope,
    width: f32,
    s: Style,
) -> Element<'a, Message> {
    let p = s.palette;
    let shown = shortlist(report, filter, scope);

    let mut cards = Column::new().spacing(s.pad(space::SNUG));
    if shown.is_empty() {
        cards = cards.push(
            container(
                text(if report.agents.is_empty() {
                    "No AI agents are running on this machine."
                } else {
                    "No agent matches this filter."
                })
                .size(s.type_size(size::EMPHASIS))
                .color(p.muted),
            )
            .padding(s.pad(space::WIDE)),
        );
    }
    let mut ended_heading = false;
    for agent in shown {
        if agent.has_ended() && !ended_heading {
            ended_heading = true;
            cards = cards.push(
                text("ENDED THIS SESSION")
                    .font(theme::STRONG)
                    .size(s.type_size(size::MICRO))
                    .color(p.faint),
            );
        }
        cards = cards.push(card(agent, selected == Some(agent.pid), s));
    }

    let controls = column![
        text_input("Filter agents or PID\u{2026}", filter)
            .on_input(Message::FilterAgents)
            .size(s.type_size(size::EMPHASIS))
            .padding([s.pad(space::SNUG), s.pad(space::BASE)])
            .style(move |_, _| text_input::Style {
                background: p.background.into(),
                border: iced::Border {
                    color: p.border,
                    width: 1.0,
                    radius: theme::radius::CONTROL.into(),
                },
                icon: p.faint,
                placeholder: p.faint,
                value: p.text,
                selection: p.selection(),
            }),
        row(Scope::ALL.map(|option| chip(option, option == scope, s))).spacing(s.pad(space::TIGHT)),
    ]
    .spacing(s.pad(space::SNUG))
    .padding(s.pad(space::BASE));

    let hint = container(
        column![
            text("Select an agent to investigate.")
                .size(s.type_size(size::MICRO))
                .color(p.faint),
            text("Sorted by risk.")
                .size(s.type_size(size::MICRO))
                .color(p.faint),
        ]
        .spacing(s.pad(space::HAIR)),
    )
    .padding([s.pad(space::SNUG), s.pad(space::BASE)])
    .width(Length::Fill);

    container(
        column![
            controls,
            scrollable(container(cards).padding([0.0, s.pad(space::BASE)]))
                .height(Length::Fill)
                .width(Length::Fill),
            hint,
        ]
        .height(Length::Fill),
    )
    .style(theme::region(Region::Chrome, p))
    .width(Length::Fixed(width))
    .height(Length::Fill)
    .into()
}

/// One agent, as a row scanned rather than a record read.
///
/// Name, score, what it belongs to, its pid, the strongest finding, and the two
/// words that say its band and whether it is still running. Everything else is
/// in the investigation beside it: a list cell wide enough for an executable
/// path is a list nobody can scan.
fn card(agent: &Agent, selected: bool, s: Style) -> Element<'_, Message> {
    let p = s.palette;
    let tint = p.grade(&agent.grade);
    let finding = agent
        .factors
        .iter()
        .max_by_key(|f| f.points)
        .map_or("No findings", |f| f.title.as_str());

    let body = column![
        row![
            text(agent.label())
                .font(theme::STRONG)
                .size(s.type_size(size::EMPHASIS))
                .color(p.text)
                .wrapping(iced::widget::text::Wrapping::None),
            iced::widget::space().width(Length::Fill),
            text(agent.score.to_string())
                .font(theme::MONO)
                .size(s.type_size(size::EMPHASIS))
                .color(tint),
        ]
        .align_y(iced::Alignment::Center),
        row![
            // The model beside how the agent was recognised: which LLM it
            // is, not only which tool.
            text(match agent.model.as_deref() {
                Some(model) => format!(
                    "{} \u{b7} {}",
                    agent.recognition(),
                    crate::report::short_model(model)
                ),
                None => agent.recognition().to_owned(),
            })
            .size(s.type_size(size::MICRO))
            .color(p.faint),
            iced::widget::space().width(Length::Fill),
            text(agent.pid.to_string())
                .font(theme::MONO)
                .size(s.type_size(size::MICRO))
                .color(p.faint),
        ],
        text(finding.to_owned())
            .size(s.type_size(size::MICRO))
            .color(p.muted),
        row![
            badge(&agent.grade.to_ascii_uppercase(), tint, s),
            text(agent.state_line())
                .size(s.type_size(size::MICRO))
                .color(if agent.has_ended() { p.muted } else { p.faint }),
        ]
        .spacing(s.pad(space::SNUG))
        .align_y(iced::Alignment::Center),
    ]
    .spacing(s.pad(space::TIGHT));

    button(
        row![
            container(iced::widget::space())
                .width(Length::Fixed(3.0))
                .height(Length::Fill)
                .style(move |_| container::Style {
                    background: Some(tint.into()),
                    ..container::Style::default()
                }),
            container(body).padding([s.pad(space::BASE), s.pad(space::BASE)]),
        ]
        .spacing(s.pad(space::BASE)),
    )
    .on_press(Message::Select(agent.pid))
    .width(Length::Fill)
    .padding(0)
    .style(move |_, status| button::Style {
        background: Some(
            if selected {
                p.selection()
            } else if matches!(status, button::Status::Hovered) {
                p.hover()
            } else {
                p.surface
            }
            .into(),
        ),
        text_color: p.text,
        border: iced::Border {
            color: if selected { p.accent } else { p.border },
            width: 1.0,
            radius: theme::radius::PANEL.into(),
        },
        ..button::Style::default()
    })
    .into()
}

/// A word in a tinted box. The word is the fact; the colour only repeats it.
fn badge<'a>(label: &str, tint: iced::Color, s: Style) -> Element<'a, Message> {
    container(
        text(label.to_owned())
            .font(theme::STRONG)
            .size(s.type_size(size::MICRO))
            .color(tint),
    )
    .style(move |_| container::Style {
        background: Some(iced::Color { a: 0.14, ..tint }.into()),
        border: iced::Border {
            color: iced::Color { a: 0.4, ..tint },
            width: 1.0,
            radius: theme::radius::CONTROL.into(),
        },
        ..container::Style::default()
    })
    .padding([s.pad(space::HAIR), s.pad(space::SNUG)])
    .into()
}

fn chip(scope: Scope, chosen: bool, s: Style) -> Element<'static, Message> {
    let p = s.palette;
    button(
        text(scope.label())
            .font(theme::STRONG)
            .size(s.type_size(size::MICRO))
            .color(if chosen { p.text } else { p.muted }),
    )
    .on_press(Message::SetScope(scope))
    .padding([s.pad(space::TIGHT), s.pad(space::SNUG)])
    .style(move |_, status| button::Style {
        background: Some(
            if chosen {
                p.selection()
            } else if matches!(status, button::Status::Hovered) {
                p.hover()
            } else {
                p.background
            }
            .into(),
        ),
        text_color: p.text,
        border: iced::Border {
            color: if chosen { p.accent } else { p.border },
            width: 1.0,
            radius: theme::radius::CONTROL.into(),
        },
        ..button::Style::default()
    })
    .into()
}

/// Who this agent is, directly above the evidence about it.
///
/// The old interface put this in a strip at the bottom of the window, so the
/// identity of the thing being investigated was as far from its evidence as the
/// layout allowed. Name, band, pid, recognition, and model sit here; the full
/// executable, account, and start time are one press away in the inspector,
/// because a path long enough to fill the window cannot share a line with a
/// control.
pub fn identity(agent: &Agent, inspecting: bool, s: Style) -> Element<'_, Message> {
    let p = s.palette;
    let tint = p.grade(&agent.grade);

    let subject = row![
        container(iced::widget::space())
            .width(Length::Fixed(4.0))
            .height(Length::Fixed(s.type_size(size::SUBJECT) * 1.8))
            .style(move |_| container::Style {
                background: Some(tint.into()),
                ..container::Style::default()
            }),
        column![
            row![
                text(agent.label())
                    .font(theme::STRONG)
                    .size(s.type_size(size::SUBJECT))
                    .color(p.text),
                badge(&agent.grade.to_ascii_uppercase(), tint, s),
            ]
            .spacing(s.pad(space::BASE))
            .align_y(iced::Alignment::Center),
            row![
                text(format!("PID {}", agent.pid))
                    .font(theme::MONO)
                    .size(s.type_size(size::EMPHASIS))
                    .color(p.muted),
                text("·").size(s.type_size(size::EMPHASIS)).color(p.border),
                text(
                    agent
                        .user
                        .clone()
                        .unwrap_or_else(|| "unknown account".into())
                )
                .size(s.type_size(size::EMPHASIS))
                .color(p.muted),
                text("·").size(s.type_size(size::EMPHASIS)).color(p.border),
                text(agent.recognition())
                    .size(s.type_size(size::EMPHASIS))
                    .color(p.muted),
                text("·").size(s.type_size(size::EMPHASIS)).color(p.border),
                text(agent.model_line())
                    .size(s.type_size(size::EMPHASIS))
                    .color(p.muted),
            ]
            .spacing(s.pad(space::SNUG))
            .align_y(iced::Alignment::Center),
        ]
        .spacing(s.pad(space::TIGHT)),
    ]
    .spacing(s.pad(space::BASE))
    .align_y(iced::Alignment::Center);
    let actions = row![
        iced::widget::space().width(Length::Fill),
        crate::shell::chrome_button(
            crate::glyph::Icon::Info,
            if inspecting { "Hide record" } else { "Record" }.to_owned(),
            Message::ToggleInspector,
            s,
        ),
        stop_button(agent.pid, s),
    ]
    .spacing(s.pad(space::BASE))
    .align_y(iced::Alignment::Center);

    // The identity may be arbitrarily long. Give it its own clipped row so it
    // cannot consume the Stop action's space at narrow widths or large scale.
    let mut block = Column::new()
        .spacing(s.pad(space::BASE))
        .push(container(subject).width(Length::Fill).clip(true))
        .push(actions);
    if inspecting {
        block = block.push(inspector(agent, s));
    }

    container(block)
        .padding([s.pad(space::WIDE), s.pad(space::LOOSE)])
        .width(Length::Fill)
        .into()
}

/// What the identity rests on, with any limit the report named.
fn identity_record(agent: &Agent) -> String {
    let mut record = agent.recognition().to_owned();
    for limit in &agent.identity_evidence.limits {
        record.push_str(". ");
        record.push_str(limit);
    }
    record
}

/// The full record behind the row: the values that are too long, too precise,
/// or too rarely needed to sit in the header.
fn inspector(agent: &Agent, s: Style) -> Element<'_, Message> {
    let p = s.palette;
    let mut fields = Column::new().spacing(s.pad(space::SNUG));
    for (label, value, copyable) in [
        (
            "Executable",
            agent
                .exe
                .clone()
                .unwrap_or_else(|| "not readable on this host".into()),
            agent.exe.is_some(),
        ),
        (
            "Account",
            agent.user.clone().unwrap_or_else(|| "unknown".into()),
            false,
        ),
        ("Started", crate::clock::stamp(agent.started_at), false),
        (
            "Runs in",
            agent.container.as_ref().map_or_else(
                || "the host, or a container Topgent could not name".to_owned(),
                crate::report::AgentContainer::describe,
            ),
            false,
        ),
        ("Identity evidence", identity_record(agent), false),
        ("Model provenance", agent.model_provenance(), false),
    ] {
        let owned = value.clone();
        fields = fields.push(
            row![
                text(label)
                    .font(theme::STRONG)
                    .size(s.type_size(size::MICRO))
                    .color(p.faint)
                    .width(Length::Fixed(140.0)),
                text(value)
                    .font(theme::MONO)
                    .size(s.type_size(size::BODY))
                    .color(p.text)
                    .width(Length::Fill),
                if copyable {
                    crate::shell::chrome_button(
                        crate::glyph::Icon::Export,
                        "Copy".to_owned(),
                        Message::Copy(owned.clone()),
                        s,
                    )
                } else {
                    iced::widget::space().width(Length::Shrink).into()
                },
                if copyable {
                    crate::shell::chrome_button(
                        crate::glyph::Icon::Search,
                        "Reveal".to_owned(),
                        Message::Reveal(owned),
                        s,
                    )
                } else {
                    iced::widget::space().width(Length::Shrink).into()
                },
            ]
            .spacing(s.pad(space::BASE))
            .align_y(iced::Alignment::Center),
        );
    }

    container(fields)
        .style(theme::region(Region::Panel, p))
        .padding(s.pad(space::WIDE))
        .width(Length::Fill)
        .into()
}

/// The five local tabs, under the identity they all describe.
pub fn tabs<'a>(current: Tab, s: Style) -> Element<'a, Message> {
    let p = s.palette;
    let mut bar = iced::widget::Row::new().spacing(s.pad(space::LOOSE));
    for tab in Tab::ALL {
        let chosen = tab == current;
        bar = bar.push(
            button(
                column![
                    text(tab.label())
                        .font(if chosen { theme::STRONG } else { theme::TEXT })
                        .size(s.type_size(size::LABEL))
                        .color(if chosen { p.text } else { p.muted }),
                    container(iced::widget::space())
                        .width(Length::Fill)
                        .height(Length::Fixed(2.0))
                        .style(move |_| container::Style {
                            background: Some(
                                if chosen {
                                    p.accent
                                } else {
                                    iced::Color::TRANSPARENT
                                }
                                .into()
                            ),
                            ..container::Style::default()
                        }),
                ]
                .spacing(s.pad(space::SNUG)),
            )
            .on_press(Message::ShowTab(tab))
            .padding(0)
            .style(move |_, status| button::Style {
                background: None,
                text_color: if matches!(status, button::Status::Hovered) {
                    p.text
                } else {
                    p.muted
                },
                ..button::Style::default()
            }),
        );
    }

    container(
        column![
            scrollable(bar).horizontal().width(Length::Fill),
            container(iced::widget::space())
                .width(Length::Fill)
                .height(Length::Fixed(1.0))
                .style(move |_| container::Style {
                    background: Some(p.border.into()),
                    ..container::Style::default()
                }),
        ]
        .spacing(0),
    )
    .padding([0.0, s.pad(space::LOOSE)])
    .width(Length::Fill)
    .into()
}

/// Where an investigation starts: the score, what produced it, and the two
/// questions an operator asks next.
///
/// The score is secondary to what produced it, and it is never presented as a
/// probability of compromise. Everything stated here comes from a field the
/// report actually carries; nothing is inferred.
// One reading surface, assembled top to bottom. Splitting it into helpers would
// scatter the page's order across the file without making any part clearer.
#[allow(clippy::too_many_lines)]
pub fn overview<'a>(report: &'a Report, agent: &'a Agent, s: Style) -> Element<'a, Message> {
    let p = s.palette;
    let tint = p.grade(&agent.grade);
    let credentials = agent
        .resources
        .iter()
        .filter(|r| r.credential_in_reach())
        .count();
    let reads = agent
        .resources
        .iter()
        .filter(|r| r.credential_read())
        .count();
    let endpoints = report
        .network
        .iter()
        .filter(|e| e.agent_pid == agent.pid)
        .count();
    let headline = agent
        .factors
        .iter()
        .max_by_key(|f| f.points)
        .map_or_else(|| "No findings.".to_owned(), |f| f.title.clone());

    let interpretation = column![
        text(headline)
            .font(theme::STRONG)
            .size(s.type_size(size::SUBJECT))
            .color(p.text),
        text(format!(
            "{} findings \u{b7} {} credential {} in reach \u{b7} {} read",
            agent.factors.len(),
            credentials,
            if credentials == 1 { "path" } else { "paths" },
            reads,
        ))
        .size(s.type_size(size::READING))
        .color(p.muted),
    ]
    .spacing(s.pad(space::BASE));

    let score = column![
        text(agent.score.to_string())
            .font(theme::MONO)
            .size(s.type_size(size::SCORE))
            .color(tint),
        text(agent.grade.to_ascii_uppercase())
            .font(theme::STRONG)
            .size(s.type_size(size::MICRO))
            .color(tint),
    ]
    .spacing(s.pad(space::HAIR))
    .width(Length::Fixed(96.0));

    let mut body = Column::new()
        .spacing(s.pad(space::LOOSE))
        .padding([s.pad(space::LOOSE), s.pad(space::LOOSE)])
        .push(
            row![score, interpretation]
                .spacing(s.pad(space::BASE))
                .align_y(iced::Alignment::Start),
        )
        .push(
            row![
                text("Why this score")
                    .font(theme::STRONG)
                    .size(s.type_size(size::SECTION))
                    .color(p.text),
                iced::widget::space().width(Length::Fill),
                text(format!(
                    "{} factors · deterministic rules",
                    agent.factors.len()
                ))
                .size(s.type_size(size::MICRO))
                .color(p.faint),
            ]
            .align_y(iced::Alignment::Center),
        );

    if agent.factors.is_empty() {
        body = body.push(
            text("No findings.")
                .size(s.type_size(size::READING))
                .color(p.muted),
        );
    } else {
        let mut ordered: Vec<_> = agent.factors.iter().collect();
        ordered.sort_by_key(|f| std::cmp::Reverse(f.points));
        let mut list = Column::new().spacing(0.0);
        for factor in ordered {
            list = list.push(factor_row(factor, tint, s));
        }
        body = body.push(list);
    }

    body = body.push(
        row![
            question(
                "What could be exposed?",
                format!(
                    "{credentials} credential paths · {} descendants · {} agents it can invoke",
                    agent.children.len(),
                    agent.invokes.len()
                ),
                "Potential access only.",
                "Explore blast radius",
                Message::ShowTab(Tab::Blast),
                s,
            ),
            question(
                "What has it actually done?",
                format!("{endpoints} observed endpoints · {reads} observed credential reads"),
                "A dash means no sensor recorded it.",
                "Follow the activity",
                Message::ShowTab(Tab::Activity),
                s,
            ),
        ]
        .spacing(s.pad(space::WIDE)),
    );

    scrollable(body)
        .height(Length::Fill)
        .width(Length::Fill)
        .into()
}

/// One scored finding: what it is worth, what it says, and where it came from.
fn factor_row(factor: &crate::report::Factor, tint: iced::Color, s: Style) -> Element<'_, Message> {
    let p = s.palette;
    container(
        row![
            text(format!("+{}", factor.points))
                .font(theme::MONO)
                .size(s.type_size(size::EMPHASIS))
                .color(tint)
                .width(Length::Fixed(48.0)),
            column![
                text(factor.title.as_str())
                    .font(theme::STRONG)
                    .size(s.type_size(size::READING))
                    .color(p.text),
                text(factor.source.as_str())
                    .size(s.type_size(size::MICRO))
                    .color(p.faint),
            ]
            .spacing(s.pad(space::TIGHT))
            .width(Length::Fill),
        ]
        .spacing(s.pad(space::BASE))
        .align_y(iced::Alignment::Start),
    )
    .style(move |_| container::Style {
        border: iced::Border {
            color: p.border,
            width: 0.0,
            radius: 0.0.into(),
        },
        background: None,
        ..container::Style::default()
    })
    .padding([s.pad(space::BASE), 0.0])
    .width(Length::Fill)
    .into()
}

/// One of the two questions an overview answers, with the control that takes
/// the reader to the evidence behind it.
fn question<'a>(
    title: &'a str,
    counts: String,
    caveat: &'a str,
    action: &'a str,
    message: Message,
    s: Style,
) -> Element<'a, Message> {
    let p = s.palette;
    container(
        column![
            text(title)
                .font(theme::STRONG)
                .size(s.type_size(size::EMPHASIS))
                .color(p.text),
            text(counts)
                .size(s.type_size(size::EMPHASIS))
                .color(p.muted),
            text(caveat).size(s.type_size(size::MICRO)).color(p.faint),
            button(
                row![
                    text(action)
                        .size(s.type_size(size::EMPHASIS))
                        .color(p.accent),
                    crate::glyph::view(
                        crate::glyph::Icon::Chevron,
                        s.type_size(size::BODY),
                        p.accent
                    ),
                ]
                .spacing(s.pad(space::TIGHT))
                .align_y(iced::Alignment::Center),
            )
            .on_press(message)
            .padding(0)
            .style(|_, _| button::Style {
                background: None,
                ..button::Style::default()
            }),
        ]
        .spacing(s.pad(space::SNUG)),
    )
    .style(theme::region(Region::Panel, p))
    .padding(s.pad(space::WIDE))
    .width(Length::FillPortion(1))
    .into()
}

/// Stop, beside the identity it applies to.
///
/// Outlined rather than filled: it has to be found without hunting and must not
/// be the loudest thing on the screen.
fn stop_button<'a>(pid: u32, s: Style) -> Element<'a, Message> {
    let p = s.palette;
    button(
        text("Stop")
            .font(theme::STRONG)
            .size(s.type_size(size::EMPHASIS))
            .color(p.critical),
    )
    .on_press(Message::AskStop(pid))
    .padding([s.pad(space::TIGHT), s.pad(space::SNUG)])
    .style(move |_, status| button::Style {
        background: Some(
            if matches!(status, button::Status::Hovered) {
                iced::Color {
                    a: 0.16,
                    ..p.critical
                }
            } else {
                iced::Color::TRANSPARENT
            }
            .into(),
        ),
        text_color: p.critical,
        border: iced::Border {
            color: p.critical,
            width: 1.0,
            radius: theme::radius::CONTROL.into(),
        },
        ..button::Style::default()
    })
    .into()
}

/// The selected agent, anchored at the bottom of the window.
///
/// Selection changes this strip immediately, so the operator can scan the
/// list and keep process identity, model, executable, and the stop action in
/// one stable place. The full record remains available without moving the
/// destructive action away from the process it applies to.
#[allow(clippy::too_many_lines)]
pub fn selected_footer(agent: &Agent, inspecting: bool, s: Style) -> Element<'_, Message> {
    let p = s.palette;
    let grade_tint = p.grade(&agent.grade);
    let grade = format!("{} {}", agent.grade.to_ascii_uppercase(), agent.score);
    let user = agent.user.clone().unwrap_or_else(|| "unknown".into());
    let executable = agent
        .exe
        .clone()
        .unwrap_or_else(|| "executable not readable".into());

    let field = |label: &'static str, value: String, width: Length, mono: bool| {
        container(
            column![
                text(label)
                    .font(theme::STRONG)
                    .size(s.type_size(size::BODY))
                    .color(p.faint),
                text(value)
                    .wrapping(iced::widget::text::Wrapping::None)
                    .font(if mono { theme::MONO } else { theme::TEXT })
                    .size(s.type_size(size::BODY))
                    .color(p.muted),
            ]
            .spacing(s.pad(space::TIGHT)),
        )
        .width(width)
        .clip(true)
    };

    let selected = container(
        column![
            text("SELECTED AGENT")
                .font(theme::STRONG)
                .size(s.type_size(size::BODY))
                .color(p.faint),
            row![
                text(agent.label())
                    .font(theme::STRONG)
                    .size(s.type_size(size::DISPLAY))
                    .color(p.text),
                container(
                    text(grade)
                        .font(theme::STRONG)
                        .size(s.type_size(size::BODY))
                        .color(grade_tint),
                )
                .style(move |_| container::Style {
                    background: Some(p.raised.into()),
                    border: iced::Border {
                        color: grade_tint,
                        width: 1.0,
                        radius: theme::radius::CONTROL.into(),
                    },
                    ..container::Style::default()
                })
                .padding([s.pad(space::HAIR), s.pad(space::SNUG)]),
            ]
            .spacing(s.pad(space::SNUG))
            .align_y(iced::Alignment::Center),
        ]
        .spacing(s.pad(space::HAIR)),
    )
    .width(Length::Fixed(224.0))
    .clip(true);

    let body = row![
        container(iced::widget::space())
            .width(Length::Fixed(4.0))
            .height(Length::Fixed(48.0))
            .style(move |_| container::Style {
                background: Some(grade_tint.into()),
                ..container::Style::default()
            }),
        selected,
        field(
            "PROCESS",
            format!(
                "PID {} · {} · {}",
                agent.pid,
                user,
                crate::clock::stamp(agent.started_at)
            ),
            Length::Fixed(240.0),
            true,
        ),
        field("MODEL", agent.model_line(), Length::Fixed(200.0), true),
        field("EXECUTABLE", executable, Length::Fill, true),
        crate::shell::chrome_button(
            crate::glyph::Icon::Info,
            if inspecting { "Hide record" } else { "Record" }.to_owned(),
            Message::ToggleInspector,
            s,
        ),
        prominent_stop_button(agent.pid, s),
    ]
    .align_y(iced::Alignment::Center)
    .spacing(s.pad(space::BASE));

    let mut footer = Column::new().push(body);
    if inspecting {
        footer = footer.push(inspector(agent, s));
    }
    container(footer)
        .style(theme::region(Region::Chrome, p))
        .padding([s.pad(space::TIGHT), s.pad(space::BASE)])
        .width(Length::Fill)
        .into()
}

/// The high-visibility stop action used in the selected-agent footer.
fn prominent_stop_button<'a>(pid: u32, s: Style) -> Element<'a, Message> {
    let p = s.palette;
    button(
        text("Stop process")
            .font(theme::STRONG)
            .size(s.type_size(size::LABEL))
            .color(p.background),
    )
    .on_press(Message::AskStop(pid))
    .padding([s.pad(space::SNUG), s.pad(space::LOOSE)])
    .style(move |_, status| button::Style {
        background: Some(
            if matches!(status, button::Status::Hovered) {
                p.high
            } else {
                p.critical
            }
            .into(),
        ),
        text_color: p.background,
        border: iced::Border {
            color: iced::Color::TRANSPARENT,
            width: 0.0,
            radius: theme::radius::CONTROL.into(),
        },
        ..button::Style::default()
    })
    .into()
}

/// What the last stop attempt said, above the interface until the next sweep.
///
/// The core's own sentence, not a rewritten one. A stop that was refused says
/// why it was refused, and paraphrasing that in the interface is how a refusal
/// starts reading like a success.
pub fn footnote<'a>(outcome: &str, s: Style) -> Element<'a, Message> {
    container(
        text(outcome.to_owned())
            .size(s.type_size(size::EMPHASIS))
            .color(s.palette.text),
    )
    .style(theme::region(Region::Panel, s.palette))
    .padding([s.pad(space::SNUG), s.pad(space::BASE)])
    .into()
}

/// The confirmation shown before anything is signalled.
///
/// It names the process rather than only the pid, because a pid alone is not
/// something anyone can check, and it says plainly that children go too.
pub fn confirm_stop<'a>(pid: u32, agent: Option<&Agent>, s: Style) -> Element<'a, Message> {
    let p = s.palette;
    let named = agent.map_or_else(
        || format!("pid {pid}"),
        |a| format!("{} (pid {})", a.label(), a.pid),
    );
    let executable = agent
        .and_then(|a| a.exe.clone())
        .unwrap_or_else(|| "executable not readable on this host".to_owned());
    let body = column![
        text("Stop this agent?")
            .font(theme::STRONG)
            .size(s.type_size(size::SECTION))
            .color(p.text),
        text(named).size(s.type_size(size::READING)).color(p.muted),
        text(executable)
            .font(theme::MONO)
            .size(s.type_size(size::BODY))
            .color(p.faint),
        text("Stops the process and its children. A reused PID is refused.")
            .size(s.type_size(size::MICRO))
            .color(p.faint),
        row![
            button(
                text("Cancel")
                    .size(s.type_size(size::EMPHASIS))
                    .color(p.text)
            )
            .on_press(Message::CancelStop)
            .padding([s.pad(space::TIGHT), s.pad(space::BASE)])
            .style(button::text),
            button(
                text("Stop")
                    .size(s.type_size(size::EMPHASIS))
                    .color(p.background)
            )
            .on_press(Message::ConfirmStop(pid))
            .padding([s.pad(space::TIGHT), s.pad(space::BASE)])
            .style(move |_, status| button::Style {
                background: Some(
                    if matches!(status, button::Status::Hovered) {
                        p.high
                    } else {
                        p.critical
                    }
                    .into()
                ),
                text_color: p.background,
                border: iced::Border {
                    color: iced::Color::TRANSPARENT,
                    width: 0.0,
                    radius: theme::radius::PANEL.into(),
                },
                ..button::Style::default()
            }),
        ]
        .spacing(s.pad(space::SNUG)),
    ]
    .spacing(s.pad(space::BASE));

    container(
        container(body)
            .style(theme::region(Region::Panel, p))
            .padding(s.pad(space::LOOSE))
            .width(Length::Fixed(460.0)),
    )
    .style(theme::region(Region::Scrim, p))
    .width(Length::Fill)
    .height(Length::Fill)
    .center_x(Length::Fill)
    .center_y(Length::Fill)
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::Factor;

    fn agent(pid: u32, grade: &str, score: u32) -> Agent {
        Agent {
            pid,
            grade: grade.to_owned(),
            score,
            family: Some("claude-code".to_owned()),
            factors: vec![Factor {
                points: score,
                title: "Can execute arbitrary processes".to_owned(),
                ..Factor::default()
            }],
            ..Agent::default()
        }
    }

    #[test]
    fn the_worst_agent_is_the_one_selected_by_default() {
        let report = Report {
            agents: vec![
                agent(1, "LOW", 10),
                agent(2, "CRITICAL", 90),
                agent(3, "MEDIUM", 40),
            ],
            ..Report::default()
        };
        assert_eq!(report.worst().map(|a| a.pid), Some(2));
    }

    /// The list is read top to bottom and clicked without looking twice. An
    /// order that depends on anything but the score is an order that moves
    /// under the pointer when a sweep lands.
    #[test]
    fn the_list_is_worst_first_and_stable() {
        let report = Report {
            agents: vec![
                agent(9, "LOW", 10),
                agent(2, "CRITICAL", 90),
                agent(1, "CRITICAL", 90),
                agent(3, "MEDIUM", 40),
            ],
            ..Report::default()
        };
        let order: Vec<u32> = shortlist(&report, "", Scope::All)
            .iter()
            .map(|a| a.pid)
            .collect();
        assert_eq!(
            order,
            vec![1, 2, 3, 9],
            "ties break on pid, not on order found"
        );
    }

    /// A filter that matched nothing but the name would hide the row an
    /// operator has a pid for, which is the one case they come to the filter
    /// with.
    #[test]
    fn the_filter_matches_a_pid_as_well_as_a_name() {
        let report = Report {
            agents: vec![agent(4242, "LOW", 10), agent(7, "LOW", 10)],
            ..Report::default()
        };
        assert_eq!(shortlist(&report, "4242", Scope::All).len(), 1);
        assert_eq!(shortlist(&report, "claude", Scope::All).len(), 2);
        assert_eq!(shortlist(&report, "nothing here", Scope::All).len(), 0);
    }

    /// "Not evaluated" is not a band between low and clear. An agent nobody
    /// scored has to be findable, because it is the one the scoring rules did
    /// not reach.
    #[test]
    fn an_unscored_agent_has_a_scope_that_finds_it() {
        let report = Report {
            agents: vec![
                agent(1, "CRITICAL", 90),
                agent(2, "LOW", 5),
                agent(3, "not evaluated", 0),
            ],
            ..Report::default()
        };
        assert_eq!(shortlist(&report, "", Scope::AtRisk).len(), 1);
        assert_eq!(shortlist(&report, "", Scope::Unscored).len(), 1);
        assert_eq!(shortlist(&report, "", Scope::All).len(), 3);
    }

    #[test]
    fn an_unrecognised_process_is_named_by_its_executable_not_called_unexamined() {
        let mut a = agent(1, "LOW", 0);
        a.family = None;
        a.exe = Some("/Applications/Visual Studio Code.app/Contents/MacOS/Code Helper".to_owned());
        assert_eq!(
            a.label(),
            "Code Helper",
            "the row must say what the process is"
        );
        assert_eq!(
            a.recognition(),
            "unrecognised",
            "it was examined, and not recognised"
        );
    }

    #[test]
    fn a_recognition_says_what_it_rests_on() {
        let mut a = agent(1, "LOW", 0);
        a.family = Some("claude-code".to_owned());
        a.identity_evidence.strength = Some("name_only".to_owned());
        a.identity_evidence.class = "suspected".to_owned();
        assert_eq!(a.recognition(), "suspected agent · name only");
        a.identity_evidence.strength = Some("known_install_path".to_owned());
        a.identity_evidence.class = "known".to_owned();
        assert_eq!(a.recognition(), "known agent · install path");
        a.identity_evidence.strength = Some("active_extension".to_owned());
        assert_eq!(a.recognition(), "known agent · active extension");
        // A report from an older build carries no strength and is not
        // upgraded to a claim it never made.
        a.identity_evidence.class.clear();
        a.identity_evidence.strength = None;
        assert_eq!(a.recognition(), "recognised");
    }

    #[test]
    fn a_model_says_whether_it_was_observed_or_declared_and_where() {
        let mut a = agent(1, "LOW", 0);
        a.model = Some("openai/gpt-5.6".to_owned());
        assert_eq!(a.model_line(), "openai/gpt-5.6", "an older report");
        assert!(a.model_provenance().contains("source not reported"));
        a.model_evidence = Some(crate::report::ModelEvidence {
            certainty: "declared".to_owned(),
            source: "~/.codex/config.toml".to_owned(),
            read: "the first 64 KB of the file; only the model name is kept".to_owned(),
        });
        assert_eq!(a.model_line(), "openai/gpt-5.6 · declared");
        assert_eq!(
            a.model_provenance(),
            "declared in ~/.codex/config.toml; read the first 64 KB of the file; only the \
             model name is kept"
        );
        a.model = None;
        assert!(a.model_provenance().starts_with("not found"));
    }

    #[test]
    fn a_process_whose_executable_cannot_be_read_says_so_rather_than_guessing() {
        let mut a = agent(4242, "LOW", 0);
        a.family = None;
        a.exe = None;
        assert_eq!(a.label(), "pid 4242");
        assert_eq!(a.recognition(), "unreadable");
    }

    /// Every tab but the overview hands its drawing to a panel. A tab with no
    /// panel and no drawing of its own is a tab that opens onto nothing.
    #[test]
    fn every_tab_draws_something() {
        for tab in Tab::ALL {
            assert!(!tab.label().is_empty());
            assert_eq!(tab.panel().is_none(), matches!(tab, Tab::Overview));
        }
    }
}
