//! The window's frame: titlebar, navigation, page heading, status strip.
//!
//! The old interface had three disconnected regions and no single place that
//! said where you were. An operator investigating one agent read its identity
//! in a bottom strip, chose evidence from a menu floating beside the middle of
//! the window, and found the agent itself in a wide band at the top. This
//! module holds the one hierarchy that replaces all of that: a host-level
//! workspace on the left, a page that names itself, and a status strip that
//! says what collection is doing.
//!
//! Everything here is a pure function from a report and a style to a widget
//! tree. Nothing reads the clock, the filesystem, or anything outside its
//! arguments.

use crate::Message;
use crate::report::Report;
use crate::theme::{self, Region, Style, size, space};

use iced::widget::{Column, button, column, container, row, text};
use iced::{Element, Length};

/// Where the source lives.
pub const REPOSITORY: &str = "https://github.com/farikonsec/topgent";
/// Who wrote it.
pub const AUTHOR: &str = "https://github.com/farikonsec";

/// A host-level destination.
///
/// One navigation hierarchy, not two. The sidebar answers "which part of this
/// host am I looking at"; inside Agents, the agent list answers "which entity"
/// and the tabs answer "which evidence about it". The previous interface mixed
/// all three questions into a single ten-item menu, so choosing Access and
/// choosing Event log looked like the same kind of decision when one is scoped
/// to a process and the other to the machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Workspace {
    /// Which agents run here and whether any needs a decision. The landing
    /// surface.
    #[default]
    Overview,
    /// Incidents, in plain words.
    Incidents,
    /// The agent list and one agent's investigation.
    Agents,
    /// Every connection and listener on this host.
    Network,
    /// The security-change journal.
    Events,
    /// Runtime behaviour rules that held, host wide.
    Behaviour,
    /// Discovered AI assets and the decisions taken about them.
    Assets,
    /// Watchlist rules and what this host can do about a finding.
    Rules,
    /// Optional agent-supplied session context.
    Context,
    /// What this host can and cannot detect.
    Coverage,
    /// Appearance, density, refresh, notifications.
    Settings,
}

impl Workspace {
    /// What is observed, in the order the sidebar lists it.
    pub const OBSERVE: [Self; 6] = [
        Self::Overview,
        Self::Incidents,
        Self::Agents,
        Self::Network,
        Self::Events,
        Self::Behaviour,
    ];
    /// The pages of the simple view. Everything else is the advanced view.
    pub const SIMPLE: [Self; 3] = [Self::Overview, Self::Incidents, Self::Settings];
    /// What is managed, in the order the sidebar lists it.
    pub const MANAGE: [Self; 5] = [
        Self::Assets,
        Self::Rules,
        Self::Context,
        Self::Coverage,
        Self::Settings,
    ];

    /// The sidebar label, which is also the page title.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Incidents => "Incidents",
            Self::Agents => "Agents",
            Self::Network => "Network",
            Self::Events => "Event log",
            Self::Behaviour => "Behaviour",
            Self::Assets => "Assets",
            Self::Rules => "Rules & response",
            Self::Context => "Session context",
            Self::Coverage => "Coverage",
            Self::Settings => "Settings",
        }
    }

    /// The sentence under the page title. It says what the page is for in the
    /// words an operator would use, not the words the collector uses.
    #[must_use]
    pub const fn purpose(self) -> &'static str {
        match self {
            Self::Overview => "Agents running on this machine.",
            Self::Incidents => "Open incidents.",
            Self::Agents => "Running and stopped agents.",
            Self::Network => "Connections and listeners.",
            Self::Events => "Security events, newest first.",
            Self::Behaviour => "Runtime rule matches.",
            Self::Assets => "AI assets and approval status.",
            Self::Rules => "Detection rules and response actions.",
            Self::Context => "Agent-reported session data. Unverified.",
            Self::Coverage => "Sensor status and coverage.",
            Self::Settings => "Theme, density, refresh, alerts.",
        }
    }

    /// The drawing beside the name.
    #[must_use]
    pub const fn icon(self) -> crate::glyph::Icon {
        use crate::glyph::Icon;
        match self {
            Self::Overview => Icon::Activity,
            Self::Agents => Icon::Assets,
            Self::Network => Icon::Network,
            Self::Events => Icon::Events,
            Self::Incidents | Self::Behaviour => Icon::Behaviour,
            Self::Assets => Icon::Risk,
            Self::Rules => Icon::Response,
            Self::Context => Icon::Context,
            Self::Coverage => Icon::Health,
            Self::Settings => Icon::Settings,
        }
    }

    /// Which panel draws this workspace's evidence, where one does.
    ///
    /// `Agents` has none, because its evidence is chosen by the selected
    /// agent's tab rather than by the workspace; `Settings` has none, because
    /// it is an overlay over whatever was being read.
    #[must_use]
    pub const fn panel(self) -> Option<crate::panels::Panel> {
        use crate::panels::Panel;
        match self {
            Self::Overview | Self::Incidents | Self::Agents | Self::Settings => None,
            Self::Network => Some(Panel::Network),
            Self::Events => Some(Panel::Events),
            Self::Behaviour => Some(Panel::Behaviour),
            Self::Assets => Some(Panel::Assets),
            Self::Rules => Some(Panel::Response),
            Self::Context => Some(Panel::Context),
            Self::Coverage => Some(Panel::Health),
        }
    }

    /// The figure drawn at the right of the sidebar row.
    ///
    /// A count where one is meaningful, and nothing where it is not. A zero is
    /// drawn as a zero: an absent badge and a badge reading zero are different
    /// answers, and only one of them says a collector ran.
    fn tally(self, report: Option<&Report>) -> Option<String> {
        let report = report?;
        match self {
            Self::Incidents => {
                (!report.incidents.is_empty()).then(|| report.incidents.len().to_string())
            }
            Self::Agents => Some(report.agents.len().to_string()),
            Self::Network => Some(report.network.len().to_string()),
            Self::Events => Some(report.events.len().to_string()),
            Self::Behaviour => Some(report.behaviour.findings.len().to_string()),
            Self::Assets => Some(report.assets.len().to_string()),
            Self::Rules => Some(report.watchlist.len().to_string()),
            Self::Context => Some(if report.context.enabled {
                report.context.records.len().to_string()
            } else {
                "Off".to_owned()
            }),
            Self::Coverage => {
                let (covered, total) = coverage(Some(report));
                Some(format!("{covered}/{total}"))
            }
            Self::Overview | Self::Settings => None,
        }
    }
}

/// How much of what this host could detect is actually being detected.
#[must_use]
pub fn coverage(report: Option<&Report>) -> (usize, usize) {
    report.map_or((0, 0), |r| {
        (
            r.coverage.iter().filter(|c| c.state == "available").count(),
            r.coverage.len(),
        )
    })
}

/// The bar above the window: where you are, and the actions that apply to the
/// whole host rather than to one agent.
pub fn titlebar<'a>(report: Option<&Report>, s: Style) -> Element<'a, Message> {
    let p = s.palette;
    // Asked of the capture itself, not inferred from the permission. A granted
    // capability that nothing is using and a capture that is reading packets
    // are different states, and the indicator has to be able to say which.
    let (capture_label, capture_tone) = topgent_collect::capture::indicator();

    container(
        row![
            text("This host")
                .font(theme::STRONG)
                .size(s.type_size(size::EMPHASIS))
                .color(p.text),
            text("/ Local workspace")
                .size(s.type_size(size::EMPHASIS))
                .color(p.faint),
            // Beside the host rather than at the far right: on a window
            // narrower than its content the right end is what gets cut off.
            text(report.map_or_else(String::new, Report::system_line))
                .font(theme::MONO)
                .size(s.type_size(size::MICRO))
                .color(p.muted)
                .wrapping(iced::widget::text::Wrapping::None),
            iced::widget::space().width(Length::Fill),
            status_button(
                crate::glyph::Icon::Response,
                // The indicator names itself. Prefixing it printed the words
                // twice.
                capture_label,
                tone_colour(capture_tone, s),
                Message::AskCapture,
                s,
            ),
            chrome_button(
                crate::glyph::Icon::Compact,
                "Compact".to_owned(),
                Message::ToggleCompact,
                s,
            ),
            chrome_button(
                crate::glyph::Icon::Export,
                "Export".to_owned(),
                Message::Export(true),
                s,
            ),
        ]
        .spacing(s.pad(space::SNUG))
        .align_y(iced::Alignment::Center),
    )
    .style(theme::region(Region::Chrome, p))
    .padding([s.pad(space::SNUG), s.pad(space::BASE)])
    .width(Length::Fill)
    .into()
}

/// One line when a sensor cannot run on this host, and the way to the page
/// that says why.
///
/// One line, not one per sensor. The reasons are on the Coverage page in full;
/// repeating them above every screen made a permanent property of the platform
/// look like a fault that had just occurred.
pub fn unavailable<'a>(report: Option<&Report>, s: Style) -> Option<Element<'a, Message>> {
    let p = s.palette;
    let count = report.map(|r| r.failures.len()).filter(|n| *n > 0)?;
    Some(
        container(
            button(
                row![
                    crate::glyph::view(
                        crate::glyph::Icon::Info,
                        s.type_size(size::EMPHASIS),
                        p.medium
                    ),
                    text(format!(
                        "{count} sensor{} unavailable on this host",
                        if count == 1 { "" } else { "s" }
                    ))
                    .font(theme::STRONG)
                    .size(s.type_size(size::EMPHASIS))
                    .color(p.medium),
                    text("See what is not being detected")
                        .size(s.type_size(size::EMPHASIS))
                        .color(p.muted),
                ]
                .spacing(s.pad(space::SNUG))
                .align_y(iced::Alignment::Center),
            )
            .on_press(Message::Go(Workspace::Coverage))
            .padding(0)
            .style(|_, _| button::Style {
                background: None,
                ..button::Style::default()
            }),
        )
        .style(move |_| container::Style {
            background: Some(
                iced::Color {
                    a: 0.10,
                    ..p.medium
                }
                .into(),
            ),
            border: iced::Border {
                color: iced::Color {
                    a: 0.35,
                    ..p.medium
                },
                width: 1.0,
                radius: 0.0.into(),
            },
            ..container::Style::default()
        })
        .padding([s.pad(space::SNUG), s.pad(space::LOOSE)])
        .width(Length::Fill)
        .into(),
    )
}

/// The one navigation hierarchy, full height beside the content.
///
/// The simple view lists its own few pages and a way into the advanced view;
/// the advanced view lists everything and a way back.
pub fn sidebar<'a>(
    current: Workspace,
    report: Option<&Report>,
    width: f32,
    simple: bool,
    s: Style,
) -> Element<'a, Message> {
    let p = s.palette;
    let mut list: Column<'a, Message> = Column::new()
        .spacing(s.pad(space::HAIR))
        .padding([s.pad(space::BASE), s.pad(space::SNUG)])
        .push(brand(s))
        .push(iced::widget::space().height(Length::Fixed(s.pad(space::LOOSE))));
    if simple {
        for workspace in Workspace::SIMPLE {
            list = list.push(destination(workspace, current, report, s));
        }
    } else {
        list = list.push(section("OBSERVE", s));
        for workspace in Workspace::OBSERVE {
            list = list.push(destination(workspace, current, report, s));
        }
        list = list
            .push(iced::widget::space().height(Length::Fixed(s.pad(space::WIDE))))
            .push(section("MANAGE", s));
        for workspace in Workspace::MANAGE {
            list = list.push(destination(workspace, current, report, s));
        }
    }
    let switch = button(
        row![
            crate::glyph::view(
                if simple {
                    crate::glyph::Icon::Settings
                } else {
                    crate::glyph::Icon::Activity
                },
                s.type_size(size::ICON),
                p.muted
            ),
            text(if simple {
                "Advanced view"
            } else {
                "Simple view"
            })
            .size(s.type_size(size::LABEL))
            .color(p.muted),
        ]
        .spacing(s.pad(space::SNUG))
        .align_y(iced::Alignment::Center),
    )
    .on_press(Message::SetSimple(!simple))
    .width(Length::Fill)
    .padding([s.pad(space::SNUG), s.pad(space::SNUG)])
    .style(move |_, status| button::Style {
        background: Some(
            if matches!(status, button::Status::Hovered) {
                p.hover()
            } else {
                iced::Color::TRANSPARENT
            }
            .into(),
        ),
        text_color: p.text,
        border: iced::Border {
            color: p.border,
            width: 1.0,
            radius: theme::radius::CONTROL.into(),
        },
        ..button::Style::default()
    });
    list = list
        .push(iced::widget::space().height(Length::Fixed(s.pad(space::WIDE))))
        .push(switch);

    container(
        column![
            list,
            iced::widget::space().height(Length::Fill),
            container(
                column![
                    text("Local only")
                        .font(theme::STRONG)
                        .size(s.type_size(size::EMPHASIS))
                        .color(p.muted),
                    text("All data stays on this machine.")
                        .size(s.type_size(size::MICRO))
                        .color(p.faint),
                ]
                .spacing(s.pad(space::TIGHT)),
            )
            .padding([s.pad(space::BASE), s.pad(space::WIDE)]),
        ]
        .height(Length::Fill),
    )
    .style(theme::region(Region::Chrome, p))
    .width(Length::Fixed(width))
    .height(Length::Fill)
    .into()
}

/// One sidebar row: a glyph, a word, and the figure that makes it worth a look.
fn destination<'a>(
    workspace: Workspace,
    current: Workspace,
    report: Option<&Report>,
    s: Style,
) -> Element<'a, Message> {
    let p = s.palette;
    let selected = workspace == current;
    let tint = if selected { p.accent } else { p.muted };
    let tally = workspace.tally(report);

    let label = row![
        container(iced::widget::space())
            .width(Length::Fixed(3.0))
            .height(Length::Fixed(s.type_size(size::ICON)))
            .style(move |_| container::Style {
                background: Some(
                    if selected {
                        p.accent
                    } else {
                        iced::Color::TRANSPARENT
                    }
                    .into()
                ),
                ..container::Style::default()
            }),
        crate::glyph::view(workspace.icon(), s.type_size(size::ICON), tint),
        text(workspace.label())
            .size(s.type_size(size::LABEL))
            .font(if selected { theme::STRONG } else { theme::TEXT })
            .color(if selected { p.text } else { p.muted }),
        iced::widget::space().width(Length::Fill),
        text(tally.unwrap_or_default())
            .font(theme::MONO)
            .size(s.type_size(size::MICRO))
            .color(p.faint),
    ]
    .spacing(s.pad(space::SNUG))
    .align_y(iced::Alignment::Center);

    button(label)
        .on_press(Message::Go(workspace))
        .style(move |_, status| button::Style {
            background: Some(
                if selected {
                    p.selection()
                } else if matches!(status, button::Status::Hovered) {
                    p.hover()
                } else {
                    iced::Color::TRANSPARENT
                }
                .into(),
            ),
            text_color: p.text,
            border: iced::Border {
                color: iced::Color::TRANSPARENT,
                width: 0.0,
                radius: theme::radius::CONTROL.into(),
            },
            ..button::Style::default()
        })
        .width(Length::Fill)
        .padding([s.pad(space::SNUG), s.pad(space::SNUG)])
        .into()
}

/// Product mark, wordmark, and what the product is for.
fn brand<'a>(s: Style) -> Element<'a, Message> {
    let p = s.palette;
    let logo = iced::widget::svg(iced::widget::svg::Handle::from_memory(
        include_bytes!("../../../assets/icon.svg").as_slice(),
    ))
    .width(Length::Fixed(30.0))
    .height(Length::Fixed(30.0));

    column![
        row![
            logo,
            row![
                text("top")
                    .font(theme::STRONG)
                    .size(s.type_size(size::BRAND))
                    .color(p.text),
                text("gent")
                    .font(theme::STRONG)
                    .size(s.type_size(size::BRAND))
                    .color(p.accent),
            ]
            .spacing(0),
        ]
        .spacing(s.pad(space::SNUG))
        .align_y(iced::Alignment::Center),
        text("Monitor your local agents.")
            .size(s.type_size(size::MICRO))
            .color(p.faint),
    ]
    .spacing(s.pad(space::TIGHT))
    .padding([0.0, s.pad(space::SNUG)])
    .into()
}

fn section(label: &str, s: Style) -> Element<'_, Message> {
    container(
        text(label)
            .font(theme::STRONG)
            .size(s.type_size(size::MICRO))
            .color(s.palette.faint),
    )
    .padding([s.pad(space::TIGHT), s.pad(space::WIDE)])
    .into()
}

/// The page's own title, its purpose, and whatever controls belong to it.
pub fn page(
    workspace: Workspace,
    trailing: Element<'_, Message>,
    s: Style,
) -> Element<'_, Message> {
    let p = s.palette;
    container(
        row![
            column![
                text(workspace.label())
                    .font(theme::STRONG)
                    .size(s.type_size(size::TITLE))
                    .color(p.text),
                text(workspace.purpose())
                    .size(s.type_size(size::READING))
                    .color(p.muted),
            ]
            .spacing(s.pad(space::TIGHT)),
            iced::widget::space().width(Length::Fill),
            trailing,
        ]
        .align_y(iced::Alignment::Center),
    )
    .padding([s.pad(space::WIDE), s.pad(space::LOOSE)])
    .width(Length::Fill)
    .into()
}

/// Sweep now or hold where it is.
///
/// A monitor whose only way to refresh is to wait is a monitor you cannot use
/// to check whether the thing you just did was seen. Pause is beside it because
/// evidence that reorders under the pointer cannot be read.
pub fn sweep_controls<'a>(sweeping: bool, paused: bool, s: Style) -> Element<'a, Message> {
    let p = s.palette;
    let tint = if sweeping { p.faint } else { p.muted };
    row![
        button(
            row![
                crate::glyph::view(
                    if paused {
                        crate::glyph::Icon::Refresh
                    } else {
                        crate::glyph::Icon::Pause
                    },
                    s.type_size(size::ICON),
                    if paused { p.medium } else { p.muted }
                ),
                text(if paused { "Paused" } else { "Pause" })
                    .font(theme::STRONG)
                    .size(s.type_size(size::LABEL))
                    .color(if paused { p.medium } else { p.muted }),
            ]
            .spacing(s.pad(space::TIGHT))
            .align_y(iced::Alignment::Center),
        )
        .on_press(Message::TogglePause)
        .style(move |_, status| button::Style {
            background: Some(
                if matches!(status, button::Status::Hovered) {
                    p.hover()
                } else {
                    iced::Color::TRANSPARENT
                }
                .into(),
            ),
            text_color: p.muted,
            border: iced::Border {
                color: iced::Color::TRANSPARENT,
                width: 0.0,
                radius: theme::radius::CONTROL.into(),
            },
            ..button::Style::default()
        })
        .padding([s.pad(space::SNUG), s.pad(space::BASE)]),
        button(
            row![
                crate::glyph::view(crate::glyph::Icon::Refresh, s.type_size(size::ICON), tint),
                text(if sweeping { "Scanning" } else { "Refresh" })
                    .font(theme::STRONG)
                    .size(s.type_size(size::LABEL))
                    .color(tint),
            ]
            .spacing(s.pad(space::TIGHT))
            .align_y(iced::Alignment::Center),
        )
        // Disabled while a sweep is outstanding. Two sweeps at once accumulate
        // subprocesses, which this product has already been bitten by.
        .on_press_maybe((!sweeping).then_some(Message::Sweep))
        .style(move |_, status| utility_style(status, p))
        .padding([s.pad(space::SNUG), s.pad(space::BASE)]),
    ]
    .spacing(s.pad(space::SNUG))
    .align_y(iced::Alignment::Center)
    .into()
}

/// The four figures that say whether this host needs attention.
///
/// A thin strip rather than a wall of dashboard cards: these are the counts an
/// operator checks before deciding where to look, and none of them is evidence
/// on its own. Each is a control, because a number nobody can follow is a
/// number nobody acts on.
pub fn metrics<'a>(report: Option<&Report>, s: Style) -> Element<'a, Message> {
    let p = s.palette;
    let agents = report.map_or(0, |r| r.agents.len());
    let critical = report.map_or(0, |r| {
        r.agents
            .iter()
            .filter(|a| a.grade.eq_ignore_ascii_case("critical"))
            .count()
    });
    let endpoints = report.map_or(0, |r| r.network.len());
    let reads = report.map_or(0, credential_reads);
    let incidents = report.map_or(0, |r| r.incidents.len());
    let incidents_critical = report.map_or(0, |r| {
        r.incidents
            .iter()
            .filter(|i| i.severity.eq_ignore_ascii_case("critical"))
            .count()
    });
    let newest = report.map_or(0, |r| {
        r.incidents.iter().map(|i| i.first_seen).max().unwrap_or(0)
    });
    let incidents_note = if newest > 0 {
        format!("latest {}", crate::clock::stamp(newest))
    } else {
        if incidents == 0 { "None open" } else { "Open" }.to_owned()
    };

    let strip = row![
        metric(
            agents.to_string(),
            "Agents",
            "Running now".to_owned(),
            p.text,
            Message::Go(Workspace::Agents),
            s,
        ),
        rule(s),
        metric(
            critical.to_string(),
            "Critical",
            "Need a decision".to_owned(),
            if critical > 0 { p.critical } else { p.muted },
            Message::Go(Workspace::Agents),
            s,
        ),
        rule(s),
        metric(
            endpoints.to_string(),
            "Connections",
            "Including listeners".to_owned(),
            if endpoints > 0 { p.text } else { p.muted },
            Message::Go(Workspace::Network),
            s,
        ),
        rule(s),
        metric(
            reads.to_string(),
            "Secrets read",
            "Seen by a sensor".to_owned(),
            if reads > 0 { p.critical } else { p.muted },
            Message::Go(Workspace::Coverage),
            s,
        ),
        rule(s),
        metric(
            incidents.to_string(),
            "Incidents",
            incidents_note,
            if incidents_critical > 0 {
                p.critical
            } else if incidents > 0 {
                p.high
            } else {
                p.muted
            },
            Message::Go(Workspace::Incidents),
            s,
        ),
    ]
    .spacing(s.pad(space::LOOSE))
    .align_y(iced::Alignment::Center);

    container(strip)
        .style(move |_| container::Style {
            background: Some(p.background.into()),
            border: iced::Border {
                color: p.border,
                width: 1.0,
                radius: 0.0.into(),
            },
            ..container::Style::default()
        })
        .padding([s.pad(space::BASE), s.pad(space::LOOSE)])
        .width(Length::Fill)
        .into()
}

/// A single-line posture summary when large type or a narrow window needs the
/// vertical space for the selected agent and its action.
pub fn metrics_compact<'a>(report: Option<&Report>, s: Style) -> Element<'a, Message> {
    let p = s.palette;
    let agents = report.map_or(0, |r| r.agents.len());
    let critical = report.map_or(0, |r| {
        r.agents
            .iter()
            .filter(|a| a.grade.eq_ignore_ascii_case("critical"))
            .count()
    });
    let endpoints = report.map_or(0, |r| r.network.len());
    let reads = report.map_or(0, credential_reads);
    let incidents = report.map_or(0, |r| r.incidents.len());
    let mut items = iced::widget::Row::new().spacing(s.pad(space::WIDE));
    for (label, value, target) in [
        ("agents", agents, Workspace::Agents),
        ("critical", critical, Workspace::Agents),
        ("connections", endpoints, Workspace::Network),
        ("secrets read", reads, Workspace::Coverage),
        ("incidents", incidents, Workspace::Incidents),
    ] {
        items = items.push(
            button(
                text(format!("{value} {label}"))
                    .font(theme::STRONG)
                    .size(s.type_size(size::BODY))
                    .color(p.muted)
                    .wrapping(iced::widget::text::Wrapping::None),
            )
            .on_press(Message::Go(target))
            .style(button::text)
            .padding([s.pad(space::TIGHT), 0.0]),
        );
    }
    container(
        iced::widget::scrollable(items)
            .horizontal()
            .width(Length::Fill),
    )
    .style(move |_| container::Style {
        background: Some(p.background.into()),
        border: iced::Border {
            color: p.border,
            width: 1.0,
            radius: 0.0.into(),
        },
        ..container::Style::default()
    })
    .padding([s.pad(space::TIGHT), s.pad(space::LOOSE)])
    .width(Length::Fill)
    .into()
}

/// Credentials an agent was actually seen reading.
///
/// Reachable is not read. This counts only the resources a collector observed
/// being opened, so a host where nothing has happened reads zero rather than
/// reading like an incident.
fn credential_reads(report: &Report) -> usize {
    report
        .agents
        .iter()
        .flat_map(|a| a.resources.iter())
        .filter(|r| r.credential_read())
        .count()
}

fn metric<'a>(
    value: String,
    label: &'static str,
    detail: String,
    tint: iced::Color,
    message: Message,
    s: Style,
) -> Element<'a, Message> {
    let p = s.palette;
    button(
        column![
            text(value)
                .font(theme::STRONG)
                .size(s.type_size(size::METRIC))
                .color(tint),
            text(label)
                .font(theme::STRONG)
                .size(s.type_size(size::EMPHASIS))
                .color(p.text),
            text(detail).size(s.type_size(size::MICRO)).color(p.faint),
        ]
        .spacing(s.pad(space::HAIR)),
    )
    .on_press(message)
    .style(move |_, status| button::Style {
        background: Some(
            if matches!(status, button::Status::Hovered) {
                p.hover()
            } else {
                iced::Color::TRANSPARENT
            }
            .into(),
        ),
        text_color: p.text,
        border: iced::Border {
            color: iced::Color::TRANSPARENT,
            width: 0.0,
            radius: theme::radius::CONTROL.into(),
        },
        ..button::Style::default()
    })
    .padding([s.pad(space::TIGHT), s.pad(space::BASE)])
    .width(Length::FillPortion(1))
    .into()
}

fn rule<'a>(s: Style) -> Element<'a, Message> {
    let p = s.palette;
    container(iced::widget::space())
        .width(Length::Fixed(1.0))
        .height(Length::Fixed(
            s.type_size(size::METRIC) + s.pad(space::LOOSE),
        ))
        .style(move |_| container::Style {
            background: Some(p.border.into()),
            ..container::Style::default()
        })
        .into()
}

/// The strip along the bottom: what collection is doing, and what the last
/// action did.
pub fn statusbar<'a>(
    report: Option<&Report>,
    sweeping: bool,
    swept_at: Option<u64>,
    refresh_ms: u64,
    status: Option<&'a str>,
    s: Style,
) -> Element<'a, Message> {
    let p = s.palette;
    let version = report.map_or_else(String::new, |r| r.version.clone());
    let (covered, total) = coverage(report);
    let tint = if sweeping { p.medium } else { p.low };
    let cadence = if refresh_ms == 0 {
        "paused".to_owned()
    } else {
        format!("{}s interval", refresh_ms / 1000)
    };

    let collection = row![
        text("\u{25cf}").size(s.type_size(size::MICRO)).color(tint),
        text(if sweeping {
            "Scanning"
        } else {
            "Monitoring locally"
        })
        .size(s.type_size(size::MICRO))
        .color(p.muted),
        text("·").size(s.type_size(size::MICRO)).color(p.border),
        text(format!(
            "Last sweep {}",
            swept_at.map_or_else(|| "never".to_owned(), crate::clock::stamp)
        ))
        .size(s.type_size(size::MICRO))
        .color(p.faint),
        text("·").size(s.type_size(size::MICRO)).color(p.border),
        text(cadence).size(s.type_size(size::MICRO)).color(p.faint),
    ]
    .spacing(s.pad(space::SNUG))
    .align_y(iced::Alignment::Center);

    let provenance = row![
        text(format!("Coverage {covered}/{total}"))
            .size(s.type_size(size::MICRO))
            .color(p.faint),
        link(crate::glyph::Icon::Repository, "source", REPOSITORY, s),
        link(crate::glyph::Icon::Author, "farikonsec", AUTHOR, s),
        text(format!("Topgent {version}"))
            .size(s.type_size(size::MICRO))
            .color(p.faint),
    ]
    .spacing(s.pad(space::BASE))
    .align_y(iced::Alignment::Center);

    container(
        row![
            container(collection).width(Length::FillPortion(3)),
            container(outcome(status, s))
                .clip(true)
                .width(Length::FillPortion(4)),
            container(provenance)
                .align_right(Length::Fill)
                .width(Length::FillPortion(4)),
        ]
        .spacing(s.pad(space::BASE))
        .align_y(iced::Alignment::Center),
    )
    .style(theme::region(Region::Chrome, p))
    .padding([s.pad(space::TIGHT), s.pad(space::BASE)])
    .width(Length::Fill)
    .into()
}

/// The most recent operator-facing outcome, in one fixed slot.
///
/// A written file gets the control that shows it, because a path in a status
/// line is a path someone has to retype.
fn outcome<'a>(status: Option<&'a str>, s: Style) -> Element<'a, Message> {
    let p = s.palette;
    let Some(value) = status else {
        return iced::widget::space().into();
    };
    let export = value.strip_prefix("session written to ");
    let view: Element<'a, Message> = if let Some(path) = export {
        let owned = path.to_owned();
        row![
            text("EXPORT READY")
                .font(theme::STRONG)
                .size(s.type_size(size::MICRO))
                .color(p.accent),
            text(crate::table::shorten(path, 60, true))
                .font(theme::MONO)
                .size(s.type_size(size::MICRO))
                .color(p.text)
                .wrapping(iced::widget::text::Wrapping::None)
                .width(Length::Fill),
            button(
                text("Show file")
                    .font(theme::STRONG)
                    .size(s.type_size(size::MICRO))
                    .color(p.background),
            )
            .on_press(Message::Reveal(owned))
            .padding([s.pad(space::HAIR), s.pad(space::SNUG)])
            .style(move |_, state| button::Style {
                background: Some(
                    if matches!(state, button::Status::Hovered) {
                        p.text
                    } else {
                        p.accent
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
            }),
        ]
        .spacing(s.pad(space::SNUG))
        .align_y(iced::Alignment::Center)
        .into()
    } else {
        text(value.to_owned())
            .font(theme::STRONG)
            .size(s.type_size(size::MICRO))
            .color(p.accent)
            .wrapping(iced::widget::text::Wrapping::None)
            .into()
    };

    container(view)
        .style(move |_| container::Style {
            background: Some(p.selection().into()),
            border: iced::Border {
                color: p.accent,
                width: 1.0,
                radius: theme::radius::CONTROL.into(),
            },
            ..container::Style::default()
        })
        .padding([s.pad(space::HAIR), s.pad(space::SNUG)])
        .width(Length::Fill)
        .into()
}

/// One control in the window's own chrome, with the word that says what it
/// does. A glyph with no word beside it is a puzzle.
pub fn chrome_button(
    icon: crate::glyph::Icon,
    label: String,
    message: Message,
    s: Style,
) -> Element<'static, Message> {
    let p = s.palette;
    button(
        row![
            crate::glyph::view(icon, s.type_size(size::ICON), p.muted),
            text(label)
                .font(theme::STRONG)
                .size(s.type_size(size::EMPHASIS))
                .color(p.muted),
        ]
        .spacing(s.pad(space::TIGHT))
        .align_y(iced::Alignment::Center),
    )
    .on_press(message)
    .style(move |_, status| button::Style {
        background: Some(
            if matches!(status, button::Status::Hovered | button::Status::Pressed) {
                p.hover()
            } else {
                iced::Color::TRANSPARENT
            }
            .into(),
        ),
        text_color: p.muted,
        border: iced::Border {
            color: iced::Color::TRANSPARENT,
            width: 0.0,
            radius: theme::radius::CONTROL.into(),
        },
        ..button::Style::default()
    })
    .padding([s.pad(space::TIGHT), s.pad(space::BASE)])
    .into()
}

/// The one chrome control that carries a state, drawn so the state is visible
/// before the words are read.
pub fn status_button(
    icon: crate::glyph::Icon,
    label: String,
    tone: iced::Color,
    message: Message,
    s: Style,
) -> Element<'static, Message> {
    let p = s.palette;
    button(
        row![
            crate::glyph::view(icon, s.type_size(size::ICON), tone),
            text(label)
                .font(theme::STRONG)
                .size(s.type_size(size::EMPHASIS))
                .color(tone),
        ]
        .spacing(s.pad(space::TIGHT))
        .align_y(iced::Alignment::Center),
    )
    .on_press(message)
    .style(move |_, status| button::Style {
        border: iced::Border {
            color: tone,
            ..utility_style(status, p).border
        },
        text_color: tone,
        ..utility_style(status, p)
    })
    .padding([s.pad(space::TIGHT), s.pad(space::BASE)])
    .into()
}

/// The colour one capture state is drawn in.
///
/// `Inactive` stays the ordinary control colour on purpose. Capture being off
/// is a choice, not a fault, and painting it like a fault would teach people to
/// ignore the colours that are.
fn tone_colour(tone: topgent_collect::capture::Tone, s: Style) -> iced::Color {
    use topgent_collect::capture::Tone;
    match tone {
        Tone::Active => s.palette.low,
        Tone::Pending | Tone::Unknown => s.palette.medium,
        Tone::Inactive => s.palette.muted,
        Tone::Unavailable => s.palette.faint,
    }
}

/// The ordinary outlined control.
pub fn utility_style(status: button::Status, p: theme::Palette) -> button::Style {
    button::Style {
        background: Some(
            if matches!(status, button::Status::Hovered | button::Status::Pressed) {
                p.hover()
            } else {
                iced::Color::TRANSPARENT
            }
            .into(),
        ),
        text_color: p.muted,
        border: iced::Border {
            color: p.border,
            width: 1.0,
            radius: theme::radius::CONTROL.into(),
        },
        ..button::Style::default()
    }
}

fn link<'a>(
    icon: crate::glyph::Icon,
    label: &'a str,
    url: &'a str,
    s: Style,
) -> Element<'a, Message> {
    let p = s.palette;
    button(
        row![
            crate::glyph::view(icon, s.type_size(size::MICRO), p.faint),
            text(label).size(s.type_size(size::MICRO)).color(p.muted),
        ]
        .spacing(s.pad(space::TIGHT))
        .align_y(iced::Alignment::Center),
    )
    .on_press(Message::Open(url.to_owned()))
    .padding(0)
    .style(move |_, status| button::Style {
        background: None,
        text_color: if matches!(status, button::Status::Hovered) {
            p.accent
        } else {
            p.muted
        },
        ..button::Style::default()
    })
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every destination has to be reachable and has to say what it is for.
    #[test]
    fn every_destination_is_named_and_explained() {
        for workspace in Workspace::OBSERVE.iter().chain(Workspace::MANAGE.iter()) {
            assert!(!workspace.label().is_empty(), "{workspace:?} has no label");
            assert!(
                workspace.purpose().ends_with('.'),
                "{workspace:?}: a page's purpose is a sentence"
            );
        }
    }

    /// Only the two workspaces that are not an evidence page have no panel: the
    /// agent investigation picks its evidence by tab, and settings is an
    /// overlay. Anything else without one would be a destination that opens
    /// onto nothing.
    #[test]
    fn every_evidence_workspace_draws_a_panel() {
        // Overview, Incidents, Agents and Settings draw their own pages, not a table.
        for workspace in Workspace::OBSERVE.iter().chain(Workspace::MANAGE.iter()) {
            let expected = !matches!(
                workspace,
                Workspace::Overview
                    | Workspace::Incidents
                    | Workspace::Agents
                    | Workspace::Settings
            );
            assert_eq!(
                workspace.panel().is_some(),
                expected,
                "{workspace:?} draws the wrong thing"
            );
        }
    }

    /// A reachable credential is not a read one. Counting reach here would
    /// report an incident on a host where nothing has happened.
    ///
    /// The rows are shaped as the report sends them: a credential that has
    /// been opened is no longer `latent_secret`, which only means "in reach
    /// and untouched". Counting latent secrets that were observed made this
    /// tile a structural zero; the first credential S6 ever saw read showed 0.
    #[test]
    fn only_an_observed_credential_counts_as_a_read() {
        use crate::report::{Agent, Resource};
        let resource = |sensitive: bool, observed: &str| Resource {
            sensitive,
            latent_secret: sensitive && observed != "yes",
            observed: observed.to_owned(),
            reachable: "yes".to_owned(),
            ..Resource::default()
        };
        let report = Report {
            agents: vec![Agent {
                resources: vec![
                    resource(true, "yes"),
                    resource(true, "no"),
                    resource(true, "unknown"),
                    resource(false, "yes"),
                ],
                ..Agent::default()
            }],
            ..Report::default()
        };
        assert_eq!(credential_reads(&report), 1);
        // Opening a credential does not take it out of reach.
        let in_reach = report
            .agents
            .iter()
            .flat_map(|a| a.resources.iter())
            .filter(|r| r.credential_in_reach())
            .count();
        assert_eq!(in_reach, 3);
    }
}
