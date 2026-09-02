//! The detail panels.
//!
//! Every one is a pure function from a report to a widget tree. None reads the
//! clock, the filesystem, or anything outside its arguments. That is what makes
//! them testable, and it is the property the previous interface lacked: each of
//! its twelve panels reached into a shared mutable object to find its data, so
//! none of them could be exercised without building the whole application.

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
            Self::Activity => Icon::Activity,
            Self::Network => Icon::Network,
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
                | Self::Events
                | Self::Activity
                | Self::Health
                | Self::Context
        )
    }

    /// Every panel, in the order the sidebar lists them.
    pub const ALL: [Self; 10] = [
        Self::Risk,
        Self::Access,
        Self::Blast,
        Self::Activity,
        Self::Network,
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
            Self::Risk => "Risk explanation",
            Self::Access => "Access",
            Self::Blast => "Blast radius",
            Self::Network => "Network activity",
            Self::Events => "Event log",
            Self::Health => "Sensor health",
            Self::Assets => "Agents & assets",
            Self::Activity => "Activity path",
            Self::Response => "Response & governance",
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
    let agent = selected.and_then(|pid| report.agents.iter().find(|a| a.pid == pid));
    let body = match panel {
        Panel::Risk => agent.map_or_else(|| select_one(s), |a| risk(a, s)),
        Panel::Access => agent.map_or_else(|| select_one(s), |a| access(a, t, s)),
        Panel::Blast => agent.map_or_else(|| select_one(s), |a| blast(a, s)),
        Panel::Network => network(report, selected, t, s),
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

/// Name the current workspace and its scope above the evidence itself.
///
/// The old layout relied on the highlighted sidebar item as the only title.
/// Once the eye moved into the data, a network table and an event table had no
/// local identity. This compact heading keeps the evidence grounded without
/// taking a dashboard-sized band away from it.
pub fn heading<'a>(panel: Panel, agent: Option<&Agent>, s: Style) -> Element<'a, Message> {
    let p = s.palette;
    let selected = agent.map_or_else(
        || "No agent selected".to_owned(),
        |a| format!("{} / pid {}", a.label(), a.pid),
    );
    let host_wide = matches!(
        panel,
        Panel::Events | Panel::Health | Panel::Response | Panel::Context | Panel::Assets
    );

    container(
        row![
            column![
                text(panel.label())
                    .font(theme::STRONG)
                    .size(s.type_size(size::HEADING))
                    .color(p.text),
                text(panel.description())
                    .size(s.type_size(size::MICRO))
                    .color(p.faint),
            ]
            .spacing(s.pad(space::HAIR)),
            iced::widget::space().width(Length::Fill),
            text(if host_wide {
                "Host wide".to_owned()
            } else {
                selected
            })
            .font(theme::MONO)
            .size(s.type_size(size::MICRO))
            .color(p.faint),
        ]
        .align_y(iced::Alignment::Center),
    )
    .padding([s.pad(space::SNUG), s.pad(space::BASE)])
    .width(Length::Fill)
    .into()
}

fn select_one<'a>(s: Style) -> Element<'a, Message> {
    theme::notice("Select an agent.", s.palette)
}

fn risk(agent: &Agent, s: Style) -> Element<'_, Message> {
    if agent.factors.is_empty() {
        return theme::notice("Nothing scored against this agent.", s.palette);
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
                if r.latent_secret {
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
    let credentials: Vec<_> = agent.resources.iter().filter(|r| r.latent_secret).collect();
    let mut list = Column::new()
        .spacing(s.pad(space::BASE))
        .padding(s.pad(space::WIDE))
        .push(
            text(format!(
                "If {} (pid {}) were compromised, an attacker would immediately reach:",
                agent.label(),
                agent.pid
            ))
            .size(s.type_size(size::EMPHASIS)),
        );
    list = list.push(count("credentials in reach", credentials.len(), s));
    list = list.push(count("agents it can invoke", agent.invokes.len(), s));
    list = list.push(count("descendant processes", agent.children.len(), s));
    for r in credentials {
        list = list.push(
            text(format!("  {}", r.path))
                .size(s.type_size(size::BODY))
                .color(s.palette.muted),
        );
    }
    for other in &agent.invokes {
        list = list.push(
            text(format!("  invokes {other}"))
                .size(s.type_size(size::BODY))
                .color(s.palette.muted),
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

fn network<'a>(
    report: &'a Report,
    selected: Option<u32>,
    t: &'a Tables,
    s: Style,
) -> Element<'a, Message> {
    let rows = report
        .network
        .iter()
        .filter(|e| selected.is_none_or(|pid| e.agent_pid == pid))
        .map(|e| {
            let owner = crate::ownership::of(&e.host);
            // A peer the platform cannot expose says so, rather than showing a
            // wildcard that reads like a bug. A raw ICMP socket is real and
            // alarming; its destination simply is not observable here.
            let host = if e.peer_observable {
                e.dns_name.clone().unwrap_or_else(|| e.host.clone())
            } else {
                "destination not observable here".to_owned()
            };
            table::Row::new(vec![
                table::Cell::new(host),
                table::Cell::new(e.protocol.clone()),
                if e.peer_observable {
                    table::Cell::new(e.host.clone())
                } else {
                    table::Cell::tinted("-", s.palette.faint)
                },
                table::Cell::new(if e.port == 0 {
                    "-".to_owned()
                } else {
                    e.port.to_string()
                }),
                // The flag never appears without the code beside it. A glyph
                // is not a fact and must not be the only carrier of one.
                // An address the table does not cover reads faint, so a row
                // whose ownership is genuinely unknown is not mistaken for one
                // that was looked up and found uninteresting.
                if owner.known() {
                    table::Cell::new(owner.country())
                } else {
                    table::Cell::tinted(owner.country(), s.palette.faint)
                },
                if owner.known() {
                    table::Cell::new(owner.network())
                } else {
                    table::Cell::tinted(owner.network(), s.palette.faint)
                },
                table::Cell::new(e.direction.clone()),
                table::Cell::tinted(e.verdict.clone(), verdict_colour(&e.verdict, s)),
            ])
            .detailed(vec![
                (
                    "agent".to_owned(),
                    format!("{} ({})", e.agent_family, e.agent_pid),
                ),
                ("protocol".to_owned(), e.protocol.clone()),
                ("address".to_owned(), e.host.clone()),
                ("name".to_owned(), e.dns_name.clone().unwrap_or_default()),
                ("country".to_owned(), owner.country()),
                ("network".to_owned(), owner.network()),
                ("port".to_owned(), e.port.to_string()),
                ("direction".to_owned(), e.direction.clone()),
                ("verdict".to_owned(), e.verdict.clone()),
                (
                    "peer observable".to_owned(),
                    if e.peer_observable {
                        "yes".to_owned()
                    } else {
                        "no, this platform does not expose it".to_owned()
                    },
                ),
                (
                    "seen now".to_owned(),
                    if e.currently_observed {
                        "yes"
                    } else {
                        "not in the last sweep"
                    }
                    .to_owned(),
                ),
            ])
        })
        .collect();
    table::view(
        table::Id::Network,
        &NETWORK,
        rows,
        &table::state_of(t, table::Id::Network),
        "No endpoints recorded for this agent.",
        s,
    )
}

static NETWORK: [table::Column2; 8] = [
    table::Column2::text("HOST", 5),
    table::Column2::text("PROTO", 1),
    table::Column2::text("ADDRESS", 4).mono(),
    table::Column2::text("PORT", 1).number().mono(),
    table::Column2::text("COUNTRY", 2),
    table::Column2::text("NETWORK", 5),
    table::Column2::text("DIRECTION", 2),
    table::Column2::text("VERDICT", 3),
];

fn verdict_colour(verdict: &str, s: Style) -> iced::Color {
    match verdict {
        "metadata_service" | "suspicious_endpoint" => s.palette.critical,
        "exposed_listener" => s.palette.high,
        "private_peer" => s.palette.medium,
        _ => s.palette.muted,
    }
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
                table::Cell::new(e.kind.clone()),
                table::Cell::new(e.agent.clone()),
                table::Cell::new(e.pid.to_string()),
                table::Cell::new(e.detail.clone()),
            ])
            // The whole record, opened by clicking the row. The previous
            // interface had this and the table lost it: a one-line row is
            // right for scanning and wrong for reading.
            .detailed(vec![
                ("when".to_owned(), crate::clock::stamp(e.at)),
                ("kind".to_owned(), e.kind.clone()),
                ("severity".to_owned(), e.severity.clone()),
                ("agent".to_owned(), e.agent.clone()),
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
        "Nothing has changed since Topgent started watching.",
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

fn health<'a>(report: &'a Report, t: &'a Tables, s: Style) -> Element<'a, Message> {
    let p = s.palette;
    let rows = report
        .sensors
        .iter()
        .map(|sensor| {
            table::Row::new(vec![
                table::Cell::new(sensor.id.clone()),
                table::Cell::tinted(sensor.state.clone(), p.sensor(&sensor.state)),
                table::Cell::new(sensor.permission.clone()),
                table::Cell::new(sensor.detail.clone()),
                // Printed for available sensors too. A green row is not the
                // same as coverage, and this column is why.
                table::Cell::new(sensor.boundary.clone()),
            ])
            .detailed(vec![
                ("sensor".to_owned(), sensor.id.clone()),
                ("state".to_owned(), sensor.state.clone()),
                ("permission".to_owned(), sensor.permission.clone()),
                ("detail".to_owned(), sensor.detail.clone()),
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
        policy_health(report, s),
        note(
            format!(
                "{covered} of {} rules have a working sensor",
                report.coverage.len()
            ),
            "BOUNDARY lists what a sensor cannot see even when available.",
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
            "Sensor binaries",
            "SYSTEM_TRUSTED means owned by the operating system and not \
             writable by the account being watched. Anything else can be \
             replaced by what Topgent is watching.",
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
    table::Column2::text("PERMISSION", 3),
    table::Column2::text("DETAIL", 6),
    table::Column2::text("BOUNDARY", 6),
];

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
    table::Column2::text("CONFIDENCE", 2),
    table::Column2::text("SOURCE", 3),
];

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
                text(format!("{} ({})", d.agent_family, d.agent_pid))
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
            text(if c.enabled {
                "Enabled"
            } else {
                "Disabled. All other collection is unaffected."
            })
            .size(s.type_size(size::EMPHASIS)),
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
        table::Id::Agents => crate::agents::columns(),
        table::Id::Access => &ACCESS,
        table::Id::Network => &NETWORK,
        table::Id::Events => &EVENTS,
        table::Id::Activity => &ACTIVITY,
        table::Id::Health => &HEALTH,
        table::Id::Tools => &TOOLS,
        table::Id::Context => &CONTEXT,
    }
}

/// The panel chooser.
///
/// A left accent bar marks the current panel rather than a fill, so the same
/// mechanism marks the current thing everywhere in the window. Each panel
/// carries a glyph, and the glyph always has its name beside it.
pub fn sidebar<'a>(current: Panel, report: Option<&Report>, s: Style) -> Element<'a, Message> {
    let p = s.palette;
    let mut list: Column<'a, Message> = Column::new()
        // Keep the complete navigation and its coverage readout visible in a
        // standard 1024x768 window, including Comfortable density. The type
        // remains large; rhythm comes from the rows rather than dead gaps.
        .spacing(0.0)
        .padding([0.0, s.pad(space::SNUG)]);
    for panel in Panel::ALL {
        if panel == Panel::Risk {
            list = list.push(section("AGENT INVESTIGATION", s));
        } else if panel == Panel::Events {
            list = list
                .push(iced::widget::space().height(Length::Fixed(s.pad(space::TIGHT))))
                .push(coverage_section(report, s));
        }
        let selected = panel == current;
        let tint = if selected { p.accent } else { p.muted };
        let label = row![
            iced::widget::container(text(" "))
                .width(Length::Fixed(3.0))
                .height(Length::Fixed(s.type_size(size::ICON)))
                .style(move |_| iced::widget::container::Style {
                    background: Some(
                        if selected {
                            p.accent
                        } else {
                            iced::Color::TRANSPARENT
                        }
                        .into()
                    ),
                    ..iced::widget::container::Style::default()
                }),
            crate::glyph::view(panel.icon(), s.type_size(size::ICON), tint),
            text(panel.label())
                .size(s.type_size(size::LABEL))
                .font(if selected { theme::STRONG } else { theme::TEXT })
                .color(if selected { p.text } else { p.muted }),
        ]
        .spacing(s.pad(space::TIGHT))
        .align_y(iced::Alignment::Center);

        let control: Element<'a, Message> = iced::widget::button(label)
            .on_press(Message::Show(panel))
            .style(move |_, status| iced::widget::button::Style {
                background: Some(
                    if selected {
                        p.selection()
                    } else if matches!(status, iced::widget::button::Status::Hovered) {
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
                ..iced::widget::button::Style::default()
            })
            .width(Length::Fill)
            // The label and 18px glyph already provide the row's height. At
            // enlarged UI scale, extra vertical padding pushes Coverage below
            // a 768px window while adding no useful visual information.
            .padding([0.0, s.pad(space::SNUG)])
            .into();
        list = list.push(control);
    }

    iced::widget::container(list)
        .style(theme::region(Region::Panel, p))
        .width(Length::Fixed(244.0))
        // Navigation is a tool palette, not a blank full-height panel. Let the
        // surface end with its last control so tall windows do not manufacture
        // a large, bordered void beneath the menu.
        .height(Length::Shrink)
        .into()
}

fn section(label: &str, s: Style) -> Element<'_, Message> {
    text(label)
        .font(theme::STRONG)
        .size(s.type_size(size::BODY))
        .color(s.palette.faint)
        .into()
}

fn coverage_section<'a>(report: Option<&Report>, s: Style) -> Element<'a, Message> {
    let p = s.palette;
    let (covered, total) = report.map_or((0, 0), |r| {
        (
            r.coverage.iter().filter(|c| c.state == "available").count(),
            r.coverage.len(),
        )
    });
    // Coloured by how much is covered, and it says the figure either way. A
    // green bar that means no coverage is the failure this product exists to
    // prevent.
    let tint = match (covered, total) {
        (_, 0) => p.faint,
        (c, t) if c * 4 >= t * 3 => p.low,
        (c, t) if c * 2 >= t => p.medium,
        _ => p.critical,
    };
    row![
        text("HOST")
            .font(theme::STRONG)
            .size(s.type_size(size::BODY))
            .color(p.faint),
        iced::widget::space().width(Length::Fill),
        text(format!("COVERAGE {covered}/{total}"))
            .font(theme::STRONG)
            .size(s.type_size(size::BODY))
            .color(tint),
    ]
    .align_y(iced::Alignment::Center)
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// Every table the interface can resize has to have a column
    /// specification, or a drag on it panics looking for one.
    #[test]
    fn every_table_knows_its_own_columns() {
        for id in [
            table::Id::Agents,
            table::Id::Access,
            table::Id::Network,
            table::Id::Events,
            table::Id::Activity,
            table::Id::Health,
            table::Id::Tools,
            table::Id::Context,
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
    fn every_verdict_that_matters_is_coloured_apart_from_the_ordinary_one() {
        let s = Style::default();
        let ordinary = verdict_colour("observed", s);
        for verdict in [
            "metadata_service",
            "suspicious_endpoint",
            "exposed_listener",
            "private_peer",
        ] {
            assert_ne!(
                verdict_colour(verdict, s),
                ordinary,
                "{verdict} looks ordinary"
            );
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
