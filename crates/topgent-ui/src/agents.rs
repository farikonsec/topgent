//! The header and the agent table.
//!
//! Both are pure functions from a report and a style to a widget tree. Nothing
//! here reads the clock, the filesystem, or anything outside its arguments,
//! which is what makes them testable.

use crate::Message;
use crate::report::{Agent, Report};
use crate::table::{self, Tables};
use crate::theme::{self, Region, Style, size, space};

use iced::widget::{Column, button, column, container, row, svg, text};
use iced::{Element, Length};

/// The bar above everything: what was found, and one line if a sensor cannot run.
pub fn header<'a>(
    report: Option<&Report>,
    sweeping: bool,
    swept_at: Option<u64>,
    s: Style,
) -> Element<'a, Message> {
    let p = s.palette;
    let mut bar = Column::new()
        .spacing(s.pad(space::TIGHT))
        .push(summary(report, sweeping, swept_at, s));

    // One line, not one per sensor. The reasons are in the sensor-health panel
    // in full; repeating them above every screen made a permanent property of
    // the platform look like a fault that had just occurred.
    if let Some(unavailable) = report.map(|r| r.failures.len()).filter(|n| *n > 0) {
        bar = bar.push(
            button(
                text(format!(
                    "{unavailable} sensor{} unavailable on this host",
                    if unavailable == 1 { "" } else { "s" }
                ))
                .font(theme::STRONG)
                .size(s.type_size(size::BODY))
                .color(p.medium),
            )
            .on_press(Message::Show(crate::panels::Panel::Health))
            .style(move |t, st| {
                let mut style = button::text(t, st);
                style.text_color = p.medium;
                style
            })
            .padding(0),
        );
    }

    container(bar)
        .style(theme::region(Region::Chrome, p))
        .padding([s.pad(space::TIGHT), s.pad(space::BASE)])
        .width(Length::Fill)
        .into()
}

/// Endpoints outside this machine.
///
/// Loopback, link-local, and the unroutable ranges are not "outside": counting
/// them makes every host look like it is talking to the world.
fn external_endpoints(report: &Report) -> usize {
    report
        .network
        .iter()
        .filter(|e| e.currently_observed && e.peer_observable)
        .filter(|e| {
            e.host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| !ip.is_loopback() && !is_private(ip))
        })
        .count()
}

fn is_private(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_link_local() || v4.is_unspecified(),
        std::net::IpAddr::V6(v6) => {
            v6.is_unspecified() || (v6.segments().first().copied().unwrap_or(0) & 0xfe00) == 0xfc00
        }
    }
}

/// Resources the operator asked to be told about that an agent has reached.
///
/// The number an operator configured a watchlist in order to see. It was
/// nowhere in the window.
fn watched_reached(report: &Report) -> usize {
    report
        .response
        .decisions
        .iter()
        .filter(|d| !d.outcome.is_empty() && d.outcome != "not_matched")
        .count()
}

/// Sweep now, rather than waiting for the timer.
///
/// A monitor whose only way to refresh is to wait is a monitor you cannot use
/// to check whether the thing you just did was seen.
fn refresh_button<'a>(sweeping: bool, s: Style) -> Element<'a, Message> {
    let p = s.palette;
    let tint = if sweeping { p.faint } else { p.muted };
    button(
        row![
            crate::glyph::view(
                crate::glyph::Icon::Refresh,
                s.type_size(size::DISPLAY),
                tint
            ),
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
    .padding([s.pad(space::SNUG), s.pad(space::BASE)])
    .into()
}

/// The branded instrument header: identity and controls above, telemetry below.
fn summary<'a>(
    report: Option<&Report>,
    sweeping: bool,
    swept_at: Option<u64>,
    s: Style,
) -> Element<'a, Message> {
    let p = s.palette;
    let count = report.map_or(0, |r| r.agents.len());
    let worst = report.and_then(Report::worst);

    let controls = row![
        refresh_button(sweeping, s),
        chrome_button(
            crate::glyph::Icon::Reset,
            "Reset",
            "Reset panel sizes",
            Message::ResetSplit,
            s,
        ),
        chrome_button(
            crate::glyph::Icon::Compact,
            "Compact",
            "Shrink to a small always-on-top window",
            Message::ToggleCompact,
            s,
        ),
        settings_button(s),
    ]
    .spacing(s.pad(space::TIGHT))
    .align_y(iced::Alignment::Center);

    let telemetry = row![
        fact("Agents", count.to_string(), p.text, s),
        fact(
            "Last scan",
            swept_at.map_or_else(|| "never".to_owned(), crate::clock::stamp),
            p.muted,
            s,
        ),
        fact(
            "External connections",
            report.map_or_else(|| "-".to_owned(), |r| external_endpoints(r).to_string()),
            if report.is_some_and(|r| external_endpoints(r) > 0) {
                p.high
            } else {
                p.muted
            },
            s,
        ),
        fact(
            "Sensitive files hit",
            report.map_or_else(|| "-".to_owned(), |r| watched_reached(r).to_string()),
            report.map_or(p.muted, |r| {
                if watched_reached(r) > 0 {
                    p.critical
                } else {
                    p.muted
                }
            }),
            s,
        ),
    ]
    .spacing(s.pad(space::LOOSE))
    .align_y(iced::Alignment::Center);

    column![
        row![
            brand(s),
            live_status(sweeping, s),
            posture(worst, s),
            iced::widget::space().width(Length::Fill),
            controls,
        ]
        .spacing(s.pad(space::BASE))
        .align_y(iced::Alignment::Center),
        container(telemetry)
            .style(move |_| iced::widget::container::Style {
                background: Some(p.background.into()),
                border: iced::Border {
                    color: p.border,
                    width: 1.0,
                    radius: theme::radius::CONTROL.into(),
                },
                ..iced::widget::container::Style::default()
            })
            .padding([s.pad(space::TIGHT), s.pad(space::BASE)])
            .width(Length::Fill),
    ]
    .spacing(s.pad(space::TIGHT))
    .into()
}

/// Product mark and wordmark. The mark is the same process-list symbol used
/// in the README and application icon, so the desktop chrome and repository
/// identify themselves as the same product.
fn brand<'a>(s: Style) -> Element<'a, Message> {
    let p = s.palette;
    let logo = svg(svg::Handle::from_memory(
        include_bytes!("../../../assets/icon.svg").as_slice(),
    ))
    .width(Length::Fixed(44.0))
    .height(Length::Fixed(44.0));

    row![
        logo,
        column![
            row![
                text("TOP")
                    .font(theme::STRONG)
                    .size(s.type_size(size::BRAND))
                    .color(p.text),
                text("GENT")
                    .font(theme::STRONG)
                    .size(s.type_size(size::BRAND))
                    .color(p.accent),
            ]
            .spacing(0),
            text("AGENT BEHAVIOUR SECURITY")
                .font(theme::STRONG)
                .size(s.type_size(size::MICRO))
                .color(p.faint),
        ]
        .spacing(s.pad(space::HAIR)),
    ]
    .spacing(s.pad(space::SNUG))
    .align_y(iced::Alignment::Center)
    .width(Length::Fixed(208.0))
    .into()
}

/// The state of collection, kept separate from posture. A healthy scanner can
/// be looking at a critical host; combining those two answers into one dot is
/// how a reassuring green light hides a dangerous result.
fn live_status<'a>(sweeping: bool, s: Style) -> Element<'a, Message> {
    let p = s.palette;
    let tint = if sweeping { p.medium } else { p.low };
    row![
        text("\u{25cf}").size(s.type_size(size::BODY)).color(tint),
        text(if sweeping { "SCANNING" } else { "LIVE" })
            .font(theme::STRONG)
            .size(s.type_size(size::LABEL))
            .color(tint),
    ]
    .spacing(s.pad(space::TIGHT))
    .align_y(iced::Alignment::Center)
    .width(Length::Fixed(84.0))
    .into()
}

/// The answer the operator came for, given enough visual weight to remain
/// visible while the rest of the header is scanned.
fn posture<'a>(worst: Option<&Agent>, s: Style) -> Element<'a, Message> {
    let p = s.palette;
    let (grade, score, tint) = worst.map_or_else(
        || ("CLEAR".to_owned(), "—".to_owned(), p.inert),
        |agent| {
            (
                agent.grade.to_ascii_uppercase(),
                agent.score.to_string(),
                p.grade(&agent.grade),
            )
        },
    );
    row![
        container(iced::widget::space())
            .width(Length::Fixed(3.0))
            .height(Length::Fixed(
                s.type_size(size::DISPLAY) + s.pad(space::SNUG)
            ))
            .style(move |_| iced::widget::container::Style {
                background: Some(tint.into()),
                ..iced::widget::container::Style::default()
            }),
        column![
            text("Host posture")
                .font(theme::STRONG)
                .size(s.type_size(size::BODY))
                .color(p.faint),
            row![
                text(grade)
                    .font(theme::STRONG)
                    .size(s.type_size(size::HEADING))
                    .color(tint),
                text(score)
                    .font(theme::MONO)
                    .size(s.type_size(size::DISPLAY))
                    .color(tint),
            ]
            .spacing(s.pad(space::SNUG))
            .align_y(iced::Alignment::Center),
        ]
        .spacing(s.pad(space::HAIR)),
    ]
    .spacing(s.pad(space::SNUG))
    .align_y(iced::Alignment::Center)
    .width(Length::Fixed(144.0))
    .into()
}

/// One labelled value in the header. The label is always drawn, because a
/// number with no name is a number nobody can act on.
fn fact(
    label: &str,
    value: impl Into<String>,
    colour: iced::Color,
    s: Style,
) -> Element<'_, Message> {
    column![
        text(label.to_ascii_uppercase())
            .font(theme::STRONG)
            .size(s.type_size(size::BODY))
            .color(s.palette.faint),
        text(value.into())
            .font(theme::STRONG)
            .size(s.type_size(size::HEADING))
            .color(colour),
    ]
    .spacing(s.pad(space::HAIR))
    .into()
}

fn settings_button<'a>(s: Style) -> Element<'a, Message> {
    chrome_button(
        crate::glyph::Icon::Settings,
        "Settings",
        "Preferences",
        Message::ToggleSettings,
        s,
    )
}

/// One control in the window's own chrome, with the sentence that says what it
/// does. A glyph with no word beside it is a puzzle.
fn chrome_button<'a>(
    icon: crate::glyph::Icon,
    label: &'a str,
    _detail: &'a str,
    message: Message,
    s: Style,
) -> Element<'a, Message> {
    let p = s.palette;
    button(
        row![
            crate::glyph::view(icon, s.type_size(size::DISPLAY), p.muted),
            text(label)
                .font(theme::STRONG)
                .size(s.type_size(size::LABEL))
                .color(p.muted),
        ]
        .spacing(s.pad(space::HAIR))
        .align_y(iced::Alignment::Center),
    )
    .on_press(message)
    .style(move |_, status| utility_style(status, p))
    .padding([s.pad(space::SNUG), s.pad(space::BASE)])
    .into()
}

fn utility_style(status: button::Status, p: theme::Palette) -> button::Style {
    button::Style {
        background: Some(
            if matches!(status, button::Status::Hovered | button::Status::Pressed) {
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
        ..button::Style::default()
    }
}

/// The agent table, worst first.
pub fn table<'a>(
    report: &'a Report,
    selected: Option<u32>,
    tables: &'a Tables,
    s: Style,
) -> Element<'a, Message> {
    let p = s.palette;
    let mut ordered: Vec<&Agent> = report.agents.iter().collect();
    ordered.sort_by_key(|a| (std::cmp::Reverse(a.score), a.pid));

    let rows = ordered
        .into_iter()
        .map(|a| {
            let top = a
                .factors
                .iter()
                .max_by_key(|f| f.points)
                .map_or("-", |f| f.title.as_str());
            table::Row::new(vec![
                table::Cell::tinted(a.label(), p.grade(&a.grade)),
                // The grade prints its own name, so colour is never the only
                // signal that a row is the worst one on the host. Grade and
                // score are two columns because one column wide enough for
                // "CRITICAL 100" leaves nothing for the path.
                table::Cell::tinted(a.grade.clone(), p.grade(&a.grade)),
                table::Cell::tinted(a.score.to_string(), p.grade(&a.grade)),
                table::Cell::new(a.recognition()),
                table::Cell::new(a.user.clone().unwrap_or_else(|| "unknown".into())),
                table::Cell::new(a.pid.to_string()),
                table::Cell::new(crate::clock::stamp(a.started_at)),
                table::Cell::path(a.exe.clone().unwrap_or_else(|| "not readable".into())),
                table::Cell::new(top),
            ])
            .selectable(a.pid, selected == Some(a.pid))
            .marked(p.grade(&a.grade))
        })
        .collect();

    container(table::view(
        table::Id::Agents,
        &COLUMNS,
        rows,
        &table::state_of(tables, table::Id::Agents),
        "No AI agents are running on this machine.",
        s,
    ))
    .style(theme::region(Region::Panel, p))
    .padding(s.pad(space::SNUG))
    .width(Length::Fill)
    .height(Length::Shrink)
    .into()
}

/// The columns, and what each is for.
///
/// `RECOGNITION` exists because a process Topgent named, one it examined and
/// could not name, and one whose executable it could not read are three
/// different answers, and the table used to print the same words for the last
/// two.
/// The agent table's columns, for anything that needs to resize one.
#[must_use]
pub fn columns() -> &'static [table::Column2] {
    &COLUMNS
}

static COLUMNS: [table::Column2; 9] = [
    table::Column2::text("AGENT", 4),
    table::Column2::text("RISK", 3),
    table::Column2::text("SCORE", 2).number(),
    table::Column2::text("IDENTITY", 4),
    table::Column2::text("USER", 2),
    table::Column2::text("PID", 2).number().mono(),
    table::Column2::text("STARTED", 3).mono(),
    table::Column2::text("EXECUTABLE", 5).mono(),
    table::Column2::text("FINDING", 4),
];

/// The detail of one agent, under the table, and the footer.
///
/// The path is given a bounded share and the button a fixed one, so an
/// executable path long enough to fill the window cannot push the control off
/// the edge. That happened, and a Stop button that cannot be reached is worse
/// than no Stop button, because the interface still claims to offer it.
pub fn detail(agent: &Agent, s: Style) -> Element<'_, Message> {
    let p = s.palette;
    let grade_tint = p.grade(&agent.grade);
    let grade = format!("{} {}", agent.grade.to_ascii_uppercase(), agent.score);

    let user = agent.user.clone().unwrap_or_else(|| "unknown".into());
    let executable = agent
        .exe
        .clone()
        .unwrap_or_else(|| "executable not readable".into());

    let body = row![
        container(iced::widget::space())
            .width(Length::Fixed(4.0))
            .height(Length::Fixed(48.0))
            .style(move |_| iced::widget::container::Style {
                background: Some(grade_tint.into()),
                ..iced::widget::container::Style::default()
            }),
        container(
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
                            .color(grade_tint)
                    )
                    .style(move |_| iced::widget::container::Style {
                        background: Some(p.raised.into()),
                        border: iced::Border {
                            color: grade_tint,
                            width: 1.0,
                            radius: theme::radius::CONTROL.into(),
                        },
                        ..iced::widget::container::Style::default()
                    })
                    .padding([s.pad(space::HAIR), s.pad(space::SNUG)]),
                ]
                .spacing(s.pad(space::SNUG))
                .align_y(iced::Alignment::Center),
            ]
            .spacing(s.pad(space::HAIR)),
        )
        .width(Length::Fixed(224.0))
        .clip(true),
        container(
            column![
                text("PROCESS")
                    .font(theme::STRONG)
                    .size(s.type_size(size::BODY))
                    .color(p.faint),
                text(format!(
                    "PID {} · {} · {}",
                    agent.pid,
                    user,
                    crate::clock::stamp(agent.started_at)
                ))
                .wrapping(iced::widget::text::Wrapping::None)
                .font(theme::MONO)
                .size(s.type_size(size::BODY))
                .color(p.text),
            ]
            .spacing(s.pad(space::TIGHT)),
        )
        .width(Length::Fixed(240.0))
        .clip(true),
        container(
            column![
                text("EXECUTABLE")
                    .font(theme::STRONG)
                    .size(s.type_size(size::BODY))
                    .color(p.faint),
                text(executable)
                    .wrapping(iced::widget::text::Wrapping::None)
                    .font(theme::MONO)
                    .size(s.type_size(size::BODY))
                    .color(p.muted),
            ]
            .spacing(s.pad(space::TIGHT)),
        )
        .width(Length::Fill)
        .clip(true),
        container(stop_button(agent.pid, s)).width(Length::Shrink),
    ]
    .align_y(iced::Alignment::Center)
    .spacing(s.pad(space::BASE));

    container(body)
        .style(theme::region(Region::Chrome, p))
        .padding([s.pad(space::TIGHT), s.pad(space::BASE)])
        .width(Length::Fill)
        .into()
}

fn stop_button<'a>(pid: u32, s: Style) -> Element<'a, Message> {
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

/// Where this came from and who wrote it.
///
/// Both links open in the reader's own browser. Nothing in this window fetches
/// anything: a monitor that reaches the network to draw its own footer has a
/// reason to be talking to a server, and it should not have one.
pub fn footer<'a>(version: &str, status: Option<&'a str>, s: Style) -> Element<'a, Message> {
    let p = s.palette;
    let version = version.to_owned();
    let provenance = row![
        link(crate::glyph::Icon::Repository, "source", REPOSITORY, s),
        text("·").size(s.type_size(size::MICRO)).color(p.border),
        link(crate::glyph::Icon::Author, "made by farikonsec", AUTHOR, s),
    ]
    .spacing(s.pad(space::BASE))
    .align_y(iced::Alignment::Center);

    container(
        row![
            container(provenance).width(Length::FillPortion(2)),
            container(footer_status(status, s))
                .clip(true)
                .width(Length::FillPortion(5)),
            container(
                text(format!("TOPGENT {version}"))
                    .font(theme::STRONG)
                    .size(s.type_size(size::BODY))
                    .color(p.faint),
            )
            .align_right(Length::Fill)
            .width(Length::FillPortion(2)),
        ]
        .spacing(s.pad(space::BASE))
        .align_y(iced::Alignment::Center),
    )
    .style(theme::region(Region::Chrome, p))
    .padding([s.pad(space::TIGHT), s.pad(space::BASE)])
    .width(Length::Fill)
    .into()
}

fn footer_status<'a>(status: Option<&'a str>, s: Style) -> Element<'a, Message> {
    let p = s.palette;
    let export = status.and_then(|value| value.strip_prefix("session written to "));
    let view: Element<'a, Message> = if let Some(path) = export {
        let path_owned = path.to_owned();
        row![
            text("EXPORT READY")
                .font(theme::STRONG)
                .size(s.type_size(size::BODY))
                .color(p.accent),
            text(table::shorten(path, 72, true))
                .font(theme::MONO)
                .size(s.type_size(size::BODY))
                .color(p.text)
                .wrapping(iced::widget::text::Wrapping::None)
                .width(Length::Fill),
            button(
                text("Show file")
                    .font(theme::STRONG)
                    .size(s.type_size(size::BODY))
                    .color(p.background),
            )
            .on_press(Message::Reveal(path_owned))
            .padding([s.pad(space::TIGHT), s.pad(space::BASE)])
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
        text(status.unwrap_or("Monitoring locally · data stays on this host"))
            .font(if status.is_some() {
                theme::STRONG
            } else {
                theme::MONO
            })
            .size(s.type_size(size::BODY))
            .color(if status.is_some() { p.accent } else { p.faint })
            .wrapping(iced::widget::text::Wrapping::None)
            .into()
    };

    container(view)
        .style(move |_| iced::widget::container::Style {
            background: Some(
                if status.is_some() {
                    p.selection()
                } else {
                    p.background
                }
                .into(),
            ),
            border: iced::Border {
                color: if status.is_some() { p.accent } else { p.border },
                width: 1.0,
                radius: theme::radius::CONTROL.into(),
            },
            ..iced::widget::container::Style::default()
        })
        .padding([s.pad(space::TIGHT), s.pad(space::BASE)])
        .width(Length::Fill)
        .into()
}

/// Where the source lives.
pub const REPOSITORY: &str = "https://github.com/farikonsec/topgent";
/// Who wrote it.
pub const AUTHOR: &str = "https://github.com/farikonsec";

fn link<'a>(
    icon: crate::glyph::Icon,
    label: &'a str,
    url: &'a str,
    s: Style,
) -> Element<'a, Message> {
    let p = s.palette;
    button(
        row![
            crate::glyph::view(icon, s.type_size(size::BODY), p.faint),
            text(label).size(s.type_size(size::BODY)).color(p.muted),
        ]
        .spacing(s.pad(space::TIGHT))
        .align_y(iced::Alignment::Center),
    )
    .on_press(Message::Open(url.to_owned()))
    .padding([s.pad(space::HAIR), s.pad(space::TIGHT)])
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

/// What the last stop attempt said, above the interface until the next sweep.
///
/// The core's own sentence, not a rewritten one. A stop that was refused says
/// why it was refused, and paraphrasing that in the interface is how a refusal
/// starts reading like a success.
pub fn footnote<'a>(outcome: &str, s: Style) -> Element<'a, Message> {
    container(
        text(outcome.to_owned())
            .size(s.type_size(size::BODY))
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
    let body = column![
        text("Stop this agent?")
            .size(s.type_size(size::HEADING))
            .color(p.text),
        text(named).size(s.type_size(size::BODY)).color(p.muted),
        text(
            "The process and everything it started are signalled, deepest first. \
             The exact identity is rechecked at the moment of the signal, so a pid \
             reused since this dialog opened is refused rather than stopped."
        )
        .size(s.type_size(size::MICRO))
        .color(p.faint),
        row![
            button(text("Cancel").size(s.type_size(size::BODY)).color(p.text))
                .on_press(Message::CancelStop)
                .padding([s.pad(space::TIGHT), s.pad(space::BASE)])
                .style(button::text),
            button(
                text("Stop")
                    .size(s.type_size(size::BODY))
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
            .width(Length::Fixed(420.0)),
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

    /// A heading that does not fit its own column is clipped, and a clipped
    /// right-aligned heading loses its first letters: `SCORE` printed as
    /// `CORE`. Every heading must fit the share its column is given.
    #[test]
    fn every_heading_fits_the_column_it_labels() {
        let total: f32 = f32::from(COLUMNS.iter().map(|c| c.portion).sum::<u16>());
        // The narrowest window this is laid out for, less the gaps and padding
        // the table takes out before sharing the width.
        let usable = 1320.0 - 190.0 - 130.0 - 12.0 * 7.0 - 24.0;
        for column in &COLUMNS {
            let share = usable * f32::from(column.portion) / total;
            let letters = u16::try_from(column.label.chars().count()).unwrap_or(u16::MAX);
            let needed = f32::from(letters) * theme::size::MICRO * 0.66;
            assert!(
                share >= needed,
                "{} needs {needed:.0}px and its column gives {share:.0}px",
                column.label
            );
        }
    }

    #[test]
    fn the_column_portions_add_up_to_the_width_they_claim() {
        let total: u16 = COLUMNS.iter().map(|c| c.portion).sum();
        assert_eq!(total, 29, "a changed portion must be deliberate");
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
    fn a_process_whose_executable_cannot_be_read_says_so_rather_than_guessing() {
        let mut a = agent(4242, "LOW", 0);
        a.family = None;
        a.exe = None;
        assert_eq!(a.label(), "pid 4242");
        assert_eq!(a.recognition(), "unreadable");
    }
}
