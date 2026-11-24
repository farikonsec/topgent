//! The small window.
//!
//! Nobody watches a dashboard. A corner of the screen that changes colour when
//! something happens is what actually gets used, so this is the shape the
//! product is most likely to be left running in: a strip that says how bad it
//! is here, how many agents are running, and what changed last.
//!
//! Deliberately not a summary of everything. It carries the three facts a
//! reader can act on from across the room, and one control to go back. A small
//! window that tries to be the large one is a large one that nobody can read.

use crate::Message;
use crate::report::{Agent, Report};
use crate::theme::{self, Region, Style, size, space};

use iced::widget::{Column, button, container, row, text};
use iced::{Element, Length};

/// The largest regular compact window. Fewer rows use less height.
pub const SIZE: iced::Size = iced::Size {
    width: 460.0,
    height: 280.0,
};

/// The confirmation needs room for the process identity and the guarded
/// action. It is temporary; leaving the dialog returns to the compact size.
pub const CONFIRM_SIZE: iced::Size = iced::Size {
    width: 540.0,
    height: 410.0,
};

/// How many agents the strip lists.
///
/// Three, because a strip that scrolls is a strip nobody scrolls. The count on
/// the first line always states the whole number, so a reader can see there are
/// more than they are being shown rather than believing they have seen all.
const LISTED: usize = 3;

/// Leave room for the summary, last event, and every row that will be shown,
/// without reserving four empty row slots when only one agent is running.
pub fn size_for(count: usize, scale: f32) -> iced::Size {
    let rows = count.min(LISTED) + usize::from(count > LISTED);
    let rows = u16::try_from(rows).unwrap_or(u16::MAX);
    iced::Size {
        width: SIZE.width,
        height: (100.0 + f32::from(rows) * 25.0 * scale.clamp(0.8, 1.5)).clamp(170.0, SIZE.height),
    }
}

/// Draw the small window.
pub fn view<'a>(
    report: Option<&'a Report>,
    sweeping: bool,
    status: Option<&str>,
    s: Style,
) -> Element<'a, Message> {
    let p = s.palette;
    let worst = report.and_then(Report::worst);
    let count = report.map_or(0, |r| r.agents.len());

    // The colour of the whole strip follows the worst grade, so the window
    // says how bad it is before anybody reads a word of it. The words are
    // there too: colour is never the only carrier of a fact.
    let tint = worst.map_or(p.inert, |a| p.grade(&a.grade));

    let latest = report.and_then(|r| r.events.first()).map_or_else(
        || "no events yet".to_owned(),
        |e| format!("{} · {}", crate::clock::stamp(e.at), e.detail),
    );

    let mut ordered: Vec<&crate::report::Agent> = report
        .map(|r| r.agents.iter().collect())
        .unwrap_or_default();
    ordered.sort_by_key(|a| (std::cmp::Reverse(a.score), a.pid));

    let mut list = Column::new().spacing(s.pad(space::HAIR));
    for agent in ordered.iter().take(LISTED) {
        list = list.push(agent_row(agent, s));
    }
    if ordered.len() > LISTED {
        list = list.push(
            text(format!("and {} more", ordered.len() - LISTED))
                .size(s.type_size(size::MICRO))
                .color(p.faint),
        );
    }
    if ordered.is_empty() {
        list = list.push(
            text("no AI agents running")
                .size(s.type_size(size::BODY))
                .color(p.muted),
        );
    }

    let body = Column::new()
        .spacing(s.pad(space::SNUG))
        .push(
            row![
                text("\u{25cf}")
                    .size(s.type_size(size::MICRO))
                    .color(if sweeping { p.faint } else { p.low }),
                text(worst.map_or_else(
                    || "nothing scored".to_owned(),
                    |a| format!("{} {}", a.grade, a.score)
                ))
                .font(theme::STRONG)
                .size(s.type_size(size::DISPLAY))
                .color(tint),
                text(format!("{count} agents"))
                    .size(s.type_size(size::BODY))
                    .color(p.muted),
                iced::widget::space().width(Length::Fill),
                button(text("expand").size(s.type_size(size::MICRO)).color(p.muted))
                    .on_press(Message::ToggleCompact)
                    .style(button::text)
                    .padding(0),
            ]
            .spacing(s.pad(space::SNUG))
            .align_y(iced::Alignment::Center),
        )
        .push(list)
        .push(
            text(status.map_or(latest, str::to_owned))
                .wrapping(iced::widget::text::Wrapping::None)
                .size(s.type_size(size::MICRO))
                .color(p.faint),
        );

    container(container(body).clip(true))
        .style(theme::region(Region::Window, p))
        .padding(s.pad(space::BASE))
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

/// One compact agent stays identifiable while its action keeps its full hit
/// target. Only the name yields width when the window gets crowded.
fn agent_row(agent: &Agent, s: Style) -> Element<'_, Message> {
    let p = s.palette;
    let grade_width = (s.type_size(size::MICRO) * 6.0).max(64.0);
    row![
        text(agent.grade.clone())
            .font(theme::STRONG)
            .size(s.type_size(size::MICRO))
            .color(p.grade(&agent.grade))
            .width(Length::Fixed(grade_width)),
        text(agent.score.to_string())
            .size(s.type_size(size::MICRO))
            .color(p.muted)
            .align_x(iced::alignment::Horizontal::Right)
            .width(Length::Fixed(26.0)),
        container(
            text(agent.label())
                .wrapping(iced::widget::text::Wrapping::None)
                .size(s.type_size(size::BODY))
                .color(p.text),
        )
        .width(Length::Fill)
        .clip(true),
        text(agent.pid.to_string())
            .font(theme::MONO)
            .size(s.type_size(size::MICRO))
            .color(p.faint),
        button(
            text("Stop")
                .font(theme::STRONG)
                .size(s.type_size(size::MICRO))
                .color(p.critical),
        )
        .on_press(Message::AskStop(agent.pid))
        .padding([s.pad(space::HAIR), s.pad(space::TIGHT)])
        .style(move |_, status| button::Style {
            background: Some(
                if matches!(status, button::Status::Hovered) {
                    p.hover()
                } else {
                    p.surface
                }
                .into()
            ),
            text_color: p.critical,
            border: iced::Border {
                color: p.critical,
                width: 1.0,
                radius: theme::radius::CONTROL.into(),
            },
            ..button::Style::default()
        }),
    ]
    .spacing(s.pad(space::SNUG))
    .align_y(iced::Alignment::Center)
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The strip has to fit in a corner and hold everything it lists.
    ///
    /// Both are properties of the numbers, so both are checked here. The clip
    /// that stops a cut line from looking broken is also what would hide one,
    /// so a height that is one row short would go unnoticed by looking.
    #[test]
    fn the_strip_fits_a_corner_and_holds_what_it_lists() {
        let (width, height) = (SIZE.width, SIZE.height);
        // Wider or taller than this is not a corner, it is a second window.
        assert!(
            width <= 460.0 && height <= 280.0,
            "{width}x{height} is not a corner"
        );

        // The heading, the agent rows, the "and N more" line, and the last
        // event, plus the padding either side.
        #[allow(clippy::cast_precision_loss)]
        let rows = (LISTED + 1) as f32 * theme::size::BODY;
        let lines = theme::size::DISPLAY + rows + theme::size::MICRO;
        assert!(
            height >= lines + 40.0,
            "{height} cannot hold the {LISTED} agents it lists"
        );
        assert!(size_for(2, 1.0).height < size_for(5, 1.0).height);
        assert!(size_for(5, 1.5).height <= SIZE.height);
    }
}
