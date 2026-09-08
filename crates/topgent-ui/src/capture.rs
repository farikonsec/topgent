//! The one place Topgent asks for more privilege than it started with.
//!
//! Everything the dialog says comes from `topgent_collect::capture`, so this
//! window and `topgent capture status` cannot describe the capability
//! differently. What is written here is the layout, not the argument.
//!
//! The limits are shown above the gains, which is the wrong way round for
//! selling something and the right way round for consent.

use iced::widget::{button, column, container, row, text};
use iced::{Element, Length};

use crate::Message;
use crate::theme::{self, Region, Style, size, space};

/// The dialog, which explains before it offers.
// One dialog, built top to bottom. Splitting it would put the order of a
// consent screen in two places, and the order is the argument.
#[allow(clippy::too_many_lines)]
pub fn dialog<'a>(
    offer: &topgent_collect::capture::Offer,
    outcome: Option<&str>,
    s: Style,
) -> Element<'a, Message> {
    use topgent_collect::capture::{Remedy, State};
    let p = s.palette;

    // One sentence, then a few bullets. A dialog nobody reads to the end is a
    // dialog that gets clicked through, and a long explanation of a privileged
    // action is worse than a short one.
    // One sentence, then two facts. A long explanation of a privileged action
    // gets clicked through, which is worse than a short one.
    let mut body = column![
        text("Enable packet capture?")
            .size(s.type_size(size::HEADING))
            .color(p.text),
        text("What is captured?")
            .size(s.type_size(size::BODY))
            .font(theme::STRONG)
            .color(p.faint),
    ]
    .spacing(s.pad(space::BASE));

    for line in [
        "TCP and UDP peers",
        "ICMP",
        "Short-lived connections",
        "Packet headers",
    ] {
        body = body.push(
            text(format!("\u{2022}  {line}"))
                .size(s.type_size(size::MICRO))
                .color(p.muted),
        );
    }

    let mut actions = row![
        button(text("Not now").size(s.type_size(size::BODY)).color(p.text))
            .on_press(Message::CancelCapture)
            .padding([s.pad(space::TIGHT), s.pad(space::BASE)])
            .style(button::text),
    ]
    .spacing(s.pad(space::SNUG));

    match &offer.state {
        State::NeedsGrant { remedy, .. } => match remedy {
            Remedy::Command { command, undo, .. } => {
                // The exact command, before it runs. Nobody should approve an
                // elevation they were not shown.
                body = body.push(
                    text(command.clone())
                        .font(theme::MONO)
                        .size(s.type_size(size::MICRO))
                        .color(p.text),
                );
                body = body.push(
                    text(format!("Undo: {undo}"))
                        .size(s.type_size(size::MICRO))
                        .color(p.faint),
                );
                actions = actions.push(
                    button(
                        text("Enable")
                            .size(s.type_size(size::BODY))
                            .color(p.background),
                    )
                    .on_press(Message::GrantCapture)
                    .padding([s.pad(space::TIGHT), s.pad(space::BASE)])
                    .style(move |_, status| button::Style {
                        background: Some(
                            if matches!(status, button::Status::Hovered) {
                                p.critical
                            } else {
                                p.high
                            }
                            .into(),
                        ),
                        text_color: p.background,
                        border: iced::Border {
                            color: iced::Color::TRANSPARENT,
                            width: 0.0,
                            radius: theme::radius::PANEL.into(),
                        },
                        ..button::Style::default()
                    }),
                );
            }
            Remedy::Install { what, source } => {
                // No button. Topgent will not put software on somebody's
                // machine, and a control that cannot act is worse than none.
                body = body.push(
                    text(format!("Needs {what}. {source}"))
                        .size(s.type_size(size::MICRO))
                        .color(p.muted),
                );
            }
        },
        State::NeedsRestart { detail } => {
            body = body.push(
                text(detail.clone())
                    .size(s.type_size(size::BODY))
                    .color(p.muted),
            );
        }
        State::Available => {
            // The honest sentence. The permission is present and no code in
            // this build reads packets yet, and saying "enabled" would claim a
            // feature that does not exist.
            body = body.push(
                text("Permitted on this machine. No capture is running yet.")
                    .size(s.type_size(size::BODY))
                    .color(p.muted),
            );
        }
        State::Unsupported { reason } | State::Unknown { detail: reason } => {
            body = body.push(
                text(reason.clone())
                    .size(s.type_size(size::MICRO))
                    .color(p.faint),
            );
        }
    }

    if let Some(outcome) = outcome {
        body = body.push(
            text(outcome.to_owned())
                .size(s.type_size(size::BODY))
                .color(p.text),
        );
    }

    body = body.push(actions);

    container(
        container(body)
            .style(theme::region(Region::Panel, p))
            .padding(s.pad(space::LOOSE))
            .width(Length::Fixed(480.0)),
    )
    .style(theme::region(Region::Scrim, p))
    .width(Length::Fill)
    .height(Length::Fill)
    .center_x(Length::Fill)
    .center_y(Length::Fill)
    .into()
}
