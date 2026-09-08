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
    // The title says what the control will do next, not what the feature is
    // called. A dialog headed "Enable packet capture?" over a capture that is
    // already running is a dialog nobody can act on.
    let running = topgent_collect::capture::live::running();
    let switched_off = topgent_collect::capture::live::stopped_by_operator();
    let heading = if running {
        "Packet capture is on"
    } else if switched_off {
        "Packet capture is off"
    } else {
        "Enable packet capture?"
    };
    let mut body = column![
        text(heading).size(s.type_size(size::HEADING)).color(p.text),
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

    // "Close" rather than "Not now". Nothing is being offered when capture is
    // already running, and a button that declines an offer nobody made reads
    // as though it does something.
    let mut actions = row![
        button(text("Close").size(s.type_size(size::BODY)).color(p.text))
            .on_press(Message::CancelCapture)
            .padding([s.pad(space::TIGHT), s.pad(space::BASE)])
            .style(button::text),
    ]
    .spacing(s.pad(space::SNUG));

    // The off switch, and it is deliberately the plain one. Stopping needs no
    // password and takes effect at once; it is not a privileged act and should
    // not be dressed as one. A capability that is easier to switch on than off
    // is a bad bargain, and this one was exactly that until now.
    if running {
        actions = actions.push(strong_button("Turn off", Message::StopCapture, p, s));
    } else if switched_off && matches!(offer.state, State::Available) {
        actions = actions.push(strong_button("Turn on", Message::StartCapture, p, s));
    }

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
            body = body.push(
                text(if running {
                    "Reading packet headers now. Turning it off stops that at once and \
                     needs no password."
                } else if switched_off {
                    "Permitted on this machine and switched off. Nothing is being read."
                } else {
                    "Permitted on this machine. Capture starts at the next sweep."
                })
                .size(s.type_size(size::BODY))
                .color(p.muted),
            );
            // The stronger step, offered but never mixed up with the switch.
            // Turning capture off stops it; this hands the permission back, so
            // nothing can start it again without asking for it afresh.
            if let Some(undo) = topgent_collect::capture::revoke_step() {
                body = body.push(
                    text(format!("To remove the permission entirely: {undo}"))
                        .size(s.type_size(size::MICRO))
                        .color(p.faint),
                );
                actions = actions.push(
                    button(
                        text("Remove permission")
                            .size(s.type_size(size::BODY))
                            .color(p.muted),
                    )
                    .on_press(Message::RevokeCapture)
                    .padding([s.pad(space::TIGHT), s.pad(space::BASE)])
                    .style(button::text),
                );
            }
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

/// The dialog's one prominent action, whatever it happens to be.
///
/// Shared so that turning capture on and turning it off look equally like a
/// button. The one that switches a capability off should never be the quieter
/// of the two.
fn strong_button(
    label: &str,
    message: Message,
    p: theme::Palette,
    s: Style,
) -> Element<'_, Message> {
    button(
        text(label)
            .size(s.type_size(size::BODY))
            .color(p.background),
    )
    .on_press(message)
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
    })
    .into()
}
