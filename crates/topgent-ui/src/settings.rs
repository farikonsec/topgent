//! What the reader chose about how this looks, and where it is kept.
//!
//! Scale exists because this is a monitoring tool people leave open on a second
//! display at an unhelpful resolution. Refresh interval exists because a sweep
//! costs seconds on some hosts, and someone watching one agent does not need
//! another one every 1.5 seconds.
//!
//! Nothing here can fail loudly. A settings file that cannot be read or written
//! gives the defaults back; an interface that refuses to draw because it could
//! not save a colour preference would be worse than one that forgets it.

use crate::Message;
use crate::theme::{Appearance, Density, Style};

use iced::widget::{Column, button, column, container, row, slider, text};
use iced::{Element, Length};
use serde::{Deserialize, Serialize};

/// The choices, as they are written to disk.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Which theme.
    pub appearance: Appearance,
    /// How much air.
    pub density: Density,
    /// Whole-interface multiplier.
    pub scale: f32,
    /// Milliseconds between sweeps.
    pub refresh_ms: u64,
    /// Whether a finding raises a notification.
    ///
    /// On by default. The response ladder has always been able to decide
    /// `Alert`; until now nothing delivered it, and a monitor that decides to
    /// tell you and then does not is worse than one that never offered.
    pub notify: bool,
    /// Whether a notification also makes a sound.
    pub sound: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            appearance: Appearance::Dark,
            density: Density::Normal,
            scale: 1.0,
            refresh_ms: 5_000,
            notify: true,
            sound: false,
        }
    }
}

/// The scale range offered. Below 0.8 the type stops being readable and above
/// 1.5 the table stops fitting, so neither end is offered.
pub const SCALE: (f32, f32) = (0.8, 1.5);

/// The refresh intervals offered, in milliseconds. The last is a pause.
pub const REFRESH: [(u64, &str); 5] = [
    (1_500, "1.5s"),
    (5_000, "5s"),
    (15_000, "15s"),
    (30_000, "30s"),
    (0, "paused"),
];

impl Settings {
    /// Fold these choices into the style every drawing function reads.
    #[must_use]
    pub fn style(self) -> Style {
        Style {
            palette: self.appearance.palette(),
            density: self.density,
            scale: self.scale.clamp(SCALE.0, SCALE.1),
        }
    }

    /// Read the saved choices, or the defaults.
    #[must_use]
    pub fn load() -> Self {
        std::fs::read_to_string(path())
            .ok()
            .and_then(|raw| serde_json::from_str::<Self>(&raw).ok())
            .map_or_else(Self::default, Self::sane)
    }

    /// Write the choices. A failure is silent by design: see the module note.
    pub fn save(self) {
        let file = path();
        if let Some(dir) = file.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Ok(raw) = serde_json::to_string_pretty(&self) {
            let _ = std::fs::write(file, raw);
        }
    }

    /// Clamp anything a hand-edited file could put out of range. A scale of
    /// 40 read from disk would draw one letter across the whole window and
    /// leave no control large enough to change it back.
    #[must_use]
    fn sane(mut self) -> Self {
        self.scale = if self.scale.is_finite() {
            self.scale.clamp(SCALE.0, SCALE.1)
        } else {
            1.0
        };
        if self.refresh_ms != 0 && !(500..=600_000).contains(&self.refresh_ms) {
            self.refresh_ms = Self::default().refresh_ms;
        }
        self
    }
}

/// Alongside the journal, so everything Topgent keeps is in one directory.
fn path() -> std::path::PathBuf {
    topgent_report::state_dir().join("interface.json")
}

/// The settings panel, drawn over the interface.
pub fn panel<'a>(current: Settings, s: Style) -> Element<'a, Message> {
    let p = s.palette;
    let heading = |label: &'a str| {
        text(label)
            .size(s.type_size(crate::theme::size::MICRO))
            .color(p.faint)
    };

    let mut themes = row![].spacing(s.pad(crate::theme::space::TIGHT));
    for appearance in Appearance::ALL {
        themes = themes.push(choice(
            appearance.label(),
            appearance == current.appearance,
            Message::SetAppearance(appearance),
            s,
        ));
    }

    let mut densities = row![].spacing(s.pad(crate::theme::space::TIGHT));
    for density in Density::ALL {
        densities = densities.push(choice(
            density.label(),
            density == current.density,
            Message::SetDensity(density),
            s,
        ));
    }

    let mut refreshes = row![].spacing(s.pad(crate::theme::space::TIGHT));
    for (ms, label) in REFRESH {
        refreshes = refreshes.push(choice(
            label,
            ms == current.refresh_ms,
            Message::SetRefresh(ms),
            s,
        ));
    }

    let body = column![
        row![
            text("Settings")
                .size(s.type_size(crate::theme::size::HEADING))
                .color(p.text),
            iced::widget::space().width(Length::Fill),
            button(
                text("close")
                    .size(s.type_size(crate::theme::size::BODY))
                    .color(p.muted)
            )
            .on_press(Message::ToggleSettings)
            .style(button::text)
            .padding(0),
        ]
        .align_y(iced::Alignment::Center),
        heading("THEME"),
        themes,
        heading("DENSITY"),
        densities,
        heading("SCALE"),
        scale_control(current.scale, s),
        heading("WHEN SOMETHING GETS WORSE"),
        toggle(
            crate::glyph::Icon::Bell,
            "notify",
            "Notify on medium and above",
            current.notify,
            Message::SetNotify(!current.notify),
            s,
        ),
        toggle(
            crate::glyph::Icon::Sound,
            "sound",
            "Play the system alert sound",
            current.sound,
            Message::SetSound(!current.sound),
            s,
        ),
        heading("THIS SESSION"),
        session_controls(s),
        heading("REFRESH"),
        refreshes,
        text("Paused stops scanning until this window is reopened.")
            .size(s.type_size(crate::theme::size::MICRO))
            .color(p.faint),
    ]
    .spacing(s.pad(crate::theme::space::BASE));

    container(
        container(body)
            .style(crate::theme::region(crate::theme::Region::Panel, p))
            .padding(s.pad(crate::theme::space::LOOSE))
            .width(Length::Fixed(460.0)),
    )
    .style(crate::theme::region(crate::theme::Region::Scrim, p))
    .width(Length::Fill)
    .height(Length::Fill)
    .center_x(Length::Fill)
    .center_y(Length::Fill)
    .into()
}

/// The scale control.
///
/// Its own function because a group of controls that reads as one block in the
/// panel should read as one block in the source too.
fn scale_control<'a>(current: f32, s: Style) -> Element<'a, Message> {
    let p = s.palette;
    row![
        slider(SCALE.0..=SCALE.1, current, Message::SetScale)
            .step(0.05_f32)
            .width(200)
            // Styled from the palette rather than left to the toolkit, so the
            // one control a reader uses to fix legibility is not the one
            // control that ignores the legibility theme.
            .style(move |_, _| slider::Style {
                rail: slider::Rail {
                    backgrounds: (p.accent.into(), p.border.into()),
                    width: 4.0,
                    border: iced::Border {
                        color: iced::Color::TRANSPARENT,
                        width: 0.0,
                        radius: 2.0.into(),
                    },
                },
                handle: slider::Handle {
                    shape: slider::HandleShape::Circle { radius: 7.0 },
                    background: p.accent.into(),
                    border_color: p.background,
                    border_width: 2.0,
                },
            }),
        text(format!("{:.0}%", current * 100.0))
            .size(s.type_size(crate::theme::size::BODY))
            .color(p.muted),
    ]
    .spacing(s.pad(crate::theme::space::BASE))
    .align_y(iced::Alignment::Center)
    .into()
}

/// One switch, with the sentence that says what it does.
///
/// The state is a word as well as a colour. A switch whose only difference is
/// a shade is a switch nobody can read in a screenshot.
fn toggle<'a>(
    icon: crate::glyph::Icon,
    label: &'a str,
    detail: &'a str,
    on: bool,
    message: Message,
    s: Style,
) -> Element<'a, Message> {
    let p = s.palette;
    let tint = if on { p.low } else { p.faint };
    button(
        row![
            crate::glyph::view(icon, s.type_size(crate::theme::size::HEADING), tint),
            column![
                row![
                    text(label)
                        .font(crate::theme::STRONG)
                        .size(s.type_size(crate::theme::size::BODY))
                        .color(p.text),
                    text(if on { "on" } else { "off" })
                        .size(s.type_size(crate::theme::size::MICRO))
                        .color(tint),
                ]
                .spacing(s.pad(crate::theme::space::SNUG)),
                text(detail)
                    .size(s.type_size(crate::theme::size::MICRO))
                    .color(p.faint),
            ]
            .spacing(s.pad(crate::theme::space::HAIR)),
        ]
        .spacing(s.pad(crate::theme::space::BASE))
        .align_y(iced::Alignment::Center),
    )
    .on_press(message)
    .width(Length::Fill)
    .padding(s.pad(crate::theme::space::SNUG))
    .style(move |_, status| button::Style {
        background: Some(
            if matches!(status, button::Status::Hovered) {
                p.raised
            } else {
                p.surface
            }
            .into(),
        ),
        text_color: p.text,
        border: iced::Border {
            color: p.border,
            width: 1.0,
            radius: crate::theme::radius::PANEL.into(),
        },
        ..button::Style::default()
    })
    .into()
}

/// Writing this session out.
fn session_controls<'a>(s: Style) -> Element<'a, Message> {
    let p = s.palette;
    Column::new()
        .spacing(s.pad(crate::theme::space::SNUG))
        .push(
            text(
                "Writes HTML and JSON to the state directory. Redacted omits home \
                 directories and peer addresses.",
            )
            .size(s.type_size(crate::theme::size::MICRO))
            .color(p.faint),
        )
        .push(
            row![
                action("Export", Message::Export(false), s),
                action("Export redacted", Message::Export(true), s),
            ]
            .spacing(s.pad(crate::theme::space::SNUG)),
        )
        .into()
}

/// A control that does something rather than choosing something.
fn action(label: &str, message: Message, s: Style) -> Element<'_, Message> {
    let p = s.palette;
    button(
        text(label)
            .font(crate::theme::STRONG)
            .size(s.type_size(crate::theme::size::BODY))
            .color(p.background),
    )
    .on_press(message)
    .padding([
        s.pad(crate::theme::space::TIGHT),
        s.pad(crate::theme::space::WIDE),
    ])
    .style(move |_, status| button::Style {
        background: Some(
            if matches!(status, button::Status::Hovered) {
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
            radius: crate::theme::radius::PANEL.into(),
        },
        ..button::Style::default()
    })
    .into()
}

/// One option in a group. The chosen one is filled, so the current state is
/// readable without hovering and without colour being the only difference.
fn choice(label: &str, chosen: bool, message: Message, s: Style) -> Element<'_, Message> {
    let p = s.palette;
    button(text(label).size(s.type_size(crate::theme::size::BODY)))
        .on_press(message)
        .padding([
            s.pad(crate::theme::space::TIGHT),
            s.pad(crate::theme::space::BASE),
        ])
        .style(move |_, status| {
            let hovered = matches!(status, button::Status::Hovered);
            button::Style {
                background: Some(
                    if chosen {
                        p.accent
                    } else if hovered {
                        p.raised
                    } else {
                        p.surface
                    }
                    .into(),
                ),
                text_color: if chosen { p.background } else { p.text },
                border: iced::Border {
                    color: p.border,
                    width: 1.0,
                    radius: crate::theme::radius::PANEL.into(),
                },
                ..button::Style::default()
            }
        })
        .into()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn a_hand_edited_file_cannot_make_the_interface_unusable() {
        let absurd = Settings {
            scale: 40.0,
            refresh_ms: 1,
            ..Settings::default()
        };
        let fixed = absurd.sane();
        assert!(
            (SCALE.0..=SCALE.1).contains(&fixed.scale),
            "scale {} escaped",
            fixed.scale
        );
        assert_eq!(fixed.refresh_ms, Settings::default().refresh_ms);
    }

    #[test]
    fn a_non_finite_scale_falls_back_rather_than_propagating() {
        let broken = Settings {
            scale: f32::NAN,
            ..Settings::default()
        };
        assert!((broken.sane().scale - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn pausing_survives_the_sanity_pass() {
        let paused = Settings {
            refresh_ms: 0,
            ..Settings::default()
        };
        assert_eq!(
            paused.sane().refresh_ms,
            0,
            "paused is a choice, not an out-of-range value"
        );
    }

    #[test]
    fn the_settings_round_trip_through_the_form_they_are_stored_in() {
        let chosen = Settings {
            appearance: Appearance::HighContrast,
            density: Density::Compact,
            scale: 1.25,
            refresh_ms: 15_000,
            notify: false,
            sound: true,
        };
        let raw = serde_json::to_string(&chosen).expect("settings serialise");
        let back: Settings = serde_json::from_str(&raw).expect("settings deserialise");
        assert_eq!(chosen, back);
    }

    #[test]
    fn notifications_are_on_by_default_and_sound_is_not() {
        // The alert rung decides regardless. Delivering it is the default
        // because a monitor nobody hears is a monitor nobody has. Sound is
        // not, because a sound every few seconds is how notifications get
        // switched off entirely.
        let d = Settings::default();
        assert!(d.notify);
        assert!(!d.sound);
    }

    #[test]
    fn an_empty_file_gives_the_defaults_rather_than_failing() {
        let back: Settings = serde_json::from_str("{}").expect("an empty object is every default");
        assert_eq!(back, Settings::default());
    }
}
