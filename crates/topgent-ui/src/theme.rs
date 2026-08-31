//! Tokens, palette, and the container roles everything else is built from.
//!
//! Every colour, size, space, and radius in the interface comes from here. A
//! literal typed at a call site is a value nobody can change consistently, and
//! the first draft of this interface had padding of 12 in some places and 4 in
//! others for no reason anyone could name.
//!
//! Two rules hold throughout.
//!
//! Colour is never the only carrier of a fact. A grade prints its name, a
//! credential prints the word, a sensor prints its state. The interface has to
//! survive a screenshot, a greyscale print, and a reader who does not separate
//! red from green.
//!
//! The interface is quiet unless something is wrong. It gets looked at while
//! something else is being done, so chrome and structure stay low contrast. If
//! everything is coloured, an amber row means nothing.

use iced::widget::container;
use iced::{Background, Border, Color, Element, Length, Theme};
use serde::{Deserialize, Serialize};

/// Spacing. Every gap and pad in the interface is one of these seven numbers.
pub mod space {
    /// Between a glyph and its label.
    pub const HAIR: f32 = 2.0;
    /// Inside a badge.
    pub const TIGHT: f32 = 4.0;
    /// Between rows.
    pub const SNUG: f32 = 8.0;
    /// Inside a row.
    pub const BASE: f32 = 12.0;
    /// Between a panel and its contents.
    pub const WIDE: f32 = 16.0;
    /// Between regions, and inside a dialog.
    pub const LOOSE: f32 = 24.0;
}

/// Five type sizes. Five, so that a size means something when it changes.
pub mod size {
    /// Column headings, provenance, the sentence under a finding.
    pub const MICRO: f32 = 11.0;
    /// Everything in a table.
    pub const BODY: f32 = 12.0;
    /// The thing a row is about.
    pub const EMPHASIS: f32 = 13.0;
    /// A panel heading.
    pub const HEADING: f32 = 15.0;
    /// The product name and a count worth reading across the room.
    pub const DISPLAY: f32 = 20.0;
}

/// Corner radius.
pub mod radius {
    /// Panels and surfaces.
    pub const PANEL: f32 = 6.0;
}

/// How much air the interface uses. Multiplies spacing only; type does not move,
/// because shrinking text to fit more rows is how a monitor becomes unreadable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Density {
    /// For a long list on a small display.
    Compact,
    /// The default.
    #[default]
    Normal,
    /// For a display being read from further away.
    Comfortable,
}

impl Density {
    /// Every density, in the order the settings panel lists them.
    pub const ALL: [Self; 3] = [Self::Compact, Self::Normal, Self::Comfortable];

    /// The multiplier applied to every space token.
    #[must_use]
    pub const fn factor(self) -> f32 {
        match self {
            Self::Compact => 0.7,
            Self::Normal => 1.0,
            Self::Comfortable => 1.35,
        }
    }

    /// Scale one space token.
    #[must_use]
    pub fn pad(self, token: f32) -> f32 {
        (token * self.factor()).round().max(1.0)
    }

    /// Row height at this density.
    #[must_use]
    pub const fn row_height(self) -> f32 {
        match self {
            Self::Compact => 26.0,
            Self::Normal => 32.0,
            Self::Comfortable => 40.0,
        }
    }

    /// Display label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Compact => "compact",
            Self::Normal => "normal",
            Self::Comfortable => "comfortable",
        }
    }
}

/// Named colour roles. Not colours chosen at a call site.
///
/// Serialisable so a palette can be loaded from the config directory: someone
/// who needs a particular contrast should not need a build to get it.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Palette {
    /// The window behind everything.
    #[serde(with = "hex")]
    pub background: Color,
    /// A panel sitting on the window.
    #[serde(with = "hex")]
    pub surface: Color,
    /// A selected row, a hovered control.
    #[serde(with = "hex")]
    pub raised: Color,
    /// The hairline between regions.
    #[serde(with = "hex")]
    pub border: Color,
    /// Primary text.
    #[serde(with = "hex")]
    pub text: Color,
    /// Secondary detail.
    #[serde(with = "hex")]
    pub muted: Color,
    /// Column headings and provenance.
    #[serde(with = "hex")]
    pub faint: Color,
    /// Selection and focus.
    #[serde(with = "hex")]
    pub accent: Color,
    /// The five grades, worst first.
    #[serde(with = "hex")]
    pub critical: Color,
    /// High.
    #[serde(with = "hex")]
    pub high: Color,
    /// Medium.
    #[serde(with = "hex")]
    pub medium: Color,
    /// Low.
    #[serde(with = "hex")]
    pub low: Color,
    /// Nothing scored.
    #[serde(with = "hex")]
    pub inert: Color,
}

/// Colours as `#rrggbb`, so a palette file is one a designer can read and edit.
///
/// An unreadable value is an error rather than a silent black: a palette that
/// half-loads gives an interface nobody can diagnose from looking at it.
mod hex {
    use iced::Color;
    use serde::{Deserialize, Deserializer, Serializer};

    #[allow(
        clippy::trivially_copy_pass_by_ref,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    pub fn serialize<S: Serializer>(colour: &Color, serializer: S) -> Result<S::Ok, S::Error> {
        let byte = |c: f32| (c.clamp(0.0, 1.0) * 255.0).round() as u8;
        serializer.serialize_str(&format!(
            "#{:02x}{:02x}{:02x}",
            byte(colour.r),
            byte(colour.g),
            byte(colour.b)
        ))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Color, D::Error> {
        let raw = String::deserialize(deserializer)?;
        let digits = raw.strip_prefix('#').unwrap_or(&raw);
        if digits.len() != 6 {
            return Err(serde::de::Error::custom(format!(
                "{raw} is not a colour: expected six hexadecimal digits, optionally prefixed with #"
            )));
        }
        let channel = |at: usize| {
            u8::from_str_radix(&digits[at..at + 2], 16)
                .map_err(|_| serde::de::Error::custom(format!("{raw} is not hexadecimal")))
        };
        Ok(super::rgb(channel(0)?, channel(2)?, channel(4)?))
    }
}

const fn rgb(r: u8, g: u8, b: u8) -> Color {
    Color {
        r: r as f32 / 255.0,
        g: g as f32 / 255.0,
        b: b as f32 / 255.0,
        a: 1.0,
    }
}

/// Which theme is in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Appearance {
    /// The default.
    #[default]
    Dark,
    /// For a bright room.
    Light,
    /// Maximum separation. Not decoration: this is what makes the interface
    /// usable on a projector and to a reader who needs it.
    HighContrast,
}

impl Appearance {
    /// Every appearance, in the order the settings panel lists them.
    pub const ALL: [Self; 3] = [Self::Dark, Self::Light, Self::HighContrast];

    /// Display label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Dark => "dark",
            Self::Light => "light",
            Self::HighContrast => "high contrast",
        }
    }

    /// The palette for this appearance.
    #[must_use]
    pub const fn palette(self) -> Palette {
        match self {
            Self::Dark => Palette {
                background: rgb(0x14, 0x16, 0x1a),
                surface: rgb(0x1a, 0x1d, 0x22),
                raised: rgb(0x24, 0x28, 0x2f),
                border: rgb(0x2b, 0x30, 0x38),
                text: rgb(0xe6, 0xe8, 0xeb),
                muted: rgb(0x9a, 0xa0, 0xa8),
                faint: rgb(0x6b, 0x72, 0x7b),
                accent: rgb(0x7c, 0x8c, 0xf0),
                critical: rgb(0xe2, 0x62, 0x5c),
                high: rgb(0xe0, 0x92, 0x40),
                medium: rgb(0xd6, 0xb8, 0x4a),
                low: rgb(0x6f, 0xa8, 0x6f),
                inert: rgb(0x7b, 0x82, 0x8a),
            },
            Self::Light => Palette {
                background: rgb(0xf7, 0xf7, 0xf5),
                surface: rgb(0xff, 0xff, 0xff),
                raised: rgb(0xec, 0xed, 0xf0),
                border: rgb(0xd8, 0xda, 0xde),
                text: rgb(0x1c, 0x1f, 0x24),
                muted: rgb(0x55, 0x5b, 0x63),
                faint: rgb(0x7d, 0x84, 0x8d),
                accent: rgb(0x3b, 0x4d, 0xd6),
                critical: rgb(0xb3, 0x2f, 0x2c),
                high: rgb(0xa5, 0x5c, 0x0c),
                medium: rgb(0x86, 0x6d, 0x0a),
                low: rgb(0x2f, 0x6b, 0x38),
                inert: rgb(0x6a, 0x70, 0x78),
            },
            Self::HighContrast => Palette {
                background: rgb(0x00, 0x00, 0x00),
                surface: rgb(0x0d, 0x0d, 0x0d),
                raised: rgb(0x2a, 0x2a, 0x2a),
                border: rgb(0x8a, 0x8a, 0x8a),
                text: rgb(0xff, 0xff, 0xff),
                muted: rgb(0xdd, 0xdd, 0xdd),
                faint: rgb(0xb0, 0xb0, 0xb0),
                accent: rgb(0x66, 0xd9, 0xff),
                critical: rgb(0xff, 0x6b, 0x6b),
                high: rgb(0xff, 0xb3, 0x4d),
                medium: rgb(0xff, 0xe0, 0x66),
                low: rgb(0x77, 0xdd, 0x88),
                inert: rgb(0xcc, 0xcc, 0xcc),
            },
        }
    }

    /// The toolkit theme, so built-in widgets match.
    #[must_use]
    pub fn toolkit(self) -> Theme {
        match self {
            Self::Light => Theme::Light,
            _ => Theme::Dark,
        }
    }
}

impl Palette {
    /// The colour for a grade, matched case-insensitively because the report
    /// has used both cases across versions.
    #[must_use]
    pub fn grade(&self, grade: &str) -> Color {
        match grade.to_ascii_uppercase().as_str() {
            "CRITICAL" => self.critical,
            "HIGH" => self.high,
            "MEDIUM" => self.medium,
            "LOW" => self.low,
            _ => self.inert,
        }
    }

    /// Every other row, lifted very slightly off the surface it sits on.
    ///
    /// Derived rather than named, so a palette loaded from a file gets one
    /// without having to know about it, and so the three built-in palettes
    /// cannot drift apart on the one value nobody would notice was wrong.
    #[must_use]
    pub fn stripe(&self) -> Color {
        let toward = if self.is_dark() { 1.0 } else { 0.0 };
        let mix = |c: f32| c + (toward - c) * 0.04;
        Color {
            r: mix(self.surface.r),
            g: mix(self.surface.g),
            b: mix(self.surface.b),
            a: 1.0,
        }
    }

    /// Whether this palette paints light on dark.
    #[must_use]
    pub fn is_dark(&self) -> bool {
        self.surface.r + self.surface.g + self.surface.b < self.text.r + self.text.g + self.text.b
    }

    /// The colour for a sensor state.
    #[must_use]
    pub fn sensor(&self, state: &str) -> Color {
        match state {
            "available" => self.low,
            "degraded" | "permission_required" => self.medium,
            "error" => self.critical,
            _ => self.inert,
        }
    }
}

/// What a region is, rather than how it should look.
///
/// Styling attaches to the role, so every panel separates the same way instead
/// of each call site deciding for itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Region {
    /// The window itself.
    Window,
    /// A panel sitting on the window, with a border.
    Panel,
    /// Hover text.
    Tooltip,
    /// The dimmed ground behind a dialog, so an overlay reads as one rather
    /// than as a panel that happens to be on top.
    Scrim,
}

/// Style a container by the part it plays.
pub fn region(role: Region, p: Palette) -> impl Fn(&Theme) -> container::Style {
    move |_| {
        let (bg, border) = match role {
            Region::Window => (p.background, Color::TRANSPARENT),
            Region::Scrim => (
                Color {
                    a: 0.72,
                    ..p.background
                },
                Color::TRANSPARENT,
            ),
            Region::Panel => (p.surface, p.border),
            // A badge and a tooltip are the same surface deliberately: both
            // are small things lifted off what is behind them, and giving them
            // separate treatments would be two things to keep in step for no
            // reader-visible gain. Radius is what tells them apart.
            Region::Tooltip => (p.raised, p.border),
        };
        let radius = radius::PANEL;
        container::Style {
            background: Some(Background::Color(bg)),
            border: Border {
                color: border,
                width: if border == Color::TRANSPARENT {
                    0.0
                } else {
                    1.0
                },
                radius: radius.into(),
            },
            text_color: Some(p.text),
            ..container::Style::default()
        }
    }
}

/// The faces, embedded rather than named.
///
/// A named font is whatever the machine happens to have. Two machines running
/// the same build then draw different interfaces, and one of them draws a
/// fallback nobody chose. Both faces are under the SIL Open Font Licence 1.1
/// and are recorded in `NOTICE`.
pub mod face {
    /// Everything proportional.
    pub const BODY: &[u8] = include_bytes!("../fonts/Inter-Regular.ttf");
    /// Headings and anything that has to separate from a row of values.
    pub const STRONG: &[u8] = include_bytes!("../fonts/Inter-SemiBold.ttf");
    /// Paths, addresses, and process ids. A column of paths that does not
    /// align is a column nobody can scan.
    pub const CODE: &[u8] = include_bytes!("../fonts/JetBrainsMono-Regular.ttf");
}

/// The proportional face.
pub const TEXT: iced::Font = iced::Font::with_name("Inter");

/// The proportional face, heavier. Column headings, panel titles, and the one
/// number in the header worth reading across the room.
pub const STRONG: iced::Font = iced::Font {
    weight: iced::font::Weight::Semibold,
    ..iced::Font::with_name("Inter")
};

/// The face for paths, addresses, and process ids.
pub const MONO: iced::Font = iced::Font::with_name("JetBrains Mono");

/// A centred sentence for an empty or failed state.
///
/// Always a sentence, never a spinner alone: a window that says nothing while
/// it waits cannot be told apart from one that has hung.
pub fn notice<'a, M: 'a>(message: impl Into<String>, p: Palette) -> Element<'a, M> {
    container(
        iced::widget::text(message.into())
            .size(size::EMPHASIS)
            .color(p.muted),
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .center_x(Length::Fill)
    .center_y(Length::Fill)
    .into()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    /// Contrast is what makes text readable, and a palette that fails it is a
    /// palette nobody can use. The ratio is the WCAG relative-luminance one.
    fn contrast(a: Color, b: Color) -> f32 {
        fn channel(c: f32) -> f32 {
            if c <= 0.039_28 {
                c / 12.92
            } else {
                ((c + 0.055) / 1.055).powf(2.4)
            }
        }
        fn luminance(c: Color) -> f32 {
            0.2126 * channel(c.r) + 0.7152 * channel(c.g) + 0.0722 * channel(c.b)
        }
        let (x, y) = (luminance(a), luminance(b));
        let (hi, lo) = if x > y { (x, y) } else { (y, x) };
        (hi + 0.05) / (lo + 0.05)
    }

    #[test]
    fn primary_text_is_readable_on_every_theme() {
        for appearance in Appearance::ALL {
            let p = appearance.palette();
            let ratio = contrast(p.text, p.background);
            assert!(
                ratio >= 7.0,
                "{} text on background is {ratio:.1}:1, below the 7:1 this aims at",
                appearance.label()
            );
        }
    }

    #[test]
    fn secondary_text_stays_above_the_readable_floor() {
        for appearance in Appearance::ALL {
            let p = appearance.palette();
            for (name, colour) in [("muted", p.muted), ("faint", p.faint)] {
                let ratio = contrast(colour, p.surface);
                assert!(
                    ratio >= 3.0,
                    "{} {name} on surface is {ratio:.1}:1, below 3:1",
                    appearance.label()
                );
            }
        }
    }

    #[test]
    fn every_grade_is_readable_against_the_surface_it_is_drawn_on() {
        for appearance in Appearance::ALL {
            let p = appearance.palette();
            for grade in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] {
                let ratio = contrast(p.grade(grade), p.surface);
                assert!(
                    ratio >= 3.0,
                    "{} {grade} is {ratio:.1}:1 on surface",
                    appearance.label()
                );
            }
        }
    }

    #[test]
    fn the_grades_are_distinguishable_from_each_other() {
        for appearance in Appearance::ALL {
            let p = appearance.palette();
            let colours = [p.critical, p.high, p.medium, p.low];
            for (i, a) in colours.iter().enumerate() {
                for b in colours.iter().skip(i + 1) {
                    assert_ne!(a, b, "{} reuses a grade colour", appearance.label());
                }
            }
        }
    }

    #[test]
    fn high_contrast_earns_its_name() {
        let p = Appearance::HighContrast.palette();
        assert!(
            contrast(p.text, p.background)
                > contrast(
                    Appearance::Dark.palette().text,
                    Appearance::Dark.palette().background
                ),
            "the high-contrast theme must beat the default one"
        );
    }

    #[test]
    fn density_scales_space_without_reaching_zero() {
        for density in Density::ALL {
            assert!(
                density.pad(space::HAIR) >= 1.0,
                "{density:?} collapsed a gap"
            );
            assert!(density.row_height() >= 24.0);
        }
        assert!(Density::Compact.pad(space::WIDE) < Density::Comfortable.pad(space::WIDE));
    }

    #[test]
    fn an_unknown_grade_is_inert_rather_than_a_panic() {
        let p = Appearance::Dark.palette();
        assert_eq!(p.grade("something new"), p.inert);
        assert_eq!(p.grade(""), p.inert);
    }

    #[test]
    fn a_palette_round_trips_through_its_file_form() {
        let p = Appearance::Dark.palette();
        let text = serde_json::to_string(&p).expect("a palette serialises");
        let back: Palette = serde_json::from_str(&text).expect("and reads back");
        assert_eq!(p, back);
    }
}

/// Everything the drawing functions need to know about appearance.
///
/// Passed by value into every panel so that no panel reaches for a global. A
/// panel that cannot see settings cannot disagree with the rest of the window
/// about them.
#[derive(Debug, Clone, Copy)]
pub struct Style {
    /// The colours in use.
    pub palette: Palette,
    /// How much air.
    pub density: Density,
    /// A whole-interface multiplier, for a second display at an unhelpful
    /// resolution. Applies to type as well as space, unlike density.
    pub scale: f32,
}

impl Default for Style {
    fn default() -> Self {
        Self {
            palette: Appearance::Dark.palette(),
            density: Density::Normal,
            scale: 1.0,
        }
    }
}

impl Style {
    /// Scale one space token to the current density, then by the user's scale.
    #[must_use]
    pub fn pad(self, token: f32) -> f32 {
        (self.density.pad(token) * self.scale).round().max(1.0)
    }

    /// Scale one type size by the user's scale. Density does not move type.
    #[must_use]
    pub fn type_size(self, token: f32) -> f32 {
        (token * self.scale).round()
    }

    /// Row height at the current density and scale.
    #[must_use]
    pub fn row_height(self) -> f32 {
        (self.density.row_height() * self.scale).round()
    }
}
