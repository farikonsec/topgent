//! The small drawings.
//!
//! Every glyph is a path written in this file. No icon font, no downloaded
//! asset, and nothing that imitates another product's mark: a security tool
//! that ships someone else's trademark in its chrome has made a legal problem
//! out of a decoration.
//!
//! Each is a 24-unit square scaled to the size asked for, drawn with the
//! toolkit's SVG widget so it takes the palette's colour rather than carrying
//! one of its own. A glyph never appears without its word beside it.

use iced::widget::svg;
use iced::{Color, Element, Length};

/// Which drawing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Icon {
    /// Risk explanation: a bar chart, worst bar first.
    Risk,
    /// Access: a key.
    Access,
    /// Blast radius: rings spreading from a point.
    Blast,
    /// Activity: a line that steps.
    Activity,
    /// Network: a globe with a latitude.
    Network,
    /// Event log: stacked lines.
    Events,
    /// Sensor health: a pulse.
    Health,
    /// Response: a shield.
    Response,
    /// Session context: a speech mark.
    Context,
    /// Assets: stacked layers.
    Assets,
    /// Settings.
    Settings,
    /// A source repository.
    Repository,
    /// A person.
    Author,
    /// A notification.
    Bell,
    /// Sound.
    Sound,
    /// Look again now.
    Refresh,
    /// Shrink to a corner.
    Compact,
    /// Put the layout back.
    Reset,
}

impl Icon {
    /// The path data, on a 24-unit square.
    const fn path(self) -> &'static str {
        match self {
            Self::Risk => "M4 20V10h4v10zM10 20V4h4v16zM16 20v-6h4v6z",
            Self::Access => {
                "M14 7a4 4 0 1 1-3.5 6H8v2H6v2H3v-3l7.5-7.5A4 4 0 0 1 14 7zm1.5 2.5a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3z"
            }
            Self::Blast => {
                "M12 10a2 2 0 1 1 0 4 2 2 0 0 1 0-4zM7.8 7.8a1 1 0 0 1 1.4 1.4 4 4 0 0 0 0 5.6 1 1 0 1 1-1.4 1.4 6 6 0 0 1 0-8.4zm8.4 0a6 6 0 0 1 0 8.4 1 1 0 1 1-1.4-1.4 4 4 0 0 0 0-5.6 1 1 0 0 1 1.4-1.4z"
            }
            Self::Activity => "M3 17h4v-4H3zm0-2h4M7 13h5V9H7zm5-2h5V5h-5zM7 15h5v2h5",
            Self::Network => {
                "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zm0 2c1.2 0 2.6 2.2 2.9 5.2H9.1C9.4 7.2 10.8 5 12 5zM5.2 11h2.9c0 .7 0 1.4.1 2H5.5a7 7 0 0 1-.3-2zm4.9 0h3.8c.1.6.1 1.3 0 2h-3.8a17 17 0 0 1 0-2zm5.8 0h2.9a7 7 0 0 1-.3 2h-2.7c.1-.6.1-1.3.1-2z"
            }
            Self::Events => "M4 6h16M4 10h16M4 14h11M4 18h7",
            Self::Health => "M3 12h4l2-5 3 10 2.5-6 1.5 3h5",
            Self::Response => "M12 3l7 3v6c0 4-3 7-7 9-4-2-7-5-7-9V6z",
            Self::Context => "M5 5h14v10H9l-4 4z",
            Self::Assets => "M12 3l9 5-9 5-9-5zM3 12l9 5 9-5M3 16l9 5 9-5",
            Self::Settings => {
                "M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6zM12 2l1.2 2.6 2.8-.6.4 2.8 2.6 1.2-1.4 2.5 1.4 2.5-2.6 1.2-.4 2.8-2.8-.6L12 22l-1.2-2.6-2.8.6-.4-2.8L5 16l1.4-2.5L5 11l2.6-1.2.4-2.8 2.8.6z"
            }
            // A branching line. Deliberately not any hosting service's mark.
            Self::Repository => {
                "M7 4a2 2 0 1 1 0 4 2 2 0 0 1 0-4zm0 12a2 2 0 1 1 0 4 2 2 0 0 1 0-4zm10-12a2 2 0 1 1 0 4 2 2 0 0 1 0-4zM7 8v8M17 8v2a3 3 0 0 1-3 3h-4"
            }
            Self::Author => "M12 4a4 4 0 1 1 0 8 4 4 0 0 1 0-8zM4 21a8 8 0 0 1 16 0z",
            Self::Bell => "M12 3a5 5 0 0 1 5 5v4l2 3H5l2-3V8a5 5 0 0 1 5-5zM10 18a2 2 0 0 0 4 0",
            Self::Sound => "M4 10h3l4-4v12l-4-4H4zM15 9a4 4 0 0 1 0 6M18 6a8 8 0 0 1 0 12",
            Self::Refresh => "M20 12a8 8 0 1 1-2.3-5.7M20 4v5h-5",
            Self::Compact => "M4 4h16v16H4zM13 11h6M13 11v6",
            Self::Reset => "M4 9h16M4 15h16M9 4v4M9 16v4",
        }
    }

    /// Whether the shape is a stroke rather than a filled area. Both exist
    /// because a chart is a shape and a pulse is a line, and drawing either as
    /// the other gives a blob.
    const fn stroked(self) -> bool {
        matches!(
            self,
            Self::Events
                | Self::Health
                | Self::Activity
                | Self::Repository
                | Self::Sound
                | Self::Bell
                | Self::Refresh
                | Self::Compact
                | Self::Reset
        )
    }
}

/// Draw one glyph at a size, in a colour.
pub fn view<'a, M: 'a>(icon: Icon, size: f32, colour: Color) -> Element<'a, M> {
    let paint = if icon.stroked() {
        format!(
            "fill=\"none\" stroke=\"{}\" stroke-width=\"1.8\" \
             stroke-linecap=\"round\" stroke-linejoin=\"round\"",
            hex(colour)
        )
    } else {
        format!("fill=\"{}\"", hex(colour))
    };
    let markup = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 24 24\">\
         <path d=\"{}\" {paint}/></svg>",
        icon.path()
    );
    svg(svg::Handle::from_memory(markup.into_bytes()))
        .width(Length::Fixed(size))
        .height(Length::Fixed(size))
        .into()
}

fn hex(c: Color) -> String {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let byte = |v: f32| (v.clamp(0.0, 1.0) * 255.0).round() as u8;
    format!("#{:02x}{:02x}{:02x}", byte(c.r), byte(c.g), byte(c.b))
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVERY: [Icon; 18] = [
        Icon::Risk,
        Icon::Access,
        Icon::Blast,
        Icon::Activity,
        Icon::Network,
        Icon::Events,
        Icon::Health,
        Icon::Response,
        Icon::Context,
        Icon::Assets,
        Icon::Settings,
        Icon::Repository,
        Icon::Author,
        Icon::Bell,
        Icon::Sound,
        Icon::Refresh,
        Icon::Compact,
        Icon::Reset,
    ];

    #[test]
    fn every_glyph_has_a_path_that_starts_where_a_path_must() {
        for icon in EVERY {
            let d = icon.path();
            assert!(d.starts_with('M'), "{icon:?} does not begin with a move");
            assert!(d.len() > 10, "{icon:?} is too short to be a drawing");
        }
    }

    #[test]
    fn no_two_glyphs_are_the_same_drawing() {
        for (i, a) in EVERY.iter().enumerate() {
            for b in EVERY.iter().skip(i + 1) {
                assert_ne!(a.path(), b.path(), "{a:?} and {b:?} draw the same thing");
            }
        }
    }

    #[test]
    fn a_colour_becomes_the_hex_the_markup_needs() {
        assert_eq!(hex(Color::from_rgb(1.0, 0.0, 0.0)), "#ff0000");
        assert_eq!(hex(Color::BLACK), "#000000");
        // The struct is built directly here because `Color::from_rgb` refuses
        // out-of-range values itself. A colour that reached this by another
        // route must still produce markup rather than a panic.
        assert_eq!(
            hex(Color {
                r: 4.0,
                g: -1.0,
                b: 0.5,
                a: 1.0
            }),
            "#ff0080"
        );
    }
}
