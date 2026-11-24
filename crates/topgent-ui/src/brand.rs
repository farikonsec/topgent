//! Names and marks: what an agent, a model and a network owner are called, and
//! the small square tile drawn beside each.
//!
//! The web viewer draws the same tiles (`viewer/ui/brands.mjs`); the two keep
//! one table each, short enough to compare by eye. A mark is a simple shape in
//! the brand's colour, drawn here as SVG so no image file ships. Anything not
//! in the table gets a neutral tile with its initial.

use std::fmt::Write as _;

use iced::widget::{container, svg, text};
use iced::{Color, Element, Length};

use crate::theme::{self, Palette};

/// An agent family's product name, from the agent catalogue.
///
/// `None` is an unrecognised process. A family the catalogue does not know,
/// which a newer report can name, is spelled from its id.
#[must_use]
pub fn agent_name(family: Option<&str>) -> String {
    let Some(family) = family.filter(|f| !f.is_empty()) else {
        return "Unknown agent".to_owned();
    };
    topgent_collect::signatures::builtin()
        .ok()
        .and_then(|c| c.families.iter().find(|f| f.id == family))
        .map_or_else(|| title_case(family), |f| f.name.clone())
}

fn title_case(id: &str) -> String {
    id.split(['-', '_'])
        .filter(|w| !w.is_empty())
        .map(|w| {
            let mut chars = w.chars();
            chars
                .next()
                .map_or_else(String::new, |c| c.to_uppercase().chain(chars).collect())
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// A model without its route: `anthropic/claude-opus-5-5` → `claude-opus-5-5`.
#[must_use]
pub fn model_name(model: &str) -> &str {
    model.rsplit('/').next().unwrap_or(model)
}

/// Network owners as the address registry spells them, and as a person would.
const OWNER_NAMES: [(&str, &str); 15] = [
    ("ANTHROPIC", "Anthropic"),
    ("OPENAI", "OpenAI"),
    ("GOOGLE", "Google"),
    ("GOOGLE-CLOUD-PLATFORM", "Google Cloud"),
    ("CLOUDFLARENET", "Cloudflare"),
    ("AMAZON-02", "Amazon Web Services"),
    ("AMAZON-AES", "Amazon Web Services"),
    ("MICROSOFT-CORP-MSN-AS-BLOCK", "Microsoft"),
    ("FASTLY", "Fastly"),
    ("GITHUB", "GitHub"),
    ("AKAMAI", "Akamai"),
    ("AKAMAI-ASN1", "Akamai"),
    ("DIGITALOCEAN-ASN", "DigitalOcean"),
    ("VERCEL", "Vercel"),
    ("CONTABO", "Contabo"),
];

/// Owners that are this machine or its local network, not a company.
const LOCAL_OWNERS: [&str; 7] = [
    "Loopback",
    "Private use",
    "Link-local",
    "Unique local",
    "Multicast",
    "This network",
    "Carrier-grade NAT",
];

/// Whether an owner is a local address range rather than a company.
#[must_use]
pub fn is_local_owner(raw: &str) -> bool {
    LOCAL_OWNERS.contains(&raw)
}

/// A network owner's name as a person reads it: `ANTHROPIC · AS399358` → Anthropic.
#[must_use]
pub fn owner_name(raw: &str) -> String {
    let base = raw
        .split(" \u{b7} ")
        .next()
        .unwrap_or("")
        .split(" (")
        .next()
        .unwrap_or("")
        .trim();
    if base.is_empty() {
        return "Unknown".to_owned();
    }
    if let Some((_, name)) = OWNER_NAMES.iter().find(|(k, _)| *k == base) {
        return (*name).to_owned();
    }
    if base != base.to_uppercase() {
        return base.to_owned();
    }
    let word = base
        .split(['-', '_', ' '])
        .next()
        .unwrap_or(base)
        .to_lowercase();
    title_case(&word)
}

/// How a brand is drawn: a shape, or one or two letters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mark {
    /// The Claude burst of rays.
    Spark,
    /// The Gemini four-point star.
    Star,
    /// Six petals: a stand-in for the `OpenAI` knot.
    Knot,
    /// A cloud.
    Cloud,
    /// The arrow under the Amazon wordmark.
    Smile,
    /// Four squares in their own colours.
    Windows,
    /// Vercel.
    Triangle,
    /// Letters.
    Letters(&'static str),
}

/// `key → (background, foreground, mark)`.
const BRANDS: [(&str, u32, u32, Mark); 30] = [
    ("claude", 0xD9_7757, 0xFF_FFFF, Mark::Spark),
    ("openai", 0x0F_0F0F, 0xFF_FFFF, Mark::Knot),
    ("gemini", 0xEE_F2FF, 0x4E_6CF5, Mark::Star),
    ("google", 0xFF_FFFF, 0x42_85F4, Mark::Letters("G")),
    ("ollama", 0x0F_0F0F, 0xFF_FFFF, Mark::Letters("O")),
    ("cursor", 0x0F_0F0F, 0xFF_FFFF, Mark::Letters("C")),
    ("github", 0x18_1717, 0xFF_FFFF, Mark::Letters("GH")),
    ("qwen", 0x61_5CED, 0xFF_FFFF, Mark::Letters("Q")),
    ("kimi", 0x0F_0F0F, 0xFF_FFFF, Mark::Letters("K")),
    ("zhipu", 0x38_59FF, 0xFF_FFFF, Mark::Letters("Z")),
    ("aider", 0x14_B014, 0xFF_FFFF, Mark::Letters("A")),
    ("goose", 0x0F_0F0F, 0xFF_FFFF, Mark::Letters("G")),
    ("cline", 0x0F_0F0F, 0xFF_FFFF, Mark::Letters("C")),
    ("roo", 0x0F_0F0F, 0xFF_FFFF, Mark::Letters("R")),
    ("continue", 0x0F_0F0F, 0xFF_FFFF, Mark::Letters("C")),
    ("windsurf", 0x0B_100F, 0x58_E5BB, Mark::Letters("W")),
    ("amp", 0xF3_4E3F, 0xFF_FFFF, Mark::Letters("A")),
    ("crush", 0x6B_50FF, 0xFF_FFFF, Mark::Letters("C")),
    ("opencode", 0x0F_0F0F, 0xFF_FFFF, Mark::Letters("OC")),
    ("unsloth", 0x16_A34A, 0xFF_FFFF, Mark::Letters("U")),
    ("llamacpp", 0x1F_2937, 0xFF_FFFF, Mark::Letters("LL")),
    ("lmstudio", 0x43_38CA, 0xFF_FFFF, Mark::Letters("LM")),
    ("aws", 0x23_2F3E, 0xFF_9900, Mark::Smile),
    ("cloudflare", 0xFF_F1E6, 0xF3_8020, Mark::Cloud),
    ("microsoft", 0xFF_FFFF, 0x00_0000, Mark::Windows),
    ("fastly", 0xFF_282D, 0xFF_FFFF, Mark::Letters("F")),
    ("akamai", 0x00_96D6, 0xFF_FFFF, Mark::Letters("A")),
    ("digitalocean", 0x00_80FF, 0xFF_FFFF, Mark::Letters("DO")),
    ("vercel", 0x0F_0F0F, 0xFF_FFFF, Mark::Triangle),
    ("contabo", 0x1F_3A68, 0xFF_FFFF, Mark::Letters("C")),
];

/// Agent family → brand key.
const FAMILY_BRAND: [(&str, &str); 27] = [
    ("claude-code", "claude"),
    ("claude-desktop", "claude"),
    ("codex-cli", "openai"),
    ("chatgpt-desktop", "openai"),
    ("chatgpt-vscode", "openai"),
    ("gemini-cli", "gemini"),
    ("ollama", "ollama"),
    ("cursor", "cursor"),
    ("qwen-code", "qwen"),
    ("kimi-code", "kimi"),
    ("zcode", "zhipu"),
    ("github-copilot-cli", "github"),
    ("copilot-chat", "github"),
    ("aider", "aider"),
    ("goose", "goose"),
    ("cline", "cline"),
    ("roo-code", "roo"),
    ("continue", "continue"),
    ("windsurf", "windsurf"),
    ("amp", "amp"),
    ("crush", "crush"),
    ("opencode", "opencode"),
    ("unsloth", "unsloth"),
    ("llama-cpp", "llamacpp"),
    ("lm-studio", "lmstudio"),
    ("codex", "openai"),
    ("copilot-cli", "github"),
];

/// Company name (as [`owner_name`] spells it) → brand key.
const COMPANY_BRAND: [(&str, &str); 13] = [
    ("Anthropic", "claude"),
    ("OpenAI", "openai"),
    ("Google", "google"),
    ("Google Cloud", "google"),
    ("Amazon Web Services", "aws"),
    ("Cloudflare", "cloudflare"),
    ("Microsoft", "microsoft"),
    ("GitHub", "github"),
    ("Fastly", "fastly"),
    ("Akamai", "akamai"),
    ("DigitalOcean", "digitalocean"),
    ("Vercel", "vercel"),
    ("Contabo", "contabo"),
];

/// Whose mark a tile shows.
#[derive(Debug, Clone, Copy)]
pub enum Subject<'a> {
    /// An agent, by family id.
    Family(Option<&'a str>),
    /// A company, by the name [`owner_name`] gives it.
    Company(&'a str),
}

fn brand_key(subject: Subject<'_>) -> Option<&'static str> {
    match subject {
        Subject::Family(Some(family)) => FAMILY_BRAND
            .iter()
            .find(|(f, _)| *f == family)
            .map(|(_, k)| *k),
        Subject::Family(None) => None,
        Subject::Company(name) => COMPANY_BRAND
            .iter()
            .find(|(c, _)| *c == name)
            .map(|(_, k)| *k),
    }
}

const fn hex(rgb: u32) -> Color {
    let [_, r, g, b] = rgb.to_be_bytes();
    Color::from_rgb8(r, g, b)
}

fn css(rgb: u32) -> String {
    format!("#{rgb:06X}")
}

/// The mark as an SVG document on a 24-unit square, in `fg`.
fn mark_svg(mark: Mark, fg: u32) -> Option<String> {
    let c = css(fg);
    let body = match mark {
        Mark::Spark => (0..12).fold(String::new(), |mut out, i| {
            let a = f64::from(i) * std::f64::consts::PI / 6.0;
            let r = if i % 2 == 1 { 7.5 } else { 10.0 };
            let _ = write!(
                out,
                r#"<line x1="12" y1="12" x2="{:.2}" y2="{:.2}" stroke="{c}" stroke-width="2.4" stroke-linecap="round"/>"#,
                12.0 + r * a.cos(),
                12.0 + r * a.sin()
            );
            out
        }),
        Mark::Star => format!(
            r#"<path d="M12 2C12.6 7.4 16.6 11.4 22 12C16.6 12.6 12.6 16.6 12 22C11.4 16.6 7.4 12.6 2 12C7.4 11.4 11.4 7.4 12 2Z" fill="{c}"/>"#
        ),
        Mark::Knot => (0..6).fold(String::new(), |mut out, i| {
            let _ = write!(
                out,
                r#"<ellipse cx="12" cy="7" rx="3" ry="5.2" fill="none" stroke="{c}" stroke-width="1.8" transform="rotate({} 12 12)"/>"#,
                i * 60
            );
            out
        }),
        Mark::Cloud => format!(r#"<path d="M7 18a5 5 0 0 1-.6-9.96A6 6 0 0 1 18 9.5 4.25 4.25 0 0 1 17.5 18Z" fill="{c}"/>"#),
        Mark::Smile => format!(
            r#"<path d="M4 13c4.5 3.2 11 3.2 16 0" fill="none" stroke="{c}" stroke-width="2.2" stroke-linecap="round"/><path d="M17 11.5l3 1.5-1.2 3" fill="none" stroke="{c}" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>"#
        ),
        Mark::Windows => concat!(
            r##"<rect x="3" y="3" width="8.4" height="8.4" fill="#F25022"/>"##,
            r##"<rect x="12.6" y="3" width="8.4" height="8.4" fill="#7FBA00"/>"##,
            r##"<rect x="3" y="12.6" width="8.4" height="8.4" fill="#00A4EF"/>"##,
            r##"<rect x="12.6" y="12.6" width="8.4" height="8.4" fill="#FFB900"/>"##,
        )
        .to_owned(),
        Mark::Triangle => format!(r#"<path d="M12 4l9 16H3Z" fill="{c}"/>"#),
        Mark::Letters(_) => return None,
    };
    Some(format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">{body}</svg>"#
    ))
}

/// A square brand tile `edge` pixels wide. `name` gives the initial when the
/// subject has no brand.
pub fn logo<'a, M: 'a>(subject: Subject<'_>, name: &str, edge: f32, p: Palette) -> Element<'a, M> {
    let brand = brand_key(subject).and_then(|key| BRANDS.iter().find(|(k, ..)| *k == key));
    let (bg, fg, mark) = brand.map_or_else(
        || {
            let initial = name.chars().next().map_or('?', |c| c.to_ascii_uppercase());
            (None, None, Err(initial.to_string()))
        },
        |&(_, bg, fg, mark)| (Some(hex(bg)), Some(fg), Ok(mark)),
    );
    let inner: Element<'a, M> = match mark {
        Ok(Mark::Letters(letters)) => text(letters)
            .font(theme::STRONG)
            .size((edge * if letters.len() > 1 { 0.38 } else { 0.5 }).round())
            .color(fg.map_or(p.muted, hex))
            .into(),
        Ok(mark) => match mark_svg(mark, fg.unwrap_or(0xFF_FFFF)) {
            Some(doc) => svg(svg::Handle::from_memory(doc.into_bytes()))
                .width(Length::Fixed((edge * 0.66).round()))
                .height(Length::Fixed((edge * 0.66).round()))
                .into(),
            None => iced::widget::space().into(),
        },
        Err(initial) => text(initial)
            .font(theme::STRONG)
            .size((edge * 0.5).round())
            .color(p.muted)
            .into(),
    };
    let fill = bg.unwrap_or(p.raised);
    let edge_colour = if bg.is_some_and(|c| c.r + c.g + c.b > 2.8) {
        p.border
    } else {
        iced::Color::TRANSPARENT
    };
    container(inner)
        .center_x(Length::Fixed(edge))
        .center_y(Length::Fixed(edge))
        .style(move |_| container::Style {
            background: Some(fill.into()),
            border: iced::Border {
                color: edge_colour,
                width: if edge_colour == iced::Color::TRANSPARENT {
                    0.0
                } else {
                    1.0
                },
                radius: (edge * 0.24).into(),
            },
            ..container::Style::default()
        })
        .into()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn agents_are_named_from_the_catalogue() {
        assert_eq!(agent_name(Some("claude-code")), "Claude Code");
        assert_eq!(agent_name(Some("llama-cpp")), "llama.cpp");
        assert_eq!(agent_name(Some("some-new-agent")), "Some New Agent");
        assert_eq!(agent_name(None), "Unknown agent");
    }

    #[test]
    fn models_lose_their_route() {
        assert_eq!(model_name("anthropic/claude-opus-5-5"), "claude-opus-5-5");
        assert_eq!(model_name("gpt-6.1-terra"), "gpt-6.1-terra");
    }

    #[test]
    fn owners_read_as_companies() {
        assert_eq!(owner_name("ANTHROPIC \u{b7} AS399358"), "Anthropic");
        assert_eq!(owner_name("AMAZON-02"), "Amazon Web Services");
        assert_eq!(owner_name("HETZNER-AS"), "Hetzner");
        assert_eq!(owner_name("Loopback"), "Loopback");
        assert_eq!(owner_name(""), "Unknown");
        assert!(is_local_owner("Private use"));
    }

    #[test]
    fn every_brand_key_has_a_tile_and_every_mark_draws() {
        for (_, key) in FAMILY_BRAND.iter().chain(COMPANY_BRAND.iter()) {
            assert!(BRANDS.iter().any(|(k, ..)| k == key), "{key} has no tile");
        }
        for &(key, _, fg, mark) in &BRANDS {
            if !matches!(mark, Mark::Letters(_)) {
                assert!(mark_svg(mark, fg).unwrap().starts_with("<svg"), "{key}");
            }
        }
    }

    #[test]
    fn every_catalogue_family_has_a_brand() {
        let catalogue = topgent_collect::signatures::builtin().unwrap();
        let missing: Vec<&str> = catalogue
            .families
            .iter()
            .map(|f| f.id.as_str())
            .filter(|id| !FAMILY_BRAND.iter().any(|(f, _)| f == id))
            .filter(|id| !matches!(*id, "openhands" | "factory-droid"))
            .collect();
        assert!(missing.is_empty(), "no brand for {missing:?}");
    }
}
