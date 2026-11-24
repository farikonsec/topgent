//! This launch's session: saved when the window closes, or not, and saved
//! sessions opened again later to look at.
//!
//! A new window starts with no history of its own (see
//! `topgent_journal::session`). Closing asks, as a capture tool does,
//! whether to keep what was seen. A saved session is one file; opening it
//! shows the report it last showed, with sweeps stopped, until the reader
//! goes back to the live host.

use std::path::{Path, PathBuf};

use iced::widget::{Column, button, column, container, row, text};
use iced::{Element, Length};

use crate::Message;
use crate::report::Report;
use crate::theme::{self, Region, Style, size, space};

/// A saved session being looked at instead of the live host.
#[derive(Debug, Clone)]
pub struct Viewing {
    /// The file it came from, by name.
    pub name: String,
    /// When it was saved, in Unix milliseconds.
    pub saved_at: u64,
}

/// Saves this session to a new file in the saved-sessions directory: a
/// fresh sweep, so the file holds what the window would show now, and every
/// history of the session. Returns where it went.
///
/// # Errors
///
/// The file could not be written, said in words for the dialog.
pub async fn save() -> Result<PathBuf, String> {
    tokio::task::spawn_blocking(|| {
        let report = topgent_report::scan();
        let to = topgent_report::saved_sessions_dir().join(format!(
            "topgent-session-{}.{}",
            file_stamp(crate::clock::now_ms()),
            topgent_report::SESSION_EXTENSION
        ));
        topgent_report::save_session(&report, &topgent_report::session_dir(), &to)
            .map(|()| to)
            .map_err(|e| format!("the session could not be saved: {e}"))
    })
    .await
    .map_err(|_| "the save thread failed".to_owned())?
}

/// Opens a saved session for viewing.
///
/// # Errors
///
/// The file is not a saved session this build reads, said in words.
pub async fn open(path: PathBuf) -> Result<(Report, Viewing), String> {
    tokio::task::spawn_blocking(move || {
        let saved = topgent_report::load_session(&path)
            .map_err(|e| format!("{} could not be opened: {e}", display_name(&path)))?;
        let report = serde_json::from_value(saved.report).map_err(|e| {
            format!(
                "{} has a report this build cannot read: {e}",
                display_name(&path)
            )
        })?;
        Ok((
            report,
            Viewing {
                name: display_name(&path),
                saved_at: saved.saved_at,
            },
        ))
    })
    .await
    .map_err(|_| "the open thread failed".to_owned())?
}

/// Saved sessions, newest first.
#[must_use]
pub fn saved() -> Vec<(PathBuf, u64)> {
    topgent_report::list_saved(&topgent_report::saved_sessions_dir())
}

/// Removes this launch's session. Called once it is saved or declined, just
/// before the window goes.
pub fn discard() {
    if let Err(error) = topgent_report::discard_session() {
        eprintln!("topgent: this session's directory could not be removed: {error}");
    }
}

fn display_name(path: &Path) -> String {
    path.file_name().map_or_else(
        || path.display().to_string(),
        |name| name.to_string_lossy().into_owned(),
    )
}

/// `YYYY-MM-DD_HH-MM-SS` in local time, for a file name that sorts.
fn file_stamp(at_ms: u64) -> String {
    let (year, month, day, h, m, sec) = crate::clock::local_parts(at_ms);
    format!("{year:04}-{month:02}-{day:02}_{h:02}-{m:02}-{sec:02}")
}

/// The question asked when the window is closed.
pub fn closing_dialog<'a>(saving: bool, outcome: Option<&str>, s: Style) -> Element<'a, Message> {
    let p = s.palette;
    let mut body = column![
        text("Save this session before closing?")
            .font(theme::STRONG)
            .size(s.type_size(size::SECTION))
            .color(p.text),
        text("Unsaved data is deleted when the window closes.")
            .size(s.type_size(size::READING))
            .color(p.muted),
        text(format!(
            "Saved to {}",
            topgent_report::saved_sessions_dir().display()
        ))
        .font(theme::MONO)
        .size(s.type_size(size::MICRO))
        .color(p.faint),
    ]
    .spacing(s.pad(space::BASE));
    if let Some(outcome) = outcome {
        body = body.push(
            text(outcome.to_owned())
                .size(s.type_size(size::BODY))
                .color(p.high),
        );
    }
    let buttons = if saving {
        row![
            text("Saving…")
                .size(s.type_size(size::EMPHASIS))
                .color(p.muted)
        ]
    } else {
        row![
            plain("Cancel", Message::CancelClose, s),
            plain("Close without saving", Message::CloseWithoutSaving, s),
            primary("Save", Message::SaveAndClose, s),
        ]
        .spacing(s.pad(space::SNUG))
    };
    container(
        container(body.push(buttons))
            .style(theme::region(Region::Panel, p))
            .padding(s.pad(space::LOOSE))
            .width(Length::Fixed(520.0)),
    )
    .style(theme::region(Region::Scrim, p))
    .width(Length::Fill)
    .height(Length::Fill)
    .center_x(Length::Fill)
    .center_y(Length::Fill)
    .into()
}

/// The line across the top while a saved session is showing.
pub fn banner<'a>(viewing: &Viewing, s: Style) -> Element<'a, Message> {
    let p = s.palette;
    container(
        // The way back first: on a narrow window the end of the line is
        // what gets cut off, and the line is only there to be left.
        row![
            plain("Back to live", Message::BackToLive, s),
            text("Saved session")
                .font(theme::STRONG)
                .size(s.type_size(size::EMPHASIS))
                .color(p.medium),
            text(format!(
                "{}, saved {}. Not live: sweeps are stopped.",
                viewing.name,
                crate::clock::stamp(viewing.saved_at)
            ))
            .size(s.type_size(size::EMPHASIS))
            .color(p.muted),
        ]
        .spacing(s.pad(space::SNUG))
        .align_y(iced::Alignment::Center),
    )
    .padding([s.pad(space::TIGHT), s.pad(space::BASE)])
    .width(Length::Fill)
    .into()
}

/// The saved sessions, for the settings page: each can be opened.
pub fn saved_list<'a>(saved: &[(PathBuf, u64)], s: Style) -> Element<'a, Message> {
    let p = s.palette;
    let mut list = Column::new().spacing(s.pad(space::TIGHT)).push(
        text(format!(
            "Saved sessions, in {}. A .{} file copied there shows here.",
            topgent_report::saved_sessions_dir().display(),
            topgent_report::SESSION_EXTENSION
        ))
        .size(s.type_size(size::MICRO))
        .color(p.faint),
    );
    if saved.is_empty() {
        list = list.push(
            text("None saved yet.")
                .size(s.type_size(size::BODY))
                .color(p.muted),
        );
    }
    for (path, modified) in saved.iter().take(20) {
        list = list.push(
            row![
                text(display_name(path))
                    .font(theme::MONO)
                    .size(s.type_size(size::BODY))
                    .color(p.text)
                    .width(Length::Fill),
                text(crate::clock::stamp(*modified))
                    .size(s.type_size(size::BODY))
                    .color(p.muted),
                plain("Open", Message::OpenSaved(path.clone()), s),
            ]
            .spacing(s.pad(space::SNUG))
            .align_y(iced::Alignment::Center),
        );
    }
    list.push(plain("Save this session now", Message::SaveNow, s))
        .into()
}

fn plain(label: &str, message: Message, s: Style) -> Element<'_, Message> {
    let p = s.palette;
    button(text(label).size(s.type_size(size::EMPHASIS)).color(p.text))
        .on_press(message)
        .padding([s.pad(space::TIGHT), s.pad(space::BASE)])
        .style(button::text)
        .into()
}

fn primary(label: &str, message: Message, s: Style) -> Element<'_, Message> {
    let p = s.palette;
    button(
        text(label)
            .size(s.type_size(size::EMPHASIS))
            .color(p.background),
    )
    .on_press(message)
    .padding([s.pad(space::TIGHT), s.pad(space::BASE)])
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
            radius: theme::radius::PANEL.into(),
        },
        ..button::Style::default()
    })
    .into()
}

#[cfg(test)]
mod tests {
    use super::file_stamp;

    #[test]
    fn a_file_stamp_sorts_and_has_no_separator_a_file_system_refuses() {
        let stamp = file_stamp(1_790_000_000_000);
        assert_eq!(stamp.len(), "2026-09-21_14-13-20".len());
        assert!(!stamp.contains([':', '/', '\\', ' ']));
    }
}
