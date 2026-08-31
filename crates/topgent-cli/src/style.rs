//! Colour and column layout for the terminal.
//!
//! Written here rather than pulled in, because a security tool that adds two
//! dependencies to draw a table has widened its supply chain to make output
//! prettier. What this needs is eight escape codes and a column that pads to a
//! width; neither is worth a crate.
//!
//! Colour is off unless the output is a terminal, and off whenever `NO_COLOR`
//! is set to anything at all. Escape codes in a file someone piped this into
//! are noise at best and, in a log a machine parses, a bug.
//!
//! Colour is never the only carrier of a fact here either. A grade prints its
//! own name, and a boundary prints its sentence, so this reads the same through
//! `| cat` as it does on a terminal.

use std::io::IsTerminal;

/// Whether this run may use colour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ink(bool);

impl Ink {
    /// Decide once, from the environment and the terminal.
    pub(crate) fn decide() -> Self {
        // `NO_COLOR` is honoured by presence, whatever its value, which is what
        // the convention says: setting it to `0` still means no colour.
        let forbidden = std::env::var_os("NO_COLOR").is_some();
        Self(!forbidden && std::io::stdout().is_terminal())
    }

    /// Wrap text in one code, or return it untouched.
    pub(crate) fn paint(self, code: &str, text: &str) -> String {
        if self.0 && !text.is_empty() {
            format!("\u{1b}[{code}m{text}\u{1b}[0m")
        } else {
            text.to_owned()
        }
    }

    /// A risk grade, coloured by its own name.
    pub(crate) fn grade(self, text: &str) -> String {
        self.as_grade(text, text)
    }

    /// Some other text, coloured by a grade named elsewhere.
    ///
    /// A score is a number and matches no grade name, so colouring it by its
    /// own text printed every score faint whatever it said.
    pub(crate) fn as_grade(self, grade: &str, text: &str) -> String {
        self.paint(
            match grade.split_whitespace().next().unwrap_or("") {
                "CRITICAL" => "1;31",
                "HIGH" => "31",
                "MEDIUM" => "33",
                "LOW" => "32",
                _ => "90",
            },
            text,
        )
    }

    /// A heading.
    pub(crate) fn heading(self, text: &str) -> String {
        self.paint("1", text)
    }

    /// Something secondary.
    pub(crate) fn faint(self, text: &str) -> String {
        self.paint("90", text)
    }

    /// Something that needs attention but is not a grade.
    pub(crate) fn warn(self, text: &str) -> String {
        self.paint("33", text)
    }
}

/// A column: a heading, a width, and which way its values sit.
pub(crate) struct Column {
    /// The heading, which also sets the minimum width.
    pub(crate) title: &'static str,
    /// Whether values are pushed to the right, for numbers.
    pub(crate) right: bool,
}

impl Column {
    /// A left-aligned column.
    pub(crate) const fn text(title: &'static str) -> Self {
        Self {
            title,
            right: false,
        }
    }

    /// A right-aligned one, so digits line up under each other.
    pub(crate) const fn number(title: &'static str) -> Self {
        Self { title, right: true }
    }
}

/// Lay out rows under headings, sized to what they hold.
///
/// Widths come from the content rather than being guessed, which is the whole
/// reason a hand-rolled table is worth having over `format!` with fixed
/// numbers: a path one character too long used to push every column after it.
pub(crate) fn table(columns: &[Column], rows: &[Vec<String>], ink: Ink) -> String {
    let widths: Vec<usize> = columns
        .iter()
        .enumerate()
        .map(|(i, column)| {
            rows.iter()
                .filter_map(|row| row.get(i))
                .map(|cell| visible(cell))
                .chain(std::iter::once(column.title.chars().count()))
                .max()
                .unwrap_or(0)
        })
        .collect();

    let mut out = String::new();
    out.push_str("  ");
    for (i, column) in columns.iter().enumerate() {
        let width = widths.get(i).copied().unwrap_or(0);
        out.push_str(&ink.faint(&pad(column.title, width, column.right)));
        out.push_str("  ");
    }
    trim_end(&mut out);
    out.push('\n');

    for row in rows {
        out.push_str("  ");
        for (i, column) in columns.iter().enumerate() {
            let width = widths.get(i).copied().unwrap_or(0);
            let cell = row.get(i).map_or("", String::as_str);
            out.push_str(&pad(cell, width, column.right));
            out.push_str("  ");
        }
        trim_end(&mut out);
        out.push('\n');
    }
    out
}

/// Drop the spaces at the end of the line being built.
///
/// Trailing whitespace is noise in a copied line and shows up as a diff in
/// anything that stores the output.
fn trim_end(out: &mut String) {
    while out.ends_with(' ') {
        out.pop();
    }
}

/// Pad a cell to a width, counting what is visible rather than what is stored.
fn pad(cell: &str, width: usize, right: bool) -> String {
    let shown = visible(cell);
    let gap = " ".repeat(width.saturating_sub(shown));
    if right {
        format!("{gap}{cell}")
    } else {
        format!("{cell}{gap}")
    }
}

/// How wide a string prints, ignoring escape sequences.
///
/// A coloured cell holds more bytes than it shows, and padding by length puts
/// every column after it out by the size of the escape codes.
fn visible(text: &str) -> usize {
    let mut count = 0;
    let mut in_escape = false;
    for c in text.chars() {
        if in_escape {
            in_escape = c != 'm';
        } else if c == '\u{1b}' {
            in_escape = true;
        } else {
            count += 1;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]

    use super::*;

    #[test]
    fn nothing_is_painted_when_colour_is_off() {
        let plain = Ink(false);
        assert_eq!(plain.grade("CRITICAL 100"), "CRITICAL 100");
        assert_eq!(plain.heading("AGENT"), "AGENT");
        assert!(!plain.faint("x").contains('\u{1b}'), "an escape survived");
    }

    #[test]
    fn a_coloured_cell_is_padded_by_what_it_shows_not_what_it_stores() {
        let ink = Ink(true);
        let painted = ink.grade("LOW");
        assert!(painted.len() > 3, "the escape codes are not there");
        assert_eq!(visible(&painted), 3, "the escapes were counted as width");
        assert_eq!(visible(&pad(&painted, 8, false)), 8);
    }

    #[test]
    fn columns_are_sized_by_the_widest_thing_in_them() {
        let columns = [Column::text("A"), Column::number("N")];
        let rows = vec![
            vec!["short".to_owned(), "1".to_owned()],
            vec!["much longer value".to_owned(), "1000".to_owned()],
        ];
        let out = table(&columns, &rows, Ink(false));
        let lines: Vec<&str> = out.lines().collect();
        // A right-aligned column ends at one offset, not starts at one. Every
        // line is the same length because every column is sized to its widest
        // value, which is what a fixed-width `format!` loses the moment a
        // value is one character too long.
        assert_eq!(lines[1].len(), lines[2].len(), "{out}");
        assert!(lines[1].contains("much longer value") || lines[2].contains("much longer value"));
    }

    #[test]
    fn a_number_column_puts_its_digits_on_the_right() {
        let columns = [Column::number("N")];
        let rows = vec![vec!["7".to_owned()], vec!["1000".to_owned()]];
        let out = table(&columns, &rows, Ink(false));
        assert!(out.contains("     7"), "{out}");
    }

    #[test]
    fn no_line_carries_trailing_whitespace() {
        let columns = [Column::text("A"), Column::text("B")];
        let rows = vec![vec!["x".to_owned(), "y".to_owned()]];
        for line in table(&columns, &rows, Ink(false)).lines() {
            assert!(!line.ends_with(' '), "trailing space in {line:?}");
        }
    }

    /// A score carries its grade's colour. Colouring it by its own text made
    /// every score faint, because `100` is not the name of a grade.
    #[test]
    fn a_score_takes_the_colour_of_the_grade_it_belongs_to() {
        let ink = Ink(true);
        assert!(ink.as_grade("CRITICAL", "100").contains("1;31"));
        assert!(ink.as_grade("LOW", "0").contains("32"));
        assert_eq!(visible(&ink.as_grade("CRITICAL", "100")), 3);
    }

    #[test]
    fn an_unknown_grade_is_not_left_uncoloured_by_accident() {
        let ink = Ink(true);
        // Anything unrecognised prints faint rather than in the terminal's
        // default, so a grade this build does not know still reads as a grade.
        assert!(ink.grade("SOMETHING").contains("90"));
    }
}
