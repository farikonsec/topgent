//! The one table.
//!
//! Panels produce rows; this module decides everything about how they are
//! drawn. Nothing here is optional at a call site, which is the point: the
//! panels used to build rows out of bare text widgets and hope, so one long
//! value wrapped across nine lines and destroyed the layout of every row under
//! it. A cell never wraps now, because a row that is not one line high is a row
//! nobody can scan a column of.
//!
//! Sort and search live in the application rather than here, keyed by table, so
//! a panel stays where the reader left it when the next sweep replaces the data
//! underneath.

use crate::Message;
use crate::theme::{self, Region, Style, size, space};

use iced::widget::{Column, button, container, row, text, text_input, tooltip};
use iced::{Element, Length};

/// Which table. Sort and search are remembered per table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Id {
    /// The agent list.
    Agents,
    /// Resources an agent declared or was observed using.
    Access,
    /// Network endpoints.
    Network,
    /// The event journal.
    Events,
    /// Agent-supplied session context.
    Context,
    /// The activity path.
    Activity,
    /// Sensor health.
    Health,
    /// The binaries the sensors run.
    Tools,
}

/// How a cell's text is aligned, which follows from what it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Align {
    /// Names, paths, sentences.
    Left,
    /// Counts and scores. Right, so digits line up under each other.
    Right,
}

/// How a value is sorted when its column is clicked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sorts {
    /// Case-insensitive, by text.
    Text,
    /// By the leading number in the cell, so `CRITICAL 100` sorts above
    /// `CRITICAL 81` rather than below it the way text would put them.
    Number,
    /// Not sortable.
    No,
}

/// One column heading and everything that follows from it.
#[derive(Debug, Clone)]
pub struct Column2 {
    /// The heading.
    pub label: &'static str,
    /// Share of the width.
    pub portion: u16,
    /// Where the text sits.
    pub align: Align,
    /// Whether the values are monospace. Paths, addresses, and process ids are.
    pub mono: bool,
    /// How clicking the heading orders the table.
    pub sorts: Sorts,
}

impl Column2 {
    /// A left-aligned proportional text column.
    #[must_use]
    pub const fn text(label: &'static str, portion: u16) -> Self {
        Self {
            label,
            portion,
            align: Align::Left,
            mono: false,
            sorts: Sorts::Text,
        }
    }

    /// A monospace column: a path, an address, a process id.
    #[must_use]
    pub const fn mono(mut self) -> Self {
        self.mono = true;
        self
    }

    /// A right-aligned numeric column.
    #[must_use]
    pub const fn number(mut self) -> Self {
        self.align = Align::Right;
        self.sorts = Sorts::Number;
        self
    }
}

/// One value in one row.
#[derive(Debug, Clone, Default)]
pub struct Cell {
    /// What is drawn, before truncation.
    pub value: String,
    /// A colour, when the value carries a grade or a state. `None` inherits.
    pub colour: Option<iced::Color>,
    /// Whether this value names a file the reader could go and look at.
    pub is_path: bool,
}

impl Cell {
    /// A plain value.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            colour: None,
            is_path: false,
        }
    }

    /// A value that carries a grade or a state.
    #[must_use]
    pub fn tinted(value: impl Into<String>, colour: iced::Color) -> Self {
        Self {
            value: value.into(),
            colour: Some(colour),
            is_path: false,
        }
    }

    /// A value naming a file, which the reader can be taken to.
    #[must_use]
    pub fn path(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            colour: None,
            is_path: true,
        }
    }
}

/// One row.
#[derive(Debug, Clone, Default)]
pub struct Row {
    /// The values, in column order.
    pub cells: Vec<Cell>,
    /// The process this row is about, when clicking it should select one.
    pub select: Option<u32>,
    /// Whether it is the selected row.
    pub selected: bool,
    /// A semantic rail at the leading edge, used when the row has a severity.
    pub marker: Option<iced::Color>,
    /// What this row says in full, shown when it is opened.
    ///
    /// A table row is one line by construction, which is right for scanning and
    /// wrong for reading. The record behind it goes here, as labelled lines,
    /// rather than being lost to truncation.
    pub detail: Vec<(String, String)>,
}

impl Row {
    /// A row of values.
    #[must_use]
    pub fn new(cells: Vec<Cell>) -> Self {
        Self {
            cells,
            select: None,
            selected: false,
            marker: None,
            detail: Vec::new(),
        }
    }

    /// Make the row selectable, and say whether it is the selected one.
    #[must_use]
    pub fn selectable(mut self, pid: u32, selected: bool) -> Self {
        self.select = Some(pid);
        self.selected = selected;
        self
    }

    /// Mark the row with a semantic colour while retaining its written grade.
    #[must_use]
    pub fn marked(mut self, colour: iced::Color) -> Self {
        self.marker = Some(colour);
        self
    }

    /// Give the row a full record, which opens under it.
    #[must_use]
    pub fn detailed(mut self, detail: Vec<(String, String)>) -> Self {
        self.detail = detail;
        self
    }

    /// Whether any cell contains this text, matched case-insensitively.
    fn matches(&self, needle: &str) -> bool {
        self.cells
            .iter()
            .any(|c| c.value.to_lowercase().contains(needle))
    }
}

/// What the application remembers for every table.
pub type Tables = std::collections::HashMap<Id, State>;

/// The state for one table, or the defaults if it has none yet.
#[must_use]
pub fn state_of(tables: &Tables, id: Id) -> State {
    tables.get(&id).cloned().unwrap_or_default()
}

/// Which column a table is ordered by, and which way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sort {
    /// Index into the column list.
    pub column: usize,
    /// Ascending when true.
    pub ascending: bool,
}

/// Everything the application remembers about one table.
#[derive(Debug, Clone, Default)]
pub struct State {
    /// The ordering, or `None` for the order the panel produced.
    pub sort: Option<Sort>,
    /// The search text, lowercased when it is applied.
    pub search: String,
    /// Rows the reader has opened, by their position after sorting.
    pub opened: std::collections::BTreeSet<usize>,
    /// The width a drag has reached, before rounding to a whole share. Kept
    /// separately so a slow drag is not repeatedly rounded away.
    exact: std::collections::HashMap<usize, f32>,
    /// Widths the reader has set, by column index, as a share replacing the
    /// declared portion. Empty until someone drags an edge.
    pub widths: std::collections::HashMap<usize, u16>,
}

impl State {
    /// The share this column takes, as the reader left it or as declared.
    #[must_use]
    pub fn portion(&self, index: usize, column: &Column2) -> u16 {
        self.widths.get(&index).copied().unwrap_or(column.portion)
    }

    /// Widen or narrow one column by a fraction of a share.
    ///
    /// The fraction is kept, so a slow drag moves the edge smoothly rather
    /// than doing nothing until it crosses a whole unit.
    ///
    /// Clamped at one share, because a column dragged to nothing is a column
    /// whose edge can never be found again.
    pub fn drag(&mut self, index: usize, column: &Column2, by: f32) {
        let current = self
            .exact
            .get(&index)
            .copied()
            .unwrap_or_else(|| f32::from(self.portion(index, column)));
        let next = (current + by).clamp(1.0, 40.0);
        self.exact.insert(index, next);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let rounded = next.round() as u16;
        self.widths.insert(index, rounded.max(1));
    }
}

/// Width of one character as a fraction of the type size.
///
/// An approximation, and deliberately a low one. Guessing narrow shortens a
/// value that would have fitted; guessing wide lets it run under the next
/// column. The first is a cosmetic loss and the second makes two columns
/// unreadable, which is what the first attempt at this did.
const CHAR_WIDTH: f32 = 0.66;

/// Draw a table.
///
/// `empty` is the sentence shown when there are no rows at all, which is never
/// the same thing as a search matching nothing.
pub fn view<'a>(
    id: Id,
    columns: &'a [Column2],
    rows: Vec<Row>,
    state: &State,
    empty: &'a str,
    s: Style,
) -> Element<'a, Message> {
    // The width is measured rather than assumed. Truncating to a guessed
    // character count let one column draw over the next, because how many
    // characters fit depends on the window, the density, and the scale.
    let columns_owned = columns;
    let rows = std::rc::Rc::new(rows);
    let state = state.clone();
    let empty = empty.to_owned();
    iced::widget::responsive(move |size| {
        draw(id, columns_owned, &rows, &state, &empty, size.width, s)
    })
    .into()
}

fn draw<'a>(
    id: Id,
    columns: &'a [Column2],
    rows: &[Row],
    state: &State,
    empty: &str,
    width: f32,
    s: Style,
) -> Element<'a, Message> {
    let p = s.palette;
    let total = rows.len();
    let needle = state.search.trim().to_lowercase();
    let mut rows: Vec<Row> = if needle.is_empty() {
        rows.to_vec()
    } else {
        rows.iter()
            .filter(|r| r.matches(&needle))
            .cloned()
            .collect()
    };

    if let Some(sort) = state.sort
        && let Some(column) = columns.get(sort.column)
    {
        sort_rows(&mut rows, sort, column.sorts);
    }

    let portions: u16 = columns
        .iter()
        .enumerate()
        .map(|(i, c)| state.portion(i, c))
        .sum();
    let layout = Layout {
        id,
        columns,
        portions,
        width,
        s,
    };
    let mut body = Column::new();
    if rows.is_empty() {
        body = body.push(
            container(
                text(if total == 0 {
                    empty.to_string()
                } else {
                    format!("Nothing in these {total} rows matches that.")
                })
                .size(s.type_size(size::BODY))
                .color(p.faint),
            )
            .padding(s.pad(space::WIDE)),
        );
    }
    for (index, r) in rows.iter().enumerate() {
        body = body.push(line(layout, index, state, r, index % 2 == 1));
        if state.opened.contains(&index) && !r.detail.is_empty() {
            body = body.push(record(&r.detail, s));
        }
    }

    Column::new()
        .push(search_box(id, state, total, rows.len(), s))
        // The heading sits outside the scroll region, so scrolling a long
        // table keeps its column names. Inside it, they leave with the first
        // rows and the rest becomes unlabelled columns.
        .push(heading_row(id, columns, state, width, s))
        .push(
            iced::widget::scrollable(body)
                .width(Length::Fill)
                .height(Length::Fill),
        )
        .spacing(s.pad(space::HAIR))
        .into()
}

fn sort_rows(rows: &mut [Row], sort: Sort, sorts: Sorts) {
    let at = |r: &Row| {
        r.cells
            .get(sort.column)
            .map(|c| c.value.clone())
            .unwrap_or_default()
    };
    match sorts {
        Sorts::Number => {
            rows.sort_by(|a, b| leading_number(&at(a)).total_cmp(&leading_number(&at(b))));
        }
        // `Sorts::No` still orders by text if the caller asks for it, because a
        // sort state that silently does nothing is worse than one that does
        // something predictable.
        Sorts::Text | Sorts::No => {
            rows.sort_by_key(|r| at(r).to_lowercase());
        }
    }
    if !sort.ascending {
        rows.reverse();
    }
}

/// The first number anywhere in the value, so `CRITICAL 100` sorts above
/// `CRITICAL 81` rather than below it the way text ordering puts them.
///
/// A cell with no number sorts to the bottom ascending, which is where a `-`
/// belongs.
fn leading_number(value: &str) -> f64 {
    let mut digits = String::new();
    for c in value.chars() {
        if c.is_ascii_digit() || (c == '.' && !digits.is_empty()) {
            digits.push(c);
        } else if !digits.is_empty() {
            break;
        }
    }
    digits.parse().unwrap_or(f64::MIN)
}

fn search_box<'a>(
    id: Id,
    state: &State,
    total: usize,
    shown: usize,
    s: Style,
) -> Element<'a, Message> {
    let p = s.palette;
    let count = if state.search.trim().is_empty() {
        format!("{total} rows")
    } else {
        format!("{shown} of {total}")
    };
    container(
        row![
            text_input("Filter rows", &state.search)
                .on_input(move |v| Message::Search(id, v))
                .size(s.type_size(size::BODY))
                .padding([s.pad(space::TIGHT), s.pad(space::SNUG)])
                .width(Length::Fixed(220.0))
                .style(move |_, _| text_input::Style {
                    background: p.background.into(),
                    border: iced::Border {
                        color: p.border,
                        width: 1.0,
                        radius: theme::radius::CONTROL.into(),
                    },
                    icon: p.faint,
                    placeholder: p.faint,
                    value: p.text,
                    selection: p.accent,
                }),
            text(count).size(s.type_size(size::MICRO)).color(p.faint),
        ]
        .spacing(s.pad(space::BASE))
        .align_y(iced::Alignment::Center),
    )
    .padding([s.pad(space::SNUG), s.pad(space::BASE)])
    .into()
}

fn heading_row<'a>(
    id: Id,
    columns: &'a [Column2],
    state: &State,
    width: f32,
    s: Style,
) -> Element<'a, Message> {
    let p = s.palette;
    let portions: u16 = columns
        .iter()
        .enumerate()
        .map(|(i, c)| state.portion(i, c))
        .sum();
    let sort = state.sort;
    let mut r = iced::widget::Row::new().spacing(s.pad(space::SNUG));
    for (index, column) in columns.iter().enumerate() {
        let active = sort.filter(|so| so.column == index);
        // The arrow, not colour alone, says which column is ordering the table.
        let label = match active {
            Some(so) if so.ascending => format!("{} \u{2191}", column.label),
            Some(_) => format!("{} \u{2193}", column.label),
            None => column.label.to_owned(),
        };
        // Heavier and a step brighter than a value, so a heading reads as a
        // heading rather than as a smaller row of data.
        let heading = text(label)
            .wrapping(iced::widget::text::Wrapping::None)
            .font(theme::STRONG)
            .size(s.type_size(size::MICRO))
            .color(if active.is_some() { p.text } else { p.muted })
            .align_x(match column.align {
                Align::Left => iced::alignment::Horizontal::Left,
                Align::Right => iced::alignment::Horizontal::Right,
            })
            .width(Length::Fill);

        let cell: Element<'a, Message> = if column.sorts == Sorts::No {
            container(heading)
                .width(Length::FillPortion(column.portion))
                .into()
        } else {
            button(heading)
                .on_press(Message::SortBy(id, index))
                .padding(0)
                .width(Length::FillPortion(state.portion(index, column)))
                .clip(true)
                .style(move |_, status| iced::widget::button::Style {
                    background: None,
                    text_color: if matches!(status, button::Status::Hovered) {
                        p.accent
                    } else {
                        p.faint
                    },
                    ..iced::widget::button::Style::default()
                })
                .into()
        };
        r = r.push(cell);
        // The edge between this heading and the next, draggable. Two units
        // wide with padding either side, so it can be caught without covering
        // the heading it belongs to.
        if index + 1 < columns.len() {
            r = r.push(handle(id, index, width, portions, s));
        }
    }
    container(r)
        .padding([s.pad(space::TIGHT), s.pad(space::BASE)])
        .width(Length::Fill)
        .height(Length::Shrink)
        .style(move |_| iced::widget::container::Style {
            background: Some(p.surface.into()),
            border: iced::Border {
                color: p.border,
                width: 0.0,
                radius: 0.0.into(),
            },
            ..iced::widget::container::Style::default()
        })
        .into()
}

/// The draggable edge of one column.
///
/// A step per drag event rather than a pixel measurement: the toolkit reports
/// the cursor inside the widget, and turning that into a width needs the
/// widget's own position, which a stateless handle does not have. A step is
/// coarser and it is predictable, which matters more here.
fn handle<'a>(id: Id, index: usize, width: f32, portions: u16, s: Style) -> Element<'a, Message> {
    let p = s.palette;
    // Pixels become a share of the width here, because only the table knows
    // how wide it is and how many shares are in play. The widget reports
    // distance moved and nothing else.
    let per_portion = (width / f32::from(portions.max(1))).max(1.0);
    crate::divider::Divider::new(
        s.type_size(size::MICRO) + s.pad(space::TIGHT),
        p.border,
        p.accent,
        move |moved| Message::Drag(id, index, moved / per_portion),
    )
    .into()
}

/// The whole record behind one row, opened under it.
fn record<'a>(detail: &[(String, String)], s: Style) -> Element<'a, Message> {
    let p = s.palette;
    let mut lines = Column::new().spacing(s.pad(space::HAIR));
    for (label, value) in detail {
        if value.is_empty() {
            continue;
        }
        lines = lines.push(
            iced::widget::Row::new()
                .spacing(s.pad(space::BASE))
                .push(
                    text(label.clone())
                        .size(s.type_size(size::MICRO))
                        .color(p.faint)
                        .width(Length::Fixed(140.0)),
                )
                .push(
                    text(value.clone())
                        .size(s.type_size(size::MICRO))
                        .font(theme::MONO)
                        .color(p.text)
                        .width(Length::Fill),
                ),
        );
    }
    container(lines)
        .style(theme::region(Region::Panel, p))
        .padding(s.pad(space::BASE))
        .width(Length::Fill)
        .into()
}

/// Everything one row needs that is the same for every row in the table.
///
/// Nine arguments is a struct wearing a signature, and the compiler said so.
#[derive(Clone, Copy)]
struct Layout<'a> {
    /// Which table, so a row can report which one it was opened in.
    id: Id,
    /// The columns.
    columns: &'a [Column2],
    /// The sum of the widths in use, which the character budget divides by.
    portions: u16,
    /// The width the toolkit actually gave the table.
    width: f32,
    /// Colours and spacing.
    s: Style,
}

fn line<'a>(
    at: Layout<'a>,
    position: usize,
    state: &State,
    r: &Row,
    stripe: bool,
) -> Element<'a, Message> {
    let (id, columns, portions, width, s) = (at.id, at.columns, at.portions, at.width, at.s);
    let p = s.palette;
    // The gaps between columns and the row's own padding are not available to
    // text, so they come off before the share is worked out.
    // Each gap is the row spacing twice over plus the six units the column
    // handle occupies, none of which is available to text.
    let between = u16::try_from(columns.len().saturating_sub(1)).unwrap_or(u16::MAX);
    let gaps = (s.pad(space::SNUG) * 2.0 + 5.0) * f32::from(between);
    let marker_width = if r.marker.is_some() { 7.0 } else { 0.0 };
    let usable = (width - gaps - s.pad(space::BASE) * 2.0 - marker_width).max(0.0);
    let mut content = iced::widget::Row::new()
        .spacing(s.pad(space::SNUG))
        .align_y(iced::Alignment::Center);
    if let Some(marker) = r.marker {
        content = content.push(
            container(iced::widget::space())
                .width(Length::Fixed(3.0))
                .height(Length::Fixed(s.row_height() - s.pad(space::SNUG)))
                .style(move |_| iced::widget::container::Style {
                    background: Some(marker.into()),
                    ..iced::widget::container::Style::default()
                }),
        );
    }
    // A row that holds a record says so with a marker, so the record is
    // something a reader finds rather than discovers by clicking.
    if !r.detail.is_empty() {
        let open = state.opened.contains(&position);
        content = content.push(
            text(if open { "\u{25be}" } else { "\u{25b8}" })
                .size(s.type_size(size::MICRO))
                .color(if open {
                    s.palette.accent
                } else {
                    s.palette.faint
                })
                .width(Length::Fixed(10.0)),
        );
    }

    for (index, column) in columns.iter().enumerate() {
        let cell = r.cells.get(index).cloned().unwrap_or_default();
        let portion = state.portion(index, column);
        let share = usable * f32::from(portion) / f32::from(portions.max(1));
        let font = s.type_size(if column.mono { size::MICRO } else { size::BODY });
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let limit = (share / (font * CHAR_WIDTH)).floor().max(0.0) as usize;
        let shown = shorten(&cell.value, limit, column.mono);
        let truncated = shown != cell.value;
        // Never wrap. Truncation decides what a cell shows; wrapping decides
        // it for us, and one long value used to take nine lines and destroy
        // the layout of every row beneath it.
        let mut label = text(shown.clone())
            .wrapping(iced::widget::text::Wrapping::None)
            .size(s.type_size(if column.mono { size::MICRO } else { size::BODY }))
            .color(
                cell.colour
                    .unwrap_or(if index == 0 { p.text } else { p.muted }),
            )
            .align_x(match column.align {
                Align::Left => iced::alignment::Horizontal::Left,
                Align::Right => iced::alignment::Horizontal::Right,
            })
            .width(Length::Fill);
        if column.mono {
            label = label.font(theme::MONO);
        }

        content = content.push(cell_view(&cell, label, portion, truncated, s));
        if index + 1 < columns.len() {
            content = content.push(iced::widget::space().width(Length::Fixed(5.0)));
        }
    }

    let selected = r.selected;
    let state_opened = state.opened.contains(&position);
    let inner = container(content)
        .height(Length::Fixed(s.row_height()))
        .padding([0.0, s.pad(space::BASE)])
        .width(Length::Fill)
        .clip(true);

    let press = r
        .select
        .map(Message::Select)
        .or_else(|| (!r.detail.is_empty()).then_some(Message::OpenRow(id, position)));
    match press {
        Some(message) => button(inner)
            .on_press(message)
            .padding(0)
            .width(Length::Fill)
            .style(move |_, status| iced::widget::button::Style {
                background: Some(background(
                    selected || state_opened,
                    matches!(status, button::Status::Hovered),
                    stripe,
                    p,
                )),
                text_color: p.text,
                ..iced::widget::button::Style::default()
            })
            .into(),
        None => inner
            .style(move |_| iced::widget::container::Style {
                background: Some(background(selected, false, stripe, p)),
                text_color: Some(p.text),
                ..iced::widget::container::Style::default()
            })
            .into(),
    }
}

/// One cell, as a control.
///
/// Its own function because a cell does four things: draw, truncate, copy, and
/// reveal, and a hundred-line loop body hides which of them went wrong.
fn cell_view<'a>(
    cell: &Cell,
    label: iced::widget::Text<'a, iced::Theme, iced::Renderer>,
    portion: u16,
    truncated: bool,
    s: Style,
) -> Element<'a, Message> {
    let p = s.palette;
    let value = cell.value.clone();
    // A cell that does not name a file copies on both buttons rather than
    // doing nothing on one of them.
    let secondary = if cell.is_path {
        Message::Reveal(value.clone())
    } else {
        Message::Copy(value.clone())
    };
    let hint = if cell.is_path {
        "Click copies · right-click reveals in the file browser"
    } else {
        "Click copies"
    };
    let control: Element<'a, Message> = iced::widget::mouse_area(
        container(label)
            .width(Length::FillPortion(portion))
            .clip(true),
    )
    .on_press(Message::Copy(value))
    .on_right_press(secondary)
    .interaction(iced::mouse::Interaction::Copy)
    .into();

    if !truncated {
        return control;
    }

    tooltip(
        control,
        container(
            Column::new()
                .spacing(s.pad(space::HAIR))
                .push(
                    text(cell.value.clone())
                        .size(s.type_size(size::MICRO))
                        .font(theme::MONO)
                        .wrapping(iced::widget::text::Wrapping::WordOrGlyph)
                        .width(Length::Fixed(420.0)),
                )
                .push(text(hint).size(s.type_size(size::MICRO)).color(p.faint)),
        )
        .style(theme::region(Region::Tooltip, p))
        .padding(s.pad(space::SNUG)),
        tooltip::Position::FollowCursor,
    )
    .delay(std::time::Duration::from_millis(450))
    .gap(s.pad(space::SNUG))
    .padding(s.pad(space::SNUG))
    .into()
}

fn background(selected: bool, hovered: bool, stripe: bool, p: theme::Palette) -> iced::Background {
    if selected {
        p.selection().into()
    } else if hovered {
        p.hover().into()
    } else if stripe {
        p.stripe().into()
    } else {
        iced::Color::TRANSPARENT.into()
    }
}

/// Shorten a value to fit, keeping the part that identifies it.
///
/// A bare path keeps its tail: `/Applications/…/Google Chrome` identifies it
/// and `/Applications/Google Chrome.app/Contents/…` does not.
///
/// Everything else keeps its head. A command line is a path followed by
/// arguments, and three invocations of the same program differ at the front,
/// not at the end: keeping the tail of those made three different commands
/// print as three identical rows. Prose is read from the front for the same
/// reason.
#[must_use]
pub fn shorten(value: &str, limit: usize, path_column: bool) -> String {
    let count = value.chars().count();
    if count <= limit || limit < 6 {
        return value.to_owned();
    }
    let chars: Vec<char> = value.chars().collect();
    let keep = limit - 1;
    let one_path = path_column && !value.contains(' ');
    if one_path {
        let tail = keep * 2 / 3;
        let head = keep - tail;
        let mut out: String = chars.iter().take(head).collect();
        out.push('\u{2026}');
        out.extend(chars.iter().skip(count - tail));
        out
    } else {
        let mut out: String = chars.iter().take(keep).collect();
        out.push('\u{2026}');
        out
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::expect_used)]

    use super::*;

    #[test]
    fn a_command_line_keeps_its_head_because_that_is_where_two_of_them_differ() {
        let long = "'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' \
                    --headless=new --screenshot=/private/tmp/shot2.png";
        let short = shorten(long, 60, true);
        assert!(
            short.chars().count() <= 60,
            "{} is still too long",
            short.chars().count()
        );
        assert!(short.starts_with("'/Applications/Google Chrome"), "{short}");
        assert!(short.ends_with('\u{2026}'), "{short}");
    }

    #[test]
    fn a_bare_path_keeps_its_tail_because_that_is_the_part_that_names_it() {
        let long = "/Applications/VisualStudioCode.app/Contents/Frameworks/CodeHelperPlugin";
        let short = shorten(long, 40, true);
        assert!(short.chars().count() <= 40);
        assert!(short.ends_with("CodeHelperPlugin"), "{short}");
    }

    #[test]
    fn a_value_that_fits_is_left_exactly_as_it_is() {
        assert_eq!(shorten("~/.ssh/id_rsa", 40, true), "~/.ssh/id_rsa");
    }

    #[test]
    fn prose_keeps_its_head_because_that_is_where_it_is_read_from() {
        let short = shorten(
            "Can execute arbitrary processes and reach a credential",
            20,
            false,
        );
        assert!(short.starts_with("Can execute"), "{short}");
        assert!(short.ends_with('\u{2026}'));
    }

    #[test]
    fn shortening_never_splits_a_character() {
        // A byte-wise truncation panics here. Paths on this machine contain
        // characters that are not one byte.
        let short = shorten("/Users/…/Приложения/Ünïcödé/файл.json", 20, true);
        assert!(short.chars().count() <= 20);
    }

    #[test]
    fn a_grade_column_sorts_by_its_number_not_by_its_text() {
        let mut rows = vec![
            Row::new(vec![Cell::new("CRITICAL 81")]),
            Row::new(vec![Cell::new("CRITICAL 100")]),
            Row::new(vec![Cell::new("LOW 0")]),
        ];
        sort_rows(
            &mut rows,
            Sort {
                column: 0,
                ascending: false,
            },
            Sorts::Number,
        );
        let order: Vec<&str> = rows.iter().map(|r| r.cells[0].value.as_str()).collect();
        assert_eq!(
            order,
            ["CRITICAL 100", "CRITICAL 81", "LOW 0"],
            "text ordering puts 100 below 81"
        );
    }

    #[test]
    fn a_cell_with_no_number_sorts_to_the_bottom_rather_than_the_top() {
        let mut rows = vec![
            Row::new(vec![Cell::new("-")]),
            Row::new(vec![Cell::new("7")]),
        ];
        sort_rows(
            &mut rows,
            Sort {
                column: 0,
                ascending: false,
            },
            Sorts::Number,
        );
        assert_eq!(rows[0].cells[0].value, "7");
    }

    /// A slow drag has to move the edge. Rounding each step to a whole share
    /// and discarding the remainder meant small movements did nothing at all,
    /// which is what a press-to-step control already did badly.
    #[test]
    fn a_slow_drag_accumulates_instead_of_being_rounded_away() {
        let column = Column2::text("AGENT", 4);
        let mut state = State::default();
        for _ in 0..10 {
            state.drag(0, &column, 0.2);
        }
        assert_eq!(
            state.portion(0, &column),
            6,
            "ten steps of a fifth is two shares"
        );
    }

    #[test]
    fn a_column_cannot_be_dragged_to_nothing() {
        let column = Column2::text("AGENT", 4);
        let mut state = State::default();
        for _ in 0..50 {
            state.drag(0, &column, -1.0);
        }
        assert!(
            state.portion(0, &column) >= 1,
            "an edge dragged away cannot be found again"
        );
    }

    #[test]
    fn search_matches_any_cell_and_ignores_case() {
        let r = Row::new(vec![
            Cell::new("claude-code"),
            Cell::new("/Users/x/.local/bin/claude"),
        ]);
        assert!(r.matches("local/bin"));
        assert!(r.matches("claude-code"));
        assert!(!r.matches("codex"));
    }
}
