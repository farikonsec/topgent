//! The Topgent desktop interface.
//!
//! A projection of one report and nothing else. The core produces a `Value`
//! from `topgent_report::scan()`; this crate turns it into a window. It holds
//! no security logic, reaches no sensor, and decides nothing: a bug here can
//! make Topgent illegible but cannot make it wrong.
//!
//! Drawn natively rather than in a webview. A browser engine embedded to render
//! a security tool's output is a large attack surface for no benefit, and on
//! Linux it pulls in a webkit2gtk stack whose Rust bindings ended in 2024 with
//! thirteen open advisories. See `docs/INTERFACE-REWRITE-PLAN.md`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
// Every drawing function returns a widget tree and has no other effect, so
// `must_use` on each is noise: the whole library is that shape. Nothing here
// is discarded by accident, because a discarded widget does not appear.
#![allow(clippy::must_use_candidate)]

pub mod agents;
pub mod alarm;
pub mod clock;
pub mod compact;
pub mod divider;
pub mod glyph;
pub mod ownership;
pub mod panels;
pub mod report;
pub mod settings;
pub mod table;
pub mod theme;

use theme::{Region, space};

use iced::widget::{column, container, pane_grid, row, stack};
use iced::{Element, Length, Subscription, Task};

/// Hand a link to whatever the reader uses for links.
///
/// The interface never fetches anything itself. Opening a browser is the
/// operating system's job, and a monitor that made its own request would have
/// a reason to be talking to a server.
fn open(url: &str) {
    #[cfg(target_os = "macos")]
    let mut command = std::process::Command::new("open");
    #[cfg(target_os = "linux")]
    let mut command = std::process::Command::new("xdg-open");
    #[cfg(windows)]
    let mut command = {
        let mut c = std::process::Command::new("cmd");
        c.args(["/C", "start", ""]);
        c
    };
    // Only the two links this interface owns. A URL from anywhere else is not
    // handed to the shell, whatever a report may contain.
    if url == agents::REPOSITORY || url == agents::AUTHOR {
        let _ = command.arg(url).spawn();
    }
}

/// Show a path in the platform's file browser, selected but not opened.
fn reveal(path: &str) {
    let target = std::path::Path::new(path);
    // Only a path that exists, and only as an argument. Nothing is
    // interpolated into a shell, and a value that is not a real file on this
    // machine is not handed to anything.
    if !target.exists() {
        return;
    }
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut c = std::process::Command::new("open");
        c.arg("-R");
        c
    };
    #[cfg(target_os = "linux")]
    let mut command = std::process::Command::new("xdg-open");
    #[cfg(windows)]
    let mut command = {
        let mut c = std::process::Command::new("explorer");
        c.arg("/select,");
        c
    };
    #[cfg(target_os = "linux")]
    let target = target.parent().unwrap_or(target);
    let _ = command.arg(target).spawn();
}

/// Give the window the size and stacking its mode calls for.
///
/// Always on top only while small. A full window pinned over everything else
/// is a window someone closes.
fn shape(compact: bool, restore: iced::Size) -> Task<Message> {
    let (size, level) = if compact {
        (compact::SIZE, iced::window::Level::AlwaysOnTop)
    } else {
        (restore, iced::window::Level::Normal)
    };
    iced::window::latest().and_then(move |id| {
        Task::batch([
            iced::window::resize(id, size),
            iced::window::set_level(id, level),
        ])
    })
}

/// The size the large window opens at.
const WINDOW: iced::Size = iced::Size {
    width: 1320.0,
    height: 860.0,
};

/// Everything the window draws from.
pub struct App {
    /// The most recent report, or `None` before the first sweep returns.
    report: Option<report::Report>,
    /// The agent the detail panels follow.
    selected: Option<u32>,
    /// Whether a sweep is outstanding.
    sweeping: bool,
    /// What went wrong, if the last sweep failed.
    error: Option<String>,
    /// Which detail panel is showing.
    panel: panels::Panel,
    /// How this looks, as the reader chose it.
    settings: settings::Settings,
    /// Whether the settings panel is over the interface.
    settings_open: bool,
    /// Where the divider between the agent table and the detail panel sits.
    ///
    /// Held rather than fixed, because how much of the window each deserves
    /// depends on how many agents are running, and only the reader knows.
    split: pane_grid::State<Pane>,
    /// Whether the window is the small always-on-top one.
    compact: bool,
    /// The size the large window had, so leaving compact mode restores it
    /// rather than guessing.
    restore: iced::Size,
    /// How each table is sorted and searched, so a panel stays where the
    /// reader left it when the next sweep replaces the data underneath.
    tables: std::collections::HashMap<table::Id, table::State>,
    /// When the last sweep returned.
    swept_at: Option<u64>,
    /// The grade each agent was at when it was last notified about, so a
    /// finding that has not changed does not raise a notification every sweep.
    raised: std::collections::HashMap<u32, String>,
    /// The rule being composed in the response panel.
    draft: Draft,
    /// The agent a stop has been asked for but not yet confirmed.
    stopping: Option<u32>,
    /// The most recent operator-facing outcome. It occupies a fixed footer
    /// slot and is cleared when the operator moves on to another action.
    status: Option<String>,
}

/// The two halves of the content area.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pane {
    /// Every agent found.
    Agents,
    /// Whichever detail panel is chosen.
    Detail,
}

impl Pane {
    /// The layout as it opens, and as the reset control restores it.
    ///
    /// Slightly more than half to the table, because the first question is
    /// always what is running and only then why.
    fn layout() -> pane_grid::State<Self> {
        let (mut state, first) = pane_grid::State::new(Self::Agents);
        let split = state.split(pane_grid::Axis::Horizontal, first, Self::Detail);
        if let Some((_, split)) = split {
            state.resize(split, 0.55);
        }
        state
    }
}

/// A watchlist rule being composed.
///
/// Held in the application rather than the panel, because a panel redrawn on
/// every sweep cannot hold what someone is halfway through typing.
#[derive(Debug, Clone)]
pub struct Draft {
    /// The substring to match against a resource path.
    pub path: String,
    /// When it applies.
    pub condition: &'static str,
    /// What it is worth.
    pub severity: &'static str,
}

impl Default for Draft {
    fn default() -> Self {
        Self {
            path: String::new(),
            condition: "reachable",
            severity: "critical",
        }
    }
}

/// Everything that can happen.
#[derive(Debug, Clone)]
pub enum Message {
    /// A sweep should start.
    Sweep,
    /// A sweep finished. Boxed because a report is large and every other
    /// message is a word or two; without the box the whole enum is sized for
    /// the biggest variant and copied at that size on every click.
    Swept(Box<Result<report::Report, String>>),
    /// A row was chosen.
    Select(u32),
    /// A detail panel was chosen.
    Show(panels::Panel),
    /// A column heading was clicked. Clicking the ordering column again
    /// reverses it rather than reordering by the same key.
    SortBy(table::Id, usize),
    /// A table's search box changed.
    Search(table::Id, String),
    /// A column edge was dragged, by a share of the table's width.
    Drag(table::Id, usize, f32),
    /// A row was opened or closed, by its position after sorting.
    OpenRow(table::Id, usize),
    /// The settings panel was opened or closed.
    ToggleSettings,
    /// The window should become the small one, or stop being it.
    ToggleCompact,
    /// The divider between the table and the panel was dragged.
    Split(pane_grid::ResizeEvent),
    /// The divider should go back where it started.
    ResetSplit,
    /// A theme was chosen.
    SetAppearance(theme::Appearance),
    /// A density was chosen.
    SetDensity(theme::Density),
    /// The scale slider moved.
    SetScale(f32),
    /// A refresh interval was chosen, `0` for paused.
    SetRefresh(u64),
    /// Stop was pressed. Nothing has been signalled yet.
    AskStop(u32),
    /// The confirmation was dismissed.
    CancelStop,
    /// The confirmation was accepted.
    ConfirmStop(u32),
    /// A stop attempt returned.
    Stopped(String),
    /// Notifications were turned on or off.
    SetNotify(bool),
    /// The sound was turned on or off.
    SetSound(bool),
    /// A rule's response mode was chosen.
    SetRuleResponse(usize, &'static str),
    /// The new-rule path box changed.
    RulePath(String),
    /// The new-rule condition was chosen.
    RuleCondition(&'static str),
    /// The new-rule severity was chosen.
    RuleSeverity(&'static str),
    /// The new rule should be added.
    AddRule,
    /// A rule should be removed.
    RemoveRule(usize),
    /// An asset's disposition was chosen.
    SetDisposition(String, &'static str),
    /// A rule change returned.
    RuleChanged(String),
    /// A link should open in the reader's own browser.
    Open(String),
    /// A cell's value should go to the clipboard.
    Copy(String),
    /// A path should be shown where the reader keeps their files.
    Reveal(String),
    /// This session should be written to a file.
    Export(bool),
    /// Something finished and there is nothing to change.
    Noop,
}

/// Whether a new operator gesture makes the previous footer outcome stale.
fn clears_status(message: &Message) -> bool {
    matches!(
        message,
        Message::Select(..)
            | Message::Show(..)
            | Message::SortBy(..)
            | Message::Search(..)
            | Message::Drag(..)
            | Message::OpenRow(..)
            | Message::ToggleSettings
            | Message::ToggleCompact
            | Message::ResetSplit
            | Message::SetAppearance(..)
            | Message::SetDensity(..)
            | Message::SetScale(..)
            | Message::SetRefresh(..)
            | Message::SetNotify(..)
            | Message::SetSound(..)
            | Message::AskStop(..)
            | Message::CancelStop
            | Message::RulePath(..)
            | Message::RuleCondition(..)
            | Message::RuleSeverity(..)
    )
}

impl App {
    fn new() -> (Self, Task<Message>) {
        let app = Self {
            report: None,
            selected: None,
            sweeping: false,
            error: None,
            panel: panels::Panel::default(),
            tables: std::collections::HashMap::new(),
            swept_at: None,
            draft: Draft::default(),
            raised: std::collections::HashMap::new(),
            settings: settings::Settings::load(),
            settings_open: false,
            split: Pane::layout(),
            compact: false,
            restore: WINDOW,
            stopping: None,
            status: None,
        };
        // The window's shape follows the state rather than only the toggle, so
        // starting compact starts small. A mode that only takes effect when
        // something is pressed is a mode that is wrong the first time it is
        // seen.
        let shaping = shape(app.compact, app.restore);
        (app, Task::batch([Task::done(Message::Sweep), shaping]))
    }

    fn title(&self) -> String {
        match &self.report {
            Some(r) => format!("Topgent {} — {} agents", r.version, r.agents.len()),
            None => "Topgent".to_owned(),
        }
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        // Feedback is contextual, not a permanent part of the interface. It
        // survives long enough to be read, then yields as soon as the reader
        // starts another interaction. Keeping it in the footer prevents both
        // stale notices and the layout jump caused by inserting a new row.
        if clears_status(&message) {
            self.status = None;
        }

        match message {
            // A sweep is never joined by a second one. The guard is here rather
            // than in a timer because the timer cannot know a sweep is still
            // running, and on a slow host the subprocesses accumulate.
            Message::Sweep if self.sweeping => Task::none(),
            Message::Sweep => {
                self.sweeping = true;
                Task::perform(report::sweep(), |r| Message::Swept(Box::new(r)))
            }
            Message::Swept(result) => {
                self.sweeping = false;
                match *result {
                    Ok(report) => {
                        if !report.agents.iter().any(|a| Some(a.pid) == self.selected) {
                            self.selected = report.worst().map(|a| a.pid);
                        }
                        self.swept_at = Some(report.generated_at);
                        self.announce(&report);
                        self.report = Some(report);
                        self.error = None;
                    }
                    Err(why) => self.error = Some(why),
                }
                Task::none()
            }
            Message::Select(pid) => {
                self.selected = Some(pid);
                Task::none()
            }
            Message::Show(panel) => {
                self.panel = panel;
                Task::none()
            }
            Message::ToggleSettings => {
                self.settings_open = !self.settings_open;
                Task::none()
            }
            Message::Split(pane_grid::ResizeEvent { split, ratio }) => {
                // Clamped, because a divider dragged to the edge leaves one
                // half with no height and no edge left to drag back.
                self.split.resize(split, ratio.clamp(0.15, 0.85));
                Task::none()
            }
            Message::ResetSplit => {
                self.split = Pane::layout();
                Task::none()
            }
            Message::ToggleCompact => {
                self.compact = !self.compact;
                self.settings_open = false;
                shape(self.compact, self.restore)
            }
            Message::SortBy(..)
            | Message::Search(..)
            | Message::Drag(..)
            | Message::OpenRow(..) => self.arrange(message),
            Message::SetAppearance(appearance) => self.settle(|c| c.appearance = appearance),
            Message::SetDensity(density) => self.settle(|c| c.density = density),
            Message::SetScale(scale) => self.settle(|c| c.scale = scale),
            Message::SetRefresh(ms) => self.settle(|c| c.refresh_ms = ms),
            Message::SetSound(on) => self.settle(|c| c.sound = on),
            Message::AskStop(pid) => {
                self.stopping = Some(pid);
                Task::none()
            }
            Message::CancelStop => {
                self.stopping = None;
                Task::none()
            }
            // The signal itself happens off the drawing thread. It takes a
            // process snapshot and can block, and a window that freezes while
            // it stops something looks exactly like one that has crashed
            // during it.
            Message::ConfirmStop(pid) => {
                self.stopping = None;
                Task::perform(report::stop(pid), Message::Stopped)
            }
            Message::Stopped(outcome) | Message::RuleChanged(outcome) => {
                self.status = Some(outcome);
                Task::done(Message::Sweep)
            }
            Message::SetNotify(on) => self.set_notify(on),
            Message::SetRuleResponse(index, mode) => {
                Task::perform(report::set_rule_response(index, mode), Message::RuleChanged)
            }
            Message::RulePath(_)
            | Message::RuleCondition(_)
            | Message::RuleSeverity(_)
            | Message::AddRule
            | Message::RemoveRule(_)
            | Message::SetDisposition(..) => self.policy(message),
            Message::Open(_) | Message::Copy(_) | Message::Reveal(_) => self.hand_off(message),
            Message::Export(redacted) => {
                self.settings_open = false;
                self.status = Some("writing this session to a file...".to_owned());
                Task::perform(report::export_session(redacted), Message::RuleChanged)
            }
            Message::Noop => Task::none(),
        }
    }

    fn view(&self) -> Element<'_, Message> {
        let s = self.settings.style();
        if self.compact {
            return compact::view(self.report.as_ref(), self.sweeping, s);
        }
        let agent = self
            .selected
            .and_then(|pid| self.report.as_ref()?.agents.iter().find(|a| a.pid == pid));

        let body: Element<'_, Message> = match (&self.report, &self.error) {
            (_, Some(why)) => theme::notice(why.clone(), s.palette),
            (None, None) => theme::notice("Looking at this machine for the first time.", s.palette),
            // The table takes the height its rows need, up to half the window,
            // and the panel takes the rest. A fixed split left a short table
            // with a hole under it and would have squeezed a long one.
            (Some(report), None) => {
                let selected = self.selected;
                let panel = self.panel;
                let tables = &self.tables;
                let draft = &self.draft;
                let grid = pane_grid(&self.split, move |_, pane, _| {
                    let content: Element<'_, Message> = match pane {
                        Pane::Agents => agents::table(report, selected, tables, s),
                        Pane::Detail => {
                            let selected_agent = selected
                                .and_then(|pid| report.agents.iter().find(|a| a.pid == pid));
                            let evidence = container(column![
                                panels::heading(panel, selected_agent, s),
                                panels::view(panel, report, selected, tables, draft, s),
                            ])
                            .style(theme::region(Region::Panel, s.palette))
                            .height(Length::Fill)
                            .width(Length::Fill);
                            // Navigation controls the active evidence view, so
                            // it belongs beside that view—not beside the agent
                            // table and not in a permanent full-height gutter.
                            row![panels::sidebar(panel, Some(report), s), evidence]
                                .spacing(s.pad(space::BASE))
                                .align_y(iced::Alignment::Start)
                                .into()
                        }
                    };
                    pane_grid::Content::new(content)
                })
                .spacing(s.pad(space::SNUG))
                // The divider is draggable, with leeway so it can be caught
                // without hitting one pixel exactly.
                .on_resize(8, Message::Split);

                grid.into()
            }
        };

        let mut window = column![agents::header(
            self.report.as_ref(),
            self.sweeping,
            self.swept_at,
            s
        )]
        .spacing(s.pad(space::SNUG));
        window = window.push(body);
        if let Some(agent) = agent.filter(|_| self.report.is_some() && self.error.is_none()) {
            window = window.push(agents::detail(agent, s));
        }
        window = window.push(agents::footer(
            self.report.as_ref().map_or("", |r| r.version.as_str()),
            self.status.as_deref(),
            s,
        ));

        let base = container(window)
            .style(theme::region(Region::Window, s.palette))
            .padding([s.pad(space::SNUG), s.pad(space::BASE)])
            .width(Length::Fill)
            .height(Length::Fill);

        // Both overlays are drawn over the interface rather than replacing it,
        // so the reader can still see what they were looking at when they
        // asked for the dialog.
        let mut layers = stack![base];
        if let Some(pid) = self.stopping {
            layers = layers.push(agents::confirm_stop(pid, agent, s));
        } else if self.settings_open {
            layers = layers.push(settings::panel(self.settings, s));
        }
        layers.into()
    }

    /// Turn notifications on or off.
    ///
    /// Turning them on raises one immediately, so the reader finds out whether
    /// this machine's notification centre will actually show one before they
    /// need it to. A switch that silently does nothing is the defect this
    /// whole feature exists to fix.
    fn set_notify(&mut self, on: bool) -> Task<Message> {
        let _ = self.settle(|c| c.notify = on);
        if !on {
            return Task::none();
        }
        let alarm = alarm::Alarm {
            agent: "Topgent".to_owned(),
            grade: "TEST".to_owned(),
            finding: "notifications are on".to_owned(),
        };
        let sound = self.settings.sound;
        Task::future(async move {
            let _ = tokio::task::spawn_blocking(move || alarm::raise(&alarm, sound)).await;
            Message::Noop
        })
    }

    /// Everything that changes how a table is arranged.
    ///
    /// Sort, search, column width, and which rows are open. All four live per
    /// table so a panel stays where the reader left it when the next sweep
    /// replaces the data underneath.
    fn arrange(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::SortBy(id, column) => {
                let state = self.tables.entry(id).or_default();
                state.opened.clear();
                state.sort = match state.sort {
                    Some(current) if current.column == column => Some(table::Sort {
                        column,
                        ascending: !current.ascending,
                    }),
                    // A new column starts descending: the reason to sort a
                    // security table is almost always to bring the worst to
                    // the top.
                    _ => Some(table::Sort {
                        column,
                        ascending: false,
                    }),
                };
            }
            Message::Search(id, needle) => {
                let state = self.tables.entry(id).or_default();
                state.search = needle;
                // Open rows are remembered by position, and a search changes
                // what each position holds. Leaving them open would open a
                // record belonging to a different row.
                state.opened.clear();
            }
            Message::OpenRow(id, position) => {
                let state = self.tables.entry(id).or_default();
                if !state.opened.remove(&position) {
                    state.opened.insert(position);
                }
            }
            Message::Drag(id, column, by) => {
                if let Some(spec) = panels::columns_of(id).get(column) {
                    self.tables.entry(id).or_default().drag(column, spec, by);
                }
            }
            _ => {}
        }
        Task::none()
    }

    /// Everything that hands a value to something outside this window.
    ///
    /// The clipboard, the browser, and the file manager. None of them fetches
    /// anything, and each is given a value this interface already had.
    fn hand_off(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Open(url) => {
                open(&url);
                Task::none()
            }
            Message::Copy(value) => {
                self.status = Some(format!("copied: {}", table::shorten(&value, 90, true)));
                iced::clipboard::write(value)
            }
            // The path is shown, not opened. Topgent tells an operator where a
            // file is; deciding to open it is theirs, and a monitor that
            // launches files it discovered can be made to launch one an
            // attacker planted.
            Message::Reveal(path) => {
                reveal(&path);
                Task::none()
            }
            _ => Task::none(),
        }
    }

    /// Everything that edits the policy on this machine.
    ///
    /// Grouped because they are one kind of thing: each writes a file, each is
    /// run off the drawing thread, and each reports what the core said rather
    /// than assuming it worked.
    fn policy(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::RulePath(path) => {
                self.draft.path = path;
                Task::none()
            }
            Message::RuleCondition(condition) => {
                self.draft.condition = condition;
                Task::none()
            }
            Message::RuleSeverity(severity) => {
                self.draft.severity = severity;
                Task::none()
            }
            // An empty path would match every resource on the machine. The
            // core trims it but does not refuse it, so the interface must.
            Message::AddRule if self.draft.path.trim().is_empty() => {
                self.status = Some("a rule needs a path to watch".to_owned());
                Task::none()
            }
            Message::AddRule => {
                let draft = std::mem::take(&mut self.draft);
                Task::perform(
                    report::add_rule(draft.path, draft.condition, draft.severity),
                    Message::RuleChanged,
                )
            }
            Message::RemoveRule(index) => {
                Task::perform(report::remove_rule(index), Message::RuleChanged)
            }
            Message::SetDisposition(id, disposition) => Task::perform(
                report::set_asset_disposition(id, disposition),
                Message::RuleChanged,
            ),
            _ => Task::none(),
        }
    }

    /// Change one setting and write it out.
    ///
    /// Every setting is stored the same way, so there is one place that saves
    /// rather than four that could each forget to.
    fn settle(&mut self, change: impl FnOnce(&mut settings::Settings)) -> Task<Message> {
        change(&mut self.settings);
        self.settings.save();
        Task::none()
    }

    /// Notify about anything that got worse since the last sweep.
    ///
    /// Keyed on the grade an agent was last raised at, so a finding that has
    /// not changed does not interrupt anyone every few seconds. An agent that
    /// improves is forgotten, so that if it gets worse again it says so.
    fn announce(&mut self, report: &report::Report) {
        if !self.settings.notify {
            return;
        }
        let sound = self.settings.sound;
        for agent in &report.agents {
            if !alarm::worth_raising(&agent.grade) {
                self.raised.remove(&agent.pid);
                continue;
            }
            if self.raised.get(&agent.pid) == Some(&agent.grade) {
                continue;
            }
            self.raised.insert(agent.pid, agent.grade.clone());
            let alarm = alarm::Alarm {
                agent: agent.label(),
                grade: agent.grade.clone(),
                finding: agent
                    .factors
                    .iter()
                    .max_by_key(|f| f.points)
                    .map_or_else(|| "scored".to_owned(), |f| f.title.clone()),
            };
            // Off the drawing thread: raising a notification spawns a process
            // and blocks, and the window must not stop while it does.
            std::thread::spawn(move || alarm::raise(&alarm, sound));
        }
    }

    fn theme(&self) -> iced::Theme {
        self.settings.appearance.toolkit()
    }

    /// Sweeps stop entirely while a stop is waiting on an answer. A report
    /// arriving mid-dialog can change the row under the pid being confirmed.
    fn subscription(&self) -> Subscription<Message> {
        if self.settings.refresh_ms == 0 || self.stopping.is_some() {
            return Subscription::none();
        }
        iced::time::every(std::time::Duration::from_millis(self.settings.refresh_ms))
            .map(|_| Message::Sweep)
    }
}

/// Open the window.
///
/// The binary is a shim over this, so the crate is a library first: a fuzz
/// target cannot link to a binary, and the parsers in here read a compiled
/// address table, a settings file anyone can edit, and a report.
/// # Errors
///
/// Whatever the toolkit could not do: no display, no graphics adapter, or a
/// window the platform refused to create.
pub fn run() -> iced::Result {
    iced::application(App::new, App::update, App::view)
        .title(App::title)
        .subscription(App::subscription)
        .theme(App::theme)
        // Loaded before the first frame, so nothing is ever drawn in a
        // fallback face and then reflowed once the real one arrives.
        .font(theme::face::BODY)
        .font(theme::face::STRONG)
        .font(theme::face::CODE)
        .default_font(theme::TEXT)
        .window(iced::window::Settings {
            icon: icon(),
            ..iced::window::Settings::default()
        })
        // Six columns of table beside a detail panel do not fit in a small
        // window, and a window that opens too small to read is one every
        // reader has to resize before they can use it once.
        .window_size(WINDOW)
        .run()
}

/// The window icon, decoded at build time.
///
/// `None` rather than a failure: a monitor that refuses to start because it
/// could not draw its own icon is worse than one that starts without it.
fn icon() -> Option<iced::window::Icon> {
    const PIXELS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/icon.rgba"));
    const SIZE: &str = include_str!(concat!(env!("OUT_DIR"), "/icon-size.txt"));
    let (width, height) = SIZE.split_once(',')?;
    iced::window::icon::from_rgba(PIXELS.to_vec(), width.parse().ok()?, height.parse().ok()?).ok()
}
