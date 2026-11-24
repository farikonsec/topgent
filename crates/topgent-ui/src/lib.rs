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
pub mod brand;
mod capture;
pub mod clock;
pub mod compact;
pub mod divider;
pub mod glyph;
pub mod incidents;
pub mod overview;
pub mod panels;
pub mod report;
pub mod session;
pub mod settings;
pub mod shell;
pub mod table;
pub mod theme;

use shell::Workspace;
use theme::{Region, Style, space};

use iced::widget::{column, container, row, stack, text};
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
    if url == shell::REPOSITORY || url == shell::AUTHOR {
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
fn shape(
    compact: bool,
    restore: iced::Size,
    confirming_stop: bool,
    compact_size: iced::Size,
) -> Task<Message> {
    let (size, level) = if compact {
        (
            if confirming_stop {
                compact::CONFIRM_SIZE
            } else {
                compact_size
            },
            iced::window::Level::AlwaysOnTop,
        )
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
// Sized to fit the smallest screen this is likely to open on. 1320x860 is
// wider and taller than a 1280x768 display, and a window that opens past the
// right edge takes its rightmost control with it: the packet-capture button
// was drawn there, unreachable, and read as missing. iced gives an application
// no monitor size to clamp against, so the default is chosen rather than
// computed.
const WINDOW: iced::Size = iced::Size {
    width: 1360.0,
    height: 840.0,
};

/// Which overlay, if any, is in front of the window.
///
/// One value rather than a flag per overlay: two of these cannot be open at
/// once, and separate booleans allow a state the interface has no drawing for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Overlay {
    /// Nothing is in front of the window.
    None,
    /// The deeper-visibility dialog.
    Capture,
    /// The question asked when the window is closed: save this session?
    /// `saving` while the save it asked for is under way.
    Closing { saving: bool },
}

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
    /// Which host-level workspace is showing.
    workspace: Workspace,
    /// Which evidence about the selected agent is showing.
    tab: agents::Tab,
    /// The program whose runs are open on the overview.
    program: Option<String>,
    /// Incidents whose evidence is open, by id. Held here so a sweep that
    /// redraws the page does not close what someone is reading.
    evidence_open: std::collections::BTreeSet<String>,
    /// What the agent list is filtered to.
    filter: String,
    /// Which agents the list is showing.
    scope: agents::Scope,
    /// Whether the selected agent's full record is open.
    inspecting: bool,
    /// How this looks, as the reader chose it.
    settings: settings::Settings,
    /// Which overlay is in front of the window, if any.
    ///
    /// One field rather than a flag each, because two overlays cannot both be
    /// open and two booleans allow exactly that. The old pair had an ordering in
    /// the draw code deciding which won, which is a rule that lived in one place
    /// and had to be remembered in every other.
    overlay: Overlay,
    /// The interval to go back to when a pause is lifted, so pausing and
    /// resuming returns the cadence the reader chose rather than a default
    /// they did not.
    resume_ms: u64,
    /// Whether the window is the small always-on-top one.
    compact: bool,
    /// The size the large window had, so leaving compact mode restores it
    /// rather than guessing.
    restore: iced::Size,
    /// Current full-window size, used to keep the evidence readable when the
    /// operator resizes the window or opens it on a smaller display.
    window_size: iced::Size,
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
    /// What the last event-log clear did, shown until the next one.
    events_notice: Option<String>,
    /// What the last grant attempt said, shown in the dialog.
    capture_outcome: Option<String>,
    /// The most recent operator-facing outcome. It occupies a fixed footer
    /// slot and is cleared when the operator moves on to another action.
    status: Option<String>,
    /// A saved session showing instead of the live host; sweeps are stopped.
    viewing: Option<session::Viewing>,
    /// Saved sessions, newest first, for the settings page.
    saved_sessions: Vec<(std::path::PathBuf, u64)>,
    /// Why the save asked for on closing failed, shown in its dialog.
    closing_outcome: Option<String>,
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
    /// A host-level workspace was chosen.
    Go(Workspace),
    /// A tab of the selected agent's evidence was chosen.
    ShowTab(agents::Tab),
    /// An agent was opened from the overview: the advanced view, on it.
    OpenAgent(u32),
    /// An incident's process was asked for: the advanced view, on the agent's
    /// Processes tab, with that process found and opened.
    ShowProcess(u32, u32),
    /// An incident's evidence was opened or closed, by incident id.
    ToggleEvidence(String),
    /// A program tile on the overview was opened, or `None` to close it.
    PickProgram(Option<String>),
    /// The simple view was chosen, or the advanced one.
    SetSimple(bool),
    /// The agent list's filter box changed.
    FilterAgents(String),
    /// The agent list's scope was chosen.
    SetScope(agents::Scope),
    /// The selected agent's full record was opened or closed.
    ToggleInspector,
    /// A column heading was clicked. Clicking the ordering column again
    /// reverses it rather than reordering by the same key.
    SortBy(table::Id, usize),
    /// A table's search box changed.
    Search(table::Id, String),
    /// A column edge was dragged, by a share of the table's width.
    Drag(table::Id, usize, f32),
    /// A row was opened or closed, by its position after sorting.
    OpenRow(table::Id, usize),
    /// The host-navigation edge moved by this many pixels.
    ResizeSidebar(f32),
    /// The agent-list edge moved by this many pixels.
    ResizeAgentList(f32),
    /// A pane drag ended; persist the settled dimensions once.
    SavePaneLayout,
    /// Fold or restore the host navigation.
    ToggleSidebar,
    /// Fold or restore the agent picker.
    ToggleAgentList,
    /// Return both panes to the product's usable defaults.
    ResetPaneLayout,
    /// The native window changed size.
    WindowResized(iced::Size),
    /// The window should become the small one, or stop being it.
    ToggleCompact,
    /// Sweeping should stop where it is, or start again.
    TogglePause,
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
    /// Set the event log aside and start a fresh one.
    ClearEvents,
    /// What clearing the event log did.
    EventsCleared(String),
    /// Open the deeper-visibility dialog.
    AskCapture,
    /// Close it without asking for anything.
    CancelCapture,
    /// Stop reading packets now. No password, immediate.
    StopCapture,
    /// Start reading packets again after it was stopped.
    StartCapture,
    /// Hand the capability back, through the operating system's own prompt.
    RevokeCapture,
    /// Ask the operating system for the capability, through its own prompt.
    GrantCapture,
    /// What the operating system answered, and whether capture is now available.
    CaptureGranted(bool, String),
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
    /// The window's close button was pressed: ask whether to save.
    CloseRequested,
    /// Save this session, then close.
    SaveAndClose,
    /// Close, and let this session go.
    CloseWithoutSaving,
    /// Do not close after all.
    CancelClose,
    /// The save asked for on closing finished.
    SavedForClose(Result<std::path::PathBuf, String>),
    /// Save this session now, and keep going.
    SaveNow,
    /// A save asked for from the settings page finished.
    SavedNow(Result<std::path::PathBuf, String>),
    /// Open a saved session to look at.
    OpenSaved(std::path::PathBuf),
    /// A saved session was read. Boxed, as a report is large.
    Opened(Result<Box<(report::Report, session::Viewing)>, String>),
    /// Leave the saved session and show the live host again.
    BackToLive,
    /// Something finished and there is nothing to change.
    Noop,
}

/// Whether a new operator gesture makes the previous footer outcome stale.
fn clears_status(message: &Message) -> bool {
    matches!(
        message,
        Message::Select(..)
            | Message::Go(..)
            | Message::OpenAgent(..)
            | Message::PickProgram(..)
            | Message::ShowProcess(..)
            | Message::ToggleEvidence(..)
            | Message::SetSimple(..)
            | Message::ShowTab(..)
            | Message::FilterAgents(..)
            | Message::SetScope(..)
            | Message::ToggleInspector
            | Message::SortBy(..)
            | Message::Search(..)
            | Message::Drag(..)
            | Message::OpenRow(..)
            | Message::ResizeSidebar(..)
            | Message::ResizeAgentList(..)
            | Message::SavePaneLayout
            | Message::ToggleSidebar
            | Message::ToggleAgentList
            | Message::ResetPaneLayout
            | Message::WindowResized(..)
            | Message::ToggleCompact
            | Message::TogglePause
            | Message::SetAppearance(..)
            | Message::SetDensity(..)
            | Message::SetScale(..)
            | Message::SetRefresh(..)
            | Message::SetNotify(..)
            | Message::SetSound(..)
            | Message::AskStop(..)
            | Message::CancelStop
            | Message::ClearEvents
            | Message::EventsCleared(..)
            | Message::StopCapture
            | Message::StartCapture
            | Message::RevokeCapture
            | Message::AskCapture
            | Message::CancelCapture
            | Message::GrantCapture
            | Message::CaptureGranted(..)
            | Message::RulePath(..)
            | Message::RuleCondition(..)
            | Message::RuleSeverity(..)
    )
}

impl App {
    fn new() -> (Self, Task<Message>) {
        let settings = {
            let loaded = settings::Settings::load();
            // Applied before the first sweep, so a capture somebody switched
            // off last time does not run for a few seconds before the
            // interface catches up with itself.
            if !loaded.capture {
                topgent_collect::capture::live::stop();
            }
            loaded
        };
        let mut app = Self {
            report: None,
            selected: None,
            sweeping: false,
            error: None,
            // Where the last session left off. A monitor is reopened to carry
            // on with something.
            // The simple view always opens on the overview: it is the page
            // that answers whether anything needs a decision.
            workspace: if settings.simple {
                Workspace::Overview
            } else {
                settings.workspace
            },
            tab: settings.tab,
            program: None,
            evidence_open: std::collections::BTreeSet::new(),
            filter: String::new(),
            scope: agents::Scope::default(),
            inspecting: false,
            tables: std::collections::HashMap::new(),
            swept_at: None,
            draft: Draft::default(),
            raised: std::collections::HashMap::new(),
            settings,
            overlay: Overlay::None,
            resume_ms: 5_000,
            compact: false,
            restore: WINDOW,
            window_size: WINDOW,
            stopping: None,
            events_notice: None,
            capture_outcome: None,
            status: None,
            viewing: None,
            // Listed when the settings page opens, not here. The folder is
            // under Documents, and on macOS a first read of Documents waits on
            // a privacy prompt: listed at start, the window did not appear
            // until that prompt was answered, and it can sit behind others.
            saved_sessions: Vec::new(),
            closing_outcome: None,
        };
        if app.workspace == Workspace::Settings {
            app.saved_sessions = session::saved();
        }
        // The window's shape follows the state rather than only the toggle, so
        // starting compact starts small. A mode that only takes effect when
        // something is pressed is a mode that is wrong the first time it is
        // seen.
        let shaping = shape(
            app.compact,
            app.restore,
            false,
            compact::size_for(0, app.settings.scale),
        );
        (app, Task::batch([Task::done(Message::Sweep), shaping]))
    }

    fn title(&self) -> String {
        let label = option_env!("TOPGENT_BUILD_LABEL").unwrap_or("");
        let name = if label.is_empty() {
            "Topgent".to_owned()
        } else {
            format!("Topgent {label}")
        };
        match &self.report {
            Some(r) => format!("{name} {} — {} agents", r.version, r.agents.len()),
            None => name,
        }
    }

    fn compact_size(&self) -> iced::Size {
        compact::size_for(
            self.report.as_ref().map_or(0, |r| r.agents.len()),
            self.settings.scale,
        )
    }

    fn shape_compact(&self, confirming_stop: bool) -> Task<Message> {
        shape(true, self.restore, confirming_stop, self.compact_size())
    }

    // One arm per message, in the order the enum declares them. Splitting it
    // would scatter the state machine across helpers without making any one of
    // them clearer.
    #[allow(clippy::too_many_lines)]
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
            // A saved session on screen is not replaced by the live host.
            Message::Sweep if self.sweeping || self.viewing.is_some() => Task::none(),
            Message::Sweep => {
                self.sweeping = true;
                Task::perform(report::sweep(), |r| Message::Swept(Box::new(r)))
            }
            // A sweep started before a saved session was opened.
            Message::Swept(_) if self.viewing.is_some() => {
                self.sweeping = false;
                Task::none()
            }
            Message::Swept(result) => {
                self.sweeping = false;
                let previous_count = self.report.as_ref().map_or(0, |r| r.agents.len());
                match *result {
                    Ok(report) => {
                        // An ended agent stays selectable: it is still in
                        // the session, and was the thing being looked at.
                        if self
                            .selected
                            .is_none_or(|pid| report.find_agent(pid).is_none())
                        {
                            self.selected = report.worst().map(|a| a.pid);
                        }
                        self.swept_at = Some(report.generated_at);
                        self.announce(&report);
                        self.report = Some(report);
                        self.error = None;
                    }
                    Err(why) => self.error = Some(why),
                }
                let count = self.report.as_ref().map_or(0, |r| r.agents.len());
                if self.compact && self.stopping.is_none() && count != previous_count {
                    self.shape_compact(false)
                } else {
                    Task::none()
                }
            }
            Message::Select(pid) => {
                self.selected = Some(pid);
                Task::none()
            }
            Message::Go(workspace) => {
                self.workspace = workspace;
                if workspace == Workspace::Settings {
                    self.saved_sessions = session::saved();
                }
                // A page the simple view does not list is a technical page, so
                // going to one is going to the advanced view.
                let simple = self.settings.simple && Workspace::SIMPLE.contains(&workspace);
                self.settle(|c| {
                    c.workspace = workspace;
                    c.simple = simple;
                })
            }
            Message::OpenAgent(pid) => {
                self.selected = Some(pid);
                self.workspace = Workspace::Agents;
                self.tab = agents::Tab::Overview;
                self.settle(|c| {
                    c.workspace = Workspace::Agents;
                    c.tab = agents::Tab::Overview;
                    c.simple = false;
                })
            }
            Message::ShowProcess(agent, pid) => {
                self.selected = Some(agent);
                self.workspace = Workspace::Agents;
                self.tab = agents::Tab::Processes;
                // Found by filtering the table to its pid, in tree order, with
                // its record open. The filter box shows why the table is short.
                let state = self.tables.entry(table::Id::Processes).or_default();
                state.search = pid.to_string();
                state.sort = None;
                state.opened = std::iter::once(0).collect();
                self.settle(|c| {
                    c.workspace = Workspace::Agents;
                    c.tab = agents::Tab::Processes;
                    c.simple = false;
                })
            }
            Message::ToggleEvidence(id) => {
                if !self.evidence_open.remove(&id) {
                    self.evidence_open.insert(id);
                }
                Task::none()
            }
            Message::PickProgram(name) => {
                self.program = name;
                Task::none()
            }
            Message::SetSimple(simple) => {
                if simple {
                    self.workspace = Workspace::Overview;
                }
                let workspace = self.workspace;
                self.settle(|c| {
                    c.simple = simple;
                    c.workspace = workspace;
                })
            }
            Message::ShowTab(tab) => {
                // Choosing evidence about an agent is also choosing the agent
                // workspace. A tab that only took effect once the sidebar was
                // put back would be a control that silently did nothing.
                self.workspace = Workspace::Agents;
                self.tab = tab;
                self.settle(|c| {
                    c.workspace = Workspace::Agents;
                    c.tab = tab;
                })
            }
            Message::FilterAgents(needle) => {
                self.filter = needle;
                Task::none()
            }
            Message::SetScope(scope) => {
                self.scope = scope;
                Task::none()
            }
            Message::ToggleInspector => {
                self.inspecting = !self.inspecting;
                Task::none()
            }
            // Held rather than forgotten: a reader who pauses to read a long
            // record expects the cadence they chose when they start again, not
            // the one the product ships with.
            Message::TogglePause => {
                let current = self.settings.refresh_ms;
                if current == 0 {
                    let resume = self.resume_ms;
                    self.settle(|c| c.refresh_ms = resume)
                } else {
                    self.resume_ms = current;
                    self.settle(|c| c.refresh_ms = 0)
                }
            }
            Message::ToggleCompact => {
                self.compact = !self.compact;
                self.overlay = Overlay::None;
                shape(self.compact, self.restore, false, self.compact_size())
            }
            Message::SortBy(..)
            | Message::Search(..)
            | Message::Drag(..)
            | Message::OpenRow(..) => self.arrange(message),
            Message::ResizeSidebar(delta) => {
                self.settings.sidebar_width = (self.settings.sidebar_width + delta)
                    .clamp(settings::SIDEBAR_WIDTH.0, settings::SIDEBAR_WIDTH.1);
                Task::none()
            }
            Message::ResizeAgentList(delta) => {
                self.settings.agent_list_width = (self.settings.agent_list_width + delta)
                    .clamp(settings::AGENT_LIST_WIDTH.0, settings::AGENT_LIST_WIDTH.1);
                Task::none()
            }
            Message::SavePaneLayout => {
                self.settings.save();
                Task::none()
            }
            Message::ToggleSidebar => self.settle(|c| {
                c.sidebar_state = c.sidebar_state.toggled();
            }),
            Message::ToggleAgentList => self.settle(|c| {
                c.agent_list_state = c.agent_list_state.toggled();
            }),
            Message::ResetPaneLayout => {
                let defaults = settings::Settings::default();
                self.settle(|c| {
                    c.sidebar_width = defaults.sidebar_width;
                    c.agent_list_width = defaults.agent_list_width;
                    c.sidebar_state = settings::PaneState::Expanded;
                    c.agent_list_state = settings::PaneState::Expanded;
                })
            }
            Message::WindowResized(size) => {
                if !self.compact {
                    self.window_size = size;
                    self.restore = size;
                }
                Task::none()
            }
            Message::SetAppearance(appearance) => self.settle(|c| c.appearance = appearance),
            Message::SetDensity(density) => self.settle(|c| c.density = density),
            Message::SetScale(scale) => self.settle(|c| c.scale = scale),
            Message::SetRefresh(ms) => self.settle(|c| c.refresh_ms = ms),
            Message::SetSound(on) => self.settle(|c| c.sound = on),
            Message::AskStop(pid) => {
                self.stopping = Some(pid);
                if self.compact {
                    self.shape_compact(true)
                } else {
                    Task::none()
                }
            }
            // Off the drawing thread, like every other action that touches
            // the disk. A rename is quick; a window that freezes while it
            // happens still looks like one that has crashed.
            Message::ClearEvents => {
                self.events_notice = Some("Clearing\u{2026}".to_owned());
                Task::perform(report::clear_events(), Message::EventsCleared)
            }
            Message::EventsCleared(message) => {
                self.events_notice = Some(message);
                // Swept immediately, so the table empties in front of the
                // person who pressed the button rather than at the next tick.
                Task::perform(report::sweep(), |r| Message::Swept(Box::new(r)))
            }
            // Stopping is not privileged and is not slow: it drops the
            // capture, which kills the helper and joins its threads. Doing it
            // on the drawing thread is fine and keeps the button honest,
            // because when it returns nothing is reading packets.
            Message::StopCapture => {
                topgent_collect::capture::live::stop();
                // Remembered on disk, not just for this run. An off switch
                // that forgets by the next launch is not an off switch.
                self.settings.capture = false;
                self.settings.save();
                self.capture_outcome = Some("Packet capture is off.".to_owned());
                Task::none()
            }
            Message::StartCapture => {
                self.settings.capture = true;
                self.settings.save();
                self.capture_outcome = Some(match topgent_collect::capture::live::start() {
                    Ok(()) => "Packet capture is on.".to_owned(),
                    Err(error) => format!("It did not start: {error}"),
                });
                Task::none()
            }
            // Off the drawing thread, like the grant: the elevation helper puts
            // a password prompt on screen and blocks until it is answered.
            Message::RevokeCapture => {
                self.capture_outcome = Some("Asking the system\u{2026}".to_owned());
                Task::perform(report::revoke_capture(), |(done, message)| {
                    Message::CaptureGranted(done, message)
                })
            }
            Message::AskCapture => {
                self.overlay = Overlay::Capture;
                self.capture_outcome = None;
                Task::none()
            }
            Message::CancelCapture => {
                self.overlay = Overlay::None;
                Task::none()
            }
            Message::GrantCapture => {
                // Off the interface thread. The elevation helper puts a
                // password prompt on screen and blocks until it is answered,
                // and doing that here froze the window: the dialog stayed up
                // after the password was accepted and looked as though nothing
                // had happened.
                self.capture_outcome = Some("Asking the system\u{2026}".to_owned());
                Task::perform(report::grant_capture(), |(granted, message)| {
                    Message::CaptureGranted(granted, message)
                })
            }
            Message::CaptureGranted(granted, message) => {
                // Success closes the dialog, because there is nothing left to
                // decide. Anything else keeps it open and says why, because
                // there is.
                self.overlay = if granted {
                    Overlay::None
                } else {
                    Overlay::Capture
                };
                self.capture_outcome = Some(message);
                Task::none()
            }
            Message::CancelStop => {
                self.stopping = None;
                if self.compact {
                    self.shape_compact(false)
                } else {
                    Task::none()
                }
            }
            // The signal itself happens off the drawing thread. It takes a
            // process snapshot and can block, and a window that freezes while
            // it stops something looks exactly like one that has crashed
            // during it.
            Message::ConfirmStop(pid) => {
                self.stopping = None;
                let stopping = Task::perform(report::stop(pid), Message::Stopped);
                if self.compact {
                    Task::batch([self.shape_compact(false), stopping])
                } else {
                    stopping
                }
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
                self.overlay = Overlay::None;
                self.status = Some("writing this session to a file...".to_owned());
                Task::perform(report::export_session(redacted), Message::RuleChanged)
            }
            Message::CloseRequested
            | Message::SaveAndClose
            | Message::CloseWithoutSaving
            | Message::CancelClose
            | Message::SavedForClose(_)
            | Message::SaveNow
            | Message::SavedNow(_)
            | Message::OpenSaved(_)
            | Message::Opened(_)
            | Message::BackToLive => self.session(message),
            Message::Noop => Task::none(),
        }
    }

    /// Saving, discarding and opening sessions.
    fn session(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::CloseRequested => {
                self.overlay = Overlay::Closing { saving: false };
                self.closing_outcome = None;
                Task::none()
            }
            Message::CancelClose => {
                self.overlay = Overlay::None;
                Task::none()
            }
            Message::SaveAndClose => {
                self.overlay = Overlay::Closing { saving: true };
                self.closing_outcome = None;
                Task::perform(session::save(), Message::SavedForClose)
            }
            Message::SavedForClose(Ok(_)) | Message::CloseWithoutSaving => {
                session::discard();
                iced::exit()
            }
            Message::SavedForClose(Err(why)) => {
                // Not closed: a session that failed to save is not let go.
                self.overlay = Overlay::Closing { saving: false };
                self.closing_outcome = Some(why);
                Task::none()
            }
            Message::SaveNow => {
                self.status = Some("saving this session...".to_owned());
                Task::perform(session::save(), Message::SavedNow)
            }
            Message::SavedNow(result) => {
                self.saved_sessions = session::saved();
                self.status = Some(match result {
                    Ok(path) => format!("session saved to {}", path.display()),
                    Err(why) => why,
                });
                Task::none()
            }
            Message::OpenSaved(path) => {
                self.status = Some(format!("opening {}...", path.display()));
                Task::perform(session::open(path), |r| Message::Opened(r.map(Box::new)))
            }
            Message::Opened(Ok(opened)) => {
                let (report, viewing) = *opened;
                self.selected = report.worst().map(|a| a.pid);
                self.swept_at = Some(report.generated_at);
                self.report = Some(report);
                self.error = None;
                self.status = Some(format!("showing saved session {}", viewing.name));
                self.viewing = Some(viewing);
                Task::none()
            }
            Message::Opened(Err(why)) => {
                self.status = Some(why);
                Task::none()
            }
            Message::BackToLive => {
                self.viewing = None;
                self.report = None;
                self.status = None;
                Task::done(Message::Sweep)
            }
            _ => Task::none(),
        }
    }

    fn view(&self) -> Element<'_, Message> {
        let s = self.settings.style();
        if self.compact {
            let base = compact::view(
                self.report.as_ref(),
                self.sweeping,
                self.status.as_deref(),
                s,
            );
            if let Some(pid) = self.stopping {
                let agent = self
                    .report
                    .as_ref()
                    .and_then(|report| report.find_agent(pid));
                return stack![base, agents::confirm_stop(pid, agent, s)].into();
            }
            if let Overlay::Closing { saving } = self.overlay {
                return stack![
                    base,
                    session::closing_dialog(saving, self.closing_outcome.as_deref(), s)
                ]
                .into();
            }
            return base;
        }
        let agent = self
            .selected
            .and_then(|pid| self.report.as_ref()?.find_agent(pid));

        let content: Element<'_, Message> = match (&self.report, &self.error) {
            (_, Some(why)) => theme::notice(why.clone(), s.palette),
            (None, None) => theme::notice("Scanning\u{2026}", s.palette),
            (Some(report), None) => self.workspace_view(report, agent, s),
        };

        let mut frame = column![shell::titlebar(self.report.as_ref(), s)];
        if let Some(viewing) = &self.viewing {
            frame = frame.push(session::banner(viewing, s));
        }
        // The simple view leaves sensor limits to the advanced one.
        if let Some(line) =
            shell::unavailable(self.report.as_ref(), s).filter(|_| !self.settings.simple)
        {
            frame = frame.push(line);
        }
        let pane_layout = pane_layout(self.settings, self.window_size.width, self.workspace);
        let mut workspace = iced::widget::Row::new().height(Length::Fill);
        if pane_layout.sidebar.is_visible() {
            workspace = workspace.push(shell::sidebar(
                self.workspace,
                self.report.as_ref(),
                self.settings.sidebar_width,
                self.settings.simple,
                s,
            ));
        }
        workspace = workspace
            .push(pane_edge(
                !pane_layout.sidebar.is_visible(),
                (!pane_layout.sidebar.is_auto_hidden()).then_some(Message::ToggleSidebar),
                Message::ResizeSidebar,
                s,
            ))
            .push(container(content).width(Length::Fill).height(Length::Fill));
        let mut frame = frame.push(workspace);
        if let Some(agent) =
            agent.filter(|_| self.report.is_some() && self.error.is_none() && !self.settings.simple)
        {
            frame = frame.push(agents::selected_footer(agent, self.inspecting, s));
        }
        let frame = frame.push(shell::statusbar(
            self.report.as_ref(),
            self.sweeping,
            self.swept_at,
            self.settings.refresh_ms,
            self.status.as_deref(),
            s,
        ));

        let base = container(frame)
            .style(theme::region(Region::Window, s.palette))
            .width(Length::Fill)
            .height(Length::Fill);

        // A dialog is drawn over the interface rather than replacing it, so the
        // reader can still see what they were looking at when they asked for it.
        let mut layers = stack![base];
        if let Some(pid) = self.stopping {
            layers = layers.push(agents::confirm_stop(pid, agent, s));
        } else if matches!(self.overlay, Overlay::Capture) {
            layers = layers.push(capture::dialog(
                &topgent_collect::capture::offer(),
                self.capture_outcome.as_deref(),
                s,
            ));
        } else if let Overlay::Closing { saving } = self.overlay {
            layers = layers.push(session::closing_dialog(
                saving,
                self.closing_outcome.as_deref(),
                s,
            ));
        }
        layers.into()
    }

    /// The page for the chosen workspace.
    ///
    /// Every page names itself and says what it is for. The old interface named
    /// the current view only by which sidebar item was highlighted, so once the
    /// eye moved into a table it had no local identity at all, and a network
    /// table and an event table looked like the same screen.
    fn workspace_view<'a>(
        &'a self,
        report: &'a report::Report,
        agent: Option<&'a report::Agent>,
        s: Style,
    ) -> Element<'a, Message> {
        let paused = self.settings.refresh_ms == 0;
        let sweep = shell::sweep_controls(self.sweeping, paused, s);
        let pane_layout = pane_layout(self.settings, self.window_size.width, self.workspace);

        if matches!(self.workspace, Workspace::Agents) {
            let metrics = if self.window_size.width < 900.0 || s.scale > 1.25 {
                shell::metrics_compact(Some(report), s)
            } else {
                shell::metrics(Some(report), s)
            };
            return column![
                shell::page(Workspace::Agents, sweep, s),
                metrics,
                agent_workspace(
                    report,
                    self.selected,
                    &self.filter,
                    self.scope,
                    self.settings.agent_list_width,
                    pane_layout.agent_list.is_visible(),
                    !pane_layout.agent_list.is_visible(),
                    (!pane_layout.agent_list.is_auto_hidden()).then_some(Message::ToggleAgentList),
                    self.investigation(report, agent, s),
                    s,
                ),
            ]
            .height(Length::Fill)
            .into();
        }

        if matches!(self.workspace, Workspace::Overview) {
            return column![
                shell::page(Workspace::Overview, sweep, s),
                overview::page(
                    report,
                    self.program.as_deref(),
                    self.window_size.width - self.settings.sidebar_width,
                    s
                ),
                iced::widget::space().height(Length::Fixed(s.pad(space::BASE))),
            ]
            .height(Length::Fill)
            .into();
        }

        // The event log is the only page with a record of its own to set
        // aside, so it is the only one whose heading carries a control.
        let trailing: Element<'a, Message> = if matches!(self.workspace, Workspace::Events) {
            row![
                text(self.events_notice.clone().unwrap_or_default())
                    .size(s.type_size(theme::size::MICRO))
                    .color(s.palette.faint),
                panels::clear_button(s),
                sweep,
            ]
            .spacing(s.pad(space::BASE))
            .align_y(iced::Alignment::Center)
            .into()
        } else {
            sweep
        };

        let body: Element<'a, Message> = match self.workspace.panel() {
            Some(panel) => panels::view(panel, report, None, &self.tables, &self.draft, s),
            None if matches!(self.workspace, Workspace::Incidents) => {
                incidents::page(report, &self.evidence_open, s)
            }
            None => settings::page(self.settings, &self.saved_sessions, s),
        };

        column![
            shell::page(self.workspace, trailing, s),
            container(body)
                .padding([0.0, s.pad(space::LOOSE)])
                .width(Length::Fill)
                .height(Length::Fill),
            iced::widget::space().height(Length::Fixed(s.pad(space::BASE))),
        ]
        .height(Length::Fill)
        .into()
    }

    /// One agent's identity, its tabs, and the evidence the chosen tab draws.
    ///
    /// Identity sits directly above the evidence it belongs to. In the old
    /// layout it was a strip along the bottom of the window, as far from the
    /// evidence as the arrangement allowed.
    fn investigation<'a>(
        &'a self,
        report: &'a report::Report,
        agent: Option<&'a report::Agent>,
        s: Style,
    ) -> Element<'a, Message> {
        let Some(agent) = agent else {
            return container(theme::notice("Select an agent to investigate.", s.palette))
                .width(Length::Fill)
                .height(Length::Fill)
                .into();
        };

        let evidence: Element<'a, Message> = match self.tab.panel() {
            None => agents::overview(report, agent, s),
            Some(panel) => container(panels::view(
                panel,
                report,
                Some(agent.pid),
                &self.tables,
                &self.draft,
                s,
            ))
            .padding([s.pad(space::WIDE), s.pad(space::LOOSE)])
            .width(Length::Fill)
            .height(Length::Fill)
            .into(),
        };

        let mut body = column![agents::tabs(self.tab, s)].height(Length::Shrink);
        // Only an outcome about this agent, and only while nothing is waiting
        // on an answer. The core's own sentence goes here rather than the
        // status strip, because a refusal has to be read beside the thing it
        // refused to act on.
        if let Some(outcome) = self
            .status
            .as_deref()
            .filter(|_| self.stopping.is_none())
            .filter(|o| o.starts_with("stop") || o.contains("refused"))
        {
            body = body.push(agents::footnote(outcome, s));
        }

        column![body, evidence].height(Length::Fill).into()
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
                agent: agent.named(),
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
        let resize = iced::window::resize_events().map(|(_, size)| Message::WindowResized(size));
        // Always: closing asks whether to save, whatever else is going on.
        let closing = iced::window::close_requests().map(|_| Message::CloseRequested);
        if self.settings.refresh_ms == 0 || self.stopping.is_some() || self.viewing.is_some() {
            return Subscription::batch([resize, closing]);
        }
        Subscription::batch([
            resize,
            closing,
            iced::time::every(std::time::Duration::from_millis(self.settings.refresh_ms))
                .map(|_| Message::Sweep),
        ])
    }
}

/// One pane boundary: a clear fold control above a full-height drag target.
fn pane_edge<'a>(
    collapsed: bool,
    toggle: Option<Message>,
    resize: fn(f32) -> Message,
    s: Style,
) -> Element<'a, Message> {
    let p = s.palette;
    let arrow = if collapsed { "›" } else { "‹" };
    let resize_target: Element<'a, Message> = if collapsed {
        iced::widget::space().height(Length::Fill).into()
    } else {
        crate::divider::Divider::new(Length::Fill, p.border, p.accent, resize)
            .on_release(|| Message::SavePaneLayout)
            .into()
    };
    iced::widget::column![
        iced::widget::button(
            iced::widget::text(arrow)
                .font(theme::STRONG)
                .size(s.type_size(theme::size::LABEL))
                .color(p.muted),
        )
        .on_press_maybe(toggle)
        .padding([s.pad(space::TIGHT), s.pad(space::TIGHT)])
        .style(move |_, status| iced::widget::button::Style {
            background: Some(
                if matches!(status, iced::widget::button::Status::Hovered) {
                    p.hover()
                } else {
                    p.surface
                }
                .into()
            ),
            text_color: p.muted,
            border: iced::Border {
                color: p.border,
                width: 1.0,
                radius: 0.0.into(),
            },
            ..iced::widget::button::Style::default()
        }),
        resize_target,
    ]
    .width(Length::Shrink)
    .height(Length::Fill)
    .into()
}

#[allow(clippy::too_many_arguments)]
fn agent_workspace<'a>(
    report: &'a report::Report,
    selected: Option<u32>,
    filter: &str,
    scope: agents::Scope,
    width: f32,
    visible: bool,
    collapsed: bool,
    toggle: Option<Message>,
    investigation: Element<'a, Message>,
    s: Style,
) -> Element<'a, Message> {
    let mut row = iced::widget::Row::new().height(Length::Fill);
    if visible {
        row = row.push(agents::list(report, selected, filter, scope, width, s));
    }
    row.push(pane_edge(collapsed, toggle, Message::ResizeAgentList, s))
        .push(investigation)
        .into()
}

/// The evidence gets first claim on horizontal space. On small windows the
/// host navigation folds before the agent picker; neither stored preference is
/// destroyed, so widening the window restores the chosen layout.
#[derive(Debug, Clone, Copy)]
struct PaneLayout {
    sidebar: PaneVisibility,
    agent_list: PaneVisibility,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PaneVisibility {
    Expanded,
    Collapsed,
    AutoHidden,
}

impl PaneVisibility {
    const fn is_visible(self) -> bool {
        matches!(self, Self::Expanded)
    }

    const fn is_auto_hidden(self) -> bool {
        matches!(self, Self::AutoHidden)
    }
}

fn pane_layout(settings: settings::Settings, width: f32, workspace: Workspace) -> PaneLayout {
    const EVIDENCE_MIN: f32 = 520.0;
    const BOUNDARIES: f32 = 40.0;
    let agents = matches!(workspace, Workspace::Agents);
    let sidebar_requested = !settings.sidebar_state.is_collapsed();
    let list_requested = agents && !settings.agent_list_state.is_collapsed();
    let mut sidebar_visible = sidebar_requested;
    let mut agent_list_visible = list_requested;
    let available = width.max(0.0) - EVIDENCE_MIN - BOUNDARIES;
    if sidebar_visible
        && settings.sidebar_width
            + if agent_list_visible {
                settings.agent_list_width
            } else {
                0.0
            }
            > available
    {
        sidebar_visible = false;
    }
    if agent_list_visible && settings.agent_list_width > available {
        agent_list_visible = false;
    }
    PaneLayout {
        sidebar: match (sidebar_requested, sidebar_visible) {
            (_, true) => PaneVisibility::Expanded,
            (true, false) => PaneVisibility::AutoHidden,
            (false, false) => PaneVisibility::Collapsed,
        },
        agent_list: match (list_requested, agent_list_visible) {
            (_, true) => PaneVisibility::Expanded,
            (true, false) => PaneVisibility::AutoHidden,
            (false, false) => PaneVisibility::Collapsed,
        },
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
    // A new window starts with no history: its own session, removed on close
    // unless saved. Failing to make one is said and not fatal; the window
    // then shares the state directory, as the command line does.
    if let Err(error) = topgent_report::begin_session() {
        eprintln!("topgent: no session of its own, using the shared state directory: {error}");
    }
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
            // Closing asks first (see `Message::CloseRequested`).
            exit_on_close_request: false,
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

#[cfg(test)]
mod pane_layout_tests {
    use super::*;

    #[test]
    fn narrow_windows_give_evidence_the_space_before_the_other_panes() {
        let settings = settings::Settings::default();
        let wide = pane_layout(settings, 1360.0, Workspace::Agents);
        assert_eq!(wide.sidebar, PaneVisibility::Expanded);
        assert_eq!(wide.agent_list, PaneVisibility::Expanded);

        let medium = pane_layout(settings, 900.0, Workspace::Agents);
        assert_eq!(medium.sidebar, PaneVisibility::AutoHidden);
        assert_eq!(medium.agent_list, PaneVisibility::Expanded);

        let narrow = pane_layout(settings, 650.0, Workspace::Agents);
        assert_eq!(narrow.sidebar, PaneVisibility::AutoHidden);
        assert_eq!(narrow.agent_list, PaneVisibility::AutoHidden);
    }

    #[test]
    fn a_deliberately_collapsed_pane_stays_collapsed_when_widened() {
        let settings = settings::Settings {
            sidebar_state: settings::PaneState::Collapsed,
            ..settings::Settings::default()
        };
        let layout = pane_layout(settings, 1360.0, Workspace::Agents);
        assert_eq!(layout.sidebar, PaneVisibility::Collapsed);
        assert_eq!(layout.agent_list, PaneVisibility::Expanded);
    }
}
