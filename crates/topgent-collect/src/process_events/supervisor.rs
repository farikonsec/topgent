//! Running the helper.
//!
//! Separate because it is the only part that touches the operating system:
//! it finds `topgent-sensor` beside this binary, starts it, reads it on a
//! thread, restarts it when it stops, and records every stretch it was down.

#[cfg(target_os = "linux")]
pub use running::take_drained;

/// The kernel process-lifecycle sensor.
///
/// Present on every platform so every report has its row: where the process
/// connector does not exist, the row says so rather than being absent.
#[derive(Debug, Default)]
pub struct ProcessEventCollector;

#[cfg(not(target_os = "linux"))]
use super::LifecycleEvent;

#[cfg(not(target_os = "linux"))]
/// Nothing is ever drained where there is no sensor.
#[must_use]
pub const fn take_drained() -> Vec<LifecycleEvent> {
    Vec::new()
}

#[cfg(not(target_os = "linux"))]
impl crate::Collector for ProcessEventCollector {
    fn id(&self) -> &'static str {
        "process_events"
    }

    fn collect(
        &self,
        _clock: &dyn crate::Clock,
    ) -> Result<Vec<topgent_facts::Fact>, crate::CollectError> {
        Err(crate::CollectError::Unavailable {
            what: "the kernel process connector is Linux-only".to_owned(),
        })
    }
}

#[cfg(target_os = "linux")]
mod running {
    use std::fmt::Write as _;
    use std::io::BufRead as _;
    use std::sync::{Arc, Mutex, OnceLock, PoisonError};

    use super::ProcessEventCollector;
    use crate::process_events::{
        LifecycleEvent, Line, Pending, STALL_MS, interval_covered, parse_line,
    };
    use crate::{Clock, CollectError, Collector};
    use topgent_facts::Fact;

    const ID: &str = "process_events";
    const HELPER: &str = "topgent-sensor";
    /// How long to wait before starting a helper that stopped.
    const RETRY_MS: u64 = 5_000;

    const BOUNDARY: &str = "Process creation, program replacement and exit, for every process \
                            on the host: from Topgent's eBPF probe where the kernel takes it, \
                            else from the kernel's process connector. No arguments, no \
                            environment, no file or network activity. Through eBPF, a process's \
                            creator, name and program path are read in the kernel as it happens; \
                            through the process connector, a process that ends before its \
                            details can be read is still recorded, with what the kernel said \
                            about it. Times are on the kernel's boot clock, which Linux \
                            publishes in whole seconds, so they can read up to a second earlier \
                            than the wall clock. Nothing is seen while the helper is not \
                            running, and each such gap is reported.";

    #[derive(Default)]
    struct State {
        pending: Arc<Mutex<Pending>>,
        child: Option<std::process::Child>,
        /// Why it is not running, when it is not.
        ended: Arc<Mutex<Option<String>>>,
        last_attempt: u64,
        /// Stretches the helper was not running, as (from, to).
        gaps: Vec<(u64, u64)>,
        down_since: Option<u64>,
        drained: Vec<LifecycleEvent>,
        /// When the running helper started, and when the previous sweep ran.
        running_since: Option<u64>,
        previous_sweep: Option<u64>,
        /// Whether the helper was receiving for the whole of the last interval;
        /// `None` before there has been an interval to cover.
        uninterrupted: Option<bool>,
        /// Loss counted in the last interval, and in total.
        interval_lost: Option<u64>,
        total_lost: u64,
        /// Sweeps whose interval had the helper silent for longer than
        /// `STALL_MS`, and the latest such silence.
        stalls: u64,
        last_stall_ms: u64,
        /// The helper session and its kernel syscall-loss count as of the
        /// last sweep, so each sweep hands on only what is new.
        syscalls_lost_seen: Option<(String, u64)>,
    }

    fn state() -> &'static Mutex<State> {
        static STATE: OnceLock<Mutex<State>> = OnceLock::new();
        STATE.get_or_init(|| Mutex::new(State::default()))
    }

    fn helper_path() -> Option<std::path::PathBuf> {
        // Where to look, not a reason to trust: the file is checked below.
        // nosemgrep: rust.lang.security.current-exe.current-exe
        let path = std::env::current_exe().ok()?.parent()?.join(HELPER);
        (path.is_file() && crate::capture::helper::safe_to_run(&path)).then_some(path)
    }

    fn start(state: &mut State, now: u64) -> Result<(), CollectError> {
        state.last_attempt = now;
        let path = helper_path().ok_or_else(|| CollectError::Unavailable {
            what: format!("no {HELPER} is installed beside this binary"),
        })?;
        let mut child = std::process::Command::new(&path)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .stdin(std::process::Stdio::null())
            .spawn()
            .map_err(|error| CollectError::Unavailable {
                what: format!("{} could not be started: {error}", path.display()),
            })?;
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let pending = Arc::clone(&state.pending);
        let ended = Arc::clone(&state.ended);
        *ended.lock().unwrap_or_else(PoisonError::into_inner) = None;
        std::thread::Builder::new()
            .name("topgent-sensor-reader".to_owned())
            .spawn(move || {
                if let Some(stdout) = stdout {
                    for line in std::io::BufReader::new(stdout).lines() {
                        let Ok(line) = line else { break };
                        if let Some(parsed) = parse_line(&line) {
                            // Ask the runtime about a container the moment
                            // one is named: a `--rm` one is gone in seconds.
                            match &parsed {
                                Line::Event(event) => {
                                    if let Some(id) = &event.container {
                                        crate::container_context::notice(id);
                                    }
                                    match event.kind {
                                        crate::process_events::LifecycleKind::Exit { .. } => {
                                            crate::observed::tally::exited(event.pid);
                                        }
                                        crate::process_events::LifecycleKind::Fork { parent } => {
                                            crate::observed::tally::forked(event.pid, parent);
                                        }
                                        crate::process_events::LifecycleKind::Exec => {
                                            let program = event
                                                .path
                                                .as_deref()
                                                .or(event.program.as_deref())
                                                .unwrap_or("");
                                            crate::observed::tally::exec(event.pid, program);
                                        }
                                        crate::process_events::LifecycleKind::Rename => {}
                                    }
                                }
                                Line::Syscall(call) => {
                                    if let Some(id) = &call.event.container {
                                        crate::container_context::notice(id);
                                    }
                                    // Counted here, before any queue can
                                    // drop it. Its time is already in the
                                    // start-time base.
                                    crate::observed::tally::add(&call.event, call.event.at);
                                }
                                Line::Health(_) => {}
                            }
                            if let Line::Health(health) = &parsed {
                                crate::observed::set_sensor_delivers(
                                    health.syscalls.is_some_and(|n| n > 0),
                                );
                            }
                            pending
                                .lock()
                                .unwrap_or_else(PoisonError::into_inner)
                                .push(parsed);
                        }
                    }
                }
                // Stopped: the Audit log is the syscall source again.
                crate::observed::set_sensor_delivers(false);
                let mut reason = String::new();
                if let Some(stderr) = stderr {
                    for line in std::io::BufReader::new(stderr).lines().take(4).flatten() {
                        reason.push_str(line.trim());
                        reason.push(' ');
                    }
                }
                let reason = reason.trim().to_owned();
                *ended.lock().unwrap_or_else(PoisonError::into_inner) =
                    Some(if reason.is_empty() {
                        "the sensor helper stopped".to_owned()
                    } else {
                        reason
                    });
            })
            .map_err(|error| CollectError::Unavailable {
                what: format!("the sensor reader could not be started: {error}"),
            })?;
        state.child = Some(child);
        Ok(())
    }

    /// What the process sensor delivered for the sweep that just ran.
    #[must_use]
    pub fn take_drained() -> Vec<LifecycleEvent> {
        std::mem::take(
            &mut state()
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .drained,
        )
    }

    impl Collector for ProcessEventCollector {
        fn id(&self) -> &'static str {
            ID
        }

        fn collect(&self, clock: &dyn Clock) -> Result<Vec<Fact>, CollectError> {
            let now = clock.now().0;
            let mut state = state().lock().unwrap_or_else(PoisonError::into_inner);
            let ended = state
                .ended
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            // Whether the helper was started during this sweep: a first start,
            // or a restart after it stopped. Either way this interval had a
            // stretch nobody was listening to.
            let mut started_now = false;
            if let Some(reason) = &ended {
                // It stopped. Reap it, note when, and try again after a while.
                if let Some(mut child) = state.child.take() {
                    drop(child.kill());
                    drop(child.wait());
                    state.down_since = Some(now);
                }
                // Not restarting yet: this interval was not covered, and the
                // next one begins now.
                if now.saturating_sub(state.last_attempt) < RETRY_MS {
                    state.uninterrupted = Some(false);
                    state.previous_sweep = Some(now);
                    let permission = reason.contains("CAP_NET_ADMIN");
                    return Err(if permission {
                        CollectError::Denied {
                            what: reason.clone(),
                        }
                    } else {
                        CollectError::Unreadable {
                            what: reason.clone(),
                        }
                    });
                }
            }
            if state.child.is_none() {
                state.running_since = None;
                start(&mut state, now)?;
                state.running_since = Some(now);
                started_now = true;
                if let Some(since) = state.down_since.take() {
                    state.gaps.push((since, now));
                }
            }
            let (drained, calls, interval_lost, total_lost, silence, health) = {
                let mut pending = state.pending.lock().unwrap_or_else(PoisonError::into_inner);
                (
                    pending.drain(),
                    pending.drain_calls(),
                    pending.take_interval_loss(),
                    pending.lost(),
                    pending.take_interval_silence(now),
                    pending.health.clone(),
                )
            };
            // Syscalls the kernel dropped since the last sweep count with the
            // ones this side dropped: a lost call is a loss wherever it went.
            let kernel_lost = new_syscall_loss(&mut state.syscalls_lost_seen, health.as_ref());
            // With the lifecycle events that came before them, in one sweep.
            crate::observed::publish_sensor_calls(calls.0, calls.1.saturating_add(kernel_lost));
            let stalled = !started_now && silence > STALL_MS;
            if stalled {
                state.stalls = state.stalls.saturating_add(1);
                state.last_stall_ms = silence;
            }
            state.uninterrupted = interval_covered(
                state.previous_sweep,
                state.running_since,
                started_now,
                stalled,
            );
            state.previous_sweep = Some(now);
            state.drained = drained;
            state.interval_lost = interval_lost;
            state.total_lost = total_lost;
            Ok(Vec::new())
        }

        fn dropped_events(&self) -> Option<u64> {
            // This interval's loss. No health line yet means no loss
            // accounting yet, not zero loss.
            state()
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .interval_lost
        }

        fn continuous(&self) -> Option<bool> {
            state()
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .uninterrupted
        }

        fn detail(&self) -> Option<String> {
            let state = state().lock().unwrap_or_else(PoisonError::into_inner);
            let pending = state.pending.lock().unwrap_or_else(PoisonError::into_inner);
            let mut detail = source(pending.health.as_ref());
            let _ = write!(
                detail,
                "{} lifecycle events this sweep; {} lost since the sensor started; {} restarts",
                state.drained.len(),
                state.total_lost,
                pending.restarts()
            );
            if let Some(health) = pending.health.as_ref()
                && let (Some(traced), Some(lost)) = (health.syscalls, health.syscalls_lost)
                && traced > 0
            {
                let _ = write!(
                    detail,
                    "; {traced} rule syscalls traced, {lost} of their events lost in the kernel since the sensor started"
                );
            }
            if state.stalls > 0 {
                let _ = write!(
                    detail,
                    "; silent for {} interval(s), the last {} ms",
                    state.stalls, state.last_stall_ms
                );
            }
            if !state.gaps.is_empty() {
                let _ = write!(
                    detail,
                    "; not running for {} stretch(es), the last {} ms long",
                    state.gaps.len(),
                    state
                        .gaps
                        .last()
                        .map_or(0, |(from, to)| to.saturating_sub(*from))
                );
            }
            Some(detail)
        }

        fn boundary(&self) -> Option<&'static str> {
            Some(BOUNDARY)
        }
    }

    /// Kernel syscall losses reported since `seen`, which it then records.
    /// A new helper session counts from zero, so all of its count is new.
    fn new_syscall_loss(
        seen: &mut Option<(String, u64)>,
        health: Option<&crate::process_events::HelperHealth>,
    ) -> u64 {
        let Some(health) = health else { return 0 };
        let Some(total) = health.syscalls_lost else {
            return 0;
        };
        let before = match seen {
            Some((session, count)) if *session == health.session => *count,
            _ => 0,
        };
        *seen = Some((health.session.clone(), total));
        total.saturating_sub(before)
    }

    /// Which kernel source the helper reported, and why not eBPF when it is
    /// not, as the opening of the sensor's detail. Nothing before the first
    /// health line: the source is not claimed before the helper says it.
    fn source(health: Option<&crate::process_events::HelperHealth>) -> String {
        let Some(health) = health else {
            return String::new();
        };
        match (health.source.as_deref(), health.note.as_deref()) {
            (Some("ebpf"), _) => "Kernel source: eBPF. ".to_owned(),
            (Some("connector"), Some(note)) => {
                format!("Kernel source: process connector (eBPF not used: {note}). ")
            }
            (Some("connector"), None) => "Kernel source: process connector. ".to_owned(),
            _ => String::new(),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{new_syscall_loss, source};
        use crate::process_events::HelperHealth;

        #[test]
        fn each_sweep_counts_only_the_kernel_syscall_losses_it_has_not_counted() {
            let health = |session: &str, lost: u64| HelperHealth {
                session: session.to_owned(),
                syscalls_lost: Some(lost),
                ..HelperHealth::default()
            };
            let mut seen = None;
            assert_eq!(new_syscall_loss(&mut seen, Some(&health("a", 3))), 3);
            assert_eq!(new_syscall_loss(&mut seen, Some(&health("a", 3))), 0);
            assert_eq!(new_syscall_loss(&mut seen, Some(&health("a", 10))), 7);
            assert_eq!(
                new_syscall_loss(&mut seen, Some(&health("b", 2))),
                2,
                "a restart starts at zero"
            );
            assert_eq!(new_syscall_loss(&mut seen, None), 0);
        }

        fn health(source: Option<&str>, note: Option<&str>) -> HelperHealth {
            HelperHealth {
                source: source.map(str::to_owned),
                note: note.map(str::to_owned),
                ..HelperHealth::default()
            }
        }

        #[test]
        fn the_detail_names_the_source_and_why_not_ebpf() {
            assert_eq!(source(None), "");
            assert_eq!(source(Some(&health(None, None))), "");
            assert_eq!(
                source(Some(&health(Some("ebpf"), None))),
                "Kernel source: eBPF. "
            );
            assert_eq!(
                source(Some(&health(
                    Some("connector"),
                    Some("this build of Topgent carries no eBPF probe")
                ))),
                "Kernel source: process connector (eBPF not used: this build of Topgent \
                 carries no eBPF probe). "
            );
        }
    }
}
