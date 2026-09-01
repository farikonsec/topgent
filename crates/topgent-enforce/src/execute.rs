//! Carrying out one authorised action.
//!
//! The order is fixed and none of it is optional: guard first, exact identity
//! second, signal last, and a fact recorded either way. Identity is checked as
//! late as possible because the window that matters is between the decision and
//! the signal, and a pid reused inside it would otherwise be stopped in place
//! of the process someone actually approved.
//!
//! A process tree is preflighted whole before any member is signalled, so a
//! protected or reused descendant stops the operation rather than leaving it
//! half done. Members are then signalled deepest first, and a failure partway
//! through says how many were already signalled rather than reporting a clean
//! failure that did not happen.

use crate::guard::Guard;
use crate::signal::{GRACE, POLL, Signal, Signaller};
use crate::{Action, Executed, ID, Outcome, Refusal};
use std::time::Instant;
use topgent_collect::{Clock, emit, process};
use topgent_facts::{Claim, Confidence, Subject};

/// Run one action.
///
/// Guards first, identity second, signal last, and a fact either way.
pub fn execute(
    action: &Action,
    guard: &Guard,
    signaller: &dyn Signaller,
    clock: &dyn Clock,
) -> Executed {
    let result = attempt(action, guard, signaller);
    let fact = emit(
        ID,
        &format!("{} pid {}", action.name(), action.pid()),
        Confidence::Certain,
        clock,
        Subject::Process {
            pid: action.pid(),
            started_at: action.started_at(),
        },
        Claim::ActionTaken {
            action: action.name().to_owned(),
            succeeded: result.is_ok(),
        },
    );
    Executed { result, fact }
}

fn attempt(action: &Action, guard: &Guard, signaller: &dyn Signaller) -> Result<Outcome, Refusal> {
    if matches!(action, Action::KillTree { .. }) {
        return attempt_tree(action, &process::snapshot(), guard, signaller);
    }
    let Action::Kill { pid, started_at } = *action else {
        unreachable!("tree action returned above")
    };

    let Some(target) = process::snapshot()
        .into_iter()
        .find(|p| p.pid == pid)
        .map(process::with_resolved_owner)
    else {
        return Err(Refusal::NotRunning);
    };
    guard.check(&target)?;

    // The identity check happens here, as late as possible, because the window
    // that matters is between the decision and the signal.
    if target.started_at != started_at {
        return Err(Refusal::IdentityChanged {
            expected: started_at,
            found: target.started_at,
        });
    }

    signaller
        .send(pid, Signal::Terminate)
        .map_err(|detail| Refusal::Denied { detail })?;

    let deadline = Instant::now() + GRACE;
    while Instant::now() < deadline {
        if signaller.identity(pid) != Some(started_at) {
            return Ok(Outcome::StoppedGracefully);
        }
        std::thread::sleep(POLL);
    }

    // Still there. Re-check identity once more: a process that exited and had
    // its pid reused during the grace period must not now be killed.
    if signaller.identity(pid) != Some(started_at) {
        return Ok(Outcome::StoppedGracefully);
    }
    signaller
        .send(pid, Signal::Force)
        .map_err(|detail| Refusal::Denied { detail })?;

    for _ in 0..20 {
        std::thread::sleep(POLL);
        if signaller.identity(pid) != Some(started_at) {
            return Ok(Outcome::Killed);
        }
    }
    Err(Refusal::Survived)
}

fn attempt_tree(
    action: &Action,
    processes: &[process::ProcInfo],
    guard: &Guard,
    signaller: &dyn Signaller,
) -> Result<Outcome, Refusal> {
    let Action::KillTree { pid, started_at } = *action else {
        return Err(Refusal::Protected {
            why: "process-tree enforcement requires a typed tree action",
        });
    };
    let Some(root) = processes.iter().find(|process| process.pid == pid) else {
        return Err(Refusal::NotRunning);
    };
    if root.started_at != started_at {
        return Err(Refusal::IdentityChanged {
            expected: started_at,
            found: root.started_at,
        });
    }

    let mut targets = tree_targets(pid, processes);
    targets.push((root, 0));
    targets.sort_by_key(|(target, depth)| (std::cmp::Reverse(*depth), target.pid));

    // Ownership is established here, for the members this response is actually
    // about. The sweep leaves it unresolved where it costs a query per process,
    // because it decides nothing until something is about to be stopped.
    let targets: Vec<(process::ProcInfo, usize)> = targets
        .into_iter()
        .map(|(target, depth)| (process::with_resolved_owner(target.clone()), depth))
        .collect();

    for (target, _) in &targets {
        guard.check(target)?;
        if let Some(found) = signaller.identity(target.pid)
            && found != target.started_at
        {
            return Err(Refusal::IdentityChanged {
                expected: target.started_at,
                found,
            });
        }
    }

    let mut attempted_count = 0_usize;
    for (target, _) in &targets {
        if signaller.identity(target.pid) == Some(target.started_at) {
            if let Err(detail) = signaller.send(target.pid, Signal::Terminate) {
                return Err(if attempted_count == 0 {
                    Refusal::Denied { detail }
                } else {
                    Refusal::Partial {
                        signalled: attempted_count,
                        detail,
                    }
                });
            }
            attempted_count = attempted_count.saturating_add(1);
        }
    }
    let deadline = Instant::now() + GRACE;
    while Instant::now() < deadline {
        if targets
            .iter()
            .all(|(target, _)| signaller.identity(target.pid) != Some(target.started_at))
        {
            return Ok(Outcome::TreeStoppedGracefully);
        }
        std::thread::sleep(POLL);
    }

    let mut forced = false;
    for (target, _) in &targets {
        if signaller.identity(target.pid) == Some(target.started_at) {
            forced = true;
            if let Err(detail) = signaller.send(target.pid, Signal::Force) {
                return Err(if attempted_count == 0 {
                    Refusal::Denied { detail }
                } else {
                    Refusal::Partial {
                        signalled: attempted_count,
                        detail,
                    }
                });
            }
            attempted_count = attempted_count.saturating_add(1);
        }
    }
    for _ in 0..20 {
        if targets
            .iter()
            .all(|(target, _)| signaller.identity(target.pid) != Some(target.started_at))
        {
            return Ok(if forced {
                Outcome::TreeKilled
            } else {
                Outcome::TreeStoppedGracefully
            });
        }
        std::thread::sleep(POLL);
    }
    Err(Refusal::Survived)
}

fn tree_targets(
    root_pid: u32,
    processes: &[process::ProcInfo],
) -> Vec<(&process::ProcInfo, usize)> {
    let mut targets = Vec::new();
    let mut frontier = vec![(root_pid, 0_usize)];
    let mut seen = std::collections::BTreeSet::from([root_pid]);
    while let Some((parent, depth)) = frontier.pop() {
        for child in processes
            .iter()
            .filter(|process| process.parent == Some(parent))
        {
            if seen.insert(child.pid) {
                let child_depth = depth.saturating_add(1);
                targets.push((child, child_depth));
                frontier.push((child.pid, child_depth));
            }
        }
    }
    targets
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::{Action, Guard, Outcome, Refusal, Signal, Signaller, attempt_tree};
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use topgent_collect::process::ProcInfo;
    use topgent_facts::UnixMillis;

    struct FakeSignaller {
        identities: RefCell<BTreeMap<u32, UnixMillis>>,
        sent: RefCell<Vec<(u32, Signal)>>,
        deny_pid: Option<u32>,
    }

    impl Signaller for FakeSignaller {
        fn send(&self, pid: u32, signal: Signal) -> Result<(), String> {
            self.sent.borrow_mut().push((pid, signal));
            if self.deny_pid == Some(pid) {
                return Err("fixture denied signal".to_owned());
            }
            self.identities.borrow_mut().remove(&pid);
            Ok(())
        }

        fn identity(&self, pid: u32) -> Option<UnixMillis> {
            self.identities.borrow().get(&pid).copied()
        }
    }

    fn process(pid: u32, parent: Option<u32>, started_at: u64, uid: u32) -> ProcInfo {
        ProcInfo {
            // The fixtures use uid zero to mean "an account that is not
            // Topgent's", which the guard must refuse.
            owner: topgent_collect::process::Owner::Uid(uid),
            exe_path_known: true,
            pid,
            started_at: UnixMillis(started_at),
            exe: format!("/fixture/{pid}"),
            name: format!("fixture-{pid}"),
            uid,
            user: "fixture".to_owned(),
            parent,
            family: (pid == 42).then_some("codex-cli"),
        }
    }

    fn action() -> Action {
        Action::KillTree {
            pid: 42,
            started_at: UnixMillis(1_000),
        }
    }

    fn guard() -> Guard {
        Guard {
            own_pid: 900,
            parent_pid: Some(901),
            own_owner: topgent_collect::process::Owner::Uid(501),
        }
    }

    #[test]
    fn a_close_request_a_console_process_cannot_receive_is_not_a_denial() {
        use crate::signal::windows_signal_outcome;
        // Windows delivers a close request as a window message, so a console
        // agent can never receive one and answers with this. Treating it as a
        // denial stopped the ladder before force, and a stop the operator had
        // approved simply did not happen. Observed live on Windows Server 2025.
        let refusal = "ERROR: The process with PID 2720 could not be terminated.\n\
                       Reason: This process can only be terminated forcefully (with /F option).";
        assert!(windows_signal_outcome(Signal::Terminate, refusal).is_ok());

        // The same words on the force rung are a real failure: there is no
        // further rung to escalate to, so it must not be swallowed.
        assert!(windows_signal_outcome(Signal::Force, refusal).is_err());

        // A process that has already exited is a completed request.
        for gone in [
            "ERROR: The process \"4242\" not found.",
            "ERROR: The process with PID 4242 could not be terminated.\n\
             Reason: There is no running instance of the task.",
        ] {
            assert!(windows_signal_outcome(Signal::Terminate, gone).is_ok());
            assert!(windows_signal_outcome(Signal::Force, gone).is_ok());
        }

        // Anything else is reported in the system's own words, bounded.
        let denied = "ERROR: The process with PID 744 could not be terminated.\n\
                      Reason: Access is denied.";
        let error = windows_signal_outcome(Signal::Force, denied)
            .expect_err("access denied is a real refusal");
        assert!(error.contains("Access is denied"), "{error}");
        let flood = "x".repeat(4_096);
        let bounded = windows_signal_outcome(Signal::Force, &flood)
            .expect_err("an unrecognised refusal is still a refusal");
        assert_eq!(bounded.chars().count(), 512);
    }

    #[test]
    fn windows_never_signals_anything_the_operating_system_stands_on() {
        // Terminating csrss, wininit, services, lsass or smss does not stop a
        // process, it stops the machine with a bug check. A response that can
        // take the host down is not a response.
        for name in crate::guard::WINDOWS_CRITICAL {
            let mut target = process(1234, Some(4), 1_000, 501);
            target.name = name.to_owned();
            let refused = crate::guard::protected_system_process(&target);
            #[cfg(windows)]
            assert!(refused.is_some(), "not protected on Windows: {name}");
            #[cfg(not(windows))]
            assert!(refused.is_none(), "protected off Windows: {name}");
        }

        // The kernel's own process and the idle process, by number.
        for pid in [0_u32, 4] {
            let target = process(pid, None, 1_000, 501);
            #[cfg(windows)]
            assert!(
                crate::guard::protected_system_process(&target).is_some(),
                "pid {pid}"
            );
            #[cfg(not(windows))]
            let _ = target;
        }

        // An agent that merely shares part of a protected name is not protected:
        // the match is on the whole executable name, not a substring.
        for ordinary in ["lsass-notreally.exe", "mycsrss.exe", "services-helper.exe"] {
            let mut target = process(1234, Some(1), 1_000, 501);
            target.name = ordinary.to_owned();
            assert!(
                crate::guard::protected_system_process(&target).is_none(),
                "an ordinary process was treated as critical: {ordinary}"
            );
        }
    }

    /// Pid 1 is the init system on every platform Topgent runs on. It was
    /// refused nowhere but Windows: `protected_system_process` returned `None`
    /// off Windows, so `topgent stop 1` offered to terminate systemd with an
    /// ordinary confirmation. Ownership refuses it today only because init
    /// belongs to root, which is no guard at all for a Topgent run as root.
    /// Found on a Linux lab host.
    #[test]
    fn the_init_process_is_refused_on_every_platform() {
        let target = process(1, None, 1_000, 0);
        assert!(
            crate::guard::protected_system_process(&target).is_some(),
            "pid 1 must be refused before ownership is consulted"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn the_kernel_and_init_are_refused_by_name_at_any_pid() {
        // A container or a user session runs its own init at a pid that is not
        // one, so the number alone is not enough.
        for name in crate::guard::UNIX_CRITICAL {
            let mut target = process(4321, Some(1), 1_000, 0);
            target.name = name.to_owned();
            assert!(
                crate::guard::protected_system_process(&target).is_some(),
                "not protected off Windows: {name}"
            );
        }

        // The match is on the whole executable name, not a substring, so an
        // agent is not protected for being called something similar.
        for ordinary in [
            "systemd-helper",
            "my-launchd",
            "initialise",
            "kernel_taskbar",
        ] {
            let mut target = process(4321, Some(1), 1_000, 501);
            target.name = ordinary.to_owned();
            assert!(
                crate::guard::protected_system_process(&target).is_none(),
                "an ordinary process was treated as critical: {ordinary}"
            );
        }
    }

    #[test]
    fn an_owner_the_platform_would_not_state_is_refused_before_any_signal() {
        // The failure this prevents: Windows reported uid zero for everything,
        // and an unresolved owner comparing equal to Topgent's own would make
        // every process on the machine look like its own to stop.
        let mut unknown = process(4242, Some(1), 1_000, 501);
        unknown.owner = topgent_collect::process::Owner::Unknown;
        assert!(matches!(
            guard().check(&unknown),
            Err(Refusal::Protected { .. })
        ));

        let mut blind = guard();
        blind.own_owner = topgent_collect::process::Owner::Unknown;
        let target = process(4242, Some(1), 1_000, 501);
        assert!(matches!(
            blind.check(&target),
            Err(Refusal::Protected { .. })
        ));

        // A different account is refused, and the same one is allowed.
        let mut other = process(4242, Some(1), 1_000, 501);
        other.owner = topgent_collect::process::Owner::Sid("S-1-5-21-1-2-3-1002".to_owned());
        assert!(other_guard().check(&other).is_err());
        let mut same = process(4242, Some(1), 1_000, 501);
        same.owner = topgent_collect::process::Owner::Sid("S-1-5-21-1-2-3-1001".to_owned());
        assert!(other_guard().check(&same).is_ok());
    }

    fn other_guard() -> Guard {
        Guard {
            own_pid: 900,
            parent_pid: Some(901),
            own_owner: topgent_collect::process::Owner::Sid("S-1-5-21-1-2-3-1001".to_owned()),
        }
    }

    #[test]
    fn tree_termination_is_deepest_first_and_accepts_already_exited_children() {
        let processes = [
            process(42, None, 1_000, 501),
            process(43, Some(42), 1_100, 501),
            process(44, Some(43), 1_200, 501),
            process(45, Some(42), 1_300, 501),
            process(99, None, 9_900, 501),
        ];
        let signaller = FakeSignaller {
            identities: RefCell::new(BTreeMap::from([
                (42, UnixMillis(1_000)),
                (43, UnixMillis(1_100)),
                (44, UnixMillis(1_200)),
            ])),
            sent: RefCell::new(Vec::new()),
            deny_pid: None,
        };
        assert_eq!(
            attempt_tree(&action(), &processes, &guard(), &signaller),
            Ok(Outcome::TreeStoppedGracefully)
        );
        assert_eq!(
            signaller
                .sent
                .borrow()
                .iter()
                .map(|(pid, _)| *pid)
                .collect::<Vec<_>>(),
            [44, 43, 42],
            "the absent child is harmless and the unrelated process is untouched"
        );
    }

    #[test]
    fn tree_preflight_refuses_protected_or_reused_descendants_before_any_signal() {
        let protected = [
            process(42, None, 1_000, 501),
            process(43, Some(42), 1_100, 0),
        ];
        let signaller = FakeSignaller {
            identities: RefCell::new(BTreeMap::from([
                (42, UnixMillis(1_000)),
                (43, UnixMillis(1_100)),
            ])),
            sent: RefCell::new(Vec::new()),
            deny_pid: None,
        };
        assert!(matches!(
            attempt_tree(&action(), &protected, &guard(), &signaller),
            Err(Refusal::Protected { .. })
        ));
        assert!(signaller.sent.borrow().is_empty());

        let reused = [
            process(42, None, 1_000, 501),
            process(43, Some(42), 1_100, 501),
        ];
        signaller
            .identities
            .borrow_mut()
            .insert(43, UnixMillis(8_800));
        assert!(matches!(
            attempt_tree(&action(), &reused, &guard(), &signaller),
            Err(Refusal::IdentityChanged { .. })
        ));
        assert!(signaller.sent.borrow().is_empty());
    }

    #[test]
    fn tree_signal_denial_is_an_explicit_partial_failure() {
        let processes = [
            process(42, None, 1_000, 501),
            process(43, Some(42), 1_100, 501),
            process(44, Some(43), 1_200, 501),
        ];
        let signaller = FakeSignaller {
            identities: RefCell::new(BTreeMap::from([
                (42, UnixMillis(1_000)),
                (43, UnixMillis(1_100)),
                (44, UnixMillis(1_200)),
            ])),
            sent: RefCell::new(Vec::new()),
            deny_pid: Some(43),
        };
        assert!(matches!(
            attempt_tree(&action(), &processes, &guard(), &signaller),
            Err(Refusal::Partial { signalled: 1, .. })
        ));
        assert_eq!(
            signaller.sent.borrow().as_slice(),
            [(44, Signal::Terminate), (43, Signal::Terminate)]
        );
    }
}
