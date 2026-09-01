//! `topgent stop` — the one command that changes something.

use crate::USAGE;
use crate::output::now_ms;
use topgent_collect::SystemClock;
use topgent_collect::process;
use topgent_enforce::Action;
use topgent_enforce::ContainerAction;
use topgent_enforce::Guard;
use topgent_enforce::SystemDockerController;
use topgent_enforce::SystemSignaller;
use topgent_enforce::execute;
use topgent_enforce::execute_container;
use topgent_journal::Journal;

/// Stop one agent, with the guards the enforcement crate owns.
pub(crate) fn stop_command(args: &[String]) -> i32 {
    let Some(pid) = args.get(1).and_then(|p| p.parse::<u32>().ok()) else {
        eprintln!("topgent stop: needs a pid\n\n{USAGE}");
        return 2;
    };
    let processes = process::snapshot();
    let Some(target) = processes.iter().find(|p| p.pid == pid) else {
        eprintln!("topgent stop: no process {pid}");
        return 1;
    };

    let label = target.family.unwrap_or("unrecognised process");

    // Asked before the prompt, not after it. The enforcement crate refuses a
    // protected process at the point of signalling, but a prompt reading "this
    // would stop systemd, re-run with --yes" invites an operator to try
    // something that is never going to happen, and says the tool would do it.
    if let Some(why) = topgent_enforce::protected_system_process(target) {
        eprintln!("topgent stop: refusing pid {pid} ({}): {why}.", target.exe);
        return 1;
    }

    if !args.iter().any(|a| a == "--yes") {
        // The owner is asked for by name here rather than taken from the
        // sweep's cheap field, which is a placeholder on Windows. A consent
        // prompt that says "started by 0" is asking the operator to approve
        // something it has not actually told them.
        let owner = process::owner_of(pid);
        eprintln!(
            "topgent stop: this would stop {label} (pid {pid}, {}), owned by {}.",
            target.exe,
            owner.label()
        );
        eprintln!("Unsaved work in that process will be lost. Re-run with --yes to go ahead.");
        return 3;
    }

    let container = topgent_collect::container::snapshot(&processes)
        .into_iter()
        .find(|container| container.init_pid == pid && Some(container.family) == target.family);
    let done = container.map_or_else(
        || {
            execute(
                &Action::Kill {
                    pid,
                    started_at: target.started_at,
                },
                &Guard::current(),
                &SystemSignaller,
                &SystemClock,
            )
        },
        |container| {
            execute_container(
                &ContainerAction {
                    container_id: container.id,
                    init_pid: pid,
                    started_at: target.started_at,
                    family: label.to_owned(),
                },
                &SystemDockerController,
                &SystemClock,
            )
        },
    );
    let journal = Journal::open_default();
    match done.result {
        Ok(outcome) => {
            let _ = journal.record_action(now_ms(), pid, label, outcome.label());
            println!("{label} (pid {pid}): {}", outcome.label());
            0
        }
        Err(refusal) => {
            let _ = journal.record_action(now_ms(), pid, label, &refusal.to_string());
            eprintln!("{label} (pid {pid}): {refusal}");
            1
        }
    }
}
