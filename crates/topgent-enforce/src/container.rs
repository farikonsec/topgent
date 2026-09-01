//! Stopping an agent that runs as a container.
//!
//! A container is not a process, so the guarded path for one is separate rather
//! than bolted onto the process path. The complete runtime identity, the init
//! process's exact pid and start time, and the family are all rechecked
//! immediately before the runtime is asked to stop anything: an id that has
//! been recycled between the decision and the action is refused.

use crate::{Executed, ID, Outcome, Refusal};
use topgent_collect::Clock;
use topgent_collect::{emit, process};
use topgent_facts::{Claim, Confidence, Subject, UnixMillis};

/// Exact container identity authorised for one stop operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerAction {
    /// Full runtime container ID; names and truncated IDs are never accepted.
    pub container_id: String,
    /// Host init pid observed for the container.
    pub init_pid: u32,
    /// Start time paired with the init pid to prevent PID reuse.
    pub started_at: UnixMillis,
    /// Provenance-verified agent family.
    pub family: String,
}

/// Runtime boundary used by guarded container response.
pub trait ContainerController {
    /// Re-read the exact running container identity.
    fn identity(&self, container_id: &str) -> Option<ContainerAction>;

    /// Stop exactly this full container ID.
    ///
    /// # Errors
    ///
    /// Returns the runtime's sanitized refusal when stop fails.
    fn stop(&self, container_id: &str) -> Result<(), String>;
}

/// Docker controller using the caller's existing local socket authorization.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemDockerController;

/// Stop one provenance-verified agent container after rechecking its complete
/// runtime ID, init pid/start identity, and family.
#[must_use]
pub fn execute_container(
    action: &ContainerAction,
    controller: &dyn ContainerController,
    clock: &dyn Clock,
) -> Executed {
    let result = if topgent_collect::container::valid_container_id(&action.container_id) {
        match controller.identity(&action.container_id) {
            None => Err(Refusal::NotRunning),
            Some(found) if found != *action => Err(Refusal::Protected {
                why: "container identity changed after approval",
            }),
            Some(_) => controller
                .stop(&action.container_id)
                .map(|()| Outcome::ContainerStopped)
                .map_err(|detail| Refusal::Denied { detail }),
        }
    } else {
        Err(Refusal::Protected {
            why: "container identity is not one full 64-hex ID",
        })
    };
    let fact = emit(
        ID,
        &format!("stop container {}", action.container_id),
        Confidence::Certain,
        clock,
        Subject::Process {
            pid: action.init_pid,
            started_at: action.started_at,
        },
        Claim::ActionTaken {
            action: "stop_container".to_owned(),
            succeeded: result.is_ok(),
        },
    );
    Executed { result, fact }
}

impl ContainerController for SystemDockerController {
    fn identity(&self, container_id: &str) -> Option<ContainerAction> {
        if !topgent_collect::container::valid_container_id(container_id) {
            return None;
        }
        let processes = process::snapshot();
        topgent_collect::container::snapshot(&processes)
            .into_iter()
            .find(|container| container.id == container_id)
            .map(|container| ContainerAction {
                container_id: container.id,
                init_pid: container.init_pid,
                started_at: container.started_at,
                family: container.family.to_owned(),
            })
    }

    fn stop(&self, container_id: &str) -> Result<(), String> {
        if !topgent_collect::container::valid_container_id(container_id) {
            return Err("container identity is not one full 64-hex ID".to_owned());
        }
        // Resolved to a path the operating system owns, never through PATH.
        // This call does not merely read the estate: it hands a termination
        // request to whatever answers, so a substituted binary would be given
        // the kill switch.
        let output = topgent_collect::tool::DOCKER
            .command()
            .map_err(|error| error.to_string())?
            .args(["container", "stop", "--time", "5", container_id])
            .output()
            .map_err(|error| format!("docker container stop unavailable: {error}"))?;
        if output.status.success() {
            Ok(())
        } else {
            let detail = String::from_utf8_lossy(&output.stderr);
            Err(detail.trim().chars().take(512).collect())
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::{ContainerAction, ContainerController, Outcome, Refusal, execute_container};
    use std::cell::Cell;
    use topgent_collect::FixedClock;
    use topgent_facts::UnixMillis;

    struct FakeController {
        identity: Option<ContainerAction>,
        stopped: Cell<bool>,
    }

    impl ContainerController for FakeController {
        fn identity(&self, _container_id: &str) -> Option<ContainerAction> {
            self.identity.clone()
        }

        fn stop(&self, _container_id: &str) -> Result<(), String> {
            self.stopped.set(true);
            Ok(())
        }
    }

    fn action() -> ContainerAction {
        ContainerAction {
            container_id: "a".repeat(64),
            init_pid: 42,
            started_at: UnixMillis(7_000),
            family: "openhands".to_owned(),
        }
    }

    #[test]
    fn container_stop_rechecks_every_identity_field_before_runtime_control() {
        let approved = action();
        let controller = FakeController {
            identity: Some(approved.clone()),
            stopped: Cell::new(false),
        };
        let executed = execute_container(&approved, &controller, &FixedClock(9_000));
        assert_eq!(executed.result, Ok(Outcome::ContainerStopped));
        assert!(controller.stopped.get());
        assert_eq!(
            executed.fact.expect("action fact").claim().kind(),
            "action_taken"
        );

        for changed in [
            ContainerAction {
                init_pid: 43,
                ..approved.clone()
            },
            ContainerAction {
                started_at: UnixMillis(8_000),
                ..approved.clone()
            },
            ContainerAction {
                family: "decoy".to_owned(),
                ..approved.clone()
            },
        ] {
            let controller = FakeController {
                identity: Some(changed),
                stopped: Cell::new(false),
            };
            assert!(matches!(
                execute_container(&approved, &controller, &FixedClock(9_000)).result,
                Err(Refusal::Protected { .. })
            ));
            assert!(!controller.stopped.get());
        }

        let invalid = ContainerAction {
            container_id: "short-id".to_owned(),
            ..approved
        };
        let controller = FakeController {
            identity: Some(invalid.clone()),
            stopped: Cell::new(false),
        };
        assert!(matches!(
            execute_container(&invalid, &controller, &FixedClock(9_000)).result,
            Err(Refusal::Protected { .. })
        ));
        assert!(!controller.stopped.get());
    }
}
