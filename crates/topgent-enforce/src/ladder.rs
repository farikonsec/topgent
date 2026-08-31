//! The response ladder, and what this installation can honestly offer.
//!
//! Observe, alert, ask, block, stop. Each rung is answered against what the
//! host can actually do rather than against what the product can do in
//! principle: a response the installation cannot deliver is reported as a
//! capability mismatch instead of being offered and then failing, and one that
//! needs a person says so and waits. Approval and block never quietly degrade
//! to an alert, because an operator who asked for prevention would be told
//! prevention happened.

use crate::signal::windows_termination_available;

/// Enforcement points the current installation can genuinely provide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnforcementCapability {
    /// A matched action can be intercepted before it executes.
    pub can_intercept: bool,
    /// A running process can be terminated through the guarded kill path.
    pub can_terminate: bool,
}

impl EnforcementCapability {
    /// Current local capability: retrospective observation plus guarded
    /// termination, but no general pre-execution interception point.
    ///
    /// Termination is claimed on Windows only when the tool that performs it is
    /// actually present where the operating system keeps it. Advertising a
    /// response that cannot run would let the ladder promise an action it would
    /// then fail to deliver, which is worse than not offering it.
    ///
    /// Interception is measured the same way. It was a hardcoded `false`, which
    /// made `Block` and `Approval` refuse identically on every host and read as
    /// "this product does not do that", when on a Linux host with a privileged
    /// helper the truth is that it does.
    #[must_use]
    pub fn local() -> Self {
        Self {
            can_intercept: topgent_collect::intercept::probe().is_available(),
            can_terminate: cfg!(unix) || windows_termination_available(),
        }
    }
}

/// State of the explicit human decision required by approval or kill.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalState {
    /// Nobody has decided yet.
    Pending,
    /// A person allowed the action.
    Approved,
    /// A person denied the action.
    Denied,
    /// The request elapsed without a decision.
    Expired,
}

/// Honest result of evaluating one requested response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionOutcome {
    /// The rule did not match.
    NoAction,
    /// Evidence was recorded only.
    Observed,
    /// A notification should be raised.
    Alert,
    /// A user decision is required before continuing.
    AwaitingApproval,
    /// The intercepted operation may continue.
    Allowed,
    /// The intercepted operation was prevented.
    Blocked,
    /// The guarded termination path may now run.
    Terminate,
    /// The requested response cannot be delivered by the installed sensor.
    CapabilityMismatch,
}

impl DecisionOutcome {
    /// Stable report label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoAction => "no_action",
            Self::Observed => "observed",
            Self::Alert => "alert",
            Self::AwaitingApproval => "awaiting_approval",
            Self::Allowed => "allowed",
            Self::Blocked => "blocked",
            Self::Terminate => "terminate",
            Self::CapabilityMismatch => "capability_mismatch",
        }
    }
}

/// Evaluate the response ladder without performing an action.
///
/// Approval and block never silently degrade to alert. Kill always requires an
/// explicit local approval even when termination is available.
#[must_use]
pub const fn decide_response(
    matched: bool,
    mode: topgent_policy::ResponseMode,
    capability: EnforcementCapability,
    approval: Option<ApprovalState>,
) -> DecisionOutcome {
    use topgent_policy::ResponseMode;
    if !matched {
        return DecisionOutcome::NoAction;
    }
    match mode {
        ResponseMode::Observe => DecisionOutcome::Observed,
        ResponseMode::Alert => DecisionOutcome::Alert,
        ResponseMode::Approval if !capability.can_intercept => DecisionOutcome::CapabilityMismatch,
        ResponseMode::Approval => match approval {
            None | Some(ApprovalState::Pending) => DecisionOutcome::AwaitingApproval,
            Some(ApprovalState::Approved) => DecisionOutcome::Allowed,
            Some(ApprovalState::Denied | ApprovalState::Expired) => DecisionOutcome::Blocked,
        },
        ResponseMode::Block if capability.can_intercept => DecisionOutcome::Blocked,
        ResponseMode::Block => DecisionOutcome::CapabilityMismatch,
        ResponseMode::Kill if !capability.can_terminate => DecisionOutcome::CapabilityMismatch,
        ResponseMode::Kill => match approval {
            None | Some(ApprovalState::Pending) => DecisionOutcome::AwaitingApproval,
            Some(ApprovalState::Approved) => DecisionOutcome::Terminate,
            Some(ApprovalState::Denied | ApprovalState::Expired) => DecisionOutcome::NoAction,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{ApprovalState, DecisionOutcome, EnforcementCapability, decide_response};
    use topgent_policy::ResponseMode;

    fn local_capability() -> EnforcementCapability {
        EnforcementCapability::local()
    }
    const INTERCEPT: EnforcementCapability = EnforcementCapability {
        can_intercept: true,
        can_terminate: true,
    };
    const TERMINATE: EnforcementCapability = EnforcementCapability {
        can_intercept: false,
        can_terminate: true,
    };

    #[test]
    fn retrospective_modes_are_always_honest() {
        assert_eq!(
            decide_response(true, ResponseMode::Observe, local_capability(), None),
            DecisionOutcome::Observed
        );
        assert_eq!(
            decide_response(true, ResponseMode::Alert, local_capability(), None),
            DecisionOutcome::Alert
        );
        assert_eq!(
            decide_response(
                false,
                ResponseMode::Kill,
                local_capability(),
                Some(ApprovalState::Approved)
            ),
            DecisionOutcome::NoAction
        );
    }

    #[test]
    fn approval_and_block_never_pretend_retrospective_visibility_is_prevention() {
        assert_eq!(
            decide_response(true, ResponseMode::Approval, local_capability(), None),
            DecisionOutcome::CapabilityMismatch
        );
        assert_eq!(
            decide_response(true, ResponseMode::Block, local_capability(), None),
            DecisionOutcome::CapabilityMismatch
        );
        assert_eq!(
            decide_response(true, ResponseMode::Block, INTERCEPT, None),
            DecisionOutcome::Blocked
        );
    }

    #[test]
    fn approval_timeout_and_denial_are_fail_closed_at_an_interception_point() {
        for state in [ApprovalState::Denied, ApprovalState::Expired] {
            assert_eq!(
                decide_response(true, ResponseMode::Approval, INTERCEPT, Some(state)),
                DecisionOutcome::Blocked
            );
        }
        assert_eq!(
            decide_response(
                true,
                ResponseMode::Approval,
                INTERCEPT,
                Some(ApprovalState::Approved),
            ),
            DecisionOutcome::Allowed
        );
    }

    #[test]
    fn kill_requires_explicit_approval_and_real_termination_capability() {
        assert_eq!(
            decide_response(true, ResponseMode::Kill, TERMINATE, None),
            DecisionOutcome::AwaitingApproval
        );
        assert_eq!(
            decide_response(
                true,
                ResponseMode::Kill,
                TERMINATE,
                Some(ApprovalState::Approved),
            ),
            DecisionOutcome::Terminate
        );
        assert_eq!(
            decide_response(
                true,
                ResponseMode::Kill,
                EnforcementCapability {
                    can_intercept: false,
                    can_terminate: false,
                },
                Some(ApprovalState::Approved),
            ),
            DecisionOutcome::CapabilityMismatch
        );
    }

    #[test]
    fn a_ladder_that_cannot_intercept_says_so_rather_than_pretending_either_way() {
        // Block and Approval need a point where the operating system pauses the
        // request and asks. Where there is none, refusing is correct; claiming
        // the rung ran would be a response that never happened.
        let capability = local_capability();
        let probe = topgent_collect::intercept::probe();
        assert_eq!(
            capability.can_intercept,
            probe.is_available(),
            "the ladder and the probe disagree about interception"
        );

        for mode in [ResponseMode::Block, ResponseMode::Approval] {
            let outcome = decide_response(true, mode, capability, Some(ApprovalState::Approved));
            if probe.is_available() {
                assert_ne!(outcome, DecisionOutcome::CapabilityMismatch);
            } else {
                assert_eq!(
                    outcome,
                    DecisionOutcome::CapabilityMismatch,
                    "{mode:?} claimed an interception point this host does not have"
                );
            }
        }

        // And the refusal is explained, so an operator can act on it instead of
        // reading it as "this product does not do that".
        assert!(
            probe.detail().len() > 20,
            "an unactionable answer: {}",
            probe.detail()
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_offers_termination_only_when_the_tool_that_performs_it_is_present() {
        // Advertising a response that cannot run would let the ladder promise
        // an action it would then fail to deliver, which is worse than not
        // offering it at all.
        let available = topgent_collect::tool::TASKKILL.resolve().is_some();
        assert_eq!(local_capability().can_terminate, available);

        let outcome = decide_response(
            true,
            ResponseMode::Kill,
            local_capability(),
            Some(ApprovalState::Approved),
        );
        assert_eq!(
            outcome,
            if available {
                DecisionOutcome::Terminate
            } else {
                DecisionOutcome::CapabilityMismatch
            }
        );

        // Termination being possible never removes the requirement for a
        // person to have said so.
        assert_eq!(
            decide_response(true, ResponseMode::Kill, local_capability(), None),
            if available {
                DecisionOutcome::AwaitingApproval
            } else {
                DecisionOutcome::CapabilityMismatch
            }
        );
    }
}
