//! One thing a process did, as the rules read it.
//!
//! A happening is either a syscall the Audit log recorded or an exec the
//! process sensor saw. Its fields come from the call itself (`evt.*`, `fd.*`)
//! and from process history as of that moment (`proc.*`, `user.*`,
//! `container.*`). Only fields on Topgent's supplied list are answered; any
//! other is unknown by construction, so no rule can pass or fail on a field
//! nothing collected.

use std::collections::BTreeMap;

use topgent_behaviour::event::{Event, Field};
use topgent_collect::observed::ObservedSyscall;
use topgent_collect::process_events::LifecycleEvent;
use topgent_core::lineage::{Lineage, ProcessKey};
use topgent_facts::UnixMillis;

use super::invocations::Invocations;
use super::{process, syscall};

/// What every happening in one sweep is read against.
pub(crate) struct Context<'a> {
    /// Process history, for the actor and its ancestors.
    pub lineage: &'a Lineage,
    /// Account names by user id.
    pub users: &'a BTreeMap<u32, String>,
    /// The host's pid namespace: a process in it is not in a container.
    pub host_pid_namespace: Option<u64>,
    /// Exec arguments, in memory only.
    pub invocations: &'a Invocations,
    /// A running process's pid namespace, for an actor history does not hold.
    pub namespace_of: &'a dyn Fn(u32) -> Option<u64>,
    /// A running process's container id, read from its cgroup.
    pub container_of: &'a dyn Fn(u32) -> Option<String>,
    /// What the container runtime said about a container, by full id.
    pub runtime_of: &'a dyn Fn(
        &str,
    ) -> Option<
        std::sync::Arc<topgent_collect::container_context::ContainerContext>,
    >,
    /// Ancestry rebuilt from the audit stream, for short-lived processes the
    /// process sensor never saw.
    pub audit: &'a super::audit_tree::AuditTree,
}

/// What happened.
#[derive(Clone, Copy)]
pub(crate) enum Happening<'a> {
    /// A syscall the Audit log recorded.
    Syscall(&'a ObservedSyscall),
    /// An exec the process sensor saw.
    Exec(&'a LifecycleEvent),
}

impl Happening<'_> {
    /// The process that acted.
    pub(crate) const fn pid(&self) -> u32 {
        match self {
            Self::Syscall(call) => call.event.pid,
            Self::Exec(exec) => exec.pid,
        }
    }

    /// When, in the start-time base.
    pub(crate) const fn at(&self) -> UnixMillis {
        match self {
            Self::Syscall(call) => call.lineage_at,
            Self::Exec(exec) => exec.at,
        }
    }
}

/// A happening with its actor placed in process history.
pub(crate) struct RuleEvent<'a> {
    pub happening: Happening<'a>,
    pub actor: Option<ProcessKey>,
    pub ctx: &'a Context<'a>,
}

impl<'a> RuleEvent<'a> {
    pub(crate) fn new(happening: Happening<'a>, ctx: &'a Context<'a>) -> Self {
        let actor = match happening {
            Happening::Exec(exec) => exec
                .started_at
                .map(|started_at| ProcessKey {
                    pid: exec.pid,
                    started_at,
                })
                .filter(|key| ctx.lineage.get(*key).is_some())
                .or_else(|| topgent_core::attributed::actor_at(ctx.lineage, exec.pid, exec.at)),
            Happening::Syscall(_) => {
                topgent_core::attributed::actor_at(ctx.lineage, happening.pid(), happening.at())
            }
        };
        Self {
            happening,
            actor,
            ctx,
        }
    }
}

impl Event for RuleEvent<'_> {
    fn field(&self, name: &str, arg: Option<&str>) -> Field {
        if !topgent_behaviour::fields::is_provided(name) {
            return Field::Unknown;
        }
        if name.starts_with("evt.") || name.starts_with("fd.") {
            syscall::field(self, name)
        } else {
            process::field(self, name, arg)
        }
    }
}

/// A known value.
pub(super) fn value(text: impl Into<String>) -> Field {
    Field::Value(text.into())
}

/// A value if there is one, unknown otherwise.
pub(super) fn known(text: Option<String>) -> Field {
    text.map_or(Field::Unknown, Field::Value)
}

/// `true` or `false`, as the rules compare booleans.
pub(super) fn flag(on: bool) -> Field {
    value(if on { "true" } else { "false" })
}
