//! Tying a socket to the process that owns it.
//!
//! Milestone M4 of `docs/MAJOR_UPGRADE_RESEARCH_PLAN.md`, and the shape
//! decision D3 asks for: the trait is ours, so a backend behind it can be
//! replaced without touching anything that reads a fact.
//!
//! # There is no backend behind it today, on purpose
//!
//! `rustnet-host` was evaluated, adapted, and validated against live socket
//! tables on Linux and macOS. It was then dropped. The full record is in
//! `docs/REUSE-RUSTNET.md`; the short version is that it reaches Topgent only
//! through `rustnet-core`, whose mandatory dependencies include `ring`, whose
//! build script needs `clang`, which a stock Rust install on Windows does not
//! have. A cross-platform security tool does not acquire a C-toolchain
//! requirement for a crypto library it never calls.
//!
//! What it would have bought was speed, not accuracy. `ss -p`, `lsof -i` and
//! `netstat -ano` already return the kernel's own pairing of a socket with its
//! owning process, which is the same evidence by a different route.
//!
//! The trait and [`topgent_facts::MatchBasis`] stay because they are the
//! durable half: they are what lets a socket fact state how its owner was
//! established, whoever establishes it.

use std::net::SocketAddr;

use topgent_facts::{MatchBasis, Protocol};

/// The socket being asked about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SocketKey {
    /// Which protocol the socket carries.
    pub protocol: Protocol,
    /// Local address and port.
    pub local: SocketAddr,
    /// Peer address and port. The unspecified address for a listener.
    pub remote: SocketAddr,
}

/// Who owns a socket, and on what basis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketOwner {
    /// Process id.
    pub pid: u32,
    /// Process name as the operating system reports it.
    pub name: String,
    /// Parent process id, where the backend resolved one.
    pub parent_pid: Option<u32>,
    /// Numeric owner, where the platform provides one.
    pub uid: Option<u32>,
    /// Absolute executable path, where it was readable.
    ///
    /// `None` is a real answer: the process may have exited between the socket
    /// listing and the lookup, and inventing a path from the process name is
    /// how a report names a binary that was never on disk.
    pub executable: Option<String>,
    /// How the socket was tied to this process.
    pub basis: MatchBasis,
}

/// Whether the backend is on its best path, and why not when it is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttributionHealth {
    /// The backend is using the best method this host allows.
    ///
    /// Not a completeness claim. None of the backends behind this trait expose
    /// per-interval loss accounting, so by `docs/NORMATIVE-CLAIMS.md` §3.7 none
    /// of them may ever be described as complete, however healthy they are.
    Best,
    /// The backend fell back, with the reason it gives.
    Degraded {
        /// What the backend said, verbatim.
        reason: String,
    },
    /// No backend is available on this host.
    Unavailable {
        /// Why.
        reason: String,
    },
}

/// A source of socket ownership.
pub trait ProcessAttributor: Send + Sync {
    /// Who owns this socket, when the backend can say.
    fn owner_of(&self, key: &SocketKey) -> Option<SocketOwner>;

    /// The name of the method in use, for the report.
    fn method(&self) -> &str;

    /// Whether the backend is degraded.
    fn health(&self) -> AttributionHealth;

    /// Refreshes any cached socket table.
    ///
    /// # Errors
    ///
    /// Returns the backend's reason when the refresh failed. A stale table is
    /// worse than a reported failure, because it attributes today's socket to
    /// yesterday's process.
    fn refresh(&self) -> Result<(), String> {
        Ok(())
    }
}
