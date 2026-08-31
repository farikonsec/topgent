//! One parsed socket.
//!
//! Fields a platform does not state are `None` and never a default. A zero byte
//! count means the kernel counted zero; an absent one means it does not count.

use topgent_facts::ByteCounters;
use topgent_facts::Direction;
use topgent_facts::Protocol;
use topgent_facts::UnixMillis;

/// One parsed socket row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketRow {
    /// Which protocol. Not every one names a peer, and the protocol is what
    /// says whether an absent host is unobservable or unread.
    pub protocol: Protocol,
    /// Owning process id.
    pub pid: u32,
    /// Peer host, or the bind address when listening.
    pub host: String,
    /// Peer port, or the bound port when listening.
    pub port: u16,
    /// Which way it goes.
    pub direction: Direction,
    /// When the operating system recorded this connection being created.
    ///
    /// `None` on platforms whose socket listing carries no such timestamp. It
    /// is never derived by comparing sweeps: that would be an inference about
    /// a connection Topgent may simply have missed.
    pub opened_at: Option<UnixMillis>,
    /// Traffic the kernel has accounted to this connection, where it counts.
    pub bytes: Option<ByteCounters>,
}
