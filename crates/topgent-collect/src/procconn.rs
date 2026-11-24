//! The Linux process connector: the kernel's own fork, exec and exit feed.
//!
//! A snapshot of the process table cannot see a process that starts and ends
//! between two sweeps, and most of what an agent runs does exactly that. The
//! process connector is a netlink socket on which the kernel announces every
//! fork, exec and exit as it happens. Kernels that restrict it require
//! `CAP_NET_ADMIN` to subscribe, which is why it is read by a small separate
//! helper and not by the interface.
//!
//! This module is the part that needs no privilege: the wire format, parsed
//! as hostile input, and the per-CPU sequence check that turns dropped
//! messages into a counted loss rather than silence. The layouts are the
//! kernel's: `linux/netlink.h`, `linux/connector.h` and `linux/cn_proc.h`.

use std::collections::BTreeMap;

/// `CN_IDX_PROC` and `CN_VAL_PROC`: the connector's process-event channel.
pub const CN_IDX_PROC: u32 = 1;
const CN_VAL_PROC: u32 = 1;
/// `NLMSG_DONE`, the type the connector uses for every message.
const NLMSG_DONE: u16 = 3;
/// `PROC_CN_MCAST_LISTEN`.
const MCAST_LISTEN: u32 = 1;

const FORK: u32 = 0x0000_0001;
const EXEC: u32 = 0x0000_0002;
const EXIT: u32 = 0x8000_0000;
const COMM: u32 = 0x0000_0200;

const NETLINK_HEADER: usize = 16;
const CONNECTOR_HEADER: usize = 20;
/// `what`, `cpu` and the 64-bit timestamp come before the event's own fields.
const EVENT_HEADER: usize = 16;

/// What happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A task was created. It is a new process when `child_pid` equals
    /// `child_tgid`, and a new thread otherwise.
    Fork {
        /// The process that created it.
        parent_tgid: u32,
        /// The new task's id.
        child_pid: u32,
        /// The process it belongs to.
        child_tgid: u32,
    },
    /// A process replaced its program.
    Exec {
        /// The process.
        tgid: u32,
    },
    /// A task ended. It is the process ending when `pid` equals `tgid`.
    Exit {
        /// The task.
        pid: u32,
        /// The process it belonged to.
        tgid: u32,
        /// The exit status the kernel recorded.
        code: u32,
    },
    /// A process renamed itself. `exec` does this, with the new program's
    /// name, before the exec event itself: the one way to learn the name of
    /// a process that exits before `/proc` can be read.
    Comm {
        /// The process.
        tgid: u32,
        /// The new name, NUL-padded, at most 16 bytes as the kernel keeps it.
        name: [u8; 16],
    },
    /// Any other kind (an id change, a thread's rename, a trace). Not used, but it
    /// still carries a sequence number, and skipping it before the loss
    /// check would make every one of them look like a dropped message.
    Other,
}

/// One event, as the kernel numbered and timed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcEvent {
    /// What happened.
    pub kind: Kind,
    /// Which CPU reported it; sequence numbers are per CPU.
    pub cpu: u32,
    /// The CPU's message number.
    pub seq: u32,
    /// When, in nanoseconds of the kernel's monotonic clock.
    pub timestamp_ns: u64,
}

impl ProcEvent {
    /// Whether this is about a whole process rather than one of its threads.
    #[must_use]
    pub const fn is_process_level(&self) -> bool {
        match self.kind {
            Kind::Fork {
                child_pid,
                child_tgid,
                ..
            } => child_pid == child_tgid,
            // A thread's rename was already turned into `Other` by the parser.
            Kind::Exec { .. } | Kind::Comm { .. } => true,
            Kind::Exit { pid, tgid, .. } => pid == tgid,
            Kind::Other => false,
        }
    }

    /// The name a rename carries, up to its first NUL, when it is text.
    #[must_use]
    pub fn name(&self) -> Option<String> {
        let Kind::Comm { name, .. } = self.kind else {
            return None;
        };
        let end = name
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(name.len());
        let text = std::str::from_utf8(name.get(..end)?).ok()?;
        (!text.is_empty() && !text.chars().any(char::is_control)).then(|| text.to_owned())
    }
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_ne_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}

/// Every fork, exec and exit in one datagram.
///
/// Anything short or mislabelled is skipped; a kind this sensor does not use
/// comes back as [`Kind::Other`] so its sequence number is still counted. A
/// length that runs past the end stops the walk, and a zero length cannot make
/// it spin.
#[must_use]
pub fn parse_datagram(bytes: &[u8]) -> Vec<ProcEvent> {
    let mut events = Vec::new();
    let mut at = 0_usize;
    while let Some(length) = u32_at(bytes, at) {
        let Ok(length) = usize::try_from(length) else {
            break;
        };
        let Some(message) = length
            .checked_add(at)
            .and_then(|end| bytes.get(at..end))
            .filter(|_| length >= NETLINK_HEADER)
        else {
            break;
        };
        if let Some(event) = parse_message(message) {
            events.push(event);
        }
        // Netlink messages are aligned to four bytes.
        let Some(next) = length
            .checked_add(3)
            .map(|n| n & !3)
            .and_then(|n| at.checked_add(n))
        else {
            break;
        };
        at = next;
    }
    events
}

fn parse_message(message: &[u8]) -> Option<ProcEvent> {
    let connector = NETLINK_HEADER;
    if u16_at(message, 4)? != NLMSG_DONE
        || u32_at(message, connector)? != CN_IDX_PROC
        || u32_at(message, connector + 4)? != CN_VAL_PROC
    {
        return None;
    }
    let seq = u32_at(message, connector + 8)?;
    let payload = usize::from(u16_at(message, connector + 16)?);
    let event = message.get(connector + CONNECTOR_HEADER..)?;
    let event = event.get(..payload)?;
    let what = u32_at(event, 0)?;
    let cpu = u32_at(event, 4)?;
    let timestamp_ns = u64_at(event, 8)?;
    let data = EVENT_HEADER;
    let kind = match what {
        FORK => Kind::Fork {
            parent_tgid: u32_at(event, data + 4)?,
            child_pid: u32_at(event, data + 8)?,
            child_tgid: u32_at(event, data + 12)?,
        },
        EXEC => Kind::Exec {
            tgid: u32_at(event, data + 4)?,
        },
        EXIT => Kind::Exit {
            pid: u32_at(event, data)?,
            tgid: u32_at(event, data + 4)?,
            code: u32_at(event, data + 8)?,
        },
        COMM => {
            let pid = u32_at(event, data)?;
            let tgid = u32_at(event, data + 4)?;
            let name: [u8; 16] = event.get(data + 8..data + 24)?.try_into().ok()?;
            // A thread renaming itself is not the process being renamed.
            if pid == tgid {
                Kind::Comm { tgid, name }
            } else {
                Kind::Other
            }
        }
        _ => Kind::Other,
    };
    Some(ProcEvent {
        kind,
        cpu,
        seq,
        timestamp_ns,
    })
}

/// The request that asks the kernel to start sending events to `pid`'s socket.
#[must_use]
pub fn subscribe_message(pid: u32) -> Vec<u8> {
    let mut message = Vec::with_capacity(40);
    message.extend(40_u32.to_ne_bytes());
    message.extend(NLMSG_DONE.to_ne_bytes());
    message.extend(0_u16.to_ne_bytes());
    message.extend(0_u32.to_ne_bytes());
    message.extend(pid.to_ne_bytes());
    message.extend(CN_IDX_PROC.to_ne_bytes());
    message.extend(CN_VAL_PROC.to_ne_bytes());
    message.extend(0_u32.to_ne_bytes());
    message.extend(0_u32.to_ne_bytes());
    message.extend(4_u16.to_ne_bytes());
    message.extend(0_u16.to_ne_bytes());
    message.extend(MCAST_LISTEN.to_ne_bytes());
    message
}

/// Counts messages the socket dropped, from gaps in each CPU's numbering.
#[derive(Debug, Default)]
pub struct SequenceTracker {
    last: BTreeMap<u32, u32>,
    lost: u64,
}

impl SequenceTracker {
    /// Records one message's number and returns how many were missed before it.
    ///
    /// The first number seen from a CPU sets its baseline. A number that goes
    /// backwards is a reset of the kernel's counter, not a loss.
    pub fn observe(&mut self, cpu: u32, seq: u32) -> u64 {
        let missed = match self.last.insert(cpu, seq) {
            Some(previous) if seq > previous => u64::from(seq - previous - 1),
            _ => 0,
        };
        self.lost = self.lost.saturating_add(missed);
        missed
    }

    /// Everything counted as lost so far.
    #[must_use]
    pub const fn lost(&self) -> u64 {
        self.lost
    }
}

/// A subscribed process-connector socket.
///
/// Opening one needs `CAP_NET_ADMIN` where the kernel restricts it. Receives
/// time out after a second, so a quiet host still lets the reader report its
/// own health.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct Connector {
    fd: std::os::fd::OwnedFd,
}

#[cfg(target_os = "linux")]
impl Connector {
    /// Opens the socket and asks the kernel to start sending.
    ///
    /// # Errors
    ///
    /// The kernel's refusal, most often `EPERM` without `CAP_NET_ADMIN`.
    pub fn open() -> std::io::Result<Self> {
        use rustix::net::{AddressFamily, SendFlags, SocketFlags, SocketType, netlink, sockopt};
        let fd = rustix::net::socket_with(
            AddressFamily::NETLINK,
            SocketType::DGRAM,
            SocketFlags::CLOEXEC,
            Some(netlink::CONNECTOR),
        )?;
        // A larger buffer rides out a burst of process creation. If the
        // kernel refuses the size, the default stands and any loss that
        // follows is still counted.
        if sockopt::set_socket_recv_buffer_size(&fd, 8 << 20).is_err() {
            // The default buffer stands.
        }
        sockopt::set_socket_timeout(
            &fd,
            sockopt::Timeout::Recv,
            Some(std::time::Duration::from_secs(1)),
        )?;
        let pid = std::process::id();
        rustix::net::bind(&fd, &netlink::SocketAddrNetlink::new(pid, CN_IDX_PROC))?;
        rustix::net::send(&fd, &subscribe_message(pid), SendFlags::empty())?;
        Ok(Self { fd })
    }

    /// Receives one datagram into `buffer` and returns its length.
    ///
    /// # Errors
    ///
    /// `WouldBlock` or `TimedOut` after a quiet second, and `ENOBUFS` when
    /// the socket overflowed and messages were dropped.
    pub fn recv(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let (received, _) = rustix::net::recv(&self.fd, buffer, rustix::net::RecvFlags::empty())?;
        Ok(received)
    }
}
