//! The socket the frames come off.
//!
//! # Why not libpcap
//!
//! Every capture tool worth borrowing from is built on libpcap, and this one
//! is not, for three reasons that all point the same way.
//!
//! It is a C library that has to be present with its headers at build time.
//! Requiring that turns "clone and build" into "clone, install a development
//! package, and build" on the machines this is meant to run on, and a security
//! tool nobody can build is a security tool nobody runs.
//!
//! It is linked, which means its parsing runs in this process with this
//! process's privileges. This crate forbids unsafe code, and a binding to a C
//! packet parser is unsafe code with a Rust name on it.
//!
//! And it is not needed. Linux hands raw frames to an ordinary socket, which
//! `socket2` opens safely, which needs exactly the one capability this build
//! already asks for by name. What libpcap adds beyond that is portability to
//! platforms where the capture offer is an install rather than a permission
//! anyway.
//!
//! # What is borrowed
//!
//! The shape. A bounded read loop feeding a parser feeding an aggregator is
//! Sniffnet's structure and every other capture tool's, because it is the one
//! that keeps a slow consumer from becoming a dropped packet. None of their
//! code is here.
//!
//! # The read is where the privacy promise is kept
//!
//! The buffer is [`SNAP`] bytes and the kernel discards the rest of each
//! frame. A payload is not filtered out further along, and it is not discarded
//! by a parser that could be changed later to keep it: it never enters the
//! process. That is the same guarantee a capture tool's snapshot length gives,
//! made by the size of an array rather than by a configuration value.

use crate::CollectError;

/// How much of each frame is read.
///
/// Enough for a link header, the longest internet header this parses, and a
/// full TCP header with options. Not enough for anything that could be called
/// content: what falls past this end is dropped by the kernel, not by us.
pub const SNAP: usize = 256;

/// How long a read waits before returning with nothing.
///
/// Short enough that a stop request is honoured promptly, long enough that an
/// idle wire does not spin.
pub const READ_TIMEOUT_MS: u64 = 250;

/// What one read produced.
#[derive(Debug)]
pub enum Frame {
    /// This many bytes were read into the buffer.
    Read(usize),
    /// Nothing arrived before the timeout, which is the ordinary state of a
    /// quiet wire and not a failure.
    Idle,
    /// The socket will not produce anything further.
    Ended {
        /// What went wrong.
        detail: String,
    },
}

/// A socket delivering every frame this host's interfaces carry.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct Wire {
    socket: socket2::Socket,
}

/// Every capture handle this host needs, which on Linux is one.
///
/// A packet socket sees every interface at once, loopback included, so one
/// handle is the whole machine. macOS has no such device and needs one handle
/// per interface, which is why callers take a list rather than a handle.
///
/// # Errors
///
/// Whatever [`Wire::open`] returns.
#[cfg(target_os = "linux")]
pub fn open_all() -> Result<Vec<Wire>, CollectError> {
    Ok(vec![Wire::open()?])
}

#[cfg(target_os = "linux")]
impl Wire {
    /// Opens the socket, or says why it could not be opened.
    ///
    /// # Errors
    ///
    /// [`CollectError::Denied`] where the capability is absent, which is the
    /// expected answer on a host where the grant has not been made or has been
    /// made and the process not yet restarted. Anything else is
    /// [`CollectError::Unavailable`].
    pub fn open() -> Result<Self, CollectError> {
        // `ETH_P_ALL` in network byte order, which is what a packet socket
        // wants as its protocol. The constant is written out rather than
        // pulled from a C header binding, which would be the only such binding
        // in the crate.
        let all = i32::from(0x0003_u16.to_be());
        let socket = socket2::Socket::new(
            socket2::Domain::PACKET,
            socket2::Type::RAW,
            Some(socket2::Protocol::from(all)),
        )
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::PermissionDenied => CollectError::Denied {
                what: "capturing packets needs a capability this process does not hold".to_owned(),
            },
            _ => CollectError::Unavailable {
                what: format!("a packet socket could not be opened: {error}"),
            },
        })?;
        socket
            .set_read_timeout(Some(std::time::Duration::from_millis(READ_TIMEOUT_MS)))
            .map_err(|error| CollectError::Unavailable {
                what: format!("the packet socket would not take a read timeout: {error}"),
            })?;
        Ok(Self { socket })
    }

    /// What sits at the front of every frame this handle produces.
    #[must_use]
    pub const fn link(&self) -> super::packet::LinkKind {
        // A packet socket hands over the link header, and every interface this
        // reads from on Linux writes an Ethernet one -- loopback included,
        // which writes a fourteen-byte header of zeroes rather than none.
        super::packet::LinkKind::Ethernet
    }

    /// Reads at most one frame, waiting no longer than [`READ_TIMEOUT_MS`].
    ///
    /// Never returns an error. A timeout and an interrupted read are the two
    /// most common outcomes on a live wire and neither is a problem, so they
    /// are answers rather than errors; only a socket that has genuinely
    /// stopped working ends the loop.
    pub fn read(&self, buffer: &mut [u8]) -> Frame {
        use std::io::Read as _;
        match (&self.socket).read(buffer) {
            Ok(0) => Frame::Idle,
            Ok(read) => Frame::Read(read),
            Err(error) => match error.kind() {
                std::io::ErrorKind::WouldBlock
                | std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::Interrupted => Frame::Idle,
                _ => Frame::Ended {
                    detail: format!("the packet socket stopped: {error}"),
                },
            },
        }
    }
}

/// One interface's worth of frames, on macOS and Windows.
///
/// # Building this
///
/// macOS needs nothing: libpcap and its headers ship in the system SDK.
/// Windows needs the Npcap SDK, which is a zip of headers and import
/// libraries, on the build machine only. Point the linker at it before
/// building:
///
/// ```text
/// $env:LIB = "$env:USERPROFILE\npcap-sdk\Lib\ARM64;" + $env:LIB
/// ```
///
/// The SDK is not the driver. The driver is the operator's to install, from
/// Npcap's own signed installer, and the capture offer says so on a machine
/// that lacks it.
///
/// # Why libpcap here and not on Linux
///
/// The reasons for avoiding it on Linux do not hold on a Mac. It is not an
/// extra thing to install: macOS ships libpcap and its headers in the system
/// SDK, so a build that links it needs nothing a Mac does not already have.
/// And there is no unprivileged alternative: capture goes through `/dev/bpf*`,
/// which needs `ioctl` to bind to an interface, which needs unsafe code this
/// crate forbids. Writing that by hand to avoid a library that is already on
/// every Mac would be effort spent making the tool worse.
///
/// The unsafe stays inside the library, where it is reviewed by more people
/// than will ever read this file.
///
/// # One handle per interface
///
/// There is no device that means "all of them" on macOS, so there is a handle
/// and a thread for each. They all feed one accumulator, so a caller sees the
/// same picture the single Linux handle gives.
#[cfg(any(target_os = "macos", windows))]
pub struct Wire {
    handle: pcap::Capture<pcap::Active>,
    link: super::packet::LinkKind,
}

#[cfg(any(target_os = "macos", windows))]
impl std::fmt::Debug for Wire {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The handle itself has no useful debug form and holds a live
        // capture; the link type is what a reader needs.
        f.debug_struct("Wire")
            .field("link", &self.link)
            .finish_non_exhaustive()
    }
}

/// Most interfaces opened at once.
///
/// A Mac with more than this has virtual interfaces nobody is watching agents
/// on, and a thread apiece is a cost with no finding behind it.
#[cfg(any(target_os = "macos", windows))]
const MAX_DEVICES: usize = 8;

#[cfg(any(target_os = "macos", windows))]
impl Wire {
    /// Opens the default interface, to answer whether capture works at all.
    ///
    /// # Errors
    ///
    /// [`CollectError::Denied`] where the capture devices cannot be opened,
    /// which is what an account outside the `access_bpf` group sees.
    pub fn open() -> Result<Self, CollectError> {
        let device = pcap::Device::lookup()
            .map_err(|error| CollectError::Unavailable {
                what: format!("no capture device could be looked up: {error}"),
            })?
            .ok_or_else(|| CollectError::Unavailable {
                what: "this machine reports no capture device".to_owned(),
            })?;
        Self::open_device(device)
    }

    /// Opens every interface worth reading.
    ///
    /// # Errors
    ///
    /// [`CollectError::Denied`] where nothing could be opened and a device
    /// refused us, and [`CollectError::Unavailable`] where there was nothing
    /// to open. A device that fails while others succeed is skipped: one
    /// unreadable virtual interface must not cost the whole capture.
    pub fn open_all() -> Result<Vec<Self>, CollectError> {
        let devices = pcap::Device::list().map_err(|error| CollectError::Unavailable {
            what: format!("the capture devices could not be listed: {error}"),
        })?;
        // Chosen, not taken in order. A Mac lists a dozen interfaces and most
        // of them carry nothing: tunnels with no address, Apple Wireless
        // Direct, `gif0` and `stf0`. Taking the first eight missed `lo0`
        // entirely, which is where every loopback finding the lab produces
        // lives, and the capture then reported nothing while calling itself
        // available.
        //
        // The rule is an interface that is up, running, and has an address.
        // That is what "traffic could flow here" means, and it keeps loopback
        // in and the empty ones out.
        let mut candidates: Vec<pcap::Device> = devices
            .into_iter()
            .filter(|device| {
                device.flags.is_up() && device.flags.is_running() && !device.addresses.is_empty()
            })
            .collect();
        // Loopback first, so a bound on the count can never be what drops it.
        candidates.sort_by_key(|device| u8::from(!device.flags.is_loopback()));

        let mut wires = Vec::new();
        let mut refusal = None;
        for device in candidates.into_iter().take(MAX_DEVICES) {
            match Self::open_device(device) {
                Ok(wire) => wires.push(wire),
                Err(error @ CollectError::Denied { .. }) => refusal = Some(error),
                Err(_) => {}
            }
        }
        if wires.is_empty() {
            return Err(refusal.unwrap_or(CollectError::Unavailable {
                what: "no capture device could be opened".to_owned(),
            }));
        }
        Ok(wires)
    }

    /// Opens one device, with the same bounds the Linux socket has.
    fn open_device(device: pcap::Device) -> Result<Self, CollectError> {
        let name = device.name.clone();
        let handle = pcap::Capture::from_device(device)
            .map_err(|error| CollectError::Unavailable {
                what: format!("{name}: {error}"),
            })?
            // The same promise the Linux buffer makes, made here by the
            // library: the kernel truncates every frame to this length, so no
            // payload reaches the process to be discarded later.
            .snaplen(i32::try_from(SNAP).unwrap_or(i32::MAX))
            // Without this the kernel holds frames back until its buffer is
            // full, which on a quiet interface is minutes.
            .immediate_mode(true)
            .timeout(i32::try_from(READ_TIMEOUT_MS).unwrap_or(i32::MAX))
            .open()
            .map_err(|error| {
                // libpcap has no typed permission error: it reports one as a
                // message, or as an errno from the `open` of the device. Both
                // mean the same thing to a person, and telling them apart from
                // a missing interface is the difference between "ask for
                // access" and "there is nothing to capture on".
                let denied = match &error {
                    pcap::Error::IoError(kind) => *kind == std::io::ErrorKind::PermissionDenied,
                    pcap::Error::PcapError(text) => {
                        text.to_ascii_lowercase().contains("permission")
                    }
                    _ => false,
                };
                if denied {
                    CollectError::Denied {
                        what: format!(
                            "{name}: capturing packets needs read access to the capture \
                             devices, which this account does not have"
                        ),
                    }
                } else {
                    CollectError::Unavailable {
                        what: format!("{name}: {error}"),
                    }
                }
            })?;
        let link = match handle.get_datalink() {
            pcap::Linktype::ETHERNET => super::packet::LinkKind::Ethernet,
            // What a loopback interface hands over on the BSDs.
            pcap::Linktype::NULL | pcap::Linktype::LOOP => super::packet::LinkKind::Null,
            pcap::Linktype::RAW => super::packet::LinkKind::Raw,
            other => {
                return Err(CollectError::Unavailable {
                    what: format!("{name}: link type {other:?} is not one this build reads"),
                });
            }
        };
        Ok(Self { handle, link })
    }

    /// What sits at the front of every frame this handle produces.
    #[must_use]
    pub const fn link(&self) -> super::packet::LinkKind {
        self.link
    }

    /// Reads at most one frame, waiting no longer than [`READ_TIMEOUT_MS`].
    ///
    /// Never returns an error, for the same reason the Linux one does not: a
    /// timeout on a quiet interface is the ordinary case and not a problem.
    pub fn read(&mut self, buffer: &mut [u8]) -> Frame {
        match self.handle.next_packet() {
            Ok(packet) => {
                let len = packet.data.len().min(buffer.len());
                let (Some(into), Some(from)) = (buffer.get_mut(..len), packet.data.get(..len))
                else {
                    return Frame::Idle;
                };
                into.copy_from_slice(from);
                Frame::Read(len)
            }
            Err(pcap::Error::TimeoutExpired) => Frame::Idle,
            Err(error) => Frame::Ended {
                detail: format!("the capture handle stopped: {error}"),
            },
        }
    }
}

/// See the Linux note above.
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
#[derive(Debug)]
pub struct Wire {
    /// Never constructed. The type exists so callers compile everywhere and
    /// the platform answer is given once, by [`Wire::open`], rather than by
    /// every call site guessing.
    never: std::convert::Infallible,
}

/// See the Linux note above.
///
/// # Errors
///
/// Always, on a platform with no backend.
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub fn open_all() -> Result<Vec<Wire>, CollectError> {
    Wire::open().map(|wire| vec![wire])
}

/// See the macOS note above.
///
/// # Errors
///
/// Whatever [`Wire::open_all`] returns.
#[cfg(any(target_os = "macos", windows))]
pub fn open_all() -> Result<Vec<Wire>, CollectError> {
    Wire::open_all()
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
impl Wire {
    /// Always refuses on this platform.
    ///
    /// # Errors
    ///
    /// Always [`CollectError::Unavailable`]. Windows needs a capture driver
    /// installed rather than a permission changed, which is what the capture
    /// offer already says there.
    pub fn open() -> Result<Self, CollectError> {
        Err(CollectError::Unavailable {
            what: "this build captures packets on Linux and macOS only".to_owned(),
        })
    }

    /// Unreachable: no value of this type can be constructed here.
    #[must_use]
    pub const fn link(&self) -> super::packet::LinkKind {
        match self.never {}
    }

    /// Unreachable: no value of this type can be constructed here.
    ///
    /// Kept so callers need no platform arms of their own.
    pub fn read(&mut self, _buffer: &mut [u8]) -> Frame {
        match self.never {}
    }
}
