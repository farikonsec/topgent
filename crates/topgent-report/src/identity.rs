//! Who is producing evidence, and on what.
//!
//! An [`Origin`] binds every record to a host, a boot, and the sensor process
//! that wrote it. Without all three a record from another machine, or from
//! before a restart, could be spliced into this chain and would verify.
//!
//! # How each part is established
//!
//! **Host.** Thirty-two random bytes generated on first use and kept in the
//! state directory. This is deliberately not a machine serial, a hardware
//! identifier or a hostname: none of those is available unprivileged on all
//! three platforms, and all of them identify the operator rather than the
//! installation. A random per-installation value is stable, unique, and says
//! nothing about the machine. Its one weakness is stated rather than hidden:
//! clearing the state directory produces a new host identity, and bundles
//! written before and after will not appear to come from the same host.
//!
//! **Boot.** Linux publishes `/proc/sys/kernel/random/boot_id`, which changes
//! on restart and is exactly the right value. macOS and Windows publish no
//! equivalent an unprivileged process can read, so this build generates a
//! fresh value per process there and [`BootBinding`] records that the guarantee
//! degraded from boot to session. That is a smaller loss than it sounds: the
//! sensor instance below already changes on every process start, so replay
//! across a restart is still refused. What is lost is the ability to tell that
//! two runs happened within one boot.
//!
//! **Sensor instance.** Thirty-two random bytes per process, never persisted.
//! Two concurrent Topgent processes are two sensors and their chains are
//! separate, which is correct: sequence numbers are only meaningful within one
//! instance.

use std::path::{Path, PathBuf};

use topgent_evidence::{KeyError, Origin, SensorKey};

/// Bytes of randomness behind each generated identifier.
const IDENTITY_BYTES: usize = 32;

/// File under the state directory holding the persistent host identity.
const HOST_FILE: &str = "host-id";

/// File under the state directory holding the sensor signing seed.
const KEY_FILE: &str = "sensor-key";

/// How firmly this platform can bind a record to one boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootBinding {
    /// The kernel published a boot identifier that changes on restart.
    Boot,
    /// No readable boot identifier, so the value is per process.
    ///
    /// Reported rather than silently substituted, because a caller comparing
    /// two bundles needs to know that "different boot" here may only mean
    /// "different run".
    Session,
}

impl BootBinding {
    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Boot => "boot",
            Self::Session => "session",
        }
    }
}

/// Why an identity could not be established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    /// The platform would not supply randomness.
    ///
    /// Nothing is derived from a fallback source. A predictable host identity
    /// or signing key would still verify, which is worse than refusing.
    NoRandomness,
    /// The state directory could not be read or written.
    State {
        /// Which path.
        path: String,
        /// What the filesystem said.
        detail: String,
    },
    /// The stored signing seed is not a usable key.
    Key(KeyError),
}

impl core::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoRandomness => f.write_str("the platform would not supply randomness"),
            Self::State { path, detail } => write!(f, "{path}: {detail}"),
            Self::Key(error) => write!(f, "stored sensor key: {error}"),
        }
    }
}

impl core::error::Error for IdentityError {}

/// Lowercase hex, because every identifier here is printed and compared.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    out
}

/// Fresh randomness as hex.
fn random_hex() -> Result<String, IdentityError> {
    let mut bytes = [0_u8; IDENTITY_BYTES];
    getrandom::fill(&mut bytes).map_err(|_| IdentityError::NoRandomness)?;
    Ok(hex(&bytes))
}

/// Reads a file, creating it with fresh content when it is absent.
///
/// The read-back is deliberate. Two processes starting together can both find
/// the file missing, and whichever write lands second must not win: both must
/// end up using the same identity, so the value returned is always the one on
/// disk after the write.
fn persistent(
    path: &Path,
    make: impl Fn() -> Result<String, IdentityError>,
) -> Result<String, IdentityError> {
    let state = |detail: String| IdentityError::State {
        path: path.display().to_string(),
        detail,
    };
    if let Ok(existing) = std::fs::read_to_string(path) {
        let trimmed = existing.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_owned());
        }
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| state(error.to_string()))?;
    }
    let fresh = make()?;
    std::fs::write(path, format!("{fresh}\n")).map_err(|error| state(error.to_string()))?;
    let settled = std::fs::read_to_string(path).map_err(|error| state(error.to_string()))?;
    Ok(settled.trim().to_owned())
}

/// The persistent identity of this installation.
///
/// # Errors
///
/// Returns [`IdentityError`] when randomness or the state directory is
/// unavailable.
pub fn host_id(state: &Path) -> Result<String, IdentityError> {
    persistent(&state.join(HOST_FILE), random_hex)
}

/// This boot, and how firmly the platform can say so.
///
/// # Errors
///
/// Returns [`IdentityError::NoRandomness`] only on the platforms that need to
/// generate a session value.
pub fn boot_id() -> Result<(String, BootBinding), IdentityError> {
    if let Ok(published) = std::fs::read_to_string("/proc/sys/kernel/random/boot_id") {
        let trimmed = published.trim();
        if !trimmed.is_empty() {
            return Ok((trimmed.to_owned(), BootBinding::Boot));
        }
    }
    Ok((random_hex()?, BootBinding::Session))
}

/// A fresh identifier for this sensor process.
///
/// # Errors
///
/// Returns [`IdentityError::NoRandomness`] when the platform will not supply it.
pub fn sensor_instance() -> Result<String, IdentityError> {
    random_hex()
}

/// The signing key for this installation, generated on first use.
///
/// The seed is kept as hex in the state directory. A caller that wants to
/// verify a bundle without trusting the producer holds the public half, which
/// [`SensorKey::public`] prints.
///
/// # Errors
///
/// Returns [`IdentityError`] when randomness or the state directory is
/// unavailable, or when the stored seed is not a usable key.
pub fn sensor_key(state: &Path) -> Result<SensorKey, IdentityError> {
    // The seed is generated here rather than taken from `SensorKey::generate`
    // because `SensorKey` does not expose its secret half, and should not. The
    // seed is the thing that has to survive a restart, so it is the thing that
    // is written, and the key is derived from it on every load.
    let stored = persistent(&state.join(KEY_FILE), random_hex)?;
    let mut seed = [0_u8; 32];
    let bytes = stored.as_bytes();
    if bytes.len() < 64 {
        return Err(IdentityError::Key(KeyError::Malformed));
    }
    for (index, slot) in seed.iter_mut().enumerate() {
        let pair = stored
            .get(index * 2..index * 2 + 2)
            .ok_or(IdentityError::Key(KeyError::Malformed))?;
        *slot =
            u8::from_str_radix(pair, 16).map_err(|_| IdentityError::Key(KeyError::Malformed))?;
    }
    SensorKey::from_seed(seed).map_err(IdentityError::Key)
}

/// Everything a producer needs to open a chain, from the default state directory.
///
/// # Errors
///
/// Returns [`IdentityError`] when any part could not be established.
pub fn origin_at(state: &Path) -> Result<(Origin, BootBinding), IdentityError> {
    let (boot, binding) = boot_id()?;
    Ok((
        Origin {
            host_id: host_id(state)?,
            boot_id: boot,
            sensor_instance: sensor_instance()?,
        },
        binding,
    ))
}

/// The state directory this build writes identities into.
#[must_use]
pub fn default_state() -> PathBuf {
    topgent_journal::state_dir()
}
