//! No probe in this build: not Linux, or built without the `probe` feature.
//!
//! [`Probe`] cannot be constructed here, so its methods can never run; they
//! exist so callers compile the same on every platform.

use std::convert::Infallible;

use topgent_ebpf_common::{ArgvRecord, CwdRecord, ProcessEvent, SyscallRecord};

use crate::Unavailable;

/// A loaded probe. Never exists in this build.
#[derive(Debug)]
pub struct Probe {
    never: Infallible,
}

impl Probe {
    /// Kernel ids of the loaded programs. Never runs in this build.
    ///
    /// # Errors
    ///
    /// Never returns; the signature matches the Linux build.
    pub fn program_ids(&self) -> Result<Vec<u32>, Unavailable> {
        match self.never {}
    }

    /// Moves waiting events into `into`. Never runs in this build.
    pub fn drain(&mut self, _into: &mut Vec<ProcessEvent>) -> usize {
        match self.never {}
    }

    /// Moves drained exec arguments into `into`. Never runs in this build.
    pub fn take_argv(&mut self, _into: &mut Vec<ArgvRecord>) {
        match self.never {}
    }

    /// Whether exec arguments are read. Never runs in this build.
    #[must_use]
    pub const fn reads_argv(&self) -> bool {
        match self.never {}
    }

    /// Moves working directories sent with execs into `into`. Never runs in
    /// this build.
    pub fn take_cwds(&mut self, _into: &mut Vec<CwdRecord>) {
        match self.never {}
    }

    /// Moves working directories sent with calls into `into`. Never runs in
    /// this build.
    pub fn take_call_cwds(&mut self, _into: &mut Vec<CwdRecord>) {
        match self.never {}
    }

    /// Whether working directories are read. Never runs in this build.
    #[must_use]
    pub const fn reads_cwd(&self) -> bool {
        match self.never {}
    }

    /// Moves waiting syscalls into `into`. Never runs in this build.
    pub fn drain_syscalls(&mut self, _into: &mut Vec<SyscallRecord>) -> usize {
        match self.never {}
    }

    /// The name of a traced call. Never runs in this build.
    #[must_use]
    pub const fn syscall_name(&self, _call: u32) -> Option<&'static str> {
        match self.never {}
    }

    /// Every syscall traced. Never runs in this build.
    #[must_use]
    pub const fn traced(&self) -> Vec<&'static str> {
        match self.never {}
    }

    /// Rule syscalls not traced, and why. Never runs in this build.
    #[must_use]
    pub const fn untraced(&self) -> &[(&'static str, String)] {
        match self.never {}
    }

    /// Syscalls dropped for a full ring buffer. Never runs in this build.
    ///
    /// # Errors
    ///
    /// Never returns; the signature matches the Linux build.
    pub fn syscalls_lost(&self) -> Result<u64, Unavailable> {
        match self.never {}
    }

    /// Events dropped for a full ring buffer. Never runs in this build.
    ///
    /// # Errors
    ///
    /// Never returns; the signature matches the Linux build.
    pub fn lost(&self) -> Result<u64, Unavailable> {
        match self.never {}
    }

    /// The pid namespace events were compared with. Never runs in this build.
    #[must_use]
    pub const fn host_pid_namespace(&self) -> Option<u64> {
        match self.never {}
    }

    /// Records that were not one whole event. Never runs in this build.
    #[must_use]
    pub const fn malformed(&self) -> u64 {
        match self.never {}
    }
}

pub(crate) fn load() -> Result<Probe, Unavailable> {
    Err(if cfg!(target_os = "linux") {
        Unavailable::NotBuilt
    } else {
        Unavailable::NotLinux
    })
}
