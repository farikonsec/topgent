//! Standard output: event lines, and a health line once a second.
//!
//! Separate because both sources write through it, and the health line is
//! where the sensor says which source it is using and, when it is not using
//! eBPF, why. A quiet sensor and a deaf one are told apart by the health
//! line's loss counts; an eBPF sensor and a fallback one by its source.

use std::io::{BufWriter, StdoutLock, Write as _};

use serde_json::{Value, json};

use crate::clock::now_ms;
use crate::line::add;

/// How often a health line is written.
const HEALTH_EVERY_MS: u64 = 1_000;

pub(crate) struct Output {
    out: BufWriter<StdoutLock<'static>>,
    session: String,
    source: &'static str,
    note: Option<String>,
    last_health: u64,
    /// Rule syscalls traced, and how many were lost, when the source
    /// delivers them.
    syscalls: Option<(u64, u64)>,
}

impl Output {
    /// `source` is `ebpf` or `connector`; `note` says why eBPF is not in use.
    pub(crate) fn new(source: &'static str, note: Option<String>) -> Self {
        Self {
            out: BufWriter::new(std::io::stdout().lock()),
            session: format!("{}-{}", std::process::id(), now_ms()),
            source,
            note,
            last_health: 0,
            syscalls: None,
        }
    }

    /// Says in each health line that `traced` rule syscalls are delivered,
    /// and that `lost` of them were dropped since the start.
    pub(crate) fn syscalls(&mut self, traced: u64, lost: u64) {
        self.syscalls = Some((traced, lost));
    }

    /// Writes one event line. `false` once the reader has gone, which is the
    /// sensor's signal to stop.
    pub(crate) fn event(&mut self, line: &Value) -> bool {
        writeln!(self.out, "{line}").is_ok()
    }

    /// Writes a health line when one is due. `lost` counts events the source
    /// numbered or queued and never delivered; `overflows`, times its buffer
    /// filled. `false` once the reader has gone.
    pub(crate) fn health(&mut self, lost: u64, overflows: u64) -> bool {
        let wall = now_ms();
        if wall.saturating_sub(self.last_health) < HEALTH_EVERY_MS {
            return true;
        }
        self.last_health = wall;
        let mut health = json!({"e": "health", "session": self.session, "lost": lost,
                                "overflows": overflows, "at": wall, "source": self.source});
        if let Some(note) = &self.note {
            add(&mut health, "note", note.as_str());
        }
        if let Some((traced, lost)) = self.syscalls {
            add(&mut health, "syscalls", traced);
            add(&mut health, "sys_lost", lost);
        }
        writeln!(self.out, "{health}").is_ok()
    }

    /// `false` once the reader has gone.
    pub(crate) fn flush(&mut self) -> bool {
        self.out.flush().is_ok()
    }
}
