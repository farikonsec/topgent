//! The adversarial benchmark: what the collectors actually saw, against what happened.
//!
//! Milestone M9 of `docs/MAJOR_UPGRADE_RESEARCH_PLAN.md`, run against the
//! snapshot collectors that ship today. That ordering is deliberate. The
//! snapshot limits are the result, not an obstacle to it: a periodic sweep
//! cannot see a process that lived and died between two sweeps, and the number
//! that quantifies how much it misses is worth more than a promise that a
//! future collector will not.
//!
//! Everything here is a pure function over a ground truth and a fact stream. No
//! process is spawned, no socket is opened, no clock is read. The fixture that
//! produces the ground truth is a separate binary, so the thing being measured
//! and the thing doing the measuring cannot share a bug.
//!
//! # What these numbers are not
//!
//! They are not accuracy against the world. They are agreement between two
//! observers of one controlled run: a fixture that recorded what it did, and a
//! collector that reported what it saw. A collector and a fixture that are both
//! wrong in the same way would score perfectly, which is why the fixture states
//! its facts from its own syscall returns rather than from a second sweep.

use serde::{Deserialize, Serialize};
use topgent_facts::{Claim, Fact, Subject};

/// Schema version of the ground-truth file this build writes and reads.
pub const GROUND_TRUTH_SCHEMA: u16 = 1;

/// One process the fixture actually created.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TruthProcess {
    /// Process id the operating system assigned.
    pub pid: u32,
    /// Executable name, as the process table would report it.
    pub name: String,
    /// Process id of its parent at the moment it was created.
    pub parent_pid: u32,
    /// Edges between this process and the fixture root.
    pub depth: u16,
    /// How long it was alive, in milliseconds.
    ///
    /// The number that decides whether a snapshot collector could have seen it
    /// at all. A process that lived 40ms between two five-second sweeps is
    /// invisible, and calling that a miss without recording the lifetime would
    /// make a correct collector look broken.
    pub lifetime_ms: u64,
}

impl TruthProcess {
    /// Whether this process could plausibly be caught by a sweep at this cadence.
    #[must_use]
    pub const fn survives(&self, sweep_interval_ms: u64) -> bool {
        self.lifetime_ms >= sweep_interval_ms
    }
}

/// One path the fixture prepared, with the answer it knows to be correct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TruthResource {
    /// Absolute path.
    pub path: String,
    /// Whether the fixture's own account could read it, established by trying.
    pub readable: bool,
}

/// One socket the fixture opened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TruthSocket {
    /// `tcp` or `udp`.
    pub protocol: String,
    /// Local port the kernel assigned or accepted.
    pub local_port: u16,
    /// Whether it was a listener rather than an outbound connection.
    pub listening: bool,
}

/// What the fixture did, written by the fixture from its own return values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroundTruth {
    /// Schema version.
    pub schema: u16,
    /// Process id of the fixture root.
    pub root_pid: u32,
    /// Absolute path to the fixture executable.
    pub root_exe: String,
    /// When the fixture started, Unix milliseconds.
    pub started_at_ms: u64,
    /// When it finished writing this file.
    pub ended_at_ms: u64,
    /// Every process it created, including the root.
    pub processes: Vec<TruthProcess>,
    /// Every path it prepared.
    pub resources: Vec<TruthResource>,
    /// Every socket it opened.
    pub sockets: Vec<TruthSocket>,
}

impl GroundTruth {
    /// Whether this build understands the file.
    #[must_use]
    pub const fn is_known_schema(&self) -> bool {
        self.schema == GROUND_TRUTH_SCHEMA
    }

    /// Every pid the fixture is responsible for.
    #[must_use]
    pub fn pids(&self) -> Vec<u32> {
        self.processes.iter().map(|process| process.pid).collect()
    }
}

/// Expected against observed, for one dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Score {
    /// How many the ground truth says existed.
    pub expected: usize,
    /// How many the collector reported.
    pub observed: usize,
    /// How many of the observed were in the ground truth.
    pub matched: usize,
}

impl Score {
    /// Share of the truth that was seen, `None` when there was nothing to see.
    ///
    /// Returning `None` rather than 1.0 for an empty expectation matters: a run
    /// where nothing happened would otherwise report perfect recall.
    #[must_use]
    pub fn recall(&self) -> Option<f64> {
        (self.expected > 0).then(|| exact(self.matched) / exact(self.expected))
    }

    /// Share of what was reported that was real, `None` when nothing was reported.
    #[must_use]
    pub fn precision(&self) -> Option<f64> {
        (self.observed > 0).then(|| exact(self.matched) / exact(self.observed))
    }

    /// How many the collector never reported.
    #[must_use]
    pub const fn missed(&self) -> usize {
        self.expected.saturating_sub(self.matched)
    }
}

/// Converts a count to a float without a lossy-cast lint on every line.
fn exact(count: usize) -> f64 {
    f64::from(u32::try_from(count).unwrap_or(u32::MAX))
}

/// Processes split by whether a sweep at this cadence could have caught them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lifetimes {
    /// The sweep interval the split was made against, in milliseconds.
    pub sweep_interval_ms: u64,
    /// Processes that outlived a sweep interval.
    pub resident: Score,
    /// Processes that did not.
    ///
    /// A snapshot collector is expected to miss most of these. The number is
    /// the finding, and a report that hid it would be claiming coverage the
    /// method cannot deliver.
    pub short_lived: Score,
}

/// Whether the collector's answer matched the answer the fixture proved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Agreement {
    /// How many the fixture prepared.
    pub expected: usize,
    /// How many the collector answered at all.
    pub answered: usize,
    /// How many answers matched the fixture's own result.
    pub agreed: usize,
    /// How many answers contradicted it.
    pub disagreed: usize,
}

impl Agreement {
    /// Share of answers that were right, `None` when nothing was answered.
    #[must_use]
    pub fn accuracy(&self) -> Option<f64> {
        (self.answered > 0).then(|| exact(self.agreed) / exact(self.answered))
    }
}

/// How long one collector took and how much it produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectorTiming {
    /// Collector id.
    pub collector: String,
    /// Reported capability state.
    pub state: String,
    /// Facts produced.
    pub facts: usize,
    /// Wall time.
    pub duration_ms: u64,
    /// Events the collector knows it dropped, when it accounts for loss at all.
    ///
    /// `None` and `Some(0)` are different answers. `None` means the collector
    /// keeps no loss accounting, so it cannot know whether it dropped anything;
    /// by `docs/NORMATIVE-CLAIMS.md` §3.7 it can never claim completeness.
    /// `Some(0)` means it counted and the count was zero.
    pub dropped_events: Option<u64>,
}

/// Why a metric read zero.
///
/// A benchmark that printed `0.0%` beside a metric the tool does not attempt is
/// not reporting a failure, it is inventing one. Every structural zero carries
/// the reason it is structural, and a reader who cannot see the difference has
/// been told half the answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Note {
    /// Which metric.
    pub metric: String,
    /// Why the number is what it is.
    pub text: String,
}

/// What the sweep cost the machine.
///
/// Wall time is measured; CPU time is not, because a portable per-process CPU
/// figure needs a second sample and an interval, and a number taken from one
/// sample would be an invention. Resident size is `None` where the platform
/// will not state it, which is a different answer from zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Overhead {
    /// Wall time for the whole sweep, across every collector.
    pub sweep_ms: u64,
    /// Resident bytes before the sweep ran.
    pub resident_before: Option<u64>,
    /// Resident bytes after it finished.
    pub resident_after: Option<u64>,
}

impl Overhead {
    /// How much the sweep added, when both samples exist.
    ///
    /// `None` rather than zero when either sample is missing: a growth of zero
    /// and an unmeasured growth are different answers.
    #[must_use]
    pub fn resident_growth(&self) -> Option<i64> {
        let before = i64::try_from(self.resident_before?).ok()?;
        let after = i64::try_from(self.resident_after?).ok()?;
        Some(after.saturating_sub(before))
    }
}

/// One benchmark run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Benchmark {
    /// Which fixture run this measures.
    pub root_pid: u32,
    /// Every process the fixture created, against every one observed.
    pub processes: Score,
    /// The same, split by whether a sweep could have caught them.
    pub lifetimes: Lifetimes,
    /// Parent edges the fixture created, against those observed correctly.
    pub ancestry: Score,
    /// Sockets the fixture opened, against those observed.
    pub sockets: Score,
    /// Reachability answers, against the answers the fixture proved by trying.
    pub reachability: Agreement,
    /// Fixture processes the collectors classified as a known agent family.
    ///
    /// What the right value is depends on the run. Unrecognised, the fixture is
    /// not an agent and every one of these is a false positive, so zero is the
    /// only acceptable answer. Recognised, exactly the root should be
    /// classified: a descendant promoted to an agent of its own is the defect
    /// there, and it is a different defect from the first.
    pub false_agents: usize,
    /// Whether the fixture ran under a name the catalogue recognises.
    ///
    /// Recorded because it changes what three of the metrics mean. Ancestry,
    /// sockets and reachability are produced only for a recognised agent, so
    /// unrecognised they are structurally zero and say nothing.
    pub recognised: bool,
    /// Per-collector cost.
    pub collectors: Vec<CollectorTiming>,
    /// Why any structurally zero metric is zero.
    pub notes: Vec<Note>,
    /// What the sweep cost.
    pub overhead: Option<Overhead>,
}

/// Scores one fact stream against one ground truth.
///
/// `sweep_interval_ms` is what the lifetime split is made against. It is a
/// parameter rather than a constant because the same fact stream scores
/// differently at a different cadence, and hiding that would make the numbers
/// look like properties of the collector rather than of the collector and its
/// schedule together.
#[must_use]
pub fn evaluate(truth: &GroundTruth, facts: &[Fact], sweep_interval_ms: u64) -> Benchmark {
    let expected: std::collections::BTreeSet<u32> = truth.pids().into_iter().collect();
    let mut observed_pids = std::collections::BTreeSet::new();
    let mut observed_parents = std::collections::BTreeMap::new();
    let mut observed_ports = std::collections::BTreeSet::new();
    let mut reach_answers = std::collections::BTreeMap::new();
    let mut false_agents = 0_usize;

    for fact in facts {
        let pid = fact.subject().pid();
        match fact.claim() {
            Claim::ProcessSeen { .. } => {
                if let Some(pid) = pid {
                    observed_pids.insert(pid);
                }
            }
            Claim::ChildProcessSeen { pid: child, .. } => {
                observed_pids.insert(*child);
                if let Some(parent) = pid {
                    observed_parents.insert(*child, parent);
                }
            }
            Claim::ProcessParent { parent_pid } => {
                if let Some(pid) = pid {
                    observed_parents.insert(pid, *parent_pid);
                }
            }
            Claim::SocketOpen { port, .. } => {
                if pid.is_some_and(|pid| expected.contains(&pid)) {
                    observed_ports.insert(*port);
                }
            }
            Claim::AgentFamily { .. } => {
                if pid.is_some_and(|pid| expected.contains(&pid)) {
                    false_agents = false_agents.saturating_add(1);
                }
            }
            Claim::ResourceReachable { path, evidence, .. } => {
                if let Subject::Resource { path: subject } = fact.subject() {
                    reach_answers.insert(subject.clone(), *evidence);
                } else {
                    reach_answers.insert(path.clone(), *evidence);
                }
            }
            _ => {}
        }
    }

    let processes = score_processes(&truth.processes, &observed_pids);
    let lifetimes = Lifetimes {
        sweep_interval_ms,
        resident: score_processes(
            &subset(&truth.processes, |process| {
                process.survives(sweep_interval_ms)
            }),
            &observed_pids,
        ),
        short_lived: score_processes(
            &subset(&truth.processes, |process| {
                !process.survives(sweep_interval_ms)
            }),
            &observed_pids,
        ),
    };

    let mut report = Benchmark {
        root_pid: truth.root_pid,
        processes,
        lifetimes,
        ancestry: score_ancestry(&truth.processes, &observed_parents),
        sockets: score_sockets(&truth.sockets, &observed_ports),
        reachability: score_reachability(&truth.resources, &reach_answers),
        false_agents,
        recognised: false,
        collectors: Vec::new(),
        notes: Vec::new(),
        overhead: None,
    };
    report.notes = notes_for(&report);
    report
}

/// The scope notes that apply to this run.
///
/// Three of Topgent's collectors deliberately produce detail only for processes
/// it has classified as an agent, and a fourth only for paths in the declared
/// inventory. A fixture that is correctly *not* recognised as an agent
/// therefore scores zero on all four, and that zero is the scoping working, not
/// the collector failing. Both facts belong in the report.
/// The scope notes for a report whose `recognised` flag has been set.
///
/// Public because the flag is set by the caller after `evaluate`, and notes
/// written before it was set would describe the wrong run.
#[must_use]
pub fn notes_for_report(report: &Benchmark) -> Vec<Note> {
    notes_for(report)
}

fn notes_for(report: &Benchmark) -> Vec<Note> {
    let mut notes = Vec::new();

    if report.recognised {
        notes.push(Note {
            metric: "recognised".to_owned(),
            text: "the fixture ran under a name the catalogue knows, so ancestry, sockets and \
                   reachability were in scope. This run cannot also show that an unrecognised \
                   process is left alone; `--unrecognised` is that run."
                .to_owned(),
        });
        if report.false_agents != 1 {
            notes.push(Note {
                metric: "false_agents".to_owned(),
                text: format!(
                    "{} fixture processes were classified as an agent. Exactly one, the root, \
                     should be: a descendant promoted to an agent of its own is a false identity.",
                    report.false_agents
                ),
            });
        }
    } else if report.false_agents > 0 {
        notes.push(Note {
            metric: "false_agents".to_owned(),
            text: "a fixture process was classified as a known agent family; the fixture is not \
                   an agent, so this is a false positive"
                .to_owned(),
        });
    }

    // A zero still needs its reason, and the reason differs by run. Out of
    // scope and looked-at-and-not-found are different answers, and a report
    // that gave the same sentence for both would be explaining the wrong thing.
    if report.ancestry.matched == 0 {
        notes.push(Note {
            metric: "ancestry".to_owned(),
            text: if report.recognised {
                "no parent edge was observed although the agent was recognised. A same-family \
                 relaunch is deliberately not reported as a separate process, so a fixture that \
                 spawns copies of itself has fewer edges to find than it created."
                    .to_owned()
            } else {
                "descendant enumeration runs only for processes classified as an agent. The \
                 fixture is deliberately not one, so no parent edge was in scope."
                    .to_owned()
            },
        });
    }
    if report.sockets.matched == 0 {
        notes.push(Note {
            metric: "sockets".to_owned(),
            text: if report.recognised {
                "no fixture socket was attributed although the agent was recognised. The socket \
                 collector's own boundary states what it can list on this platform."
                    .to_owned()
            } else {
                "socket attribution runs only for agent processes, so the fixture's loopback \
                 sockets were out of scope."
                    .to_owned()
            },
        });
    }
    if report.reachability.answered == 0 {
        notes.push(Note {
            metric: "reachability".to_owned(),
            text: "reachability is evaluated over the declared inventory only, never the whole \
                   filesystem. The fixture's temporary paths are not in it."
                .to_owned(),
        });
    }
    notes
}

/// The subset of processes matching a predicate.
fn subset(processes: &[TruthProcess], keep: impl Fn(&TruthProcess) -> bool) -> Vec<TruthProcess> {
    processes.iter().filter(|p| keep(p)).cloned().collect()
}

/// How many of these processes were seen.
///
/// `observed` counts only pids the fixture created. A collector reporting every
/// process on the host is not imprecise about the fixture, it is answering a
/// different question, and counting the whole host as false positives would
/// produce a meaningless number.
fn score_processes(
    processes: &[TruthProcess],
    observed: &std::collections::BTreeSet<u32>,
) -> Score {
    let matched = processes
        .iter()
        .filter(|process| observed.contains(&process.pid))
        .count();
    Score {
        expected: processes.len(),
        observed: matched,
        matched,
    }
}

/// How many parent edges were reported, and reported correctly.
fn score_ancestry(
    processes: &[TruthProcess],
    observed: &std::collections::BTreeMap<u32, u32>,
) -> Score {
    let edges: Vec<_> = processes
        .iter()
        .filter(|process| process.depth > 0)
        .collect();
    let reported = edges
        .iter()
        .filter(|process| observed.contains_key(&process.pid))
        .count();
    let matched = edges
        .iter()
        .filter(|process| observed.get(&process.pid) == Some(&process.parent_pid))
        .count();
    Score {
        expected: edges.len(),
        observed: reported,
        matched,
    }
}

/// How many of the fixture's sockets appeared, matched on local port.
fn score_sockets(sockets: &[TruthSocket], observed: &std::collections::BTreeSet<u16>) -> Score {
    let matched = sockets
        .iter()
        .filter(|socket| observed.contains(&socket.local_port))
        .count();
    Score {
        expected: sockets.len(),
        observed: observed.len(),
        matched,
    }
}

/// Whether the reachability answers matched what the fixture proved by trying.
///
/// `PathResolves` is not counted as agreement with a readable path. The two are
/// different findings by `docs/NORMATIVE-CLAIMS.md` §3.4, and scoring them as
/// the same would reward exactly the conflation the vocabulary forbids.
fn score_reachability(
    resources: &[TruthResource],
    answers: &std::collections::BTreeMap<String, topgent_facts::Reachability>,
) -> Agreement {
    let mut answered = 0_usize;
    let mut agreed = 0_usize;
    let mut disagreed = 0_usize;
    for resource in resources {
        let Some(evidence) = answers.get(&resource.path) else {
            continue;
        };
        answered = answered.saturating_add(1);
        let says_readable = evidence.establishes_readability();
        if says_readable == resource.readable {
            agreed = agreed.saturating_add(1);
        } else {
            disagreed = disagreed.saturating_add(1);
        }
    }
    Agreement {
        expected: resources.len(),
        answered,
        agreed,
        disagreed,
    }
}
