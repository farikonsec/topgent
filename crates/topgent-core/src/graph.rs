//! The fold: a fact stream in, an agent graph out.
//!
//! This module is a pure function. It never reads a clock, a file or a socket, so
//! the same facts always produce the same graph — on your laptop, in CI, and in a
//! test replaying a recorded stream. That is what makes the timeline free (the
//! fact log *is* the timeline) and what lets the core be fuzzed with synthetic
//! streams and no operating system in the loop.

use std::collections::BTreeMap;
use topgent_facts::{
    Access, ByteCounters, Claim, Confidence, Direction, Fact, Protocol, Reachability, Subject, Tri,
    UnixMillis,
};

/// Stable identity of one agent.
///
/// Pid plus start time, because pids are reused: a recycled pid must never
/// inherit the previous occupant's findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AgentId {
    /// Process id.
    pub pid: u32,
    /// Process start time.
    pub started_at: UnixMillis,
}

/// Whose authority an agent acts under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityKind {
    /// The agent runs under a person's account and takes its permissions from
    /// that person's configuration. Anything it does is logged as them.
    DelegatedHuman,
    /// The agent runs under an account of its own with no human's config behind it.
    ServiceAccount,
    /// Not enough was observed to say.
    Unknown,
}

impl IdentityKind {
    /// Display label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::DelegatedHuman => "delegated human",
            Self::ServiceAccount => "service account",
            Self::Unknown => "unknown",
        }
    }

    /// Multiplier applied to every risk factor.
    ///
    /// Borrowing a person's identity is worse than holding one of your own,
    /// because the audit trail then names them for what the agent did.
    #[must_use]
    pub const fn multiplier(self) -> u32 {
        match self {
            Self::DelegatedHuman => 100,
            Self::ServiceAccount => 75,
            Self::Unknown => 85,
        }
    }
}

/// What Topgent knows about one resource, in the three columns that matter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceAccess {
    /// The path.
    pub path: String,
    /// What the agent's own configuration permits.
    pub declared: Tri,
    /// What the agent actually touched.
    pub observed: Tri,
    /// What it could touch with no further permission.
    ///
    /// `Yes` only where the kernel was asked and answered. A path that merely
    /// resolves leaves this `Unknown` and records why in [`Self::reach_evidence`],
    /// because a stat that succeeded is not a read that would.
    pub reachable: Tri,
    /// What the reachability probe actually established, when one ran.
    ///
    /// Kept alongside the column so a report can print the finding rather than
    /// a word. Account-level in every case: process confinement is not
    /// evaluated, and the statement says so.
    pub reach_evidence: Option<Reachability>,
    /// Whether the path holds a credential.
    pub sensitive: bool,
    /// The strongest access seen across all three columns.
    pub access: Option<Access>,
    /// Probes that produced these cells, in stable order.
    pub evidence: Vec<String>,
}

impl ResourceAccess {
    /// The agent touched something its own configuration does not grant.
    ///
    /// The declared-versus-observed test. Everyone else scans config or watches
    /// runtime; the disagreement between the two is the finding.
    #[must_use]
    pub const fn is_drift(&self) -> bool {
        matches!(self.declared, Tri::No) && matches!(self.observed, Tri::Yes)
    }

    /// A credential sits in reach that nothing has touched.
    ///
    /// No runtime signal will ever fire for this, which is exactly why the
    /// reachable column exists.
    #[must_use]
    pub const fn is_latent_secret(&self) -> bool {
        self.sensitive && matches!(self.reachable, Tri::Yes) && !matches!(self.observed, Tri::Yes)
    }
}

/// A network destination the agent holds a socket to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// Which protocol carries it.
    ///
    /// A TCP peer is always named; a bound UDP socket has none to name; and on
    /// macOS an ICMP socket exposes neither host nor port. Without this, an
    /// unobservable destination and an unread one look the same.
    pub protocol: Protocol,
    /// Peer host, or `*` where the platform states no address.
    pub host: String,
    /// Peer port.
    pub port: u16,
    /// Which way the connection goes.
    pub direction: Direction,
    /// When the operating system recorded the connection being created.
    ///
    /// `None` means the platform keeps no such record. It never means "just
    /// now", and an age is never derived by comparing two sweeps.
    pub opened_at: Option<UnixMillis>,
    /// Traffic the kernel has accounted to this connection, when it counts.
    ///
    /// `None` means no counter exists here. It never means zero traffic, and it
    /// is never a count of how often Topgent saw the endpoint.
    pub bytes: Option<ByteCounters>,
}

/// A connector the agent declares it may call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connector {
    /// Connector name.
    pub name: String,
    /// Access it grants.
    pub access: Access,
}

/// An edge to another agent this one can invoke — the second hop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentEdge {
    /// Process id of the agent that can be invoked.
    pub target_pid: u32,
    /// How, such as `mcp` or `child-process`.
    pub via: String,
}

/// A process running beneath an agent in the current process tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildProcess {
    /// Process id.
    pub pid: u32,
    /// Executable name, never its arguments.
    pub name: String,
    /// Distance from the agent in parent edges.
    pub depth: u16,
}

/// An agent extension active inside a shared editor extension host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditorExtension {
    /// Stable agent family.
    pub family: String,
    /// Exact extension publisher and package identifier.
    pub extension_id: String,
}

/// One agent and everything known about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Agent {
    /// Stable identity.
    pub id: AgentId,
    /// Family name, when one was recognised.
    pub family: Option<String>,
    /// Agent extensions active inside this host, sorted by extension id.
    pub extensions: Vec<EditorExtension>,
    /// Executable path, or the process name when the path was refused.
    pub exe: Option<String>,
    /// Whether [`Agent::exe`] is the path the operating system reported.
    ///
    /// False means only the name is known. Family recognition reads the path,
    /// so an unrecognised agent with no readable path has not been ruled out;
    /// it has not been examined, and the interface must say so.
    pub exe_path_known: bool,
    /// Numeric owner.
    pub uid: Option<u32>,
    /// Resolved owner name.
    pub user: Option<String>,
    /// Whose authority it acts under.
    pub identity: IdentityKind,
    /// Provider and model, when observed.
    pub model: Option<(String, String)>,
    /// Parent process, when observed.
    pub parent_pid: Option<u32>,
    /// Descendant processes, sorted by depth then pid.
    pub children: Vec<ChildProcess>,
    /// Declared connectors, sorted by name.
    pub connectors: Vec<Connector>,
    /// Network destinations, sorted.
    pub endpoints: Vec<Endpoint>,
    /// Resources, sorted by path.
    pub resources: Vec<ResourceAccess>,
    /// Agents it can invoke, sorted by pid.
    pub invokes: Vec<AgentEdge>,
    /// Actions Topgent took against it, sorted.
    pub actions: Vec<(String, bool)>,
    /// How sure we are this is an agent at all.
    pub discovery_confidence: Confidence,
    /// Weakest confidence seen per kind of evidence, keyed by claim kind.
    ///
    /// A risk factor reads its own evidence kind from here rather than borrowing
    /// the agent's best signal, so an inference is never presented with the
    /// authority of a direct observation.
    pub evidence_confidence: BTreeMap<&'static str, Confidence>,
    /// Number of facts that produced this agent.
    pub fact_count: usize,
}

impl Agent {
    /// Resources whose observed access exceeds what was declared.
    #[must_use]
    pub fn drift(&self) -> Vec<&ResourceAccess> {
        self.resources.iter().filter(|r| r.is_drift()).collect()
    }

    /// Credentials in reach that nothing has touched.
    #[must_use]
    pub fn latent_secrets(&self) -> Vec<&ResourceAccess> {
        self.resources
            .iter()
            .filter(|r| r.is_latent_secret())
            .collect()
    }

    /// Confidence of one kind of evidence, or `Possible` when we have none.
    ///
    /// Absence is the least certain answer, never the most.
    #[must_use]
    pub fn confidence_for(&self, claim_kind: &str) -> Confidence {
        self.evidence_confidence
            .get(claim_kind)
            .copied()
            .unwrap_or(Confidence::Possible)
    }

    /// Distinct outbound destinations.
    #[must_use]
    pub fn outbound_count(&self) -> usize {
        self.endpoints
            .iter()
            .filter(|e| matches!(e.direction, Direction::Outbound))
            .count()
    }

    /// Distinct outbound hosts, ignoring the port.
    ///
    /// A jump here is what reaching out to many machines looks like — the shape
    /// of scanning a network, visible from socket metadata with nothing
    /// decrypted.
    #[must_use]
    pub fn distinct_hosts(&self) -> usize {
        let mut hosts: Vec<&str> = self
            .endpoints
            .iter()
            .filter(|e| matches!(e.direction, Direction::Outbound))
            .map(|e| e.host.as_str())
            .collect();
        hosts.sort_unstable();
        hosts.dedup();
        hosts.len()
    }

    /// The most distinct ports Topgent has seen open to any single host.
    ///
    /// Many ports to one host is the shape of a port scan, again from metadata
    /// alone.
    #[must_use]
    pub fn max_ports_to_one_host(&self) -> usize {
        use std::collections::BTreeMap;
        let mut by_host: BTreeMap<&str, std::collections::BTreeSet<u16>> = BTreeMap::new();
        for e in self
            .endpoints
            .iter()
            .filter(|e| matches!(e.direction, Direction::Outbound))
        {
            by_host.entry(e.host.as_str()).or_default().insert(e.port);
        }
        by_host
            .values()
            .map(std::collections::BTreeSet::len)
            .max()
            .unwrap_or(0)
    }

    /// Whether anything gives this agent the ability to run arbitrary commands.
    #[must_use]
    pub fn can_execute(&self) -> bool {
        self.resources
            .iter()
            .any(|r| matches!(r.access, Some(Access::Execute)) && r.declared.is_yes())
            || self
                .connectors
                .iter()
                .any(|c| matches!(c.access, Access::Execute))
    }

    /// Whether the agent declares that it runs sandboxed.
    #[must_use]
    pub fn is_sandboxed(&self) -> bool {
        self.resources.iter().any(|r| r.path == "<sandbox>")
    }

    /// Whether it may write outside anything it declared.
    #[must_use]
    pub fn can_write_broadly(&self) -> bool {
        self.resources.iter().any(|r| {
            r.declared.is_yes()
                && r.access.is_some_and(Access::is_mutating)
                && r.path.contains("**")
        })
    }
}

/// A fact the fold refused, kept so nothing disappears silently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejected {
    /// Why it was refused.
    pub reason: RejectReason,
    /// The claim kind, for reporting.
    pub claim_kind: &'static str,
    /// The identity it was about, when it had one.
    ///
    /// An attribution defect is only findable if the refused facts name what
    /// they were about, so unanchored activity is kept here rather than
    /// dropped.
    pub subject: Option<AgentId>,
}

/// Why the fold refused a fact.
///
/// Schema mismatch is deliberately absent: `Fact::new` is the only constructor
/// and it already refuses a version this build does not speak, so a second gate
/// here would be a branch nothing can reach. One gate, in the one place a fact
/// can enter the system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectReason {
    /// The fact is about a subject that is not a process, and nothing anchors it.
    UnanchoredSubject,
    /// The fact is about a process nothing established to be an agent.
    ///
    /// The filesystem, network-event and DNS collectors build their pid maps
    /// from every visible process, so with audit sensors live an unrelated
    /// shell that opened a watched file used to arrive in the inventory with a
    /// risk score of its own. Being seen doing something is not the same as
    /// being an agent.
    UnanchoredIdentity,
}

/// The whole picture, folded from a fact stream.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AgentGraph {
    /// Agents, sorted by pid then start time so the output is stable.
    pub agents: Vec<Agent>,
    /// Facts that were refused, with the reason.
    pub rejected: Vec<Rejected>,
}

impl AgentGraph {
    /// Find an agent by pid, when exactly one matches.
    #[must_use]
    pub fn by_pid(&self, pid: u32) -> Option<&Agent> {
        let mut hits = self.agents.iter().filter(|a| a.id.pid == pid);
        let first = hits.next()?;
        if hits.next().is_some() {
            None
        } else {
            Some(first)
        }
    }
}

/// What is known about one endpoint while a fold is in progress.
type EndpointFacts = (Direction, Option<UnixMillis>, Option<ByteCounters>);

/// Working state for one agent while folding.
#[derive(Default)]
struct Builder {
    family: Option<String>,
    extensions: BTreeMap<String, String>,
    exe: Option<String>,
    exe_path_known: bool,
    uid: Option<u32>,
    user: Option<String>,
    model: Option<(String, String)>,
    parent_pid: Option<u32>,
    connectors: BTreeMap<String, Access>,
    endpoints: BTreeMap<(Protocol, String, u16, u8), EndpointFacts>,
    resources: BTreeMap<String, ResourceBuilder>,
    invokes: BTreeMap<u32, String>,
    actions: Vec<(String, bool)>,
    children: BTreeMap<u32, (String, u16)>,
    best_confidence: Option<Confidence>,
    claim_confidence: BTreeMap<&'static str, Confidence>,
    has_declared_permissions: bool,
    fact_count: usize,
}

struct ResourceBuilder {
    declared: Tri,
    observed: Tri,
    reachable: Tri,
    reach_evidence: Option<Reachability>,
    sensitive: bool,
    access: Option<Access>,
    evidence: Vec<String>,
}

impl Default for ResourceBuilder {
    fn default() -> Self {
        // Every column starts Unknown. "We have not looked" is a different answer
        // from "we looked and it is not so", and the fold must not conflate them.
        Self {
            declared: Tri::Unknown,
            observed: Tri::Unknown,
            reachable: Tri::Unknown,
            reach_evidence: None,
            sensitive: false,
            access: None,
            evidence: Vec::new(),
        }
    }
}

impl ResourceBuilder {
    fn note(&mut self, probe: &str) {
        let probe = probe.to_owned();
        if !self.evidence.contains(&probe) {
            self.evidence.push(probe);
        }
    }

    /// Record what a reachability probe established.
    ///
    /// Only the kernel's own answer closes the column. A path that resolves
    /// proves the directory chain is traversable and nothing about whether the
    /// file opens, so the cell stays `Unknown` and the evidence carries what
    /// was actually established. The stronger evidence wins where one path is
    /// probed more than once, which keeps the fold order-independent.
    fn reach(&mut self, access: Access, sensitive: bool, evidence: Reachability) {
        if evidence.establishes_readability() {
            self.reachable = Tri::Yes;
            self.widen(access);
        }
        self.reach_evidence = Some(match self.reach_evidence {
            Some(kept) if kept.establishes_readability() => kept,
            _ => evidence,
        });
        self.sensitive |= sensitive;
    }

    /// Widen the recorded access to cover both what we had and what we just saw.
    ///
    /// Execute outranks everything: being able to run a thing is strictly worse
    /// than being able to read it, so it never gets downgraded to read-write.
    fn widen(&mut self, access: Access) {
        self.access = Some(match (self.access, access) {
            (None, a) => a,
            (Some(Access::Execute), _) | (_, Access::Execute) => Access::Execute,
            (Some(a), b) if a == b => a,
            (Some(_), _) => Access::ReadWrite,
        });
    }
}

/// One key per resource, whatever names it.
///
/// Reachability reports `~/.aws/credentials` because that is what a person
/// reads. The filesystem sensor reports `/home/kali/.aws/credentials` because
/// that is what the kernel saw. Keyed as written, those are two resources: the
/// credential stays "never touched" however often it is opened, and
/// `CREDENTIAL_ACCESS` can never fire for anything under a home directory, which
/// is every credential in the catalogue.
///
/// The tilde form wins. It is the one already shown, and it keeps the account
/// name out of a report.
#[must_use]
pub fn resource_key(path: &str, home: Option<&str>) -> String {
    if path.starts_with("~/") {
        return path.to_owned();
    }
    let Some(home) = home
        .map(|home| home.trim_end_matches('/'))
        .filter(|home| !home.is_empty())
    else {
        return path.to_owned();
    };
    match path.strip_prefix(home) {
        Some(rest) if rest.starts_with('/') => format!("~{rest}"),
        _ => path.to_owned(),
    }
}
/// Fold a fact stream into an agent graph.
///
/// Order-independent by construction: every collection is sorted before it is
/// returned, so shuffling the input cannot change the output. That property is
/// asserted directly in the test suite.
#[must_use]
pub fn fold(facts: &[Fact]) -> AgentGraph {
    fold_with_home(facts, std::env::var("HOME").ok().as_deref())
}

/// The fold, with the home directory supplied rather than read.
///
/// The one impure edge of the core is which directory `~` stands for. Taking it
/// as an argument keeps the fold a pure function of its input, which is what
/// lets the suite replay fact streams without an operating system under them.
#[must_use]
pub fn fold_with_home(facts: &[Fact], home: Option<&str>) -> AgentGraph {
    let mut builders: BTreeMap<AgentId, Builder> = BTreeMap::new();
    let mut rejected = Vec::new();

    // Pass one: which identities were actually established as agents.
    //
    // Order-independence is why this is a separate pass rather than a check
    // inside the fold: an extension host's `EditorExtensionActive` can arrive
    // before its `ProcessSeen`, and shuffling the input must not change the
    // output. The suite asserts that property directly.
    let anchored = anchored_identities(facts);

    for fact in facts {
        let Subject::Process { pid, started_at } = *fact.subject() else {
            // A fact about a bare path or endpoint has no agent to attach to.
            // Collectors always anchor to the process that did the thing; a fact
            // that does not is a collector bug, and is reported rather than dropped.
            rejected.push(Rejected {
                reason: RejectReason::UnanchoredSubject,
                claim_kind: fact.claim().kind(),
                subject: None,
            });
            continue;
        };

        let id = AgentId { pid, started_at };
        if !anchored.contains(&id) {
            rejected.push(Rejected {
                reason: RejectReason::UnanchoredIdentity,
                claim_kind: fact.claim().kind(),
                subject: Some(id),
            });
            continue;
        }
        let b = builders.entry(id).or_default();
        b.fact_count += 1;
        b.best_confidence = Some(match b.best_confidence {
            Some(c) if c >= fact.confidence() => c,
            _ => fact.confidence(),
        });
        // Weakest wins per evidence kind: a factor is only as good as the least
        // certain observation behind it.
        b.claim_confidence
            .entry(fact.claim().kind())
            .and_modify(|c| {
                if fact.confidence() < *c {
                    *c = fact.confidence();
                }
            })
            .or_insert_with(|| fact.confidence());

        apply(b, fact, home);
    }

    let mut agents: Vec<Agent> = builders.into_iter().map(|(id, b)| finish(id, b)).collect();
    agents.sort_by_key(|a| (a.id.pid, a.id.started_at));

    rejected.sort_by(|a, b| {
        (a.claim_kind, a.subject.map(|id| (id.pid, id.started_at)))
            .cmp(&(b.claim_kind, b.subject.map(|id| (id.pid, id.started_at))))
    });

    AgentGraph { agents, rejected }
}

/// The identities the fact stream established as agents.
///
/// An anchor is a `ProcessSeen` — which carries the executable and the owner
/// that detection actually rests on — plus one of the two things that says
/// *what* it is: a recognised family, or an agent extension verified active
/// inside an editor host.
///
/// Neither half is enough alone. `ProcessSeen` is emitted for extension hosts
/// and, with `include_unrecognised`, for every process on the machine.
/// `AgentFamily` on its own has none of the executable and owner evidence that
/// normally accompanies a detection.
///
/// A descendant is deliberately *not* a third way in. An agent that spawns
/// `curl` is answerable for what `curl` does, but the activity timeline already
/// attributes a descendant's facts to the agent that spawned it, working from
/// the fact stream rather than from the inventory. Anchoring descendants as
/// well put a blank row in the inventory for every helper process an agent had
/// touched — nineteen of them on one lab host — which is the same defect this
/// function exists to close, wearing a different hat.
fn anchored_identities(facts: &[Fact]) -> std::collections::BTreeSet<AgentId> {
    let mut seen = std::collections::BTreeSet::new();
    let mut named = std::collections::BTreeSet::new();
    for fact in facts {
        let Subject::Process { pid, started_at } = *fact.subject() else {
            continue;
        };
        let id = AgentId { pid, started_at };
        match fact.claim() {
            Claim::ProcessSeen { .. } => {
                seen.insert(id);
            }
            Claim::AgentFamily { .. } | Claim::EditorExtensionActive { .. } => {
                named.insert(id);
            }
            _ => {}
        }
    }
    seen.intersection(&named).copied().collect()
}

fn apply(b: &mut Builder, fact: &Fact, home: Option<&str>) {
    let probe = fact.provenance().probe.as_str();
    match fact.claim() {
        Claim::ProcessSeen {
            exe,
            exe_path_known,
            uid,
            user,
        } => {
            b.exe = Some(exe.clone());
            b.exe_path_known = *exe_path_known;
            b.uid = (*uid != 0).then_some(*uid);
            b.user = Some(user.clone());
        }
        Claim::ProcessParent { parent_pid } => b.parent_pid = Some(*parent_pid),
        Claim::ChildProcessSeen { pid, name, depth } => {
            b.children.insert(*pid, (name.clone(), *depth));
        }
        Claim::SocketOpen {
            protocol,
            host,
            port,
            direction,
            opened_at,
            bytes,
        } => {
            // The protocol is part of the identity. A UDP datagram and a TCP
            // stream to the same host and port are two different things, and
            // folding them together loses the one that has no peer.
            let key = (*protocol, host.clone(), *port, direction_key(*direction));
            // Keep the earliest creation time any collector reported for this
            // endpoint. A later sweep of the same live connection must not
            // make it look younger, and a collector with no timestamp must not
            // erase one from a collector that has it.
            let entry = b
                .endpoints
                .entry(key)
                .or_insert((*direction, *opened_at, *bytes));
            entry.0 = *direction;
            entry.1 = match (entry.1, *opened_at) {
                (Some(kept), Some(seen)) => Some(kept.min(seen)),
                (kept, seen) => kept.or(seen),
            };
            // Counters only rise for the life of a connection, so the largest
            // reading is the current one. A collector without counters must not
            // erase one from a collector that has them.
            entry.2 = match (entry.2, *bytes) {
                (Some(kept), Some(seen)) => Some(ByteCounters {
                    sent: kept.sent.max(seen.sent),
                    received: kept.received.max(seen.received),
                }),
                (kept, seen) => kept.or(seen),
            };
        }
        // A lookup, a teardown and a filtering decision are all events in
        // time. None of them is a standing property of the agent, so none of
        // them belongs in the graph; the activity timeline is their home.
        Claim::SocketClosed { .. }
        | Claim::ConnectionAttempt { .. }
        | Claim::DnsQueryObserved { .. } => {}
        Claim::FileTouched { path, access } => {
            let r = b.resources.entry(resource_key(path, home)).or_default();
            r.observed = Tri::Yes;
            r.widen(*access);
            r.note(probe);
        }
        Claim::PermissionDeclared {
            path,
            access,
            granted,
        } => {
            b.has_declared_permissions = true;
            let r = b.resources.entry(resource_key(path, home)).or_default();
            r.declared = if *granted { Tri::Yes } else { Tri::No };
            if *granted {
                r.widen(*access);
            }
            r.note(probe);
        }
        Claim::ResourceReachable {
            path,
            access,
            sensitive,
            evidence,
        } => {
            let r = b.resources.entry(resource_key(path, home)).or_default();
            r.reach(*access, *sensitive, *evidence);
            r.note(probe);
        }
        Claim::AgentFamily { family } => b.family = Some(family.clone()),
        Claim::EditorExtensionActive {
            family,
            extension_id,
        } => {
            b.extensions.insert(extension_id.clone(), family.clone());
        }
        Claim::ModelInUse { provider, model } => {
            b.model = Some((provider.clone(), model.clone()));
        }
        Claim::ConnectorDeclared { name, access } => {
            b.connectors.insert(name.clone(), *access);
        }
        Claim::InvokesAgent { target_pid, via } => {
            b.invokes.insert(*target_pid, via.clone());
        }
        Claim::ActionTaken { action, succeeded } => {
            b.actions.push((action.clone(), *succeeded));
        }
    }
}

const fn direction_key(d: Direction) -> u8 {
    match d {
        Direction::Outbound => 0,
        Direction::Listening => 1,
    }
}

fn finish(id: AgentId, b: Builder) -> Agent {
    // A resource the agent's own config never mentions is `No`, not `Unknown`,
    // but only once we have seen that it HAS a config to mention things in.
    // Without that check an agent nobody has read config for would report every
    // path as denied, which reads as reassurance we have not earned.
    let close_declared = b.has_declared_permissions;

    let mut resources: Vec<ResourceAccess> = b
        .resources
        .into_iter()
        .map(|(path, r)| {
            let declared = match r.declared {
                Tri::Unknown if close_declared => Tri::No,
                other => other,
            };
            let mut evidence = r.evidence;
            evidence.sort();
            ResourceAccess {
                path,
                declared,
                observed: match r.observed {
                    Tri::Unknown if close_declared => Tri::No,
                    other => other,
                },
                reachable: r.reachable,
                reach_evidence: r.reach_evidence,
                sensitive: r.sensitive,
                access: r.access,
                evidence,
            }
        })
        .collect();
    resources.sort_by(|a, b| a.path.cmp(&b.path));

    let mut connectors: Vec<Connector> = b
        .connectors
        .into_iter()
        .map(|(name, access)| Connector { name, access })
        .collect();
    connectors.sort_by(|a, b| a.name.cmp(&b.name));

    let mut endpoints: Vec<Endpoint> = b
        .endpoints
        .into_iter()
        .map(
            |((protocol, host, port, _), (direction, opened_at, bytes))| Endpoint {
                protocol,
                host,
                port,
                direction,
                opened_at,
                bytes,
            },
        )
        .collect();
    endpoints.sort_by(|a, b| (&a.host, a.port, a.protocol).cmp(&(&b.host, b.port, b.protocol)));

    let mut invokes: Vec<AgentEdge> = b
        .invokes
        .into_iter()
        .map(|(target_pid, via)| AgentEdge { target_pid, via })
        .collect();
    invokes.sort_by_key(|e| e.target_pid);

    let mut actions = b.actions;
    actions.sort();

    let extensions = b
        .extensions
        .into_iter()
        .map(|(extension_id, family)| EditorExtension {
            family,
            extension_id,
        })
        .collect();

    let mut children: Vec<ChildProcess> = b
        .children
        .into_iter()
        .map(|(pid, (name, depth))| ChildProcess { pid, name, depth })
        .collect();
    children.sort_by_key(|c| (c.depth, c.pid));

    // An agent whose permissions come from a person's configuration file is
    // acting as that person, whatever the process table says. One with an
    // account of its own and no such config is a service.
    let identity = match (b.has_declared_permissions, b.uid) {
        (true, Some(_)) => IdentityKind::DelegatedHuman,
        (false, Some(_)) => IdentityKind::ServiceAccount,
        (_, None) => IdentityKind::Unknown,
    };

    Agent {
        id,
        family: b.family,
        extensions,
        exe: b.exe,
        exe_path_known: b.exe_path_known,
        uid: b.uid,
        user: b.user,
        identity,
        model: b.model,
        parent_pid: b.parent_pid,
        children,
        connectors,
        endpoints,
        resources,
        invokes,
        actions,
        discovery_confidence: b.best_confidence.unwrap_or(Confidence::Possible),
        evidence_confidence: b.claim_confidence,
        fact_count: b.fact_count,
    }
}
