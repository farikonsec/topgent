//! Everything this build promises the outside world, in one hashable list.
//!
//! Topgent's public surface is not one file. It is the fact vocabulary, the
//! schema versions, the finding codes, the words a report is allowed to use
//! about quality and coverage, the signals a policy may read, and the names of
//! the collectors that ship. Any of those can be widened, narrowed or renamed
//! in an ordinary refactor, and nothing would notice until somebody's parser
//! broke.
//!
//! This module gathers all of it, renders it in a fixed order, and hashes the
//! rendering. The hash goes in a test. Changing the contract on purpose means
//! updating one constant and saying so in a commit; changing it by accident
//! means a red build with a diff naming what moved.
//!
//! # Why it is not generated
//!
//! A list that a macro derived would follow the code wherever it went, which
//! is exactly the property that makes it useless as a contract. The point is
//! that a human has to agree. What is mechanical here is the *coupling*: every
//! enumeration below is produced by an exhaustive `match`, so a variant added
//! to the fact vocabulary will not compile until it appears here.

use sha2::{Digest, Sha256};
use topgent_facts::{
    Access, Claim, Confidence, ConnectionOutcome, Direction, DnsOutcome, MatchBasis, Protocol,
    Reachability, Subject, Tri,
};

/// One named group of contract entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// What this group covers.
    pub name: &'static str,
    /// The entries, in the order they are hashed.
    pub entries: Vec<String>,
}

/// The whole public surface of this build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contract {
    /// Every section, in a fixed order.
    pub sections: Vec<Section>,
}

/// The descriptor for one subject variant, matched exhaustively.
///
/// The `match` is the guard. A new [`Subject`] variant will not compile until
/// it is named here, which is what stops the contract silently falling behind
/// the vocabulary it claims to describe.
const fn subject_shape(subject: &Subject) -> &'static str {
    match subject {
        Subject::Process { .. } => "Process(pid,started_at)",
        Subject::Resource { .. } => "Resource(path)",
        Subject::Endpoint { .. } => "Endpoint(host,port)",
    }
}

/// The descriptor for one claim variant, matched exhaustively.
const fn claim_shape(claim: &Claim) -> &'static str {
    match claim {
        Claim::ProcessSeen { .. } => "ProcessSeen(exe,exe_path_known,uid,user)",
        Claim::ProcessParent { .. } => "ProcessParent(parent_pid)",
        Claim::ChildProcessSeen { .. } => "ChildProcessSeen(pid,name,depth)",
        Claim::SocketOpen { .. } => {
            "SocketOpen(protocol,host,port,direction,opened_at,bytes,basis)"
        }
        Claim::SocketClosed { .. } => "SocketClosed(host,port,direction,duration_ms)",
        Claim::ConnectionAttempt { .. } => "ConnectionAttempt(host,port,direction,outcome)",
        Claim::TrafficObserved { .. } => {
            "TrafficObserved(protocol,host,port,direction,packets,first_seen,last_seen)"
        }
        Claim::DnsQueryObserved { .. } => "DnsQueryObserved(name,query_type,outcome)",
        Claim::FileTouched { .. } => "FileTouched(path,access)",
        Claim::PermissionDeclared { .. } => "PermissionDeclared(path,access,granted)",
        Claim::ResourceReachable { .. } => "ResourceReachable(path,access,sensitive,evidence)",
        Claim::AgentFamily { .. } => "AgentFamily(family)",
        Claim::EditorExtensionActive { .. } => "EditorExtensionActive(family,extension_id)",
        Claim::ModelInUse { .. } => "ModelInUse(provider,model)",
        Claim::ConnectorDeclared { .. } => "ConnectorDeclared(name,access)",
        Claim::InvokesAgent { .. } => "InvokesAgent(target_pid,via)",
        Claim::SubjectNotEvaluated { .. } => "SubjectNotEvaluated(reason)",
        Claim::ActionTaken { .. } => "ActionTaken(action)",
    }
}

/// Every subject shape this build understands.
///
/// Paired with [`subject_shape`] by a test, so neither can drift.
const SUBJECTS: &[&str] = &[
    "Process(pid,started_at)",
    "Resource(path)",
    "Endpoint(host,port)",
];

/// Every claim shape this build understands.
const CLAIMS: &[&str] = &[
    "ProcessSeen(exe,exe_path_known,uid,user)",
    "ProcessParent(parent_pid)",
    "ChildProcessSeen(pid,name,depth)",
    "SocketOpen(protocol,host,port,direction,opened_at,bytes,basis)",
    "SocketClosed(host,port,direction,duration_ms)",
    "ConnectionAttempt(host,port,direction,outcome)",
    "TrafficObserved(protocol,host,port,direction,packets,first_seen,last_seen)",
    "DnsQueryObserved(name,query_type,outcome)",
    "FileTouched(path,access)",
    "PermissionDeclared(path,access,granted)",
    "ResourceReachable(path,access,sensitive,evidence)",
    "AgentFamily(family)",
    "EditorExtensionActive(family,extension_id)",
    "ModelInUse(provider,model)",
    "ConnectorDeclared(name,access)",
    "InvokesAgent(target_pid,via)",
    "SubjectNotEvaluated(reason)",
    "ActionTaken(action)",
];

/// Scalar vocabularies, each matched exhaustively so a variant cannot be added
/// without this list refusing to compile.
// Nine exhaustive matches in one place. Splitting them into nine functions
// would hide that this is one list, and the list is the point.
#[allow(clippy::too_many_lines)]
fn scalars() -> Vec<String> {
    const fn confidence(value: Confidence) -> &'static str {
        match value {
            Confidence::Possible => "Confidence::Possible",
            Confidence::Likely => "Confidence::Likely",
            Confidence::Certain => "Confidence::Certain",
        }
    }
    const fn tri(value: Tri) -> &'static str {
        match value {
            Tri::Yes => "Tri::Yes",
            Tri::No => "Tri::No",
            Tri::Unknown => "Tri::Unknown",
        }
    }
    const fn access(value: Access) -> &'static str {
        match value {
            Access::Read => "Access::Read",
            Access::Write => "Access::Write",
            Access::ReadWrite => "Access::ReadWrite",
            Access::Execute => "Access::Execute",
        }
    }
    const fn direction(value: Direction) -> &'static str {
        match value {
            Direction::Outbound => "Direction::Outbound",
            Direction::Listening => "Direction::Listening",
        }
    }
    const fn protocol(value: Protocol) -> &'static str {
        match value {
            Protocol::Tcp => "Protocol::Tcp",
            Protocol::Udp => "Protocol::Udp",
            Protocol::Icmp => "Protocol::Icmp",
            Protocol::Other => "Protocol::Other",
            Protocol::Unstated => "Protocol::Unstated",
        }
    }
    const fn reachability(value: Reachability) -> &'static str {
        match value {
            Reachability::AccountReadable => "Reachability::AccountReadable",
            Reachability::PathResolves => "Reachability::PathResolves",
        }
    }
    const fn basis(value: MatchBasis) -> &'static str {
        match value {
            MatchBasis::Unreported => "MatchBasis::Unreported",
            MatchBasis::Listener => "MatchBasis::Listener",
            MatchBasis::WildcardLocal => "MatchBasis::WildcardLocal",
            MatchBasis::ExactTuple => "MatchBasis::ExactTuple",
            MatchBasis::KernelEvent => "MatchBasis::KernelEvent",
        }
    }
    const fn connection(value: ConnectionOutcome) -> &'static str {
        match value {
            ConnectionOutcome::Allowed => "ConnectionOutcome::Allowed",
            ConnectionOutcome::Blocked => "ConnectionOutcome::Blocked",
        }
    }
    const fn dns(value: DnsOutcome) -> &'static str {
        match value {
            DnsOutcome::Answered => "DnsOutcome::Answered",
            DnsOutcome::NotFound => "DnsOutcome::NotFound",
            DnsOutcome::Failed => "DnsOutcome::Failed",
        }
    }
    let mut out: Vec<String> = Vec::new();
    for value in [
        Confidence::Possible,
        Confidence::Likely,
        Confidence::Certain,
    ] {
        out.push(confidence(value).to_owned());
    }
    for value in [Tri::Yes, Tri::No, Tri::Unknown] {
        out.push(tri(value).to_owned());
    }
    for value in [
        Access::Read,
        Access::Write,
        Access::ReadWrite,
        Access::Execute,
    ] {
        out.push(access(value).to_owned());
    }
    for value in [Direction::Outbound, Direction::Listening] {
        out.push(direction(value).to_owned());
    }
    for value in [
        Protocol::Tcp,
        Protocol::Udp,
        Protocol::Icmp,
        Protocol::Other,
        Protocol::Unstated,
    ] {
        out.push(protocol(value).to_owned());
    }
    for value in [Reachability::AccountReadable, Reachability::PathResolves] {
        out.push(reachability(value).to_owned());
    }
    for value in [
        MatchBasis::Unreported,
        MatchBasis::Listener,
        MatchBasis::WildcardLocal,
        MatchBasis::ExactTuple,
        MatchBasis::KernelEvent,
    ] {
        out.push(basis(value).to_owned());
    }
    for value in [ConnectionOutcome::Allowed, ConnectionOutcome::Blocked] {
        out.push(connection(value).to_owned());
    }
    for value in [
        DnsOutcome::Answered,
        DnsOutcome::NotFound,
        DnsOutcome::Failed,
    ] {
        out.push(dns(value).to_owned());
    }
    out
}

/// The words a report may use about how well something was established.
fn quality_vocabulary() -> Vec<String> {
    use topgent_evidence::{AttributionQuality, CollectionCoverage, Limitation};
    const fn quality(value: AttributionQuality) -> &'static str {
        match value {
            AttributionQuality::Unknown => "AttributionQuality::Unknown",
            AttributionQuality::Contradicted => "AttributionQuality::Contradicted",
            AttributionQuality::Weak => "AttributionQuality::Weak",
            AttributionQuality::Strong => "AttributionQuality::Strong",
            AttributionQuality::Exact => "AttributionQuality::Exact",
        }
    }
    const fn coverage(value: CollectionCoverage) -> &'static str {
        match value {
            CollectionCoverage::Unsupported => "CollectionCoverage::Unsupported",
            CollectionCoverage::LossObserved => "CollectionCoverage::LossObserved",
            CollectionCoverage::CollectorDegraded => "CollectionCoverage::CollectorDegraded",
            CollectionCoverage::SnapshotOnly => "CollectionCoverage::SnapshotOnly",
            CollectionCoverage::CompleteForWindow => "CollectionCoverage::CompleteForWindow",
        }
    }
    const fn limitation(value: Limitation) -> &'static str {
        match value {
            Limitation::ConfinementUnknown => "Limitation::ConfinementUnknown",
            Limitation::ForeignCredentials => "Limitation::ForeignCredentials",
            Limitation::NoAccessCheck => "Limitation::NoAccessCheck",
            Limitation::OwnerUnresolved => "Limitation::OwnerUnresolved",
            Limitation::SnapshotAncestry => "Limitation::SnapshotAncestry",
            Limitation::PartialTuple => "Limitation::PartialTuple",
            Limitation::EventsDropped => "Limitation::EventsDropped",
            Limitation::SensorGap => "Limitation::SensorGap",
            Limitation::ProvenanceUnreported => "Limitation::ProvenanceUnreported",
        }
    }
    let mut out = Vec::new();
    for value in [
        AttributionQuality::Unknown,
        AttributionQuality::Contradicted,
        AttributionQuality::Weak,
        AttributionQuality::Strong,
        AttributionQuality::Exact,
    ] {
        out.push(quality(value).to_owned());
    }
    for value in [
        CollectionCoverage::Unsupported,
        CollectionCoverage::LossObserved,
        CollectionCoverage::CollectorDegraded,
        CollectionCoverage::SnapshotOnly,
        CollectionCoverage::CompleteForWindow,
    ] {
        out.push(coverage(value).to_owned());
    }
    for value in [
        Limitation::ConfinementUnknown,
        Limitation::ForeignCredentials,
        Limitation::NoAccessCheck,
        Limitation::OwnerUnresolved,
        Limitation::SnapshotAncestry,
        Limitation::PartialTuple,
        Limitation::EventsDropped,
        Limitation::SensorGap,
        Limitation::ProvenanceUnreported,
    ] {
        out.push(limitation(value).to_owned());
    }
    out
}

/// The grades a score may be reported as.
fn grades() -> Vec<String> {
    use topgent_core::Grade;
    const fn grade(value: Grade) -> &'static str {
        match value {
            Grade::NotEvaluated => "Grade::NotEvaluated",
            Grade::Low => "Grade::Low",
            Grade::Medium => "Grade::Medium",
            Grade::High => "Grade::High",
            Grade::Critical => "Grade::Critical",
        }
    }
    [
        Grade::NotEvaluated,
        Grade::Low,
        Grade::Medium,
        Grade::High,
        Grade::Critical,
    ]
    .into_iter()
    .map(|value| grade(value).to_owned())
    .collect()
}

/// The contract this build ships.
#[must_use]
// One section per group, in the order they are hashed. Splitting it would put
// the order in two places, and the order is what the fingerprint is over.
#[allow(clippy::too_many_lines)]
pub fn contract() -> Contract {
    let collectors: Vec<String> = topgent_collect::default_collectors()
        .iter()
        .map(|collector| collector.id().to_owned())
        .collect();

    let mut factor_codes: Vec<String> = topgent_policy::catalogue::KNOWN_CODES
        .iter()
        .map(|code| (*code).to_owned())
        .collect();
    factor_codes.sort_unstable();

    let signals: Vec<String> = topgent_policy::Signal::all()
        .iter()
        .map(|signal| signal.as_str().to_owned())
        .collect();

    Contract {
        sections: vec![
            Section {
                name: "schema_versions",
                entries: vec![
                    format!("fact_schema={}", topgent_facts::SCHEMA_VERSION.0),
                    format!("evidence_schema={}", topgent_evidence::EVIDENCE_SCHEMA),
                    format!(
                        "report_contract={}",
                        topgent_export::REPORT_CONTRACT_VERSION
                    ),
                    format!(
                        "replay_contract={}",
                        topgent_report::REPLAY_CONTRACT_VERSION
                    ),
                    format!(
                        "risk_catalogue_schema={}",
                        topgent_policy::catalogue::builtin()
                            .map(|catalogue| catalogue.schema_version)
                            .unwrap_or_default()
                    ),
                    format!("cyclonedx_spec={}", topgent_export::CYCLONEDX_SPEC_VERSION),
                    format!("rule_catalogue={}", topgent_report::RULE_CATALOGUE_VERSION),
                ],
            },
            Section {
                name: "fact_subjects",
                entries: SUBJECTS.iter().map(|s| (*s).to_owned()).collect(),
            },
            Section {
                name: "fact_claims",
                entries: CLAIMS.iter().map(|s| (*s).to_owned()).collect(),
            },
            Section {
                name: "fact_scalars",
                entries: scalars(),
            },
            Section {
                name: "evidence_quality",
                entries: quality_vocabulary(),
            },
            Section {
                name: "risk_codes",
                entries: factor_codes,
            },
            Section {
                name: "factor_maturity",
                entries: {
                    use topgent_policy::Maturity;
                    const fn maturity(value: Maturity) -> &'static str {
                        match value {
                            Maturity::Sandbox => "sandbox",
                            Maturity::Experimental => "experimental",
                            Maturity::Incubating => "incubating",
                            Maturity::Stable => "stable",
                            Maturity::Deprecated => "deprecated",
                        }
                    }
                    let mut names: Vec<String> = [
                        Maturity::Sandbox,
                        Maturity::Experimental,
                        Maturity::Incubating,
                        Maturity::Stable,
                        Maturity::Deprecated,
                    ]
                    .into_iter()
                    .map(|value| maturity(value).to_owned())
                    .collect();
                    // Which factors are on by default is part of the contract
                    // too: switching one off changes what a report means.
                    if let Ok(catalogue) = topgent_policy::catalogue::builtin() {
                        for entry in &catalogue.factors {
                            names.push(format!("{}={}", entry.code, entry.maturity.as_str()));
                        }
                    }
                    names
                },
            },
            Section {
                name: "grades",
                entries: grades(),
            },
            Section {
                name: "policy_signals",
                entries: signals,
            },
            Section {
                name: "policy_operators",
                entries: ["all", "any", "not", "is", "at_least", "below"]
                    .iter()
                    .map(|s| (*s).to_owned())
                    .collect(),
            },
            Section {
                name: "item_vocabulary",
                entries: {
                    use topgent_policy::ItemKind;
                    let mut out = Vec::new();
                    for kind in ItemKind::all() {
                        for flag in kind.flags() {
                            out.push(format!("{}.{}", kind.as_str(), flag.as_str()));
                        }
                        for number in kind.numbers() {
                            out.push(format!("{}.{}", kind.as_str(), number.as_str()));
                        }
                        for placeholder in kind.placeholders() {
                            out.push(format!("{}.{{{}}}", kind.as_str(), placeholder.as_str()));
                        }
                    }
                    out
                },
            },
            Section {
                name: "item_operators",
                entries: ["all", "any", "not", "is", "in_list", "at_least"]
                    .iter()
                    .map(|s| (*s).to_owned())
                    .collect(),
            },
            Section {
                name: "policy_thresholds",
                entries: [
                    "network_spread",
                    "recon_hosts",
                    "recon_ports",
                    "process_children",
                ]
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            },
            Section {
                name: "collectors",
                entries: collectors,
            },
        ],
    }
}

impl Contract {
    /// The contract as text, in a fixed order, one entry per line.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        for section in &self.sections {
            for entry in &section.entries {
                out.push_str(section.name);
                out.push('\t');
                out.push_str(entry);
                out.push('\n');
            }
        }
        out
    }

    /// The hash of that text.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let digest = Sha256::digest(self.render().as_bytes());
        let mut out = String::with_capacity(digest.len() * 2);
        for byte in digest {
            out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
            out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
        }
        out
    }

    /// What changed between two contracts, as lines a person can read.
    ///
    /// This is the part that makes a failing fingerprint useful. A hash that
    /// differs tells you something moved; this tells you what, so the reviewer
    /// can decide whether it was meant.
    #[must_use]
    pub fn diff(&self, other: &Self) -> Vec<String> {
        let mine: Vec<String> = self.render().lines().map(str::to_owned).collect();
        let theirs: Vec<String> = other.render().lines().map(str::to_owned).collect();
        let mut out = Vec::new();
        for line in &theirs {
            if !mine.contains(line) {
                out.push(format!("+ {line}"));
            }
        }
        for line in &mine {
            if !theirs.contains(line) {
                out.push(format!("- {line}"));
            }
        }
        out
    }
}

/// Pairs the exhaustive matches with the constant lists, so neither can drift.
///
/// Exposed rather than kept private because the test that uses it is the whole
/// reason the matches exist.
#[must_use]
pub fn shape_of_subject(subject: &Subject) -> &'static str {
    subject_shape(subject)
}

/// See [`shape_of_subject`].
#[must_use]
pub fn shape_of_claim(claim: &Claim) -> &'static str {
    claim_shape(claim)
}

/// Every subject shape the contract lists.
#[must_use]
pub const fn listed_subjects() -> &'static [&'static str] {
    SUBJECTS
}

/// Every claim shape the contract lists.
#[must_use]
pub const fn listed_claims() -> &'static [&'static str] {
    CLAIMS
}
