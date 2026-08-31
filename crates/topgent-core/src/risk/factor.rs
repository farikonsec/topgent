//! The vocabulary of findings.
//!
//! Every factor code carries its own points and its own sentence. A score is
//! only ever the sum of these, so there is no path by which a number appears
//! that cannot name what produced it.

use topgent_facts::Confidence;

/// Which contribution a factor is.
///
/// An enum rather than a string so every mapping over it — display, remediation,
/// the fix list — is exhaustive by the compiler. A string here produced a
/// catch-all arm nothing could reach.
/// Variants are declared worst-first on purpose: `Ord` follows declaration
/// order, and factors on equal points are broken by this ordering, so the list a
/// user reads is severity-ordered rather than alphabetical.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FactorCode {
    /// The agent can run arbitrary commands.
    ArbitraryExecution,
    /// It can write outside anything it declared.
    BroadWrite,
    /// A credential sits in reach.
    SecretReachable,
    /// Its outbound network is unbounded.
    UnrestrictedNetwork,
    /// It touched something its config never granted.
    DeclarationDrift,
    /// It can invoke another agent.
    AgentChain,
    /// It can both reach a credential and act on one.
    ExfiltrationPath,
    /// Its live connections have the shape of scanning — many hosts, or many
    /// ports to one host.
    ReconFanout,
    /// It matched a path on the user's watchlist.
    Watchlist,
    /// It claims to be sandboxed, but its behaviour reaches outside the sandbox.
    SandboxEscape,
    /// The agent exposed a listener beyond loopback.
    ExposedListener,
    /// A known offensive utility is running below the agent.
    OffensiveTool,
    /// The agent has spawned an unusual number of descendants.
    ProcessExplosion,
    /// A raw address is contacted on a suspicious port.
    SuspiciousEndpoint,
    /// The agent is talking to a private-network peer.
    PrivatePeer,
    /// The agent contacted a cloud instance metadata service.
    MetadataService,
    /// A credential was actually opened.
    CredentialAccess,
    /// A persistence location was modified.
    PersistenceWrite,
    /// The agent modified Topgent or its policy.
    SelfTampering,
    /// The agent is using an asset the user explicitly disallowed.
    DisallowedAsset,
}

impl FactorCode {
    /// Stable machine-readable name, for logs and tests.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ArbitraryExecution => "ARBITRARY_EXECUTION",
            Self::BroadWrite => "BROAD_WRITE",
            Self::UnrestrictedNetwork => "UNRESTRICTED_NETWORK",
            Self::SecretReachable => "SECRET_REACHABLE",
            Self::DeclarationDrift => "DECLARATION_DRIFT",
            Self::AgentChain => "AGENT_CHAIN",
            Self::ExfiltrationPath => "EXFILTRATION_PATH",
            Self::ReconFanout => "RECON_FANOUT",
            Self::Watchlist => "WATCHLIST",
            Self::SandboxEscape => "SANDBOX_ESCAPE",
            Self::ExposedListener => "EXPOSED_LISTENER",
            Self::OffensiveTool => "OFFENSIVE_TOOL",
            Self::ProcessExplosion => "PROCESS_EXPLOSION",
            Self::SuspiciousEndpoint => "SUSPICIOUS_ENDPOINT",
            Self::PrivatePeer => "PRIVATE_PEER",
            Self::MetadataService => "METADATA_SERVICE",
            Self::CredentialAccess => "CREDENTIAL_ACCESS",
            Self::PersistenceWrite => "PERSISTENCE_WRITE",
            Self::SelfTampering => "SELF_TAMPERING",
            Self::DisallowedAsset => "DISALLOWED_ASSET",
        }
    }

    /// What to do about it, and where.
    ///
    /// Read from the factor catalogue rather than restated here, so the
    /// sentence an operator acts on is the same one the interface showed them.
    /// A build whose catalogue will not load says so instead of offering
    /// advice it cannot source.
    #[must_use]
    pub fn remedy(self) -> (&'static str, &'static str) {
        topgent_policy::catalogue::builtin()
            .ok()
            .and_then(|catalogue| catalogue.entry(self.as_str()))
            .map_or(
                (
                    "Reinstall Topgent: this build cannot read its own risk catalogue",
                    "topgent itself",
                ),
                |entry| (entry.remedy.as_str(), entry.remedy_where.as_str()),
            )
    }
}

/// A named contribution to an agent's score.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Factor {
    /// Which contribution this is.
    pub code: FactorCode,
    /// Points this factor added, after the identity multiplier.
    pub points: u32,
    /// One line the user reads.
    pub title: String,
    /// The observation behind it, printable.
    pub source: String,
    /// How much the observation is worth.
    pub confidence: Confidence,
}
