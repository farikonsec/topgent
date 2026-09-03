//! Canonical bytes for the fact vocabulary.
//!
//! The wire name of every foreign enum is written here rather than borrowed
//! from a `label()` or `as_str()` upstream. Those exist for reports, and a
//! report label is allowed to change wording. A wire name is not: changing one
//! changes every evidence id derived from it. Keeping the mapping local means a
//! new upstream variant fails to compile here, which is the correct failure.

use topgent_facts::{
    Access, ByteCounters, Claim, Confidence, ConnectionOutcome, Direction, DnsOutcome, Fact,
    MatchBasis, Protocol, Provenance, Reachability, Subject, UnixMillis,
};

use crate::canonical::{Canonical, Encode};

impl Encode for UnixMillis {
    fn encode(&self, into: &mut Canonical) {
        into.u64(self.0);
    }
}

impl Encode for Access {
    fn encode(&self, into: &mut Canonical) {
        into.text(match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::ReadWrite => "read_write",
            Self::Execute => "execute",
        });
    }
}

impl Encode for Direction {
    fn encode(&self, into: &mut Canonical) {
        into.text(match self {
            Self::Outbound => "outbound",
            Self::Listening => "listening",
        });
    }
}

impl Encode for Protocol {
    fn encode(&self, into: &mut Canonical) {
        into.text(match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
            Self::Other => "other",
        });
    }
}

impl Encode for MatchBasis {
    fn encode(&self, into: &mut Canonical) {
        into.text(match self {
            Self::Unreported => "unreported",
            Self::Listener => "listener",
            Self::WildcardLocal => "wildcard_local",
            Self::ExactTuple => "exact_tuple",
            Self::KernelEvent => "kernel_event",
        });
    }
}

impl Encode for Reachability {
    fn encode(&self, into: &mut Canonical) {
        into.text(match self {
            Self::AccountReadable => "account_readable",
            Self::PathResolves => "path_resolves",
        });
    }
}

impl Encode for Confidence {
    fn encode(&self, into: &mut Canonical) {
        into.text(match self {
            Self::Possible => "possible",
            Self::Likely => "likely",
            Self::Certain => "certain",
        });
    }
}

impl Encode for ConnectionOutcome {
    fn encode(&self, into: &mut Canonical) {
        into.text(match self {
            Self::Allowed => "allowed",
            Self::Blocked => "blocked",
        });
    }
}

impl Encode for DnsOutcome {
    fn encode(&self, into: &mut Canonical) {
        into.text(match self {
            Self::Answered => "answered",
            Self::NotFound => "not_found",
            Self::Failed => "failed",
        });
    }
}

impl Encode for ByteCounters {
    fn encode(&self, into: &mut Canonical) {
        into.u64(self.sent);
        into.u64(self.received);
    }
}

impl Encode for Subject {
    fn encode(&self, into: &mut Canonical) {
        match self {
            Self::Process { pid, started_at } => {
                into.text("process");
                into.u32(*pid);
                started_at.encode(into);
            }
            Self::Resource { path } => {
                into.text("resource");
                into.text(path);
            }
            Self::Endpoint { host, port } => {
                into.text("endpoint");
                into.text(host);
                into.u16(*port);
            }
        }
    }
}

impl Encode for Provenance {
    fn encode(&self, into: &mut Canonical) {
        into.text(&self.collector);
        into.text(&self.probe);
        self.confidence.encode(into);
        self.observed_at.encode(into);
    }
}

impl Encode for Fact {
    fn encode(&self, into: &mut Canonical) {
        into.u16(self.schema().0);
        self.subject().encode(into);
        self.claim().encode(into);
        self.provenance().encode(into);
    }
}

/// Writes a boolean as one byte.
fn boolean(into: &mut Canonical, value: bool) {
    into.tag(u8::from(value));
}

impl Encode for Claim {
    // One flat exhaustive match over the whole vocabulary. Splitting it across
    // helpers to satisfy a line count would cost the exhaustiveness check that
    // makes a new upstream variant fail to compile here, which is the only
    // thing stopping a claim from being silently encoded as nothing.
    #[allow(clippy::too_many_lines)]
    /// Fields are written in declaration order, after the stable kind name.
    ///
    /// The kind is written as text rather than as a numeric discriminant, so a
    /// variant added upstream cannot shift the meaning of an existing id.
    fn encode(&self, into: &mut Canonical) {
        into.text(self.kind());
        match self {
            Self::ProcessSeen {
                exe,
                exe_path_known,
                uid,
                user,
            } => {
                into.text(exe);
                boolean(into, *exe_path_known);
                into.u32(*uid);
                into.text(user);
            }
            Self::ProcessParent { parent_pid } => into.u32(*parent_pid),
            Self::ChildProcessSeen { pid, name, depth } => {
                into.u32(*pid);
                into.text(name);
                into.u16(*depth);
            }
            Self::SocketOpen {
                protocol,
                host,
                port,
                direction,
                opened_at,
                bytes,
                basis,
            } => {
                protocol.encode(into);
                into.text(host);
                into.u16(*port);
                direction.encode(into);
                into.option(opened_at.as_ref());
                into.option(bytes.as_ref());
                basis.encode(into);
            }
            Self::SocketClosed {
                host,
                port,
                direction,
                duration_ms,
            } => {
                into.text(host);
                into.u16(*port);
                direction.encode(into);
                into.u64(*duration_ms);
            }
            Self::ConnectionAttempt {
                host,
                port,
                direction,
                outcome,
            } => {
                into.text(host);
                into.u16(*port);
                direction.encode(into);
                outcome.encode(into);
            }
            Self::DnsQueryObserved {
                name,
                query_type,
                outcome,
            } => {
                into.text(name);
                into.u16(*query_type);
                outcome.encode(into);
            }
            Self::FileTouched { path, access } => {
                into.text(path);
                access.encode(into);
            }
            Self::PermissionDeclared {
                path,
                access,
                granted,
            } => {
                into.text(path);
                access.encode(into);
                boolean(into, *granted);
            }
            Self::ResourceReachable {
                path,
                access,
                sensitive,
                evidence,
            } => {
                into.text(path);
                access.encode(into);
                boolean(into, *sensitive);
                evidence.encode(into);
            }
            Self::AgentFamily { family } => into.text(family),
            Self::EditorExtensionActive {
                family,
                extension_id,
            } => {
                into.text(family);
                into.text(extension_id);
            }
            Self::ModelInUse { provider, model } => {
                into.text(provider);
                into.text(model);
            }
            Self::ConnectorDeclared { name, access } => {
                into.text(name);
                access.encode(into);
            }
            Self::InvokesAgent { target_pid, via } => {
                into.u32(*target_pid);
                into.text(via);
            }
            Self::SubjectNotEvaluated { reason } => into.text(reason),
            Self::ActionTaken { action, succeeded } => {
                into.text(action);
                boolean(into, *succeeded);
            }
        }
    }
}

use crate::reader::{Decode, DecodeError, Reader};

impl Decode for UnixMillis {
    fn decode(from: &mut Reader<'_>) -> Result<Self, DecodeError> {
        from.u64().map(Self)
    }
}

impl Decode for Access {
    fn decode(from: &mut Reader<'_>) -> Result<Self, DecodeError> {
        from.variant(
            "access",
            &[
                ("read", Self::Read),
                ("write", Self::Write),
                ("read_write", Self::ReadWrite),
                ("execute", Self::Execute),
            ],
        )
    }
}

impl Decode for Direction {
    fn decode(from: &mut Reader<'_>) -> Result<Self, DecodeError> {
        from.variant(
            "direction",
            &[("outbound", Self::Outbound), ("listening", Self::Listening)],
        )
    }
}

impl Decode for Protocol {
    fn decode(from: &mut Reader<'_>) -> Result<Self, DecodeError> {
        from.variant(
            "protocol",
            &[
                ("tcp", Self::Tcp),
                ("udp", Self::Udp),
                ("icmp", Self::Icmp),
                ("other", Self::Other),
            ],
        )
    }
}

impl Decode for MatchBasis {
    fn decode(from: &mut Reader<'_>) -> Result<Self, DecodeError> {
        from.variant(
            "match_basis",
            &[
                ("unreported", Self::Unreported),
                ("listener", Self::Listener),
                ("wildcard_local", Self::WildcardLocal),
                ("exact_tuple", Self::ExactTuple),
                ("kernel_event", Self::KernelEvent),
            ],
        )
    }
}

impl Decode for Reachability {
    fn decode(from: &mut Reader<'_>) -> Result<Self, DecodeError> {
        from.variant(
            "reachability",
            &[
                ("account_readable", Self::AccountReadable),
                ("path_resolves", Self::PathResolves),
            ],
        )
    }
}

impl Decode for Confidence {
    fn decode(from: &mut Reader<'_>) -> Result<Self, DecodeError> {
        from.variant(
            "confidence",
            &[
                ("possible", Self::Possible),
                ("likely", Self::Likely),
                ("certain", Self::Certain),
            ],
        )
    }
}

impl Decode for ConnectionOutcome {
    fn decode(from: &mut Reader<'_>) -> Result<Self, DecodeError> {
        from.variant(
            "connection_outcome",
            &[("allowed", Self::Allowed), ("blocked", Self::Blocked)],
        )
    }
}

impl Decode for DnsOutcome {
    fn decode(from: &mut Reader<'_>) -> Result<Self, DecodeError> {
        from.variant(
            "dns_outcome",
            &[
                ("answered", Self::Answered),
                ("not_found", Self::NotFound),
                ("failed", Self::Failed),
            ],
        )
    }
}

impl Decode for ByteCounters {
    fn decode(from: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            sent: from.u64()?,
            received: from.u64()?,
        })
    }
}

impl Decode for Subject {
    fn decode(from: &mut Reader<'_>) -> Result<Self, DecodeError> {
        match from.text()? {
            "process" => Ok(Self::Process {
                pid: from.u32()?,
                started_at: UnixMillis::decode(from)?,
            }),
            "resource" => Ok(Self::Resource {
                path: from.string()?,
            }),
            "endpoint" => Ok(Self::Endpoint {
                host: from.string()?,
                port: from.u16()?,
            }),
            found => Err(DecodeError::UnknownVariant {
                vocabulary: "subject",
                found: found.to_owned(),
            }),
        }
    }
}

impl Decode for Provenance {
    fn decode(from: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            collector: from.string()?,
            probe: from.string()?,
            confidence: Confidence::decode(from)?,
            observed_at: UnixMillis::decode(from)?,
        })
    }
}

impl Decode for Fact {
    /// Reads through [`Fact::new`], so a record that could not have been
    /// produced cannot be read in either.
    fn decode(from: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let schema = topgent_facts::SchemaVersion(from.u16()?);
        let subject = Subject::decode(from)?;
        let claim = Claim::decode(from)?;
        let provenance = Provenance::decode(from)?;
        Self::new(schema, subject, claim, provenance).map_err(|error| DecodeError::Rejected {
            reason: error.to_string(),
        })
    }
}

impl Decode for Claim {
    // The mirror of `encode`, arm for arm. Same reason for the flat match: the
    // exhaustive kind list is the thing that makes an unknown claim an error
    // rather than a silent zero-byte read.
    #[allow(clippy::too_many_lines)]
    fn decode(from: &mut Reader<'_>) -> Result<Self, DecodeError> {
        match from.text()? {
            "process_seen" => Ok(Self::ProcessSeen {
                exe: from.string()?,
                exe_path_known: from.boolean()?,
                uid: from.u32()?,
                user: from.string()?,
            }),
            "process_parent" => Ok(Self::ProcessParent {
                parent_pid: from.u32()?,
            }),
            "child_process_seen" => Ok(Self::ChildProcessSeen {
                pid: from.u32()?,
                name: from.string()?,
                depth: from.u16()?,
            }),
            "socket_open" => Ok(Self::SocketOpen {
                protocol: Protocol::decode(from)?,
                host: from.string()?,
                port: from.u16()?,
                direction: Direction::decode(from)?,
                opened_at: from.option()?,
                bytes: from.option()?,
                basis: MatchBasis::decode(from)?,
            }),
            "socket_closed" => Ok(Self::SocketClosed {
                host: from.string()?,
                port: from.u16()?,
                direction: Direction::decode(from)?,
                duration_ms: from.u64()?,
            }),
            "connection_attempt" => Ok(Self::ConnectionAttempt {
                host: from.string()?,
                port: from.u16()?,
                direction: Direction::decode(from)?,
                outcome: ConnectionOutcome::decode(from)?,
            }),
            "dns_query_observed" => Ok(Self::DnsQueryObserved {
                name: from.string()?,
                query_type: from.u16()?,
                outcome: DnsOutcome::decode(from)?,
            }),
            "file_touched" => Ok(Self::FileTouched {
                path: from.string()?,
                access: Access::decode(from)?,
            }),
            "permission_declared" => Ok(Self::PermissionDeclared {
                path: from.string()?,
                access: Access::decode(from)?,
                granted: from.boolean()?,
            }),
            "resource_reachable" => Ok(Self::ResourceReachable {
                path: from.string()?,
                access: Access::decode(from)?,
                sensitive: from.boolean()?,
                evidence: Reachability::decode(from)?,
            }),
            "agent_family" => Ok(Self::AgentFamily {
                family: from.string()?,
            }),
            "editor_extension_active" => Ok(Self::EditorExtensionActive {
                family: from.string()?,
                extension_id: from.string()?,
            }),
            "model_in_use" => Ok(Self::ModelInUse {
                provider: from.string()?,
                model: from.string()?,
            }),
            "connector_declared" => Ok(Self::ConnectorDeclared {
                name: from.string()?,
                access: Access::decode(from)?,
            }),
            "invokes_agent" => Ok(Self::InvokesAgent {
                target_pid: from.u32()?,
                via: from.string()?,
            }),
            "subject_not_evaluated" => Ok(Self::SubjectNotEvaluated {
                reason: from.string()?,
            }),
            "action_taken" => Ok(Self::ActionTaken {
                action: from.string()?,
                succeeded: from.boolean()?,
            }),
            found => Err(DecodeError::UnknownVariant {
                vocabulary: "claim",
                found: found.to_owned(),
            }),
        }
    }
}
