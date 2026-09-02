//! Fact-stream fixtures.
//!
//! Tests describe what a collector *saw*, not what the core should do about it.
//! Everything downstream is then a pure function of that description, which is
//! why none of these tests need an operating system.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use topgent_facts::{
    Access, Claim, Confidence, ConnectionOutcome, Direction, DnsOutcome, Fact, Provenance,
    Reachability, SCHEMA_VERSION, Subject, UnixMillis,
};

/// A timestamp, in the arbitrary units the tests agree on.
#[must_use]
pub fn at(ms: u64) -> UnixMillis {
    UnixMillis(ms)
}

/// A subject that is a bare path, which the fold has nothing to anchor to.
#[must_use]
pub fn resource_subject(path: &str) -> Subject {
    Subject::Resource {
        path: path.to_owned(),
    }
}

/// A subject that is a bare endpoint, which the fold has nothing to anchor to.
#[must_use]
pub fn endpoint_subject(host: &str, port: u16) -> Subject {
    Subject::Endpoint {
        host: host.to_owned(),
        port,
    }
}

/// The `ProcessSeen` an editor extension host arrives with.
///
/// The editor collector emits this alongside every `EditorExtensionActive`, and
/// the fold anchors on both, so a fixture that models a shared host needs it
/// too.
#[must_use]
pub fn host_process(subject: Subject) -> Fact {
    fact(
        subject,
        Claim::ProcessSeen {
            exe: "/Applications/Visual Studio Code.app/Contents/MacOS/Electron".to_owned(),
            exe_path_known: true,
            uid: 501,
            user: "testuser".to_owned(),
        },
    )
}

pub fn fact(subject: Subject, claim: Claim) -> Fact {
    Fact::new(
        SCHEMA_VERSION,
        subject,
        claim,
        Provenance {
            collector: "test".to_owned(),
            probe: "fixture".to_owned(),
            confidence: Confidence::Certain,
            observed_at: at(1_000),
        },
    )
    .unwrap()
}

/// Builds a fact stream about one process.
pub struct Stream {
    pid: u32,
    started_at: UnixMillis,
    confidence: Confidence,
    probe: String,
    clock: u64,
    facts: Vec<Fact>,
    /// Whether `build` should supply a placeholder family so the fold anchors
    /// this identity. Set by `seen`, which models a process that is an agent.
    anchor: bool,
}

impl Stream {
    /// A stream about `pid`, started at a fixed default time.
    #[must_use]
    pub fn new(pid: u32) -> Self {
        Self::new_at(pid, at(1_000))
    }

    /// A stream about `pid` started at a specific time.
    #[must_use]
    pub fn new_at(pid: u32, started_at: UnixMillis) -> Self {
        Self {
            pid,
            started_at,
            confidence: Confidence::Certain,
            probe: "fixture".to_owned(),
            clock: 2_000,
            facts: Vec::new(),
            anchor: false,
        }
    }

    /// Confidence applied to every fact added after this call.
    #[must_use]
    pub fn confidence(mut self, c: Confidence) -> Self {
        self.confidence = c;
        self
    }

    fn push(mut self, claim: Claim) -> Self {
        self.clock += 1;
        let f = Fact::new(
            SCHEMA_VERSION,
            Subject::Process {
                pid: self.pid,
                started_at: self.started_at,
            },
            claim,
            Provenance {
                collector: "test".to_owned(),
                probe: self.probe.clone(),
                confidence: self.confidence,
                observed_at: UnixMillis(self.clock),
            },
        )
        .unwrap();
        self.facts.push(f);
        self
    }

    /// The process exists.
    ///
    /// The fold anchors an identity on a `ProcessSeen` **plus** something that
    /// says what it is, so [`Self::build`] supplies a placeholder family for a
    /// stream that names none. Use [`Self::seen_unrecognised`] to model the
    /// case the anchoring rule exists for: a process nothing recognised.
    #[must_use]
    pub fn seen(self, exe: &str, uid: u32, user: &str) -> Self {
        let mut next = self.seen_unrecognised(exe, uid, user);
        next.anchor = true;
        next
    }

    /// The process exists, and nothing established what it is.
    #[must_use]
    pub fn seen_unrecognised(self, exe: &str, uid: u32, user: &str) -> Self {
        self.push(Claim::ProcessSeen {
            exe_path_known: true,
            exe: exe.to_owned(),
            uid,
            user: user.to_owned(),
        })
    }

    /// It belongs to a known family.
    #[must_use]
    pub fn family(self, family: &str) -> Self {
        self.push(Claim::AgentFamily {
            family: family.to_owned(),
        })
    }

    /// It talks to a model.
    #[must_use]
    pub fn model(self, provider: &str, model: &str) -> Self {
        self.push(Claim::ModelInUse {
            provider: provider.to_owned(),
            model: model.to_owned(),
        })
    }

    /// It was spawned by another process.
    #[must_use]
    pub fn parent(self, parent_pid: u32) -> Self {
        self.push(Claim::ProcessParent { parent_pid })
    }

    /// A descendant process is running beneath it.
    #[must_use]
    pub fn child(self, pid: u32, name: &str, depth: u16) -> Self {
        self.push(Claim::ChildProcessSeen {
            pid,
            name: name.to_owned(),
            depth,
        })
    }

    /// Its config grants or refuses a path.
    #[must_use]
    pub fn declares(self, path: &str, access: Access, granted: bool) -> Self {
        self.push(Claim::PermissionDeclared {
            path: path.to_owned(),
            access,
            granted,
        })
    }

    /// It touched a path.
    #[must_use]
    pub fn touched(self, path: &str, access: Access) -> Self {
        self.push(Claim::FileTouched {
            path: path.to_owned(),
            access,
        })
    }

    /// It touched a path, attributed to a named probe.
    #[must_use]
    pub fn touched_via(mut self, path: &str, access: Access, probe: &str) -> Self {
        let previous = std::mem::replace(&mut self.probe, probe.to_owned());
        let mut next = self.touched(path, access);
        next.probe = previous;
        next
    }

    /// A path the kernel says this account can read, whether or not it was
    /// touched.
    #[must_use]
    pub fn reachable(self, path: &str, access: Access, sensitive: bool) -> Self {
        self.reachable_by(path, access, sensitive, Reachability::AccountReadable)
    }

    /// A path probed with a stated kind of evidence.
    ///
    /// The default above is the kernel's own answer. This one exists so a test
    /// can assert that weaker evidence — a path that merely resolves — does not
    /// close the reachable column.
    #[must_use]
    pub fn reachable_by(
        self,
        path: &str,
        access: Access,
        sensitive: bool,
        evidence: Reachability,
    ) -> Self {
        self.push(Claim::ResourceReachable {
            path: path.to_owned(),
            access,
            sensitive,
            evidence,
        })
    }

    /// It holds a socket.
    #[must_use]
    pub fn socket(self, host: &str, port: u16, direction: Direction) -> Self {
        self.push(Claim::SocketOpen {
            protocol: topgent_facts::Protocol::Tcp,
            bytes: None,
            opened_at: None,
            host: host.to_owned(),
            port,
            direction,
        })
    }

    /// It holds a socket the operating system timestamped.
    #[must_use]
    pub fn socket_opened_at(
        self,
        host: &str,
        port: u16,
        direction: Direction,
        opened_at: u64,
    ) -> Self {
        self.push(Claim::SocketOpen {
            protocol: topgent_facts::Protocol::Tcp,
            bytes: None,
            opened_at: Some(topgent_facts::UnixMillis(opened_at)),
            host: host.to_owned(),
            port,
            direction,
        })
    }

    /// It holds a socket the kernel has counted traffic on.
    #[must_use]
    pub fn socket_with_bytes(
        self,
        host: &str,
        port: u16,
        direction: Direction,
        sent: u64,
        received: u64,
    ) -> Self {
        self.push(Claim::SocketOpen {
            protocol: topgent_facts::Protocol::Tcp,
            bytes: Some(topgent_facts::ByteCounters { sent, received }),
            opened_at: None,
            host: host.to_owned(),
            port,
            direction,
        })
    }

    /// It asked the resolver for a name.
    #[must_use]
    pub fn dns_query(self, name: &str, query_type: u16, outcome: DnsOutcome) -> Self {
        self.push(Claim::DnsQueryObserved {
            name: name.to_owned(),
            query_type,
            outcome,
        })
    }

    /// It closed a previously connected socket.
    #[must_use]
    pub fn socket_closed(
        self,
        host: &str,
        port: u16,
        direction: Direction,
        duration_ms: u64,
    ) -> Self {
        self.push(Claim::SocketClosed {
            host: host.to_owned(),
            port,
            direction,
            duration_ms,
        })
    }

    /// The operating system allowed or blocked a connection attempt.
    #[must_use]
    pub fn connection_attempt(self, host: &str, port: u16, outcome: ConnectionOutcome) -> Self {
        self.push(Claim::ConnectionAttempt {
            host: host.to_owned(),
            port,
            direction: Direction::Outbound,
            outcome,
        })
    }

    /// It declares a connector.
    #[must_use]
    pub fn connector(self, name: &str, access: Access) -> Self {
        self.push(Claim::ConnectorDeclared {
            name: name.to_owned(),
            access,
        })
    }

    /// It can invoke another agent.
    #[must_use]
    pub fn invokes(self, target_pid: u32, via: &str) -> Self {
        self.push(Claim::InvokesAgent {
            target_pid,
            via: via.to_owned(),
        })
    }

    /// Topgent did something to it.
    #[must_use]
    pub fn action(self, action: &str, succeeded: bool) -> Self {
        self.push(Claim::ActionTaken {
            action: action.to_owned(),
            succeeded,
        })
    }

    /// The facts, in the order they were added.
    #[must_use]
    pub fn build(self) -> Vec<Fact> {
        // Decided from what the stream contains rather than appended blindly,
        // so a stream that names its own family keeps it and reversing the
        // result cannot change which family won.
        let named = self.facts.iter().any(|fact| {
            matches!(
                fact.claim(),
                Claim::AgentFamily { .. } | Claim::EditorExtensionActive { .. }
            )
        });
        if self.anchor && !named {
            return self.family("fixture-agent").facts;
        }
        self.facts
    }
}

/// The worked example: a coding agent with shell, broad write, an unbounded
/// network, two untouched credentials in reach, one drifted path, and an edge to
/// a second agent. Every finding the product exists to show, in one stream.
#[must_use]
pub fn busy_agent() -> Vec<Fact> {
    Stream::new(66493)
        .seen("/usr/local/bin/claude", 501, "testuser")
        .family("claude-code")
        .model("anthropic", "claude-opus-5")
        .declares("*", Access::Execute, true)
        .declares("~/Projects/topgent/**", Access::Write, true)
        .touched("~/Projects/topgent/**", Access::Write)
        .touched("~/Projects", Access::Read)
        .reachable("~/.ssh/id_ed25519", Access::Read, true)
        .reachable("~/.aws/credentials", Access::Read, true)
        .socket("api.anthropic.com", 443, Direction::Outbound)
        .socket("statsig.anthropic.com", 443, Direction::Outbound)
        .socket("github.com", 443, Direction::Outbound)
        .socket("registry.npmjs.org", 443, Direction::Outbound)
        .socket("127.0.0.1", 11434, Direction::Outbound)
        .connector("filesystem", Access::ReadWrite)
        .invokes(71204, "mcp")
        .build()
}

/// A local model server: its own account, no human config, nothing in reach.
#[must_use]
pub fn quiet_service() -> Vec<Fact> {
    Stream::new(998)
        .seen("/usr/local/bin/ollama", 501, "testuser")
        .family("ollama")
        .model("local", "llama4-scout")
        .socket("127.0.0.1", 11434, Direction::Listening)
        .build()
}
