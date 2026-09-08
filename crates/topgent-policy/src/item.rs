//! Conditions about one item, for the factors that decide per item.
//!
//! Nine factors ask a question about an agent as a whole and are answered by
//! [`crate::firing::Firing`]. Eleven ask a question about each of the agent's
//! endpoints, children or resources, and produce one finding per match. This is
//! their half of the vocabulary.
//!
//! # What stays in Rust, and why
//!
//! An item condition reads a typed *view* of one item, and that view carries
//! computed flags beside its raw fields. Whether an address is loopback,
//! private, a bare literal or a cloud metadata service is network knowledge.
//! Whether a path is a persistence location or belongs to Topgent itself is
//! filesystem knowledge. None of it is policy, and none of it is anybody's to
//! tune. Those classifications are made in Rust and presented here as booleans.
//!
//! What data expresses is the combination: *outbound, and private, and not
//! loopback*. That is the part an operator has a reason to change. Teaching
//! this language CIDR arithmetic and path classification instead is how a
//! condition file stops being data and becomes a program.

use serde::Deserialize;

/// Which of an agent's collections a condition walks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    /// Network destinations and listeners.
    Endpoints,
    /// Descendant processes.
    Children,
    /// Filesystem paths, declared, observed or reachable.
    Resources,
}

impl ItemKind {
    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Endpoints => "endpoints",
            Self::Children => "children",
            Self::Resources => "resources",
        }
    }

    /// Every kind, for validation and for the schema.
    #[must_use]
    pub const fn all() -> [Self; 3] {
        [Self::Endpoints, Self::Children, Self::Resources]
    }

    /// The flags an item of this kind carries.
    #[must_use]
    pub const fn flags(self) -> &'static [Flag] {
        match self {
            Self::Endpoints => &[
                Flag::Loopback,
                Flag::PrivatePeer,
                Flag::RawAddress,
                Flag::MetadataService,
                Flag::Listening,
                Flag::Outbound,
                Flag::Held,
                Flag::Attempted,
                Flag::Closed,
                Flag::Captured,
            ],
            Self::Children => &[Flag::OffensiveTool],
            Self::Resources => &[
                Flag::Observed,
                Flag::Declared,
                Flag::Reachable,
                Flag::Sensitive,
                Flag::Mutating,
                Flag::PersistenceLocation,
                Flag::TopgentOwned,
            ],
        }
    }

    /// The numeric fields an item of this kind carries.
    #[must_use]
    pub const fn numbers(self) -> &'static [Number] {
        match self {
            Self::Endpoints => &[Number::Port],
            Self::Children => &[Number::Pid, Number::Depth],
            Self::Resources => &[],
        }
    }
}

/// A yes-or-no property of one item.
///
/// Every entry is either a raw fact about the item or a classification Rust
/// made. A condition cannot tell the difference and does not need to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Flag {
    /// The address is a loopback address.
    Loopback,
    /// The address is on a private network.
    PrivatePeer,
    /// The host is an address literal rather than a name.
    RawAddress,
    /// The host is a known cloud instance metadata service.
    MetadataService,
    /// The socket is listening rather than connected outward.
    Listening,
    /// The connection goes outward.
    Outbound,
    /// A socket to this destination was open at the moment of a sweep.
    Held,
    /// The operating system recorded an attempt to reach this destination.
    ///
    /// Present whether or not the connection succeeded, and present after it
    /// has gone. This is the flag that makes an agent which connects, acts and
    /// disconnects between two sweeps visible at all.
    Attempted,
    /// The operating system recorded this connection being torn down.
    Closed,
    /// Packets to or from this destination were seen on the wire.
    ///
    /// The only flag that says traffic moved rather than that a socket
    /// existed, and the only one available for a protocol no socket listing
    /// reports. It appears only where packet capture is running.
    Captured,
    /// The child's executable name is known offensive tooling.
    OffensiveTool,
    /// The resource was actually touched.
    Observed,
    /// The agent's own configuration names this path.
    Declared,
    /// The account could reach it, whether or not it did.
    Reachable,
    /// The path holds a credential.
    Sensitive,
    /// The access seen would change the file.
    Mutating,
    /// The path is somewhere programs are started from.
    PersistenceLocation,
    /// The path belongs to Topgent or its policy.
    TopgentOwned,
}

impl Flag {
    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::PrivatePeer => "private_peer",
            Self::RawAddress => "raw_address",
            Self::MetadataService => "metadata_service",
            Self::Listening => "listening",
            Self::Outbound => "outbound",
            Self::Held => "held",
            Self::Attempted => "attempted",
            Self::Closed => "closed",
            Self::Captured => "captured",
            Self::OffensiveTool => "offensive_tool",
            Self::Observed => "observed",
            Self::Declared => "declared",
            Self::Reachable => "reachable",
            Self::Sensitive => "sensitive",
            Self::Mutating => "mutating",
            Self::PersistenceLocation => "persistence_location",
            Self::TopgentOwned => "topgent_owned",
        }
    }
}

/// A numeric property of one item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Number {
    /// Endpoint port.
    Port,
    /// Child process id.
    Pid,
    /// Parent edges between the agent and this child.
    Depth,
}

impl Number {
    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Port => "port",
            Self::Pid => "pid",
            Self::Depth => "depth",
        }
    }
}

/// A named list from the detection signals a condition may test against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NumberList {
    /// Ports that read as a backdoor or a handler.
    SuspiciousPorts,
}

impl NumberList {
    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SuspiciousPorts => "suspicious_ports",
        }
    }
}

/// One item, as a condition sees it.
///
/// Built by the scorer, which is the only thing that knows how to classify an
/// address or a path. Every field is filled for every item; a kind that has no
/// meaning for a field leaves it false or zero, and [`ItemKind::flags`] is what
/// says which ones a condition may legitimately ask about.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Item {
    /// Which collection this came from.
    pub kind: Option<ItemKind>,
    /// Endpoint host, child name, or resource path.
    pub text: String,
    /// Endpoint port.
    pub port: u32,
    /// Child process id.
    pub pid: u32,
    /// Child depth.
    pub depth: u32,
    /// Set flags, sorted and deduplicated.
    pub flags: Vec<Flag>,
}

impl Item {
    /// Whether one flag is set.
    #[must_use]
    pub fn has(&self, flag: Flag) -> bool {
        self.flags.contains(&flag)
    }

    /// One numeric field.
    #[must_use]
    pub const fn number(&self, number: Number) -> u32 {
        match number {
            Number::Port => self.port,
            Number::Pid => self.pid,
            Number::Depth => self.depth,
        }
    }
}

/// When one item matches.
///
/// The same shape as [`crate::firing::Firing`] and deliberately no larger:
/// four combinators and three tests, all total.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum ItemCondition {
    /// Every branch holds. An empty list is true.
    All(Vec<ItemCondition>),
    /// Some branch holds. An empty list is false.
    Any(Vec<ItemCondition>),
    /// The branch does not hold.
    Not(Box<ItemCondition>),
    /// A flag is set.
    Is(Flag),
    /// A numeric field is in a named list.
    InList(Number, NumberList),
    /// A numeric field is at or above a literal.
    AtLeast(Number, u32),
}

impl ItemCondition {
    /// Whether this holds for one item.
    ///
    /// `numbers` resolves a named list, so the lists stay in the one data file
    /// that already holds them rather than being copied into conditions.
    #[must_use]
    pub fn holds(&self, item: &Item, numbers: &dyn Fn(NumberList) -> Vec<u32>) -> bool {
        match self {
            Self::All(branches) => branches.iter().all(|branch| branch.holds(item, numbers)),
            Self::Any(branches) => branches.iter().any(|branch| branch.holds(item, numbers)),
            Self::Not(inner) => !inner.holds(item, numbers),
            Self::Is(flag) => item.has(*flag),
            Self::InList(number, list) => numbers(*list).contains(&item.number(*number)),
            Self::AtLeast(number, least) => item.number(*number) >= *least,
        }
    }

    /// Every flag this condition reads.
    #[must_use]
    pub fn flags(&self) -> Vec<Flag> {
        let mut out = Vec::new();
        self.walk(&mut |condition| {
            if let Self::Is(flag) = condition {
                out.push(*flag);
            }
        });
        out.sort_unstable();
        out.dedup();
        out
    }

    /// Every numeric field this condition reads.
    #[must_use]
    pub fn numbers(&self) -> Vec<Number> {
        let mut out = Vec::new();
        self.walk(&mut |condition| match condition {
            Self::InList(number, _) | Self::AtLeast(number, _) => out.push(*number),
            _ => {}
        });
        out.sort_unstable();
        out.dedup();
        out
    }

    fn walk(&self, visit: &mut impl FnMut(&Self)) {
        visit(self);
        match self {
            Self::All(branches) | Self::Any(branches) => {
                for branch in branches {
                    branch.walk(visit);
                }
            }
            Self::Not(inner) => inner.walk(visit),
            Self::Is(_) | Self::InList(..) | Self::AtLeast(..) => {}
        }
    }

    /// Whether every field this reads exists on the given kind.
    ///
    /// A condition asking an endpoint whether it is `sensitive` is a mistake
    /// that would otherwise present as a factor that never fires, which looks
    /// exactly like a quiet host.
    #[must_use]
    pub fn fields_exist_on(&self, kind: ItemKind) -> bool {
        self.flags().iter().all(|flag| kind.flags().contains(flag))
            && self
                .numbers()
                .iter()
                .all(|number| kind.numbers().contains(number))
    }
}

/// A placeholder a message template may name.
///
/// Closed on purpose, and per kind. A template naming a placeholder the item
/// does not carry is refused at load rather than rendering the literal text
/// `{path}` into a finding an operator then has to interpret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Placeholder {
    /// Endpoint host, as recorded.
    Host,
    /// Endpoint port.
    Port,
    /// Child executable name.
    Name,
    /// Child process id.
    Pid,
    /// Child depth beneath the agent.
    Depth,
    /// Resource path.
    Path,
}

impl Placeholder {
    /// The name as it appears between braces.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Port => "port",
            Self::Name => "name",
            Self::Pid => "pid",
            Self::Depth => "depth",
            Self::Path => "path",
        }
    }

    /// The placeholder of that name, if this build has one.
    ///
    /// Not `FromStr`: an unknown name is not an error here, it is an answer,
    /// and the caller decides whether the absence matters.
    #[must_use]
    pub fn named(name: &str) -> Option<Self> {
        [
            Self::Host,
            Self::Port,
            Self::Name,
            Self::Pid,
            Self::Depth,
            Self::Path,
        ]
        .into_iter()
        .find(|candidate| candidate.as_str() == name)
    }

    /// What it renders to for one item.
    #[must_use]
    pub fn render(self, item: &Item) -> String {
        match self {
            Self::Host | Self::Name | Self::Path => item.text.clone(),
            Self::Port => item.port.to_string(),
            Self::Pid => item.pid.to_string(),
            Self::Depth => item.depth.to_string(),
        }
    }
}

impl ItemKind {
    /// The placeholders a template over this kind may name.
    #[must_use]
    pub const fn placeholders(self) -> &'static [Placeholder] {
        match self {
            Self::Endpoints => &[Placeholder::Host, Placeholder::Port],
            Self::Children => &[Placeholder::Name, Placeholder::Pid, Placeholder::Depth],
            Self::Resources => &[Placeholder::Path],
        }
    }
}

/// Why a template could not be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateError {
    /// A placeholder this build does not know.
    Unknown {
        /// The name as written.
        name: String,
    },
    /// A placeholder the item kind does not carry.
    WrongKind {
        /// The name as written.
        name: String,
        /// The kind it was written for.
        kind: &'static str,
    },
    /// A brace was opened and never closed.
    Unbalanced,
    /// The template is blank, so the finding would print nothing.
    Blank,
}

impl core::fmt::Display for TemplateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unknown { name } => write!(f, "no placeholder named `{name}`"),
            Self::WrongKind { name, kind } => {
                write!(f, "`{name}` is not carried by a {kind} item")
            }
            Self::Unbalanced => f.write_str("an opening brace was never closed"),
            Self::Blank => f.write_str("a template that renders nothing is not a finding"),
        }
    }
}

impl core::error::Error for TemplateError {}

/// One sentence a finding prints, with the matched item filled in.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct Template(String);

impl Template {
    /// Builds a template, checking every placeholder against the kind.
    ///
    /// # Errors
    ///
    /// Returns [`TemplateError`] for a blank template, an unbalanced brace, a
    /// placeholder this build does not know, or one the kind does not carry.
    pub fn new(text: &str, kind: ItemKind) -> Result<Self, TemplateError> {
        if text.trim().is_empty() {
            return Err(TemplateError::Blank);
        }
        let mut rest = text;
        while let Some(open) = rest.find('{') {
            let after = rest.get(open + 1..).ok_or(TemplateError::Unbalanced)?;
            let close = after.find('}').ok_or(TemplateError::Unbalanced)?;
            let name = after.get(..close).ok_or(TemplateError::Unbalanced)?;
            let placeholder = Placeholder::named(name).ok_or_else(|| TemplateError::Unknown {
                name: name.to_owned(),
            })?;
            if !kind.placeholders().contains(&placeholder) {
                return Err(TemplateError::WrongKind {
                    name: name.to_owned(),
                    kind: kind.as_str(),
                });
            }
            rest = after.get(close + 1..).unwrap_or("");
        }
        Ok(Self(text.to_owned()))
    }

    /// The template as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The sentence for one item.
    ///
    /// Every placeholder was checked at construction, so nothing here can fail
    /// and no `{name}` can survive into a finding.
    #[must_use]
    pub fn render(&self, item: &Item) -> String {
        let mut out = String::with_capacity(self.0.len());
        let mut rest = self.0.as_str();
        while let Some(open) = rest.find('{') {
            out.push_str(rest.get(..open).unwrap_or(""));
            let Some(after) = rest.get(open + 1..) else {
                break;
            };
            let Some(close) = after.find('}') else {
                break;
            };
            if let Some(placeholder) = after.get(..close).and_then(Placeholder::named) {
                out.push_str(&placeholder.render(item));
            }
            rest = after.get(close + 1..).unwrap_or("");
        }
        out.push_str(rest);
        out
    }
}
