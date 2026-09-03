//! The hash chain, the keys, and the signed checkpoints.
//!
//! Milestone M8 of `docs/MAJOR_UPGRADE_RESEARCH_PLAN.md`, and the place where
//! decision D5 has to hold in code rather than in prose:
//!
//! > Signing establishes that evidence was not modified, inserted, reordered,
//! > or truncated after collection. It does not establish that the sensor
//! > observed reality correctly, and it does not establish that nothing was
//! > missed. A fully compromised administrator or kernel can make the sensor
//! > lie, and no signature over a lie makes it true.
//!
//! # Why the chain is not inside the record
//!
//! An [`EvidenceRecord`] is content-addressed: the same observation has the
//! same id wherever it appears, which is what lets two bundles be merged and
//! duplicates collapse. Putting the previous entry's hash inside the record
//! would make that id depend on the record's position in one stream, so the
//! same observation exported twice would become two different records.
//!
//! The chain is therefore a separate, ordered structure over ids. A record says
//! what was seen. An entry says that this record occupied this position in this
//! sensor's stream, and nothing else did.

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};

use crate::canonical::{Canonical, Encode, digest_of};
use crate::reader::{Decode, DecodeError, Reader};
use crate::record::{EvidenceId, EvidenceRecord, Origin};

/// Reads a domain separation tag, refusing anything else.
///
/// Every signed structure writes one. Without it, a signature over a checkpoint
/// could be replayed as a signature over a rotation whose fields happen to
/// encode to the same bytes, and the two would be indistinguishable.
fn domain(from: &mut Reader<'_>, expected: &'static str) -> Result<(), DecodeError> {
    let found = from.text()?;
    if found == expected {
        Ok(())
    } else {
        Err(DecodeError::UnknownVariant {
            vocabulary: expected,
            found: found.to_owned(),
        })
    }
}

/// Lowercase hex alphabet, for key rendering.
const HEX_ALPHABET: &[u8; 16] = b"0123456789abcdef";

/// Bytes in an Ed25519 signature.
pub const SIGNATURE_BYTES: usize = 64;

/// Bytes in an Ed25519 public key.
pub const PUBLIC_KEY_BYTES: usize = 32;

/// Bytes in an Ed25519 private key seed.
pub const SECRET_KEY_BYTES: usize = 32;

/// Identifier of one signing key, derived from the key itself.
///
/// A key names itself, so a bundle cannot claim to be signed by a key whose id
/// does not match the key material it carries.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyId(String);

impl KeyId {
    /// The hex digest.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The first twelve characters, for a line of output. Never used for lookup.
    #[must_use]
    pub fn short(&self) -> &str {
        self.0.get(..12).unwrap_or(&self.0)
    }
}

impl core::fmt::Display for KeyId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Encode for KeyId {
    fn encode(&self, into: &mut Canonical) {
        into.text(&self.0);
    }
}

impl Decode for KeyId {
    fn decode(from: &mut Reader<'_>) -> Result<Self, DecodeError> {
        from.string().map(Self)
    }
}

/// The public half of a sensor key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    bytes: [u8; PUBLIC_KEY_BYTES],
    id: KeyId,
}

impl PublicKey {
    /// Wraps raw key bytes, deriving the id.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::Malformed`] when the bytes are not a valid Ed25519
    /// public key. A point that is not on the curve is refused here rather than
    /// producing a verification failure that reads like tampering.
    pub fn from_bytes(bytes: [u8; PUBLIC_KEY_BYTES]) -> Result<Self, KeyError> {
        VerifyingKey::from_bytes(&bytes).map_err(|_| KeyError::Malformed)?;
        let id = KeyId(digest_of(&RawKey(bytes)));
        Ok(Self { bytes, id })
    }

    /// Reads a key from its 64-character hex form.
    ///
    /// Hex because a public key is pasted between people and machines, and a
    /// form that survives an email is worth more than a compact one.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::Malformed`] for the wrong length, a non-hex
    /// character, or bytes that are not a valid Ed25519 key.
    pub fn from_hex(hex: &str) -> Result<Self, KeyError> {
        if hex.len() != PUBLIC_KEY_BYTES * 2 {
            return Err(KeyError::Malformed);
        }
        let (pairs, rest) = hex.as_bytes().as_chunks::<2>();
        if !rest.is_empty() {
            return Err(KeyError::Malformed);
        }
        let mut bytes = [0_u8; PUBLIC_KEY_BYTES];
        for (slot, pair) in bytes.iter_mut().zip(pairs) {
            let text = core::str::from_utf8(pair).map_err(|_| KeyError::Malformed)?;
            *slot = u8::from_str_radix(text, 16).map_err(|_| KeyError::Malformed)?;
        }
        Self::from_bytes(bytes)
    }

    /// The 64-character hex form.
    #[must_use]
    pub fn to_hex(&self) -> String {
        self.bytes
            .iter()
            .fold(String::with_capacity(64), |mut out, byte| {
                let high = usize::from(byte >> 4);
                let low = usize::from(byte & 0x0f);
                out.push(char::from(HEX_ALPHABET.get(high).copied().unwrap_or(b'0')));
                out.push(char::from(HEX_ALPHABET.get(low).copied().unwrap_or(b'0')));
                out
            })
    }

    /// The raw key bytes.
    #[must_use]
    pub const fn bytes(&self) -> &[u8; PUBLIC_KEY_BYTES] {
        &self.bytes
    }

    /// This key's identifier.
    #[must_use]
    pub const fn id(&self) -> &KeyId {
        &self.id
    }

    /// Checks a signature over a message.
    fn verifies(&self, message: &[u8], signature: &Sealed) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(&self.bytes) else {
            return false;
        };
        key.verify(message, &Signature::from_bytes(&signature.0))
            .is_ok()
    }
}

/// Raw key bytes, so a key id is a digest over a length-prefixed field rather
/// than over thirty-two naked bytes that could be confused with anything else.
struct RawKey([u8; PUBLIC_KEY_BYTES]);

impl Encode for RawKey {
    fn encode(&self, into: &mut Canonical) {
        into.text("topgent-ed25519-key-v1");
        into.bytes(&self.0);
    }
}

impl Encode for PublicKey {
    fn encode(&self, into: &mut Canonical) {
        into.bytes(&self.bytes);
    }
}

impl Decode for PublicKey {
    fn decode(from: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let bytes: [u8; PUBLIC_KEY_BYTES] =
            from.bytes()?
                .try_into()
                .map_err(|_| DecodeError::Rejected {
                    reason: "a public key was not 32 bytes".to_owned(),
                })?;
        Self::from_bytes(bytes).map_err(|error| DecodeError::Rejected {
            reason: error.to_string(),
        })
    }
}

/// The private half. Never encoded, never printed, never left in a bundle.
pub struct SensorKey {
    signing: SigningKey,
    public: PublicKey,
}

impl core::fmt::Debug for SensorKey {
    /// Prints the id and nothing else.
    ///
    /// A key that can be logged by accident is a key that will be.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SensorKey")
            .field("id", &self.public.id)
            .finish_non_exhaustive()
    }
}

impl SensorKey {
    /// Derives a key from a 32-byte seed.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::Malformed`] when the seed does not yield a usable key.
    pub fn from_seed(seed: [u8; SECRET_KEY_BYTES]) -> Result<Self, KeyError> {
        let signing = SigningKey::from_bytes(&seed);
        let public = PublicKey::from_bytes(signing.verifying_key().to_bytes())?;
        Ok(Self { signing, public })
    }

    /// Generates a key from the operating system's randomness.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::NoRandomness`] when the platform will not supply it.
    /// A key derived from a fallback source would be worse than no key, because
    /// it would still verify.
    pub fn generate() -> Result<Self, KeyError> {
        let mut seed = [0_u8; SECRET_KEY_BYTES];
        getrandom::fill(&mut seed).map_err(|_| KeyError::NoRandomness)?;
        Self::from_seed(seed)
    }

    /// The public half.
    #[must_use]
    pub const fn public(&self) -> &PublicKey {
        &self.public
    }

    /// This key's identifier.
    #[must_use]
    pub const fn id(&self) -> &KeyId {
        self.public.id()
    }

    /// Signs a message.
    fn seal(&self, message: &[u8]) -> Sealed {
        Sealed(self.signing.sign(message).to_bytes())
    }
}

/// Why a key could not be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    /// The bytes are not a usable Ed25519 key.
    Malformed,
    /// The platform would not supply randomness.
    NoRandomness,
}

impl core::fmt::Display for KeyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed => f.write_str("the bytes are not a usable Ed25519 key"),
            Self::NoRandomness => f.write_str("the platform supplied no randomness"),
        }
    }
}

impl core::error::Error for KeyError {}

/// One Ed25519 signature.
#[derive(Clone, PartialEq, Eq)]
pub struct Sealed([u8; SIGNATURE_BYTES]);

impl core::fmt::Debug for Sealed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Sealed({SIGNATURE_BYTES} bytes)")
    }
}

impl Sealed {
    /// The raw signature bytes.
    #[must_use]
    pub const fn bytes(&self) -> &[u8; SIGNATURE_BYTES] {
        &self.0
    }
}

impl Encode for Sealed {
    fn encode(&self, into: &mut Canonical) {
        into.bytes(&self.0);
    }
}

impl Decode for Sealed {
    fn decode(from: &mut Reader<'_>) -> Result<Self, DecodeError> {
        from.bytes()?
            .try_into()
            .map(Self)
            .map_err(|_| DecodeError::Rejected {
                reason: "a signature was not 64 bytes".to_owned(),
            })
    }
}

/// Hash of one chain entry.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntryHash(String);

impl EntryHash {
    /// The hex digest.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The first twelve characters, for a line of output.
    #[must_use]
    pub fn short(&self) -> &str {
        self.0.get(..12).unwrap_or(&self.0)
    }
}

impl core::fmt::Display for EntryHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Encode for EntryHash {
    fn encode(&self, into: &mut Canonical) {
        into.text(&self.0);
    }
}

impl Decode for EntryHash {
    fn decode(from: &mut Reader<'_>) -> Result<Self, DecodeError> {
        from.string().map(Self)
    }
}

/// One record's position in one sensor's stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainEntry {
    previous: Option<EntryHash>,
    sequence: u64,
    record_id: EvidenceId,
    hash: EntryHash,
}

impl ChainEntry {
    /// Assembles an entry from parts, without checking any of them.
    ///
    /// This is what decoding does, and it is deliberately available to callers:
    /// a reader assembling a bundle from bytes cannot validate before it has
    /// something to validate. Nothing here is trusted. [`Bundle::verify`]
    /// recomputes the hash, the link, and the order, and an entry that was
    /// assembled wrongly fails there with a named reason.
    ///
    /// [`Bundle::verify`]: crate::bundle::Bundle::verify
    #[must_use]
    pub const fn from_parts(
        previous: Option<EntryHash>,
        sequence: u64,
        record_id: EvidenceId,
        hash: EntryHash,
    ) -> Self {
        Self {
            previous,
            sequence,
            record_id,
            hash,
        }
    }

    /// The entry before this one, absent only for the first.
    #[must_use]
    pub const fn previous(&self) -> Option<&EntryHash> {
        self.previous.as_ref()
    }

    /// Position in the stream.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Which record occupied this position.
    #[must_use]
    pub const fn record_id(&self) -> &EvidenceId {
        &self.record_id
    }

    /// This entry's hash, which the next entry commits to.
    #[must_use]
    pub const fn hash(&self) -> &EntryHash {
        &self.hash
    }

    /// The hash this entry should carry, given its own contents.
    #[must_use]
    pub fn recomputed(&self) -> EntryHash {
        EntryHash(digest_of(&EntryBody {
            previous: self.previous.as_ref(),
            sequence: self.sequence,
            record_id: &self.record_id,
        }))
    }
}

/// The fields an entry hash is taken over.
///
/// A separate type so the hash cannot accidentally include the hash it produces.
struct EntryBody<'a> {
    previous: Option<&'a EntryHash>,
    sequence: u64,
    record_id: &'a EvidenceId,
}

impl Encode for EntryBody<'_> {
    fn encode(&self, into: &mut Canonical) {
        into.text("topgent-chain-entry-v1");
        into.option(self.previous);
        into.u64(self.sequence);
        self.record_id.encode(into);
    }
}

impl Encode for ChainEntry {
    fn encode(&self, into: &mut Canonical) {
        into.option(self.previous.as_ref());
        into.u64(self.sequence);
        self.record_id.encode(into);
        self.hash.encode(into);
    }
}

impl Decode for ChainEntry {
    fn decode(from: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            previous: from.option()?,
            sequence: from.u64()?,
            record_id: EvidenceId::decode(from)?,
            hash: EntryHash::decode(from)?,
        })
    }
}

/// Why a record could not be appended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// The record belongs to a different host, boot, or sensor instance.
    ForeignOrigin {
        /// The origin this chain was opened for.
        expected: Box<Origin>,
        /// The origin the record carried.
        found: Box<Origin>,
    },
    /// The record's sequence did not follow the one before it.
    OutOfOrder {
        /// The last sequence appended.
        last: u64,
        /// The sequence offered.
        offered: u64,
    },
}

impl core::fmt::Display for ChainError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ForeignOrigin { expected, found } => write!(
                f,
                "a record from {}/{} was offered to the chain for {}/{}",
                found.host_id, found.boot_id, expected.host_id, expected.boot_id
            ),
            Self::OutOfOrder { last, offered } => {
                write!(f, "sequence {offered} does not follow {last}")
            }
        }
    }
}

impl core::error::Error for ChainError {}

/// An append-only chain over one sensor instance's records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chain {
    origin: Origin,
    entries: Vec<ChainEntry>,
}

impl Chain {
    /// Assembles a chain from parts, without checking any of them.
    ///
    /// See [`ChainEntry::from_parts`] for why an unchecked constructor exists.
    #[must_use]
    pub const fn from_parts(origin: Origin, entries: Vec<ChainEntry>) -> Self {
        Self { origin, entries }
    }

    /// Opens an empty chain for one origin.
    #[must_use]
    pub const fn new(origin: Origin) -> Self {
        Self {
            origin,
            entries: Vec::new(),
        }
    }

    /// Appends one record.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError::ForeignOrigin`] when the record belongs to another
    /// host, boot, or sensor instance, and [`ChainError::OutOfOrder`] when its
    /// sequence does not strictly follow the last appended one.
    pub fn append(&mut self, record: &EvidenceRecord) -> Result<&ChainEntry, ChainError> {
        if *record.origin() != self.origin {
            return Err(ChainError::ForeignOrigin {
                expected: Box::new(self.origin.clone()),
                found: Box::new(record.origin().clone()),
            });
        }
        if let Some(last) = self.entries.last()
            && record.sequence() <= last.sequence
        {
            return Err(ChainError::OutOfOrder {
                last: last.sequence,
                offered: record.sequence(),
            });
        }
        let previous = self.entries.last().map(|last| last.hash.clone());
        let hash = EntryHash(digest_of(&EntryBody {
            previous: previous.as_ref(),
            sequence: record.sequence(),
            record_id: record.id(),
        }));
        self.entries.push(ChainEntry {
            previous,
            sequence: record.sequence(),
            record_id: record.id().clone(),
            hash,
        });
        self.entries.last().ok_or(ChainError::OutOfOrder {
            last: 0,
            offered: 0,
        })
    }

    /// Which sensor instance this chain belongs to.
    #[must_use]
    pub const fn origin(&self) -> &Origin {
        &self.origin
    }

    /// Every entry, in order.
    #[must_use]
    pub fn entries(&self) -> &[ChainEntry] {
        &self.entries
    }

    /// The last entry's hash.
    #[must_use]
    pub fn head(&self) -> Option<&EntryHash> {
        self.entries.last().map(|last| &last.hash)
    }

    /// Signs the current head.
    ///
    /// One signature covers every entry before it, because each entry commits
    /// to the one before. Signing periodically rather than per record is what
    /// stops a holder of a disclosed segment from reordering inside it.
    #[must_use]
    pub fn checkpoint(&self, key: &SensorKey) -> Option<Checkpoint> {
        let head = self.head()?.clone();
        let through = self.entries.last().map(|last| last.sequence)?;
        let body = CheckpointBody {
            key_id: key.id().clone(),
            origin: self.origin.clone(),
            through_sequence: through,
            entry_count: u64::try_from(self.entries.len()).unwrap_or(u64::MAX),
            head,
        };
        let signature = key.seal(&Canonical::of(&body));
        Some(Checkpoint { body, signature })
    }
}

impl Encode for Chain {
    fn encode(&self, into: &mut Canonical) {
        self.origin.encode(into);
        into.list(&self.entries);
    }
}

impl Decode for Chain {
    fn decode(from: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            origin: Origin::decode(from)?,
            entries: from.list()?,
        })
    }
}

/// The fields a checkpoint signature covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointBody {
    /// Which key signed.
    pub key_id: KeyId,
    /// Which sensor instance, host, and boot.
    pub origin: Origin,
    /// The last sequence covered.
    pub through_sequence: u64,
    /// How many entries the chain held.
    pub entry_count: u64,
    /// The chain head at that moment.
    pub head: EntryHash,
}

impl Encode for CheckpointBody {
    fn encode(&self, into: &mut Canonical) {
        into.text("topgent-checkpoint-v1");
        self.key_id.encode(into);
        self.origin.encode(into);
        into.u64(self.through_sequence);
        into.u64(self.entry_count);
        self.head.encode(into);
    }
}

impl Decode for CheckpointBody {
    fn decode(from: &mut Reader<'_>) -> Result<Self, DecodeError> {
        domain(from, "topgent-checkpoint-v1")?;
        Ok(Self {
            key_id: KeyId::decode(from)?,
            origin: Origin::decode(from)?,
            through_sequence: from.u64()?,
            entry_count: from.u64()?,
            head: EntryHash::decode(from)?,
        })
    }
}

/// A signed statement about the chain up to one point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    body: CheckpointBody,
    signature: Sealed,
}

impl Checkpoint {
    /// What the signature covers.
    #[must_use]
    pub const fn body(&self) -> &CheckpointBody {
        &self.body
    }

    /// The signature.
    #[must_use]
    pub const fn signature(&self) -> &Sealed {
        &self.signature
    }

    /// Whether this key produced this signature.
    #[must_use]
    pub fn signed_by(&self, key: &PublicKey) -> bool {
        *key.id() == self.body.key_id && key.verifies(&Canonical::of(&self.body), &self.signature)
    }
}

impl Encode for Checkpoint {
    fn encode(&self, into: &mut Canonical) {
        self.body.encode(into);
        self.signature.encode(into);
    }
}

impl Decode for Checkpoint {
    fn decode(from: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            body: CheckpointBody::decode(from)?,
            signature: Sealed::decode(from)?,
        })
    }
}

/// The fields a rotation signature covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationBody {
    /// The key being retired.
    pub retiring: KeyId,
    /// The key taking over.
    pub replacing: PublicKey,
    /// The sequence from which the new key is authoritative.
    pub from_sequence: u64,
}

impl Encode for RotationBody {
    fn encode(&self, into: &mut Canonical) {
        into.text("topgent-rotation-v1");
        self.retiring.encode(into);
        self.replacing.encode(into);
        into.u64(self.from_sequence);
    }
}

impl Decode for RotationBody {
    fn decode(from: &mut Reader<'_>) -> Result<Self, DecodeError> {
        domain(from, "topgent-rotation-v1")?;
        Ok(Self {
            retiring: KeyId::decode(from)?,
            replacing: PublicKey::decode(from)?,
            from_sequence: from.u64()?,
        })
    }
}

/// One key handing authority to the next, signed by the key stepping down.
///
/// Signed by the retiring key, not the incoming one. A rotation an attacker
/// could sign with a key they generated would let them replace the whole chain
/// of authority with their own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rotation {
    body: RotationBody,
    signature: Sealed,
}

impl Rotation {
    /// Signs a handover with the retiring key.
    #[must_use]
    pub fn sign(retiring: &SensorKey, replacing: &PublicKey, from_sequence: u64) -> Self {
        let body = RotationBody {
            retiring: retiring.id().clone(),
            replacing: replacing.clone(),
            from_sequence,
        };
        let signature = retiring.seal(&Canonical::of(&body));
        Self { body, signature }
    }

    /// What the signature covers.
    #[must_use]
    pub const fn body(&self) -> &RotationBody {
        &self.body
    }

    /// Whether the retiring key actually signed this handover.
    #[must_use]
    pub fn signed_by(&self, key: &PublicKey) -> bool {
        *key.id() == self.body.retiring && key.verifies(&Canonical::of(&self.body), &self.signature)
    }
}

impl Encode for Rotation {
    fn encode(&self, into: &mut Canonical) {
        self.body.encode(into);
        self.signature.encode(into);
    }
}

impl Decode for Rotation {
    fn decode(from: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            body: RotationBody::decode(from)?,
            signature: Sealed::decode(from)?,
        })
    }
}
