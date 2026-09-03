//! The canonical encoding.
//!
//! Every hash, id, and signature in Topgent is taken over the bytes this module
//! produces, so the encoding is a wire format with a specification, not an
//! implementation detail. Two properties are load-bearing:
//!
//! 1. **One value has exactly one encoding.** There are no maps, so there is no
//!    key ordering to get wrong; no floats, so there is no rounding; and no
//!    optional whitespace, so there is nothing for a formatter to normalise.
//! 2. **No escaping.** Text and bytes are length-prefixed rather than delimited.
//!    An escaping bug is the classic way two implementations of a canonical
//!    format disagree, and this format has nowhere to put one.
//!
//! # Grammar
//!
//! | Shape | Bytes |
//! |---|---|
//! | `u8` / tag | one byte |
//! | `u16` | two bytes, big-endian |
//! | `u32` | four bytes, big-endian |
//! | `u64` | eight bytes, big-endian |
//! | text or bytes | `u32` length, then the bytes, UTF-8 for text |
//! | option | `0x00`, or `0x01` followed by the value |
//! | list | `u32` count, then each item |
//!
//! Enum discriminants are written explicitly by each type and are part of the
//! format. Reordering an enum's variants changes every id derived from it, so a
//! variant is appended, never inserted.

/// A type with exactly one byte representation.
pub trait Encode {
    /// Appends this value's canonical bytes.
    fn encode(&self, into: &mut Canonical);
}

/// Accumulates canonical bytes.
#[derive(Debug, Default, Clone)]
pub struct Canonical {
    bytes: Vec<u8>,
}

impl Canonical {
    /// An empty encoder.
    #[must_use]
    pub const fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    /// Encodes one value on its own and returns the bytes.
    #[must_use]
    pub fn of<T: Encode + ?Sized>(value: &T) -> Vec<u8> {
        let mut canonical = Self::new();
        value.encode(&mut canonical);
        canonical.finish()
    }

    /// Writes one byte, used for enum discriminants.
    pub fn tag(&mut self, tag: u8) {
        self.bytes.push(tag);
    }

    /// Writes a `u16`, big-endian.
    pub fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    /// Writes a `u32`, big-endian.
    pub fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    /// Writes a `u64`, big-endian.
    pub fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    /// Writes a length-prefixed byte string.
    ///
    /// A length above `u32::MAX` is impossible to encode. Records are size-capped
    /// long before that by [`crate::MAX_FIELD_BYTES`], so the saturating cast
    /// here is unreachable rather than lossy.
    pub fn bytes(&mut self, value: &[u8]) {
        self.u32(u32::try_from(value.len()).unwrap_or(u32::MAX));
        self.bytes.extend_from_slice(value);
    }

    /// Writes length-prefixed UTF-8.
    pub fn text(&mut self, value: &str) {
        self.bytes(value.as_bytes());
    }

    /// Writes an absent or present value.
    pub fn option<T: Encode>(&mut self, value: Option<&T>) {
        match value {
            None => self.tag(0),
            Some(inner) => {
                self.tag(1);
                inner.encode(self);
            }
        }
    }

    /// Writes a counted sequence.
    pub fn list<T: Encode>(&mut self, items: &[T]) {
        self.u32(u32::try_from(items.len()).unwrap_or(u32::MAX));
        for item in items {
            item.encode(self);
        }
    }

    /// The accumulated bytes.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.bytes
    }

    /// How many bytes have been written.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether nothing has been written.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl Encode for str {
    fn encode(&self, into: &mut Canonical) {
        into.text(self);
    }
}

impl Encode for String {
    fn encode(&self, into: &mut Canonical) {
        into.text(self);
    }
}

impl Encode for u64 {
    fn encode(&self, into: &mut Canonical) {
        into.u64(*self);
    }
}

/// Lowercase hex alphabet, for digest rendering.
const HEX: &[u8; 16] = b"0123456789abcdef";

/// The SHA-256 digest of a value's canonical bytes, lowercase hex.
#[must_use]
pub fn digest_of<T: Encode + ?Sized>(value: &T) -> String {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(Canonical::of(value));
    hasher
        .finalize()
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            let high = usize::from(byte >> 4);
            let low = usize::from(byte & 0x0f);
            out.push(char::from(HEX.get(high).copied().unwrap_or(b'0')));
            out.push(char::from(HEX.get(low).copied().unwrap_or(b'0')));
            out
        })
}
