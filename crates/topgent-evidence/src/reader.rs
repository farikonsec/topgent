//! Reading canonical bytes back.
//!
//! The encoder alone would be enough for hashing. A reader is required because
//! the verifier is independent by decision: something that does not trust the
//! sensor, the journal writer, or the user interface has to be able to parse a
//! bundle without any of them. See `docs/MAJOR_UPGRADE_RESEARCH_PLAN.md` §0, D4.
//!
//! Every failure is an explicit variant. A reader that guesses at a length, a
//! variant name, or a truncated tail is how two implementations of a canonical
//! format come to disagree about what a signature covered.
//!
//! **Unknown values are refused, never skipped.** The format has no field tags
//! to walk past, so a reader that met an unfamiliar enum variant could not know
//! how many bytes it should have consumed. Forward compatibility here means the
//! envelope schema version is checked first and an unknown one is rejected
//! whole, rather than a newer record being read as an older shape.

use crate::canonical::{Canonical, Encode};

/// Why canonical bytes could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// The input ended in the middle of a value.
    UnexpectedEnd {
        /// How many more bytes were needed.
        needed: usize,
        /// How many remained.
        remaining: usize,
    },
    /// A length-prefixed field was not valid UTF-8.
    InvalidUtf8,
    /// A length prefix exceeded what the input could hold.
    LengthTooLarge {
        /// The length the input claimed.
        claimed: usize,
        /// How many bytes remained.
        remaining: usize,
    },
    /// An enum named a variant this build does not know.
    UnknownVariant {
        /// Which vocabulary.
        vocabulary: &'static str,
        /// The name found.
        found: String,
    },
    /// An option or boolean tag was neither zero nor one.
    InvalidTag {
        /// The byte found.
        found: u8,
    },
    /// The value read back was refused by its own construction rules.
    ///
    /// Decoding runs through the same constructors as collection, so a record
    /// that could not have been produced cannot be read in either.
    Rejected {
        /// What the constructor said.
        reason: String,
    },
    /// Bytes remained after the value was read.
    TrailingBytes {
        /// How many.
        remaining: usize,
    },
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnexpectedEnd { needed, remaining } => {
                write!(f, "needed {needed} more bytes, {remaining} remained")
            }
            Self::InvalidUtf8 => f.write_str("a text field was not valid UTF-8"),
            Self::LengthTooLarge { claimed, remaining } => {
                write!(f, "a field claimed {claimed} bytes, {remaining} remained")
            }
            Self::UnknownVariant { vocabulary, found } => {
                write!(f, "unknown {vocabulary} variant `{found}`")
            }
            Self::InvalidTag { found } => write!(f, "expected a 0 or 1 tag, found {found}"),
            Self::Rejected { reason } => write!(f, "the decoded value was refused: {reason}"),
            Self::TrailingBytes { remaining } => {
                write!(f, "{remaining} bytes remained after the value")
            }
        }
    }
}

impl core::error::Error for DecodeError {}

/// A type that can be read back from its canonical bytes.
pub trait Decode: Sized {
    /// Reads one value.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] when the bytes end early, hold invalid UTF-8, or
    /// name a variant this build does not know.
    fn decode(from: &mut Reader<'_>) -> Result<Self, DecodeError>;
}

/// Reads canonical bytes in order.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    /// A reader positioned at the start.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    /// Reads one value from a complete buffer, refusing a trailing tail.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] from the value itself, or
    /// [`DecodeError::TrailingBytes`] when bytes remain afterwards.
    pub fn read<T: Decode>(bytes: &'a [u8]) -> Result<T, DecodeError> {
        let mut reader = Self::new(bytes);
        let value = T::decode(&mut reader)?;
        reader.finish()?;
        Ok(value)
    }

    /// How many bytes remain.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.at)
    }

    /// Refuses anything left over.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::TrailingBytes`] when bytes remain.
    pub const fn finish(&self) -> Result<(), DecodeError> {
        match self.remaining() {
            0 => Ok(()),
            remaining => Err(DecodeError::TrailingBytes { remaining }),
        }
    }

    /// Takes `count` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnexpectedEnd`] when fewer remain.
    pub fn take(&mut self, count: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.at.saturating_add(count);
        let slice = self
            .bytes
            .get(self.at..end)
            .ok_or(DecodeError::UnexpectedEnd {
                needed: count,
                remaining: self.remaining(),
            })?;
        self.at = end;
        Ok(slice)
    }

    /// Reads one byte.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnexpectedEnd`] at the end of input.
    pub fn tag(&mut self) -> Result<u8, DecodeError> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(DecodeError::UnexpectedEnd {
                needed: 1,
                remaining: 0,
            })
    }

    /// Reads a boolean written as a tag.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::InvalidTag`] for any byte but zero or one.
    pub fn boolean(&mut self) -> Result<bool, DecodeError> {
        match self.tag()? {
            0 => Ok(false),
            1 => Ok(true),
            found => Err(DecodeError::InvalidTag { found }),
        }
    }

    /// Reads a big-endian `u16`.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnexpectedEnd`] when fewer than two bytes remain.
    pub fn u16(&mut self) -> Result<u16, DecodeError> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| DecodeError::InvalidUtf8)?;
        Ok(u16::from_be_bytes(bytes))
    }

    /// Reads a big-endian `u32`.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnexpectedEnd`] when fewer than four bytes remain.
    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| DecodeError::InvalidUtf8)?;
        Ok(u32::from_be_bytes(bytes))
    }

    /// Reads a big-endian `u64`.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnexpectedEnd`] when fewer than eight bytes remain.
    pub fn u64(&mut self) -> Result<u64, DecodeError> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| DecodeError::InvalidUtf8)?;
        Ok(u64::from_be_bytes(bytes))
    }

    /// Reads a length-prefixed byte string.
    ///
    /// The length is checked against what remains before anything is allocated,
    /// so a record claiming four gigabytes costs one comparison.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::LengthTooLarge`] when the claim exceeds the input.
    pub fn bytes(&mut self) -> Result<&'a [u8], DecodeError> {
        let claimed = self.u32()? as usize;
        if claimed > self.remaining() {
            return Err(DecodeError::LengthTooLarge {
                claimed,
                remaining: self.remaining(),
            });
        }
        self.take(claimed)
    }

    /// Reads length-prefixed UTF-8.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::InvalidUtf8`] when the bytes are not UTF-8.
    pub fn text(&mut self) -> Result<&'a str, DecodeError> {
        core::str::from_utf8(self.bytes()?).map_err(|_| DecodeError::InvalidUtf8)
    }

    /// Reads an owned string.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::InvalidUtf8`] when the bytes are not UTF-8.
    pub fn string(&mut self) -> Result<String, DecodeError> {
        Ok(self.text()?.to_owned())
    }

    /// Reads an absent or present value.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::InvalidTag`] for any tag but zero or one.
    pub fn option<T: Decode>(&mut self) -> Result<Option<T>, DecodeError> {
        match self.tag()? {
            0 => Ok(None),
            1 => T::decode(self).map(Some),
            found => Err(DecodeError::InvalidTag { found }),
        }
    }

    /// Reads a counted sequence.
    ///
    /// The count is not used to reserve capacity. A hostile record claiming four
    /// billion items would otherwise allocate before a single item was read.
    ///
    /// # Errors
    ///
    /// Returns whatever the item decoder returns, or
    /// [`DecodeError::UnexpectedEnd`] when the input ends first.
    pub fn list<T: Decode>(&mut self) -> Result<Vec<T>, DecodeError> {
        let count = self.u32()?;
        let mut items = Vec::new();
        for _ in 0..count {
            items.push(T::decode(self)?);
        }
        Ok(items)
    }

    /// Reads a variant name and maps it through a table.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnknownVariant`] when the name is not in the table.
    pub fn variant<T: Copy>(
        &mut self,
        vocabulary: &'static str,
        table: &[(&str, T)],
    ) -> Result<T, DecodeError> {
        let found = self.text()?;
        table
            .iter()
            .find(|(name, _)| *name == found)
            .map(|(_, value)| *value)
            .ok_or_else(|| DecodeError::UnknownVariant {
                vocabulary,
                found: found.to_owned(),
            })
    }
}

impl Decode for u64 {
    fn decode(from: &mut Reader<'_>) -> Result<Self, DecodeError> {
        from.u64()
    }
}

impl Decode for String {
    fn decode(from: &mut Reader<'_>) -> Result<Self, DecodeError> {
        from.string()
    }
}

/// Round-trips a value through the canonical encoding.
///
/// Used by the property tests, and by any caller that wants to assert a value
/// survives the format it will be stored in.
///
/// # Errors
///
/// Returns [`DecodeError`] when the encoded bytes do not read back.
pub fn round_trip<T: Encode + Decode>(value: &T) -> Result<T, DecodeError> {
    Reader::read(&Canonical::of(value))
}
