//! Who announces an address, and from where.
//!
//! An agent talking entirely to one cloud provider and one that suddenly
//! reaches an unfamiliar network in another jurisdiction are different
//! situations, and a bare address cannot tell them apart.
//!
//! Longest-prefix match over a sorted table compiled into the binary. No
//! lookup at runtime, no account, no network access, and a machine with no
//! connectivity resolves ownership exactly as well as one with it. v4 and v6
//! share one structure by widening every address to 128 bits, so there is one
//! path to get wrong rather than two.
//!
//! **An address in no range is `unknown`, never a guess.** The table's coverage
//! is the honest boundary of this column, and inventing an owner for an address
//! nobody announced would be exactly the kind of confident wrong answer this
//! product exists to avoid.

use std::net::IpAddr;
use std::sync::OnceLock;

/// What the table says about one address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Owner {
    asn: u32,
    country: [u8; 2],
    name: &'static str,
}

/// Nothing known. Printed as `unknown`, which is a different answer from a
/// range the table records as announced by nobody.
const UNKNOWN: Owner = Owner {
    asn: 0,
    country: *b"  ",
    name: "",
};

impl Owner {
    /// The country, as a flag followed by its code.
    ///
    /// Never a flag alone. A glyph is not a fact and must not be the only
    /// carrier of one: a reader whose font has no flags, or who is looking at
    /// a greyscale print, still gets the country.
    #[must_use]
    pub fn country(self) -> String {
        let code = std::str::from_utf8(&self.country).unwrap_or("  ").trim();
        if code.len() != 2 {
            return "unknown".to_owned();
        }
        format!("{} {code}", flag(code))
    }

    /// The announcing network, with its number.
    #[must_use]
    pub fn network(self) -> String {
        match (self.asn, self.name) {
            (0, "") => "unknown".to_owned(),
            (0, name) => name.to_owned(),
            (asn, "") => format!("AS{asn}"),
            (asn, name) => format!("{name} · AS{asn}"),
        }
    }

    /// Whether the table had an answer at all.
    #[must_use]
    pub fn known(self) -> bool {
        self != UNKNOWN
    }
}

/// Regional indicator symbols for an ISO 3166-1 alpha-2 code.
fn flag(code: &str) -> String {
    code.chars()
        .filter(char::is_ascii_uppercase)
        .filter_map(|c| char::from_u32(0x1F1E6 + (c as u32 - 'A' as u32)))
        .collect()
}

/// Look up one address, given as text the way the report carries it.
#[must_use]
pub fn of(address: &str) -> Owner {
    address.parse::<IpAddr>().map_or(UNKNOWN, at)
}

/// Look up one parsed address.
#[must_use]
pub fn at(address: IpAddr) -> Owner {
    let t = table();
    let (rows, size, width) = match address {
        IpAddr::V4(_) => (t.v4, V4_ROW, 4),
        IpAddr::V6(_) => (t.v6, V6_ROW, 16),
    };
    let key = match address {
        IpAddr::V4(v4) => u128::from(u32::from(v4)),
        IpAddr::V6(v6) => u128::from(v6),
    };
    search(rows, size, key, width)
        .and_then(|row| read(row, width, t))
        .unwrap_or(UNKNOWN)
}

/// One row into an owner.
///
/// Fallible throughout. A blob that is not the shape this build wrote must
/// give `unknown`, not a panic: the interface has to draw even when its data
/// is wrong, and an ownership column is not worth a crash.
fn read(row: &[u8], width: usize, t: &'static Table) -> Option<Owner> {
    let at = 2 * width;
    let country = [*row.get(at + 4)?, *row.get(at + 5)?];
    Some(Owner {
        asn: le32(row, at)?,
        country,
        name: t.name(le32(row, at + 6)?),
    })
}

/// The last range starting at or before the address, if it contains it.
///
/// The build sorts ranges by start and puts the narrower of two sharing a
/// start last, so the last candidate is the most specific one.
fn search(rows: &'static [u8], row_size: usize, key: u128, width: usize) -> Option<&'static [u8]> {
    let count = rows.len() / row_size;
    let row = |i: usize| rows.get(i * row_size..(i + 1) * row_size);
    let mut lo = 0usize;
    let mut hi = count;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if row(mid).is_some_and(|r| number(r, 0, width) <= key) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    let candidate = row(lo.checked_sub(1)?)?;
    (key <= number(candidate, width, width)).then_some(candidate)
}

fn number(row: &[u8], at: usize, width: usize) -> u128 {
    let mut bytes = [0u8; 16];
    let Some(slice) = row.get(at..at + width) else {
        return 0;
    };
    if let Some(into) = bytes.get_mut(..width) {
        into.copy_from_slice(slice);
    }
    u128::from_le_bytes(bytes)
}

fn le32(row: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(row.get(at..at + 4)?.try_into().ok()?))
}

const V4_ROW: usize = 18;
const V6_ROW: usize = 42;

/// The table, compiled by `build.rs` from the vendored source.
const BLOB: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/networks.bin"));

struct Table {
    v4: &'static [u8],
    v6: &'static [u8],
    strings: &'static [u8],
}

impl Table {
    /// The name at an offset, up to its terminator.
    fn name(&self, at: u32) -> &'static str {
        let at = at as usize;
        let rest = self.strings.get(at..).unwrap_or_default();
        let end = rest.iter().position(|b| *b == 0).unwrap_or(rest.len());
        rest.get(..end)
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .unwrap_or("")
    }
}

fn table() -> &'static Table {
    static TABLE: OnceLock<Table> = OnceLock::new();
    TABLE.get_or_init(|| {
        // A blob that is not the one this build produced is refused whole
        // rather than read as ranges. Answering from a misread table would be
        // worse than answering `unknown`.
        let empty = Table {
            v4: &[],
            v6: &[],
            strings: &[],
        };
        if BLOB.get(..5) != Some(b"CRNW1") {
            return empty;
        }
        let count = |at: usize| le32(BLOB, at).unwrap_or(0) as usize;
        let (v4_len, v6_len, text_len) = (count(5) * V4_ROW, count(9) * V6_ROW, count(13));
        let v4_at = 17;
        let v6_at = v4_at + v4_len;
        let text_at = v6_at + v6_len;
        if text_at + text_len != BLOB.len() {
            return empty;
        }
        match (
            BLOB.get(v4_at..v6_at),
            BLOB.get(v6_at..text_at),
            BLOB.get(text_at..),
        ) {
            (Some(v4), Some(v6), Some(strings)) => Table { v4, v6, strings },
            _ => empty,
        }
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn the_compiled_table_is_the_one_this_build_produced() {
        let t = table();
        assert!(
            !t.v4.is_empty(),
            "the v4 table is empty; the blob was rejected"
        );
        assert!(!t.v6.is_empty(), "the v6 table is empty");
        assert_eq!(t.v4.len() % V4_ROW, 0);
        assert_eq!(t.v6.len() % V6_ROW, 0);
    }

    #[test]
    fn the_ranges_are_ordered_so_the_binary_search_is_valid() {
        for (rows, size, width) in [(table().v4, V4_ROW, 4), (table().v6, V6_ROW, 16)] {
            let mut previous = 0u128;
            for chunk in rows.chunks_exact(size) {
                let start = number(chunk, 0, width);
                assert!(start >= previous, "the table is not sorted by start");
                assert!(
                    number(chunk, width, width) >= start,
                    "a range ends before it begins"
                );
                previous = start;
            }
        }
    }

    #[test]
    fn the_addresses_this_machine_actually_reaches_resolve() {
        // Every one of these was `unknown` under the starter table, which is
        // why the full one is shipped.
        for (address, expect) in [
            ("160.79.104.10", "ANTHROPIC"),
            ("1.1.1.1", "CLOUDFLARENET"),
            ("8.8.8.8", "GOOGLE"),
        ] {
            let owner = of(address);
            assert!(
                owner.network().contains(expect),
                "{address} resolved to {}, not {expect}",
                owner.network()
            );
            assert_eq!(owner.country(), "\u{1f1fa}\u{1f1f8} US", "{address}");
        }
    }

    #[test]
    fn v6_resolves_from_the_same_call_as_v4() {
        assert!(of("2606:4700::1111").network().contains("CLOUDFLARENET"));
        assert!(of("2600:1901:0:9e23::").network().contains("GOOGLE"));
    }

    #[test]
    fn a_loopback_address_is_named_rather_than_left_to_the_published_table() {
        for address in ["127.0.0.1", "::1"] {
            let network = of(address).network();
            assert!(
                network.to_lowercase().contains("loopback"),
                "{address} gave {network}"
            );
        }
    }

    #[test]
    fn the_cloud_metadata_address_is_named_because_it_is_the_one_that_matters() {
        let owner = of("169.254.169.254");
        assert!(
            owner.network().to_lowercase().contains("metadata"),
            "{}",
            owner.network()
        );
    }

    #[test]
    fn a_more_specific_range_wins_over_the_block_that_contains_it() {
        // 169.254.169.254/32 sits inside 169.254.0.0/16. The wider one must
        // not answer for the narrower.
        assert_ne!(of("169.254.169.254").network(), of("169.254.1.1").network());
    }

    #[test]
    fn a_private_address_says_so_rather_than_reading_unknown() {
        for address in ["10.1.2.3", "192.168.1.1", "172.16.0.1"] {
            assert!(
                of(address).network().to_lowercase().contains("private"),
                "{address}"
            );
        }
    }

    #[test]
    fn an_address_in_no_range_is_unknown_and_never_a_guess() {
        // 0.0.0.0 is in a range; a documentation block is too. This one is
        // reserved and unannounced.
        let owner = of("240.255.255.255");
        assert!(!owner.known() || owner.asn == 0, "{}", owner.network());
    }

    #[test]
    fn nonsense_does_not_panic() {
        for raw in ["", "not-an-address", "999.999.999.999", "::::"] {
            assert_eq!(of(raw), UNKNOWN, "{raw}");
        }
    }

    #[test]
    fn a_country_is_never_shown_as_a_flag_alone() {
        let shown = of("1.1.1.1").country();
        assert!(shown.ends_with("US"), "{shown} drops the code");
        assert!(shown.chars().count() > 3, "{shown} has no flag");
    }

    #[test]
    fn a_range_with_no_country_says_unknown_rather_than_drawing_an_empty_flag() {
        assert_eq!(of("127.0.0.1").country(), "unknown");
    }
}
