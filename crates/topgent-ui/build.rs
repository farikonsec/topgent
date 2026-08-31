//! Compile the address-ownership table into a form the interface can search.
//!
//! The published table is 700,000 lines of text. Parsing that at every start
//! would cost a second of a monitor's startup and hold the text in memory for
//! the life of the process, so it is converted here, once, into two sorted
//! arrays of fixed-width records and one string table.
//!
//! The source is vendored. Nothing is fetched during a build: a security tool
//! whose build reaches the network is a security tool whose build is someone
//! else's to change.

// A build script is the one place a panic is the correct behaviour. A build
// that cannot produce this table must fail loudly; the alternative is shipping
// a binary that answers ownership questions from a table nobody wrote.
#![allow(clippy::expect_used, clippy::cast_possible_truncation)]

use std::io::{BufRead, BufReader, Write};
use std::net::IpAddr;

/// The vendored table, and the special-use blocks that it records only as
/// "not routed". Those blocks are exactly the ones an operator most needs
/// named, so they are kept separately and merged in.
const SOURCE: &str = "data/ip2asn-combined.tsv.gz";
const SPECIAL: &str = "data/networks.txt";

fn main() {
    println!("cargo:rerun-if-changed={SOURCE}");
    println!("cargo:rerun-if-changed={SPECIAL}");
    println!("cargo:rerun-if-changed=build.rs");

    let mut strings = StringTable::default();
    let mut v4: Vec<[u8; 18]> = Vec::with_capacity(460_000);
    let mut v6: Vec<[u8; 42]> = Vec::with_capacity(130_000);

    for (start, end, asn, country, name) in read_special(&mut strings)
        .into_iter()
        .chain(read_published(&mut strings))
    {
        let id = strings.id(&name);
        let cc = country_code(&country);
        match (start, end) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                let mut row = [0u8; 18];
                row[0..4].copy_from_slice(&u32::from(a).to_le_bytes());
                row[4..8].copy_from_slice(&u32::from(b).to_le_bytes());
                row[8..12].copy_from_slice(&asn.to_le_bytes());
                row[12..14].copy_from_slice(&cc);
                row[14..18].copy_from_slice(&id.to_le_bytes());
                v4.push(row);
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                let mut row = [0u8; 42];
                row[0..16].copy_from_slice(&u128::from(a).to_le_bytes());
                row[16..32].copy_from_slice(&u128::from(b).to_le_bytes());
                row[32..36].copy_from_slice(&asn.to_le_bytes());
                row[36..38].copy_from_slice(&cc);
                row[38..42].copy_from_slice(&id.to_le_bytes());
                v6.push(row);
            }
            // A range whose ends are different families is malformed. Dropped
            // rather than guessed at.
            _ => {}
        }
    }

    // Sorted by start, and where two share one, the narrower last: the search
    // takes the last range starting at or before the address, which must be
    // the most specific one that contains it.
    v4.sort_by_key(|r| (le32(&r[0..4]), std::cmp::Reverse(le32(&r[4..8]))));
    v6.sort_by_key(|r| (le128(&r[0..16]), std::cmp::Reverse(le128(&r[16..32]))));

    let out = std::path::Path::new(&std::env::var("OUT_DIR").expect("cargo sets OUT_DIR"))
        .join("networks.bin");
    let mut file = std::io::BufWriter::new(std::fs::File::create(&out).expect("write the table"));
    let text = strings.finish();
    file.write_all(b"CRNW1").expect("header");
    for count in [v4.len() as u32, v6.len() as u32, text.len() as u32] {
        file.write_all(&count.to_le_bytes()).expect("counts");
    }
    for row in &v4 {
        file.write_all(row).expect("v4");
    }
    for row in &v6 {
        file.write_all(row).expect("v6");
    }
    file.write_all(&text).expect("strings");
}

fn le32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().expect("four bytes"))
}

fn le128(bytes: &[u8]) -> u128 {
    u128::from_le_bytes(bytes.try_into().expect("sixteen bytes"))
}

/// Two ASCII letters, or two spaces where the table does not say.
fn country_code(raw: &str) -> [u8; 2] {
    let bytes = raw.as_bytes();
    match (bytes.first(), bytes.get(1)) {
        (Some(a), Some(b)) if a.is_ascii_alphabetic() && b.is_ascii_alphabetic() => {
            [a.to_ascii_uppercase(), b.to_ascii_uppercase()]
        }
        _ => *b"  ",
    }
}

type Row = (IpAddr, IpAddr, u32, String, String);

/// The special-use blocks, written as prefixes because that is how the RFCs
/// define them.
fn read_special(_strings: &mut StringTable) -> Vec<Row> {
    let raw = std::fs::read_to_string(SPECIAL).expect("the special-use table is vendored");
    raw.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| {
            let mut fields = line.splitn(4, '\t');
            let (start, end) = cidr(fields.next()?)?;
            let asn = fields.next()?.trim_start_matches("AS").parse().ok()?;
            let country = fields.next()?.to_owned();
            let name = fields.next().unwrap_or("").trim().to_owned();
            Some((start, end, asn, country, name))
        })
        .collect()
}

/// The published table. Ranges announced by nobody are dropped: the source
/// records them as "Not routed" with no useful name, and the special-use file
/// carries the ones worth naming.
fn read_published(_strings: &mut StringTable) -> Vec<Row> {
    let file = std::fs::File::open(SOURCE).expect("the published table is vendored");
    let reader = BufReader::new(flate2::read::GzDecoder::new(file));
    let mut rows = Vec::with_capacity(580_000);
    for line in reader.lines().map_while(Result::ok) {
        let mut fields = line.split('\t');
        let Some(start) = fields.next().and_then(|f| f.parse::<IpAddr>().ok()) else {
            continue;
        };
        let Some(end) = fields.next().and_then(|f| f.parse::<IpAddr>().ok()) else {
            continue;
        };
        let Some(asn) = fields.next().and_then(|f| f.parse::<u32>().ok()) else {
            continue;
        };
        if asn == 0 {
            continue;
        }
        let country = fields.next().unwrap_or("").to_owned();
        // The first token of the name. The full description runs to hundreds
        // of characters and no table column can show it.
        let name = fields
            .next()
            .unwrap_or("")
            .split_whitespace()
            .next()
            .unwrap_or("")
            .chars()
            .take(31)
            .collect();
        rows.push((start, end, asn, country, name));
    }
    rows
}

fn cidr(block: &str) -> Option<(IpAddr, IpAddr)> {
    let (address, bits) = block.split_once('/')?;
    let address: IpAddr = address.parse().ok()?;
    let bits: u32 = bits.parse().ok()?;
    match address {
        IpAddr::V4(a) => {
            if bits > 32 {
                return None;
            }
            let start = u32::from(a);
            let size = 1u64 << (32 - bits);
            let end = u32::try_from(u64::from(start) + size - 1).ok()?;
            Some((IpAddr::V4(start.into()), IpAddr::V4(end.into())))
        }
        IpAddr::V6(a) => {
            if bits > 128 {
                return None;
            }
            let start = u128::from(a);
            let size = 1u128.checked_shl(128 - bits)?;
            // `ff00::/8` ends at the last address there is, and computing that
            // by addition overflows. Saturating is the right answer: the end
            // of the space is the end of the space.
            let end = start.saturating_add(size - 1);
            Some((IpAddr::V6(start.into()), IpAddr::V6(end.into())))
        }
    }
}

/// Network names, deduplicated. 78,000 unique names across 580,000 ranges.
#[derive(Default)]
struct StringTable {
    ids: std::collections::HashMap<String, u32>,
    text: Vec<u8>,
}

impl StringTable {
    /// The offset of this name, adding it if it is new.
    fn id(&mut self, name: &str) -> u32 {
        if let Some(id) = self.ids.get(name) {
            return *id;
        }
        let id = u32::try_from(self.text.len()).expect("the string table fits in four bytes");
        self.text.extend_from_slice(name.as_bytes());
        self.text.push(0);
        self.ids.insert(name.to_owned(), id);
        id
    }

    fn finish(self) -> Vec<u8> {
        self.text
    }
}
