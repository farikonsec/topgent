//! Where a kernel struct keeps a field, read from the kernel's own type
//! descriptions in `/sys/kernel/tracing`-adjacent `/sys/kernel/btf/vmlinux`.
//!
//! The probe reads a few fields of kernel structs, and where each sits
//! differs between kernels and build configurations. The loader looks each
//! offset up here and writes it into the probe before it loads, as it does
//! tracepoint offsets from tracefs, so no offset is compiled in
//! (docs/ebpf/PLAN.md, E8).
//!
//! Only what that needs is parsed. A field nested in an anonymous struct or
//! union (`mm_struct` keeps nearly all of its fields in one) is found through
//! it, its offset the sum of the two. Native byte order only: a file in the
//! other order is refused rather than misread.

use std::collections::HashMap;

/// Kinds this reader distinguishes (include/uapi/linux/btf.h). Everything
/// else is walked past so type ids stay aligned.
mod kind {
    pub(super) const STRUCT: u8 = 4;
    pub(super) const UNION: u8 = 5;
}

/// One member of a struct or union.
#[derive(Debug, Clone, Copy)]
struct Member {
    /// Offset into the string section of its name.
    name: u32,
    /// The member's own type id.
    type_id: u32,
    /// From the start of the containing struct, in bits.
    bit_offset: u32,
}

/// One type: only what an offset lookup needs.
#[derive(Debug, Clone)]
struct Entry {
    name: u32,
    kind: u8,
    members: Vec<Member>,
}

/// The kernel's types, indexed for a field lookup.
#[derive(Debug)]
pub(crate) struct Btf {
    entries: Vec<Entry>,
    strings: Vec<u8>,
    /// Struct id by name.
    structs: HashMap<String, usize>,
}

/// The BTF header, all little-or-native u32 after the 4-byte preamble
/// (magic, version, flags), then offsets and lengths of the two sections.
struct Header {
    type_off: usize,
    type_len: usize,
    str_off: usize,
    str_len: usize,
}

const MAGIC: u16 = 0xeb9f;
const HEADER_LEN: usize = 24;
/// Each fixed type entry is three u32 before its kind-specific data.
const ENTRY_HEAD: usize = 12;

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn header(bytes: &[u8]) -> Option<Header> {
    // Native order only: the magic reads as itself, never byte-swapped.
    if u16::from_ne_bytes(bytes.get(0..2)?.try_into().ok()?) != MAGIC {
        return None;
    }
    // struct btf_header: magic u16, version u8, flags u8, then five u32:
    // hdr_len, type_off, type_len, str_off, str_len. The two *_off are from
    // the end of the header.
    let hdr_len = u32_at(bytes, 4)? as usize;
    if hdr_len < HEADER_LEN {
        return None;
    }
    Some(Header {
        type_off: hdr_len + u32_at(bytes, 8)? as usize,
        type_len: u32_at(bytes, 12)? as usize,
        str_off: hdr_len + u32_at(bytes, 16)? as usize,
        str_len: u32_at(bytes, 20)? as usize,
    })
}

/// The trailing bytes after one type's fixed 12, from its kind and vlen.
/// A kind this reader does not know is refused rather than mis-sized.
// One arm per kind, some sharing a body: the kind number beside its size is
// what makes this checkable against the BTF spec.
#[allow(clippy::match_same_arms)]
fn trailing(kind: u8, vlen: usize) -> Option<usize> {
    Some(match kind {
        1 => 4,             // INT
        3 => 12,            // ARRAY
        4 | 5 => vlen * 12, // STRUCT, UNION: btf_member each
        6 => vlen * 8,      // ENUM
        13 => vlen * 8,     // FUNC_PROTO: btf_param each
        14 => 4,            // VAR
        15 => vlen * 12,    // DATASEC
        17 => 4,            // DECL_TAG
        19 => vlen * 12,    // ENUM64
        // PTR, FWD, TYPEDEF, VOLATILE, CONST, RESTRICT, FUNC, FLOAT, TYPE_TAG
        2 | 7 | 8..=12 | 16 | 18 => 0,
        _ => return None,
    })
}

/// Reads every type. Index 0 is the implicit `void`, so real ids start at 1
/// and are their position in the returned vector.
fn parse_types(section: &[u8]) -> Option<Vec<Entry>> {
    let mut entries = vec![Entry {
        name: 0,
        kind: 0,
        members: Vec::new(),
    }];
    let mut at = 0;
    while at + ENTRY_HEAD <= section.len() {
        let name = u32_at(section, at)?;
        let info = u32_at(section, at + 4)?;
        let vlen = (info & 0xffff) as usize;
        let kind = ((info >> 24) & 0x1f) as u8;
        let kind_flag = (info >> 31) & 1 == 1;
        let body = at + ENTRY_HEAD;
        let len = trailing(kind, vlen)?;
        if body + len > section.len() {
            return None;
        }
        let members = if kind == kind::STRUCT || kind == kind::UNION {
            (0..vlen)
                .map(|i| {
                    let m = body + i * 12;
                    let raw = u32_at(section, m + 8)?;
                    // With kind_flag the low 24 bits are the bit offset and
                    // the top 8 the bitfield size; without it the whole word
                    // is the bit offset. Our fields are not bitfields.
                    let bit_offset = if kind_flag { raw & 0x00ff_ffff } else { raw };
                    Some(Member {
                        name: u32_at(section, m)?,
                        type_id: u32_at(section, m + 4)?,
                        bit_offset,
                    })
                })
                .collect::<Option<Vec<_>>>()?
        } else {
            Vec::new()
        };
        entries.push(Entry {
            name,
            kind,
            members,
        });
        at = body + len;
    }
    Some(entries)
}

/// How deep a chain of anonymous structs the lookup follows.
const MAX_NESTING: usize = 8;

impl Btf {
    /// Parses `/sys/kernel/btf/vmlinux`. `None` when it is not BTF in this
    /// host's byte order, or is truncated.
    pub(crate) fn parse(bytes: &[u8]) -> Option<Self> {
        let header = header(bytes)?;
        let types = bytes.get(header.type_off..header.type_off + header.type_len)?;
        let strings = bytes
            .get(header.str_off..header.str_off + header.str_len)?
            .to_vec();
        let entries = parse_types(types)?;
        let mut structs = HashMap::new();
        for (id, entry) in entries.iter().enumerate() {
            if entry.kind == kind::STRUCT
                && entry.name != 0
                && let Some(name) = string_at(&strings, entry.name)
            {
                // The first definition wins; a later forward or duplicate
                // does not replace the real one.
                structs.entry(name.to_owned()).or_insert(id);
            }
        }
        Some(Self {
            entries,
            strings,
            structs,
        })
    }

    /// Byte offset of `field` within struct `name`, following one or more
    /// anonymous struct or union members to reach a nested field. `None`
    /// when the struct or the field is not there.
    pub(crate) fn offset(&self, name: &str, field: &str) -> Option<u32> {
        let id = *self.structs.get(name)?;
        self.field_in(id, field, 0, MAX_NESTING)
    }

    fn field_in(&self, id: usize, field: &str, base: u32, depth: usize) -> Option<u32> {
        if depth == 0 {
            return None;
        }
        let entry = self.entries.get(id)?;
        for member in &entry.members {
            let here = base + member.bit_offset / 8;
            if member.name != 0 {
                if string_at(&self.strings, member.name) == Some(field) {
                    return Some(here);
                }
            } else if let Some(inner) = self.as_struct(member.type_id)
                && let Some(found) = self.field_in(inner, field, here, depth - 1)
            {
                // An anonymous struct or union: its fields sit at this member's
                // own offset plus their own.
                return Some(found);
            }
        }
        None
    }

    /// The struct or union a type id names directly, as an index into
    /// `entries`. An anonymous member points straight at its type, so no
    /// typedef or qualifier is followed here; `None` for anything else.
    fn as_struct(&self, type_id: u32) -> Option<usize> {
        let entry = self.entries.get(type_id as usize)?;
        matches!(entry.kind, kind::STRUCT | kind::UNION).then_some(type_id as usize)
    }
}

/// A NUL-terminated string at `off` in the string section, as UTF-8.
fn string_at(strings: &[u8], off: u32) -> Option<&str> {
    let rest = strings.get(off as usize..)?;
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    std::str::from_utf8(rest.get(..end)?).ok()
}

#[cfg(test)]
mod tests {
    // The blob builder casts small test lengths to u32.
    #![allow(clippy::cast_possible_truncation, clippy::expect_used)]

    use super::Btf;

    /// Builds a BTF blob: a string section and the given type entries, each
    /// already encoded, so a test states exactly the bytes the parser reads.
    fn blob(strings: &[u8], types: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0xeb9f_u16.to_ne_bytes()); // magic
        out.push(1); // version
        out.push(0); // flags
        out.extend_from_slice(&24_u32.to_ne_bytes()); // hdr_len
        out.extend_from_slice(&0_u32.to_ne_bytes()); // type_off
        out.extend_from_slice(&(types.len() as u32).to_ne_bytes());
        out.extend_from_slice(&(types.len() as u32).to_ne_bytes()); // str_off
        out.extend_from_slice(&(strings.len() as u32).to_ne_bytes());
        out.extend_from_slice(types);
        out.extend_from_slice(strings);
        out
    }

    fn header(name: u32, kind: u8, vlen: u16) -> Vec<u8> {
        let info = (u32::from(kind) << 24) | u32::from(vlen);
        let mut out = name.to_ne_bytes().to_vec();
        out.extend_from_slice(&info.to_ne_bytes());
        out.extend_from_slice(&0_u32.to_ne_bytes());
        out
    }

    fn member(name: u32, type_id: u32, bit_offset: u32) -> Vec<u8> {
        let mut out = name.to_ne_bytes().to_vec();
        out.extend_from_slice(&type_id.to_ne_bytes());
        out.extend_from_slice(&bit_offset.to_ne_bytes());
        out
    }

    #[test]
    fn a_nested_field_is_found_through_an_anonymous_member() {
        // strings: offsets are into this. 0 is the empty name.
        let mut strings = vec![0u8];
        let off = |strings: &mut Vec<u8>, s: &str| {
            let at = strings.len() as u32;
            strings.extend_from_slice(s.as_bytes());
            strings.push(0);
            at
        };
        let s_int = off(&mut strings, "int");
        let s_task = off(&mut strings, "task_struct");
        let s_pid = off(&mut strings, "pid");
        let s_inner = off(&mut strings, "inner");
        let s_nested = off(&mut strings, "vpid");

        let mut types = Vec::new();
        // id 1: INT with its 4-byte info word.
        types.extend(header(s_int, 1, 0));
        types.extend_from_slice(&0_u32.to_ne_bytes());
        // id 2: struct inner { vpid at byte 8 }.
        types.extend(header(s_inner, 4, 1));
        types.extend(member(s_nested, 1, 8 * 8));
        // id 3: struct task_struct { pid at 0; anonymous inner at byte 16 }.
        types.extend(header(s_task, 4, 2));
        types.extend(member(s_pid, 1, 0));
        types.extend(member(0, 2, 16 * 8));

        let btf = Btf::parse(&blob(&strings, &types)).expect("parses");
        assert_eq!(btf.offset("task_struct", "pid"), Some(0));
        assert_eq!(btf.offset("task_struct", "vpid"), Some(24), "16 + 8");
        assert_eq!(btf.offset("task_struct", "gone"), None);
        assert_eq!(btf.offset("no_such_struct", "pid"), None);
    }

    #[test]
    fn a_file_that_is_not_native_btf_is_refused() {
        assert!(Btf::parse(&[0; 8]).is_none(), "no magic");
        assert!(Btf::parse(&[]).is_none(), "empty");
        // A struct header promising one member, with the member's bytes cut.
        let truncated = header(0, 4, 1);
        assert!(
            Btf::parse(&blob(&[0], &truncated)).is_none(),
            "a member past the end"
        );
    }
}

#[cfg(test)]
mod kernel {
    #![allow(clippy::expect_used, clippy::print_stdout)]

    use super::Btf;

    /// Against the running kernel's own BTF, where it is present (the lab VM;
    /// not the Mac or CI). `task_struct` and `cred` are in every kernel, and
    /// their fields are what E8 reads, so finding them proves the reader on
    /// the real 6 MB file, not only on the synthetic one.
    #[test]
    fn the_running_kernels_task_struct_is_read() {
        let Ok(bytes) = std::fs::read("/sys/kernel/btf/vmlinux") else {
            eprintln!("no /sys/kernel/btf/vmlinux here; skipped");
            return;
        };
        let btf = Btf::parse(&bytes).expect("the kernel's BTF parses");
        // Every task has a credentials pointer and a memory map.
        assert!(btf.offset("task_struct", "cred").is_some(), "task->cred");
        assert!(btf.offset("task_struct", "mm").is_some(), "task->mm");
        // The capability sets E8's rules read live in struct cred.
        assert!(
            btf.offset("cred", "cap_effective").is_some(),
            "cred->cap_effective"
        );
        // The exec-argument range the sudo gap needs, nested in mm_struct's
        // anonymous struct: the lookup must reach through it.
        assert!(
            btf.offset("mm_struct", "arg_start").is_some(),
            "mm_struct->arg_start, through its anonymous struct"
        );
        assert_eq!(btf.offset("task_struct", "no_such_field"), None);
    }
}
