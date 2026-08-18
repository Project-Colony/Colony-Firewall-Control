//! A minimal read-only BTF parser, used for exactly one job: resolving the
//! byte offsets of `task_struct::real_parent` and `task_struct::tgid` from
//! `/sys/kernel/btf/vmlinux` so the loader can hand them to the kernel-side
//! programs as `.rodata` globals.
//!
//! # Why this exists rather than calling into aya
//!
//! Rust/aya has no CO-RE field relocation (LLVM only emits the relocation
//! records for C's `__builtin_preserve_access_index`), so the BPF programs
//! cannot look a field offset up themselves - see
//! `crates/cfc-ebpf/README.md`. The loader has to do it, which means parsing
//! the running kernel's BTF.
//!
//! aya *does* parse BTF (`aya::Btf`, re-exported from `aya-obj`), but as of
//! aya-obj 0.3 the only public introspection entry point is
//! `Btf::id_by_type_name_kind`, which returns a type id. Everything needed to
//! go from that id to a member list - `Btf::types()`, `Btf::type_by_id`, the
//! `BtfMember` struct and `Struct::members` - is `pub(crate)`. There is no
//! public API for "give me the offset of this member", so a loader that wants
//! one has to read the bytes itself.
//!
//! Doing it here also means the resolver is testable in the default build:
//! this module has **no dependency on aya at all** and is compiled (and unit
//! tested) whether or not the `ebpf` cargo feature is on.
//!
//! # Format
//!
//! BTF is documented at <https://docs.kernel.org/bpf/btf.html>. The shape used
//! here:
//!
//! ```text
//! struct btf_header {            struct btf_type {
//!     u16 magic;   // 0xeB9F         u32 name_off;
//!     u8  version;                   u32 info;   // vlen:16 kind:5 kind_flag:1
//!     u8  flags;                     union { u32 size; u32 type; };
//!     u32 hdr_len;               };
//!     u32 type_off;              struct btf_member {   // vlen of these follow
//!     u32 type_len;                  u32 name_off;     // a STRUCT/UNION
//!     u32 str_off;                   u32 type;
//!     u32 str_len;                   u32 offset;       // bits, or
//! };                             };                    // bitfield when kind_flag
//! ```
//!
//! `type_off` and `str_off` are relative to the *end* of the header
//! (`hdr_len`), not to the start of the file.
//!
//! Every walk here is bounded by the section lengths declared in the header
//! and every read is checked, so a truncated or hostile blob produces an error
//! rather than a panic. The file is root-readable kernel data, but this parser
//! runs inside the firewall daemon and gets the same treatment as a packet.

use std::path::Path;

/// Where the running kernel publishes its own BTF.
pub const VMLINUX_BTF: &str = "/sys/kernel/btf/vmlinux";

/// Little-endian BTF magic. A big-endian blob stores the same value with the
/// bytes swapped, which is how endianness is detected.
const BTF_MAGIC: u16 = 0xEB9F;

/// `struct btf_header` is 24 bytes; anything shorter cannot be BTF.
const HEADER_LEN: usize = 24;

/// `struct btf_type` without its kind-specific tail.
const TYPE_LEN: usize = 12;

/// `struct btf_member`.
const MEMBER_LEN: usize = 12;

const KIND_INT: u32 = 1;
const KIND_ARRAY: u32 = 3;
const KIND_STRUCT: u32 = 4;
const KIND_UNION: u32 = 5;
const KIND_ENUM: u32 = 6;
const KIND_FUNC_PROTO: u32 = 13;
const KIND_VAR: u32 = 14;
const KIND_DATASEC: u32 = 15;
const KIND_DECL_TAG: u32 = 17;
const KIND_ENUM64: u32 = 19;

/// Everything that can go wrong reading a BTF blob. All of these are
/// non-fatal for the daemon: the loader logs a warning and leaves the
/// `.rodata` globals at 0, which the BPF programs read as "unresolved" and
/// answer with `ppid = 0`.
#[derive(Debug, thiserror::Error)]
pub enum BtfError {
    #[error("BTF blob is truncated at byte {offset} (need {need} bytes, have {have})")]
    Truncated {
        offset: usize,
        need: usize,
        have: usize,
    },
    #[error("not a BTF blob: bad magic {magic:#06x}")]
    BadMagic { magic: u16 },
    #[error("unsupported BTF version {version}")]
    BadVersion { version: u8 },
    #[error("BTF header declares hdr_len {hdr_len}, which is shorter than the 24-byte header")]
    ShortHeader { hdr_len: u32 },
    #[error("BTF string offset {offset} is outside the {len}-byte string section")]
    BadStringOffset { offset: usize, len: usize },
    #[error("no struct named `{name}` in this BTF blob")]
    NoSuchStruct { name: String },
}

/// The two `task_struct` member offsets the kernel-side programs need.
///
/// Both are byte offsets from the start of `task_struct`. `0` is the
/// kernel-side sentinel for "unresolved" - which is safe precisely because
/// neither field can genuinely live at offset 0 (`task_struct` opens with
/// `thread_info`/`__state` on every kernel that has ever existed).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TaskStructOffsets {
    pub real_parent: u32,
    pub tgid: u32,
}

impl TaskStructOffsets {
    /// True when both offsets were found and are usable as globals.
    pub fn is_resolved(self) -> bool {
        self.real_parent != 0 && self.tgid != 0
    }
}

/// Resolves the offsets from the running kernel's BTF.
pub fn task_struct_offsets() -> anyhow::Result<TaskStructOffsets> {
    task_struct_offsets_from(Path::new(VMLINUX_BTF))
}

/// Resolves the offsets from a BTF file, for tests and for hosts that keep
/// their BTF somewhere other than `/sys/kernel/btf/vmlinux`.
pub fn task_struct_offsets_from(path: &Path) -> anyhow::Result<TaskStructOffsets> {
    let raw = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))
        .map_err(|e| {
            // A missing file is the common case on a kernel built without
            // CONFIG_DEBUG_INFO_BTF; keep the message actionable.
            e.context("kernel BTF unavailable; ppid enrichment will be disabled")
        })?;
    let found = member_offsets(&raw, "task_struct", &["real_parent", "tgid"])?;
    Ok(TaskStructOffsets {
        real_parent: found[0].unwrap_or(0),
        tgid: found[1].unwrap_or(0),
    })
}

/// Byte offsets of `wanted` members inside the BTF struct named `type_name`.
///
/// Returns one entry per requested name, in the same order; `None` means the
/// struct exists but has no such member. Bitfields report the byte offset of
/// the bit they start at, which is meaningless for a bitfield and is why the
/// caller only ever asks for whole-word members.
pub fn member_offsets(
    raw: &[u8],
    type_name: &str,
    wanted: &[&str],
) -> Result<Vec<Option<u32>>, BtfError> {
    let hdr = Header::parse(raw)?;
    let types = hdr.section(raw, hdr.type_off, hdr.type_len)?;
    let strings = hdr.section(raw, hdr.str_off, hdr.str_len)?;

    let mut cursor = 0usize;
    while cursor < types.len() {
        let ty = TypeHeader::parse(types, cursor, hdr.little)?;
        let body = cursor + TYPE_LEN;
        let tail = ty.tail_len();
        // A tail that runs past the section is a malformed blob, not a
        // reason to keep walking into whatever follows.
        if body + tail > types.len() {
            return Err(BtfError::Truncated {
                offset: body,
                need: tail,
                have: types.len() - body,
            });
        }

        if ty.kind == KIND_STRUCT && string_at(strings, ty.name_off)? == type_name {
            let mut out = vec![None; wanted.len()];
            for i in 0..ty.vlen as usize {
                let at = body + i * MEMBER_LEN;
                let name_off = read_u32(types, at, hdr.little)?;
                let raw_offset = read_u32(types, at + 8, hdr.little)?;
                // With kind_flag set, the low 24 bits are the bit offset and
                // the top 8 are the bitfield width.
                let bit_offset = if ty.kind_flag {
                    raw_offset & 0x00ff_ffff
                } else {
                    raw_offset
                };
                let name = string_at(strings, name_off)?;
                for (slot, want) in out.iter_mut().zip(wanted) {
                    if slot.is_none() && name == *want {
                        *slot = Some(bit_offset / 8);
                    }
                }
            }
            return Ok(out);
        }

        cursor = body + tail;
    }

    Err(BtfError::NoSuchStruct {
        name: type_name.to_string(),
    })
}

struct Header {
    little: bool,
    hdr_len: u32,
    type_off: u32,
    type_len: u32,
    str_off: u32,
    str_len: u32,
}

impl Header {
    fn parse(raw: &[u8]) -> Result<Self, BtfError> {
        if raw.len() < HEADER_LEN {
            return Err(BtfError::Truncated {
                offset: 0,
                need: HEADER_LEN,
                have: raw.len(),
            });
        }
        let le = u16::from_le_bytes([raw[0], raw[1]]);
        let little = if le == BTF_MAGIC {
            true
        } else if u16::from_be_bytes([raw[0], raw[1]]) == BTF_MAGIC {
            false
        } else {
            return Err(BtfError::BadMagic { magic: le });
        };
        let version = raw[2];
        if version != 1 {
            return Err(BtfError::BadVersion { version });
        }
        let hdr_len = read_u32(raw, 4, little)?;
        if (hdr_len as usize) < HEADER_LEN {
            return Err(BtfError::ShortHeader { hdr_len });
        }
        Ok(Self {
            little,
            hdr_len,
            type_off: read_u32(raw, 8, little)?,
            type_len: read_u32(raw, 12, little)?,
            str_off: read_u32(raw, 16, little)?,
            str_len: read_u32(raw, 20, little)?,
        })
    }

    /// A section slice, with both its start (`hdr_len + off`) and its end
    /// bounds-checked against the blob.
    fn section<'a>(&self, raw: &'a [u8], off: u32, len: u32) -> Result<&'a [u8], BtfError> {
        let start = self.hdr_len as usize + off as usize;
        let end = start + len as usize;
        raw.get(start..end).ok_or(BtfError::Truncated {
            offset: start,
            need: len as usize,
            have: raw.len().saturating_sub(start),
        })
    }
}

struct TypeHeader {
    name_off: u32,
    kind: u32,
    vlen: u32,
    kind_flag: bool,
}

impl TypeHeader {
    /// `little` is the blob's endianness, taken from its header: the `info`
    /// bit layout below is only well-defined once the word itself has been
    /// decoded the right way round.
    fn parse(types: &[u8], at: usize, little: bool) -> Result<Self, BtfError> {
        let name_off = read_u32(types, at, little)?;
        let info = read_u32(types, at + 4, little)?;
        Ok(Self {
            name_off,
            kind: (info >> 24) & 0x1f,
            vlen: info & 0xffff,
            kind_flag: (info >> 31) == 1,
        })
    }

    /// Size of the kind-specific data that follows `struct btf_type`.
    fn tail_len(&self) -> usize {
        match self.kind {
            KIND_INT | KIND_VAR | KIND_DECL_TAG => 4,
            KIND_ARRAY => 12,
            KIND_STRUCT | KIND_UNION => MEMBER_LEN * self.vlen as usize,
            KIND_ENUM | KIND_FUNC_PROTO => 8 * self.vlen as usize,
            KIND_DATASEC | KIND_ENUM64 => 12 * self.vlen as usize,
            _ => 0,
        }
    }
}

fn read_u32(buf: &[u8], at: usize, little: bool) -> Result<u32, BtfError> {
    let bytes: [u8; 4] =
        buf.get(at..at + 4)
            .and_then(|s| s.try_into().ok())
            .ok_or(BtfError::Truncated {
                offset: at,
                need: 4,
                have: buf.len().saturating_sub(at),
            })?;
    Ok(if little {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    })
}

/// NUL-terminated string at `offset` in the string section. Names are ASCII C
/// identifiers, so non-UTF-8 is treated as "not the name we are looking for"
/// rather than an error.
fn string_at(strings: &[u8], offset: u32) -> Result<&str, BtfError> {
    let offset = offset as usize;
    let rest = strings.get(offset..).ok_or(BtfError::BadStringOffset {
        offset,
        len: strings.len(),
    })?;
    let end = rest.iter().position(|b| *b == 0).unwrap_or(rest.len());
    Ok(std::str::from_utf8(&rest[..end]).unwrap_or(""))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal but structurally valid little-endian BTF blob with a
    /// single STRUCT and the members given as `(name, bit_offset)`.
    fn blob(struct_name: &str, members: &[(&str, u32)], kind_flag: bool) -> Vec<u8> {
        // String section: a leading NUL (offset 0 is the empty string, as the
        // format requires), then every name we need.
        let mut strings = vec![0u8];
        let off_of = |s: &str, strings: &mut Vec<u8>| -> u32 {
            let at = strings.len() as u32;
            strings.extend_from_slice(s.as_bytes());
            strings.push(0);
            at
        };
        let struct_name_off = off_of(struct_name, &mut strings);
        let member_offs: Vec<u32> = members
            .iter()
            .map(|(n, _)| off_of(n, &mut strings))
            .collect();

        let mut types = Vec::new();
        // A leading INT type, so the walker has to skip a non-struct entry
        // (and its 4-byte tail) before reaching the struct.
        types.extend_from_slice(&0u32.to_le_bytes()); // name_off (anonymous)
        types.extend_from_slice(&(KIND_INT << 24).to_le_bytes()); // info
        types.extend_from_slice(&4u32.to_le_bytes()); // size
        types.extend_from_slice(&0u32.to_le_bytes()); // int tail

        let info = (u32::from(kind_flag) << 31) | (KIND_STRUCT << 24) | (members.len() as u32);
        types.extend_from_slice(&struct_name_off.to_le_bytes());
        types.extend_from_slice(&info.to_le_bytes());
        types.extend_from_slice(&4096u32.to_le_bytes()); // struct size
        for ((_, bit_offset), name_off) in members.iter().zip(&member_offs) {
            types.extend_from_slice(&name_off.to_le_bytes());
            types.extend_from_slice(&1u32.to_le_bytes()); // member type id
            types.extend_from_slice(&bit_offset.to_le_bytes());
        }

        let mut out = Vec::new();
        out.extend_from_slice(&BTF_MAGIC.to_le_bytes());
        out.push(1); // version
        out.push(0); // flags
        out.extend_from_slice(&(HEADER_LEN as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // type_off
        out.extend_from_slice(&(types.len() as u32).to_le_bytes());
        out.extend_from_slice(&(types.len() as u32).to_le_bytes()); // str_off
        out.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        out.extend_from_slice(&types);
        out.extend_from_slice(&strings);
        out
    }

    #[test]
    fn finds_member_offsets_in_a_hand_built_blob() {
        // Bit offsets, as BTF stores them: 0x9c0 bits = 312 bytes.
        let raw = blob(
            "task_struct",
            &[("state", 0x10), ("tgid", 0x9c0), ("real_parent", 0xb00)],
            false,
        );
        let got = member_offsets(&raw, "task_struct", &["real_parent", "tgid"]).unwrap();
        assert_eq!(got, vec![Some(0xb00 / 8), Some(0x9c0 / 8)]);
    }

    #[test]
    fn missing_member_is_none_not_an_error() {
        let raw = blob("task_struct", &[("tgid", 64)], false);
        let got = member_offsets(&raw, "task_struct", &["real_parent", "tgid"]).unwrap();
        assert_eq!(got, vec![None, Some(8)]);
    }

    #[test]
    fn kind_flag_masks_the_bitfield_width_out_of_the_offset() {
        // With kind_flag set the top 8 bits are the bitfield size and must
        // not leak into the offset.
        let raw = blob("task_struct", &[("tgid", (5 << 24) | 512)], true);
        let got = member_offsets(&raw, "task_struct", &["tgid"]).unwrap();
        assert_eq!(got, vec![Some(64)]);
    }

    #[test]
    fn unknown_struct_is_an_error() {
        let raw = blob("task_struct", &[("tgid", 0)], false);
        assert!(matches!(
            member_offsets(&raw, "sock", &["sk_protocol"]),
            Err(BtfError::NoSuchStruct { .. })
        ));
    }

    #[test]
    fn rejects_a_blob_that_is_not_btf() {
        assert!(matches!(
            member_offsets(b"\x7fELF\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", "x", &[]),
            Err(BtfError::BadMagic { .. })
        ));
        assert!(matches!(
            member_offsets(b"short", "x", &[]),
            Err(BtfError::Truncated { .. })
        ));
    }

    #[test]
    fn truncated_type_section_errors_instead_of_panicking() {
        let mut raw = blob("task_struct", &[("tgid", 0), ("real_parent", 64)], false);
        // Chop the last member off without fixing the header's type_len.
        raw.truncate(raw.len() - 20);
        assert!(member_offsets(&raw, "task_struct", &["tgid"]).is_err());
    }

    #[test]
    fn offsets_are_unresolved_until_both_are_found() {
        assert!(!TaskStructOffsets::default().is_resolved());
        assert!(!TaskStructOffsets {
            real_parent: 8,
            tgid: 0
        }
        .is_resolved());
        assert!(TaskStructOffsets {
            real_parent: 8,
            tgid: 16
        }
        .is_resolved());
    }

    /// Runs against the real kernel BTF. Ignored by default: it needs
    /// `/sys/kernel/btf/vmlinux` to exist and be readable, which is a
    /// property of the machine, not of the code.
    ///
    ///     cargo test -p cfc-daemon --lib -- --ignored resolves_offsets_from_the_running_kernel --nocapture
    #[test]
    #[ignore = "requires a readable /sys/kernel/btf/vmlinux"]
    fn resolves_offsets_from_the_running_kernel() {
        let offs = task_struct_offsets().expect("reading kernel BTF");
        println!("task_struct: real_parent @ {offs:?}");
        assert!(
            offs.is_resolved(),
            "both offsets should resolve on a BTF-enabled kernel: {offs:?}"
        );
        // Sanity: task_struct is a few kilobytes; anything past that means we
        // read the wrong struct.
        assert!(offs.real_parent < 16 * 1024);
        assert!(offs.tgid < 16 * 1024);
    }
}
