//! Bounded, panic-free DNS response parsing.
//!
//! This is the arithmetic half of the `cgroup_skb/ingress` program in
//! `cfc-ebpf`. It is written to the eBPF verifier's rules and therefore obeys
//! some unusual constraints:
//!
//! * **no panics** — every read goes through [`Option`]-returning accessors, so
//!   the compiler never emits a bounds-check panic path. A BPF object with a
//!   reachable `panic!` either fails to link (no `core::fmt`) or traps.
//! * **no unbounded loops** — every loop has a *compile-time constant* trip
//!   count and exits early via `break`. The verifier walks all paths, so a
//!   runtime-bounded loop is either rejected or explodes the instruction count.
//! * **no dynamic slicing** — `&buf[a..b]` panics; only `slice::get` is used.
//! * **no big stack frames** — BPF gives a program 512 bytes of stack *total*.
//!   [`DnsAnswer`] alone is 276 bytes, so the caller owns it (in a per-CPU map
//!   on the kernel side) and the parser only ever holds a handful of `usize`s.
//!
//! # What is supported
//!
//! * `A` (type 1) and `AAAA` (type 28) records in class `IN`, from the answer
//!   section of a response (QR=1) with `RCODE == NOERROR`.
//! * Name compression pointers (RFC 1035 §4.1.4), up to [`MAX_LABEL_JUMPS`]
//!   jumps per name, and only *backwards* pointers (`ptr < current_offset`),
//!   which makes non-termination impossible independently of the jump cap.
//!
//! # What is deliberately skipped
//!
//! * more than [`MAX_ANSWERS`] answer records per response — the rest of the
//!   packet is ignored;
//! * more than [`MAX_QUESTIONS`] questions — the packet is dropped entirely,
//!   because the answer section offset cannot be computed without walking them;
//! * `CNAME`/`SOA`/`NS`/anything else — skipped by `rdlength`, not reported;
//! * records whose owner name exceeds [`MAX_NAME_LEN`] (253) bytes;
//! * responses longer than the caller's scratch buffer (the parser stops at the
//!   first record it cannot read in full — see [`crate::DNS_BUF_LEN`]);
//! * TCP DNS, DoT, DoH, mDNS, EDNS(0) option parsing.

use crate::DnsAnswer;

/// Fixed DNS header size (RFC 1035 §4.1.1).
pub const DNS_HEADER_LEN: usize = 12;

/// Longest presentation-format domain name, per RFC 1035 §2.3.4.
pub const MAX_NAME_LEN: usize = 253;

/// Longest single label, per RFC 1035 §2.3.4.
pub const MAX_LABEL_LEN: usize = 63;

/// Upper bound on labels walked while resolving one name (compression jumps
/// included). Keeps the verifier's path budget small.
pub const MAX_LABELS: usize = 32;

/// Compression pointers followed per name before the packet is rejected.
pub const MAX_LABEL_JUMPS: usize = 4;

/// Answer records examined per response. Records past this cap are ignored.
pub const MAX_ANSWERS: usize = 8;

/// Questions walked before the response is rejected. Real responses have 1.
pub const MAX_QUESTIONS: usize = 4;

/// `A` record type.
pub const TYPE_A: u16 = 1;
/// `AAAA` record type.
pub const TYPE_AAAA: u16 = 28;
/// `IN` record class.
pub const CLASS_IN: u16 = 1;

const PTR_MASK: u8 = 0xc0;

/// A bounds-checked, panic-free reader over a DNS message.
///
/// `base` is where the DNS message starts inside `buf` (compression pointers
/// are relative to that, not to the packet), and `len` is how many DNS bytes
/// are actually available.
#[derive(Clone, Copy)]
pub struct DnsCursor<'a> {
    buf: &'a [u8],
    base: usize,
    len: usize,
}

impl<'a> DnsCursor<'a> {
    /// A cursor over a buffer that starts exactly at the DNS header.
    #[inline(always)]
    pub fn new(buf: &'a [u8]) -> Self {
        Self::with_base(buf, 0, buf.len())
    }

    /// A cursor over a DNS message embedded at `base` in a larger buffer.
    ///
    /// `len` is clamped so it can never point past `buf`.
    #[inline(always)]
    pub fn with_base(buf: &'a [u8], base: usize, len: usize) -> Self {
        let avail = buf.len().saturating_sub(base);
        let len = if len < avail { len } else { avail };
        Self { buf, base, len }
    }

    /// Number of readable DNS bytes.
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.len
    }

    /// True when there is no readable DNS payload at all.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline(always)]
    fn u8_at(&self, off: usize) -> Option<u8> {
        if off >= self.len {
            return None;
        }
        self.buf.get(self.base + off).copied()
    }

    #[inline(always)]
    fn u16_at(&self, off: usize) -> Option<u16> {
        let hi = self.u8_at(off)? as u16;
        let lo = self.u8_at(off + 1)? as u16;
        Some((hi << 8) | lo)
    }

    #[inline(always)]
    fn u32_at(&self, off: usize) -> Option<u32> {
        let hi = self.u16_at(off)? as u32;
        let lo = self.u16_at(off + 2)? as u32;
        Some((hi << 16) | lo)
    }
}

/// The 12-byte DNS header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DnsHeader {
    /// Transaction id.
    pub id: u16,
    /// Raw flags word (QR/OPCODE/AA/TC/RD/RA/Z/RCODE).
    pub flags: u16,
    /// Question count.
    pub qdcount: u16,
    /// Answer record count.
    pub ancount: u16,
    /// Authority record count.
    pub nscount: u16,
    /// Additional record count.
    pub arcount: u16,
}

impl DnsHeader {
    /// QR bit: this message is a response.
    #[inline(always)]
    pub fn is_response(&self) -> bool {
        self.flags & 0x8000 != 0
    }

    /// TC bit: the message was truncated and should be retried over TCP.
    #[inline(always)]
    pub fn is_truncated(&self) -> bool {
        self.flags & 0x0200 != 0
    }

    /// Low 4 bits of the flags word.
    #[inline(always)]
    pub fn rcode(&self) -> u8 {
        (self.flags & 0x000f) as u8
    }
}

/// Reads the fixed header. `None` if fewer than 12 bytes are available.
#[inline(always)]
pub fn parse_header(c: &DnsCursor<'_>) -> Option<DnsHeader> {
    Some(DnsHeader {
        id: c.u16_at(0)?,
        flags: c.u16_at(2)?,
        qdcount: c.u16_at(4)?,
        ancount: c.u16_at(6)?,
        nscount: c.u16_at(8)?,
        arcount: c.u16_at(10)?,
    })
}

/// Advances past a name without materialising it.
///
/// A compression pointer terminates the name in the *stream*, so this returns
/// `off + 2` without following it — which is exactly what the question and
/// record-skipping paths need.
#[inline(always)]
pub fn skip_name(c: &DnsCursor<'_>, start: usize) -> Option<usize> {
    let mut off = start;
    let mut i = 0;
    while i < MAX_LABELS {
        let b = c.u8_at(off)?;
        if b == 0 {
            return Some(off + 1);
        }
        if b & PTR_MASK == PTR_MASK {
            // Second pointer byte must exist even though we do not follow it.
            c.u8_at(off + 1)?;
            return Some(off + 2);
        }
        if b & PTR_MASK != 0 {
            // 0b01 / 0b10 label types are reserved (RFC 6891 retired them).
            return None;
        }
        off += 1 + b as usize;
        i += 1;
    }
    None
}

/// Walks the question section and returns the offset of the answer section.
///
/// `None` when the packet is truncated or declares more than
/// [`MAX_QUESTIONS`] questions.
#[inline(always)]
pub fn skip_questions(c: &DnsCursor<'_>, qdcount: u16) -> Option<usize> {
    if qdcount as usize > MAX_QUESTIONS {
        return None;
    }
    let mut off = DNS_HEADER_LEN;
    let mut i = 0usize;
    while i < MAX_QUESTIONS {
        if i >= qdcount as usize {
            break;
        }
        off = skip_name(c, off)?;
        // QTYPE + QCLASS must both be present.
        c.u16_at(off)?;
        c.u16_at(off + 2)?;
        off += 4;
        i += 1;
    }
    Some(off)
}

/// Materialises the name at `start` into `out` as dot-separated ASCII.
///
/// Returns `(bytes_written, offset_just_past_the_name_in_the_stream)`. A single
/// NUL is written at `out[bytes_written]` (when it fits); bytes beyond that are
/// left as-is and must be treated as undefined by callers -- both the returned
/// length and [`crate::nul_terminated`] keep them unreachable.
///
/// Compression pointers are followed, but only backwards and at most
/// [`MAX_LABEL_JUMPS`] times.
#[inline(always)]
pub fn read_name(
    c: &DnsCursor<'_>,
    start: usize,
    out: &mut [u8; MAX_NAME_LEN],
) -> Option<(u8, usize)> {
    let mut off = start;
    let mut written = 0usize;
    let mut jumps = 0usize;
    let mut next: Option<usize> = None;
    let mut terminated = false;

    let mut label = 0usize;
    while label < MAX_LABELS {
        let b = c.u8_at(off)?;

        if b == 0 {
            if next.is_none() {
                next = Some(off + 1);
            }
            terminated = true;
            break;
        }

        if b & PTR_MASK == PTR_MASK {
            if jumps >= MAX_LABEL_JUMPS {
                return None;
            }
            let lo = c.u8_at(off + 1)?;
            let target = (((b & !PTR_MASK) as usize) << 8) | lo as usize;
            // Only backwards pointers: guarantees strict progress, so the walk
            // terminates even if MAX_LABEL_JUMPS were raised.
            if target >= off {
                return None;
            }
            if next.is_none() {
                next = Some(off + 2);
            }
            off = target;
            jumps += 1;
            label += 1;
            continue;
        }

        if b & PTR_MASK != 0 {
            return None;
        }

        let label_len = b as usize;
        if label_len > MAX_LABEL_LEN {
            return None;
        }

        if written != 0 {
            if written >= MAX_NAME_LEN {
                return None;
            }
            *out.get_mut(written)? = b'.';
            written += 1;
        }
        if written + label_len > MAX_NAME_LEN {
            return None;
        }

        let mut k = 0usize;
        while k < MAX_LABEL_LEN {
            if k >= label_len {
                break;
            }
            let ch = c.u8_at(off + 1 + k)?;
            *out.get_mut(written + k)? = ch;
            k += 1;
        }

        written += label_len;
        off += 1 + label_len;
        label += 1;
    }

    if !terminated {
        return None;
    }

    // NUL-terminate rather than zero the whole tail.
    //
    // Zeroing `out[written..]` -- however it is spelled, including an explicit
    // byte loop, which LLVM's loop-idiom pass happily rewrites -- becomes a
    // `memset` of up to 253 bytes. The BPF backend cannot lower a memset that
    // large to inline stores and emits a libcall, which then fails to link
    // ("A call to built-in function 'memset' is not supported"). One store is
    // enough: `name_len` is authoritative and
    // [`crate::nul_terminated`] additionally stops here, so userspace can never
    // observe the stale bytes beyond this point.
    if let Some(slot) = out.get_mut(written) {
        *slot = 0;
    }

    Some((written as u8, next?))
}

/// Parses one resource record starting at `off`.
///
/// `out` is filled in full (name, ttl, ip, is_v6) when the record is an
/// `IN A`/`IN AAAA`; otherwise only the name/ttl scratch is disturbed and the
/// returned flag is `false`.
///
/// Returns `(is_a_or_aaaa, offset_of_next_record)`.
#[inline(always)]
pub fn parse_answer_at(
    c: &DnsCursor<'_>,
    off: usize,
    out: &mut DnsAnswer,
) -> Option<(bool, usize)> {
    let (name_len, after_name) = read_name(c, off, &mut out.name)?;

    let rtype = c.u16_at(after_name)?;
    let rclass = c.u16_at(after_name + 2)?;
    let ttl = c.u32_at(after_name + 4)?;
    let rdlength = c.u16_at(after_name + 8)? as usize;
    let rdata = after_name + 10;

    // The whole RDATA must be inside the readable window, otherwise the "next
    // record" offset would be a guess.
    if rdata + rdlength > c.len() {
        return None;
    }
    let next = rdata + rdlength;

    out.name_len = name_len;
    out.ttl = ttl;
    out._pad = [0; 1];

    let mut matched = false;
    if rclass == CLASS_IN {
        if rtype == TYPE_A && rdlength == 4 {
            out.ip = [0; 16];
            let mut i = 0usize;
            while i < 4 {
                *out.ip.get_mut(i)? = c.u8_at(rdata + i)?;
                i += 1;
            }
            out.is_v6 = 0;
            matched = true;
        } else if rtype == TYPE_AAAA && rdlength == 16 {
            let mut i = 0usize;
            while i < 16 {
                *out.ip.get_mut(i)? = c.u8_at(rdata + i)?;
                i += 1;
            }
            out.is_v6 = 1;
            matched = true;
        }
    }

    Some((matched, next))
}

/// Drives the whole answer section, invoking `f` for every `A`/`AAAA` record.
///
/// This is the exact loop the BPF program runs; keeping it here is what makes
/// the kernel-side control flow host-testable.
///
/// `scratch` is caller-owned because [`DnsAnswer`] is 276 bytes and would blow
/// more than half of a BPF program's 512-byte stack. On the kernel side it
/// lives in a `PerCpuArray`.
///
/// Returns the number of records passed to `f` (never more than
/// [`MAX_ANSWERS`]).
#[inline(always)]
pub fn for_each_answer<F>(c: &DnsCursor<'_>, scratch: &mut DnsAnswer, mut f: F) -> u32
where
    F: FnMut(&DnsAnswer),
{
    let header = match parse_header(c) {
        Some(h) => h,
        None => return 0,
    };
    if !header.is_response() || header.rcode() != 0 || header.ancount == 0 {
        return 0;
    }
    let mut off = match skip_questions(c, header.qdcount) {
        Some(o) => o,
        None => return 0,
    };

    let mut emitted = 0u32;
    let mut i = 0usize;
    while i < MAX_ANSWERS {
        if i >= header.ancount as usize {
            break;
        }
        match parse_answer_at(c, off, scratch) {
            Some((matched, next)) => {
                if matched {
                    f(scratch);
                    emitted += 1;
                }
                off = next;
            }
            None => break,
        }
        i += 1;
    }
    emitted
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DNS_BUF_LEN;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    // ---- tiny DNS packet builder ----------------------------------------

    #[derive(Default)]
    struct Pkt(Vec<u8>);

    impl Pkt {
        fn header(flags: u16, qd: u16, an: u16) -> Self {
            let mut p = Pkt(Vec::new());
            p.u16(0x1234);
            p.u16(flags);
            p.u16(qd);
            p.u16(an);
            p.u16(0);
            p.u16(0);
            p
        }
        fn response(qd: u16, an: u16) -> Self {
            Self::header(0x8180, qd, an)
        }
        fn u8(&mut self, v: u8) -> &mut Self {
            self.0.push(v);
            self
        }
        fn u16(&mut self, v: u16) -> &mut Self {
            self.0.extend_from_slice(&v.to_be_bytes());
            self
        }
        fn u32(&mut self, v: u32) -> &mut Self {
            self.0.extend_from_slice(&v.to_be_bytes());
            self
        }
        fn name(&mut self, n: &str) -> &mut Self {
            for label in n.split('.') {
                self.0.push(label.len() as u8);
                self.0.extend_from_slice(label.as_bytes());
            }
            self.0.push(0);
            self
        }
        /// A compression pointer to an absolute offset.
        fn ptr(&mut self, target: u16) -> &mut Self {
            self.u16(0xc000 | target);
            self
        }
        fn question(&mut self, n: &str) -> &mut Self {
            self.name(n);
            self.u16(TYPE_A);
            self.u16(CLASS_IN);
            self
        }
        fn a_record_ptr(&mut self, target: u16, ttl: u32, ip: [u8; 4]) -> &mut Self {
            self.ptr(target);
            self.u16(TYPE_A);
            self.u16(CLASS_IN);
            self.u32(ttl);
            self.u16(4);
            self.0.extend_from_slice(&ip);
            self
        }
        fn a_record(&mut self, n: &str, ttl: u32, ip: [u8; 4]) -> &mut Self {
            self.name(n);
            self.u16(TYPE_A);
            self.u16(CLASS_IN);
            self.u32(ttl);
            self.u16(4);
            self.0.extend_from_slice(&ip);
            self
        }
        fn aaaa_record(&mut self, n: &str, ttl: u32, ip: [u8; 16]) -> &mut Self {
            self.name(n);
            self.u16(TYPE_AAAA);
            self.u16(CLASS_IN);
            self.u32(ttl);
            self.u16(16);
            self.0.extend_from_slice(&ip);
            self
        }
        fn cname_record(&mut self, n: &str, ttl: u32, target: &str) -> &mut Self {
            self.name(n);
            self.u16(5); // CNAME
            self.u16(CLASS_IN);
            self.u32(ttl);
            let mut rd = Pkt(Vec::new());
            rd.name(target);
            self.u16(rd.0.len() as u16);
            self.0.extend_from_slice(&rd.0);
            self
        }
        fn bytes(&self) -> Vec<u8> {
            self.0.clone()
        }
    }

    fn collect(buf: &[u8]) -> Vec<DnsAnswer> {
        let c = DnsCursor::new(buf);
        let mut scratch = DnsAnswer::zeroed();
        let mut out = Vec::new();
        for_each_answer(&c, &mut scratch, |a| out.push(*a));
        out
    }

    /// Same packet, but placed inside a fixed 512-byte scratch buffer at a
    /// non-zero base — exactly how the BPF program sees it.
    fn collect_in_scratch(buf: &[u8], base: usize) -> Vec<DnsAnswer> {
        let mut scratch_buf = [0u8; DNS_BUF_LEN];
        let n = buf.len().min(DNS_BUF_LEN - base);
        scratch_buf[base..base + n].copy_from_slice(&buf[..n]);
        let c = DnsCursor::with_base(&scratch_buf, base, n);
        let mut scratch = DnsAnswer::zeroed();
        let mut out = Vec::new();
        for_each_answer(&c, &mut scratch, |a| out.push(*a));
        out
    }

    // ---- header ----------------------------------------------------------

    #[test]
    fn header_roundtrip() {
        let mut p = Pkt::response(1, 2);
        p.question("example.com");
        let b = p.bytes();
        let h = parse_header(&DnsCursor::new(&b)).unwrap();
        assert_eq!(h.id, 0x1234);
        assert!(h.is_response());
        assert!(!h.is_truncated());
        assert_eq!(h.rcode(), 0);
        assert_eq!(h.qdcount, 1);
        assert_eq!(h.ancount, 2);
    }

    #[test]
    fn header_needs_twelve_bytes() {
        assert!(parse_header(&DnsCursor::new(&[0u8; 11])).is_none());
        assert!(parse_header(&DnsCursor::new(&[0u8; 12])).is_some());
        assert!(parse_header(&DnsCursor::new(&[])).is_none());
    }

    #[test]
    fn queries_and_errors_are_ignored() {
        // QR = 0 (a query, not a response)
        let mut q = Pkt::header(0x0100, 1, 1);
        q.question("example.com");
        q.a_record("example.com", 60, [1, 2, 3, 4]);
        assert!(collect(&q.bytes()).is_empty());

        // NXDOMAIN
        let mut nx = Pkt::header(0x8183, 1, 1);
        nx.question("nope.example");
        nx.a_record("nope.example", 60, [1, 2, 3, 4]);
        assert!(collect(&nx.bytes()).is_empty());
    }

    // ---- names -----------------------------------------------------------

    #[test]
    fn read_name_basic() {
        let mut p = Pkt(Vec::new());
        p.name("www.example.com");
        let b = p.bytes();
        let mut out = [0u8; MAX_NAME_LEN];
        let (len, next) = read_name(&DnsCursor::new(&b), 0, &mut out).unwrap();
        assert_eq!(&out[..len as usize], b"www.example.com");
        assert_eq!(next, b.len());
        assert_eq!(out[len as usize], 0, "tail must be zeroed");
    }

    #[test]
    fn read_name_nul_terminates_over_stale_bytes() {
        let mut p = Pkt(Vec::new());
        p.name("a.b");
        let b = p.bytes();
        let mut out = [0xaau8; MAX_NAME_LEN];
        let (len, _) = read_name(&DnsCursor::new(&b), 0, &mut out).unwrap();
        assert_eq!(len as usize, 3);
        assert_eq!(out[3], 0, "must NUL-terminate");
        // Everything past the NUL is stale on purpose (see `read_name`), but it
        // must be unreachable through the public accessors.
        let mut answer = DnsAnswer::zeroed();
        answer.name = out;
        answer.name_len = len;
        assert_eq!(answer.name_bytes(), b"a.b");
    }

    #[test]
    fn stale_tail_is_never_visible_through_name_bytes() {
        // Parse a long name, then a short one into the same scratch, exactly
        // like the per-CPU scratch buffer does across packets.
        let mut long = Pkt(Vec::new());
        long.name("averyveryverylongname.example.invalid");
        let mut short = Pkt(Vec::new());
        short.name("a.b");

        let mut scratch = DnsAnswer::zeroed();
        let (l1, _) = read_name(&DnsCursor::new(&long.bytes()), 0, &mut scratch.name).unwrap();
        scratch.name_len = l1;
        assert_eq!(
            scratch.name_bytes(),
            b"averyveryverylongname.example.invalid"
        );

        let (l2, _) = read_name(&DnsCursor::new(&short.bytes()), 0, &mut scratch.name).unwrap();
        scratch.name_len = l2;
        assert_eq!(scratch.name_bytes(), b"a.b");
    }

    #[test]
    fn read_name_root_is_empty() {
        let b = [0u8];
        let mut out = [0u8; MAX_NAME_LEN];
        let (len, next) = read_name(&DnsCursor::new(&b), 0, &mut out).unwrap();
        assert_eq!(len, 0);
        assert_eq!(next, 1);
    }

    #[test]
    fn read_name_rejects_missing_terminator() {
        // 3 "abc" and then the buffer just ends.
        let b = [3u8, b'a', b'b', b'c'];
        let mut out = [0u8; MAX_NAME_LEN];
        assert!(read_name(&DnsCursor::new(&b), 0, &mut out).is_none());
    }

    #[test]
    fn read_name_rejects_forward_pointer() {
        // Pointer at offset 0 aiming forward at offset 2.
        let b = [0xc0u8, 0x02, 0x00];
        let mut out = [0u8; MAX_NAME_LEN];
        assert!(read_name(&DnsCursor::new(&b), 0, &mut out).is_none());
    }

    #[test]
    fn read_name_rejects_self_pointer_loop() {
        // Classic compression bomb: pointer at 12 pointing at itself.
        let mut b = vec![0u8; 12];
        b.push(0xc0);
        b.push(12);
        let mut out = [0u8; MAX_NAME_LEN];
        assert!(read_name(&DnsCursor::new(&b), 12, &mut out).is_none());
    }

    #[test]
    fn read_name_rejects_reserved_label_type() {
        let b = [0x80u8, 0x00];
        let mut out = [0u8; MAX_NAME_LEN];
        assert!(read_name(&DnsCursor::new(&b), 0, &mut out).is_none());
    }

    #[test]
    fn read_name_rejects_overlong_name() {
        // 5 labels of 63 bytes = 63*5 + 4 separators = 319 > 253.
        let mut p = Pkt(Vec::new());
        for _ in 0..5 {
            p.u8(63);
            p.0.extend(std::iter::repeat_n(b'x', 63));
        }
        p.u8(0);
        let b = p.bytes();
        let mut out = [0u8; MAX_NAME_LEN];
        assert!(read_name(&DnsCursor::new(&b), 0, &mut out).is_none());
    }

    #[test]
    fn read_name_accepts_max_length_name() {
        // 3 labels of 63 + 1 label of 61 => 63*3 + 61 + 3 dots = 253.
        let mut p = Pkt(Vec::new());
        for _ in 0..3 {
            p.u8(63);
            p.0.extend(std::iter::repeat_n(b'x', 63));
        }
        p.u8(61);
        p.0.extend(std::iter::repeat_n(b'y', 61));
        p.u8(0);
        let b = p.bytes();
        let mut out = [0u8; MAX_NAME_LEN];
        let (len, _) = read_name(&DnsCursor::new(&b), 0, &mut out).unwrap();
        assert_eq!(len as usize, MAX_NAME_LEN);
    }

    #[test]
    fn read_name_follows_backwards_pointer() {
        // "example.com" at offset 0, then "www" + pointer back to 0.
        let mut p = Pkt(Vec::new());
        p.name("example.com");
        let suffix_at = 0u16;
        let start = p.0.len();
        p.u8(3);
        p.0.extend_from_slice(b"www");
        p.ptr(suffix_at);
        let b = p.bytes();

        let mut out = [0u8; MAX_NAME_LEN];
        let (len, next) = read_name(&DnsCursor::new(&b), start, &mut out).unwrap();
        assert_eq!(&out[..len as usize], b"www.example.com");
        // The stream continues right after the 2-byte pointer: 4 bytes for the
        // literal "www" label plus 2 for the pointer.
        assert_eq!(next, start + 6);
        assert_eq!(next, b.len());
    }

    #[test]
    fn read_name_rejects_too_many_jumps() {
        // Chain of 5 backwards pointers, one more than MAX_LABEL_JUMPS.
        // layout: [0]=0 (root) then pointers at 1,3,5,7,9,11 each -> previous.
        let mut b = vec![0u8]; // root label at offset 0
        let mut prev = 0u16;
        for _ in 0..(MAX_LABEL_JUMPS + 1) {
            let here = b.len() as u16;
            b.push(0xc0 | (prev >> 8) as u8);
            b.push((prev & 0xff) as u8);
            prev = here;
        }
        let start = prev as usize;
        let mut out = [0u8; MAX_NAME_LEN];
        assert!(read_name(&DnsCursor::new(&b), start, &mut out).is_none());
    }

    #[test]
    fn skip_name_does_not_follow_pointers() {
        let b = [0xc0u8, 0x00, 0xde, 0xad];
        assert_eq!(skip_name(&DnsCursor::new(&b), 0), Some(2));
    }

    #[test]
    fn skip_questions_walks_all_of_them() {
        let mut p = Pkt::response(2, 0);
        p.question("a.test");
        p.question("bb.test");
        let b = p.bytes();
        assert_eq!(skip_questions(&DnsCursor::new(&b), 2), Some(b.len()));
    }

    #[test]
    fn skip_questions_rejects_absurd_qdcount() {
        let mut p = Pkt::response(9, 0);
        p.question("a.test");
        let b = p.bytes();
        assert!(skip_questions(&DnsCursor::new(&b), 9).is_none());
    }

    // ---- answers ---------------------------------------------------------

    #[test]
    fn single_a_record() {
        let mut p = Pkt::response(1, 1);
        p.question("example.com");
        p.a_record("example.com", 300, [93, 184, 216, 34]);
        let got = collect(&p.bytes());
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name_str(), "example.com");
        assert_eq!(
            got[0].ip_addr(),
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))
        );
        assert_eq!(got[0].ttl, 300);
        assert!(!got[0].is_ipv6());
        assert_eq!(&got[0].ip[4..], &[0u8; 12]);
    }

    #[test]
    fn single_aaaa_record() {
        let v6 = Ipv6Addr::new(0x2606, 0x2800, 0x220, 1, 0x248, 0x1893, 0x25c8, 0x1946);
        let mut p = Pkt::response(1, 1);
        p.question("example.com");
        p.aaaa_record("example.com", 60, v6.octets());
        let got = collect(&p.bytes());
        assert_eq!(got.len(), 1);
        assert!(got[0].is_ipv6());
        assert_eq!(got[0].ip_addr(), IpAddr::V6(v6));
        assert_eq!(got[0].ttl, 60);
    }

    #[test]
    fn compressed_answer_name_resolves_to_the_question() {
        // The realistic wire form: the answer's owner name is a pointer to the
        // question name at offset 12.
        let mut p = Pkt::response(1, 1);
        p.question("www.example.com");
        p.a_record_ptr(DNS_HEADER_LEN as u16, 42, [10, 0, 0, 7]);
        let got = collect(&p.bytes());
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name_str(), "www.example.com");
        assert_eq!(got[0].ttl, 42);
        assert_eq!(got[0].ip_addr(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)));
    }

    #[test]
    fn cname_is_skipped_but_following_a_is_kept() {
        let mut p = Pkt::response(1, 2);
        p.question("alias.example");
        p.cname_record("alias.example", 30, "real.example");
        p.a_record("real.example", 31, [1, 1, 1, 1]);
        let got = collect(&p.bytes());
        assert_eq!(got.len(), 1, "only the A record is reported");
        assert_eq!(got[0].name_str(), "real.example");
        assert_eq!(got[0].ttl, 31);
    }

    #[test]
    fn mixed_a_and_aaaa() {
        let v6 = Ipv6Addr::LOCALHOST;
        let mut p = Pkt::response(1, 3);
        p.question("dual.example");
        p.a_record("dual.example", 10, [192, 0, 2, 1]);
        p.aaaa_record("dual.example", 11, v6.octets());
        p.a_record("dual.example", 12, [192, 0, 2, 2]);
        let got = collect(&p.bytes());
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].ip_addr(), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(got[1].ip_addr(), IpAddr::V6(v6));
        assert_eq!(got[2].ip_addr(), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)));
    }

    #[test]
    fn answer_cap_is_enforced_at_eight() {
        let mut p = Pkt::response(1, 9);
        p.question("many.example");
        for i in 0..9u8 {
            p.a_record("many.example", 100 + i as u32, [10, 0, 0, i]);
        }
        let got = collect(&p.bytes());
        assert_eq!(got.len(), MAX_ANSWERS, "must stop at MAX_ANSWERS");
        assert_eq!(got[7].ttl, 107);
        // and the 9th (10.0.0.8) never appears
        assert!(got.iter().all(|a| a.ip[3] != 8));
    }

    #[test]
    fn ancount_larger_than_reality_stops_cleanly() {
        // Claims 4 answers, carries 1, then the buffer ends.
        let mut p = Pkt::response(1, 4);
        p.question("short.example");
        p.a_record("short.example", 5, [8, 8, 8, 8]);
        let got = collect(&p.bytes());
        assert_eq!(got.len(), 1);
    }

    #[test]
    fn truncated_packets_never_panic() {
        let mut p = Pkt::response(1, 2);
        p.question("cut.example");
        p.a_record("cut.example", 5, [8, 8, 8, 8]);
        p.aaaa_record("cut.example", 5, Ipv6Addr::LOCALHOST.octets());
        let full = p.bytes();
        // Every prefix must either parse a subset or return nothing.
        for n in 0..full.len() {
            let got = collect(&full[..n]);
            assert!(got.len() <= 2, "prefix {n} produced {} answers", got.len());
        }
    }

    #[test]
    fn rdlength_running_past_the_buffer_is_rejected() {
        let mut p = Pkt::response(1, 1);
        p.question("liar.example");
        p.name("liar.example");
        p.u16(TYPE_A);
        p.u16(CLASS_IN);
        p.u32(60);
        p.u16(4000); // claims 4000 bytes of RDATA
        p.0.extend_from_slice(&[1, 2, 3, 4]);
        assert!(collect(&p.bytes()).is_empty());
    }

    #[test]
    fn wrong_rdlength_for_type_is_not_reported() {
        let mut p = Pkt::response(1, 1);
        p.question("bad.example");
        p.name("bad.example");
        p.u16(TYPE_A);
        p.u16(CLASS_IN);
        p.u32(60);
        p.u16(16); // A record with 16 bytes of RDATA
        p.0.extend_from_slice(&[0u8; 16]);
        assert!(collect(&p.bytes()).is_empty());
    }

    #[test]
    fn non_in_class_is_skipped() {
        let mut p = Pkt::response(1, 1);
        p.question("ch.example");
        p.name("ch.example");
        p.u16(TYPE_A);
        p.u16(3); // CLASS CH
        p.u32(60);
        p.u16(4);
        p.0.extend_from_slice(&[1, 2, 3, 4]);
        assert!(collect(&p.bytes()).is_empty());
    }

    #[test]
    fn works_at_a_non_zero_base_like_the_bpf_scratch_buffer() {
        // 20-byte IPv4 header + 8-byte UDP header = base 28.
        let mut p = Pkt::response(1, 1);
        p.question("www.example.com");
        p.a_record_ptr(DNS_HEADER_LEN as u16, 77, [203, 0, 113, 5]);
        let got = collect_in_scratch(&p.bytes(), 28);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name_str(), "www.example.com");
        assert_eq!(got[0].ttl, 77);
        assert_eq!(got[0].ip_addr(), IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)));
    }

    #[test]
    fn oversized_response_is_parsed_up_to_the_scratch_bound() {
        // 30 answers: only the first 8 are looked at anyway, and everything
        // past DNS_BUF_LEN is simply invisible.
        let mut p = Pkt::response(1, 30);
        p.question("big.example");
        for i in 0..30u8 {
            p.a_record("big.example", 1, [10, 1, 0, i]);
        }
        assert!(p.bytes().len() > DNS_BUF_LEN);
        let got = collect_in_scratch(&p.bytes(), 0);
        assert_eq!(got.len(), MAX_ANSWERS);
    }

    #[test]
    fn empty_and_garbage_inputs_are_safe() {
        assert!(collect(&[]).is_empty());
        assert!(collect(&[0u8; 512]).is_empty());
        assert!(collect(&[0xffu8; 512]).is_empty());
        let mut prng = 0x2545_f491_4f6c_dd1du64;
        for _ in 0..2000 {
            let mut buf = [0u8; 96];
            for b in buf.iter_mut() {
                prng ^= prng << 13;
                prng ^= prng >> 7;
                prng ^= prng << 17;
                *b = prng as u8;
            }
            // Force it to look like a NOERROR response so the parser actually
            // walks into the record loop.
            buf[2] = 0x81;
            buf[3] = 0x80;
            let _ = collect(&buf);
        }
    }

    #[test]
    fn cursor_clamps_len_to_the_buffer() {
        let buf = [0u8; 16];
        let c = DnsCursor::with_base(&buf, 8, 999);
        assert_eq!(c.len(), 8);
        assert!(!c.is_empty());
        let c = DnsCursor::with_base(&buf, 99, 10);
        assert_eq!(c.len(), 0);
        assert!(c.is_empty());
    }
}
