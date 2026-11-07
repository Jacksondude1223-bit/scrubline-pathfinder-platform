//! The reflection guard: answers reflected at a protected address. An attacker sends small
//! requests to servers on the internet with the address forged as their source, and the servers
//! send their much larger answers there. The answers come from real servers, at real addresses,
//! so no rule on sources stops them; what gives them away is that nobody at the address asked.
//!
//! Each vector is a UDP service that answers a small request with a large one, told by the port
//! its answers come from and by what they open with: CLDAP, DNS, NTP, memcached, SSDP, SNMP,
//! chargen and echo (which Fraggle aims at), QOTD, portmapper, NetBIOS, MS-SQL's resolution
//! service, WS-Discovery, CoAP, mDNS, Ubiquiti's discovery and RIPv1. Nobody behind a game server
//! asks most of them anything, so an answer it did not ask for is dropped whatever the volume.
//! DNS and NTP the server uses itself, to look up names and set its clock, so an answer of theirs
//! it did not ask for is dropped only while the prefix is flooded with them: telling which it
//! asked for takes seeing its own traffic, which an asymmetric path or a flow record's delay can
//! hide.
//!
//! Long answers arrive in fragments, and only the first fragment carries the port, so a source
//! caught reflecting has its later fragments dropped too.
use crate::{
    guards::{Engagement, Key},
    model::{Flow, ReflectionPolicy},
    tuning::{self, Custom, Mode},
};
use serde_json::{json, Value};
use std::{collections::HashMap, net::IpAddr};

/// The port CLDAP answers come from.
pub const CLDAP_PORT: i64 = 389;
/// How many sources caught reflecting a node remembers at once.
pub const SOURCES_MAX: usize = 65536;
/// How long after its last answer a source caught reflecting has the later fragments of its
/// answers dropped: as long as a host holds fragments for reassembly.
pub const REFLECTING_FOR: i64 = 30_000;
/// How recently the origin must have sent an address a query of a vector for an answer of that
/// vector from it to count as one it asked for.
pub const ASKED_WITHIN: i64 = 30_000;
/// How many packets a second of answers it did not ask for a prefix takes, of a vector the server
/// asks itself, before they are dropped, when the policy names no other number.
pub const ENGAGE_PPS: u64 = 1000;
/// How long a prefix stays flooded after the last second its answers were over the threshold.
pub const FLOOD_HOLD: i64 = 60_000;

/// How an answer is judged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Nobody behind a game server asks the service anything: an answer the server did not ask
    /// for is dropped whatever the volume.
    Never,
    /// The server asks the service itself: an answer it did not ask for is dropped only while the
    /// prefix is flooded with them.
    Flood,
}

/// A UDP service attackers reflect off.
pub struct Vector {
    pub name: &'static str,
    /// The port its answers come from.
    pub port: u16,
    /// What its answers are called in a drop's reason.
    pub label: &'static str,
    /// Whether a payload from the port is one of its answers: how it is judged, and what it is.
    answer: fn(&[u8]) -> Option<(Kind, &'static str)>,
    /// Whether a payload the server sends to the port asks for an answer. A service that answers
    /// anything at all has no question to tell from a game server's answer to a forged one, so
    /// nothing the server sends asks it.
    query: fn(&[u8]) -> bool,
    /// How a record without its payload is judged, by its port alone: a well-known port, which no
    /// player's NAT maps to, as an answer is; a high one, which a player's NAT may well map to,
    /// only while the prefix is flooded.
    pub bare: Kind,
}

fn be16(p: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([p[at], p[at + 1]])
}
fn be32(p: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([p[at], p[at + 1], p[at + 2], p[at + 3]])
}
fn starts_with_ignore_case(p: &[u8], prefix: &[u8]) -> bool {
    p.len() >= prefix.len() && p[..prefix.len()].eq_ignore_ascii_case(prefix)
}
fn contains(p: &[u8], needle: &[u8]) -> bool {
    p.windows(needle.len()).any(|w| w == needle)
}
/// Text a person could read: what chargen and QOTD answer with.
fn printable(p: &[u8]) -> bool {
    !p.is_empty()
        && p.iter()
            .all(|c| (0x20..=0x7e).contains(c) || matches!(c, b'\r' | b'\n' | b'\t'))
}
fn never(_: &[u8]) -> bool {
    false
}

/// The operation an LDAP message opens with: after a SEQUENCE and its length, an INTEGER message
/// ID of one to four bytes, the tag of its protocolOp. The first fragment of a long message still
/// opens as one, though its length runs past the fragment.
fn ldap_operation(p: &[u8]) -> Option<u8> {
    if p.first() != Some(&0x30) {
        return None;
    }
    let mut i = 2;
    match p.get(1) {
        Some(&l) if l & 0x80 == 0 => {}
        // The long form gives the length in one to four bytes after it.
        Some(&l) if (1..=4).contains(&(l & 0x7f)) => i += usize::from(l & 0x7f),
        _ => return None,
    }
    if p.get(i) != Some(&0x02) {
        return None;
    }
    match p.get(i + 1) {
        Some(&n) if (1..=4).contains(&n) => i += 2 + usize::from(n),
        _ => return None,
    }
    p.get(i).copied()
}
/// Whether a payload opens as an LDAP answer to a search: an entry, a reference or the done that
/// ends them ([APPLICATION 4], [APPLICATION 19] and [APPLICATION 5]).
pub fn ldap_answer(p: &[u8]) -> bool {
    matches!(ldap_operation(p), Some(0x64 | 0x65 | 0x73))
}
/// Whether a payload opens as an LDAP search ([APPLICATION 3]), as a CLDAP query does.
pub fn ldap_search(p: &[u8]) -> bool {
    ldap_operation(p) == Some(0x63)
}
fn cldap_answer(p: &[u8]) -> Option<(Kind, &'static str)> {
    ldap_answer(p).then_some((Kind::Never, "an LDAP answer from port 389"))
}
/// A DNS header, as far as telling a standard query from its answer: twelve bytes, QR in the top
/// bit of the third and the opcode in the four under it. Whether it answers, and how many
/// questions and answers it counts.
fn dns(p: &[u8]) -> Option<(bool, u16, u16)> {
    if p.len() < 12 || (p[2] >> 3) & 0x0f != 0 {
        return None;
    }
    Some((p[2] & 0x80 != 0, be16(p, 4), be16(p, 6)))
}
fn dns_answer(p: &[u8]) -> Option<(Kind, &'static str)> {
    matches!(dns(p), Some((true, 0..=1, _))).then_some((Kind::Flood, "a DNS answer from port 53"))
}
fn dns_query(p: &[u8]) -> bool {
    matches!(dns(p), Some((false, 1, 0)))
}
fn mdns_answer(p: &[u8]) -> Option<(Kind, &'static str)> {
    matches!(dns(p), Some((true, ..)))
        .then_some((Kind::Never, "a multicast DNS answer from port 5353"))
}
fn mdns_query(p: &[u8]) -> bool {
    matches!(dns(p), Some((false, 1.., _)))
}
/// An NTP packet's version, from the three bits above its mode, which every mode keeps there.
fn ntp_version(b: u8) -> bool {
    (1..=4).contains(&((b >> 3) & 7))
}
/// Mode 7 (private) puts its response bit at the top of the first byte, mode 6 (control) at the
/// top of the second. Implementations answer a monlist (MON_GETLIST_1) query of 8 bytes with up
/// to 600 entries, the amplification attacks on NTP are built on.
fn ntp_answer(p: &[u8]) -> Option<(Kind, &'static str)> {
    let b = *p.first()?;
    if !ntp_version(b) {
        return None;
    }
    match b & 7 {
        7 if b & 0x80 != 0 && p.len() >= 8 => Some((
            Kind::Never,
            "a monlist or other private (mode 7) NTP answer from port 123",
        )),
        6 if p.len() >= 12 && p[1] & 0x80 != 0 => {
            Some((Kind::Never, "an NTP control (mode 6) answer from port 123"))
        }
        4 | 5 if p.len() >= 48 => Some((Kind::Flood, "an NTP time answer from port 123")),
        _ => None,
    }
}
fn ntp_query(p: &[u8]) -> bool {
    let Some(&b) = p.first() else {
        return false;
    };
    ntp_version(b)
        && match b & 7 {
            3 => p.len() >= 48,
            6 => p.len() >= 12 && p[1] & 0x80 == 0,
            7 => p.len() >= 8 && b & 0x80 == 0,
            _ => false,
        }
}
/// The frame memcached puts before every UDP datagram: a request ID, the datagram's sequence
/// number and how many datagrams the answer takes, and two reserved bytes of zero.
fn memcached_frame(p: &[u8]) -> Option<u16> {
    if p.len() <= 8 || p[6] != 0 || p[7] != 0 {
        return None;
    }
    let (seq, total) = (be16(p, 2), be16(p, 4));
    (total >= 1 && seq < total).then_some(seq)
}
/// An answer's first datagram opens with a reply; the rest carry on with what it holds.
fn memcached_answer(p: &[u8]) -> Option<(Kind, &'static str)> {
    let seq = memcached_frame(p)?;
    let replies: [&[u8]; 9] = [
        b"VALUE ",
        b"STAT ",
        b"END\r\n",
        b"ERROR",
        b"VERSION ",
        b"CLIENT_ERROR",
        b"SERVER_ERROR",
        b"STORED",
        b"NOT_FOUND",
    ];
    (seq > 0 || replies.iter().any(|r| p[8..].starts_with(r)))
        .then_some((Kind::Never, "a memcached answer from UDP port 11211"))
}
fn memcached_query(p: &[u8]) -> bool {
    let commands: [&[u8]; 5] = [b"get ", b"gets ", b"gat ", b"stats", b"version"];
    memcached_frame(p).is_some() && commands.iter().any(|c| p[8..].starts_with(c))
}
fn ssdp_answer(p: &[u8]) -> Option<(Kind, &'static str)> {
    [&b"HTTP/1.1 200"[..], b"HTTP/1.0 200", b"NOTIFY * HTTP/1.1"]
        .iter()
        .any(|s| starts_with_ignore_case(p, s))
        .then_some((Kind::Never, "an SSDP discovery answer from port 1900"))
}
fn ssdp_query(p: &[u8]) -> bool {
    starts_with_ignore_case(p, b"M-SEARCH * HTTP/1.1")
}
/// A BER length at `at`: its value, and where what it measures starts.
fn ber_length(p: &[u8], at: usize) -> Option<(usize, usize)> {
    let l = *p.get(at)?;
    if l & 0x80 == 0 {
        return Some((usize::from(l), at + 1));
    }
    let n = usize::from(l & 0x7f);
    if !(1..=4).contains(&n) {
        return None;
    }
    let bytes = p.get(at + 1..at + 1 + n)?;
    Some((
        bytes.iter().fold(0, |v, b| v << 8 | usize::from(*b)),
        at + 1 + n,
    ))
}
/// The PDU an SNMPv1 or v2c message carries, after its SEQUENCE, version and community.
fn snmp_pdu(p: &[u8]) -> Option<u8> {
    if p.first() != Some(&0x30) {
        return None;
    }
    let (_, at) = ber_length(p, 1)?;
    if !matches!(p.get(at..at + 4)?, [0x02, 0x01, 0 | 1, 0x04]) {
        return None;
    }
    let (n, at) = ber_length(p, at + 4)?;
    p.get(at.checked_add(n)?).copied()
}
fn snmp_answer(p: &[u8]) -> Option<(Kind, &'static str)> {
    (snmp_pdu(p) == Some(0xa2)).then_some((Kind::Never, "an SNMP GetResponse from port 161"))
}
fn snmp_query(p: &[u8]) -> bool {
    matches!(snmp_pdu(p), Some(0xa0 | 0xa1 | 0xa5))
}
fn chargen_answer(p: &[u8]) -> Option<(Kind, &'static str)> {
    printable(p).then_some((Kind::Never, "characters from chargen's port 19"))
}
fn echo_answer(_: &[u8]) -> Option<(Kind, &'static str)> {
    Some((Kind::Never, "an echo from UDP port 7"))
}
fn qotd_answer(p: &[u8]) -> Option<(Kind, &'static str)> {
    printable(p).then_some((Kind::Never, "a quote from port 17"))
}
/// An ONC RPC message: its transaction ID, then 0 for a call or 1 for a reply.
fn portmap_answer(p: &[u8]) -> Option<(Kind, &'static str)> {
    (p.len() >= 24 && be32(p, 4) == 1).then_some((Kind::Never, "a portmapper reply from port 111"))
}
/// A call to the portmapper itself: RPC version 2, program 100000.
fn portmap_query(p: &[u8]) -> bool {
    p.len() >= 40 && be32(p, 4) == 0 && be32(p, 8) == 2 && be32(p, 12) == 100_000
}
/// A NetBIOS name service header, laid out as DNS's is.
fn netbios_answer(p: &[u8]) -> Option<(Kind, &'static str)> {
    (p.len() >= 12 && p[2] & 0x80 != 0 && (p[2] >> 3) & 0x0f == 0)
        .then_some((Kind::Never, "a NetBIOS name service answer from port 137"))
}
fn netbios_query(p: &[u8]) -> bool {
    p.len() >= 12 && p[2] & 0x80 == 0 && (p[2] >> 3) & 0x0f == 0 && be16(p, 4) == 1
}
/// The SQL Server Resolution Protocol's answer: 0x05, its length, and the instances it lists.
fn mssql_answer(p: &[u8]) -> Option<(Kind, &'static str)> {
    (p.len() > 3
        && p[0] == 0x05
        && usize::from(u16::from_le_bytes([p[1], p[2]])) + 3 >= p.len()
        && starts_with_ignore_case(&p[3..], b"ServerName"))
    .then_some((Kind::Never, "an MS-SQL resolution answer from port 1434"))
}
fn mssql_query(p: &[u8]) -> bool {
    matches!(p, [0x02] | [0x03] | [0x04, ..])
}
/// A SOAP envelope, as WS-Discovery sends.
fn soap(p: &[u8]) -> bool {
    let p = p.strip_prefix(b"\xef\xbb\xbf").unwrap_or(p);
    let p = &p[p.iter().take_while(|c| c.is_ascii_whitespace()).count()..];
    p.first() == Some(&b'<') && contains(&p[..p.len().min(512)], b"Envelope")
}
/// A WS-Discovery request: a Probe or a Resolve, which devices answer with their matches or,
/// for a malformed one, with a fault.
fn wsd_request(p: &[u8]) -> bool {
    contains(p, b"Probe") && !contains(p, b"ProbeMatch")
        || contains(p, b"Resolve") && !contains(p, b"ResolveMatch")
}
fn wsd_answer(p: &[u8]) -> Option<(Kind, &'static str)> {
    (soap(p) && !wsd_request(p)).then_some((Kind::Never, "a WS-Discovery answer from port 3702"))
}
fn wsd_query(p: &[u8]) -> bool {
    soap(p) && wsd_request(p)
}
/// A CoAP header: version 1, a token of at most eight bytes, and the code, whose top three bits
/// are its class.
fn coap(p: &[u8]) -> Option<u8> {
    let b = *p.first()?;
    (p.len() >= 4 && b >> 6 == 1 && b & 0x0f <= 8).then(|| p[1])
}
fn coap_answer(p: &[u8]) -> Option<(Kind, &'static str)> {
    matches!(coap(p).map(|c| c >> 5), Some(2 | 4 | 5))
        .then_some((Kind::Never, "a CoAP response from port 5683"))
}
fn coap_query(p: &[u8]) -> bool {
    matches!(coap(p), Some(c) if c >> 5 == 0 && c != 0)
}
/// Ubiquiti's discovery answer: version 1, command 0, and the length of what follows.
fn ubiquiti_answer(p: &[u8]) -> Option<(Kind, &'static str)> {
    (p.len() > 4 && p[0] == 1 && p[1] == 0 && usize::from(be16(p, 2)) + 4 >= p.len())
        .then_some((Kind::Never, "a Ubiquiti discovery answer from port 10001"))
}
fn ubiquiti_query(p: &[u8]) -> bool {
    p == [1, 0, 0, 0]
}
/// A RIP message: command 1 asks, 2 answers, in version 1 or 2, with two bytes of zero after.
fn rip_answer(p: &[u8]) -> Option<(Kind, &'static str)> {
    (p.len() >= 4 && p[0] == 2 && matches!(p[1], 1 | 2) && p[2] == 0 && p[3] == 0)
        .then_some((Kind::Never, "a RIP response from port 520"))
}
fn rip_query(p: &[u8]) -> bool {
    p.len() >= 4 && p[0] == 1 && matches!(p[1], 1 | 2)
}

/// How many vectors the guard knows, how many of an operator's own a policy may add, and so how
/// many any table of vectors holds.
pub const VECTORS_LEN: usize = 17;
pub const CUSTOM_MAX: usize = 8;
pub const VECTORS_MAX: usize = VECTORS_LEN + CUSTOM_MAX;
/// Every vector, CLDAP first.
pub const VECTORS: [Vector; VECTORS_LEN] = [
    Vector {
        name: "cldap",
        port: 389,
        label: "CLDAP",
        answer: cldap_answer,
        query: ldap_search,
        bare: Kind::Never,
    },
    Vector {
        name: "dns",
        port: 53,
        label: "DNS",
        answer: dns_answer,
        query: dns_query,
        bare: Kind::Flood,
    },
    Vector {
        name: "ntp",
        port: 123,
        label: "NTP",
        answer: ntp_answer,
        query: ntp_query,
        bare: Kind::Flood,
    },
    Vector {
        name: "memcached",
        port: 11211,
        label: "memcached",
        answer: memcached_answer,
        query: memcached_query,
        bare: Kind::Flood,
    },
    Vector {
        name: "ssdp",
        port: 1900,
        label: "SSDP",
        answer: ssdp_answer,
        query: ssdp_query,
        bare: Kind::Flood,
    },
    Vector {
        name: "snmp",
        port: 161,
        label: "SNMP",
        answer: snmp_answer,
        query: snmp_query,
        bare: Kind::Never,
    },
    Vector {
        name: "chargen",
        port: 19,
        label: "Fraggle (chargen)",
        answer: chargen_answer,
        query: never,
        bare: Kind::Never,
    },
    Vector {
        name: "echo",
        port: 7,
        label: "Fraggle (echo)",
        answer: echo_answer,
        query: never,
        bare: Kind::Never,
    },
    Vector {
        name: "qotd",
        port: 17,
        label: "QOTD",
        answer: qotd_answer,
        query: never,
        bare: Kind::Never,
    },
    Vector {
        name: "portmap",
        port: 111,
        label: "Portmapper",
        answer: portmap_answer,
        query: portmap_query,
        bare: Kind::Never,
    },
    Vector {
        name: "netbios",
        port: 137,
        label: "NetBIOS",
        answer: netbios_answer,
        query: netbios_query,
        bare: Kind::Never,
    },
    Vector {
        name: "mssql",
        port: 1434,
        label: "MS-SQL",
        answer: mssql_answer,
        query: mssql_query,
        bare: Kind::Flood,
    },
    Vector {
        name: "wsd",
        port: 3702,
        label: "WS-Discovery",
        answer: wsd_answer,
        query: wsd_query,
        bare: Kind::Flood,
    },
    Vector {
        name: "coap",
        port: 5683,
        label: "CoAP",
        answer: coap_answer,
        query: coap_query,
        bare: Kind::Flood,
    },
    Vector {
        name: "mdns",
        port: 5353,
        label: "mDNS",
        answer: mdns_answer,
        query: mdns_query,
        bare: Kind::Flood,
    },
    Vector {
        name: "ubiquiti",
        port: 10001,
        label: "Ubiquiti discovery",
        answer: ubiquiti_answer,
        query: ubiquiti_query,
        bare: Kind::Flood,
    },
    Vector {
        name: "rip",
        port: 520,
        label: "RIPv1",
        answer: rip_answer,
        query: rip_query,
        bare: Kind::Never,
    },
];
/// Where a vector is in VECTORS, by its name.
pub fn vector(name: &str) -> Option<usize> {
    VECTORS.iter().position(|v| v.name == name)
}
/// The bit that stands for a vector among what the origin has asked an address.
pub fn bit(i: usize) -> u32 {
    1 << i
}
/// The vector a flow the origin sends asks for an answer of, if it asks for one: a query to its
/// port, with a payload that is one.
pub fn queried(f: &Flow) -> Option<usize> {
    if !f.proto.eq_ignore_ascii_case("udp") || f.payload.is_empty() {
        return None;
    }
    let i = VECTORS.iter().position(|v| i64::from(v.port) == f.dport)?;
    (VECTORS[i].query)(&f.payload).then_some(i)
}
/// A vector's mode under a policy: its own, CLDAP's from where policies before the other vectors
/// set it, or the policy's for every vector; enforce when none is set.
pub fn mode_of(policy: Option<&ReflectionPolicy>, name: &str) -> &'static str {
    let set = policy.and_then(|p| {
        p.vectors
            .get(name)
            .map(String::as_str)
            .filter(|m| !m.is_empty())
            .or_else(|| (name == "cldap" && !p.cldap.is_empty()).then_some(p.cldap.as_str()))
            .or_else(|| (!p.mode.is_empty()).then_some(p.mode.as_str()))
    });
    match set {
        Some("observe") => "observe",
        Some("off") => "off",
        _ => "enforce",
    }
}

/// What the guard knows and has done.
pub struct Guard {
    /// Per vector, the guard's own then the operator's: answers dropped, answers observed,
    /// answers let through because the origin had asked, and later fragments dropped.
    pub counts: [[u64; 4]; VECTORS_MAX],
    /// The sources caught reflecting, when each last was, and the vector it was caught at.
    sources: HashMap<IpAddr, (i64, u8)>,
    /// Sources not remembered because the table was full of ones still reflecting.
    pub untracked: u64,
    last_sweep: i64,
    /// Which aggregates are flooded with answers they did not ask for, per vector judged in
    /// floods.
    floods: Engagement<(Key, usize)>,
}
impl Default for Guard {
    fn default() -> Self {
        Self {
            counts: [[0; 4]; VECTORS_MAX],
            sources: HashMap::new(),
            untracked: 0,
            last_sweep: 0,
            floods: Engagement::default(),
        }
    }
}
/// What a flow is to the guard.
#[derive(Debug, PartialEq)]
pub enum Seen {
    /// Nothing it looks for.
    Not,
    /// An answer of the vector at this index: UDP from its port that opens as one of its answers
    /// when its payload is there to read. How it is judged, and what it is, which a record
    /// without its payload, and an operator's vector, cannot say.
    Answer(usize, Kind, Option<&'static str>),
    /// A fragment after the first, from a source caught reflecting the vector at this index.
    Fragment(usize),
}
/// A vector's name, what its answers are called, and its port: one of the guard's own, or past
/// them one of the operator's.
pub fn about(i: usize, custom: &[Custom]) -> (&str, &str, u16) {
    match VECTORS.get(i) {
        Some(v) => (v.name, v.label, v.port),
        None => {
            let c = &custom[i - VECTORS_LEN];
            (&c.name, &c.name, c.port)
        }
    }
}
impl Guard {
    /// Forgets the aggregates no longer in the program.
    pub fn load(&mut self, live: &dyn Fn(&str) -> bool) {
        self.floods.retain(|(aggregate, _)| live(aggregate));
    }
    /// What the flow is, by its port and payload, or for a fragment after the first, which
    /// carries neither, by its source. `later_fragment` is asked only for a flow that could be
    /// one, since telling takes reading the packet.
    pub fn seen(
        &self,
        f: &Flow,
        now: i64,
        s: &tuning::Reflection,
        custom: &[Custom],
        reflecting_for: i64,
        later_fragment: impl FnOnce() -> bool,
    ) -> Seen {
        if !f.proto.eq_ignore_ascii_case("udp") {
            return Seen::Not;
        }
        let mode = |i: usize| s.modes.get(i).copied().unwrap_or_default();
        if let Some(i) = VECTORS.iter().position(|v| i64::from(v.port) == f.sport) {
            if mode(i) == Mode::Off {
                return Seen::Not;
            }
            let v = &VECTORS[i];
            let kind = |k: Kind| s.kinds.get(i).copied().flatten().unwrap_or(k);
            // A payload that does not open as one of the vector's answers is not one: a player
            // whose NAT happened to map them to its port, say. A record without its payload has
            // only the port to go by.
            if !f.has_payload {
                return Seen::Answer(i, kind(v.bare), None);
            }
            return match (v.answer)(&f.payload) {
                Some((k, what)) => Seen::Answer(i, kind(k), Some(what)),
                None => Seen::Not,
            };
        }
        if let Some(j) = custom.iter().position(|c| i64::from(c.port) == f.sport) {
            let i = VECTORS_LEN + j;
            let c = &custom[j];
            if mode(i) == Mode::Off || f.has_payload && !f.payload.starts_with(&c.prefix) {
                return Seen::Not;
            }
            let kind = s.kinds.get(i).copied().flatten().unwrap_or(c.kind);
            return Seen::Answer(i, kind, None);
        }
        if f.sport == 0 && !f.packet.is_empty() {
            if let Some(i) = self.reflecting(&f.src_ip, now, reflecting_for) {
                if mode(i) != Mode::Off && later_fragment() {
                    return Seen::Fragment(i);
                }
            }
        }
        Seen::Not
    }
    /// The vector a source was caught reflecting within the last `reflecting_for`, if one was.
    fn reflecting(&self, src: &str, now: i64, reflecting_for: i64) -> Option<usize> {
        src.parse::<IpAddr>()
            .ok()
            .and_then(|a| self.sources.get(&a))
            .filter(|&&(t, _)| now - t < reflecting_for)
            .map(|&(_, i)| usize::from(i))
    }
    /// Remembers a source caught reflecting a vector. A full table is swept of sources no longer
    /// reflecting at most once a second, so a flood of new sources costs the node a sweep a
    /// second rather than one each; a source that finds it full of live ones is not remembered.
    pub fn caught(&mut self, src: &str, i: usize, now: i64, reflecting_for: i64) {
        let Ok(addr) = src.parse::<IpAddr>() else {
            return;
        };
        if self.sources.len() >= SOURCES_MAX && !self.sources.contains_key(&addr) {
            if now - self.last_sweep >= 1000 {
                self.last_sweep = now;
                self.sources
                    .retain(|_, &mut (t, _)| now - t < reflecting_for);
            }
            if self.sources.len() >= SOURCES_MAX {
                self.untracked += 1;
                return;
            }
        }
        self.sources.insert(addr, (now, i as u8));
    }
    /// Counts answers of a vector judged in floods that the server did not ask for, and says
    /// whether the aggregate is flooded with them: this second over the threshold, or an earlier
    /// second within the hold.
    pub fn flooded_by(
        &mut self,
        aggregate: &Key,
        i: usize,
        pps: u64,
        s: &tuning::Reflection,
        now: i64,
    ) -> bool {
        self.floods
            .engaged_by(&(aggregate.clone(), i), pps, s.engage_pps, s.hold, now)
    }
    pub fn sources(&self) -> usize {
        self.sources.len()
    }
    pub fn stats(&self, s: &tuning::Reflection, custom: &[Custom], now: i64) -> Value {
        let vectors: Vec<_> = (0..VECTORS_LEN + custom.len())
            .map(|i| {
                let (name, _, port) = about(i, custom);
                let [dropped, observed, asked, fragments] = self.counts[i];
                json!({
                    "vector": name,
                    "port": port,
                    "mode": s.modes.get(i).copied().unwrap_or_default().name(),
                    "dropped": dropped,
                    "observed": observed,
                    "asked": asked,
                    "fragments": fragments,
                    "engaged": self.floods.count(now, |(_, j)| *j == i),
                })
            })
            .collect();
        json!({
            "sources": self.sources.len(),
            "sources_max": SOURCES_MAX,
            "sources_untracked": self.untracked,
            "engage_pps": s.engage_pps,
            "vectors": vectors,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ldap_answers_are_told_from_other_payloads() {
        // Active Directory writes its lengths in four bytes.
        let ad = [
            0x30, 0x84, 0x00, 0x00, 0x0b, 0x9f, 0x02, 0x01, 0x01, 0x64, 0x84, 0x00, 0x00, 0x0b,
        ];
        assert!(ldap_answer(&ad));
        // OpenLDAP the shortest form it can; a done with no entry, as an error is answered.
        assert!(ldap_answer(&[
            0x30, 0x82, 0x01, 0x2c, 0x02, 0x02, 0x12, 0x34, 0x64
        ]));
        assert!(ldap_answer(&[
            0x30, 0x0c, 0x02, 0x01, 0x01, 0x65, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00
        ]));
        assert!(ldap_answer(&[0x30, 0x05, 0x02, 0x01, 0x07, 0x73, 0x00]));
        for not in [
            &[][..],
            &[0x30],
            // A request, not an answer: searchRequest is [APPLICATION 3].
            &[0x30, 0x25, 0x02, 0x01, 0x01, 0x63, 0x20],
            // A bind response.
            &[0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07],
            // Indefinite and over-long lengths, and message IDs of no bytes or five.
            &[0x30, 0x80, 0x02, 0x01, 0x01, 0x64],
            &[0x30, 0x85, 0, 0, 0, 0, 1, 0x02, 0x01, 0x01, 0x64],
            &[0x30, 0x05, 0x02, 0x00, 0x64],
            &[0x30, 0x0a, 0x02, 0x05, 1, 2, 3, 4, 5, 0x64],
            // Cut off before the result.
            &[0x30, 0x84, 0x00, 0x00, 0x0b, 0x9f, 0x02, 0x01, 0x01],
            // A game's packet.
            &[0xff, 0xff, 0xff, 0xff, 0x54, 0x53, 0x6f, 0x75],
        ] {
            assert!(!ldap_answer(not), "{not:02x?}");
        }
    }
    #[test]
    fn ldap_searches_are_told_from_answers_and_other_payloads() {
        // A domain controller locator's LDAP ping: a search of the rootDSE.
        let ping = [
            0x30, 0x84, 0x00, 0x00, 0x00, 0x7c, 0x02, 0x01, 0x01, 0x63, 0x84,
        ];
        assert!(ldap_search(&ping));
        assert!(!ldap_answer(&ping));
        assert!(!ldap_search(&[0x30, 0x0c, 0x02, 0x01, 0x01, 0x65, 0x07]));
        // A game's answer to a query, whatever port it is sent to.
        assert!(!ldap_search(&[0xff, 0xff, 0xff, 0xff, 0x49, 0x11]));
    }
    /// What a vector makes of a payload as an answer, and as a query.
    fn judged(name: &str, p: &[u8]) -> (Option<Kind>, bool) {
        let v = &VECTORS[vector(name).unwrap()];
        ((v.answer)(p).map(|(k, _)| k), (v.query)(p))
    }
    /// A game's packet, as a player whose NAT mapped them to a vector's port sends it.
    const GAME: [u8; 9] = [0xff, 0xff, 0xff, 0xff, 0x54, 0x53, 0x6f, 0x75, 0x72];
    #[test]
    fn every_vector_tells_its_answers_from_its_queries_and_from_a_game() {
        let mut dns_answer = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 9, 0, 0, 0, 1];
        dns_answer.resize(3_000, 0);
        let dns_query = [
            0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1, 3, b'c', b'o', b'm',
        ];
        // A monlist answer, a control answer, a time answer and a client's query.
        let mut monlist = vec![0xd7, 0x00, 0x03, 0x2a, 0x00, 0x06, 0x00, 0x48];
        monlist.resize(440, 0);
        let mut time = vec![0x24, 0x02, 0x00, 0xe7];
        time.resize(48, 0);
        let mut ask_time = vec![0x23, 0, 0, 0];
        ask_time.resize(48, 0);
        let mut memcached = vec![0, 1, 0, 0, 0, 3, 0, 0];
        memcached.extend(b"VALUE a 0 1000000\r\n");
        let mut memcached_more = vec![0, 1, 0, 2, 0, 3, 0, 0];
        memcached_more.extend([b'x'; 1392]);
        let mut memcached_get = vec![0, 1, 0, 0, 0, 1, 0, 0];
        memcached_get.extend(b"get a\r\n");
        let snmp_response = [
            0x30, 0x82, 0x05, 0xdc, 0x02, 0x01, 0x01, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i',
            b'c', 0xa2, 0x82, 0x05, 0xcd,
        ];
        let snmp_bulk = [
            0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa5,
            0x19,
        ];
        let mut portmap_reply = vec![0, 0, 0, 7, 0, 0, 0, 1];
        portmap_reply.resize(28, 0);
        let mut portmap_call = vec![0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1, 0x86, 0xa0];
        portmap_call.resize(40, 0);
        let netbios_answer = [0x12, 0x34, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0, 0x20];
        let netbios_query = [0x12, 0x34, 0x00, 0x10, 0, 1, 0, 0, 0, 0, 0, 0, 0x20];
        let mut mssql = vec![0x05, 0x40, 0x00];
        mssql.extend(b"ServerName;SQL1;InstanceName;MSSQLSERVER;IsClustered;No;");
        let wsd = b"<?xml version=\"1.0\"?><soap:Envelope><soap:Body><d:ProbeMatches/>";
        let wsd_probe = b"<?xml version=\"1.0\"?><soap:Envelope><soap:Body><d:Probe/>";
        let ubiquiti = [1, 0, 0, 3, 2, 0, 0];
        let cases: Vec<(&str, Vec<u8>, Vec<u8>)> = vec![
            ("dns", dns_answer.clone(), dns_query.to_vec()),
            ("mdns", dns_answer.clone(), dns_query.to_vec()),
            ("ntp", monlist.clone(), ask_time),
            ("memcached", memcached, memcached_get),
            (
                "ssdp",
                b"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\n".to_vec(),
                b"M-SEARCH * HTTP/1.1\r\n".to_vec(),
            ),
            ("snmp", snmp_response.to_vec(), snmp_bulk.to_vec()),
            ("portmap", portmap_reply, portmap_call),
            ("netbios", netbios_answer.to_vec(), netbios_query.to_vec()),
            ("mssql", mssql, vec![0x02]),
            ("wsd", wsd.to_vec(), wsd_probe.to_vec()),
            (
                "coap",
                vec![0x60, 0x45, 0x12, 0x34, 0xff, b'x'],
                vec![0x40, 0x01, 0x12, 0x34],
            ),
            ("ubiquiti", ubiquiti.to_vec(), vec![1, 0, 0, 0]),
            ("rip", vec![2, 1, 0, 0, 0, 2], vec![1, 1, 0, 0]),
        ];
        for (name, answer, query) in &cases {
            assert!(judged(name, answer).0.is_some(), "{name} answer");
            assert!(judged(name, query).1, "{name} query");
            assert_eq!(judged(name, query).0, None, "{name}: a query is no answer");
            assert_eq!(
                judged(name, &GAME),
                (None, false),
                "{name}: a game's packet"
            );
        }
        // NTP answers by mode: time is one the server asks for itself.
        assert_eq!(judged("ntp", &time).0, Some(Kind::Flood));
        assert_eq!(judged("ntp", &monlist).0, Some(Kind::Never));
        let mut control = vec![0x16, 0x82, 0, 1];
        control.resize(12, 0);
        assert_eq!(judged("ntp", &control).0, Some(Kind::Never));
        control[1] = 0x02;
        assert!(judged("ntp", &control).1, "a control query");
        assert_eq!(judged("dns", &dns_answer).0, Some(Kind::Flood));
        // Every datagram of a memcached answer after its first carries on with the value.
        assert!(judged("memcached", &memcached_more).0.is_some());
        // Chargen and QOTD answer text; echo answers anything; none takes a question.
        assert!(
            judged("chargen", b"!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGH\r\n")
                .0
                .is_some()
        );
        assert_eq!(judged("chargen", &GAME).0, None);
        assert!(judged("qotd", b"\"A quote.\" - Someone\r\n").0.is_some());
        assert!(judged("echo", &GAME).0.is_some());
        for name in ["chargen", "echo", "qotd"] {
            assert!(!judged(name, b"anything at all").1, "{name}");
        }
    }
    #[test]
    fn a_vector_takes_its_own_mode_then_cldaps_then_the_policys() {
        let p = ReflectionPolicy {
            mode: "observe".into(),
            cldap: "off".into(),
            vectors: [("dns".to_string(), "enforce".to_string())].into(),
            ..Default::default()
        };
        assert_eq!(mode_of(Some(&p), "dns"), "enforce");
        assert_eq!(mode_of(Some(&p), "cldap"), "off");
        assert_eq!(mode_of(Some(&p), "ntp"), "observe");
        assert_eq!(mode_of(None, "ntp"), "enforce");
        assert_eq!(
            mode_of(Some(&ReflectionPolicy::default()), "ssdp"),
            "enforce"
        );
    }
    #[test]
    fn a_full_table_is_swept_once_a_second_and_counts_what_it_cannot_keep() {
        let mut g = Guard::default();
        let addr = |i: usize| format!("10.{}.{}.{}", i >> 16, (i >> 8) & 255, i & 255);
        for i in 0..SOURCES_MAX {
            g.caught(&addr(i), 0, 1, REFLECTING_FOR);
        }
        assert_eq!(g.sources(), SOURCES_MAX);
        // Full of sources still reflecting: the new one is counted, not kept.
        g.caught("192.0.2.1", 3, 2, REFLECTING_FOR);
        assert_eq!((g.sources(), g.untracked), (SOURCES_MAX, 1));
        assert_eq!(g.reflecting(&addr(7), 2, REFLECTING_FOR), Some(0));
        assert_eq!(g.reflecting("192.0.2.1", 2, REFLECTING_FOR), None);
        // Once they have stopped, the sweep makes room, and a source seen again is renewed.
        g.caught("192.0.2.1", 3, 1 + REFLECTING_FOR, REFLECTING_FOR);
        assert_eq!(g.sources(), 1);
        assert_eq!(
            g.reflecting("192.0.2.1", REFLECTING_FOR + 2, REFLECTING_FOR),
            Some(3)
        );
        assert_eq!(
            g.reflecting(&addr(7), REFLECTING_FOR + 2, REFLECTING_FOR),
            None
        );
        g.caught("192.0.2.1", 3, 2 * REFLECTING_FOR, REFLECTING_FOR);
        assert!(g
            .reflecting("192.0.2.1", 3 * REFLECTING_FOR - 1, REFLECTING_FOR)
            .is_some());
        assert!(g
            .reflecting("192.0.2.1", 3 * REFLECTING_FOR, REFLECTING_FOR)
            .is_none());
    }
}
