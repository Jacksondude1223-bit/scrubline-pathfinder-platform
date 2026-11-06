//! What a packet can legitimately be. A datapath that hands the node whole packets has each one
//! read here from its IP header on and held to the rules its own headers state; a flow record
//! without one is held to what its fields can show. Three kinds of packet do their harm without
//! volume, so no rate or threshold would ever catch them:
//!
//! - stack: built to crash or wedge the stack that receives it, as LAND, impossible TCP flags,
//!   Teardrop's overlapping fragments, source routing and SACK Panic's tiny MSS are;
//! - protocol: breaking the rules of the protocol it claims to be, with a header that miscounts
//!   itself, a malformed option, a UDP length that disagrees with its datagram, port 0, or ICMP
//!   that never leaves its own link;
//! - buffer: sized to overrun a buffer or a reassembly table, with a length that claims more than
//!   arrived, a datagram past 65,535 bytes as Ping of Death sends, or fragments too small for any
//!   real link to have made.
//!
//! Every check judges what no legitimate stack sends, so none of them needs tuning.
use crate::model::Flow;
use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

pub const FIN: u16 = 0x01;
pub const SYN: u16 = 0x02;
pub const RST: u16 = 0x04;
pub const PSH: u16 = 0x08;
pub const ACK: u16 = 0x10;
pub const URG: u16 = 0x20;
pub const ECE: u16 = 0x40;
pub const CWR: u16 = 0x80;
pub const NS: u16 = 0x100;
const NAMES: [(&str, u16); 9] = [
    ("fin", FIN),
    ("syn", SYN),
    ("rst", RST),
    ("psh", PSH),
    ("ack", ACK),
    ("urg", URG),
    ("ece", ECE),
    ("cwr", CWR),
    ("ns", NS),
];
/// The flags that say what a segment is. The rest qualify it.
const KIND: u16 = SYN | ACK | FIN | RST;
const TCP: u8 = 6;
const UDP: u8 = 17;
const ICMP: u8 = 1;
const ICMPV6: u8 = 58;
/// What a link may pad a frame with past the end of the IP packet: Ethernet's minimum frame, and
/// a trailer.
const PADDING: usize = 64;
/// The smallest fragment, short of the last, that any real link's MTU produces. Smaller ones are
/// built to be expensive to reassemble.
pub const MIN_FRAGMENT: usize = 256;
/// The largest MSS a SYN may offer and still be refused: SACK Panic (CVE-2019-11477) needs a tiny
/// one, and the published mitigation drops SYNs offering 500 bytes or less.
pub const LOW_MSS: u16 = 500;

/// One rule a crafted packet breaks. The order is the order of the node's counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Check {
    Land,
    TcpFlags,
    MartianSource,
    SourceRoute,
    LowMss,
    FragmentOverlap,
    IpHeader,
    IpOptions,
    ExtensionHeaders,
    TcpHeader,
    UdpHeader,
    Icmp,
    PortZero,
    Fragment,
    Length,
    Oversize,
    TinyFragment,
}
impl Check {
    pub const ALL: [Check; 17] = [
        Check::Land,
        Check::TcpFlags,
        Check::MartianSource,
        Check::SourceRoute,
        Check::LowMss,
        Check::FragmentOverlap,
        Check::IpHeader,
        Check::IpOptions,
        Check::ExtensionHeaders,
        Check::TcpHeader,
        Check::UdpHeader,
        Check::Icmp,
        Check::PortZero,
        Check::Fragment,
        Check::Length,
        Check::Oversize,
        Check::TinyFragment,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Check::Land => "land",
            Check::TcpFlags => "tcp_flags",
            Check::MartianSource => "martian_source",
            Check::SourceRoute => "source_route",
            Check::LowMss => "low_mss",
            Check::FragmentOverlap => "fragment_overlap",
            Check::IpHeader => "ip_header",
            Check::IpOptions => "ip_options",
            Check::ExtensionHeaders => "extension_headers",
            Check::TcpHeader => "tcp_header",
            Check::UdpHeader => "udp_header",
            Check::Icmp => "icmp",
            Check::PortZero => "port_zero",
            Check::Fragment => "fragment",
            Check::Length => "length",
            Check::Oversize => "oversize",
            Check::TinyFragment => "tiny_fragment",
        }
    }
    pub fn class(self) -> &'static str {
        match self {
            Check::Land
            | Check::TcpFlags
            | Check::MartianSource
            | Check::SourceRoute
            | Check::LowMss
            | Check::FragmentOverlap => "stack",
            Check::IpHeader
            | Check::IpOptions
            | Check::ExtensionHeaders
            | Check::TcpHeader
            | Check::UdpHeader
            | Check::Icmp
            | Check::PortZero
            | Check::Fragment => "protocol",
            Check::Length | Check::Oversize | Check::TinyFragment => "buffer",
        }
    }
}
/// A rule a packet breaks, and how it breaks it.
#[derive(Debug, Clone, PartialEq)]
pub struct Anomaly {
    pub check: Check,
    pub why: String,
}
fn anomaly(check: Check, why: impl Into<String>) -> Option<Anomaly> {
    Some(Anomaly {
        check,
        why: why.into(),
    })
}

/// The flags a record or a rule names: flag names separated by ',', '|' or '+', or "none" for a
/// segment with none set. None for anything else, which is compared as text.
pub fn tcp_flags(s: &str) -> Option<u16> {
    if s.is_empty() {
        return None;
    }
    let mut bits = 0;
    let mut none = false;
    for name in s.split([',', '|', '+']) {
        let name = name.trim();
        if name.eq_ignore_ascii_case("none") {
            none = true;
            continue;
        }
        bits |= NAMES.iter().find(|(n, _)| name.eq_ignore_ascii_case(n))?.1;
    }
    (!none || bits == 0).then_some(bits)
}
/// Flags as a record carries them: lowercase names joined by ',', or "none".
pub fn flag_names(bits: u16) -> String {
    let names: Vec<_> = NAMES
        .iter()
        .filter(|(_, b)| bits & b != 0)
        .map(|(n, _)| *n)
        .collect();
    if names.is_empty() {
        "none".into()
    } else {
        names.join(",")
    }
}
/// Whether a segment's flags meet a rule's: the four that say what a segment is (SYN, ACK, FIN and
/// RST) exactly as the rule names them, and any other flag the rule names set. "syn" is a SYN with
/// or without ECN or PSH, so setting a spare bit slips past no rule, and never a SYN-ACK.
pub fn flags_meet(rule: u16, segment: u16) -> bool {
    segment & KIND == rule & KIND && segment & rule & !KIND == rule & !KIND
}
fn listed(names: &[&str]) -> String {
    match names {
        [] => String::new(),
        [one] => (*one).into(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}
/// Why no stack sends a segment with these flags, if none does. Every segment after a SYN carries
/// an ACK but a bare RST, and no segment both opens and closes or resets a connection.
fn impossible(f: u16) -> Option<String> {
    let set = |b: u16| f & b != 0;
    if f & (FIN | SYN | RST | PSH | ACK | URG) == 0 {
        return Some(
            "a TCP segment with none of SYN, ACK, FIN, RST, PSH and URG set, as a NULL scan sends"
                .into(),
        );
    }
    for (a, b, what) in [
        (SYN, FIN, "SYN and FIN"),
        (SYN, RST, "SYN and RST"),
        (FIN, RST, "FIN and RST"),
    ] {
        if set(a) && set(b) {
            return Some(format!("{what} set together, which no stack sends"));
        }
    }
    let bare = f & !(ECE | CWR | NS);
    if !set(SYN) && !set(ACK) && bare != RST {
        if set(FIN) && set(PSH) && set(URG) {
            return Some("FIN, PSH and URG without ACK, as a Christmas tree scan sends".into());
        }
        let names: Vec<_> = NAMES
            .iter()
            .filter(|(_, b)| bare & b != 0)
            .map(|(n, _)| n.to_uppercase())
            .collect();
        let names: Vec<_> = names.iter().map(String::as_str).collect();
        return Some(format!(
            "{} without ACK, which every segment after a SYN carries",
            listed(&names)
        ));
    }
    None
}
/// Why no packet from the internet can come from this address, if none can.
fn martian(a: IpAddr) -> Option<&'static str> {
    match a {
        IpAddr::V4(v) => match v.octets() {
            [0, ..] => Some("a source in 0.0.0.0/8, which never crosses a router"),
            [127, ..] => Some("a loopback source, which never leaves its own host"),
            [169, 254, ..] => Some("a link-local source, which no router forwards"),
            [224..=239, ..] => Some("a multicast source, which no packet can come from"),
            [240..=255, ..] => Some("a source in 240.0.0.0/4, which is reserved or broadcast"),
            _ => None,
        },
        IpAddr::V6(v) => {
            let first = v.segments()[0];
            if v.is_unspecified() {
                Some("the unspecified address as a source")
            } else if v.is_loopback() {
                Some("a loopback source, which never leaves its own host")
            } else if first & 0xff00 == 0xff00 {
                Some("a multicast source, which no packet can come from")
            } else if first & 0xffc0 == 0xfe80 {
                Some("a link-local source, which no router forwards")
            } else if v.to_ipv4_mapped().is_some() {
                Some("an IPv4-mapped source, which never appears on the wire")
            } else {
                None
            }
        }
    }
}
const LAND: &str = "the same address as source and destination, as LAND sends";
/// Why an ICMP message of this type cannot have come from the internet, if it cannot.
fn link_only(kind: u8, v6: bool) -> Option<String> {
    let what = if v6 {
        match kind {
            130..=132 | 143 => "a multicast listener message",
            133..=137 => "a neighbour discovery message",
            141 | 142 | 148 | 149 | 151..=153 => "a link-local ICMPv6 message",
            _ => return None,
        }
    } else {
        match kind {
            5 => "a redirect",
            9 | 10 => "a router advertisement or solicitation",
            4 | 6 | 15..=18 | 30..=39 => {
                return Some(format!(
                    "a deprecated ICMP message (type {kind}), which nothing sends any more"
                ))
            }
            _ => return None,
        }
    };
    Some(format!(
        "{what} (ICMP{} type {kind}), which never leaves its own link",
        if v6 { "v6" } else { "" }
    ))
}

/// A packet as its headers describe it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Packet<'a> {
    pub src: Option<IpAddr>,
    pub dst: Option<IpAddr>,
    pub v6: bool,
    /// The protocol the datagram carries: IPv4's protocol field, or where IPv6's extension headers
    /// end, which for a later fragment is the fragment header's next header.
    pub proto: u8,
    /// The datagram's identification, which tells one datagram's fragments from another's.
    pub id: u32,
    /// Where in its datagram this packet's share starts, in bytes, and whether more follows.
    pub offset: u32,
    pub more: bool,
    /// The bytes of its datagram this packet carries: from the transport header on, or for a
    /// fragment, its share of that.
    pub data: u32,
    /// Whether this packet holds the transport header: a whole datagram, or its first fragment.
    pub transport: bool,
    pub sport: u16,
    pub dport: u16,
    pub flags: Option<u16>,
    /// The receive window a TCP segment advertises, as written: unscaled.
    pub window: Option<u16>,
    pub icmp: Option<(u8, u8)>,
    pub payload: &'a [u8],
}
impl Packet<'_> {
    pub fn fragment(&self) -> bool {
        self.offset > 0 || self.more
    }
}
fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}
/// The ones' complement sum a valid IPv4 header comes to: 0xffff.
fn sum(h: &[u8]) -> u16 {
    let mut s: u32 = h
        .chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])))
        .sum();
    while s > 0xffff {
        s = (s & 0xffff) + (s >> 16);
    }
    s as u16
}
/// Reads a packet from its IP header on, and the first rule it breaks, if it breaks one. What was
/// read before the break is kept, so a flow still has the addresses and ports it got that far.
pub fn parse(b: &[u8]) -> (Packet<'_>, Option<Anomaly>) {
    let mut p = Packet::default();
    let found = match b.first().map(|v| v >> 4) {
        Some(4) => v4(b, &mut p),
        Some(6) => v6(b, &mut p),
        Some(v) => anomaly(
            Check::IpHeader,
            format!("IP version {v}, which is neither 4 nor 6"),
        ),
        None => anomaly(Check::Length, "an empty packet"),
    };
    let found = found.or_else(|| judge(&p));
    (p, found)
}
/// What a well-formed packet can still be built to do: come from nowhere, or from its own
/// destination, or carry flags no stack sends.
fn judge(p: &Packet) -> Option<Anomaly> {
    if let Some(src) = p.src {
        if let Some(why) = martian(src) {
            return anomaly(Check::MartianSource, why);
        }
        if p.dst == Some(src) {
            return anomaly(Check::Land, LAND);
        }
    }
    p.flags
        .and_then(impossible)
        .and_then(|why| anomaly(Check::TcpFlags, why))
}
/// Holds a flow record that carries no packet to what its own fields can show: where it comes
/// from, where it goes (`dst`, as read from it), its TCP flags, and the size of its payload. A
/// field the record leaves out shows nothing.
pub fn record(f: &Flow, dst: Option<IpAddr>) -> Option<Anomaly> {
    if let Ok(src) = f.src_ip.parse::<IpAddr>() {
        if let Some(why) = martian(src) {
            return anomaly(Check::MartianSource, why);
        }
        if dst == Some(src) {
            return anomaly(Check::Land, LAND);
        }
    }
    if f.proto.eq_ignore_ascii_case("tcp") {
        if let Some(why) = tcp_flags(&f.flags).and_then(impossible) {
            return anomaly(Check::TcpFlags, why);
        }
    }
    if f.payload.len() > 65_535 {
        return anomaly(
            Check::Oversize,
            format!(
                "a payload of {} bytes, more than any IP packet can carry",
                f.payload.len()
            ),
        );
    }
    None
}
fn v4<'a>(b: &'a [u8], p: &mut Packet<'a>) -> Option<Anomaly> {
    if b.len() < 20 {
        return anomaly(
            Check::Length,
            format!("{} bytes, too short for an IPv4 header", b.len()),
        );
    }
    p.src = Some(IpAddr::V4(Ipv4Addr::new(b[12], b[13], b[14], b[15])));
    p.dst = Some(IpAddr::V4(Ipv4Addr::new(b[16], b[17], b[18], b[19])));
    p.proto = b[9];
    p.id = u32::from(be16(b, 4));
    let frag = be16(b, 6);
    p.more = frag & 0x2000 != 0;
    p.offset = u32::from(frag & 0x1fff) * 8;
    let ihl = usize::from(b[0] & 0x0f) * 4;
    let total = usize::from(be16(b, 2));
    if ihl < 20 {
        return anomaly(
            Check::IpHeader,
            format!("a header length of {ihl} bytes, under the 20 an IPv4 header takes"),
        );
    }
    if ihl > b.len() {
        return anomaly(
            Check::Length,
            format!("a {ihl}-byte header in a packet of {} bytes", b.len()),
        );
    }
    if total < ihl {
        return anomaly(
            Check::IpHeader,
            format!("a total length of {total} bytes, shorter than its own {ihl}-byte header"),
        );
    }
    if total > b.len() {
        return anomaly(
            Check::Length,
            format!("a total length of {total} bytes in a packet of {}", b.len()),
        );
    }
    if b.len() - total > PADDING {
        return anomaly(
            Check::Length,
            format!(
                "{} bytes past the {total} its header declares, more than any link pads a frame with",
                b.len() - total
            ),
        );
    }
    if frag & 0x8000 != 0 {
        return anomaly(
            Check::IpHeader,
            "the reserved flag bit set, which must be zero",
        );
    }
    if sum(&b[..ihl]) != 0xffff {
        return anomaly(Check::IpHeader, "a header checksum that does not add up");
    }
    if let Some(a) = ip_options(&b[20..ihl]) {
        return Some(a);
    }
    datagram(p, &b[ihl..total], ihl, 0)
}
fn ip_options(o: &[u8]) -> Option<Anomaly> {
    let mut i = 0;
    while i < o.len() {
        let kind = o[i];
        match kind {
            0 => break,
            1 => i += 1,
            _ => {
                let Some(&len) = o.get(i + 1) else {
                    return anomaly(
                        Check::IpOptions,
                        format!("IP option {kind} cut off by the end of the header"),
                    );
                };
                let len = usize::from(len);
                if len < 2 || i + len > o.len() {
                    return anomaly(
                        Check::IpOptions,
                        format!(
                            "IP option {kind} claiming {len} bytes, which the header cannot hold"
                        ),
                    );
                }
                if kind == 131 || kind == 137 {
                    return anomaly(
                        Check::SourceRoute,
                        format!(
                            "a {} source route option, which lets the sender choose the path the packet and its replies take",
                            if kind == 131 { "loose" } else { "strict" }
                        ),
                    );
                }
                i += len;
            }
        }
    }
    None
}
const HOP_BY_HOP: u8 = 0;
const ROUTING: u8 = 43;
const FRAGMENT: u8 = 44;
const AH: u8 = 51;
fn v6<'a>(b: &'a [u8], p: &mut Packet<'a>) -> Option<Anomaly> {
    p.v6 = true;
    if b.len() < 40 {
        return anomaly(
            Check::Length,
            format!("{} bytes, too short for an IPv6 header", b.len()),
        );
    }
    let address = |at: usize| {
        let mut a = [0u8; 16];
        a.copy_from_slice(&b[at..at + 16]);
        IpAddr::V6(Ipv6Addr::from(a))
    };
    p.src = Some(address(8));
    p.dst = Some(address(24));
    let len = usize::from(be16(b, 4));
    if 40 + len > b.len() {
        return anomaly(
            Check::Length,
            format!(
                "a payload length of {len} bytes in a packet of {} bytes",
                b.len()
            ),
        );
    }
    if b.len() - 40 - len > PADDING {
        return anomaly(
            Check::Length,
            format!(
                "{} bytes past the {len} its header declares, more than any link pads a frame with",
                b.len() - 40 - len
            ),
        );
    }
    let body = &b[40..40 + len];
    let mut next = b[6];
    let mut at = 0;
    let mut headers = 0;
    // Where the fragmentable part starts, past the fragment header, in a packet that has one.
    let mut fragmentable = None;
    let cut = |fragmentable: Option<usize>, p: &Packet| {
        if fragmentable.is_some() && p.more {
            anomaly(
                Check::TinyFragment,
                "a first fragment without its whole header chain, which hides the transport header from filters (RFC 7112)",
            )
        } else {
            anomaly(
                Check::Length,
                "an extension header that runs past the end of the packet",
            )
        }
    };
    while matches!(
        next,
        HOP_BY_HOP | ROUTING | FRAGMENT | AH | 60 | 135 | 139 | 140 | 253 | 254
    ) {
        headers += 1;
        if headers > 8 {
            return anomaly(
                Check::ExtensionHeaders,
                "more than eight extension headers, a chain built to push the transport header past what filters read",
            );
        }
        if next == HOP_BY_HOP && headers > 1 {
            return anomaly(
                Check::ExtensionHeaders,
                "a hop-by-hop header after another extension header, where only the first may be one",
            );
        }
        if next == FRAGMENT {
            if fragmentable.is_some() {
                return anomaly(
                    Check::ExtensionHeaders,
                    "two fragment headers in one packet",
                );
            }
            if body.len() < at + 8 {
                return cut(fragmentable, p);
            }
            let h = &body[at..at + 8];
            let field = be16(h, 2);
            p.offset = u32::from(field >> 3) * 8;
            p.more = field & 1 != 0;
            p.id = u32::from_be_bytes([h[4], h[5], h[6], h[7]]);
            next = h[0];
            at += 8;
            fragmentable = Some(at);
            // A later fragment carries none of the datagram's headers past this one.
            if p.offset > 0 {
                break;
            }
            continue;
        }
        if body.len() < at + 2 {
            return cut(fragmentable, p);
        }
        let size = if next == AH {
            (usize::from(body[at + 1]) + 2) * 4
        } else {
            (usize::from(body[at + 1]) + 1) * 8
        };
        if body.len() < at + size {
            return cut(fragmentable, p);
        }
        if next == ROUTING && body[at + 2] == 0 {
            return anomaly(
                Check::SourceRoute,
                "a type 0 routing header, which lets the sender bounce a packet between hosts (RFC 5095)",
            );
        }
        next = body[at];
        at += size;
    }
    p.proto = next;
    match fragmentable {
        // What precedes the fragment header counts towards the reassembled datagram's 65,535.
        Some(f) => datagram(p, &body[f..], f - 8, at - f),
        None => datagram(p, body, 0, at),
    }
}
/// Holds a packet's share of its datagram to the rules fragments keep, then reads the transport
/// header if the share starts the datagram at `l4` bytes in. `head` is what every fragment
/// repeats ahead of its share, which counts towards the datagram's size.
fn datagram<'a>(p: &mut Packet<'a>, data: &'a [u8], head: usize, l4: usize) -> Option<Anomaly> {
    p.data = data.len() as u32;
    if p.fragment() {
        let end = head as u64 + u64::from(p.offset) + data.len() as u64;
        if end > 65_535 {
            return anomaly(
                Check::Oversize,
                format!("a fragment reaching byte {end} of its datagram, past the 65,535 an IP datagram can hold, as Ping of Death sends"),
            );
        }
        if p.more && data.len() % 8 != 0 {
            return anomaly(
                Check::Fragment,
                format!("a fragment of {} bytes before the last, where every fragment but the last is a multiple of 8", data.len()),
            );
        }
        if p.offset == 8 && p.proto == TCP {
            return anomaly(
                Check::FragmentOverlap,
                "a fragment 8 bytes into a TCP datagram, which rewrites the flags of a header filters have already read (RFC 1858)",
            );
        }
        if p.offset > 0 {
            return tiny(p, data);
        }
    }
    // A first fragment too short for its transport header says so before it is called small.
    transport(p, &data[l4..]).or_else(|| tiny(p, data))
}
fn tiny(p: &Packet, data: &[u8]) -> Option<Anomaly> {
    if p.more && data.len() < MIN_FRAGMENT {
        return anomaly(
            Check::TinyFragment,
            format!("a fragment of {} bytes before the last, smaller than any real link makes, as FragmentSmack sends to exhaust reassembly", data.len()),
        );
    }
    None
}
fn transport<'a>(p: &mut Packet<'a>, l4: &'a [u8]) -> Option<Anomaly> {
    let first = p.fragment();
    let short = |what: &str, need: usize| {
        if first {
            anomaly(
                Check::TinyFragment,
                format!("a first fragment too short to hold the {what} header, which hides it from filters (RFC 1858)"),
            )
        } else {
            anomaly(
                Check::Length,
                format!(
                    "a {what} header cut short at {} of its {need} bytes",
                    l4.len()
                ),
            )
        }
    };
    match p.proto {
        TCP => {
            if l4.len() < 20 {
                return short("TCP", 20);
            }
            p.transport = true;
            p.sport = be16(l4, 0);
            p.dport = be16(l4, 2);
            let flags = u16::from(l4[12] & 1) << 8 | u16::from(l4[13]);
            p.flags = Some(flags);
            p.window = Some(be16(l4, 14));
            let offset = usize::from(l4[12] >> 4) * 4;
            if offset < 20 {
                return anomaly(
                    Check::TcpHeader,
                    format!("a data offset of {offset} bytes, under the 20 a TCP header takes"),
                );
            }
            if offset > l4.len() {
                return short("TCP", offset);
            }
            if let Some(a) = tcp_options(&l4[20..offset], flags & SYN != 0) {
                return Some(a);
            }
            p.payload = &l4[offset..];
        }
        UDP => {
            if l4.len() < 8 {
                return short("UDP", 8);
            }
            p.transport = true;
            p.sport = be16(l4, 0);
            p.dport = be16(l4, 2);
            let len = usize::from(be16(l4, 4));
            if len < 8 {
                return anomaly(
                    Check::UdpHeader,
                    format!("a UDP length of {len} bytes, under its own 8-byte header"),
                );
            }
            // A first fragment holds only part of the datagram the length counts.
            if !first && len > l4.len() {
                return anomaly(
                    Check::Length,
                    format!("a UDP length of {len} bytes in a datagram of {}", l4.len()),
                );
            }
            if !first && len < l4.len() {
                return anomaly(
                    Check::UdpHeader,
                    format!(
                        "a UDP length of {len} bytes in a datagram of {}, which hides the rest from whatever reads the length",
                        l4.len()
                    ),
                );
            }
            p.payload = &l4[8..len.min(l4.len())];
        }
        ICMP | ICMPV6 if (p.proto == ICMPV6) == p.v6 => {
            if l4.len() < 8 {
                return if first {
                    short("ICMP", 8)
                } else {
                    anomaly(
                        Check::Icmp,
                        format!(
                            "an ICMP message of {} bytes, shorter than its 8-byte header",
                            l4.len()
                        ),
                    )
                };
            }
            p.transport = true;
            p.icmp = Some((l4[0], l4[1]));
            if let Some(why) = link_only(l4[0], p.v6) {
                return anomaly(Check::Icmp, why);
            }
            p.payload = &l4[8..];
        }
        _ => p.payload = l4,
    }
    if matches!(p.proto, TCP | UDP) && (p.sport == 0 || p.dport == 0) {
        return anomaly(
            Check::PortZero,
            format!(
                "a {} {} port 0, which no service uses",
                if p.proto == TCP {
                    "TCP segment"
                } else {
                    "UDP datagram"
                },
                if p.sport == 0 { "from" } else { "to" }
            ),
        );
    }
    None
}
fn tcp_options(o: &[u8], syn: bool) -> Option<Anomaly> {
    let mut i = 0;
    while i < o.len() {
        let kind = o[i];
        match kind {
            0 => break,
            1 => i += 1,
            _ => {
                let Some(&len) = o.get(i + 1) else {
                    return anomaly(
                        Check::TcpHeader,
                        format!("TCP option {kind} cut off by the end of the header"),
                    );
                };
                let len = usize::from(len);
                if len < 2 || i + len > o.len() {
                    return anomaly(
                        Check::TcpHeader,
                        format!(
                            "TCP option {kind} claiming {len} bytes, which the header cannot hold"
                        ),
                    );
                }
                let (name, fits) = match kind {
                    2 => ("MSS", len == 4),
                    3 => ("window scale", len == 3),
                    4 => ("SACK-permitted", len == 2),
                    5 => ("SACK", len >= 10 && (len - 2) % 8 == 0),
                    8 => ("timestamp", len == 10),
                    _ => ("", true),
                };
                if !fits {
                    return anomaly(
                        Check::TcpHeader,
                        format!("a TCP {name} option {len} bytes long"),
                    );
                }
                if kind == 2 && syn {
                    let mss = be16(o, i + 2);
                    if mss <= LOW_MSS {
                        return anomaly(
                            Check::LowMss,
                            format!("a SYN offering an MSS of {mss} bytes, the shape of SACK Panic (CVE-2019-11477)"),
                        );
                    }
                }
                i += len;
            }
        }
    }
    None
}
/// What a protocol is called in a flow record and a rule: its name when it has one here, or else
/// its number.
pub fn protocol_name(proto: u8) -> String {
    match proto {
        TCP => "tcp".into(),
        UDP => "udp".into(),
        ICMP | ICMPV6 => "icmp".into(),
        4 => "ipip".into(),
        41 => "ipv6".into(),
        47 => "gre".into(),
        50 => "esp".into(),
        51 => "ah".into(),
        132 => "sctp".into(),
        n => n.to_string(),
    }
}
/// Fills a flow from the packet it carries, as the packet's own headers state its addresses,
/// protocol, ports, flags and payload. A packet too broken to read that far leaves the rest of the
/// record's fields as they were.
pub fn fill(f: &mut Flow) {
    if f.packet.is_empty() {
        return;
    }
    let (p, _) = parse(&f.packet);
    let (Some(src), Some(dst)) = (p.src, p.dst) else {
        return;
    };
    let payload = p.payload.to_vec();
    f.src_ip = src.to_string();
    f.dst_ip = dst.to_string();
    f.proto = protocol_name(p.proto);
    f.sport = i64::from(p.sport);
    f.dport = i64::from(p.dport);
    f.flags = p.flags.map(flag_names).unwrap_or_default();
    f.window = p.window;
    f.has_payload = p.transport;
    f.payload = payload;
}

/// How many fragmented datagrams a node tracks at once, and how many pieces of each.
pub const FRAGMENTS_MAX: usize = 4096;
const PIECES_MAX: usize = 64;
/// How long a datagram's fragments are remembered after its first arrives, as a host holds them
/// for reassembly.
const REASSEMBLY: i64 = 30_000;
/// The fragments of each datagram in reassembly, by source, destination, protocol and
/// identification, so a fragment that overlaps another of its datagram is caught: Teardrop and
/// its kin are built so that reassembling them breaks the host that does it. The table is
/// bounded: when it is full the oldest datagram is forgotten, so a flood of fragments costs the
/// node only its oldest entries, and a pair of overlapping fragments sent together is still
/// caught.
#[derive(Default)]
pub struct Fragments {
    map: HashMap<(IpAddr, IpAddr, u8, u32), Datagram>,
    order: VecDeque<((IpAddr, IpAddr, u8, u32), i64)>,
    /// Datagrams forgotten before their time to make room, and pieces past what one datagram
    /// keeps.
    pub untracked: u64,
}
#[derive(Default)]
struct Datagram {
    pieces: Vec<(u32, u32)>,
    /// Where the last fragment ends the datagram, once it has arrived.
    end: Option<u32>,
}
impl Fragments {
    pub fn len(&self) -> usize {
        self.map.len()
    }
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
    /// Records a fragment, and says how it breaks its datagram if it overlaps a piece already
    /// seen or runs past where the datagram ends. The same piece twice is a network duplicating
    /// a packet, not an overlap.
    pub fn observe(&mut self, p: &Packet, now: i64) -> Option<Anomaly> {
        let (Some(src), Some(dst)) = (p.src, p.dst) else {
            return None;
        };
        while self
            .order
            .front()
            .is_some_and(|(_, at)| now - at >= REASSEMBLY)
        {
            let (key, _) = self.order.pop_front().unwrap();
            self.map.remove(&key);
        }
        let key = (src, dst, p.proto, p.id);
        if !self.map.contains_key(&key) {
            if self.map.len() >= FRAGMENTS_MAX {
                if let Some((oldest, _)) = self.order.pop_front() {
                    self.map.remove(&oldest);
                    self.untracked += 1;
                }
            }
            self.map.insert(key, Datagram::default());
            self.order.push_back((key, now));
        }
        let d = self.map.get_mut(&key).unwrap();
        let (start, end) = (p.offset, p.offset + p.data);
        if d.pieces.contains(&(start, end)) {
            return None;
        }
        if let Some(&(s, e)) = d.pieces.iter().find(|&&(s, e)| start < e && s < end) {
            return anomaly(
                Check::FragmentOverlap,
                format!("a fragment over bytes {start} to {end} of a datagram whose bytes {s} to {e} already arrived, as Teardrop sends"),
            );
        }
        if let Some(last) = d.end.filter(|last| end > *last) {
            return anomaly(
                Check::FragmentOverlap,
                format!("a fragment reaching byte {end} of a datagram its last fragment ended at byte {last}"),
            );
        }
        if !p.more {
            if let Some(&(_, e)) = d.pieces.iter().find(|&&(_, e)| e > end) {
                return anomaly(
                    Check::FragmentOverlap,
                    format!("a last fragment ending its datagram at byte {end}, short of byte {e} already arrived"),
                );
            }
            d.end = Some(end);
        }
        if d.pieces.len() >= PIECES_MAX {
            self.untracked += 1;
            return None;
        }
        d.pieces.push((start, end));
        None
    }
}
