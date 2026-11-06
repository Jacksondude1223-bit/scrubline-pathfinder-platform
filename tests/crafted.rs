//! Packets built to harm the stack that receives them rather than to swamp it. Every classic one
//! of each kind (stack, protocol and buffer) is built here byte by byte and dropped, every kind of
//! packet a real stack sends is passed, and the parsers are fed random and mangled input without
//! falling over.
use base64::{engine::general_purpose::STANDARD, Engine};
use pathfinder::{
    model::{
        ACLEntry, CraftedPolicy, FPGAEntry, Flow, GameFilter, GameHttp, Match, NodeTunnel, Policy,
        Program, ProtocolPolicy, ReputationPolicy,
    },
    packet::{self, Check, ACK, CWR, ECE, FIN, PSH, RST, SYN, URG},
    pipeline::Pipeline,
    telemetry::Metrics,
    validation,
};
use rand::{rngs::StdRng, Rng, SeedableRng};
use serde_json::json;
use std::net::Ipv6Addr;

const T0: i64 = 1767225600000;
const TCP: u8 = 6;
const UDP: u8 = 17;
const ICMP: u8 = 1;
const ICMPV6: u8 = 58;
const CLIENT: [u8; 4] = [192, 0, 2, 1];
const SERVER: [u8; 4] = [203, 0, 113, 10];
const CLIENT6: &str = "2001:db8:ffff::1";
const SERVER6: &str = "2001:db8:100::10";

fn ones(h: &[u8]) -> u16 {
    let mut s: u32 = h
        .chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])))
        .sum();
    while s > 0xffff {
        s = (s & 0xffff) + (s >> 16);
    }
    s as u16
}
/// Writes an IPv4 header's checksum, after a field of it was changed.
fn seal(p: &mut [u8]) {
    let ihl = (usize::from(p[0] & 0x0f) * 4).min(p.len());
    p[10] = 0;
    p[11] = 0;
    let c = !ones(&p[..ihl]);
    p[10..12].copy_from_slice(&c.to_be_bytes());
}
/// An IPv4 packet with the don't-fragment bit, `options` already padded to a multiple of 4.
fn v4(src: [u8; 4], dst: [u8; 4], proto: u8, options: &[u8], l4: &[u8]) -> Vec<u8> {
    let ihl = 20 + options.len();
    let mut p = vec![0x40 | (ihl / 4) as u8, 0];
    p.extend(((ihl + l4.len()) as u16).to_be_bytes());
    p.extend([0x12, 0x34, 0x40, 0x00, 64, proto, 0, 0]);
    p.extend(src);
    p.extend(dst);
    p.extend(options);
    p.extend(l4);
    seal(&mut p);
    p
}
/// The same packet as a fragment of datagram `id`, `offset` bytes into it.
fn fragment(mut p: Vec<u8>, id: u16, offset: u16, more: bool) -> Vec<u8> {
    p[4..6].copy_from_slice(&id.to_be_bytes());
    let field = (offset / 8) | if more { 0x2000 } else { 0 };
    p[6..8].copy_from_slice(&field.to_be_bytes());
    seal(&mut p);
    p
}
fn tcp(sport: u16, dport: u16, flags: u16, options: &[u8], data: &[u8]) -> Vec<u8> {
    let offset = 20 + options.len();
    let mut t = Vec::new();
    t.extend(sport.to_be_bytes());
    t.extend(dport.to_be_bytes());
    t.extend([0, 0, 0, 1, 0, 0, 0, 0]);
    t.push(((offset / 4) as u8) << 4 | (flags >> 8) as u8);
    t.push(flags as u8);
    t.extend([0xff, 0xff, 0, 0, 0, 0]);
    t.extend(options);
    t.extend(data);
    t
}
fn udp(sport: u16, dport: u16, data: &[u8]) -> Vec<u8> {
    let mut u = Vec::new();
    u.extend(sport.to_be_bytes());
    u.extend(dport.to_be_bytes());
    u.extend((8 + data.len() as u16).to_be_bytes());
    u.extend([0, 0]);
    u.extend(data);
    u
}
fn icmp(kind: u8, code: u8, data: &[u8]) -> Vec<u8> {
    let mut m = vec![kind, code, 0, 0, 0, 0, 0, 0];
    m.extend(data);
    m
}
fn v6(src: &str, dst: &str, next: u8, rest: &[u8]) -> Vec<u8> {
    let mut p = vec![0x60, 0, 0, 0];
    p.extend((rest.len() as u16).to_be_bytes());
    p.extend([next, 64]);
    p.extend(src.parse::<Ipv6Addr>().unwrap().octets());
    p.extend(dst.parse::<Ipv6Addr>().unwrap().octets());
    p.extend(rest);
    p
}
/// An IPv6 extension header in the common shape, `body` filling it to a multiple of 8 bytes.
fn ext(next: u8, body: &[u8]) -> Vec<u8> {
    assert_eq!((2 + body.len()) % 8, 0);
    let mut h = vec![next, ((2 + body.len()) / 8 - 1) as u8];
    h.extend(body);
    h
}
const PADN: [u8; 6] = [1, 4, 0, 0, 0, 0];
/// An IPv6 fragment header; `offset` is in bytes and a multiple of 8, so it sits where the field
/// keeps it.
fn frag6(next: u8, offset: u16, more: bool, id: u32) -> Vec<u8> {
    let mut h = vec![next, 0];
    h.extend((offset | u16::from(more)).to_be_bytes());
    h.extend(id.to_be_bytes());
    h
}
fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}
/// A flow record carrying a packet, as a datapath posts one.
fn wire(bytes: &[u8]) -> Flow {
    serde_json::from_value(json!({ "packet": STANDARD.encode(bytes) })).unwrap()
}
fn node() -> Program {
    Program {
        prefixes: vec!["203.0.113.0/24".into(), "2001:db8:100::/48".into()],
        ..Default::default()
    }
}
fn syn() -> Vec<u8> {
    tcp(40000, 443, SYN, &[2, 4, 0x05, 0xb4], &[])
}
/// What a real stack sends, all of which must pass.
fn legitimate() -> Vec<(&'static str, Vec<u8>)> {
    let options = [
        2, 4, 0x05, 0xb4, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 7,
    ];
    // A 3,000-byte UDP datagram over a 1,500-byte MTU.
    let datagram = udp(53000, 19132, &[7; 3000]);
    let piece = |id: u16, at: usize, to: usize, more: bool| {
        fragment(
            v4(CLIENT, SERVER, UDP, &[], &datagram[at..to]),
            id,
            at as u16,
            more,
        )
    };
    let datagram6 = udp(53000, 19132, &[7; 2000]);
    let mut padded = v4(CLIENT, SERVER, TCP, &[], &tcp(40000, 443, ACK, &[], &[]));
    padded.extend([0; 6]);
    vec![
        (
            "a SYN with every common option",
            v4(
                CLIENT,
                SERVER,
                TCP,
                &[],
                &tcp(40000, 443, SYN, &options, &[]),
            ),
        ),
        (
            "a SYN asking for ECN",
            v4(
                CLIENT,
                SERVER,
                TCP,
                &[],
                &tcp(40000, 443, SYN | ECE | CWR, &[2, 4, 0x05, 0xb4], &[]),
            ),
        ),
        (
            "a SYN offering a 501-byte MSS",
            v4(
                CLIENT,
                SERVER,
                TCP,
                &[],
                &tcp(40000, 443, SYN, &[2, 4, 0x01, 0xf5], &[]),
            ),
        ),
        (
            "a SYN-ACK to a connection the server opened",
            v4(
                CLIENT,
                SERVER,
                TCP,
                &[],
                &tcp(443, 40000, SYN | ACK, &[2, 4, 0x05, 0xb4], &[]),
            ),
        ),
        (
            "an ACK",
            v4(CLIENT, SERVER, TCP, &[], &tcp(40000, 443, ACK, &[], &[])),
        ),
        (
            "a PSH-ACK carrying data",
            v4(
                CLIENT,
                SERVER,
                TCP,
                &[],
                &tcp(40000, 443, PSH | ACK, &[], b"GET / HTTP/1.1\r\n\r\n"),
            ),
        ),
        (
            "a FIN-ACK",
            v4(
                CLIENT,
                SERVER,
                TCP,
                &[],
                &tcp(40000, 443, FIN | ACK, &[], &[]),
            ),
        ),
        (
            "an urgent ACK",
            v4(
                CLIENT,
                SERVER,
                TCP,
                &[],
                &tcp(40000, 443, URG | ACK, &[], &[1]),
            ),
        ),
        (
            "a bare RST",
            v4(CLIENT, SERVER, TCP, &[], &tcp(40000, 443, RST, &[], &[])),
        ),
        (
            "a RST-ACK",
            v4(
                CLIENT,
                SERVER,
                TCP,
                &[],
                &tcp(40000, 443, RST | ACK, &[], &[]),
            ),
        ),
        (
            "a game datagram",
            v4(CLIENT, SERVER, UDP, &[], &udp(53000, 19132, &[0x84, 0, 0])),
        ),
        (
            "an empty datagram",
            v4(CLIENT, SERVER, UDP, &[], &udp(53000, 19132, &[])),
        ),
        (
            "a DNS answer",
            v4(CLIENT, SERVER, UDP, &[], &udp(53, 40000, &[0; 64])),
        ),
        (
            "an echo request",
            v4(CLIENT, SERVER, ICMP, &[], &icmp(8, 0, &[1; 56])),
        ),
        (
            "an echo reply",
            v4(CLIENT, SERVER, ICMP, &[], &icmp(0, 0, &[1; 56])),
        ),
        (
            "fragmentation needed",
            v4(CLIENT, SERVER, ICMP, &[], &icmp(3, 4, &[0; 28])),
        ),
        (
            "time exceeded",
            v4(CLIENT, SERVER, ICMP, &[], &icmp(11, 0, &[0; 28])),
        ),
        (
            "a timestamp request",
            v4(CLIENT, SERVER, ICMP, &[], &icmp(13, 0, &[0; 12])),
        ),
        (
            "GRE",
            v4(CLIENT, SERVER, 47, &[], &[0, 0, 0x08, 0, 0x45, 0, 0, 0]),
        ),
        (
            "a record-route option",
            v4(
                CLIENT,
                SERVER,
                UDP,
                &[7, 7, 4, 0, 0, 0, 0, 0],
                &udp(53000, 19132, &[1]),
            ),
        ),
        ("a frame padded to Ethernet's minimum", padded),
        ("a first fragment", piece(1, 0, 1480, true)),
        ("a middle fragment", piece(1, 1480, 2960, true)),
        ("a last fragment", piece(1, 2960, datagram.len(), false)),
        (
            "a last fragment first",
            piece(2, 2960, datagram.len(), false),
        ),
        ("a middle fragment second", piece(2, 1480, 2960, true)),
        ("a first fragment last", piece(2, 0, 1480, true)),
        ("a fragment the network duplicated", piece(2, 0, 1480, true)),
        (
            "an IPv6 SYN",
            v6(
                CLIENT6,
                SERVER6,
                TCP,
                &tcp(40000, 443, SYN, &[2, 4, 0x05, 0xa0], &[]),
            ),
        ),
        (
            "an IPv6 datagram",
            v6(CLIENT6, SERVER6, UDP, &udp(53000, 19132, &[0x84])),
        ),
        (
            "an IPv6 echo request",
            v6(CLIENT6, SERVER6, ICMPV6, &icmp(128, 0, &[1; 56])),
        ),
        (
            "packet too big",
            v6(CLIENT6, SERVER6, ICMPV6, &icmp(2, 0, &[0; 48])),
        ),
        (
            "destination options",
            v6(
                CLIENT6,
                SERVER6,
                60,
                &cat(&[&ext(UDP, &PADN), &udp(53000, 19132, &[1])]),
            ),
        ),
        (
            "hop-by-hop first",
            v6(
                CLIENT6,
                SERVER6,
                0,
                &cat(&[&ext(UDP, &[5, 2, 0, 0, 1, 0]), &udp(53000, 19132, &[1])]),
            ),
        ),
        (
            "an atomic fragment",
            v6(
                CLIENT6,
                SERVER6,
                44,
                &cat(&[&frag6(UDP, 0, false, 9), &udp(53000, 19132, &[1])]),
            ),
        ),
        (
            "an IPv6 first fragment",
            v6(
                CLIENT6,
                SERVER6,
                44,
                &cat(&[&frag6(UDP, 0, true, 10), &datagram6[..1232]]),
            ),
        ),
        (
            "an IPv6 last fragment",
            v6(
                CLIENT6,
                SERVER6,
                44,
                &cat(&[&frag6(UDP, 1232, false, 10), &datagram6[1232..]]),
            ),
        ),
    ]
}
#[test]
fn every_kind_of_packet_a_real_stack_sends_passes() {
    // GRE among them, which a protected address receives only when the policy lets it.
    let mut pipe = Pipeline::new(Program {
        protocols: Some(ProtocolPolicy {
            allow: vec!["gre".into()],
            ..Default::default()
        }),
        ..node()
    });
    for (i, (what, bytes)) in legitimate().into_iter().enumerate() {
        let (_, found) = packet::parse(&bytes);
        assert_eq!(found, None, "{what}");
        let d = pipe.decide(&wire(&bytes), T0 + i as i64);
        assert_eq!(
            (d.action.as_str(), d.check.as_str()),
            ("permit", ""),
            "{what}: {}",
            d.reason
        );
    }
    assert_eq!(pipe.stats(T0 + 100)["crafted"]["dropped"], 0);
}
/// Packets each built to break one rule, the check that must catch it, and part of why.
fn crafted() -> Vec<(&'static str, Vec<u8>, Check, &'static str)> {
    let udp4 = |l4: &[u8]| v4(CLIENT, SERVER, UDP, &[], l4);
    let tcp4 = |flags: u16| v4(CLIENT, SERVER, TCP, &[], &tcp(40000, 80, flags, &[], &[]));
    let mut ihl = udp4(&udp(53000, 19132, &[1]));
    ihl[0] = 0x44;
    seal(&mut ihl);
    let mut short_total = udp4(&udp(53000, 19132, &[1]));
    short_total[2..4].copy_from_slice(&10u16.to_be_bytes());
    seal(&mut short_total);
    let mut checksum = udp4(&udp(53000, 19132, &[1]));
    checksum[10] ^= 0xff;
    let mut reserved = udp4(&udp(53000, 19132, &[1]));
    reserved[6] |= 0x80;
    seal(&mut reserved);
    let mut version = udp4(&udp(53000, 19132, &[1]));
    version[0] = 0x55;
    let mut offset4 = tcp(40000, 80, ACK, &[], &[]);
    offset4[12] = 4 << 4;
    let mut offset15 = tcp(40000, 80, ACK, &[], &[]);
    offset15[12] = 15 << 4;
    let mut udp_tiny = udp(53000, 19132, &[1; 20]);
    udp_tiny[4..6].copy_from_slice(&4u16.to_be_bytes());
    let mut udp_short = udp(53000, 19132, &[1; 20]);
    udp_short[4..6].copy_from_slice(&10u16.to_be_bytes());
    let mut udp_long = udp(53000, 19132, &[1; 20]);
    udp_long[4..6].copy_from_slice(&100u16.to_be_bytes());
    let mut cut = udp4(&udp(53000, 19132, &[1; 20]));
    cut.truncate(cut.len() - 10);
    let mut trailing = udp4(&udp(53000, 19132, &[1; 20]));
    trailing.extend([0; 100]);
    let mut v6_long = v6(CLIENT6, SERVER6, UDP, &udp(53000, 19132, &[1]));
    v6_long[4..6].copy_from_slice(&1000u16.to_be_bytes());
    let nine: Vec<u8> = (0..9)
        .flat_map(|i| ext(if i == 8 { UDP } else { 60 }, &PADN))
        .chain(udp(53000, 19132, &[1]))
        .collect();
    vec![
        // Stack: built to crash or wedge the stack that receives it.
        (
            "LAND",
            v4(SERVER, SERVER, TCP, &[], &tcp(80, 80, SYN, &[], &[])),
            Check::Land,
            "as LAND sends",
        ),
        (
            "LAND over IPv6",
            v6(SERVER6, SERVER6, TCP, &tcp(80, 80, SYN, &[], &[])),
            Check::Land,
            "same address",
        ),
        (
            "SYN-FIN",
            tcp4(SYN | FIN),
            Check::TcpFlags,
            "SYN and FIN set together",
        ),
        (
            "SYN-RST",
            tcp4(SYN | RST),
            Check::TcpFlags,
            "SYN and RST set together",
        ),
        (
            "FIN-RST",
            tcp4(FIN | RST | ACK),
            Check::TcpFlags,
            "FIN and RST set together",
        ),
        (
            "a NULL scan",
            tcp4(0),
            Check::TcpFlags,
            "as a NULL scan sends",
        ),
        (
            "a Christmas tree",
            tcp4(FIN | PSH | URG),
            Check::TcpFlags,
            "Christmas tree",
        ),
        ("a FIN scan", tcp4(FIN), Check::TcpFlags, "FIN without ACK"),
        (
            "PSH and URG alone",
            tcp4(PSH | URG),
            Check::TcpFlags,
            "PSH and URG without ACK",
        ),
        (
            "a loopback source",
            v4([127, 0, 0, 1], SERVER, UDP, &[], &udp(53000, 19132, &[1])),
            Check::MartianSource,
            "loopback",
        ),
        (
            "a multicast source",
            v4([224, 0, 0, 5], SERVER, UDP, &[], &udp(53000, 19132, &[1])),
            Check::MartianSource,
            "multicast",
        ),
        (
            "the broadcast address",
            v4([255; 4], SERVER, UDP, &[], &udp(53000, 19132, &[1])),
            Check::MartianSource,
            "240.0.0.0/4",
        ),
        (
            "this network",
            v4([0, 0, 0, 0], SERVER, UDP, &[], &udp(68, 67, &[1])),
            Check::MartianSource,
            "0.0.0.0/8",
        ),
        (
            "a link-local source",
            v4([169, 254, 3, 4], SERVER, UDP, &[], &udp(53000, 19132, &[1])),
            Check::MartianSource,
            "link-local",
        ),
        (
            "IPv6 loopback",
            v6("::1", SERVER6, UDP, &udp(53000, 19132, &[1])),
            Check::MartianSource,
            "loopback",
        ),
        (
            "IPv6 link-local",
            v6("fe80::1", SERVER6, UDP, &udp(53000, 19132, &[1])),
            Check::MartianSource,
            "link-local",
        ),
        (
            "IPv6 multicast",
            v6("ff02::1", SERVER6, UDP, &udp(53000, 19132, &[1])),
            Check::MartianSource,
            "multicast",
        ),
        (
            "an IPv4-mapped source",
            v6("::ffff:192.0.2.1", SERVER6, UDP, &udp(53000, 19132, &[1])),
            Check::MartianSource,
            "IPv4-mapped",
        ),
        (
            "loose source routing",
            v4(
                CLIENT,
                SERVER,
                UDP,
                &[131, 7, 4, 192, 0, 2, 9, 0],
                &udp(53000, 19132, &[1]),
            ),
            Check::SourceRoute,
            "loose source route",
        ),
        (
            "strict source routing",
            v4(
                CLIENT,
                SERVER,
                UDP,
                &[137, 7, 4, 192, 0, 2, 9, 0],
                &udp(53000, 19132, &[1]),
            ),
            Check::SourceRoute,
            "strict source route",
        ),
        (
            "a type 0 routing header",
            v6(
                CLIENT6,
                SERVER6,
                43,
                &cat(&[&ext(UDP, &[0, 1, 0, 0, 0, 0]), &udp(53000, 19132, &[1])]),
            ),
            Check::SourceRoute,
            "RFC 5095",
        ),
        (
            "SACK Panic",
            v4(
                CLIENT,
                SERVER,
                TCP,
                &[],
                &tcp(40000, 80, SYN, &[2, 4, 0, 48], &[]),
            ),
            Check::LowMss,
            "an MSS of 48 bytes",
        ),
        (
            "a 500-byte MSS",
            v4(
                CLIENT,
                SERVER,
                TCP,
                &[],
                &tcp(40000, 80, SYN, &[2, 4, 0x01, 0xf4], &[]),
            ),
            Check::LowMss,
            "CVE-2019-11477",
        ),
        (
            "a fragment over the TCP flags",
            fragment(v4(CLIENT, SERVER, TCP, &[], &[0; 16]), 7, 8, false),
            Check::FragmentOverlap,
            "RFC 1858",
        ),
        // Protocol: breaking the rules of the protocol it claims to be.
        (
            "a 16-byte IPv4 header",
            ihl,
            Check::IpHeader,
            "under the 20 an IPv4 header takes",
        ),
        (
            "a total length shorter than the header",
            short_total,
            Check::IpHeader,
            "shorter than its own 20-byte header",
        ),
        (
            "a bad header checksum",
            checksum,
            Check::IpHeader,
            "checksum",
        ),
        (
            "the evil bit",
            reserved,
            Check::IpHeader,
            "reserved flag bit",
        ),
        ("IP version 5", version, Check::IpHeader, "IP version 5"),
        (
            "a zero-length IP option",
            v4(CLIENT, SERVER, UDP, &[7, 0, 0, 0], &udp(53000, 19132, &[1])),
            Check::IpOptions,
            "IP option 7 claiming 0 bytes",
        ),
        (
            "an IP option past the header",
            v4(
                CLIENT,
                SERVER,
                UDP,
                &[68, 12, 5, 0],
                &udp(53000, 19132, &[1]),
            ),
            Check::IpOptions,
            "which the header cannot hold",
        ),
        (
            "hop-by-hop second",
            v6(
                CLIENT6,
                SERVER6,
                60,
                &cat(&[&ext(0, &PADN), &ext(UDP, &PADN), &udp(53000, 19132, &[1])]),
            ),
            Check::ExtensionHeaders,
            "only the first may be one",
        ),
        (
            "two fragment headers",
            v6(
                CLIENT6,
                SERVER6,
                44,
                &cat(&[
                    &frag6(44, 0, false, 1),
                    &frag6(UDP, 0, false, 2),
                    &udp(53000, 19132, &[1]),
                ]),
            ),
            Check::ExtensionHeaders,
            "two fragment headers",
        ),
        (
            "nine extension headers",
            v6(CLIENT6, SERVER6, 60, &nine),
            Check::ExtensionHeaders,
            "more than eight",
        ),
        (
            "a 16-byte TCP header",
            v4(CLIENT, SERVER, TCP, &[], &offset4),
            Check::TcpHeader,
            "a data offset of 16 bytes",
        ),
        (
            "a 3-byte MSS option",
            v4(
                CLIENT,
                SERVER,
                TCP,
                &[],
                &tcp(40000, 80, SYN, &[2, 3, 5, 1], &[]),
            ),
            Check::TcpHeader,
            "a TCP MSS option 3 bytes long",
        ),
        (
            "a TCP option past the header",
            v4(
                CLIENT,
                SERVER,
                TCP,
                &[],
                &tcp(40000, 80, ACK, &[8, 12, 0, 0], &[]),
            ),
            Check::TcpHeader,
            "TCP option 8 claiming 12 bytes",
        ),
        (
            "a TCP option cut off",
            v4(
                CLIENT,
                SERVER,
                TCP,
                &[],
                &tcp(40000, 80, ACK, &[1, 1, 1, 5], &[]),
            ),
            Check::TcpHeader,
            "cut off",
        ),
        (
            "a UDP length under its header",
            udp4(&udp_tiny),
            Check::UdpHeader,
            "under its own 8-byte header",
        ),
        (
            "a UDP length short of its datagram",
            udp4(&udp_short),
            Check::UdpHeader,
            "hides the rest",
        ),
        (
            "an ICMP redirect",
            v4(CLIENT, SERVER, ICMP, &[], &icmp(5, 1, &[0; 28])),
            Check::Icmp,
            "a redirect",
        ),
        (
            "an ICMP router advertisement",
            v4(CLIENT, SERVER, ICMP, &[], &icmp(9, 0, &[0; 8])),
            Check::Icmp,
            "router advertisement",
        ),
        (
            "an address mask request",
            v4(CLIENT, SERVER, ICMP, &[], &icmp(17, 0, &[0; 4])),
            Check::Icmp,
            "deprecated",
        ),
        (
            "Bad Neighbor's router advertisement",
            v6(CLIENT6, SERVER6, ICMPV6, &icmp(134, 0, &[0; 16])),
            Check::Icmp,
            "neighbour discovery",
        ),
        (
            "a 4-byte ICMP message",
            v4(CLIENT, SERVER, ICMP, &[], &[8, 0, 0, 0]),
            Check::Icmp,
            "shorter than its 8-byte header",
        ),
        (
            "UDP to port 0",
            udp4(&udp(53000, 0, &[1])),
            Check::PortZero,
            "a UDP datagram to port 0",
        ),
        (
            "TCP from port 0",
            v4(CLIENT, SERVER, TCP, &[], &tcp(0, 80, SYN, &[], &[])),
            Check::PortZero,
            "a TCP segment from port 0",
        ),
        (
            "a misaligned fragment",
            fragment(v4(CLIENT, SERVER, UDP, &[], &[0; 300]), 9, 0, true),
            Check::Fragment,
            "multiple of 8",
        ),
        // Buffer: sized to overrun a buffer or a reassembly table.
        (
            "a total length past the packet",
            cut,
            Check::Length,
            "a total length of 48 bytes in a packet of 38",
        ),
        (
            "a UDP length past the datagram",
            udp4(&udp_long),
            Check::Length,
            "a UDP length of 100 bytes in a datagram of 28",
        ),
        (
            "a TCP header past the segment",
            v4(CLIENT, SERVER, TCP, &[], &offset15),
            Check::Length,
            "cut short at 20 of its 60 bytes",
        ),
        (
            "an IPv6 payload length past the packet",
            v6_long,
            Check::Length,
            "a payload length of 1000 bytes",
        ),
        (
            "bytes hidden past the end",
            trailing,
            Check::Length,
            "100 bytes past the 48",
        ),
        (
            "ten bytes",
            vec![0x45, 0, 0, 10, 0, 0, 0, 0, 64, 17],
            Check::Length,
            "too short for an IPv4 header",
        ),
        (
            "Ping of Death",
            fragment(v4(CLIENT, SERVER, ICMP, &[], &[0; 100]), 11, 65528, false),
            Check::Oversize,
            "Ping of Death",
        ),
        (
            "a first fragment without the TCP header",
            fragment(v4(CLIENT, SERVER, TCP, &[], &[0; 16]), 12, 0, true),
            Check::TinyFragment,
            "too short to hold the TCP header",
        ),
        (
            "FragmentSmack",
            fragment(v4(CLIENT, SERVER, UDP, &[], &[0; 64]), 13, 512, true),
            Check::TinyFragment,
            "FragmentSmack",
        ),
        (
            "an IPv6 first fragment without its header chain",
            v6(
                CLIENT6,
                SERVER6,
                44,
                &cat(&[&frag6(60, 0, true, 14), &[UDP, 31, 0, 0, 0, 0, 0, 0]]),
            ),
            Check::TinyFragment,
            "RFC 7112",
        ),
    ]
}
#[test]
fn every_classic_crafted_packet_is_dropped_by_the_check_it_breaks() {
    let mut pipe = Pipeline::new(node());
    let mut seen = std::collections::HashSet::new();
    for (i, (what, bytes, check, why)) in crafted().into_iter().enumerate() {
        let (_, found) = packet::parse(&bytes);
        let found = found.unwrap_or_else(|| panic!("{what}: not caught"));
        assert_eq!(found.check, check, "{what}: {}", found.why);
        assert!(found.why.contains(why), "{what}: {}", found.why);
        let d = pipe.decide(&wire(&bytes), T0 + i as i64);
        assert_eq!(
            (d.action.as_str(), d.check.as_str()),
            ("drop", check.name()),
            "{what}"
        );
        assert_eq!(
            d.reason,
            format!("crafted packet ({}): {}", check.class(), found.why),
            "{what}"
        );
        seen.insert(check);
    }
    // Fragments overlapping across packets take their own test; every other check has a case.
    assert_eq!(seen.len(), Check::ALL.len(), "{seen:?}");
    let stats = pipe.stats(T0 + 1000);
    let rows = stats["crafted"]["checks"].as_array().unwrap();
    assert_eq!(rows.len(), Check::ALL.len());
    for row in rows {
        assert!(
            row["dropped"].as_u64().unwrap() > 0,
            "{} dropped nothing",
            row["check"]
        );
    }
    assert_eq!(
        stats["crafted"]["dropped"],
        crafted().len() as u64,
        "{}",
        stats["crafted"]
    );
}
#[test]
fn fragments_that_overlap_across_packets_are_caught_as_teardrop_and_its_kin() {
    let mut pipe = Pipeline::new(node());
    let datagram = udp(53000, 19132, &[1; 1016]);
    let piece = |id: u16, at: usize, to: usize, more: bool| {
        wire(&fragment(
            v4(CLIENT, SERVER, UDP, &[], &datagram[at..to]),
            id,
            at as u16,
            more,
        ))
    };
    let judged = |pipe: &mut Pipeline, f: Flow, at: i64| {
        let d = pipe.decide(&f, at);
        (d.action, d.stage, d.check, d.reason)
    };
    // Teardrop: a last fragment over bytes the first already carried.
    assert_eq!(judged(&mut pipe, piece(20, 0, 512, true), T0).0, "permit");
    let (action, stage, check, reason) = judged(&mut pipe, piece(20, 256, 320, false), T0 + 1);
    assert_eq!(
        (action.as_str(), stage.as_str(), check.as_str()),
        ("drop", "zc", "fragment_overlap")
    );
    assert!(
        reason.ends_with("whose bytes 0 to 512 already arrived, as Teardrop sends"),
        "{reason}"
    );
    // The same piece twice is a network duplicating a packet, not an attack.
    for at in 0..2 {
        assert_eq!(
            judged(&mut pipe, piece(21, 0, 512, true), T0 + 2 + at).0,
            "permit"
        );
    }
    // A last fragment ending the datagram short of what already arrived.
    assert_eq!(
        judged(&mut pipe, piece(22, 512, 1024, true), T0 + 4).0,
        "permit"
    );
    let (_, _, check, reason) = judged(&mut pipe, piece(22, 256, 384, false), T0 + 5);
    assert_eq!(check, "fragment_overlap");
    assert!(reason.contains("short of byte 1024"), "{reason}");
    // A fragment past the end the last one set.
    let tail = fragment(v4(CLIENT, SERVER, UDP, &[], &[1; 88]), 23, 512, false);
    assert_eq!(judged(&mut pipe, wire(&tail), T0 + 6).0, "permit");
    let past = fragment(v4(CLIENT, SERVER, UDP, &[], &[1; 256]), 23, 600, true);
    let (_, _, check, reason) = judged(&mut pipe, wire(&past), T0 + 7);
    assert_eq!(check, "fragment_overlap");
    assert!(
        reason.contains("its last fragment ended at byte 600"),
        "{reason}"
    );
    // Another datagram's pieces, from another source, never overlap these.
    let other = fragment(
        v4([192, 0, 2, 2], SERVER, UDP, &[], &datagram[256..320]),
        20,
        256,
        false,
    );
    assert_eq!(judged(&mut pipe, wire(&other), T0 + 8).0, "permit");
    // A reassembly time later the datagram is forgotten, as the host has forgotten it.
    assert_eq!(
        judged(&mut pipe, piece(20, 256, 320, false), T0 + 31_000).0,
        "permit"
    );
}
#[test]
fn a_flood_of_fragments_costs_the_node_only_its_oldest_entries() {
    let mut pipe = Pipeline::new(node());
    let first = |id: u16| {
        wire(&fragment(
            v4(
                CLIENT,
                SERVER,
                UDP,
                &[],
                &udp(53000, 19132, &[1; 1472])[..1480],
            ),
            id,
            0,
            true,
        ))
    };
    for id in 0..5000u16 {
        assert_eq!(pipe.decide(&first(id), T0).action, "permit");
    }
    let stats = pipe.stats(T0);
    assert_eq!(
        (
            &stats["crafted"]["fragments"],
            &stats["crafted"]["fragments_untracked"]
        ),
        (
            &json!(packet::FRAGMENTS_MAX),
            &json!(5000 - packet::FRAGMENTS_MAX)
        )
    );
    // A pair of overlapping fragments sent together is still caught, the flood notwithstanding.
    let overlap = fragment(v4(CLIENT, SERVER, UDP, &[], &[1; 64]), 4999, 128, false);
    assert_eq!(pipe.decide(&first(4998), T0 + 1).action, "permit");
    assert_eq!(
        pipe.decide(&wire(&overlap), T0 + 1).check,
        "fragment_overlap"
    );
}
#[test]
fn a_record_without_a_packet_is_held_to_what_its_fields_show() {
    let mut pipe = Pipeline::new(node());
    let record = |src: &str, proto: &str, flags: &str| Flow {
        src_ip: src.into(),
        dst_ip: "203.0.113.10".into(),
        proto: proto.into(),
        dport: 443,
        flags: flags.into(),
        pps: 1,
        ..Default::default()
    };
    for (f, check) in [
        (record("203.0.113.10", "tcp", "syn"), "land"),
        (record("127.0.0.1", "udp", ""), "martian_source"),
        (record("192.0.2.1", "tcp", "syn,fin"), "tcp_flags"),
        (record("192.0.2.1", "tcp", "SYN|FIN"), "tcp_flags"),
        (record("192.0.2.1", "tcp", "none"), "tcp_flags"),
        (record("192.0.2.1", "tcp", "fin+psh+urg"), "tcp_flags"),
        (
            Flow {
                payload: vec![0; 70_000],
                has_payload: true,
                ..record("192.0.2.1", "udp", "")
            },
            "oversize",
        ),
    ] {
        let d = pipe.decide(&f, T0);
        assert_eq!(
            (d.action.as_str(), d.check.as_str()),
            ("drop", check),
            "{f:?}"
        );
    }
    // What a record leaves out shows nothing, and flags on anything but TCP mean nothing.
    for f in [
        record("192.0.2.1", "tcp", ""),
        record("192.0.2.1", "tcp", "syn"),
        record("192.0.2.1", "tcp", "SYN+ACK"),
        record("192.0.2.1", "tcp", "ack,psh"),
        record("192.0.2.1", "tcp", "rst"),
        record("192.0.2.1", "tcp", "synack"),
        record("192.0.2.1", "udp", "syn,fin"),
        record("", "udp", ""),
    ] {
        let d = pipe.decide(&f, T0);
        assert_eq!(d.check, "", "{f:?}: {}", d.reason);
    }
}
/// A node with an operator's permit, a DNS-reflection drop, a SYN meter, the penalty box and an
/// on-demand tunnel, the checks in `mode`.
fn guarded(mode: &str) -> Program {
    Program {
        prefixes: vec!["203.0.113.0/24".into(), "198.51.100.0/24".into()],
        asic: vec![
            ACLEntry {
                rule_id: "partner".into(),
                action: "permit".into(),
                r#match: Match {
                    src_cidr: "192.0.2.7/32".into(),
                    ..Default::default()
                },
                ..Default::default()
            },
            ACLEntry {
                rule_id: "dns".into(),
                action: "drop".into(),
                r#match: Match {
                    proto: "udp".into(),
                    sport: 53,
                    ..Default::default()
                },
                ..Default::default()
            },
        ],
        fpga: vec![FPGAEntry {
            rule_id: "syn-meter".into(),
            action: "rate_limit".into(),
            meter_pps: 100,
            r#match: Match {
                proto: "tcp".into(),
                tcp_flags: "syn".into(),
                ..Default::default()
            },
            ..Default::default()
        }],
        reputation: Some(ReputationPolicy {
            fast_pass: "egress".into(),
            penalty_box: true,
        }),
        tunnels: vec![NodeTunnel {
            id: "contoso".into(),
            prefixes: vec!["198.51.100.0/24".into()],
            mitigation: "on_demand".into(),
            attack_pps: 1_000_000,
            attack_kbps: 1_000_000,
            ..Default::default()
        }],
        crafted: Some(CraftedPolicy { mode: mode.into() }),
        ..Default::default()
    }
}
#[test]
fn no_permit_trust_or_idle_tunnel_lets_a_crafted_packet_through() {
    let mut pipe = Pipeline::new(guarded(""));
    let syn_fin = |src: [u8; 4], dst: [u8; 4]| {
        wire(&v4(
            src,
            dst,
            TCP,
            &[],
            &tcp(40000, 443, SYN | FIN, &[], &[]),
        ))
    };
    // An operator's permit vouches for an address, which a crafted packet forges with the rest.
    let d = pipe.decide(&syn_fin([192, 0, 2, 7], SERVER), T0);
    assert_eq!(d.check, "tcp_flags");
    let d = pipe.decide(&wire(&v4([192, 0, 2, 7], SERVER, TCP, &[], &syn())), T0);
    assert_eq!(d.reason, "TCAM ACL permit");
    // A source the origin answers is verified, and its crafted packets are dropped all the same.
    for tick in 0..3 {
        pipe.observe_return(
            &Flow {
                src_ip: "203.0.113.10".into(),
                dst_ip: "192.0.2.8".into(),
                proto: "udp".into(),
                pps: 4,
                ..Default::default()
            },
            T0 + tick * 250,
        );
    }
    let d = pipe.decide(
        &wire(&v4([192, 0, 2, 8], SERVER, TCP, &[], &syn())),
        T0 + 1000,
    );
    assert_eq!(d.reason, "verified source, fast path");
    assert_eq!(
        pipe.decide(&syn_fin([192, 0, 2, 8], SERVER), T0 + 1001)
            .check,
        "tcp_flags"
    );
    // A tunnel watched until it is attacked is still protected from what needs no volume.
    let d = pipe.decide(&syn_fin([192, 0, 2, 9], [198, 51, 100, 10]), T0 + 1002);
    assert_eq!((d.action.as_str(), d.check.as_str()), ("drop", "tcp_flags"));
    let reflected = wire(&v4(
        [192, 0, 2, 9],
        [198, 51, 100, 10],
        UDP,
        &[],
        &udp(53, 40000, &[0; 64]),
    ));
    assert_eq!(
        pipe.decide(&reflected, T0 + 1003).reason,
        "watching only: tunnel contoso is under its attack thresholds"
    );
    // No source is boxed for a crafted packet, since its address is as likely forged: the next
    // clean packet from each is judged as anyone's, and the verified source is still verified.
    for i in 0..10 {
        pipe.decide(&syn_fin([100, 64, 0, 9], SERVER), T0 + 2000 + i);
    }
    let d = pipe.decide(
        &wire(&v4(
            [100, 64, 0, 9],
            SERVER,
            UDP,
            &[],
            &udp(53000, 19132, &[1]),
        )),
        T0 + 2100,
    );
    assert_eq!(d.reason, "no matching drop rule");
    let d = pipe.decide(
        &wire(&v4([192, 0, 2, 8], SERVER, TCP, &[], &syn())),
        T0 + 2101,
    );
    assert_eq!(d.reason, "verified source, fast path");
    let stats = pipe.stats(T0 + 2101);
    assert_eq!(stats["reputation"]["boxed"], 0);
    assert_eq!(stats["reputation"]["strikes"], 0);
    let prefixes = stats["prefixes"].as_array().unwrap();
    let crafted: Vec<_> = prefixes
        .iter()
        .map(|p| (p["prefix"].as_str().unwrap(), p["crafted"].clone()))
        .collect();
    assert_eq!(
        crafted,
        [
            (
                "198.51.100.0/24",
                json!([{"class":"stack","flows":1,"dropped":1}])
            ),
            (
                "203.0.113.0/24",
                json!([{"class":"stack","flows":12,"dropped":12}])
            ),
        ]
    );
}
#[test]
fn a_tunnels_meter_counts_crafted_packets_so_mitigation_starts_on_the_whole_attack() {
    let mut program = guarded("");
    program.tunnels[0].attack_pps = 1000;
    let mut pipe = Pipeline::new(program);
    // 900 pps of SYN-FIN and 100 pps of reflected DNS: neither alone reaches the threshold.
    let syn_fin = serde_json::from_value::<Flow>(json!({
        "packet": STANDARD.encode(v4(CLIENT, [198, 51, 100, 10], TCP, &[], &tcp(40000, 443, SYN | FIN, &[], &[]))),
        "pps": 900,
    }))
    .unwrap();
    assert_eq!(pipe.decide(&syn_fin, T0).check, "tcp_flags");
    let reflected = serde_json::from_value::<Flow>(json!({
        "packet": STANDARD.encode(v4(CLIENT, [198, 51, 100, 10], UDP, &[], &udp(53, 40000, &[0; 64]))),
        "pps": 100,
    }))
    .unwrap();
    let d = pipe.decide(&reflected, T0 + 100);
    assert_eq!((d.action.as_str(), d.rule_id.as_str()), ("drop", "dns"));
}
#[test]
fn observing_counts_what_would_be_dropped_and_off_does_not_look() {
    let land = wire(&v4(SERVER, SERVER, TCP, &[], &tcp(80, 80, SYN, &[], &[])));
    let mut pipe = Pipeline::new(guarded("observe"));
    let d = pipe.decide(&land, T0);
    assert_eq!((d.action.as_str(), d.check.as_str()), ("permit", ""));
    let stats = pipe.stats(T0);
    assert_eq!(
        (
            &stats["crafted"]["mode"],
            &stats["crafted"]["dropped"],
            &stats["crafted"]["observed"]
        ),
        (&json!("observe"), &json!(0), &json!(1))
    );
    assert_eq!(
        stats["crafted"]["checks"][0],
        json!({"check":"land","class":"stack","dropped":0,"observed":1})
    );
    pipe.load(guarded("off"));
    pipe.decide(&land, T0 + 1);
    let stats = pipe.stats(T0 + 1);
    assert_eq!(
        (&stats["crafted"]["mode"], &stats["crafted"]["observed"]),
        (&json!("off"), &json!(1))
    );
    // Enforcing again, the counts carried over a reload.
    pipe.load(guarded("enforce"));
    assert_eq!(pipe.decide(&land, T0 + 2).check, "land");
    assert_eq!(pipe.stats(T0 + 2)["crafted"]["observed"], 1);
    let policy = |mode: &str| Policy {
        name: "p".into(),
        protected: vec!["203.0.113.0/24".into()],
        crafted: Some(CraftedPolicy { mode: mode.into() }),
        ..Default::default()
    };
    for mode in ["", "enforce", "observe", "off"] {
        validation::policy(&policy(mode)).unwrap();
    }
    let e = validation::policy(&policy("strict")).unwrap_err();
    assert!(e.starts_with("crafted.mode \"strict\""), "{e}");
}
#[test]
fn a_spare_flag_bit_slips_past_no_rule() {
    let mut pipe = Pipeline::new(guarded(""));
    let burst = |flags: &str| Flow {
        src_ip: "192.0.2.30".into(),
        dst_ip: "203.0.113.10".into(),
        proto: "tcp".into(),
        dport: 443,
        flags: flags.into(),
        pps: 1000,
        ..Default::default()
    };
    // A SYN meter meters a SYN however its spare bits are set, as text or in the packet...
    for flags in ["syn", "SYN", "syn,ece,cwr", "psh+syn"] {
        let d = pipe.decide(&burst(flags), T0);
        assert_eq!(d.reason, "FPGA meter 100 pps exceeded", "{flags}");
    }
    let ecn = serde_json::from_value::<Flow>(json!({
        "packet": STANDARD.encode(v4([192, 0, 2, 31], SERVER, TCP, &[], &tcp(40000, 443, SYN | ECE | CWR, &[], &[]))),
        "pps": 1000,
    }))
    .unwrap();
    assert_eq!(ecn.flags, "syn,ece,cwr");
    assert_eq!(pipe.decide(&ecn, T0).reason, "FPGA meter 100 pps exceeded");
    // ...and never a SYN-ACK, which is something else.
    for flags in ["syn,ack", "ack"] {
        assert_eq!(
            pipe.decide(&burst(flags), T0).reason,
            "no matching drop rule",
            "{flags}"
        );
    }
    // A rule's flags the vocabulary does not name compare as text, as they always did.
    assert_eq!(packet::tcp_flags("S"), None);
    assert!(packet::flags_meet(SYN, SYN | ECE | CWR | PSH));
    assert!(!packet::flags_meet(SYN, SYN | ACK));
    assert!(packet::flags_meet(SYN | ACK, SYN | ACK | ECE));
    assert!(!packet::flags_meet(ACK | PSH, ACK));
}
#[test]
fn a_packet_drives_the_rules_and_filters_as_its_own_headers_say() {
    let mut program = guarded("");
    program.games = vec![GameFilter {
        id: "bedrock".into(),
        dst_cidr: "203.0.113.10/32".into(),
        proto: "udp".into(),
        dport: 19132,
        profile: "raknet".into(),
        ..Default::default()
    }];
    program.challenge_secret = "secret".into();
    let mut pipe = Pipeline::new(program);
    let reflected = wire(&v4(
        [100, 64, 0, 53],
        SERVER,
        UDP,
        &[],
        &udp(53, 40000, &[0; 64]),
    ));
    assert_eq!(
        (
            reflected.src_ip.as_str(),
            reflected.proto.as_str(),
            reflected.sport,
            reflected.pps
        ),
        ("100.64.0.53", "udp", 53, 1)
    );
    let d = pipe.decide(&reflected, T0);
    assert_eq!((d.action.as_str(), d.rule_id.as_str()), ("drop", "dns"));
    let player = |payload: &[u8]| {
        wire(&v4(
            [192, 0, 2, 40],
            SERVER,
            UDP,
            &[],
            &udp(53000, 19132, payload),
        ))
    };
    let d = pipe.decide(&player(&[0x84, 0, 0]), T0 + 1);
    assert_eq!((d.action.as_str(), d.filter.as_str()), ("drop", "bedrock"));
    pipe.decide(&player(&[0x05]), T0 + 2);
    pipe.decide(&player(&[0x07]), T0 + 3);
    assert_eq!(pipe.decide(&player(&[0x84, 0, 0]), T0 + 4).action, "permit");
    // A later fragment carries no ports, so it is not the game's to judge.
    let later = wire(&fragment(
        v4([192, 0, 2, 41], SERVER, UDP, &[], &[0; 512]),
        40,
        1480,
        true,
    ));
    assert_eq!((later.dport, later.has_payload), (0, false));
    assert_eq!(pipe.decide(&later, T0 + 5).action, "permit");
    // A packet's bit rate is its own length.
    let mut on = guarded("");
    on.tunnels[0].attack_kbps = 100;
    let mut pipe = Pipeline::new(on);
    let big = serde_json::from_value::<Flow>(json!({
        "packet": STANDARD.encode(v4(CLIENT, [198, 51, 100, 10], UDP, &[], &udp(53, 40000, &[0; 1200]))),
        "pps": 10,
    }))
    .unwrap();
    // 10 packets of 1,228 bytes a second is 98 kbit/s, under; a second burst passes 100.
    assert_eq!(
        pipe.decide(&big, T0).reason,
        "watching only: tunnel contoso is under its attack thresholds"
    );
    assert_eq!(pipe.decide(&big, T0 + 100).rule_id, "dns");
}
#[test]
fn the_checks_are_counted_for_the_fabric_and_its_dashboards() {
    let mut pipe = Pipeline::new(node());
    for (_, bytes, _, _) in crafted() {
        pipe.decide(&wire(&bytes), T0);
    }
    let stats = pipe.stats(T0);
    let kept = serde_json::to_value(
        serde_json::from_value::<pathfinder::wire::Stats>(stats.clone()).unwrap(),
    )
    .unwrap();
    assert_eq!(kept["crafted"], stats["crafted"]);
    let mut m = Metrics::new();
    m.reports(
        &[json!({"node_id":"n1","name":"lhr-1","region":"lhr","stats":stats})],
        T0,
    );
    let text = m.render().unwrap();
    for line in [
        "scrubline_crafted_dropped_total{node=\"n1\",name=\"lhr-1\",region=\"lhr\",check=\"land\",class=\"stack\"} 2",
        "scrubline_crafted_dropped_total{node=\"n1\",name=\"lhr-1\",region=\"lhr\",check=\"length\",class=\"buffer\"} 6",
        "scrubline_crafted_observed_total{node=\"n1\",name=\"lhr-1\",region=\"lhr\",check=\"icmp\",class=\"protocol\"} 0",
        "scrubline_crafted_mode{node=\"n1\",name=\"lhr-1\",region=\"lhr\",mode=\"enforce\"} 1",
        "scrubline_crafted_mode{node=\"n1\",name=\"lhr-1\",region=\"lhr\",mode=\"off\"} 0",
        "scrubline_crafted_fragments_max{node=\"n1\",name=\"lhr-1\",region=\"lhr\"} 4096",
    ] {
        assert!(text.contains(line), "{line}\n{text}");
    }
}
/// An HTTP request to a site whose filter holds it to the rules servers keep.
fn site() -> Pipeline {
    Pipeline::new(Program {
        prefixes: vec!["203.0.113.0/24".into()],
        games: vec![GameFilter {
            id: "site".into(),
            dst_cidr: "203.0.113.20/32".into(),
            dport: 80,
            http: Some(GameHttp::default()),
            ..Default::default()
        }],
        ..Default::default()
    })
}
fn request(payload: &str) -> Flow {
    wire(&v4(
        CLIENT,
        [203, 0, 113, 20],
        TCP,
        &[],
        &tcp(40000, 80, PSH | ACK, &[], payload.as_bytes()),
    ))
}
#[test]
fn overlong_request_lines_and_headers_never_reach_the_server() {
    let mut pipe = site();
    let cookie = "c".repeat(4000);
    let headers: String = (0..98)
        .map(|i| format!("X-Header-{i}: value\r\n"))
        .collect();
    let fine = format!("GET / HTTP/1.1\r\nHost: shop\r\nCookie: {cookie}\r\n{headers}\r\n");
    let d = pipe.decide(&request(&fine), T0);
    assert_eq!(d.action, "permit", "{}", d.reason);
    let long_target = format!("GET /{} HTTP/1.1\r\nHost: shop\r\n\r\n", "a".repeat(9000));
    let long_header = format!(
        "GET / HTTP/1.1\r\nHost: shop\r\nCookie: {}\r\n\r\n",
        "c".repeat(9000)
    );
    let cut_header = format!(
        "GET / HTTP/1.1\r\nHost: shop\r\nCookie: {}",
        "c".repeat(9000)
    );
    let many: String = (0..101)
        .map(|i| format!("X-Header-{i}: value\r\n"))
        .collect();
    let many = format!("GET / HTTP/1.1\r\n{many}\r\n");
    for (payload, why) in [
        (long_target, "a request line longer than 8192 bytes"),
        (long_header, "a header line longer than 8192 bytes"),
        (cut_header, "a header line longer than 8192 bytes"),
        (many, "more than 100 header lines"),
    ] {
        let d = pipe.decide(&request(&payload), T0 + 1);
        assert_eq!(d.action, "drop", "{why}");
        assert!(d.reason.contains(why), "{}", d.reason);
    }
}
fn mangle(rng: &mut StdRng, mut p: Vec<u8>) -> Vec<u8> {
    for _ in 0..rng.gen_range(1..=4) {
        match rng.gen_range(0..7) {
            0 if !p.is_empty() => {
                let i = rng.gen_range(0..p.len());
                p[i] ^= 1 << rng.gen_range(0..8);
            }
            1 if !p.is_empty() => {
                let i = rng.gen_range(0..p.len());
                p[i] = rng.gen();
            }
            2 if !p.is_empty() => {
                let to = rng.gen_range(0..p.len());
                p.truncate(to);
            }
            3 => {
                for _ in 0..rng.gen_range(1..80) {
                    p.push(rng.gen());
                }
            }
            // The fields lengths are read from.
            4 if p.len() >= 8 => {
                let at = [2, 4, 6][rng.gen_range(0..3)];
                let v: u16 = rng.gen();
                p[at..at + 2].copy_from_slice(&v.to_be_bytes());
            }
            5 if p.len() >= 20 && p[0] >> 4 == 4 => seal(&mut p),
            _ => p.reverse(),
        }
    }
    p
}
/// Everything a node does with a packet, so the fuzzing below reaches every parser.
fn everything() -> Program {
    let mut program = guarded("");
    program.games = vec![
        GameFilter {
            id: "bedrock".into(),
            dst_cidr: "203.0.113.10/32".into(),
            proto: "udp".into(),
            dport: 19132,
            profile: "raknet".into(),
            ..Default::default()
        },
        GameFilter {
            id: "queries".into(),
            dst_cidr: "203.0.113.10/32".into(),
            proto: "udp".into(),
            dport: 27015,
            profile: "a2s".into(),
            ..Default::default()
        },
        GameFilter {
            id: "site".into(),
            dst_cidr: "203.0.113.20/32".into(),
            dport: 80,
            http: Some(GameHttp {
                rate_per_source: 50,
                max_body_bytes: 4096,
                ..Default::default()
            }),
            ..Default::default()
        },
    ];
    program.challenge_secret = "secret".into();
    program
}
#[test]
fn no_mangled_packet_or_random_input_brings_the_node_down() {
    let mut rng = StdRng::seed_from_u64(0x5eed);
    // Random bytes, half of them starting as an IP header would.
    for _ in 0..200_000 {
        let n = rng.gen_range(0..120);
        let mut p: Vec<u8> = (0..n).map(|_| rng.gen()).collect();
        if !p.is_empty() && rng.gen() {
            p[0] = [0x45, 0x46, 0x4f, 0x60][rng.gen_range(0..4)];
        }
        let (parsed, found) = packet::parse(&p);
        if found.is_none() {
            assert!(
                parsed.src.is_some() && parsed.data as usize <= p.len(),
                "{p:?}"
            );
        }
        let mut f = Flow {
            packet: p,
            ..Default::default()
        };
        packet::fill(&mut f);
    }
    // Real packets, legitimate and crafted, mangled, through everything a node does.
    let mut corpus: Vec<Vec<u8>> = legitimate().into_iter().map(|(_, p)| p).collect();
    corpus.extend(crafted().into_iter().map(|(_, p, _, _)| p));
    for payload in [
        "GET /index.html HTTP/1.1\r\nHost: shop\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
        "POST /api HTTP/1.1\r\nHost: shop\r\nContent-Length: 5\r\n\r\nhello",
        "POST /up HTTP/1.1\r\nHost: shop\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\n\r\nGET /b HTTP/1.1\r\nHost: a\r\n\r\n",
    ] {
        corpus.push(v4(CLIENT, [203, 0, 113, 20], TCP, &[], &tcp(40000, 80, PSH | ACK, &[], payload.as_bytes())));
    }
    for payload in [
        &[0x05, 0, 0xff][..],
        &[0x07; 32],
        &[0x84, 0, 0, 0],
        b"\xff\xff\xff\xffTSource Engine Query\0",
    ] {
        corpus.push(v4(CLIENT, SERVER, UDP, &[], &udp(53000, 19132, payload)));
        corpus.push(v4(CLIENT, SERVER, UDP, &[], &udp(53000, 27015, payload)));
    }
    let mut pipe = Pipeline::new(everything());
    for i in 0..60_000 {
        let base = corpus[rng.gen_range(0..corpus.len())].clone();
        let p = mangle(&mut rng, base);
        let mut f = wire(&p);
        f.pps = rng.gen_range(1..100_000);
        let d = pipe.decide(&f, T0 + i * 7);
        assert!(
            d.action == "permit" || d.action == "drop" || d.action == "challenge",
            "{d:?}"
        );
        if i % 1000 == 0 {
            serde_json::from_value::<pathfinder::wire::Stats>(pipe.stats(T0 + i * 7)).unwrap();
        }
    }
    // Payloads alone, as a datapath that sends records does.
    for i in 0..60_000 {
        let n = rng.gen_range(0..1600);
        let payload: Vec<u8> = (0..n).map(|_| rng.gen()).collect();
        let (dst, proto, dport) = [
            ("203.0.113.10", "udp", 19132),
            ("203.0.113.10", "udp", 27015),
            ("203.0.113.20", "tcp", 80),
        ][rng.gen_range(0..3)];
        let f = Flow {
            src_ip: format!("100.64.{}.{}", rng.gen_range(0..4), rng.gen_range(1..250)),
            dst_ip: dst.into(),
            proto: proto.into(),
            sport: rng.gen_range(1024..65535),
            dport,
            flags: ["", "syn", "ack", "psh,ack", "fin,ack", "syn,fin"][rng.gen_range(0..6)].into(),
            pps: rng.gen_range(1..1000),
            payload,
            has_payload: true,
            ..Default::default()
        };
        pipe.decide(&f, T0 + 1_000_000 + i);
    }
    // Flags as any text at all.
    for _ in 0..20_000 {
        let n = rng.gen_range(0..24);
        let s: String = (0..n)
            .map(|_| b"synackfinrstpshurgecwnoe,|+ SYNACK"[rng.gen_range(0..34)] as char)
            .collect();
        if let Some(bits) = packet::tcp_flags(&s) {
            assert!(packet::flags_meet(bits, bits), "{s}");
        }
    }
}
#[test]
fn the_api_guides_examples_are_dropped_as_it_says() {
    let guide = include_str!("../docs/api.md");
    let mut pipe = Pipeline::new(node());
    let examples: Vec<&str> = guide
        .split("-d '")
        .skip(1)
        .map(|rest| &rest[..rest.find('\'').unwrap()])
        .filter(|body| body.contains("\"packet\"") || body.contains("syn,fin"))
        .collect();
    assert_eq!(examples.len(), 2, "{examples:?}");
    for body in examples {
        let f: Flow = serde_json::from_str(body).unwrap();
        let d = pipe.decide(&f, T0);
        assert_eq!(
            serde_json::to_string(&d).unwrap(),
            r#"{"action":"drop","stage":"asic","reason":"crafted packet (stack): SYN and FIN set together, which no stack sends","check":"tcp_flags"}"#
        );
    }
}
#[test]
fn the_readmes_example_packet_is_the_clean_syn_it_says() {
    let readme = include_str!("../README.md");
    let at = readme.find("{\"packet\": \"").unwrap();
    let example: serde_json::Value =
        serde_json::from_str(&readme[at..at + readme[at..].find('}').unwrap() + 1]).unwrap();
    let f: Flow = serde_json::from_value(example).unwrap();
    assert_eq!(
        (
            f.src_ip.as_str(),
            f.dst_ip.as_str(),
            f.proto.as_str(),
            f.sport,
            f.dport,
            f.flags.as_str()
        ),
        ("192.0.2.1", "203.0.113.10", "tcp", 40000, 443, "syn")
    );
    assert_eq!(packet::parse(&f.packet).1, None);
}
