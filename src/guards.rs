//! Guards on what reaches a protected address, beside the reflection guard. Each answers a way
//! botnets and booters flood, and each judges a packet by what it is and what the server has
//! said, not by how much of it arrives alone.
//!
//! The protocol guard drops IP protocols a game server never receives. GRE is the one botnets use:
//! Mirai's GRE floods wrap junk in GRE so it passes filters that only look at TCP and UDP. Anything
//! but TCP, UDP and ICMP goes the same way, unless the policy lets it in; protocol 0 among them,
//! which an IP NULL attack sends.
//!
//! The ACK flood guard drops TCP that belongs to no connection the server has. Every segment of an
//! open connection but the opening SYN is answered by the server, so a source the server has not
//! sent TCP to has no connection to send ACKs, RSTs or FINs for, and a SYN-ACK answers only a SYN
//! the server sent. The return-traffic table knows whom the server has sent to, but only where the
//! server's traffic passes the node, so the guard waits until the node has watched it long enough
//! to know every connection open, and engages only while a prefix is flooded with such TCP: a
//! stray segment after a restart costs nobody anything.
//!
//! The SYN flood guard holds opening SYNs from sources the server has no connection with while a
//! prefix is flooded with them: a real client sends its SYN again a second or so later when the
//! first goes unanswered, and that retry passes, while a forged one is sent once.
//!
//! The fragment guard drops TCP and ICMP that arrive in fragments. TCP sizes its segments to the
//! path and ICMP's messages are small, so neither is ever fragmented by a real sender: fragmented
//! ACK floods and ICMP fragmentation floods are built that way to cost reassembly.
//!
//! The ICMP guard holds ICMP to a rate per prefix, drops echo replies the server never asked for
//! while a prefix is flooded with them, as a Smurf attack sends, and drops errors that quote no
//! packet the prefix sent.
//!
//! Floods are judged over an aggregate rather than each protected prefix alone: a prefix narrower
//! than a /24, or a /48 for IPv6, is judged with the rest of its /24 or /48, so an attack spread
//! thin across many addresses protected one by one shows whole.
use crate::model::Flow;
use crate::packet;
use crate::tuning::{self, Mode};
use ipnet::IpNet;
use serde_json::{json, Value};
use std::{
    borrow::Borrow,
    collections::{hash_map::RandomState, BTreeMap, HashMap},
    hash::{BuildHasher, Hash},
    net::IpAddr,
    sync::Arc,
};

/// The protocols every protected address receives.
pub const ALWAYS: [&str; 3] = ["tcp", "udp", "icmp"];
/// The protocols besides those that rules and the allow list name.
pub const PROTOCOLS: [&str; 6] = ["gre", "esp", "ah", "sctp", "ipip", "ipv6"];

/// How a protocol is known, from its name or its number; None for a name that is not one.
pub fn protocol(name: &str) -> Option<String> {
    if let Ok(n) = name.trim().parse::<u8>() {
        return Some(packet::protocol_name(n));
    }
    let lower = name.trim().to_ascii_lowercase();
    (ALWAYS.contains(&lower.as_str()) || PROTOCOLS.contains(&lower.as_str())).then_some(lower)
}

/// An aggregate's name, shared by every flow to it without being copied.
pub type Key = Arc<str>;
/// The aggregate a protected prefix's floods are judged over: the prefix itself, or for one
/// narrower than a /24 (IPv4) or a /48 (IPv6), the /24 or /48 that holds it.
pub fn aggregate(prefix: &str, net: &IpNet) -> String {
    aggregate_at(prefix, net, (24, 48))
}
/// The same, at the policy's lengths for IPv4 and IPv6.
pub fn aggregate_at(prefix: &str, net: &IpNet, (v4, v6): (u8, u8)) -> String {
    let wide = match net {
        IpNet::V4(_) => v4,
        IpNet::V6(_) => v6,
    };
    if net.prefix_len() <= wide {
        return prefix.into();
    }
    IpNet::new(net.addr(), wide)
        .map(|n| n.trunc().to_string())
        .unwrap_or_else(|_| prefix.into())
}

/// What a key took this second, and until when it counts as flooded.
#[derive(Default)]
struct Watch {
    second: i64,
    pps: u64,
    until: i64,
}
/// Which keys are flooded with what a guard counts. One watch for each key that has taken any, so
/// as many as the program has aggregates (times vectors, for the reflection guard).
pub struct Engagement<K> {
    watches: HashMap<K, Watch>,
}
impl<K> Default for Engagement<K> {
    fn default() -> Self {
        Self {
            watches: HashMap::new(),
        }
    }
}
impl<K: Hash + Eq + Clone> Engagement<K> {
    /// Counts what a key took, and says whether it is flooded: by this second's being over the
    /// threshold, or by an earlier second's within the hold.
    pub fn engaged_by(&mut self, key: &K, pps: u64, threshold: u64, hold: i64, now: i64) -> bool {
        if !self.watches.contains_key(key) {
            self.watches.insert(key.clone(), Watch::default());
        }
        let w = self.watches.get_mut(key).unwrap();
        let second = now.div_euclid(1000);
        if w.second != second {
            w.second = second;
            w.pps = 0;
        }
        w.pps = w.pps.saturating_add(pps);
        if w.pps > threshold {
            w.until = now + hold;
        }
        now < w.until
    }
    pub fn engaged<Q: Hash + Eq + ?Sized>(&self, key: &Q, now: i64) -> bool
    where
        K: Borrow<Q>,
    {
        self.watches.get(key).is_some_and(|w| now < w.until)
    }
    /// How many of the keys `which` picks are flooded now.
    pub fn count(&self, now: i64, mut which: impl FnMut(&K) -> bool) -> usize {
        self.watches
            .iter()
            .filter(|(k, w)| now < w.until && which(k))
            .count()
    }
    pub fn retain(&mut self, mut keep: impl FnMut(&K) -> bool) {
        self.watches.retain(|k, _| keep(k));
    }
}

/// What the protocol guard has done.
#[derive(Default)]
pub struct ProtocolGuard {
    /// Per protocol: flows dropped, and flows observed.
    counts: BTreeMap<String, [u64; 2]>,
}
impl ProtocolGuard {
    /// The protocol a flow carries, when it is one the protected addresses do not receive. A flow
    /// that names no protocol, or one the node does not know, is not judged.
    pub fn stopped(&self, proto: &str, s: &tuning::Protocols) -> Option<String> {
        if s.mode == Mode::Off || proto.is_empty() || proto.eq_ignore_ascii_case("any") {
            return None;
        }
        let name = protocol(proto)?;
        if ALWAYS.contains(&name.as_str()) || s.allow.contains(&name) {
            return None;
        }
        Some(name)
    }
    /// Counts a flow of the protocol, as dropped or as observed.
    pub fn count(&mut self, name: &str, observed: bool) {
        // At most one entry for each of the 256 protocols.
        self.counts.entry(name.into()).or_default()[usize::from(observed)] += 1;
    }
    pub fn stats(&self, s: &tuning::Protocols) -> Value {
        let rows: Vec<_> = self
            .counts
            .iter()
            .map(|(p, [d, o])| json!({"protocol": p, "dropped": d, "observed": o}))
            .collect();
        json!({
            "mode": s.mode.name(),
            "allow": s.allow,
            "dropped": self.counts.values().map(|c| c[0]).sum::<u64>(),
            "observed": self.counts.values().map(|c| c[1]).sum::<u64>(),
            "by_protocol": rows,
        })
    }
}
/// Why a flow of the protocol is dropped.
pub fn why(name: &str) -> String {
    match name {
        "gre" => "GRE flood: GRE sent to a protected address, which no game server receives".into(),
        "0" => "IP NULL: protocol 0, which carries nothing, sent to a protected address".into(),
        _ => format!(
            "IP protocol {name} sent to a protected address, which receives only TCP, UDP and ICMP"
        ),
    }
}

/// How many packets a second of TCP belonging to no connection a prefix takes before its guard
/// engages, when the policy names no other number.
pub const ENGAGE_PPS: u64 = 5000;
/// How long a prefix's guard stays engaged after the last second its unsolicited TCP was over the
/// threshold.
pub const ACK_HOLD: i64 = 60_000;
/// How long the node must have watched a prefix's own traffic before its guard may engage: as long
/// as the return-traffic table keeps an address the server has gone quiet to, so every connection
/// open when the watch began has been seen.
pub const ACK_WARM: i64 = 120_000;
/// How recently the server must have sent a source TCP for the source's segments to belong to a
/// connection it has.
pub const TALKED_WITHIN: i64 = 120_000;
/// How long after the server answers a SYN the client may finish its handshake, and how many
/// segments it may send before the server's own say the connection is open: its ACK and the
/// first of what it has to say, as a real client sends, and no flood of them.
pub const HANDSHAKE: i64 = 10_000;
pub const HANDSHAKE_SEGMENTS: u32 = 4;

/// What the ACK flood guard has done.
#[derive(Default)]
pub struct AckGuard {
    floods: Engagement<Key>,
    /// Segments dropped, and segments observed.
    pub counts: [u64; 2],
}
/// Whether a segment's flags say it belongs to an open connection: anything but a SYN that opens
/// one. A record that names no flags says nothing either way.
pub fn mid_connection(flags: &str) -> bool {
    packet::tcp_flags(flags).is_some_and(|f| f & packet::SYN == 0 || f & packet::ACK != 0)
}
/// Whether a segment opens a connection: a SYN without an ACK.
pub fn opening(flags: &str) -> bool {
    packet::tcp_flags(flags).is_some_and(|f| f & packet::SYN != 0 && f & packet::ACK == 0)
}
/// Whether a segment is a SYN-ACK, which only answers a SYN.
pub fn syn_ack(flags: &str) -> bool {
    packet::tcp_flags(flags).is_some_and(|f| f & packet::SYN != 0 && f & packet::ACK != 0)
}
/// Why a segment for no connection is dropped, named for the flood it is part of.
pub fn unsolicited_why(flags: &str) -> &'static str {
    match packet::tcp_flags(flags) {
        Some(f) if f & packet::SYN != 0 => {
            "SYN-ACK flood: a SYN-ACK answering no SYN the server sent, while the prefix is flooded with TCP for no connection"
        }
        Some(f) if f & (packet::RST | packet::FIN) != 0 => {
            "RST/FIN flood: a reset or close for a connection the server never had, while the prefix is flooded with TCP for no connection"
        }
        _ => {
            "ACK flood: TCP for a connection the server never had, while the prefix is flooded with it"
        }
    }
}
impl AckGuard {
    /// Forgets the aggregates no longer in the program.
    pub fn load(&mut self, live: &dyn Fn(&str) -> bool) {
        self.floods.retain(|a| live(a));
    }
    /// Counts TCP that belongs to no connection at an aggregate, and says whether its guard is
    /// engaged: by this second's TCP being over the threshold, or by an earlier second's within
    /// the hold.
    pub fn engaged_by(&mut self, aggregate: &Key, pps: u64, s: &tuning::Ack, now: i64) -> bool {
        self.floods
            .engaged_by(aggregate, pps, s.engage_pps, s.hold, now)
    }
    pub fn engaged(&self, aggregate: &str, now: i64) -> bool {
        self.floods.engaged(aggregate, now)
    }
    pub fn stats(&self, s: &tuning::Ack, now: i64) -> Value {
        json!({
            "mode": s.mode.name(),
            "engage_pps": s.engage_pps,
            "engaged": self.floods.count(now, |_| true),
            "dropped": self.counts[0],
            "observed": self.counts[1],
        })
    }
}

/// How many packets a second of opening SYNs from sources the server has no connection with an
/// aggregate takes before its guard engages, when the policy names no other number.
pub const SYN_ENGAGE_PPS: u64 = 2000;
/// How long the SYN flood guard stays engaged after the last second over its threshold.
pub const SYN_HOLD: i64 = 60_000;
/// How many SYNs a second a record may count on one connection and still be a client retrying:
/// one sends its SYN again a second, then two, then four after the first, and no faster.
pub const SYN_RETRIES: i64 = 3;
/// Bits in each second's record of the opening SYNs seen, and how many seconds are kept, this one
/// included: a client's first retry comes a second (Linux, macOS, recent Windows) to three (older
/// Windows) after its SYN. Each connection sets two bits, so a forged SYN finds both of its set by
/// others rarely: about one in five hundred at 100,000 a second.
const SYN_BITS: usize = 1 << 23;
const SYN_SECONDS: usize = 5;
/// What the SYN flood guard has done.
pub struct SynGuard {
    floods: Engagement<Key>,
    /// The opening SYNs seen in each of the last SYN_SECONDS seconds, as bits set by a keyed hash
    /// of their connection, and which second each holds. Allocated on the first SYN.
    seen: Vec<u64>,
    seconds: [i64; SYN_SECONDS],
    hasher: RandomState,
    /// SYNs dropped, SYNs observed, and SYNs let through as a client's retry.
    pub counts: [u64; 3],
}
impl Default for SynGuard {
    fn default() -> Self {
        Self {
            floods: Engagement::default(),
            seen: Vec::new(),
            seconds: [i64::MIN; SYN_SECONDS],
            hasher: RandomState::new(),
            counts: [0; 3],
        }
    }
}
impl SynGuard {
    /// Forgets the aggregates no longer in the program.
    pub fn load(&mut self, live: &dyn Fn(&str) -> bool) {
        self.floods.retain(|a| live(a));
    }
    /// Records an opening SYN, and says whether its connection sent one within the last `within`
    /// seconds before this one's: whether it is a retry.
    pub fn retried(&mut self, f: &Flow, within: i64, now: i64) -> bool {
        const WORDS: usize = SYN_BITS / 64;
        if self.seen.is_empty() {
            self.seen = vec![0; WORDS * SYN_SECONDS];
        }
        let second = now.div_euclid(1000);
        let slot = second.rem_euclid(SYN_SECONDS as i64) as usize;
        if self.seconds[slot] != second {
            self.seen[slot * WORDS..(slot + 1) * WORDS].fill(0);
            self.seconds[slot] = second;
        }
        let h = self
            .hasher
            .hash_one((&f.src_ip, f.sport, &f.dst_ip, f.dport));
        let bits = [h as usize % SYN_BITS, (h >> 32) as usize % SYN_BITS];
        let set =
            |seen: &[u64], s: usize, b: usize| seen[s * WORDS + b / 64] & (1 << (b % 64)) != 0;
        let found = (0..SYN_SECONDS).any(|s| {
            let age = second.saturating_sub(self.seconds[s]);
            (1..=within.min(SYN_SECONDS as i64 - 1)).contains(&age)
                && bits.iter().all(|&b| set(&self.seen, s, b))
        });
        for b in bits {
            self.seen[slot * WORDS + b / 64] |= 1 << (b % 64);
        }
        found
    }
    /// Counts opening SYNs from sources the server has no connection with at an aggregate, and
    /// says whether its guard is engaged.
    pub fn engaged_by(&mut self, aggregate: &Key, pps: u64, s: &tuning::Syn, now: i64) -> bool {
        self.floods
            .engaged_by(aggregate, pps, s.engage_pps, s.hold, now)
    }
    pub fn engaged(&self, aggregate: &str, now: i64) -> bool {
        self.floods.engaged(aggregate, now)
    }
    /// Bytes the record of SYNs holds, once allocated.
    pub fn bytes(&self) -> usize {
        self.seen.len() * 8
    }
    pub fn stats(&self, s: &tuning::Syn, now: i64) -> Value {
        json!({
            "mode": s.mode.name(),
            "engage_pps": s.engage_pps,
            "engaged": self.floods.count(now, |_| true),
            "dropped": self.counts[0],
            "observed": self.counts[1],
            "retried": self.counts[2],
        })
    }
}
/// Why an opening SYN is dropped.
pub const SYN_WHY: &str = "SYN flood: an opening SYN from a source the server has no connection with, while the prefix is flooded with them; a real client sends it again a second or so later, and that passes";

/// The protocols whose fragments the fragment guard can drop, in the order of its counters.
pub const FRAGMENTED: [&str; 4] = ["tcp", "icmp", "udp", "other"];
/// What the fragment guard has done.
#[derive(Default)]
pub struct FragmentGuard {
    /// Per protocol in FRAGMENTED order: fragments dropped, and fragments observed.
    pub counts: [[u64; 2]; 4],
}
impl FragmentGuard {
    /// Which of FRAGMENTED a packet is a fragment of, if it is one the settings drop: its first
    /// fragment or any after, which carry the protocol in their IP header (IPv4) or fragment
    /// header (IPv6).
    pub fn fragment(&self, p: &packet::Packet, s: &tuning::Fragments) -> Option<usize> {
        if s.mode == Mode::Off || !p.fragment() {
            return None;
        }
        let i = match p.proto {
            6 => 0,
            1 | 58 => 1,
            17 => 2,
            _ => 3,
        };
        s.protocols[i].then_some(i)
    }
    pub fn stats(&self, s: &tuning::Fragments) -> Value {
        let rows: Vec<_> = FRAGMENTED
            .iter()
            .zip(self.counts)
            .map(|(p, [d, o])| json!({"protocol": p, "dropped": d, "observed": o}))
            .collect();
        let on: Vec<_> = FRAGMENTED
            .iter()
            .zip(s.protocols)
            .filter(|(_, on)| *on)
            .map(|(p, _)| *p)
            .collect();
        json!({
            "mode": s.mode.name(),
            "protocols": on,
            "dropped": self.counts.iter().map(|c| c[0]).sum::<u64>(),
            "observed": self.counts.iter().map(|c| c[1]).sum::<u64>(),
            "by_protocol": rows,
        })
    }
}
/// Why a fragment of the protocol is dropped.
pub fn fragment_why(i: usize) -> &'static str {
    match i {
        0 => "fragmented ACK flood: TCP in fragments, which no TCP stack sends, since TCP sizes its segments to the path",
        1 => "ICMP fragmentation flood: ICMP in fragments, which no ping or error a game server needs arrives as",
        2 => "UDP fragment flood: UDP in fragments, which the policy says the protected addresses never receive",
        _ => "a fragment of a protocol the policy says arrives whole",
    }
}

/// How many packets a second of ICMP, echo replies aside, an aggregate takes before the rest are
/// dropped, and how many echo replies the server never asked for before those are, when the
/// policy names no other numbers.
pub const ICMP_LIMIT_PPS: u64 = 1000;
pub const SMURF_PPS: u64 = 1000;
/// How long an aggregate counts as flooded with echo replies after the last second over.
pub const SMURF_HOLD: i64 = 60_000;
/// The bit that stands for an echo request among what the origin has asked an address, above the
/// reflection guard's vectors.
pub const ECHO_BIT: u32 = 1 << 31;
/// What the ICMP guard drops, in the order of its counters.
pub const ICMP_KINDS: [&str; 4] = ["flood", "smurf", "error", "type"];
/// What an ICMP message is to the guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Icmp {
    /// An echo reply, which answers an echo request.
    Reply,
    /// An error, which quotes the packet it is about: whether that packet came from the
    /// prefix the error is sent to.
    Error { from_prefix: bool },
    /// Anything else: an echo request, another message, or a record that does not say which.
    Other,
}
/// What an ICMP packet is, read from its header and, for an error, the packet it quotes.
pub fn icmp_of(p: &packet::Packet, prefix: &IpNet) -> Icmp {
    let Some((kind, _)) = p.icmp else {
        return Icmp::Other;
    };
    let error = if p.v6 {
        matches!(kind, 1..=4)
    } else {
        matches!(kind, 3 | 11 | 12)
    };
    if error {
        let q = p.payload;
        let quoted = match q.first().map(|b| b >> 4) {
            Some(4) if q.len() >= 20 => Some(IpAddr::from([q[12], q[13], q[14], q[15]])),
            Some(6) if q.len() >= 40 => {
                let mut a = [0u8; 16];
                a.copy_from_slice(&q[8..24]);
                Some(IpAddr::from(a))
            }
            _ => None,
        };
        return Icmp::Error {
            from_prefix: quoted.is_some_and(|a| prefix.contains(&a)),
        };
    }
    if kind == if p.v6 { 129 } else { 0 } {
        Icmp::Reply
    } else {
        Icmp::Other
    }
}
/// Whether an ICMP packet the origin sends is an echo request, which asks for a reply.
pub fn echo_request(p: &packet::Packet) -> bool {
    p.icmp
        .is_some_and(|(kind, _)| kind == if p.v6 { 128 } else { 8 })
}
/// What the ICMP guard has done.
#[derive(Default)]
pub struct IcmpGuard {
    /// The ICMP each aggregate took this second, echo replies aside: one for each aggregate that
    /// has taken any.
    seconds: HashMap<Key, (i64, u64)>,
    replies: Engagement<Key>,
    /// Per kind in ICMP_KINDS order: packets dropped, and packets observed.
    pub counts: [[u64; 2]; 4],
}
impl IcmpGuard {
    /// Forgets the aggregates no longer in the program.
    pub fn load(&mut self, live: &dyn Fn(&str) -> bool) {
        self.seconds.retain(|a, _| live(a));
        self.replies.retain(|a| live(a));
    }
    /// Counts ICMP that is not an echo reply at an aggregate, and says whether this second's is
    /// over the limit.
    pub fn over_limit(&mut self, aggregate: &Key, pps: u64, limit: u64, now: i64) -> bool {
        if !self.seconds.contains_key(aggregate) {
            self.seconds.insert(aggregate.clone(), (0, 0));
        }
        let (second, count) = self.seconds.get_mut(aggregate).unwrap();
        let this = now.div_euclid(1000);
        if *second != this {
            *second = this;
            *count = 0;
        }
        *count = count.saturating_add(pps);
        *count > limit
    }
    /// Counts echo replies the server never asked for at an aggregate, and says whether it is
    /// flooded with them.
    pub fn smurfed_by(&mut self, aggregate: &Key, pps: u64, s: &tuning::Icmp, now: i64) -> bool {
        self.replies
            .engaged_by(aggregate, pps, s.smurf_pps, s.hold, now)
    }
    pub fn smurfed(&self, aggregate: &str, now: i64) -> bool {
        self.replies.engaged(aggregate, now)
    }
    pub fn stats(&self, s: &tuning::Icmp, now: i64) -> Value {
        let rows: Vec<_> = ICMP_KINDS
            .iter()
            .zip(self.counts)
            .map(|(k, [d, o])| json!({"kind": k, "dropped": d, "observed": o}))
            .collect();
        json!({
            "mode": s.mode.name(),
            "limit_pps": s.limit_pps,
            "smurf_pps": s.smurf_pps,
            "smurf_engaged": self.replies.count(now, |_| true),
            "dropped": self.counts.iter().map(|c| c[0]).sum::<u64>(),
            "observed": self.counts.iter().map(|c| c[1]).sum::<u64>(),
            "kinds": rows,
        })
    }
}
/// Why ICMP of a kind is dropped.
pub fn icmp_why(i: usize, limit: u64, kind: u8) -> String {
    match i {
        0 => format!("ICMP flood: more than {limit} ICMP packets a second to the prefix, echo replies aside"),
        1 => "Smurf: an echo reply to a ping the server never sent, while the prefix is flooded with them".into(),
        2 => "forged ICMP error: an error about a packet the protected prefix never sent, as BlackNurse floods with".into(),
        _ => format!("ICMP type {kind}, which the policy drops"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Program, ProtocolPolicy};
    /// The policy's settings for a program, as the pipeline resolves them.
    fn settings(p: Program) -> tuning::Guards {
        tuning::resolve(&p).guards.remove(0)
    }
    #[test]
    fn protocols_are_known_by_name_or_number() {
        assert_eq!(protocol("GRE").as_deref(), Some("gre"));
        assert_eq!(protocol("47").as_deref(), Some("gre"));
        assert_eq!(protocol("50").as_deref(), Some("esp"));
        assert_eq!(protocol("253").as_deref(), Some("253"));
        assert_eq!(protocol("udp").as_deref(), Some("udp"));
        assert_eq!(protocol("58").as_deref(), Some("icmp"));
        for not in ["", "quic", "256", "-1", "gre6"] {
            assert_eq!(protocol(not), None, "{not}");
        }
    }
    #[test]
    fn the_protocol_guard_stops_what_is_neither_always_received_nor_allowed() {
        let g = ProtocolGuard::default();
        let s = settings(Program::default()).protocols;
        for passes in ["tcp", "UDP", "icmp", "", "any", "quic"] {
            assert_eq!(g.stopped(passes, &s), None, "{passes}");
        }
        assert_eq!(g.stopped("gre", &s).as_deref(), Some("gre"));
        assert_eq!(g.stopped("47", &s).as_deref(), Some("gre"));
        assert_eq!(g.stopped("esp", &s).as_deref(), Some("esp"));
        // IP NULL: protocol 0.
        assert_eq!(g.stopped("0", &s).as_deref(), Some("0"));
        assert!(why("0").starts_with("IP NULL: "));
        let s = settings(Program {
            protocols: Some(ProtocolPolicy {
                mode: String::new(),
                allow: vec!["50".into(), "AH".into()],
            }),
            ..Default::default()
        })
        .protocols;
        assert_eq!(g.stopped("esp", &s), None);
        assert_eq!(g.stopped("ah", &s), None);
        assert_eq!(g.stopped("gre", &s).as_deref(), Some("gre"));
        let s = settings(Program {
            protocols: Some(ProtocolPolicy {
                mode: "off".into(),
                allow: vec![],
            }),
            ..Default::default()
        })
        .protocols;
        assert_eq!(g.stopped("gre", &s), None);
    }
    #[test]
    fn only_segments_of_an_open_connection_are_mid_connection() {
        for mid in [
            "ack", "psh,ack", "fin,ack", "rst", "rst,ack", "syn,ack", "ack+ece", "none",
        ] {
            assert!(mid_connection(mid), "{mid}");
            assert!(!opening(mid), "{mid}");
        }
        for not in ["syn", "syn,ece,cwr", "", "bogus"] {
            assert!(!mid_connection(not), "{not}");
        }
        assert!(opening("syn") && opening("syn,ece,cwr"));
        assert!(syn_ack("syn,ack") && !syn_ack("syn") && !syn_ack("ack"));
        assert!(unsolicited_why("syn,ack").starts_with("SYN-ACK flood: "));
        assert!(unsolicited_why("rst").starts_with("RST/FIN flood: "));
        assert!(unsolicited_why("fin,ack").starts_with("RST/FIN flood: "));
        assert!(unsolicited_why("psh,ack").starts_with("ACK flood: "));
    }
    #[test]
    fn floods_are_judged_over_a_slash_24_or_a_slash_48() {
        let net = |s: &str| s.parse::<IpNet>().unwrap();
        assert_eq!(
            aggregate("203.0.113.10/32", &net("203.0.113.10/32")),
            "203.0.113.0/24"
        );
        assert_eq!(
            aggregate("203.0.113.128/25", &net("203.0.113.128/25")),
            "203.0.113.0/24"
        );
        assert_eq!(
            aggregate("203.0.112.0/22", &net("203.0.112.0/22")),
            "203.0.112.0/22"
        );
        assert_eq!(
            aggregate("2001:db8:1:2::/64", &net("2001:db8:1:2::/64")),
            "2001:db8:1::/48"
        );
        assert_eq!(
            aggregate("2001:db8::/32", &net("2001:db8::/32")),
            "2001:db8::/32"
        );
    }
    #[test]
    fn the_ack_guard_engages_over_its_threshold_and_holds() {
        let mut g = AckGuard::default();
        let s = settings(Program::default()).ack;
        let p: Key = "203.0.113.0/24".into();
        assert!(!g.engaged_by(&p, 4000, &s, 1_000));
        assert!(!g.engaged_by(&p, 1000, &s, 1_500));
        assert!(g.engaged_by(&p, 1, &s, 1_900));
        // Quiet again, it holds for a minute after the last second over.
        assert!(g.engaged_by(&p, 1, &s, 2_100));
        assert!(g.engaged(&p, 1_900 + ACK_HOLD - 1));
        assert!(!g.engaged(&p, 1_900 + ACK_HOLD));
        assert!(!g.engaged("198.51.100.0/24", 1_900));
        g.load(&|_| false);
        assert!(
            !g.engaged(&p, 2_000),
            "a prefix no longer in the program is forgotten"
        );
    }
    fn syn(src: &str, sport: i64) -> Flow {
        Flow {
            src_ip: src.into(),
            dst_ip: "203.0.113.10".into(),
            proto: "tcp".into(),
            sport,
            dport: 443,
            flags: "syn".into(),
            pps: 1,
            ..Default::default()
        }
    }
    #[test]
    fn a_retry_is_a_syn_on_the_same_connection_a_second_or_more_later() {
        let mut g = SynGuard::default();
        let first = syn("192.0.2.1", 50_000);
        assert!(!g.retried(&first, 4, 10_000));
        // Within the same second is no retry; one to four seconds later is.
        assert!(!g.retried(&first, 4, 10_900));
        assert!(g.retried(&first, 4, 11_000));
        assert!(g.retried(&first, 4, 14_999));
        // Another port, or another source, is another connection.
        assert!(!g.retried(&syn("192.0.2.1", 50_001), 4, 11_000));
        assert!(!g.retried(&syn("192.0.2.2", 50_000), 4, 11_000));
        // Five seconds on, the first second's record is gone.
        let lone = syn("192.0.2.3", 1);
        assert!(!g.retried(&lone, 4, 20_000));
        assert!(!g.retried(&lone, 4, 25_000));
        assert_eq!(g.bytes(), SYN_BITS / 8 * SYN_SECONDS);
        // A forged flood from a fresh source each time finds no retry among its own, or almost
        // none: the bits are set by a keyed hash of each connection.
        let mut passed = 0;
        for i in 0..100_000u32 {
            let f = syn(
                &format!("10.{}.{}.{}", i >> 16, (i >> 8) & 255, i & 255),
                1024 + i64::from(i % 60_000),
            );
            passed += u32::from(g.retried(&f, 4, 30_000 + i64::from(i) / 50));
        }
        assert!(
            passed < 100,
            "{passed} of 100,000 forged SYNs passed as retries"
        );
    }
    #[test]
    fn icmp_is_held_to_a_limit_and_echo_replies_to_what_was_asked() {
        let mut g = IcmpGuard::default();
        let s = settings(Program::default()).icmp;
        let a: Key = "203.0.113.0/24".into();
        assert!(!g.over_limit(&a, ICMP_LIMIT_PPS, s.limit_pps, 1_000));
        assert!(g.over_limit(&a, 1, s.limit_pps, 1_500));
        assert!(
            !g.over_limit(&a, 1, s.limit_pps, 2_000),
            "a new second starts over"
        );
        assert!(!g.smurfed_by(&a, SMURF_PPS, &s, 1_000));
        assert!(g.smurfed_by(&a, 1, &s, 1_001));
        assert!(g.smurfed(&a, 1_001 + SMURF_HOLD - 1));
        assert!(!g.smurfed(&a, 1_001 + SMURF_HOLD));
    }
}
