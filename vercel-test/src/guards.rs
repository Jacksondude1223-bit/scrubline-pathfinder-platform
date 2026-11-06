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
use crate::model::{
    AckFloodPolicy, Flow, FragmentPolicy, IcmpPolicy, ProtocolPolicy, SynFloodPolicy,
};
use crate::packet;
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
/// Whether a mode is one a guard runs in.
fn mode(m: Option<&str>) -> String {
    match m {
        Some(mode @ ("observe" | "off")) => mode.into(),
        _ => "enforce".into(),
    }
}

/// An aggregate's name, shared by every flow to it without being copied.
pub type Key = Arc<str>;
/// The aggregate a protected prefix's floods are judged over: the prefix itself, or for one
/// narrower than a /24 (IPv4) or a /48 (IPv6), the /24 or /48 that holds it.
pub fn aggregate(prefix: &str, net: &IpNet) -> String {
    let wide = match net {
        IpNet::V4(_) => 24,
        IpNet::V6(_) => 48,
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

/// What the protocol guard does and has done.
pub struct ProtocolGuard {
    /// "enforce", "observe" or "off".
    pub mode: String,
    allow: Vec<String>,
    /// Per protocol: flows dropped, and flows observed.
    counts: BTreeMap<String, [u64; 2]>,
}
impl Default for ProtocolGuard {
    fn default() -> Self {
        Self {
            mode: "enforce".into(),
            allow: Vec::new(),
            counts: BTreeMap::new(),
        }
    }
}
impl ProtocolGuard {
    pub fn load(&mut self, policy: Option<&ProtocolPolicy>) {
        self.mode = mode(policy.map(|p| p.mode.as_str()));
        self.allow = policy
            .map(|p| p.allow.iter().filter_map(|a| protocol(a)).collect())
            .unwrap_or_default();
    }
    /// The protocol a flow carries, when it is one the protected addresses do not receive. A flow
    /// that names no protocol, or one the node does not know, is not judged.
    pub fn stopped(&self, proto: &str) -> Option<String> {
        if self.mode == "off" || proto.is_empty() || proto.eq_ignore_ascii_case("any") {
            return None;
        }
        let name = protocol(proto)?;
        if ALWAYS.contains(&name.as_str()) || self.allow.contains(&name) {
            return None;
        }
        Some(name)
    }
    /// Counts a flow of the protocol, as dropped or as observed.
    pub fn count(&mut self, name: &str, observed: bool) {
        // At most one entry for each of the 256 protocols.
        self.counts.entry(name.into()).or_default()[usize::from(observed)] += 1;
    }
    pub fn stats(&self) -> Value {
        let rows: Vec<_> = self
            .counts
            .iter()
            .map(|(p, [d, o])| json!({"protocol": p, "dropped": d, "observed": o}))
            .collect();
        json!({
            "mode": self.mode,
            "allow": self.allow,
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

/// What the ACK flood guard does and has done.
pub struct AckGuard {
    /// "enforce", "observe" or "off".
    pub mode: String,
    pub engage_pps: u64,
    floods: Engagement<Key>,
    /// Segments dropped, and segments observed.
    pub counts: [u64; 2],
}
impl Default for AckGuard {
    fn default() -> Self {
        Self {
            mode: "enforce".into(),
            engage_pps: ENGAGE_PPS,
            floods: Engagement::default(),
            counts: [0; 2],
        }
    }
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
    pub fn load(&mut self, policy: Option<&AckFloodPolicy>, live: &dyn Fn(&str) -> bool) {
        self.mode = mode(policy.map(|p| p.mode.as_str()));
        self.engage_pps = policy
            .map(|p| p.engage_pps)
            .filter(|&p| p > 0)
            .map_or(ENGAGE_PPS, |p| p as u64);
        self.floods.retain(|a| live(a));
    }
    /// Counts TCP that belongs to no connection at an aggregate, and says whether its guard is
    /// engaged: by this second's TCP being over the threshold, or by an earlier second's within
    /// the hold.
    pub fn engaged_by(&mut self, aggregate: &Key, pps: u64, now: i64) -> bool {
        self.floods
            .engaged_by(aggregate, pps, self.engage_pps, ACK_HOLD, now)
    }
    pub fn engaged(&self, aggregate: &str, now: i64) -> bool {
        self.floods.engaged(aggregate, now)
    }
    pub fn stats(&self, now: i64) -> Value {
        json!({
            "mode": self.mode,
            "engage_pps": self.engage_pps,
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
/// What the SYN flood guard does and has done.
pub struct SynGuard {
    /// "enforce", "observe" or "off".
    pub mode: String,
    pub engage_pps: u64,
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
            mode: "enforce".into(),
            engage_pps: SYN_ENGAGE_PPS,
            floods: Engagement::default(),
            seen: Vec::new(),
            seconds: [i64::MIN; SYN_SECONDS],
            hasher: RandomState::new(),
            counts: [0; 3],
        }
    }
}
impl SynGuard {
    pub fn load(&mut self, policy: Option<&SynFloodPolicy>, live: &dyn Fn(&str) -> bool) {
        self.mode = mode(policy.map(|p| p.mode.as_str()));
        self.engage_pps = policy
            .map(|p| p.engage_pps)
            .filter(|&p| p > 0)
            .map_or(SYN_ENGAGE_PPS, |p| p as u64);
        self.floods.retain(|a| live(a));
    }
    /// Records an opening SYN, and says whether its connection sent one in an earlier second the
    /// guard still remembers: whether it is a retry.
    pub fn retried(&mut self, f: &Flow, now: i64) -> bool {
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
            (1..SYN_SECONDS as i64).contains(&age) && bits.iter().all(|&b| set(&self.seen, s, b))
        });
        for b in bits {
            self.seen[slot * WORDS + b / 64] |= 1 << (b % 64);
        }
        found
    }
    /// Counts opening SYNs from sources the server has no connection with at an aggregate, and
    /// says whether its guard is engaged.
    pub fn engaged_by(&mut self, aggregate: &Key, pps: u64, now: i64) -> bool {
        self.floods
            .engaged_by(aggregate, pps, self.engage_pps, SYN_HOLD, now)
    }
    pub fn engaged(&self, aggregate: &str, now: i64) -> bool {
        self.floods.engaged(aggregate, now)
    }
    /// Bytes the record of SYNs holds, once allocated.
    pub fn bytes(&self) -> usize {
        self.seen.len() * 8
    }
    pub fn stats(&self, now: i64) -> Value {
        json!({
            "mode": self.mode,
            "engage_pps": self.engage_pps,
            "engaged": self.floods.count(now, |_| true),
            "dropped": self.counts[0],
            "observed": self.counts[1],
            "retried": self.counts[2],
        })
    }
}
/// Why an opening SYN is dropped.
pub const SYN_WHY: &str = "SYN flood: an opening SYN from a source the server has no connection with, while the prefix is flooded with them; a real client sends it again a second or so later, and that passes";

/// The protocols whose fragments the fragment guard drops, in the order of its counters.
pub const FRAGMENTED: [&str; 2] = ["tcp", "icmp"];
/// What the fragment guard does and has done.
pub struct FragmentGuard {
    /// "enforce", "observe" or "off".
    pub mode: String,
    /// Per protocol in FRAGMENTED order: fragments dropped, and fragments observed.
    pub counts: [[u64; 2]; 2],
}
impl Default for FragmentGuard {
    fn default() -> Self {
        Self {
            mode: "enforce".into(),
            counts: [[0; 2]; 2],
        }
    }
}
impl FragmentGuard {
    pub fn load(&mut self, policy: Option<&FragmentPolicy>) {
        self.mode = mode(policy.map(|p| p.mode.as_str()));
    }
    /// Which of FRAGMENTED a packet is a fragment of, if it is one: its first fragment or any
    /// after, which carry the protocol in their IP header (IPv4) or fragment header (IPv6).
    pub fn fragment(&self, p: &packet::Packet) -> Option<usize> {
        if self.mode == "off" || !p.fragment() {
            return None;
        }
        match p.proto {
            6 => Some(0),
            1 | 58 => Some(1),
            _ => None,
        }
    }
    pub fn stats(&self) -> Value {
        let rows: Vec<_> = FRAGMENTED
            .iter()
            .zip(self.counts)
            .map(|(p, [d, o])| json!({"protocol": p, "dropped": d, "observed": o}))
            .collect();
        json!({
            "mode": self.mode,
            "dropped": self.counts.iter().map(|c| c[0]).sum::<u64>(),
            "observed": self.counts.iter().map(|c| c[1]).sum::<u64>(),
            "by_protocol": rows,
        })
    }
}
/// Why a fragment of the protocol is dropped.
pub fn fragment_why(i: usize) -> &'static str {
    if i == 0 {
        "fragmented ACK flood: TCP in fragments, which no TCP stack sends, since TCP sizes its segments to the path"
    } else {
        "ICMP fragmentation flood: ICMP in fragments, which no ping or error a game server needs arrives as"
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
pub const ICMP_KINDS: [&str; 3] = ["flood", "smurf", "error"];
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
/// What the ICMP guard does and has done.
pub struct IcmpGuard {
    /// "enforce", "observe" or "off".
    pub mode: String,
    pub limit_pps: u64,
    pub smurf_pps: u64,
    /// The ICMP each aggregate took this second, echo replies aside: one for each aggregate that
    /// has taken any.
    seconds: HashMap<Key, (i64, u64)>,
    replies: Engagement<Key>,
    /// Per kind in ICMP_KINDS order: packets dropped, and packets observed.
    pub counts: [[u64; 2]; 3],
}
impl Default for IcmpGuard {
    fn default() -> Self {
        Self {
            mode: "enforce".into(),
            limit_pps: ICMP_LIMIT_PPS,
            smurf_pps: SMURF_PPS,
            seconds: HashMap::new(),
            replies: Engagement::default(),
            counts: [[0; 2]; 3],
        }
    }
}
impl IcmpGuard {
    pub fn load(&mut self, policy: Option<&IcmpPolicy>, live: &dyn Fn(&str) -> bool) {
        self.mode = mode(policy.map(|p| p.mode.as_str()));
        let pps = |v: Option<i64>, default: u64| v.filter(|&p| p > 0).map_or(default, |p| p as u64);
        self.limit_pps = pps(policy.map(|p| p.limit_pps), ICMP_LIMIT_PPS);
        self.smurf_pps = pps(policy.map(|p| p.smurf_pps), SMURF_PPS);
        self.seconds.retain(|a, _| live(a));
        self.replies.retain(|a| live(a));
    }
    /// Counts ICMP that is not an echo reply at an aggregate, and says whether this second's is
    /// over the limit.
    pub fn over_limit(&mut self, aggregate: &Key, pps: u64, now: i64) -> bool {
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
        *count > self.limit_pps
    }
    /// Counts echo replies the server never asked for at an aggregate, and says whether it is
    /// flooded with them.
    pub fn smurfed_by(&mut self, aggregate: &Key, pps: u64, now: i64) -> bool {
        self.replies
            .engaged_by(aggregate, pps, self.smurf_pps, SMURF_HOLD, now)
    }
    pub fn smurfed(&self, aggregate: &str, now: i64) -> bool {
        self.replies.engaged(aggregate, now)
    }
    pub fn stats(&self, now: i64) -> Value {
        let rows: Vec<_> = ICMP_KINDS
            .iter()
            .zip(self.counts)
            .map(|(k, [d, o])| json!({"kind": k, "dropped": d, "observed": o}))
            .collect();
        json!({
            "mode": self.mode,
            "limit_pps": self.limit_pps,
            "smurf_pps": self.smurf_pps,
            "smurf_engaged": self.replies.count(now, |_| true),
            "dropped": self.counts.iter().map(|c| c[0]).sum::<u64>(),
            "observed": self.counts.iter().map(|c| c[1]).sum::<u64>(),
            "kinds": rows,
        })
    }
}
/// Why ICMP of a kind is dropped.
pub fn icmp_why(i: usize, limit: u64) -> String {
    match i {
        0 => format!("ICMP flood: more than {limit} ICMP packets a second to the prefix, echo replies aside"),
        1 => "Smurf: an echo reply to a ping the server never sent, while the prefix is flooded with them".into(),
        _ => "forged ICMP error: an error about a packet the protected prefix never sent, as BlackNurse floods with".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let mut g = ProtocolGuard::default();
        for passes in ["tcp", "UDP", "icmp", "", "any", "quic"] {
            assert_eq!(g.stopped(passes), None, "{passes}");
        }
        assert_eq!(g.stopped("gre").as_deref(), Some("gre"));
        assert_eq!(g.stopped("47").as_deref(), Some("gre"));
        assert_eq!(g.stopped("esp").as_deref(), Some("esp"));
        // IP NULL: protocol 0.
        assert_eq!(g.stopped("0").as_deref(), Some("0"));
        assert!(why("0").starts_with("IP NULL: "));
        g.load(Some(&ProtocolPolicy {
            mode: String::new(),
            allow: vec!["50".into(), "AH".into()],
        }));
        assert_eq!(g.stopped("esp"), None);
        assert_eq!(g.stopped("ah"), None);
        assert_eq!(g.stopped("gre").as_deref(), Some("gre"));
        g.load(Some(&ProtocolPolicy {
            mode: "off".into(),
            allow: vec![],
        }));
        assert_eq!(g.stopped("gre"), None);
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
        let p: Key = "203.0.113.0/24".into();
        assert!(!g.engaged_by(&p, 4000, 1_000));
        assert!(!g.engaged_by(&p, 1000, 1_500));
        assert!(g.engaged_by(&p, 1, 1_900));
        // Quiet again, it holds for a minute after the last second over.
        assert!(g.engaged_by(&p, 1, 2_100));
        assert!(g.engaged(&p, 1_900 + ACK_HOLD - 1));
        assert!(!g.engaged(&p, 1_900 + ACK_HOLD));
        assert!(!g.engaged("198.51.100.0/24", 1_900));
        g.load(None, &|_| false);
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
        assert!(!g.retried(&first, 10_000));
        // Within the same second is no retry; one to four seconds later is.
        assert!(!g.retried(&first, 10_900));
        assert!(g.retried(&first, 11_000));
        assert!(g.retried(&first, 14_999));
        // Another port, or another source, is another connection.
        assert!(!g.retried(&syn("192.0.2.1", 50_001), 11_000));
        assert!(!g.retried(&syn("192.0.2.2", 50_000), 11_000));
        // Five seconds on, the first second's record is gone.
        let lone = syn("192.0.2.3", 1);
        assert!(!g.retried(&lone, 20_000));
        assert!(!g.retried(&lone, 25_000));
        assert_eq!(g.bytes(), SYN_BITS / 8 * SYN_SECONDS);
        // A forged flood from a fresh source each time finds no retry among its own, or almost
        // none: the bits are set by a keyed hash of each connection.
        let mut passed = 0;
        for i in 0..100_000u32 {
            let f = syn(
                &format!("10.{}.{}.{}", i >> 16, (i >> 8) & 255, i & 255),
                1024 + i64::from(i % 60_000),
            );
            passed += u32::from(g.retried(&f, 30_000 + i64::from(i) / 50));
        }
        assert!(
            passed < 100,
            "{passed} of 100,000 forged SYNs passed as retries"
        );
    }
    #[test]
    fn icmp_is_held_to_a_limit_and_echo_replies_to_what_was_asked() {
        let mut g = IcmpGuard::default();
        let a: Key = "203.0.113.0/24".into();
        assert!(!g.over_limit(&a, ICMP_LIMIT_PPS, 1_000));
        assert!(g.over_limit(&a, 1, 1_500));
        assert!(!g.over_limit(&a, 1, 2_000), "a new second starts over");
        assert!(!g.smurfed_by(&a, SMURF_PPS, 1_000));
        assert!(g.smurfed_by(&a, 1, 1_001));
        assert!(g.smurfed(&a, 1_001 + SMURF_HOLD - 1));
        assert!(!g.smurfed(&a, 1_001 + SMURF_HOLD));
    }
}
