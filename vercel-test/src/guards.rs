//! Two guards on what reaches a protected address, beside the reflection guard. Both answer what
//! IoT botnets flood with, and both are judged from what a packet is and what the server has said,
//! not from how much of it arrives alone.
//!
//! The protocol guard drops IP protocols a game server never receives. GRE is the one botnets use:
//! Mirai's GRE floods wrap junk in GRE so it passes filters that only look at TCP and UDP. Anything
//! but TCP, UDP and ICMP goes the same way, unless the policy lets it in.
//!
//! The ACK flood guard drops TCP that belongs to no connection the server has. Every segment of an
//! open connection but the opening SYN is answered by the server, so a source the server has not
//! sent TCP to has no connection to send ACKs, RSTs or FINs for. The return-traffic table knows
//! whom the server has sent to, but only where the server's traffic passes the node, so the guard
//! waits until the node has watched it long enough to know every connection open, and engages only
//! while a prefix is flooded with such TCP: a stray segment after a restart costs nobody anything.
use crate::model::{AckFloodPolicy, ProtocolPolicy};
use crate::packet;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};

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
        self.mode = match policy.map(|p| p.mode.as_str()) {
            Some(mode @ ("observe" | "off")) => mode.into(),
            _ => "enforce".into(),
        };
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
    if name == "gre" {
        "GRE flood: GRE sent to a protected address, which no game server receives".into()
    } else {
        format!(
            "IP protocol {name} sent to a protected address, which receives only TCP, UDP and ICMP"
        )
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

/// The TCP a prefix received this second that belongs to no connection, and how long its guard
/// is engaged for.
#[derive(Default)]
struct Watch {
    second: i64,
    pps: u64,
    engaged_until: i64,
}
/// What the ACK flood guard does and has done.
pub struct AckGuard {
    /// "enforce", "observe" or "off".
    pub mode: String,
    pub engage_pps: u64,
    /// One for each protected prefix that has received such TCP, so as many as the program has.
    watches: HashMap<String, Watch>,
    /// Segments dropped, and segments observed.
    pub counts: [u64; 2],
}
impl Default for AckGuard {
    fn default() -> Self {
        Self {
            mode: "enforce".into(),
            engage_pps: ENGAGE_PPS,
            watches: HashMap::new(),
            counts: [0; 2],
        }
    }
}
/// Whether a segment's flags say it belongs to an open connection: anything but a SYN that opens
/// one. A record that names no flags says nothing either way.
pub fn mid_connection(flags: &str) -> bool {
    packet::tcp_flags(flags).is_some_and(|f| f & packet::SYN == 0 || f & packet::ACK != 0)
}
impl AckGuard {
    pub fn load(&mut self, policy: Option<&AckFloodPolicy>, live: &HashSet<String>) {
        self.mode = match policy.map(|p| p.mode.as_str()) {
            Some(mode @ ("observe" | "off")) => mode.into(),
            _ => "enforce".into(),
        };
        self.engage_pps = policy
            .map(|p| p.engage_pps)
            .filter(|&p| p > 0)
            .map_or(ENGAGE_PPS, |p| p as u64);
        self.watches.retain(|p, _| live.contains(p));
    }
    /// Counts TCP that belongs to no connection at a prefix, and says whether the prefix's guard
    /// is engaged: by this second's TCP being over the threshold, or by an earlier second's within
    /// the hold.
    pub fn engaged_by(&mut self, prefix: &str, pps: u64, now: i64) -> bool {
        if !self.watches.contains_key(prefix) {
            self.watches.insert(prefix.into(), Watch::default());
        }
        let w = self.watches.get_mut(prefix).unwrap();
        let second = now.div_euclid(1000);
        if w.second != second {
            w.second = second;
            w.pps = 0;
        }
        w.pps = w.pps.saturating_add(pps);
        if w.pps > self.engage_pps {
            w.engaged_until = now + ACK_HOLD;
        }
        now < w.engaged_until
    }
    pub fn engaged(&self, prefix: &str, now: i64) -> bool {
        self.watches
            .get(prefix)
            .is_some_and(|w| now < w.engaged_until)
    }
    pub fn stats(&self, now: i64) -> Value {
        json!({
            "mode": self.mode,
            "engage_pps": self.engage_pps,
            "engaged": self.watches.values().filter(|w| now < w.engaged_until).count(),
            "dropped": self.counts[0],
            "observed": self.counts[1],
        })
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
        }
        for not in ["syn", "syn,ece,cwr", "", "bogus"] {
            assert!(!mid_connection(not), "{not}");
        }
    }
    #[test]
    fn the_ack_guard_engages_over_its_threshold_and_holds() {
        let mut g = AckGuard::default();
        let p = "203.0.113.0/24";
        assert!(!g.engaged_by(p, 4000, 1_000));
        assert!(!g.engaged_by(p, 1000, 1_500));
        assert!(g.engaged_by(p, 1, 1_900));
        // Quiet again, it holds for a minute after the last second over.
        assert!(g.engaged_by(p, 1, 2_100));
        assert!(g.engaged(p, 1_900 + ACK_HOLD - 1));
        assert!(!g.engaged(p, 1_900 + ACK_HOLD));
        assert!(!g.engaged("198.51.100.0/24", 1_900));
        g.load(None, &HashSet::new());
        assert!(
            !g.engaged(p, 2_000),
            "a prefix no longer in the program is forgotten"
        );
    }
}
