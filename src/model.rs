//! Wire-compatible policy and program types shared by the Rust components.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
pub type Action = String;
pub type Stage = String;
pub type AnnounceState = String;
fn is_zero<T: Default + PartialEq>(v: &T) -> bool {
    *v == T::default()
}
pub fn null_default<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}
pub fn zero_time() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("0001-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc)
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Match {
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub src_cidr: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub dst_cidr: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub proto: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub dport: i64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub sport: i64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub tcp_flags: String,
    /// The last port of a range that starts at `dport` or `sport`; a single port when unset.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub dport_to: i64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub sport_to: i64,
    /// The IP packet's length in bytes, header and all: at least `length_min`, at most
    /// `length_max`. A record without its packet is measured by its rates, or else by its payload.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub length_min: i64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub length_max: i64,
    /// The packet's TTL (IPv4) or hop limit (IPv6), within these bounds. Only a packet, or a
    /// record that carries it, has one.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub ttl_min: i64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub ttl_max: i64,
    /// An ICMP message's type and code, as ICMP or ICMPv6 numbers them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icmp_type: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icmp_code: Option<i64>,
    /// The DSCP code point the packet is marked with, 0 to 63, as BGP Flowspec matches it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dscp: Option<i64>,
    /// "yes" for fragments only, the first and the rest; "no" for whole packets only. Only a
    /// packet shows whether it is a fragment.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub fragment: String,
    /// Bytes the payload holds, in hex: `payload_hex` at `payload_offset`, and `payload_contains`
    /// anywhere in it.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub payload_hex: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub payload_offset: i64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub payload_contains: String,
    /// A list of the policy's `lists` the source, or the destination, is in.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub src_list: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub dst_list: String,
    /// Match only while the protected prefix the packet goes to takes at least this many packets
    /// a second, or megabits a second, over the last second: a rule for when it is under attack.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub attack_pps: i64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub attack_mbps: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Rule {
    #[serde(deserialize_with = "null_default")]
    pub id: String,
    #[serde(deserialize_with = "null_default")]
    pub stage: Stage,
    #[serde(deserialize_with = "null_default")]
    pub action: Action,
    pub r#match: Match,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub pps: i64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub priority: i64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub comment: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Policy {
    #[serde(deserialize_with = "null_default")]
    pub id: String,
    #[serde(deserialize_with = "null_default")]
    pub name: String,
    #[serde(deserialize_with = "null_default")]
    pub protected: Vec<String>,
    #[serde(deserialize_with = "null_default")]
    pub rules: Vec<Rule>,
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub steering: Vec<Steering>,
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub games: Vec<GameFilter>,
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub tunnels: Vec<Tunnel>,
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub sessions: Vec<Session>,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub pulse_floor_pps: i64,
    #[serde(skip_serializing_if = "is_zero")]
    pub reputation: Option<ReputationPolicy>,
    #[serde(skip_serializing_if = "is_zero")]
    pub egress: Option<EgressPolicy>,
    #[serde(skip_serializing_if = "is_zero")]
    pub ml: Option<MlPolicy>,
    #[serde(skip_serializing_if = "is_zero")]
    pub crafted: Option<CraftedPolicy>,
    #[serde(skip_serializing_if = "is_zero")]
    pub reflection: Option<ReflectionPolicy>,
    #[serde(skip_serializing_if = "is_zero")]
    pub protocols: Option<ProtocolPolicy>,
    #[serde(skip_serializing_if = "is_zero")]
    pub ack_flood: Option<AckFloodPolicy>,
    #[serde(skip_serializing_if = "is_zero")]
    pub syn_flood: Option<SynFloodPolicy>,
    #[serde(skip_serializing_if = "is_zero")]
    pub fragments: Option<FragmentPolicy>,
    #[serde(skip_serializing_if = "is_zero")]
    pub icmp: Option<IcmpPolicy>,
    #[serde(skip_serializing_if = "is_zero")]
    pub aggregation: Option<AggregationPolicy>,
    #[serde(skip_serializing_if = "is_zero")]
    pub pulse: Option<PulsePolicy>,
    #[serde(skip_serializing_if = "is_zero")]
    pub mitigation: Option<MitigationPolicy>,
    /// "high", the default, "medium" or "low": how readily the flood guards engage. Lower
    /// sensitivity multiplies every flood threshold the policy leaves unset, by 4 or by 16.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub sensitivity: String,
    /// Settings for some of the protected addresses that differ from the policy's.
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub profiles: Vec<Profile>,
    /// Named lists of addresses, CIDRs, that rules match their sources or destinations against.
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub lists: BTreeMap<String, Vec<String>>,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub challenge_secret: String,
    #[serde(deserialize_with = "null_time")]
    pub updated_at: DateTime<Utc>,
    #[serde(deserialize_with = "null_default")]
    pub version: i64,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            id: Default::default(),
            name: Default::default(),
            protected: Vec::new(),
            rules: Vec::new(),
            steering: Vec::new(),
            games: Vec::new(),
            tunnels: Vec::new(),
            sessions: Vec::new(),
            pulse_floor_pps: Default::default(),
            reputation: None,
            egress: None,
            ml: None,
            crafted: None,
            reflection: None,
            protocols: None,
            ack_flood: None,
            syn_flood: None,
            fragments: None,
            icmp: None,
            aggregation: None,
            pulse: None,
            mitigation: None,
            sensitivity: Default::default(),
            profiles: Vec::new(),
            lists: BTreeMap::new(),
            challenge_secret: Default::default(),
            updated_at: zero_time(),
            version: Default::default(),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ReputationPolicy {
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub fast_pass: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub penalty_box: bool,
    /// How long a proof keeps a source trusted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_seconds: Option<i64>,
    /// How many strikes within `strike_window_seconds` put a source in the penalty box.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strikes: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strike_window_seconds: Option<i64>,
    /// How long each sentence in the box lasts, the first and each after it; the last repeats.
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub penalty_seconds: Vec<i64>,
    /// How long a source must stay clean for its next sentence to drop back a step.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forgive_seconds: Option<i64>,
}

/// Where the published classifiers judge traffic, and whether they drop what they score at their
/// threshold.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct MlPolicy {
    /// "all", the default: the flow model has the last word on everything the stages let
    /// through, and the request model on every request the HTTP rules allow. "inspect": only the
    /// flows a zc inspect or rate_limit rule sends the flow model.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub scope: String,
    /// "enforce", the default, or "observe": score and count what would be dropped, and drop
    /// nothing.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub mode: String,
    /// "tighten", the default: when much of what the models score for a protected prefix lands
    /// just under their thresholds, as traffic shaped to slip past them does, they drop at lower
    /// thresholds for that prefix for a while. "ignore" keeps the thresholds where they are.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub probing: String,
    /// How long a step of tightening holds after the probing that set it, and how many near
    /// misses in ten seconds it takes to be probing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub probe_hold_seconds: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub probe_min: Option<i64>,
}
/// What a node does with a packet built to harm the stack that receives it rather than to swamp
/// it: one that breaks a rule its own headers state (see packet.rs).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct CraftedPolicy {
    /// "enforce", the default: drop it. "observe": count what would be dropped, and drop nothing.
    /// "off": do not look.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub mode: String,
    /// Modes for single checks, by name, over the mode for all of them.
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub checks: BTreeMap<String, String>,
    /// The largest MSS a SYN may offer and still be dropped as SACK Panic's shape.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub low_mss: Option<i64>,
    /// The smallest fragment, short of a datagram's last, that is not dropped as too small.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_fragment: Option<i64>,
}
/// What a node does with answers reflected at a protected address: replies from servers on the
/// internet to requests an attacker sent them with that address forged as the source, which they
/// answer many times over (see reflection.rs). Per vector, "enforce", the default, drops them;
/// "observe" counts what would be dropped and drops nothing; "off" does not look.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ReflectionPolicy {
    /// Every vector's mode, unless `vectors` names its own.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub mode: String,
    /// Connectionless LDAP, UDP from port 389: a rootDSE query of about 50 bytes is answered with
    /// several kilobytes. The same as naming cldap in `vectors`.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub cldap: String,
    /// Modes for single vectors, by name: cldap, dns, ntp, memcached, ssdp, snmp, chargen, echo,
    /// qotd, portmap, netbios, mssql, wsd, coap, mdns, ubiquiti, rip.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub vectors: BTreeMap<String, String>,
    /// How many packets a second of answers it never asked for a prefix takes, of the vectors the
    /// server asks itself (DNS and NTP's time), before they are dropped; 1000 when unset.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub engage_pps: i64,
    /// How long a prefix counts as flooded after its last second over `engage_pps`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hold_seconds: Option<i64>,
    /// How recently the server must have queried an address for its answer to count as asked for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asked_within_seconds: Option<i64>,
    /// How long a source caught reflecting has its later fragments dropped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reflecting_for_seconds: Option<i64>,
    /// How a vector's answers the server never asked for are judged, by name: "always", however
    /// few arrive, or "flood", only while the prefix is flooded with them.
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub judge: BTreeMap<String, String>,
    /// Vectors of your own: services the guard does not know, told by their port and, if given,
    /// the bytes their answers open with.
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub custom: Vec<CustomVector>,
}
/// A reflection vector of an operator's own.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct CustomVector {
    #[serde(deserialize_with = "null_default")]
    pub name: String,
    /// The UDP port its answers come from.
    #[serde(deserialize_with = "null_default")]
    pub port: i64,
    /// What its answers open with, in hex; any payload from the port when unset.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub payload_hex: String,
    /// "always", the default, or "flood".
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub judge: String,
}
/// What a node does with IP protocols a game server never receives, sent to a protected address:
/// GRE above all, which botnets flood with, and anything but TCP, UDP and ICMP (see guards.rs).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ProtocolPolicy {
    /// "enforce", the default, drops them; "observe" counts what would be dropped and drops
    /// nothing; "off" does not look.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub mode: String,
    /// Protocols the protected addresses do receive besides TCP, UDP and ICMP, by name (gre, esp,
    /// ah, sctp, ipip, ipv6) or number.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub allow: Vec<String>,
}
/// What a node does with TCP that belongs to no connection the protected server has: ACKs and the
/// rest of an established connection's segments from sources it never sent TCP to, as an ACK
/// flood is made of (see guards.rs).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct AckFloodPolicy {
    /// "enforce", the default, drops them while a prefix is flooded with them; "observe" counts
    /// what would be dropped and drops nothing; "off" does not look.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub mode: String,
    /// How many packets a second of such TCP a prefix takes before the guard starts dropping it;
    /// 5000 when unset.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub engage_pps: i64,
    /// How long the guard stays engaged after the last second over `engage_pps`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hold_seconds: Option<i64>,
    /// How long the node must have watched the server's own traffic before the guard may engage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warm_seconds: Option<i64>,
    /// How recently the server must have sent a source TCP for its segments to belong to a
    /// connection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub talked_within_seconds: Option<i64>,
    /// How long, and for how many segments, a client the server answered may finish its
    /// handshake.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handshake_seconds: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handshake_segments: Option<i64>,
}
/// What a node does with opening SYNs from sources the protected server has no connection with
/// while a prefix is flooded with them, as a SYN flood is made of (see guards.rs). A client's
/// retry, a second or so later, passes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct SynFloodPolicy {
    /// "enforce", the default, holds them back while a prefix is flooded; "observe" counts what
    /// would be dropped and drops nothing; "off" does not look.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub mode: String,
    /// How many packets a second of such SYNs a prefix takes before the guard engages; 2000 when
    /// unset.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub engage_pps: i64,
    /// How long the guard stays engaged after the last second over `engage_pps`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hold_seconds: Option<i64>,
    /// How long after a SYN its connection's next SYN still counts as a retry, up to 4 seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_within_seconds: Option<i64>,
    /// The most SYNs a second one connection may send and still be a client retrying.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retries_pps: Option<i64>,
}
/// What a node does with TCP and ICMP that arrive in fragments, which no real sender fragments:
/// fragmented ACK floods and ICMP fragmentation floods (see guards.rs).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct FragmentPolicy {
    /// "enforce", the default, drops them; "observe" counts what would be dropped and drops
    /// nothing; "off" does not look.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub mode: String,
    /// Which protocols' fragments are dropped: tcp, icmp, udp and other. tcp and icmp when unset.
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub protocols: Vec<String>,
}
/// What a node does with ICMP to a protected address: a rate for each prefix, echo replies the
/// server never asked for (Smurf), and errors about packets it never sent (see guards.rs).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct IcmpPolicy {
    /// "enforce", the default, drops what the guard catches; "observe" counts what would be
    /// dropped and drops nothing; "off" does not look.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub mode: String,
    /// How many packets a second of ICMP, echo replies aside, a prefix takes before the rest are
    /// dropped; 1000 when unset.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub limit_pps: i64,
    /// How many packets a second of echo replies the server never asked for a prefix takes before
    /// they are dropped; 1000 when unset.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub smurf_pps: i64,
    /// How long a prefix counts as flooded with echo replies after its last second over.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hold_seconds: Option<i64>,
    /// ICMP types (IPv4 numbering) and ICMPv6 types dropped whatever their rate.
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub drop_types: Vec<i64>,
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub drop_types_v6: Vec<i64>,
    /// "verify", the default, drops an error that quotes no packet the prefix sent; "allow" lets
    /// every error through to the rate.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub errors: String,
}
/// How floods are judged together: protected prefixes narrower than these are judged with the rest
/// of the prefix of this length that holds them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct AggregationPolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub v4: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub v6: Option<i64>,
}
/// How a burst attack is told: the crest a prefix's peak must reach over its mean, the most of the
/// last minute its traffic may fill, how many bursts it takes, and how long it is held as pulsing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct PulsePolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crest: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duty: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bursts: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latch_seconds: Option<i64>,
}
/// How long an on-demand tunnel's mitigation lasts after its traffic falls under its thresholds,
/// how long a wave may follow the last and still be the same attack, and the longest a wave holds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct MitigationPolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hold_seconds: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub campaign_seconds: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hold_max_seconds: Option<i64>,
}
/// Settings for some of the protected addresses that differ from the policy's: any of the guards'
/// sections, and how sensitive the flood guards are. A protected address takes the most specific
/// profile whose prefixes hold it, and the policy's settings for whatever that profile leaves
/// unset.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Profile {
    #[serde(deserialize_with = "null_default")]
    pub name: String,
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub prefixes: Vec<String>,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub sensitivity: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub crafted: Option<CraftedPolicy>,
    #[serde(skip_serializing_if = "is_zero")]
    pub reflection: Option<ReflectionPolicy>,
    #[serde(skip_serializing_if = "is_zero")]
    pub protocols: Option<ProtocolPolicy>,
    #[serde(skip_serializing_if = "is_zero")]
    pub ack_flood: Option<AckFloodPolicy>,
    #[serde(skip_serializing_if = "is_zero")]
    pub syn_flood: Option<SynFloodPolicy>,
    #[serde(skip_serializing_if = "is_zero")]
    pub fragments: Option<FragmentPolicy>,
    #[serde(skip_serializing_if = "is_zero")]
    pub icmp: Option<IcmpPolicy>,
}
impl MlPolicy {
    pub fn everywhere(&self) -> bool {
        self.scope != "inspect"
    }
    pub fn enforcing(&self) -> bool {
        self.mode != "observe"
    }
    pub fn tightens(&self) -> bool {
        self.probing != "ignore"
    }
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct EgressPolicy {
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub lockdown: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub lockdown_pps: i64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub grace_millis: i64,
    /// How much of the origin's traffic to a client confirms it: at least `confirm_packets`
    /// packets in `confirm_ticks` quarters of a second, within `confirm_window_seconds`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirm_packets: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirm_ticks: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirm_window_seconds: Option<i64>,
    /// How long a confirmation lasts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmed_seconds: Option<i64>,
    /// How recently the origin's traffic must have been seen for its return path to count as
    /// visible.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visible_seconds: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Steering {
    #[serde(deserialize_with = "null_default")]
    pub prefix: String,
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub regions: Vec<String>,
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub communities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Node {
    #[serde(deserialize_with = "null_default")]
    pub id: String,
    #[serde(deserialize_with = "null_default")]
    pub name: String,
    #[serde(deserialize_with = "null_default")]
    pub region: String,
    #[serde(deserialize_with = "null_default")]
    pub capacity_gbps: f64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub capacity_pps: i64,
    #[serde(deserialize_with = "null_default")]
    pub backends: Vec<Stage>,
    #[serde(deserialize_with = "null_time")]
    pub last_seen: DateTime<Utc>,
    #[serde(deserialize_with = "null_default")]
    pub status: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub advertise: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub tunnel_src: String,
}
impl Default for Node {
    fn default() -> Self {
        Self {
            id: Default::default(),
            name: Default::default(),
            region: Default::default(),
            capacity_gbps: Default::default(),
            capacity_pps: Default::default(),
            backends: Vec::new(),
            last_seen: zero_time(),
            status: Default::default(),
            advertise: Default::default(),
            tunnel_src: Default::default(),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Tenant {
    #[serde(deserialize_with = "null_default")]
    pub id: String,
    #[serde(deserialize_with = "null_default")]
    pub name: String,
    #[serde(deserialize_with = "null_default")]
    pub prefixes: Vec<String>,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub contact: String,
    #[serde(deserialize_with = "null_time")]
    pub created_at: DateTime<Utc>,
    #[serde(deserialize_with = "null_time")]
    pub updated_at: DateTime<Utc>,
}
impl Default for Tenant {
    fn default() -> Self {
        Self {
            id: Default::default(),
            name: Default::default(),
            prefixes: Vec::new(),
            contact: Default::default(),
            created_at: zero_time(),
            updated_at: zero_time(),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Serialize, Default)]
#[serde(default)]
pub struct Flow {
    pub src_ip: String,
    pub dst_ip: String,
    pub proto: String,
    pub sport: i64,
    pub dport: i64,
    #[serde(skip_serializing_if = "is_zero")]
    pub flags: String,
    pub pps: i64,
    /// The flow's bit rate, when the record carries one. Without it a node counts the packets'
    /// headers and whatever payload the record holds.
    #[serde(skip_serializing_if = "is_zero")]
    pub bps: i64,
    #[serde(with = "base64_bytes", skip_serializing_if = "is_zero")]
    pub payload: Vec<u8>,
    #[serde(skip)]
    pub has_payload: bool,
    /// The receive window a TCP segment advertises, as written in its header, when the flow
    /// carries the packet.
    #[serde(skip)]
    pub window: Option<u16>,
    /// What rules can match beside the addresses, ports and flags: the IP packet's length, its
    /// TTL or hop limit, its DSCP code point, an ICMP message's type and code, and whether it is
    /// a fragment. Read from the packet when the flow carries it; a record may say them itself.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dscp: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icmp_type: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icmp_code: Option<u8>,
    #[serde(skip_serializing_if = "is_zero")]
    pub fragment: bool,
    /// The packet itself, from its IP header on, when the datapath hands over whole packets. The
    /// node reads the addresses, protocol, ports, flags and payload from its headers rather than
    /// from the record's fields, and holds it to the rules those headers state.
    #[serde(with = "base64_bytes", skip_serializing_if = "is_zero")]
    pub packet: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Decision {
    #[serde(deserialize_with = "null_default")]
    pub action: Action,
    #[serde(deserialize_with = "null_default")]
    pub stage: Stage,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub rule_id: String,
    #[serde(deserialize_with = "null_default")]
    pub reason: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub node_id: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub score: f64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub filter: String,
    /// The crafted-packet check a packet broke, when one dropped it.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub check: String,
    /// The reflection vector a packet belonged to, such as cldap, when the reflection guard
    /// dropped it.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub reflection: String,
    /// The guard that dropped a packet, when one did: "protocol" for a protocol a protected
    /// address does not receive, "ack_flood" for TCP that belongs to no connection, "syn_flood"
    /// for an opening SYN held back during a SYN flood, "fragment" for TCP or ICMP in fragments,
    /// "icmp" for ICMP over its rate, an unasked echo reply or a forged error.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub guard: String,
    #[serde(with = "base64_bytes", skip_serializing_if = "is_zero")]
    pub reply: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ACLEntry {
    #[serde(deserialize_with = "null_default")]
    pub priority: i64,
    #[serde(deserialize_with = "null_default")]
    pub action: Action,
    pub r#match: Match,
    #[serde(deserialize_with = "null_default")]
    pub rule_id: String,
    #[serde(deserialize_with = "null_default")]
    pub tcam_key: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct FPGAEntry {
    #[serde(deserialize_with = "null_default")]
    pub table: String,
    #[serde(deserialize_with = "null_default")]
    pub priority: i64,
    pub r#match: Match,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub meter_pps: i64,
    #[serde(deserialize_with = "null_default")]
    pub action: Action,
    #[serde(deserialize_with = "null_default")]
    pub rule_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ZCEntry {
    #[serde(deserialize_with = "null_default")]
    pub cluster: String,
    #[serde(deserialize_with = "null_default")]
    pub priority: i64,
    pub r#match: Match,
    #[serde(deserialize_with = "null_default")]
    pub action: Action,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub pps: i64,
    #[serde(deserialize_with = "null_default")]
    pub rule_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Program {
    #[serde(deserialize_with = "null_default")]
    pub node_id: String,
    #[serde(deserialize_with = "null_default")]
    pub policy_id: String,
    #[serde(deserialize_with = "null_default")]
    pub version: i64,
    #[serde(deserialize_with = "null_default")]
    pub prefixes: Vec<String>,
    #[serde(deserialize_with = "null_default")]
    pub asic: Vec<ACLEntry>,
    #[serde(deserialize_with = "null_default")]
    pub fpga: Vec<FPGAEntry>,
    #[serde(deserialize_with = "null_default")]
    pub zc: Vec<ZCEntry>,
    #[serde(deserialize_with = "null_default")]
    pub announcements: Vec<Announcement>,
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub games: Vec<GameFilter>,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub challenge_secret: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub pulse_floor_pps: i64,
    #[serde(skip_serializing_if = "is_zero")]
    pub reputation: Option<ReputationPolicy>,
    #[serde(skip_serializing_if = "is_zero")]
    pub egress: Option<EgressPolicy>,
    #[serde(skip_serializing_if = "is_zero")]
    pub ml: Option<MlPolicy>,
    #[serde(skip_serializing_if = "is_zero")]
    pub crafted: Option<CraftedPolicy>,
    #[serde(skip_serializing_if = "is_zero")]
    pub reflection: Option<ReflectionPolicy>,
    #[serde(skip_serializing_if = "is_zero")]
    pub protocols: Option<ProtocolPolicy>,
    #[serde(skip_serializing_if = "is_zero")]
    pub ack_flood: Option<AckFloodPolicy>,
    #[serde(skip_serializing_if = "is_zero")]
    pub syn_flood: Option<SynFloodPolicy>,
    #[serde(skip_serializing_if = "is_zero")]
    pub fragments: Option<FragmentPolicy>,
    #[serde(skip_serializing_if = "is_zero")]
    pub icmp: Option<IcmpPolicy>,
    #[serde(skip_serializing_if = "is_zero")]
    pub aggregation: Option<AggregationPolicy>,
    #[serde(skip_serializing_if = "is_zero")]
    pub pulse: Option<PulsePolicy>,
    #[serde(skip_serializing_if = "is_zero")]
    pub mitigation: Option<MitigationPolicy>,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub sensitivity: String,
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub profiles: Vec<Profile>,
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub lists: BTreeMap<String, Vec<String>>,
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub tunnels: Vec<NodeTunnel>,
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub sessions: Vec<Session>,
    /// The node's own address for tunnels and customer peering, as the control plane holds it.
    /// An operator can reassign it at any time, so the agent takes it from here rather than from
    /// what it registered with.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub tunnel_src: String,
    /// Tunnels to the other nodes, for customers pinned to one of them or to this one.
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub backhaul: Vec<Backhaul>,
    /// Prefixes of the customers pinned to this node: what traffic arriving over a backhaul may
    /// be addressed to.
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub pinned: Vec<String>,
    /// Every address this node accepts tunnels from: the other nodes' tunnel endpoints and the
    /// customer end of each tunnel built here. The firewall drops GRE and IPIP from anywhere else.
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub tunnel_peers: Vec<String>,
    #[serde(deserialize_with = "null_time")]
    pub compiled_at: DateTime<Utc>,
}
impl Default for Program {
    fn default() -> Self {
        Self {
            node_id: Default::default(),
            policy_id: Default::default(),
            version: Default::default(),
            prefixes: Vec::new(),
            asic: Vec::new(),
            fpga: Vec::new(),
            zc: Vec::new(),
            announcements: Vec::new(),
            games: Vec::new(),
            challenge_secret: Default::default(),
            pulse_floor_pps: Default::default(),
            reputation: None,
            egress: None,
            ml: None,
            crafted: None,
            reflection: None,
            protocols: None,
            ack_flood: None,
            syn_flood: None,
            fragments: None,
            icmp: None,
            aggregation: None,
            pulse: None,
            mitigation: None,
            sensitivity: Default::default(),
            profiles: Vec::new(),
            lists: BTreeMap::new(),
            tunnels: Vec::new(),
            sessions: Vec::new(),
            tunnel_src: Default::default(),
            backhaul: Vec::new(),
            pinned: Vec::new(),
            tunnel_peers: Vec::new(),
            compiled_at: zero_time(),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct NodeTunnel {
    #[serde(deserialize_with = "null_default")]
    pub id: String,
    #[serde(deserialize_with = "null_default")]
    pub r#type: String,
    #[serde(deserialize_with = "null_default")]
    pub local: String,
    #[serde(deserialize_with = "null_default")]
    pub remote: String,
    #[serde(deserialize_with = "null_default")]
    pub prefixes: Vec<String>,
    #[serde(deserialize_with = "null_default")]
    pub mtu: i64,
    #[serde(deserialize_with = "null_default")]
    pub mss_clamp: i64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub key: u32,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub required: bool,
    #[serde(deserialize_with = "null_default")]
    pub interface: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub comment: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub direction: String,
    /// Every prefix of the tunnel, including ones steered away from this node: replies coming
    /// back up the tunnel may be sourced from any of them.
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub sources: Vec<String>,
    /// Other tunnels' prefixes inside this tunnel's, policy-wide. They are those customers'
    /// address space, so replies coming up this tunnel may not be sourced from them.
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub foreign: Vec<String>,
    /// This node's share of the tunnel's clean-traffic allowance, in kbit/s.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub rate_kbps: i64,
    /// "on_demand" when the node only watches the tunnel's traffic until it reaches either
    /// threshold, this node's share of the tunnel's, and filters it from then on, a game filter's
    /// HTTP rules apart, which judge it throughout. Empty filters it always.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub mitigation: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub attack_pps: i64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub attack_kbps: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct GameFilter {
    #[serde(deserialize_with = "null_default")]
    pub id: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub dst_cidr: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub proto: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub dport: i64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub profile: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub custom: Option<GameSignature>,
    /// Layer-7 rules for the HTTP the game server answers on the same address.
    #[serde(skip_serializing_if = "is_zero")]
    pub http: Option<GameHttp>,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub observe: bool,
    /// How long a player that cleared the gate stays admitted after its last packet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle_seconds: Option<i64>,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub comment: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct GameSignature {
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub min_len: i64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub max_len: i64,
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub packet_ids: Vec<i64>,
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub magic: Vec<GameMagic>,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub gate: String,
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub opener_ids: Vec<i64>,
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub complete_ids: Vec<i64>,
}

/// What a game filter allows of the HTTP its server answers: on TCP to the filter's address, on
/// the filter's port unless `ports` names others.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct GameHttp {
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub ports: Vec<i64>,
    /// Methods allowed; GET, HEAD and POST when empty.
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub methods: Vec<String>,
    /// Prefixes one of which a request's User-Agent must start with; any client when empty.
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub user_agents: Vec<String>,
    /// Requests a second one source may make across the whole filter; no limit at zero.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub rate_per_source: i64,
    /// Requests a second the whole filter takes from every source together, past which only
    /// sources the fabric has verified get through; no budget at zero.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub rate_total: i64,
    /// The largest body a request may declare; no limit at zero.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub max_body_bytes: i64,
    /// What a path no rule names gets: allow, the default, or drop.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub default: String,
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub paths: Vec<GameHttpPath>,
    /// The most requests one segment may pipeline, the longest request or header line, the most
    /// header lines, and the shortest segment that may end inside a request line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pipelined_max: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_max: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers_max: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub split_bytes: Option<i64>,
    /// "count", the default, holds each TLS ClientHello to the rates as a request; "ignore" lets
    /// TLS through untouched.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub tls: String,
    /// How slowly a request may arrive.
    #[serde(skip_serializing_if = "is_zero")]
    pub slow: Option<GameHttpSlow>,
}
/// How slowly a request may arrive before it is taken for Slowloris, R.U.D.Y. or a slow read.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct GameHttpSlow {
    /// "enforce", the default, drops what arrives too slowly; "observe" counts it; "off" does not
    /// watch.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub mode: String,
    /// A head's time to arrive, one more second for every `min_rate` bytes, up to
    /// `head_seconds_max`; a body's, likewise without a cap.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_seconds: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_seconds_max: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_seconds: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_rate: Option<i64>,
    /// The window, as a segment writes it, under which a client is not reading, and for how
    /// long it may stay under.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window_min: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub starved_seconds: Option<i64>,
    /// The most requests one source may leave incomplete at once.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub incomplete_max: Option<i64>,
}

/// A rule for one path, or every path under a prefix. Anything it leaves unset comes from the
/// filter's `http`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct GameHttpPath {
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub path: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub prefix: String,
    /// allow, the default, or drop.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub action: String,
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub methods: Vec<String>,
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub user_agents: Vec<String>,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub rate_per_source: i64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub rate_total: i64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub max_body_bytes: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct GameMagic {
    #[serde(deserialize_with = "null_default")]
    pub offset: i64,
    #[serde(deserialize_with = "null_default")]
    pub hex: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Tunnel {
    #[serde(deserialize_with = "null_default")]
    pub id: String,
    #[serde(deserialize_with = "null_default")]
    pub prefixes: Vec<String>,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub r#type: String,
    #[serde(deserialize_with = "null_default")]
    pub remote: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub mtu: i64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub mss_clamp: i64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub key: u32,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub required: bool,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub comment: String,
    /// "both" (the default when empty): clean traffic goes to the customer through the tunnel
    /// and the customer's replies come back up it to the node. "return": the tunnel only
    /// carries clean traffic out, and replies leave the customer directly.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub direction: String,
    /// Node ids that must not build this tunnel; they withdraw its prefixes instead.
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub disabled: Vec<String>,
    /// The customer (tenant id) this tunnel is allocated to. Its prefixes must be the tenant's.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub tenant: String,
    /// Clean traffic allowed down this tunnel in Mbit/s, summed across every node sending it.
    /// Zero takes the maximum, tunnel::MAX_RATE_MBPS.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub rate_mbps: i64,
    /// The node (id) the customer's tunnel ends on: the location chosen for them, so they hold
    /// one tunnel. Only it announces the prefixes until it is overloaded or down; then the other
    /// nodes join in and forward what they scrub to it. Empty fans the tunnel out to every node
    /// carrying the prefixes instead.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub node: String,
    /// "always" (the default when empty): every node filters the customer's traffic all the
    /// time. "on_demand": each node holding the tunnel only watches its traffic until it reaches
    /// attack_pps or attack_mbps, then filters it until it has stayed under both for a while. A
    /// game filter's HTTP rules judge it throughout.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub mitigation: String,
    /// The traffic to the tunnel's prefixes at which on-demand mitigation starts, summed like
    /// rate_mbps. Zero takes the default: half the clean-traffic allowance, and the packet rate
    /// that is at 512-byte packets.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub attack_pps: i64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub attack_mbps: i64,
}

/// A node-to-node GRE tunnel. A node that helps another with a customer pinned there forwards
/// the clean traffic it scrubs over one, and the location receives it on its own end.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Backhaul {
    #[serde(deserialize_with = "null_default")]
    pub peer: String,
    #[serde(deserialize_with = "null_default")]
    pub interface: String,
    #[serde(deserialize_with = "null_default")]
    pub local: String,
    #[serde(deserialize_with = "null_default")]
    pub remote: String,
    #[serde(deserialize_with = "null_default")]
    pub mtu: i64,
    #[serde(deserialize_with = "null_default")]
    pub mss_clamp: i64,
    /// Prefixes routed into it: those pinned at the peer that this node carries. Empty on the
    /// location's end, which only receives.
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub prefixes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Session {
    #[serde(deserialize_with = "null_default")]
    pub id: String,
    #[serde(deserialize_with = "null_default")]
    pub peer_ip: String,
    #[serde(deserialize_with = "null_default")]
    pub peer_as: i64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub local_as: i64,
    #[serde(deserialize_with = "null_default")]
    pub prefixes: Vec<String>,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub max_prefixes: i64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub password: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub multihop: i64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub passive: bool,
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub nodes: Vec<String>,
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub regions: Vec<String>,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub comment: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct TunnelStatus {
    #[serde(deserialize_with = "null_default")]
    pub tunnel_id: String,
    #[serde(deserialize_with = "null_default")]
    pub state: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub detail: String,
    #[serde(default = "zero_time")]
    #[serde(deserialize_with = "null_time")]
    pub reported_at: DateTime<Utc>,
}
impl Default for TunnelStatus {
    fn default() -> Self {
        Self {
            tunnel_id: Default::default(),
            state: Default::default(),
            detail: Default::default(),
            reported_at: zero_time(),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct SourceReputation {
    #[serde(deserialize_with = "null_default")]
    pub source: String,
    #[serde(deserialize_with = "null_default")]
    pub state: String,
    #[serde(deserialize_with = "null_default")]
    pub proof: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub expires_in_seconds: f64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub level: i64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub strikes: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Announcement {
    #[serde(deserialize_with = "null_default")]
    pub prefix: String,
    #[serde(deserialize_with = "null_default")]
    pub node_id: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub node_name: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub region: String,
    #[serde(deserialize_with = "null_default")]
    pub state: AnnounceState,
    #[serde(deserialize_with = "null_default")]
    pub prepends: i64,
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub communities: Vec<String>,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub next_hop: String,
    #[serde(deserialize_with = "null_default")]
    pub reason: String,
}

mod base64_bytes {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let v = Option::<String>::deserialize(d)?;
        v.map(|v| STANDARD.decode(v).map_err(serde::de::Error::custom))
            .unwrap_or_else(|| Ok(Vec::new()))
    }
}

fn null_time<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<DateTime<Utc>, D::Error> {
    Ok(Option::<DateTime<Utc>>::deserialize(d)?.unwrap_or_else(zero_time))
}

impl<'de> Deserialize<'de> for Flow {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Wire {
            #[serde(deserialize_with = "null_default")]
            src_ip: String,
            #[serde(deserialize_with = "null_default")]
            dst_ip: String,
            #[serde(deserialize_with = "null_default")]
            proto: String,
            #[serde(deserialize_with = "null_default")]
            sport: i64,
            #[serde(deserialize_with = "null_default")]
            dport: i64,
            #[serde(deserialize_with = "null_default")]
            flags: String,
            pps: Option<i64>,
            #[serde(deserialize_with = "null_default")]
            bps: i64,
            payload: Option<String>,
            #[serde(deserialize_with = "null_default")]
            packet: String,
            length: Option<u32>,
            ttl: Option<u8>,
            dscp: Option<u8>,
            icmp_type: Option<u8>,
            icmp_code: Option<u8>,
            #[serde(deserialize_with = "null_default")]
            fragment: bool,
        }
        use base64::Engine;
        let w = Wire::deserialize(d)?;
        let has_payload = w.payload.is_some();
        let decode = |s: String| {
            base64::engine::general_purpose::STANDARD
                .decode(s)
                .map_err(serde::de::Error::custom)
        };
        let payload = w.payload.map(decode).transpose()?.unwrap_or_default();
        let packet = decode(w.packet)?;
        let mut f = Self {
            src_ip: w.src_ip,
            dst_ip: w.dst_ip,
            proto: w.proto,
            sport: w.sport,
            dport: w.dport,
            flags: w.flags,
            // A record carrying a packet stands for that packet unless it says otherwise.
            pps: w.pps.unwrap_or(i64::from(!packet.is_empty())),
            bps: w.bps,
            payload,
            has_payload,
            window: None,
            length: w.length,
            ttl: w.ttl,
            dscp: w.dscp,
            icmp_type: w.icmp_type,
            icmp_code: w.icmp_code,
            fragment: w.fragment,
            packet,
        };
        crate::packet::fill(&mut f);
        if let Ok(n) = f.proto.parse::<u8>() {
            f.proto = crate::packet::protocol_name(n);
        }
        Ok(f)
    }
}
