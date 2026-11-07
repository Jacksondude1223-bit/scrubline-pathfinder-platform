//! Every setting a policy can tune, in one catalog: where it sits in the policy, what it takes,
//! its default, its bounds and unit, and what it does. Validation holds a policy to the catalog,
//! the API serves it, and the datapath's settings take their defaults from it, so none of them can
//! drift from the others.
//!
//! A setting marked for profiles can also be set in a profile, for the protected addresses the
//! profile holds; the rest are the policy's alone. Settings are resolved once per program load:
//! the policy's, and one set for each profile, falling back to the policy's for whatever it leaves
//! unset, and to the catalog's default for whatever both leave unset.
use crate::{
    model::*,
    packet,
    reflection::{self, VECTORS},
    state::{EgressConfig, PulseConfig, ReputationConfig},
};
use ipnet::IpNet;
use serde_json::{json, Value};

/// What a setting takes.
#[derive(Debug, Clone, Copy)]
pub enum Kind {
    /// A number from `min` to `max`. Where `zero` is set, 0 takes the default, as it does for the
    /// settings that came before the rest.
    Number {
        default: f64,
        min: f64,
        max: f64,
        unit: &'static str,
        integer: bool,
        zero: bool,
    },
    /// One of these words.
    Choice {
        options: &'static [&'static str],
        default: &'static str,
    },
    Flag {
        default: bool,
    },
    /// A list, or a map of names to values, of what `of` says.
    List {
        of: &'static str,
    },
    Map {
        of: &'static str,
    },
    Text {
        of: &'static str,
    },
}
/// One setting.
#[derive(Debug, Clone, Copy)]
pub struct Setting {
    /// Its place in the policy: `syn_flood.hold_seconds`, `games[].http.slow.head_seconds`.
    pub path: &'static str,
    pub kind: Kind,
    pub about: &'static str,
    /// Whether a profile may set it too.
    pub profile: bool,
}
impl Setting {
    const fn p(mut self) -> Self {
        self.profile = true;
        self
    }
}
const fn num(
    path: &'static str,
    default: f64,
    min: f64,
    max: f64,
    unit: &'static str,
    about: &'static str,
) -> Setting {
    Setting {
        path,
        kind: Kind::Number {
            default,
            min,
            max,
            unit,
            integer: true,
            zero: false,
        },
        about,
        profile: false,
    }
}
/// A number where 0 takes the default.
const fn numz(
    path: &'static str,
    default: f64,
    max: f64,
    unit: &'static str,
    about: &'static str,
) -> Setting {
    Setting {
        path,
        kind: Kind::Number {
            default,
            min: 0.0,
            max,
            unit,
            integer: true,
            zero: true,
        },
        about,
        profile: false,
    }
}
const fn frac(
    path: &'static str,
    default: f64,
    min: f64,
    max: f64,
    about: &'static str,
) -> Setting {
    Setting {
        path,
        kind: Kind::Number {
            default,
            min,
            max,
            unit: "",
            integer: false,
            zero: false,
        },
        about,
        profile: false,
    }
}
const fn choice(
    path: &'static str,
    options: &'static [&'static str],
    default: &'static str,
    about: &'static str,
) -> Setting {
    Setting {
        path,
        kind: Kind::Choice { options, default },
        about,
        profile: false,
    }
}
const fn flag(path: &'static str, default: bool, about: &'static str) -> Setting {
    Setting {
        path,
        kind: Kind::Flag { default },
        about,
        profile: false,
    }
}
const fn list(path: &'static str, of: &'static str, about: &'static str) -> Setting {
    Setting {
        path,
        kind: Kind::List { of },
        about,
        profile: false,
    }
}
const fn map(path: &'static str, of: &'static str, about: &'static str) -> Setting {
    Setting {
        path,
        kind: Kind::Map { of },
        about,
        profile: false,
    }
}
const fn text(path: &'static str, of: &'static str, about: &'static str) -> Setting {
    Setting {
        path,
        kind: Kind::Text { of },
        about,
        profile: false,
    }
}
pub const MODES: &[&str] = &["enforce", "observe", "off"];
/// The default of a number that has none: unset, it is not there at all.
const NONE: f64 = f64::NAN;
const PPS: f64 = 1e9;
const DAY: f64 = 86_400.0;
const WEEK: f64 = 604_800.0;

/// Every setting.
pub static SETTINGS: &[Setting] = &[
    choice("sensitivity", &["high", "medium", "low"], "high", "How readily the flood guards engage: medium multiplies every flood threshold left unset by 4, low by 16.").p(),
    numz("pulse_floor_pps", 10_000.0, PPS, "pps", "The least a quarter second's traffic must reach to count toward a burst."),
    map("lists", "lists of CIDRs, by name", "Named lists of addresses that rules match their sources or destinations against (src_list, dst_list)."),
    // Crafted packets.
    choice("crafted.mode", MODES, "enforce", "What the crafted-packet checks do: drop, count only, or not look.").p(),
    map("crafted.checks", "check name to enforce, observe or off", "Modes for single checks (land, tcp_flags, martian_source, source_route, low_mss, fragment_overlap, ip_header, ip_options, extension_headers, tcp_header, udp_header, icmp, port_zero, fragment, length, oversize, tiny_fragment), over crafted.mode.").p(),
    num("crafted.low_mss", 500.0, 0.0, 1460.0, "bytes", "The largest MSS a SYN may offer and still be dropped as SACK Panic's shape; 0 drops none for it.").p(),
    num("crafted.min_fragment", 256.0, 8.0, 1480.0, "bytes", "The smallest fragment short of a datagram's last that is not dropped as too small.").p(),
    // Reflection.
    choice("reflection.mode", MODES, "enforce", "Every reflection vector's mode, unless reflection.vectors names its own.").p(),
    choice("reflection.cldap", MODES, "enforce", "CLDAP's mode, from before the other vectors; the same as reflection.vectors.cldap.").p(),
    map("reflection.vectors", "vector name to enforce, observe or off", "Modes for single vectors: cldap, dns, ntp, memcached, ssdp, snmp, chargen, echo, qotd, portmap, netbios, mssql, wsd, coap, mdns, ubiquiti, rip, and your own.").p(),
    map("reflection.judge", "vector name to always or flood", "How a vector's answers the server never asked for are judged: always, however few arrive, or flood, only while the prefix is flooded with them.").p(),
    numz("reflection.engage_pps", 1000.0, PPS, "pps", "Answers the server never asked for, a second, past which an aggregate counts as flooded, for the vectors judged in floods.").p(),
    num("reflection.hold_seconds", 60.0, 0.0, DAY, "seconds", "How long an aggregate counts as flooded after its last second over reflection.engage_pps.").p(),
    num("reflection.asked_within_seconds", 30.0, 1.0, 3600.0, "seconds", "How recently the server must have queried an address for its answer to count as asked for.").p(),
    num("reflection.reflecting_for_seconds", 30.0, 1.0, 3600.0, "seconds", "How long a source caught reflecting has the later fragments of its answers dropped."),
    list("reflection.custom", "vectors of your own", "Reflection vectors the guard does not know, at most 8: each a name, the UDP port its answers come from, what they open with, and how they are judged."),
    text("reflection.custom[].name", "lowercase letters, digits and _", "The vector's name, as drops, counters and reflection.vectors name it."),
    num("reflection.custom[].port", NONE, 1.0, 65535.0, "port", "The UDP port the vector's answers come from; not one a vector the guard knows uses."),
    text("reflection.custom[].payload_hex", "up to 64 bytes in hex", "What the vector's answers open with; any payload from the port when unset."),
    choice("reflection.custom[].judge", &["always", "flood"], "always", "How its answers the server never asked for are judged."),
    // Protocols.
    choice("protocols.mode", MODES, "enforce", "What the protocol guard does with IP protocols a protected address does not receive.").p(),
    list("protocols.allow", "protocol names or numbers", "Protocols every protected address receives besides TCP, UDP and ICMP: gre, esp, ah, sctp, ipip, ipv6, or a number.").p(),
    // ACK floods.
    choice("ack_flood.mode", MODES, "enforce", "What the ACK flood guard does.").p(),
    numz("ack_flood.engage_pps", 5000.0, PPS, "pps", "TCP for no connection, a second, past which an aggregate's guard engages.").p(),
    num("ack_flood.hold_seconds", 60.0, 0.0, DAY, "seconds", "How long the guard stays engaged after the last second over ack_flood.engage_pps.").p(),
    num("ack_flood.warm_seconds", 120.0, 0.0, 3600.0, "seconds", "How long the node must have watched the server's own traffic before the guard may engage.").p(),
    num("ack_flood.talked_within_seconds", 120.0, 1.0, 3600.0, "seconds", "How recently the server must have sent a source TCP for the source's segments to belong to a connection.").p(),
    num("ack_flood.handshake_seconds", 10.0, 0.0, 300.0, "seconds", "How long a client the server answered may take to finish its handshake.").p(),
    num("ack_flood.handshake_segments", 4.0, 0.0, 1000.0, "segments", "How many segments a client the server answered may send before the server's own say the connection is open.").p(),
    // SYN floods.
    choice("syn_flood.mode", MODES, "enforce", "What the SYN flood guard does.").p(),
    numz("syn_flood.engage_pps", 2000.0, PPS, "pps", "Opening SYNs from sources the server has no connection with, a second, past which an aggregate's guard engages.").p(),
    num("syn_flood.hold_seconds", 60.0, 0.0, DAY, "seconds", "How long the guard stays engaged after the last second over syn_flood.engage_pps.").p(),
    num("syn_flood.retry_within_seconds", 4.0, 1.0, 4.0, "seconds", "How long after a SYN its connection's next one still counts as a retry.").p(),
    num("syn_flood.retries_pps", 3.0, 1.0, 100.0, "pps", "The most SYNs a second one connection may send and still be a client retrying.").p(),
    // Fragments.
    choice("fragments.mode", MODES, "enforce", "What the fragment guard does.").p(),
    list("fragments.protocols", "tcp, icmp, udp, other", "Whose fragments are dropped; tcp and icmp when unset. udp drops every fragmented datagram, which some games send.").p(),
    // ICMP.
    choice("icmp.mode", MODES, "enforce", "What the ICMP guard does.").p(),
    numz("icmp.limit_pps", 1000.0, PPS, "pps", "ICMP, echo replies aside, an aggregate takes a second before the rest is dropped.").p(),
    numz("icmp.smurf_pps", 1000.0, PPS, "pps", "Echo replies the server never asked for, a second, past which an aggregate counts as flooded with them.").p(),
    num("icmp.hold_seconds", 60.0, 0.0, DAY, "seconds", "How long an aggregate counts as flooded with echo replies after its last second over.").p(),
    list("icmp.drop_types", "ICMP types, 0 to 255", "ICMP types dropped whatever their rate, such as 8 to answer no pings. Dropping 3, destination unreachable, breaks path MTU discovery.").p(),
    list("icmp.drop_types_v6", "ICMPv6 types, 0 to 255", "ICMPv6 types dropped whatever their rate, such as 128 to answer no pings. Dropping 2, packet too big, breaks path MTU discovery.").p(),
    choice("icmp.errors", &["verify", "allow"], "verify", "Whether an error that quotes no packet the prefix sent is dropped, or let through to the rate.").p(),
    // Aggregation.
    num("aggregation.v4", 24.0, 0.0, 32.0, "prefix length", "IPv4 prefixes narrower than this are judged for floods with the rest of the prefix of this length that holds them."),
    num("aggregation.v6", 48.0, 0.0, 128.0, "prefix length", "IPv6 prefixes narrower than this are judged for floods with the rest of the prefix of this length that holds them."),
    // Reputation.
    choice("reputation.fast_pass", &["challenge", "egress", "handshake", "off"], "challenge", "The weakest proof that takes a source past the classifiers and the challenge: an answered challenge, confirmed return traffic, or a completed handshake."),
    flag("reputation.penalty_box", false, "Whether sources that keep breaking the rules are boxed."),
    num("reputation.trust_seconds", 300.0, 1.0, DAY, "seconds", "How long a proof keeps a source trusted."),
    num("reputation.strikes", 4.0, 1.0, 1000.0, "strikes", "How many strikes within reputation.strike_window_seconds box a source."),
    num("reputation.strike_window_seconds", 30.0, 1.0, 3600.0, "seconds", "How long strikes count toward the box."),
    list("reputation.penalty_seconds", "1 to 8 durations in seconds", "Each sentence in the box in turn, the last repeating; 60, 600 and 3600 when unset."),
    num("reputation.forgive_seconds", 3600.0, 1.0, WEEK, "seconds", "How long a source must stay clean for its next sentence to drop back a step."),
    // Return traffic.
    choice("egress.lockdown", &["off", "limit", "drop"], "off", "What happens to unconfirmed sources while a prefix is under attack."),
    numz("egress.lockdown_pps", 500.0, PPS, "pps", "What an unconfirmed source may send a second while lockdown limits it."),
    numz("egress.grace_millis", 500.0, 600_000.0, "milliseconds", "How long a new source passes lockdown before it must be confirmed."),
    num("egress.confirm_packets", 10.0, 1.0, 100_000.0, "packets", "Packets the origin must send a client to confirm it."),
    num("egress.confirm_ticks", 3.0, 1.0, 40.0, "quarter seconds", "Quarter seconds those packets must spread over."),
    num("egress.confirm_window_seconds", 10.0, 1.0, 300.0, "seconds", "How long the packets and quarter seconds have to add up."),
    num("egress.confirmed_seconds", 120.0, 1.0, DAY, "seconds", "How long a confirmation lasts."),
    num("egress.visible_seconds", 30.0, 1.0, 3600.0, "seconds", "How recently the origin's traffic must have been seen for its return path to count as visible."),
    // Bursts.
    frac("pulse.crest", 4.0, 1.0, 1000.0, "How many times its mean a prefix's peak must reach to be shaped like a burst attack."),
    frac("pulse.duty", 0.5, 0.01, 1.0, "The most of the last minute's quarter seconds a burst attack's traffic may fill."),
    num("pulse.bursts", 3.0, 1.0, 240.0, "bursts", "How many bursts in the last minute make a prefix pulsing."),
    num("pulse.latch_seconds", 300.0, 0.0, DAY, "seconds", "How long a prefix is held as pulsing after the shape was last seen."),
    // On-demand mitigation.
    num("mitigation.hold_seconds", 300.0, 0.0, DAY, "seconds", "How long an on-demand tunnel's first wave of mitigation lasts after its traffic falls under its thresholds; each later wave of the same attack holds twice as long."),
    num("mitigation.campaign_seconds", 3600.0, 0.0, DAY, "seconds", "How soon after the last a wave must start to be part of the same attack."),
    num("mitigation.hold_max_seconds", 3600.0, 0.0, DAY, "seconds", "The longest any wave's mitigation holds."),
    // Classifiers.
    choice("ml.scope", &["all", "inspect"], "all", "Where the classifiers judge traffic: everything the stages let through, or only what zc inspect rules send them."),
    choice("ml.mode", &["enforce", "observe"], "enforce", "Whether the classifiers drop what they score at their threshold."),
    choice("ml.probing", &["tighten", "ignore"], "tighten", "Whether probing lowers a target's thresholds for a while."),
    num("ml.probe_hold_seconds", 300.0, 1.0, DAY, "seconds", "How long a step of tightening holds after the probing that set it."),
    num("ml.probe_min", 20.0, 1.0, 100_000.0, "near misses", "Near misses in ten seconds, a quarter of what was scored, that make a target probed."),
    // Game filters.
    num("games[].idle_seconds", 120.0, 1.0, DAY, "seconds", "How long a player that cleared a filter's gate stays admitted after its last packet."),
    list("games[].http.ports", "ports", "TCP ports the HTTP rules judge; the filter's own when unset."),
    list("games[].http.methods", "methods", "Methods allowed; GET, HEAD and POST when unset."),
    list("games[].http.user_agents", "prefixes", "Prefixes one of which a request's User-Agent must start with."),
    numz("games[].http.rate_per_source", 0.0, PPS, "requests a second", "Requests a second one source may make; no limit at 0."),
    numz("games[].http.rate_total", 0.0, PPS, "requests a second", "Requests a second from everyone together, past which only verified sources pass; no budget at 0."),
    numz("games[].http.max_body_bytes", 0.0, 1e12, "bytes", "The largest body a request may declare; no limit at 0."),
    choice("games[].http.default", &["allow", "drop"], "allow", "What a path no rule names gets."),
    list("games[].http.paths", "path rules", "Rules for single paths or prefixes."),
    num("games[].http.pipelined_max", 64.0, 1.0, 1024.0, "requests", "The most requests one segment may pipeline."),
    num("games[].http.line_max", 8192.0, 256.0, 65_536.0, "bytes", "The longest request or header line."),
    num("games[].http.headers_max", 100.0, 1.0, 1000.0, "lines", "The most header lines a request may carry."),
    num("games[].http.split_bytes", 512.0, 0.0, 65_536.0, "bytes", "A segment shorter than this that ends inside a request line is dropped as split on purpose."),
    choice("games[].http.tls", &["count", "ignore"], "count", "Whether each TLS ClientHello counts against the rates as a request."),
    choice("games[].http.slow.mode", MODES, "enforce", "What happens to a request that arrives too slowly."),
    num("games[].http.slow.head_seconds", 20.0, 1.0, 3600.0, "seconds", "How long a head may take, one more second for every min_rate bytes of it."),
    num("games[].http.slow.head_seconds_max", 40.0, 1.0, 3600.0, "seconds", "The longest a head may take however fast it arrives."),
    num("games[].http.slow.body_seconds", 20.0, 1.0, 3600.0, "seconds", "How long a body may take, one more second for every min_rate bytes of it."),
    num("games[].http.slow.min_rate", 500.0, 0.0, PPS, "bytes a second", "The bytes that buy a request one more second."),
    num("games[].http.slow.window_min", 64.0, 0.0, 65_535.0, "bytes", "The window, as a segment writes it, under which a client is not reading."),
    num("games[].http.slow.starved_seconds", 30.0, 1.0, 3600.0, "seconds", "How long a client may keep its window under window_min."),
    num("games[].http.slow.incomplete_max", 32.0, 1.0, 65_535.0, "requests", "The most requests one source may leave incomplete at once."),
    // Rules.
    choice("rules[].stage", &["asic", "fpga", "zc"], "asic", "Where the rule runs."),
    choice("rules[].action", &["drop", "permit", "rate_limit", "shape", "inspect", "count"], "drop", "What the rule does: shape holds everything it matches, from every source together, to pps."),
    numz("rules[].pps", 0.0, PPS, "pps", "The rate a rate_limit, shape, inspect or fpga meter holds to."),
    text("rules[].match.src_cidr", "a CIDR", "The source's prefix."),
    text("rules[].match.dst_cidr", "a CIDR", "The destination's prefix."),
    choice("rules[].match.proto", &["any", "tcp", "udp", "icmp", "gre", "esp", "ah", "sctp", "ipip", "ipv6"], "any", "The IP protocol."),
    numz("rules[].match.dport", 0.0, 65535.0, "port", "The destination port, or the first of a range."),
    numz("rules[].match.dport_to", 0.0, 65535.0, "port", "The last destination port of a range from dport."),
    numz("rules[].match.sport", 0.0, 65535.0, "port", "The source port, or the first of a range."),
    numz("rules[].match.sport_to", 0.0, 65535.0, "port", "The last source port of a range from sport."),
    text("rules[].match.tcp_flags", "flag names joined by , | or +", "TCP flags, compared as a set: syn, ack, fin, rst, psh, urg, ece, cwr, ns, or none."),
    numz("rules[].match.length_min", 0.0, 65535.0, "bytes", "The shortest IP packet, header and all."),
    numz("rules[].match.length_max", 0.0, 65535.0, "bytes", "The longest IP packet, header and all."),
    numz("rules[].match.ttl_min", 0.0, 255.0, "hops", "The lowest TTL or hop limit."),
    numz("rules[].match.ttl_max", 0.0, 255.0, "hops", "The highest TTL or hop limit."),
    num("rules[].match.dscp", NONE, 0.0, 63.0, "code point", "The DSCP code point the packet is marked with; any when unset."),
    num("rules[].match.icmp_type", NONE, 0.0, 255.0, "type", "An ICMP or ICMPv6 type; any when unset."),
    num("rules[].match.icmp_code", NONE, 0.0, 255.0, "code", "An ICMP or ICMPv6 code; any when unset."),
    choice("rules[].match.fragment", &["", "yes", "no"], "", "yes for fragments only, no for whole packets only."),
    text("rules[].match.payload_hex", "up to 64 bytes in hex", "Bytes the payload holds at payload_offset."),
    numz("rules[].match.payload_offset", 0.0, 1500.0, "bytes", "Where in the payload payload_hex sits."),
    text("rules[].match.payload_contains", "up to 64 bytes in hex", "Bytes the payload holds anywhere."),
    text("rules[].match.src_list", "a list's name", "A list the source is in."),
    text("rules[].match.dst_list", "a list's name", "A list the destination is in."),
    numz("rules[].match.attack_pps", 0.0, PPS, "pps", "Match only while the destination's protected prefix takes at least this many packets a second."),
    numz("rules[].match.attack_mbps", 0.0, 1e7, "Mbps", "Match only while the destination's protected prefix takes at least this many megabits a second."),
    // Profiles.
    text("profiles[].name", "a name", "The profile's name."),
    list("profiles[].prefixes", "CIDRs within the protected prefixes", "The addresses the profile's settings hold for; a protected address takes the most specific."),
];

/// The setting at a path.
pub fn setting(path: &str) -> Option<&'static Setting> {
    SETTINGS.iter().find(|s| s.path == path)
}
/// A number setting's default.
pub(crate) fn default_of(path: &str) -> f64 {
    match setting(path).map(|s| s.kind) {
        Some(Kind::Number { default, .. }) => default,
        _ => panic!("{path} is not a number setting"),
    }
}
/// A choice setting's default.
fn word_of(path: &str) -> &'static str {
    match setting(path).map(|s| s.kind) {
        Some(Kind::Choice { default, .. }) => default,
        _ => panic!("{path} is not a choice setting"),
    }
}

/// What a guard or check does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    #[default]
    Enforce,
    Observe,
    Off,
}
impl Mode {
    pub fn of(s: &str) -> Option<Self> {
        match s {
            "enforce" => Some(Mode::Enforce),
            "observe" => Some(Mode::Observe),
            "off" => Some(Mode::Off),
            _ => None,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Mode::Enforce => "enforce",
            Mode::Observe => "observe",
            Mode::Off => "off",
        }
    }
}
/// A set of 256 small numbers, as ICMP types are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Bits([u64; 4]);
impl Bits {
    pub fn has(&self, n: u8) -> bool {
        self.0[usize::from(n >> 6)] & (1 << (n & 63)) != 0
    }
    fn set(&mut self, n: u8) {
        self.0[usize::from(n >> 6)] |= 1 << (n & 63);
    }
    fn of(list: &[i64]) -> Self {
        let mut b = Bits::default();
        for n in list.iter().filter_map(|n| u8::try_from(*n).ok()) {
            b.set(n);
        }
        b
    }
}

/// A reflection vector of an operator's own, as the guard judges it.
#[derive(Debug, Clone, PartialEq)]
pub struct Custom {
    pub name: String,
    pub port: u16,
    pub prefix: Vec<u8>,
    pub kind: reflection::Kind,
}
#[derive(Debug, Clone, PartialEq)]
pub struct Crafted {
    pub mode: Mode,
    /// Each check's mode, in packet::Check order.
    pub checks: [Mode; 17],
    pub limits: packet::Limits,
}
#[derive(Debug, Clone, PartialEq)]
pub struct Reflection {
    /// Each vector's mode, the guard's own and then the operator's, in that order.
    pub modes: Vec<Mode>,
    /// How each vector's unasked answers are judged, where a policy says otherwise than the
    /// vector does.
    pub kinds: Vec<Option<reflection::Kind>>,
    pub engage_pps: u64,
    pub hold: i64,
    pub asked_within: i64,
}
#[derive(Debug, Clone, PartialEq)]
pub struct Protocols {
    pub mode: Mode,
    pub allow: Vec<String>,
}
#[derive(Debug, Clone, PartialEq)]
pub struct Ack {
    pub mode: Mode,
    pub engage_pps: u64,
    pub hold: i64,
    pub warm: i64,
    pub talked_within: i64,
    pub handshake: i64,
    pub handshake_segments: u32,
}
#[derive(Debug, Clone, PartialEq)]
pub struct Syn {
    pub mode: Mode,
    pub engage_pps: u64,
    pub hold: i64,
    /// In whole seconds, as the guard's record of SYNs keeps them.
    pub retry_within: i64,
    pub retries_pps: i64,
}
#[derive(Debug, Clone, PartialEq)]
pub struct Fragments {
    pub mode: Mode,
    /// Whose fragments are dropped, in guards::FRAGMENTED order: tcp, icmp, udp, other.
    pub protocols: [bool; 4],
}
#[derive(Debug, Clone, PartialEq)]
pub struct Icmp {
    pub mode: Mode,
    pub limit_pps: u64,
    pub smurf_pps: u64,
    pub hold: i64,
    pub drop: Bits,
    pub drop_v6: Bits,
    pub verify_errors: bool,
}
/// The guards' settings for the policy, or for one profile. Times are milliseconds.
#[derive(Debug, Clone, PartialEq)]
pub struct Guards {
    /// The profile's name; empty for the policy's own.
    pub name: String,
    pub sensitivity: &'static str,
    pub crafted: Crafted,
    pub reflection: Reflection,
    pub protocols: Protocols,
    pub ack: Ack,
    pub syn: Syn,
    pub fragments: Fragments,
    pub icmp: Icmp,
}
#[derive(Debug, Clone, PartialEq)]
pub struct Mitigation {
    pub hold: i64,
    pub campaign: i64,
    pub hold_max: i64,
}
/// The settings that are the policy's alone. Times are milliseconds.
#[derive(Debug, Clone, PartialEq)]
pub struct Global {
    pub aggregation: (u8, u8),
    pub reputation: ReputationConfig,
    pub egress: EgressConfig,
    pub pulse: PulseConfig,
    pub mitigation: Mitigation,
    pub probe_hold: i64,
    pub probe_min: u64,
    pub reflecting_for: i64,
    pub custom: Vec<Custom>,
}
/// A program's settings: its own, each profile's, and which addresses each profile holds, most
/// specific first.
#[derive(Debug, Clone, PartialEq)]
pub struct Resolved {
    pub global: Global,
    /// The policy's at 0, then each profile's in the order the program lists them.
    pub guards: Vec<Guards>,
    pub profiled: Vec<(IpNet, usize)>,
}
impl Resolved {
    /// The guards' settings for a destination: the most specific profile that holds it, or the
    /// policy's.
    pub fn for_address(&self, dst: Option<std::net::IpAddr>) -> usize {
        dst.and_then(|a| {
            self.profiled
                .iter()
                .find(|(net, _)| net.contains(&a))
                .map(|(_, i)| *i)
        })
        .unwrap_or(0)
    }
}

fn secs(path: &str, v: Option<i64>) -> i64 {
    v.map_or_else(|| default_of(path) as i64, |v| v)
        .saturating_mul(1000)
}
fn number(path: &str, v: Option<i64>) -> i64 {
    v.unwrap_or_else(|| default_of(path) as i64)
}
/// The decoded bytes of a hex string the validation has passed.
pub fn hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .filter_map(|i| u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok())
        .collect()
}
/// A program's custom vectors.
fn custom(p: &Program) -> Vec<Custom> {
    p.reflection
        .iter()
        .flat_map(|r| &r.custom)
        .filter_map(|c| {
            Some(Custom {
                name: c.name.clone(),
                port: u16::try_from(c.port).ok().filter(|p| *p > 0)?,
                prefix: hex(&c.payload_hex),
                kind: if c.judge == "flood" {
                    reflection::Kind::Flood
                } else {
                    reflection::Kind::Never
                },
            })
        })
        .take(reflection::CUSTOM_MAX)
        .collect()
}
/// Resolves a program's settings.
pub fn resolve(p: &Program) -> Resolved {
    let custom = custom(p);
    let mut guards = vec![guards_of(p, None, &custom)];
    let mut profiled = Vec::new();
    for prof in &p.profiles {
        let i = guards.len();
        guards.push(guards_of(p, Some(prof), &custom));
        profiled.extend(
            prof.prefixes
                .iter()
                .filter_map(|s| s.parse::<IpNet>().ok())
                .map(|net| (net, i)),
        );
    }
    profiled.sort_by_key(|(net, _)| std::cmp::Reverse(net.prefix_len()));
    let rep = p.reputation.as_ref();
    let eg = p.egress.as_ref();
    let pu = p.pulse.as_ref();
    let mi = p.mitigation.as_ref();
    let agg = p.aggregation.as_ref();
    let mut egress = EgressConfig {
        confirm_packets: number("egress.confirm_packets", eg.and_then(|e| e.confirm_packets)),
        confirm_ticks: number("egress.confirm_ticks", eg.and_then(|e| e.confirm_ticks)),
        confirm_window: secs(
            "egress.confirm_window_seconds",
            eg.and_then(|e| e.confirm_window_seconds),
        ),
        confirmed: secs(
            "egress.confirmed_seconds",
            eg.and_then(|e| e.confirmed_seconds),
        ),
        visible: secs("egress.visible_seconds", eg.and_then(|e| e.visible_seconds)),
        keep: EgressConfig::default().keep,
    };
    // The table keeps a client the origin has gone quiet to for as long as anything asks about
    // it: a confirmation, and the ACK flood guard's memory of whom the server talks TCP to.
    egress.keep = guards
        .iter()
        .map(|g| g.ack.talked_within)
        .chain([egress.keep, egress.confirmed])
        .max()
        .unwrap_or(egress.keep);
    let penalties: Vec<i64> = rep
        .map(|r| {
            r.penalty_seconds
                .iter()
                .map(|s| s.saturating_mul(1000))
                .collect()
        })
        .filter(|v: &Vec<i64>| !v.is_empty())
        .unwrap_or_else(|| ReputationConfig::default().penalties);
    let global = Global {
        aggregation: (
            number("aggregation.v4", agg.and_then(|a| a.v4)) as u8,
            number("aggregation.v6", agg.and_then(|a| a.v6)) as u8,
        ),
        reputation: ReputationConfig {
            trust: secs(
                "reputation.trust_seconds",
                rep.and_then(|r| r.trust_seconds),
            ),
            strikes: number("reputation.strikes", rep.and_then(|r| r.strikes)),
            window: secs(
                "reputation.strike_window_seconds",
                rep.and_then(|r| r.strike_window_seconds),
            ),
            penalties,
            forgive: secs(
                "reputation.forgive_seconds",
                rep.and_then(|r| r.forgive_seconds),
            ),
        },
        egress,
        pulse: PulseConfig {
            crest: pu
                .and_then(|x| x.crest)
                .unwrap_or(default_of("pulse.crest")),
            duty: pu.and_then(|x| x.duty).unwrap_or(default_of("pulse.duty")),
            bursts: number("pulse.bursts", pu.and_then(|x| x.bursts)) as u32,
            latch: secs("pulse.latch_seconds", pu.and_then(|x| x.latch_seconds)),
        },
        mitigation: Mitigation {
            hold: secs("mitigation.hold_seconds", mi.and_then(|m| m.hold_seconds)),
            campaign: secs(
                "mitigation.campaign_seconds",
                mi.and_then(|m| m.campaign_seconds),
            ),
            hold_max: secs(
                "mitigation.hold_max_seconds",
                mi.and_then(|m| m.hold_max_seconds),
            ),
        },
        probe_hold: secs(
            "ml.probe_hold_seconds",
            p.ml.as_ref().and_then(|m| m.probe_hold_seconds),
        ),
        probe_min: number("ml.probe_min", p.ml.as_ref().and_then(|m| m.probe_min)) as u64,
        reflecting_for: secs(
            "reflection.reflecting_for_seconds",
            p.reflection.as_ref().and_then(|r| r.reflecting_for_seconds),
        ),
        custom,
    };
    Resolved {
        global,
        guards,
        profiled,
    }
}
/// The guards' settings for the policy, or for one of its profiles over it.
fn guards_of(p: &Program, prof: Option<&Profile>, custom: &[Custom]) -> Guards {
    // A field of a section: the profile's if it sets it, else the policy's.
    macro_rules! pick {
        ($sec:ident, $f:ident) => {
            prof.and_then(|x| x.$sec.as_ref())
                .and_then(|s| s.$f)
                .or_else(|| p.$sec.as_ref().and_then(|s| s.$f))
        };
    }
    // The same, for a field where 0, an empty word or an empty list is unset.
    macro_rules! pick_set {
        ($sec:ident, $f:ident) => {
            prof.and_then(|x| x.$sec.as_ref())
                .map(|s| &s.$f)
                .filter(|v| !unset(*v))
                .or_else(|| p.$sec.as_ref().map(|s| &s.$f).filter(|v| !unset(*v)))
        };
    }
    let sensitivity = prof
        .map(|x| x.sensitivity.as_str())
        .filter(|s| !s.is_empty())
        .or_else(|| Some(p.sensitivity.as_str()).filter(|s| !s.is_empty()))
        .unwrap_or("high");
    let (sensitivity, scale): (&'static str, u64) = match sensitivity {
        "medium" => ("medium", 4),
        "low" => ("low", 16),
        _ => ("high", 1),
    };
    // A flood threshold: what is set, or the default scaled by the sensitivity.
    let flood = |path: &str, v: Option<&i64>| match v {
        Some(v) => *v as u64,
        None => (default_of(path) as u64).saturating_mul(scale),
    };
    let mode = |v: Option<&String>, path: &str| {
        v.and_then(|m| Mode::of(m))
            .or_else(|| Mode::of(word_of(path)))
            .unwrap_or_default()
    };
    // Crafted packets.
    let crafted_mode = mode(pick_set!(crafted, mode), "crafted.mode");
    let mut checks = [crafted_mode; 17];
    for (i, c) in packet::Check::ALL.iter().enumerate() {
        let of = |cp: Option<&CraftedPolicy>| {
            cp.and_then(|x| x.checks.get(c.name()))
                .and_then(|m| Mode::of(m))
        };
        if let Some(m) = of(prof.and_then(|x| x.crafted.as_ref())).or_else(|| {
            // The profile's mode for all checks beats the policy's for one.
            if prof
                .and_then(|x| x.crafted.as_ref())
                .is_some_and(|c| !c.mode.is_empty())
            {
                None
            } else {
                of(p.crafted.as_ref())
            }
        }) {
            checks[i] = m;
        }
    }
    let crafted = Crafted {
        mode: crafted_mode,
        checks,
        limits: packet::Limits {
            low_mss: number("crafted.low_mss", pick!(crafted, low_mss)) as u16,
            min_fragment: number("crafted.min_fragment", pick!(crafted, min_fragment)) as usize,
        },
    };
    // Reflection.
    let names: Vec<&str> = VECTORS
        .iter()
        .map(|v| v.name)
        .chain(custom.iter().map(|c| c.name.as_str()))
        .collect();
    let modes = names
        .iter()
        .map(|name| {
            let of = |r: Option<&ReflectionPolicy>| {
                r.and_then(|r| {
                    r.vectors
                        .get(*name)
                        .filter(|m| !m.is_empty())
                        .or_else(|| Some(&r.cldap).filter(|c| *name == "cldap" && !c.is_empty()))
                        .or_else(|| Some(&r.mode).filter(|m| !m.is_empty()))
                        .and_then(|m| Mode::of(m))
                })
            };
            of(prof.and_then(|x| x.reflection.as_ref()))
                .or_else(|| of(p.reflection.as_ref()))
                .unwrap_or_default()
        })
        .collect();
    let kinds = names
        .iter()
        .map(|name| {
            let of = |r: Option<&ReflectionPolicy>| {
                r.and_then(|r| r.judge.get(*name))
                    .and_then(|j| match j.as_str() {
                        "always" => Some(reflection::Kind::Never),
                        "flood" => Some(reflection::Kind::Flood),
                        _ => None,
                    })
            };
            of(prof.and_then(|x| x.reflection.as_ref())).or_else(|| of(p.reflection.as_ref()))
        })
        .collect();
    let reflection = Reflection {
        modes,
        kinds,
        engage_pps: flood("reflection.engage_pps", pick_set!(reflection, engage_pps)),
        hold: secs("reflection.hold_seconds", pick!(reflection, hold_seconds)),
        asked_within: secs(
            "reflection.asked_within_seconds",
            pick!(reflection, asked_within_seconds),
        ),
    };
    let protocols = Protocols {
        mode: mode(pick_set!(protocols, mode), "protocols.mode"),
        allow: pick_set!(protocols, allow)
            .map(|a| {
                a.iter()
                    .filter_map(|n| crate::guards::protocol(n))
                    .collect()
            })
            .unwrap_or_default(),
    };
    let ack = Ack {
        mode: mode(pick_set!(ack_flood, mode), "ack_flood.mode"),
        engage_pps: flood("ack_flood.engage_pps", pick_set!(ack_flood, engage_pps)),
        hold: secs("ack_flood.hold_seconds", pick!(ack_flood, hold_seconds)),
        warm: secs("ack_flood.warm_seconds", pick!(ack_flood, warm_seconds)),
        talked_within: secs(
            "ack_flood.talked_within_seconds",
            pick!(ack_flood, talked_within_seconds),
        ),
        handshake: secs(
            "ack_flood.handshake_seconds",
            pick!(ack_flood, handshake_seconds),
        ),
        handshake_segments: number(
            "ack_flood.handshake_segments",
            pick!(ack_flood, handshake_segments),
        ) as u32,
    };
    let syn = Syn {
        mode: mode(pick_set!(syn_flood, mode), "syn_flood.mode"),
        engage_pps: flood("syn_flood.engage_pps", pick_set!(syn_flood, engage_pps)),
        hold: secs("syn_flood.hold_seconds", pick!(syn_flood, hold_seconds)),
        retry_within: number(
            "syn_flood.retry_within_seconds",
            pick!(syn_flood, retry_within_seconds),
        ),
        retries_pps: number("syn_flood.retries_pps", pick!(syn_flood, retries_pps)),
    };
    let fragmented = pick_set!(fragments, protocols);
    let has = |name: &str| {
        fragmented.map_or(name == "tcp" || name == "icmp", |l| {
            l.iter().any(|p| p == name)
        })
    };
    let fragments = Fragments {
        mode: mode(pick_set!(fragments, mode), "fragments.mode"),
        protocols: [has("tcp"), has("icmp"), has("udp"), has("other")],
    };
    let icmp = Icmp {
        mode: mode(pick_set!(icmp, mode), "icmp.mode"),
        limit_pps: flood("icmp.limit_pps", pick_set!(icmp, limit_pps)),
        smurf_pps: flood("icmp.smurf_pps", pick_set!(icmp, smurf_pps)),
        hold: secs("icmp.hold_seconds", pick!(icmp, hold_seconds)),
        drop: Bits::of(pick_set!(icmp, drop_types).map_or(&[][..], |v| v.as_slice())),
        drop_v6: Bits::of(pick_set!(icmp, drop_types_v6).map_or(&[][..], |v| v.as_slice())),
        verify_errors: pick_set!(icmp, errors).is_none_or(|e| e != "allow"),
    };
    Guards {
        name: prof.map(|x| x.name.clone()).unwrap_or_default(),
        sensitivity,
        crafted,
        reflection,
        protocols,
        ack,
        syn,
        fragments,
        icmp,
    }
}
/// Whether a field counts as unset: 0, an empty word, or an empty list.
pub(crate) fn unset<T: Unset + ?Sized>(v: &T) -> bool {
    v.unset()
}
pub(crate) trait Unset {
    fn unset(&self) -> bool;
}
impl Unset for i64 {
    fn unset(&self) -> bool {
        *self == 0
    }
}
impl Unset for String {
    fn unset(&self) -> bool {
        self.is_empty()
    }
}
impl<T> Unset for Vec<T> {
    fn unset(&self) -> bool {
        self.is_empty()
    }
}

/// The catalog, as the API serves it.
pub fn catalog() -> Value {
    let rows: Vec<Value> = SETTINGS
        .iter()
        .map(|s| {
            let mut v = json!({"path": s.path, "about": s.about, "profile": s.profile});
            match s.kind {
                Kind::Number {
                    default,
                    min,
                    max,
                    unit,
                    integer,
                    zero,
                } => {
                    v["type"] = json!(if integer { "integer" } else { "number" });
                    v["default"] = if default.is_nan() {
                        Value::Null
                    } else {
                        json!(default)
                    };
                    v["min"] = json!(min);
                    v["max"] = json!(max);
                    if !unit.is_empty() {
                        v["unit"] = json!(unit);
                    }
                    if zero {
                        v["zero_takes_default"] = json!(true);
                    }
                }
                Kind::Choice { options, default } => {
                    v["type"] = json!("choice");
                    v["options"] = json!(options);
                    v["default"] = json!(default);
                }
                Kind::Flag { default } => {
                    v["type"] = json!("flag");
                    v["default"] = json!(default);
                }
                Kind::List { of } => {
                    v["type"] = json!("list");
                    v["of"] = json!(of);
                }
                Kind::Map { of } => {
                    v["type"] = json!("map");
                    v["of"] = json!(of);
                }
                Kind::Text { of } => {
                    v["type"] = json!("text");
                    v["of"] = json!(of);
                }
            }
            v
        })
        .collect();
    json!({ "settings": rows })
}
fn s(ms: i64) -> f64 {
    ms as f64 / 1000.0
}
/// The part of a node's program a policy's settings make: what the settings of a policy that is
/// not deployed resolve to.
pub fn program_of(p: &Policy) -> Program {
    Program {
        pulse_floor_pps: p.pulse_floor_pps,
        reputation: p.reputation.clone(),
        egress: p.egress.clone(),
        ml: p.ml.clone(),
        crafted: p.crafted.clone(),
        reflection: p.reflection.clone(),
        protocols: p.protocols.clone(),
        ack_flood: p.ack_flood.clone(),
        syn_flood: p.syn_flood.clone(),
        fragments: p.fragments.clone(),
        icmp: p.icmp.clone(),
        aggregation: p.aggregation.clone(),
        pulse: p.pulse.clone(),
        mitigation: p.mitigation.clone(),
        sensitivity: p.sensitivity.clone(),
        profiles: p.profiles.clone(),
        lists: p.lists.clone(),
        ..Default::default()
    }
}
/// A number where 0 takes the catalog's default, as the datapath reads it.
fn or_default(path: &str, v: i64) -> i64 {
    if v == 0 {
        default_of(path) as i64
    } else {
        v
    }
}
/// A word where empty takes the catalog's default.
fn word_or_default<'a>(path: &str, v: &'a str) -> &'a str {
    if v.is_empty() {
        word_of(path)
    } else {
        v
    }
}
/// A program's settings, every one of them, the way a policy sets them: the policy's own, and
/// each profile's.
pub fn effective(p: &Program) -> Value {
    let r = &resolve(p);
    let names: Vec<String> = VECTORS
        .iter()
        .map(|v| v.name.to_string())
        .chain(r.global.custom.iter().map(|c| c.name.clone()))
        .collect();
    let guards = |g: &Guards| {
        let checks: serde_json::Map<String, Value> = packet::Check::ALL
            .iter()
            .zip(g.crafted.checks)
            .map(|(c, m)| (c.name().to_string(), json!(m.name())))
            .collect();
        let vectors: serde_json::Map<String, Value> = names
            .iter()
            .zip(&g.reflection.modes)
            .map(|(n, m)| (n.clone(), json!(m.name())))
            .collect();
        // A vector the guard knows is judged its own way unless the policy says otherwise: DNS
        // and NTP's time answers in floods, the rest always.
        let word = |k: reflection::Kind| {
            if k == reflection::Kind::Flood {
                "flood"
            } else {
                "always"
            }
        };
        let judge: serde_json::Map<String, Value> = names
            .iter()
            .enumerate()
            .map(|(i, n)| {
                let own = (i >= VECTORS.len()).then(|| r.global.custom[i - VECTORS.len()].kind);
                let w = g.reflection.kinds[i].or(own).map_or("default", word);
                (n.clone(), json!(w))
            })
            .collect();
        let types = |b: &Bits| (0..=255u8).filter(|t| b.has(*t)).collect::<Vec<_>>();
        let fragmented: Vec<_> = crate::guards::FRAGMENTED
            .iter()
            .zip(g.fragments.protocols)
            .filter(|(_, on)| *on)
            .map(|(p, _)| *p)
            .collect();
        json!({
            "sensitivity": g.sensitivity,
            "crafted": {"mode": g.crafted.mode.name(), "checks": checks,
                "low_mss": g.crafted.limits.low_mss, "min_fragment": g.crafted.limits.min_fragment},
            "reflection": {"vectors": vectors, "judge": judge, "engage_pps": g.reflection.engage_pps,
                "hold_seconds": s(g.reflection.hold), "asked_within_seconds": s(g.reflection.asked_within)},
            "protocols": {"mode": g.protocols.mode.name(), "allow": g.protocols.allow},
            "ack_flood": {"mode": g.ack.mode.name(), "engage_pps": g.ack.engage_pps,
                "hold_seconds": s(g.ack.hold), "warm_seconds": s(g.ack.warm),
                "talked_within_seconds": s(g.ack.talked_within),
                "handshake_seconds": s(g.ack.handshake), "handshake_segments": g.ack.handshake_segments},
            "syn_flood": {"mode": g.syn.mode.name(), "engage_pps": g.syn.engage_pps,
                "hold_seconds": s(g.syn.hold), "retry_within_seconds": g.syn.retry_within,
                "retries_pps": g.syn.retries_pps},
            "fragments": {"mode": g.fragments.mode.name(), "protocols": fragmented},
            "icmp": {"mode": g.icmp.mode.name(), "limit_pps": g.icmp.limit_pps,
                "smurf_pps": g.icmp.smurf_pps, "hold_seconds": s(g.icmp.hold),
                "drop_types": types(&g.icmp.drop), "drop_types_v6": types(&g.icmp.drop_v6),
                "errors": if g.icmp.verify_errors { "verify" } else { "allow" }},
        })
    };
    let gl = &r.global;
    let mut policy = guards(&r.guards[0]);
    policy["reflection"]["reflecting_for_seconds"] = json!(s(gl.reflecting_for));
    policy["reflection"]["custom"] = json!(gl
        .custom
        .iter()
        .map(|c| json!({"name": c.name, "port": c.port,
            "payload_hex": c.prefix.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "judge": if c.kind == reflection::Kind::Flood { "flood" } else { "always" }}))
        .collect::<Vec<_>>());
    policy["pulse_floor_pps"] = json!(or_default("pulse_floor_pps", p.pulse_floor_pps));
    policy["aggregation"] = json!({"v4": gl.aggregation.0, "v6": gl.aggregation.1});
    let rep = p.reputation.clone().unwrap_or_default();
    policy["reputation"] = json!({
        "fast_pass": word_or_default("reputation.fast_pass", &rep.fast_pass),
        "penalty_box": rep.penalty_box,
        "trust_seconds": s(gl.reputation.trust),
        "strikes": gl.reputation.strikes, "strike_window_seconds": s(gl.reputation.window),
        "penalty_seconds": gl.reputation.penalties.iter().map(|p| s(*p)).collect::<Vec<_>>(),
        "forgive_seconds": s(gl.reputation.forgive)});
    let eg = p.egress.clone().unwrap_or_default();
    policy["egress"] = json!({
        "lockdown": word_or_default("egress.lockdown", &eg.lockdown),
        "lockdown_pps": or_default("egress.lockdown_pps", eg.lockdown_pps),
        "grace_millis": or_default("egress.grace_millis", eg.grace_millis),
        "confirm_packets": gl.egress.confirm_packets,
        "confirm_ticks": gl.egress.confirm_ticks,
        "confirm_window_seconds": s(gl.egress.confirm_window),
        "confirmed_seconds": s(gl.egress.confirmed), "visible_seconds": s(gl.egress.visible)});
    policy["pulse"] = json!({"crest": gl.pulse.crest, "duty": gl.pulse.duty,
        "bursts": gl.pulse.bursts, "latch_seconds": s(gl.pulse.latch)});
    policy["mitigation"] = json!({"hold_seconds": s(gl.mitigation.hold),
        "campaign_seconds": s(gl.mitigation.campaign), "hold_max_seconds": s(gl.mitigation.hold_max)});
    let ml = p.ml.clone().unwrap_or_default();
    policy["ml"] = json!({
        "scope": word_or_default("ml.scope", &ml.scope),
        "mode": word_or_default("ml.mode", &ml.mode),
        "probing": word_or_default("ml.probing", &ml.probing),
        "probe_hold_seconds": s(gl.probe_hold), "probe_min": gl.probe_min});
    policy["lists"] = json!(p.lists);
    let profiles: Vec<Value> = r.guards[1..]
        .iter()
        .enumerate()
        .map(|(i, g)| {
            let mut v = guards(g);
            v["name"] = json!(g.name);
            v["prefixes"] = json!(r
                .profiled
                .iter()
                .filter(|(_, at)| *at == i + 1)
                .map(|(net, _)| net.to_string())
                .collect::<Vec<_>>());
            v
        })
        .collect();
    json!({"policy": policy, "profiles": profiles})
}

/// The values a path holds in a policy: one for a plain path, one for each element of an array
/// it passes through (`games[]`), and none where it leads nowhere.
fn values<'a>(v: &'a Value, path: &str) -> Vec<(String, &'a Value)> {
    let mut at = vec![(String::new(), v)];
    for part in path.split('.') {
        let (key, many) = match part.strip_suffix("[]") {
            Some(k) => (k, true),
            None => (part, false),
        };
        let mut next = Vec::new();
        for (where_, v) in at {
            let Some(child) = v.get(key) else {
                continue;
            };
            let here = if where_.is_empty() {
                key.to_string()
            } else {
                format!("{where_}.{key}")
            };
            if many {
                for (i, item) in child.as_array().into_iter().flatten().enumerate() {
                    next.push((format!("{here}[{i}]"), item));
                }
            } else {
                next.push((here, child));
            }
        }
        at = next;
    }
    at
}
/// Holds every number a policy sets to the catalog's bounds, in the policy and in each profile.
pub fn check_numbers(policy: &Value) -> Result<(), String> {
    for s in SETTINGS {
        let Kind::Number {
            min,
            max,
            integer,
            unit,
            ..
        } = s.kind
        else {
            continue;
        };
        let mut found = values(policy, s.path);
        if s.profile {
            found.extend(values(policy, &format!("profiles[].{}", s.path)));
        }
        for (at, v) in found {
            if v.is_null() {
                continue;
            }
            let Some(n) = v.as_f64() else {
                return Err(format!("{at} must be a number"));
            };
            if integer && n.fract() != 0.0 {
                return Err(format!("{at} must be a whole number"));
            }
            if n < min || n > max {
                let unit = if unit.is_empty() {
                    String::new()
                } else {
                    format!(" {unit}")
                };
                return Err(format!("{at} must be within {min}..{max}{unit}, not {n}"));
            }
        }
    }
    Ok(())
}
/// The objects of a policy whose keys are checked: those holding settings and nothing else, and
/// those holding settings beside fields of their own. A profile's sections are checked too.
pub const OBJECTS: &[&str] = &[
    "",
    "crafted",
    "reflection",
    "reflection.custom[]",
    "protocols",
    "ack_flood",
    "syn_flood",
    "fragments",
    "icmp",
    "aggregation",
    "reputation",
    "egress",
    "pulse",
    "mitigation",
    "ml",
    "games[]",
    "games[].http",
    "games[].http.slow",
    "games[].http.paths[]",
    "rules[]",
    "rules[].match",
    "profiles[]",
];
/// The keys of those objects that are not settings: what names the policy, a filter or a rule,
/// and the routing a policy carries beside its settings.
const FIELDS: &[(&str, &[&str])] = &[
    (
        "",
        &[
            "id",
            "name",
            "protected",
            "steering",
            "tunnels",
            "sessions",
            "challenge_secret",
            "updated_at",
            "version",
        ],
    ),
    (
        "games[]",
        &[
            "id", "dst_cidr", "proto", "dport", "profile", "custom", "observe", "comment",
        ],
    ),
    (
        "games[].http.paths[]",
        &[
            "path",
            "prefix",
            "action",
            "methods",
            "user_agents",
            "rate_per_source",
            "rate_total",
            "max_body_bytes",
        ],
    ),
    ("rules[]", &["id", "priority", "comment"]),
];
/// The keys the settings give an object: the settings in it, and the objects of settings under
/// it. `profile` takes only what a profile may set.
fn settings_under(object: &str, profile: bool) -> Vec<&'static str> {
    SETTINGS
        .iter()
        .filter(|s| !profile || s.profile)
        .filter_map(|s| {
            let rest = if object.is_empty() {
                Some(s.path)
            } else {
                s.path.strip_prefix(object)?.strip_prefix('.')
            };
            rest.map(|r| r.split('.').next().unwrap_or(r).trim_end_matches("[]"))
        })
        .collect()
}
/// Every key an object of a policy takes, sorted. A profile's sections, `profiles[].crafted` and
/// the rest, take what a profile may set in them.
pub fn keys(object: &str) -> Vec<&'static str> {
    let mut keys: Vec<&'static str> = FIELDS
        .iter()
        .filter(|(o, _)| *o == object)
        .flat_map(|(_, f)| f.iter().copied())
        .collect();
    match object.strip_prefix("profiles[]") {
        Some("") => keys.extend(settings_under("", true)),
        Some(section) => keys.extend(settings_under(section.trim_start_matches('.'), true)),
        None => {}
    }
    keys.extend(settings_under(object, false));
    keys.sort_unstable();
    keys.dedup();
    keys
}
/// Turns down a key that is no setting, nor a field of the object it is in: a mistyped name would
/// otherwise be passed over without a word, and the setting it meant left at its default, or a
/// whole section of them.
pub fn check_known(policy: &Value) -> Result<(), String> {
    let mut objects: Vec<String> = OBJECTS.iter().map(|o| o.to_string()).collect();
    for s in SETTINGS.iter().filter(|s| s.profile) {
        if let Some((section, _)) = s.path.split_once('.') {
            let o = format!("profiles[].{section}");
            if !objects.contains(&o) {
                objects.push(o);
            }
        }
    }
    for object in &objects {
        let known = keys(object);
        let found = if object.is_empty() {
            vec![(String::new(), policy)]
        } else {
            values(policy, object)
        };
        let fields = FIELDS.iter().any(|(o, _)| o == object);
        for (at, v) in found {
            let Some(o) = v.as_object() else {
                continue;
            };
            if let Some(key) = o.keys().find(|k| !known.contains(&k.as_str())) {
                let takes = known.join(", ");
                return Err(if at.is_empty() {
                    format!("{key} is not a setting or field of a policy; a policy takes {takes}")
                } else if fields {
                    format!("{at}.{key} is not a setting or field; {at} takes {takes}")
                } else {
                    format!("{at}.{key} is not a setting; {at} takes {takes}")
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_number_defaults_within_its_bounds_and_every_choice_to_one_of_its_options() {
        for s in SETTINGS {
            match s.kind {
                Kind::Number {
                    default, min, max, ..
                } => assert!(
                    min <= max
                        && (default >= min && default <= max || default == 0.0 || default.is_nan()),
                    "{}",
                    s.path
                ),
                Kind::Choice { options, default } => {
                    assert!(options.contains(&default), "{}", s.path)
                }
                _ => {}
            }
            assert!(!s.about.is_empty(), "{}", s.path);
        }
        let mut paths: Vec<_> = SETTINGS.iter().map(|s| s.path).collect();
        paths.sort_unstable();
        let n = paths.len();
        paths.dedup();
        assert_eq!(paths.len(), n, "a setting is listed twice");
    }
    #[test]
    fn a_program_without_settings_resolves_to_the_defaults_the_guards_had() {
        let r = resolve(&Program::default());
        let g = &r.guards[0];
        assert_eq!(g.syn.engage_pps, crate::guards::SYN_ENGAGE_PPS);
        assert_eq!(g.syn.hold, crate::guards::SYN_HOLD);
        assert_eq!(g.ack.engage_pps, crate::guards::ENGAGE_PPS);
        assert_eq!(
            (g.ack.hold, g.ack.warm, g.ack.talked_within),
            (
                crate::guards::ACK_HOLD,
                crate::guards::ACK_WARM,
                crate::guards::TALKED_WITHIN
            )
        );
        assert_eq!(
            (g.ack.handshake, g.ack.handshake_segments),
            (crate::guards::HANDSHAKE, crate::guards::HANDSHAKE_SEGMENTS)
        );
        assert_eq!(g.icmp.limit_pps, crate::guards::ICMP_LIMIT_PPS);
        assert_eq!(g.icmp.smurf_pps, crate::guards::SMURF_PPS);
        assert_eq!(g.icmp.hold, crate::guards::SMURF_HOLD);
        assert_eq!(g.reflection.engage_pps, reflection::ENGAGE_PPS);
        assert_eq!(g.reflection.hold, reflection::FLOOD_HOLD);
        assert_eq!(g.reflection.asked_within, reflection::ASKED_WITHIN);
        assert_eq!(g.crafted.limits, packet::Limits::default());
        assert_eq!(g.fragments.protocols, [true, true, false, false]);
        assert_eq!(r.global.reflecting_for, reflection::REFLECTING_FOR);
        assert_eq!(r.global.reputation, ReputationConfig::default());
        assert_eq!(r.global.egress, EgressConfig::default());
        assert_eq!(r.global.pulse, PulseConfig::default());
        assert_eq!(r.global.aggregation, (24, 48));
        assert_eq!(
            r.global.mitigation,
            Mitigation {
                hold: crate::pipeline::MITIGATION_HOLD,
                campaign: crate::pipeline::CAMPAIGN,
                hold_max: crate::pipeline::MITIGATION_HOLD_MAX,
            }
        );
        assert_eq!(r.global.probe_hold, crate::pipeline::PROBE_HOLD);
    }
    #[test]
    fn a_profile_takes_its_own_settings_and_the_policys_for_the_rest() {
        let p = Program {
            syn_flood: Some(SynFloodPolicy {
                engage_pps: 9000,
                hold_seconds: Some(30),
                ..Default::default()
            }),
            sensitivity: "medium".into(),
            profiles: vec![Profile {
                name: "fivem".into(),
                prefixes: vec!["203.0.113.20/32".into()],
                sensitivity: "low".into(),
                syn_flood: Some(SynFloodPolicy {
                    hold_seconds: Some(5),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        };
        let r = resolve(&p);
        assert_eq!(
            (r.guards[0].syn.engage_pps, r.guards[0].syn.hold),
            (9000, 30_000)
        );
        // The policy's threshold, the profile's hold, and the profile's sensitivity for the
        // thresholds neither sets.
        assert_eq!(
            (r.guards[1].syn.engage_pps, r.guards[1].syn.hold),
            (9000, 5_000)
        );
        assert_eq!(r.guards[0].ack.engage_pps, 4 * crate::guards::ENGAGE_PPS);
        assert_eq!(r.guards[1].ack.engage_pps, 16 * crate::guards::ENGAGE_PPS);
        assert_eq!(r.for_address("203.0.113.20".parse().ok()), 1);
        assert_eq!(r.for_address("203.0.113.21".parse().ok()), 0);
    }
    #[test]
    fn a_mistyped_setting_or_one_out_of_bounds_is_turned_down() {
        let p = json!({"syn_flood": {"hold_secnods": 30}});
        let e = check_known(&p).unwrap_err();
        assert!(e.starts_with("syn_flood.hold_secnods is not a setting; syn_flood takes engage_pps, hold_seconds, mode,"), "{e}");
        let p = json!({"profiles": [{"name": "a", "icmp": {"limit": 5}}]});
        assert!(check_known(&p)
            .unwrap_err()
            .starts_with("profiles[0].icmp.limit is not a setting"));
        let p = json!({"profiles": [{"name": "a", "pulse": {"crest": 2}}]});
        assert!(check_known(&p)
            .unwrap_err()
            .starts_with("profiles[0].pulse is not a setting"));
        let p = json!({"games": [{"http": {"slow": {"head_seconds": 0}}}]});
        assert_eq!(
            check_numbers(&p).unwrap_err(),
            "games[0].http.slow.head_seconds must be within 1..3600 seconds, not 0"
        );
        let p = json!({"profiles": [{"syn_flood": {"retry_within_seconds": 9}}]});
        assert!(check_numbers(&p)
            .unwrap_err()
            .starts_with("profiles[0].syn_flood.retry_within_seconds must be within 1..4"));
        let p = json!({"pulse": {"bursts": 2.5}});
        assert_eq!(
            check_numbers(&p).unwrap_err(),
            "pulse.bursts must be a whole number"
        );
        let ok = json!({"syn_flood": {"mode": "observe", "hold_seconds": 30},
            "rules": [{"match": {"dport": 27015, "dport_to": 27030}}],
            "games": [{"http": {"rate_per_source": 5, "slow": {"head_seconds": 10}}}]});
        check_known(&ok).unwrap();
        check_numbers(&ok).unwrap();
    }
}
