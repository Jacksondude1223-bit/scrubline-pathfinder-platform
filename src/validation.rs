use crate::{bgp, gamefilter, model::*, tunnel, Result};
use ipnet::IpNet;
use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
};
pub fn node(n: &Node) -> Result<()> {
    if n.name.is_empty() {
        return Err("name required".into());
    }
    if n.name.contains(['/', '|']) {
        return Err("name must not contain '/' or '|'".into());
    }
    if !n.capacity_gbps.is_finite() || n.capacity_gbps < 0.0 {
        return Err("capacity_gbps must be finite and nonnegative".into());
    }
    if n.capacity_pps < 0 {
        return Err("capacity_pps must not be negative".into());
    }
    if !n.tunnel_src.is_empty() {
        tunnel_endpoint(&n.tunnel_src)?;
    }
    for b in &n.backends {
        if !["asic", "fpga", "zc"].contains(&b.as_str()) {
            return Err(format!("unknown backend {b:?}"));
        }
    }
    Ok(())
}
/// A node's own address for tunnels: IPv4, since the encapsulation arithmetic is IPv4's, and one
/// a peer can actually reach.
pub fn tunnel_endpoint(addr: &str) -> Result<()> {
    let a = addr
        .parse::<Ipv4Addr>()
        .map_err(|_| "tunnel_src must be IPv4")?;
    if a.is_unspecified() || a.is_multicast() || a.is_loopback() || a.is_broadcast() {
        return Err("tunnel_src is not a usable tunnel endpoint".into());
    }
    Ok(())
}
fn unique<'a>(values: impl Iterator<Item = &'a str>, name: &str) -> Result<()> {
    let mut seen = HashSet::new();
    for v in values {
        if v.is_empty() || v.contains('|') || !seen.insert(v) {
            return Err(format!("{name}: empty, invalid or duplicate id {v:?}"));
        }
    }
    Ok(())
}
/// The most of each thing one policy may hold. Every node is compiled a program from the policy,
/// reports counters for its prefixes and rules, and the control plane keeps both for each node,
/// so the policy's size is multiplied by the fabric's: these keep the largest policy on the
/// largest fabric (store::NODES_MAX nodes) within the memory a 16 GB server can give it.
pub const PREFIXES_MAX: usize = 1024;
pub const RULES_MAX: usize = 1024;
pub const GAMES_MAX: usize = 256;
pub const TUNNELS_MAX: usize = 1024;
pub const SESSIONS_MAX: usize = 256;
pub fn policy(p: &Policy) -> Result<()> {
    if p.name.is_empty() || p.protected.is_empty() {
        return Err("name and protected prefixes required".into());
    }
    for (what, n, max) in [
        ("protected prefixes", p.protected.len(), PREFIXES_MAX),
        ("rules", p.rules.len(), RULES_MAX),
        ("game filters", p.games.len(), GAMES_MAX),
        ("tunnels", p.tunnels.len(), TUNNELS_MAX),
        ("sessions", p.sessions.len(), SESSIONS_MAX),
    ] {
        if n > max {
            return Err(format!(
                "a policy holds at most {max} {what}, and this one has {n}; every node is compiled and reports all of them"
            ));
        }
    }
    let mut protected = HashSet::new();
    let mut networks = HashMap::new();
    for prefix in &p.protected {
        let net = prefix
            .parse::<IpNet>()
            .map_err(|e| format!("protected prefix {prefix:?}: {e}"))?;
        // ExaBGP refuses a route with host bits set, so such a prefix would never be announced.
        if net.addr() != net.network() {
            return Err(format!(
                "protected prefix {prefix} has host bits set; write it as {}",
                net.trunc()
            ));
        }
        // A repeat would be announced, enforced and attributed twice per node, and another
        // spelling of one network (case, leading zeros) is the same repeat.
        if let Some(other) = networks.insert(net, prefix) {
            return Err(if other == prefix {
                format!("duplicate protected prefix {prefix}")
            } else {
                format!("protected prefixes {other} and {prefix} are the same network")
            });
        }
        protected.insert(prefix.clone());
    }
    unique(p.steering.iter().map(|s| s.prefix.as_str()), "steering")?;
    for s in &p.steering {
        if !protected.contains(&s.prefix) {
            return Err("steering prefix is not protected".into());
        }
        if s.regions.iter().any(|r| r.trim().is_empty()) {
            return Err("steering region must not be empty".into());
        }
        for c in &s.communities {
            bgp::validate_community(c)?;
        }
    }
    // A node judges only traffic to the prefixes it carries, so a filter or rule aimed anywhere
    // else would be accepted and never apply.
    let reaches = |cidr: &str| {
        cidr.parse::<IpNet>().is_ok_and(|target| {
            networks
                .keys()
                .any(|p: &IpNet| p.contains(&target.addr()) || target.contains(&p.addr()))
        })
    };
    unique(p.games.iter().map(|g| g.id.as_str()), "games")?;
    for g in &p.games {
        if !g.dst_cidr.is_empty() && g.dst_cidr.parse::<IpNet>().is_ok() && !reaches(&g.dst_cidr) {
            return Err(format!(
                "game filter {:?}: dst_cidr {} is outside every protected prefix, so no node would ever judge it",
                g.id, g.dst_cidr
            ));
        }
        if !(0..=65535).contains(&g.dport) {
            return Err("game dport must be within 0..65535".into());
        }
        if !["", "any", "udp", "tcp"].contains(&g.proto.to_ascii_lowercase().as_str()) {
            return Err("unknown game proto".into());
        }
        if g.dst_cidr.is_empty()
            && g.dport == 0
            && g.http.as_ref().is_none_or(|h| h.ports.is_empty())
        {
            return Err("game filter needs a dst_cidr, a dport or http ports".into());
        }
    }
    gamefilter::unshadowed(&gamefilter::compile(&p.games)?)?;
    unique(p.tunnels.iter().map(|t| t.id.as_str()), "tunnels")?;
    let mut carried = HashSet::new();
    let mut ends = HashMap::new();
    let mut dedicated = HashSet::new();
    for t in &p.tunnels {
        tunnel::validate(t, Some(&protected))?;
        if !t.local.is_empty() {
            if !dedicated.insert(t.local.as_str()) {
                return Err("dedicated tunnel endpoints must be unique".into());
            }
            let addr = t
                .local
                .parse::<std::net::IpAddr>()
                .map_err(|_| "invalid local endpoint")?;
            if p.protected
                .iter()
                .any(|v| v.parse::<IpNet>().is_ok_and(|net| net.contains(&addr)))
            {
                return Err("dedicated endpoint must be outside protected prefixes".into());
            }
            if p.tunnels.iter().any(|other| other.remote == t.local) {
                return Err("dedicated endpoint cannot be a customer remote endpoint".into());
            }
        }
        // Every tunnel on a node starts from the node's one address, and Linux holds one tunnel
        // per encapsulation, remote and key: the second would fail to build on every node.
        let kind = if t.r#type.is_empty() {
            "gre"
        } else {
            t.r#type.as_str()
        };
        if let Some(other) = ends.insert((kind, t.remote.as_str(), t.key), t.id.as_str()) {
            return Err(format!(
                "tunnels {other} and {} both run {kind} to {} with key {}; give one a distinct key",
                t.id, t.remote, t.key
            ));
        }
        for prefix in &t.prefixes {
            if !carried.insert(prefix) {
                return Err("a prefix has one return path".into());
            }
        }
    }
    unique(p.sessions.iter().map(|s| s.id.as_str()), "sessions")?;
    let mut peers = HashSet::new();
    let mut protocols = HashSet::new();
    for s in &p.sessions {
        bgp::validate_session(s, Some(&protected))?;
        // BIRD names each session from its id with dashes folded to underscores, and a duplicate
        // protocol name makes BIRD reject the node's whole session configuration.
        if !protocols.insert(s.id.replace('-', "_")) {
            return Err(format!(
                "session id {:?} renders to the same BIRD protocol as another session",
                s.id
            ));
        }
        if !peers.insert(&s.peer_ip) {
            return Err("duplicate session peer".into());
        }
    }
    if p.pulse_floor_pps < 0 {
        return Err("pulse_floor_pps must not be negative".into());
    }
    if let Some(r) = &p.reputation {
        if !["", "challenge", "egress", "handshake", "off"].contains(&r.fast_pass.as_str()) {
            return Err("invalid reputation.fast_pass".into());
        }
    }
    if let Some(m) = &p.ml {
        if !["", "all", "inspect"].contains(&m.scope.as_str()) {
            return Err(format!(
                "ml.scope {:?}: use all, or inspect for only what zc inspect rules send the model",
                m.scope
            ));
        }
        if !["", "enforce", "observe"].contains(&m.mode.as_str()) {
            return Err(format!("ml.mode {:?}: use enforce or observe", m.mode));
        }
        if !["", "tighten", "ignore"].contains(&m.probing.as_str()) {
            return Err(format!("ml.probing {:?}: use tighten or ignore", m.probing));
        }
    }
    custom_vectors(p.reflection.as_ref())?;
    let custom = p
        .reflection
        .as_ref()
        .map_or(&[][..], |r| r.custom.as_slice());
    sections("", &Sections::of_policy(p), custom)?;
    profiles(p, &reaches, custom)?;
    lists(p)?;
    if let Some(e) = &p.egress {
        if !["", "off", "limit", "drop"].contains(&e.lockdown.as_str())
            || e.lockdown_pps < 0
            || e.grace_millis < 0
        {
            return Err("invalid egress lockdown configuration".into());
        }
        if e.lockdown == "drop" && e.grace_millis != 0 && e.grace_millis < 50 {
            return Err("a dropping lockdown needs at least 50ms grace".into());
        }
    }
    unique(p.rules.iter().map(|r| r.id.as_str()), "rules")?;
    for r in &p.rules {
        if !["asic", "fpga", "zc"].contains(&r.stage.as_str()) {
            return Err(format!("unknown stage {:?}", r.stage));
        }
        if !["drop", "permit", "rate_limit", "shape", "inspect", "count"]
            .contains(&r.action.as_str())
        {
            return Err(format!("unknown action {:?}", r.action));
        }
        if r.stage == "asic" && (r.action == "rate_limit" || r.action == "shape") {
            return Err(format!(
                "the asic stage cannot meter; use the fpga or zc stage for {}",
                r.action
            ));
        }
        if r.pps < 0 || (r.action == "rate_limit" || r.action == "shape") && r.pps == 0 {
            return Err(format!(
                "{} requires positive pps; pps must not be negative",
                if r.action == "shape" {
                    "shape"
                } else {
                    "rate_limit"
                }
            ));
        }
        let meters = r.stage == "fpga" && (r.action == "rate_limit" || r.action == "shape")
            || r.stage == "zc"
                && (r.action == "rate_limit" || r.action == "shape" || r.action == "inspect");
        if r.pps > 0 && !meters {
            return Err(
                "pps belongs on an fpga rate_limit or shape rule, or a zc rate_limit, shape or inspect rule"
                    .into(),
            );
        }
        // The datapath compares these as text, so a value outside the vocabulary is a rule that
        // never matches, and proto is also written into the TCAM key.
        let proto = r.r#match.proto.to_ascii_lowercase();
        if !["", "any", "tcp", "udp", "icmp"].contains(&proto.as_str())
            && !crate::guards::PROTOCOLS.contains(&proto.as_str())
        {
            return Err(format!(
                "rule {:?}: unknown proto {:?}; use tcp, udp, icmp, {} or any",
                r.id,
                r.r#match.proto,
                crate::guards::PROTOCOLS.join(", ")
            ));
        }
        // Their packets carry no ports the node reads.
        if crate::guards::PROTOCOLS.contains(&proto.as_str())
            && (r.r#match.dport != 0
                || r.r#match.sport != 0
                || r.r#match.dport_to != 0
                || r.r#match.sport_to != 0)
        {
            return Err(format!("rule {:?}: {proto} has no ports to match", r.id));
        }
        matches(r, &proto, p)?;
        if !r
            .r#match
            .tcp_flags
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b",|+".contains(&c))
        {
            return Err(format!(
                "rule {:?}: tcp_flags may only hold flag names separated by ',', '|' or '+'",
                r.id
            ));
        }
        let mut families = Vec::new();
        for cidr in [&r.r#match.src_cidr, &r.r#match.dst_cidr] {
            if !cidr.is_empty() {
                let net = cidr.parse::<IpNet>().map_err(|e| e.to_string())?;
                families.push(net.addr().is_ipv4());
            }
        }
        if !r.r#match.dst_cidr.is_empty() && !reaches(&r.r#match.dst_cidr) {
            return Err(format!(
                "rule {:?}: dst_cidr {} is outside every protected prefix, so it would never match",
                r.id, r.r#match.dst_cidr
            ));
        }
        if families.len() == 2 && families[0] != families[1] {
            return Err(format!(
                "rule {:?}: src_cidr and dst_cidr are different address families, so it would never match",
                r.id
            ));
        }
        if !(0..=65535).contains(&r.r#match.dport) || !(0..=65535).contains(&r.r#match.sport) {
            return Err("match ports must be within 0..65535".into());
        }
    }
    let value = serde_json::to_value(p).map_err(|e| e.to_string())?;
    crate::tuning::check_numbers(&value)?;
    tuned(p)
}
/// The most lists one policy may name, the most addresses all of them may hold together, and the
/// most profiles and profile prefixes. Every node is compiled its policy's lists and profiles, so
/// these are bounded for the same reason the rules are.
pub const LISTS_MAX: usize = 64;
pub const LIST_ENTRIES_MAX: usize = 4096;
pub const PROFILES_MAX: usize = 64;
pub const PROFILE_PREFIXES_MAX: usize = PREFIXES_MAX;
/// The most bytes a payload match, or a custom vector's opening, may name.
pub const PAYLOAD_MATCH_MAX: usize = 64;

/// Whether a name is one a list, a profile or a custom vector can take: letters, digits, `_` and
/// `-`, as counters and drop reasons carry it.
fn name_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}
/// Bytes written in hex, at most PAYLOAD_MATCH_MAX of them.
fn hex_ok(what: &str, s: &str) -> Result<()> {
    if s.len() % 2 != 0 || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "{what} {s:?}: write bytes as pairs of hex digits, such as 0a1b"
        ));
    }
    if s.len() / 2 > PAYLOAD_MATCH_MAX {
        return Err(format!(
            "{what} names {} bytes; it may name at most {PAYLOAD_MATCH_MAX}",
            s.len() / 2
        ));
    }
    Ok(())
}

/// The guards' sections: the policy's own, or one profile's over them.
struct Sections<'a> {
    sensitivity: &'a str,
    crafted: Option<&'a CraftedPolicy>,
    reflection: Option<&'a ReflectionPolicy>,
    protocols: Option<&'a ProtocolPolicy>,
    ack_flood: Option<&'a AckFloodPolicy>,
    syn_flood: Option<&'a SynFloodPolicy>,
    fragments: Option<&'a FragmentPolicy>,
    icmp: Option<&'a IcmpPolicy>,
}
impl<'a> Sections<'a> {
    fn of_policy(p: &'a Policy) -> Self {
        Sections {
            sensitivity: &p.sensitivity,
            crafted: p.crafted.as_ref(),
            reflection: p.reflection.as_ref(),
            protocols: p.protocols.as_ref(),
            ack_flood: p.ack_flood.as_ref(),
            syn_flood: p.syn_flood.as_ref(),
            fragments: p.fragments.as_ref(),
            icmp: p.icmp.as_ref(),
        }
    }
    fn of_profile(p: &'a Profile) -> Self {
        Sections {
            sensitivity: &p.sensitivity,
            crafted: p.crafted.as_ref(),
            reflection: p.reflection.as_ref(),
            protocols: p.protocols.as_ref(),
            ack_flood: p.ack_flood.as_ref(),
            syn_flood: p.syn_flood.as_ref(),
            fragments: p.fragments.as_ref(),
            icmp: p.icmp.as_ref(),
        }
    }
}

/// Validates the guards' sections. `at` is where they sit, empty for the policy's own and
/// `profiles[i].` for a profile's; `custom` is the policy's own reflection vectors.
fn sections(at: &str, s: &Sections, custom: &[CustomVector]) -> Result<()> {
    if !["", "high", "medium", "low"].contains(&s.sensitivity) {
        return Err(format!(
            "{at}sensitivity {:?}: use high, medium (flood thresholds left unset times 4) or low (times 16)",
            s.sensitivity
        ));
    }
    let mode = |m: &str| ["", "enforce", "observe", "off"].contains(&m);
    // A threshold in packets a second: zero takes the guard's own.
    let pps = |v: i64, what: &str, default: u64| {
        if (0..=1_000_000_000).contains(&v) {
            Ok(())
        } else {
            Err(format!(
                "{at}{what} must be within 0..1000000000; 0 takes {default}"
            ))
        }
    };
    if let Some(c) = s.crafted {
        if !mode(&c.mode) {
            return Err(format!(
                "{at}crafted.mode {:?}: use enforce, observe, or off to stop checking packets",
                c.mode
            ));
        }
        for (name, m) in &c.checks {
            if !crate::packet::Check::ALL.iter().any(|k| k.name() == name) {
                let names: Vec<_> = crate::packet::Check::ALL.iter().map(|k| k.name()).collect();
                return Err(format!(
                    "{at}crafted.checks: {name:?} is not a check; use {}",
                    names.join(", ")
                ));
            }
            if m.is_empty() || !mode(m) {
                return Err(format!(
                    "{at}crafted.checks.{name} {m:?}: use enforce, observe, or off"
                ));
            }
        }
    }
    if let Some(r) = s.reflection {
        if !mode(&r.cldap) {
            return Err(format!(
                "{at}reflection.cldap {:?}: use enforce, observe, or off to stop looking for reflected CLDAP",
                r.cldap
            ));
        }
        if !mode(&r.mode) {
            return Err(format!(
                "{at}reflection.mode {:?}: use enforce, observe, or off to stop looking for reflected answers",
                r.mode
            ));
        }
        let known = |name: &str| {
            crate::reflection::vector(name).is_some() || custom.iter().any(|c| c.name == name)
        };
        let names = || {
            crate::reflection::VECTORS
                .iter()
                .map(|v| v.name)
                .chain(custom.iter().map(|c| c.name.as_str()))
                .collect::<Vec<_>>()
                .join(", ")
        };
        for (name, m) in &r.vectors {
            if !known(name) {
                return Err(format!(
                    "{at}reflection.vectors: {name:?} is not a vector the guard knows; use {}",
                    names()
                ));
            }
            if !mode(m) {
                return Err(format!(
                    "{at}reflection.vectors.{name} {m:?}: use enforce, observe, or off"
                ));
            }
        }
        if !r.cldap.is_empty() && r.vectors.get("cldap").is_some_and(|m| !m.is_empty()) {
            return Err(format!(
                "{at}reflection.cldap and {at}reflection.vectors.cldap are both set; set one"
            ));
        }
        pps(
            r.engage_pps,
            "reflection.engage_pps",
            crate::reflection::ENGAGE_PPS,
        )?;
        for (name, j) in &r.judge {
            if !known(name) {
                return Err(format!(
                    "{at}reflection.judge: {name:?} is not a vector the guard knows; use {}",
                    names()
                ));
            }
            if !["always", "flood"].contains(&j.as_str()) {
                return Err(format!(
                    "{at}reflection.judge.{name} {j:?}: use always, or flood to drop its answers only while the prefix is flooded with them"
                ));
            }
        }
        if !at.is_empty() && !r.custom.is_empty() {
            return Err(format!(
                "{at}reflection.custom: vectors are the policy's; define them in reflection.custom, and a profile may set their modes"
            ));
        }
        if !at.is_empty() && r.reflecting_for_seconds.is_some() {
            return Err(format!(
                "{at}reflection.reflecting_for_seconds is the policy's alone; set it in reflection"
            ));
        }
    }
    if let Some(g) = s.protocols {
        if !mode(&g.mode) {
            return Err(format!(
                "{at}protocols.mode {:?}: use enforce, observe, or off to stop looking at protocols",
                g.mode
            ));
        }
        for name in &g.allow {
            if crate::guards::protocol(name).is_none() {
                return Err(format!(
                    "{at}protocols.allow {name:?}: name a protocol ({}) or give its number; tcp, udp and icmp always pass",
                    crate::guards::PROTOCOLS.join(", ")
                ));
            }
        }
    }
    if let Some(a) = s.ack_flood {
        if !mode(&a.mode) {
            return Err(format!(
                "{at}ack_flood.mode {:?}: use enforce, observe, or off to stop looking for ACK floods",
                a.mode
            ));
        }
        pps(
            a.engage_pps,
            "ack_flood.engage_pps",
            crate::guards::ENGAGE_PPS,
        )?;
    }
    if let Some(g) = s.syn_flood {
        if !mode(&g.mode) {
            return Err(format!(
                "{at}syn_flood.mode {:?}: use enforce, observe, or off to stop looking for SYN floods",
                g.mode
            ));
        }
        pps(
            g.engage_pps,
            "syn_flood.engage_pps",
            crate::guards::SYN_ENGAGE_PPS,
        )?;
    }
    if let Some(g) = s.fragments {
        if !mode(&g.mode) {
            return Err(format!(
                "{at}fragments.mode {:?}: use enforce, observe, or off to stop looking at fragments",
                g.mode
            ));
        }
        let mut seen = HashSet::new();
        for name in &g.protocols {
            if !crate::guards::FRAGMENTED.contains(&name.as_str()) {
                return Err(format!(
                    "{at}fragments.protocols {name:?}: use tcp, icmp, udp or other"
                ));
            }
            if !seen.insert(name) {
                return Err(format!("{at}fragments.protocols names {name} twice"));
            }
        }
    }
    if let Some(g) = s.icmp {
        if !mode(&g.mode) {
            return Err(format!(
                "{at}icmp.mode {:?}: use enforce, observe, or off to stop looking at ICMP",
                g.mode
            ));
        }
        pps(g.limit_pps, "icmp.limit_pps", crate::guards::ICMP_LIMIT_PPS)?;
        pps(g.smurf_pps, "icmp.smurf_pps", crate::guards::SMURF_PPS)?;
        for (what, types) in [
            ("drop_types", &g.drop_types),
            ("drop_types_v6", &g.drop_types_v6),
        ] {
            if let Some(t) = types.iter().find(|t| !(0..=255).contains(*t)) {
                return Err(format!(
                    "{at}icmp.{what}: {t} is not a type; ICMP types are 0 to 255"
                ));
            }
        }
        if !["", "verify", "allow"].contains(&g.errors.as_str()) {
            return Err(format!(
                "{at}icmp.errors {:?}: use verify, or allow to let errors that quote no packet the prefix sent through to the rate",
                g.errors
            ));
        }
    }
    Ok(())
}

/// The reflection vectors of the operator's own.
fn custom_vectors(r: Option<&ReflectionPolicy>) -> Result<()> {
    let Some(r) = r else {
        return Ok(());
    };
    if r.custom.len() > crate::reflection::CUSTOM_MAX {
        return Err(format!(
            "reflection.custom holds {} vectors; the guard takes at most {} of your own",
            r.custom.len(),
            crate::reflection::CUSTOM_MAX
        ));
    }
    let mut names = HashSet::new();
    let mut ports = HashMap::new();
    for (i, c) in r.custom.iter().enumerate() {
        let at = format!("reflection.custom[{i}]");
        let lowercase = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_';
        if c.name.is_empty() || c.name.len() > 32 || !c.name.bytes().all(lowercase) {
            return Err(format!(
                "{at}.name {:?}: name the vector with lowercase letters, digits and _",
                c.name
            ));
        }
        if crate::reflection::vector(&c.name).is_some() {
            return Err(format!(
                "{at}.name {:?} is a vector the guard knows; set its mode in reflection.vectors and how it is judged in reflection.judge",
                c.name
            ));
        }
        if !names.insert(c.name.as_str()) {
            return Err(format!("{at}.name {:?} names two vectors", c.name));
        }
        if !(1..=65535).contains(&c.port) {
            return Err(format!(
                "{at}.port {}: give the UDP port its answers come from, 1 to 65535",
                c.port
            ));
        }
        if let Some(v) = crate::reflection::VECTORS
            .iter()
            .find(|v| i64::from(v.port) == c.port)
        {
            return Err(format!(
                "{at}.port {} is {}'s, which the guard knows; set reflection.vectors.{} and reflection.judge.{} instead",
                c.port, v.name, v.name, v.name
            ));
        }
        if let Some(other) = ports.insert(c.port, c.name.as_str()) {
            return Err(format!(
                "{at}.port {} is also {other}'s; a port's answers are one vector's",
                c.port
            ));
        }
        if !c.payload_hex.is_empty() {
            hex_ok(&format!("{at}.payload_hex"), &c.payload_hex)?;
        }
        if !["", "always", "flood"].contains(&c.judge.as_str()) {
            return Err(format!(
                "{at}.judge {:?}: use always, or flood to drop its answers only while the prefix is flooded with them",
                c.judge
            ));
        }
    }
    Ok(())
}

/// The profiles: named, each holding addresses no other profile holds, and their sections as
/// valid as the policy's.
fn profiles(p: &Policy, reaches: &dyn Fn(&str) -> bool, custom: &[CustomVector]) -> Result<()> {
    if p.profiles.len() > PROFILES_MAX {
        return Err(format!(
            "a policy holds at most {PROFILES_MAX} profiles, and this one has {}",
            p.profiles.len()
        ));
    }
    let held: usize = p.profiles.iter().map(|x| x.prefixes.len()).sum();
    if held > PROFILE_PREFIXES_MAX {
        return Err(format!(
            "the profiles hold {held} prefixes together; they may hold at most {PROFILE_PREFIXES_MAX}"
        ));
    }
    let mut names = HashSet::new();
    let mut prefixes: HashMap<IpNet, &str> = HashMap::new();
    for (i, x) in p.profiles.iter().enumerate() {
        let at = format!("profiles[{i}]");
        if !name_ok(&x.name) {
            return Err(format!(
                "{at}.name {:?}: name the profile with letters, digits, _ and -",
                x.name
            ));
        }
        if !names.insert(x.name.as_str()) {
            return Err(format!("{at}.name {:?} names two profiles", x.name));
        }
        if x.prefixes.is_empty() {
            return Err(format!(
                "{at}: profile {:?} holds no prefixes, so its settings would hold for nothing",
                x.name
            ));
        }
        for prefix in &x.prefixes {
            let net = prefix
                .parse::<IpNet>()
                .map_err(|e| format!("{at}.prefixes {prefix:?}: {e}"))?;
            if net.addr() != net.network() {
                return Err(format!(
                    "{at}.prefixes {prefix} has host bits set; write it as {}",
                    net.trunc()
                ));
            }
            if !reaches(prefix) {
                return Err(format!(
                    "{at}.prefixes {prefix} is outside every protected prefix, so its settings would hold for nothing"
                ));
            }
            if let Some(other) = prefixes.insert(net, x.name.as_str()) {
                return Err(if other == x.name {
                    format!("{at}.prefixes names {prefix} twice")
                } else {
                    format!(
                        "{prefix} is in profiles {other:?} and {:?}; a prefix takes one profile's settings",
                        x.name
                    )
                });
            }
        }
        sections(&format!("{at}."), &Sections::of_profile(x), custom)?;
    }
    Ok(())
}

/// The named lists rules match against.
fn lists(p: &Policy) -> Result<()> {
    if p.lists.len() > LISTS_MAX {
        return Err(format!(
            "a policy holds at most {LISTS_MAX} lists, and this one has {}",
            p.lists.len()
        ));
    }
    let entries: usize = p.lists.values().map(Vec::len).sum();
    if entries > LIST_ENTRIES_MAX {
        return Err(format!(
            "the lists hold {entries} prefixes together; they may hold at most {LIST_ENTRIES_MAX}"
        ));
    }
    for (name, cidrs) in &p.lists {
        if !name_ok(name) {
            return Err(format!(
                "lists: {name:?} is not a name; use letters, digits, _ and -"
            ));
        }
        for cidr in cidrs {
            cidr.parse::<IpNet>()
                .map_err(|e| format!("lists.{name} {cidr:?}: {e}; write a prefix, such as 192.0.2.0/24 or 2001:db8::1/128"))?;
        }
    }
    Ok(())
}

/// A rule's match fields beyond the five-tuple.
fn matches(r: &Rule, proto: &str, p: &Policy) -> Result<()> {
    let m = &r.r#match;
    let id = &r.id;
    for (from, to, what) in [
        (m.dport, m.dport_to, "dport"),
        (m.sport, m.sport_to, "sport"),
    ] {
        if to != 0 && from == 0 {
            return Err(format!(
                "rule {id:?}: {what}_to ends a range; set {what} to its first port"
            ));
        }
        if to != 0 && to < from {
            return Err(format!(
                "rule {id:?}: {what}_to {to} is before {what} {from}"
            ));
        }
        if !(0..=65535).contains(&to) {
            return Err(format!("rule {id:?}: {what}_to must be within 0..65535"));
        }
    }
    for (min, max, what) in [
        (m.length_min, m.length_max, "length"),
        (m.ttl_min, m.ttl_max, "ttl"),
    ] {
        if max != 0 && min > max {
            return Err(format!(
                "rule {id:?}: {what}_min {min} is past {what}_max {max}, so it would never match"
            ));
        }
    }
    if (m.icmp_type.is_some() || m.icmp_code.is_some()) && proto != "icmp" {
        return Err(format!(
            "rule {id:?}: icmp_type and icmp_code match ICMP alone; set proto to icmp"
        ));
    }
    if m.icmp_code.is_some() && m.icmp_type.is_none() {
        return Err(format!(
            "rule {id:?}: an ICMP code means something only within its type; set icmp_type too"
        ));
    }
    if !["", "yes", "no"].contains(&m.fragment.as_str()) {
        return Err(format!(
            "rule {id:?}: fragment {:?}: use yes for fragments alone, or no for whole packets alone",
            m.fragment
        ));
    }
    let payload = !m.payload_hex.is_empty() || !m.payload_contains.is_empty();
    if !m.payload_hex.is_empty() {
        hex_ok(&format!("rule {id:?}: payload_hex"), &m.payload_hex)?;
    }
    if !m.payload_contains.is_empty() {
        hex_ok(
            &format!("rule {id:?}: payload_contains"),
            &m.payload_contains,
        )?;
    }
    if m.payload_offset != 0 && m.payload_hex.is_empty() {
        return Err(format!(
            "rule {id:?}: payload_offset says where payload_hex sits; set payload_hex too"
        ));
    }
    if payload && r.stage == "asic" {
        return Err(format!(
            "rule {id:?}: the asic stage matches headers alone; match payloads at the fpga or zc stage"
        ));
    }
    for (list, what) in [(&m.src_list, "src_list"), (&m.dst_list, "dst_list")] {
        if !list.is_empty() && !p.lists.contains_key(list) {
            return Err(format!(
                "rule {id:?}: {what} {list:?} is not one of the policy's lists"
            ));
        }
    }
    Ok(())
}

/// The settings that hold one another to account: a setting that, beside another, could never
/// take effect.
fn tuned(p: &Policy) -> Result<()> {
    let default = |path: &str| crate::tuning::default_of(path) as i64;
    if let Some(r) = &p.reputation {
        if r.penalty_seconds.len() > 8 {
            return Err(format!(
                "reputation.penalty_seconds holds {} sentences; give at most 8, the last repeating",
                r.penalty_seconds.len()
            ));
        }
        if let Some(s) = r
            .penalty_seconds
            .iter()
            .find(|s| !(1..=604_800).contains(*s))
        {
            return Err(format!(
                "reputation.penalty_seconds: {s} must be within 1..604800 seconds"
            ));
        }
    }
    if let Some(e) = &p.egress {
        let ticks = e.confirm_ticks.unwrap_or(default("egress.confirm_ticks"));
        let window = e
            .confirm_window_seconds
            .unwrap_or(default("egress.confirm_window_seconds"));
        if ticks > window.saturating_mul(4) {
            return Err(format!(
                "egress.confirm_ticks {ticks} quarter seconds do not fit in confirm_window_seconds {window}, so no client would ever be confirmed"
            ));
        }
    }
    if let Some(m) = &p.mitigation {
        let hold = m.hold_seconds.unwrap_or(default("mitigation.hold_seconds"));
        let max = m
            .hold_max_seconds
            .unwrap_or(default("mitigation.hold_max_seconds"));
        if hold > max {
            return Err(format!(
                "mitigation.hold_seconds {hold} is past hold_max_seconds {max}; the first wave holds no longer than the longest"
            ));
        }
    }
    Ok(())
}
/// How specifically a tenant's prefixes cover `net`: the length of the most specific one
/// containing it, if any does.
fn coverage(t: &Tenant, net: &IpNet) -> Option<u8> {
    t.prefixes
        .iter()
        .filter_map(|p| p.parse::<IpNet>().ok())
        .filter(|own| own.contains(net))
        .map(|own| own.prefix_len())
        .max()
}
/// Whether a tenant's address space covers a prefix.
pub fn owns(t: &Tenant, prefix: &str) -> bool {
    prefix
        .parse::<IpNet>()
        .is_ok_and(|net| coverage(t, &net).is_some())
}
/// Whether a prefix is `t`'s own rather than a customer of theirs': no other tenant covers it more
/// specifically. Tenants' address space may nest, a reseller's around its customers'.
pub fn belongs_to(prefix: &str, t: &Tenant, tenants: &[Tenant]) -> bool {
    let Ok(net) = prefix.parse::<IpNet>() else {
        return false;
    };
    let Some(mine) = coverage(t, &net) else {
        return false;
    };
    tenants
        .iter()
        .filter_map(|other| coverage(other, &net))
        .all(|theirs| theirs <= mine)
}
/// Tunnels allocated to a customer may only carry that customer's address space: a tunnel holding
/// someone else's prefix would hand their clean traffic to the wrong edge.
pub fn tunnel_tenants(p: &Policy, tenants: &[Tenant]) -> Result<()> {
    for t in p.tunnels.iter().filter(|t| !t.tenant.is_empty()) {
        let Some(owner) = tenants.iter().find(|v| v.id == t.tenant) else {
            return Err(format!("tunnel {}: unknown tenant {:?}", t.id, t.tenant));
        };
        if let Some(prefix) = t.prefixes.iter().find(|prefix| !owns(owner, prefix)) {
            return Err(format!(
                "tunnel {}: prefix {prefix} is not within tenant {}'s prefixes",
                t.id, t.tenant
            ));
        }
    }
    Ok(())
}
pub fn tenant(t: &Tenant) -> Result<()> {
    if t.name.is_empty() {
        return Err("name required".into());
    }
    if t.prefixes.is_empty() {
        return Err("at least one prefix required, or the tenant is entitled to nothing".into());
    }
    if t.prefixes.len() > PREFIXES_MAX {
        return Err(format!(
            "a tenant holds at most {PREFIXES_MAX} prefixes, as many as a policy protects"
        ));
    }
    for prefix in &t.prefixes {
        let p = prefix.parse::<IpNet>().map_err(|e| e.to_string())?;
        if p.addr() != p.network() {
            return Err(format!(
                "prefix {prefix} has host bits set; write it as {}",
                p.trunc()
            ));
        }
    }
    Ok(())
}
