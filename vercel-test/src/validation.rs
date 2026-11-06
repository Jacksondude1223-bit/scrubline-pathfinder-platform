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
    for t in &p.tunnels {
        tunnel::validate(t, Some(&protected))?;
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
    if let Some(c) = &p.crafted {
        if !["", "enforce", "observe", "off"].contains(&c.mode.as_str()) {
            return Err(format!(
                "crafted.mode {:?}: use enforce, observe, or off to stop checking packets",
                c.mode
            ));
        }
    }
    if let Some(r) = &p.reflection {
        if !["", "enforce", "observe", "off"].contains(&r.cldap.as_str()) {
            return Err(format!(
                "reflection.cldap {:?}: use enforce, observe, or off to stop looking for reflected CLDAP",
                r.cldap
            ));
        }
    }
    if let Some(g) = &p.protocols {
        if !["", "enforce", "observe", "off"].contains(&g.mode.as_str()) {
            return Err(format!(
                "protocols.mode {:?}: use enforce, observe, or off to stop looking at protocols",
                g.mode
            ));
        }
        for name in &g.allow {
            if crate::guards::protocol(name).is_none() {
                return Err(format!(
                    "protocols.allow {name:?}: name a protocol ({}) or give its number; tcp, udp and icmp always pass",
                    crate::guards::PROTOCOLS.join(", ")
                ));
            }
        }
    }
    if let Some(a) = &p.ack_flood {
        if !["", "enforce", "observe", "off"].contains(&a.mode.as_str()) {
            return Err(format!(
                "ack_flood.mode {:?}: use enforce, observe, or off to stop looking for ACK floods",
                a.mode
            ));
        }
        if !(0..=1_000_000_000).contains(&a.engage_pps) {
            return Err("ack_flood.engage_pps must be within 0..1000000000; 0 takes 5000".into());
        }
    }
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
        if !["drop", "permit", "rate_limit", "inspect", "count"].contains(&r.action.as_str()) {
            return Err(format!("unknown action {:?}", r.action));
        }
        if r.stage == "asic" && r.action == "rate_limit" {
            return Err(
                "the asic stage cannot meter; use the fpga or zc stage for rate_limit".into(),
            );
        }
        if r.pps < 0 || r.action == "rate_limit" && r.pps == 0 {
            return Err("rate_limit requires positive pps; pps must not be negative".into());
        }
        let meters = r.stage == "fpga" && r.action == "rate_limit"
            || r.stage == "zc" && (r.action == "rate_limit" || r.action == "inspect");
        if r.pps > 0 && !meters {
            return Err("pps belongs on an fpga rate_limit or zc rate_limit/inspect rule".into());
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
            && (r.r#match.dport != 0 || r.r#match.sport != 0)
        {
            return Err(format!("rule {:?}: {proto} has no ports to match", r.id));
        }
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
