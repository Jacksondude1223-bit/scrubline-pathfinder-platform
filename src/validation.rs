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
        let a = n
            .tunnel_src
            .parse::<Ipv4Addr>()
            .map_err(|_| "tunnel_src must be IPv4")?;
        if a.is_unspecified() || a.is_multicast() || a.is_loopback() {
            return Err("tunnel_src is not a usable tunnel endpoint".into());
        }
    }
    for b in &n.backends {
        if !["asic", "fpga", "zc"].contains(&b.as_str()) {
            return Err(format!("unknown backend {b:?}"));
        }
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
pub fn policy(p: &Policy) -> Result<()> {
    if p.name.is_empty() || p.protected.is_empty() {
        return Err("name and protected prefixes required".into());
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
    unique(p.games.iter().map(|g| g.id.as_str()), "games")?;
    for g in &p.games {
        if !(0..=65535).contains(&g.dport) {
            return Err("game dport must be within 0..65535".into());
        }
        if !["", "any", "udp", "tcp"].contains(&g.proto.to_ascii_lowercase().as_str()) {
            return Err("unknown game proto".into());
        }
        if g.dst_cidr.is_empty() && g.dport == 0 {
            return Err("game filter needs a dst_cidr or dport".into());
        }
    }
    gamefilter::compile(&p.games)?;
    unique(p.tunnels.iter().map(|t| t.id.as_str()), "tunnels")?;
    let mut carried = HashSet::new();
    for t in &p.tunnels {
        tunnel::validate(t, Some(&protected))?;
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
        if !["", "any", "tcp", "udp", "icmp"]
            .contains(&r.r#match.proto.to_ascii_lowercase().as_str())
        {
            return Err(format!(
                "rule {:?}: unknown proto {:?}; use tcp, udp, icmp or any",
                r.id, r.r#match.proto
            ));
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
        for cidr in [&r.r#match.src_cidr, &r.r#match.dst_cidr] {
            if !cidr.is_empty() {
                cidr.parse::<IpNet>().map_err(|e| e.to_string())?;
            }
        }
        if !(0..=65535).contains(&r.r#match.dport) || !(0..=65535).contains(&r.r#match.sport) {
            return Err("match ports must be within 0..65535".into());
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
