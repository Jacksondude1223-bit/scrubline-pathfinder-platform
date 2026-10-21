//! Return path validation and deterministic iproute2/nftables rendering.
use crate::{model::*, Result};
use ipnet::IpNet;
use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
};
pub fn overhead(t: &Tunnel) -> i64 {
    if t.r#type == "ipip" {
        20
    } else {
        24 + if t.key == 0 { 0 } else { 4 }
    }
}
/// The most clean traffic one tunnel may carry to a customer, summed across the fabric: 2.5 Gbit/s.
pub const MAX_RATE_MBPS: i64 = 2500;
/// The clean-traffic allowance a tunnel actually gets: its own, or the maximum when it sets none.
pub fn rate_mbps(t: &Tunnel) -> i64 {
    if t.rate_mbps == 0 {
        MAX_RATE_MBPS
    } else {
        t.rate_mbps
    }
}
pub fn default_mtu(t: &Tunnel) -> i64 {
    1500 - overhead(t)
}
pub fn mss_for(mtu: i64) -> i64 {
    (mtu - 40).max(0)
}
fn carries_v6(prefixes: &[String]) -> bool {
    prefixes
        .iter()
        .any(|p| matches!(p.parse::<IpNet>(), Ok(IpNet::V6(_))))
}
// The clamp rule sits in an inet table and rewrites IPv6 SYNs too, whose headers are 60 bytes,
// so a tunnel carrying any IPv6 prefix clamps to fit those.
fn clamp_for(t: &Tunnel, mtu: i64) -> i64 {
    if carries_v6(&t.prefixes) {
        (mtu - 60).max(0)
    } else {
        mss_for(mtu)
    }
}
pub fn validate_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 11
        || !id.as_bytes()[0].is_ascii_lowercase() && !id.as_bytes()[0].is_ascii_digit()
        || !id
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
    {
        Err("tunnel id must be 1..11 lowercase letters, digits and dashes, starting with a letter or digit".into())
    } else {
        Ok(())
    }
}
pub fn interface_name(id: &str) -> Result<String> {
    validate_id(id)?;
    Ok(format!("scr-{id}"))
}
pub fn validate(t: &Tunnel, protected: Option<&HashSet<String>>) -> Result<()> {
    validate_id(&t.id)?;
    match t.r#type.as_str() {
        "" | "gre" => {}
        "ipip" if t.key == 0 => {}
        "ipip" => return Err("ipip carries no key".into()),
        _ => return Err("unknown tunnel type".into()),
    }
    if !["", "both", "return"].contains(&t.direction.as_str()) {
        return Err("direction must be both or return".into());
    }
    if !(0..=MAX_RATE_MBPS).contains(&t.rate_mbps) {
        return Err(format!(
            "rate_mbps must be within 1..{MAX_RATE_MBPS} (2.5 Gbit/s); 0 takes the maximum"
        ));
    }
    let mut disabled = HashSet::new();
    if t.disabled
        .iter()
        .any(|id| id.trim().is_empty() || !disabled.insert(id))
    {
        return Err("disabled must list distinct node ids".into());
    }
    let remote = t.remote.parse::<Ipv4Addr>().map_err(|e| e.to_string())?;
    if remote.is_unspecified() || remote.is_multicast() || remote.is_loopback() {
        return Err("remote is not a usable endpoint".into());
    }
    if t.prefixes.is_empty() {
        return Err("tunnel needs at least one prefix".into());
    }
    let mut seen = HashSet::new();
    for prefix in &t.prefixes {
        prefix.parse::<IpNet>().map_err(|e| e.to_string())?;
        if !seen.insert(prefix) {
            return Err(format!("duplicate prefix {prefix}"));
        }
        if protected.is_some_and(|ps| !ps.contains(prefix)) {
            return Err(format!("prefix {prefix} is not protected"));
        }
    }
    if t.r#type == "ipip" && carries_v6(&t.prefixes) {
        return Err("ipip carries IPv4 only; use gre for a tunnel with IPv6 prefixes".into());
    }
    if t.mtu != 0 && !(576..=default_mtu(t)).contains(&t.mtu) {
        return Err("MTU does not fit the IPv4 path".into());
    }
    let mtu = if t.mtu == 0 { default_mtu(t) } else { t.mtu };
    if t.mss_clamp != 0 && !(536..=clamp_for(t, mtu)).contains(&t.mss_clamp) {
        return Err("MSS clamp does not fit the MTU".into());
    }
    Ok(())
}
pub fn for_node(t: &Tunnel, n: &Node, prefixes: &[String]) -> Result<NodeTunnel> {
    let local = n
        .tunnel_src
        .parse::<Ipv4Addr>()
        .map_err(|_| format!("node {} has no usable IPv4 tunnel_src", n.id))?;
    let mtu = if t.mtu == 0 { default_mtu(t) } else { t.mtu };
    let mut prefixes = prefixes.to_vec();
    prefixes.sort();
    Ok(NodeTunnel {
        id: t.id.clone(),
        r#type: if t.r#type.is_empty() {
            "gre".into()
        } else {
            t.r#type.clone()
        },
        local: local.to_string(),
        remote: t.remote.clone(),
        prefixes,
        mtu,
        mss_clamp: if t.mss_clamp == 0 {
            clamp_for(t, mtu)
        } else {
            t.mss_clamp
        },
        key: t.key,
        required: t.required,
        interface: interface_name(&t.id)?,
        comment: t.comment.clone(),
        direction: t.direction.clone(),
        // The whole allowance; compiling the fabric splits it among the nodes sending.
        rate_kbps: rate_mbps(t).saturating_mul(1000),
    })
}
/// Whether the customer's replies come back up this tunnel to the node.
pub fn carries_replies(t: &NodeTunnel) -> bool {
    t.direction != "return"
}
/// The rules for traffic coming back up a tunnel: the customer's replies, which the node forwards
/// to the internet. Only the tunnel's own prefixes may be sources, or the tunnel would be an open
/// relay for anything the customer's edge sends into it, and SYNs leaving through it are clamped
/// so the far side's segments fit the tunnel too.
pub fn reply_commands(tunnels: &[NodeTunnel]) -> Result<Vec<String>> {
    let mut rows: Vec<_> = tunnels.iter().filter(|t| carries_replies(t)).collect();
    rows.sort_by_key(|t| &t.id);
    let mut lines = Vec::new();
    for t in rows {
        let name = interface_name(&t.id)?;
        let (mut v4, mut v6) = (Vec::new(), Vec::new());
        for prefix in &t.prefixes {
            match prefix.parse::<IpNet>().map_err(|e| e.to_string())?.trunc() {
                IpNet::V4(p) => v4.push(p.to_string()),
                IpNet::V6(p) => v6.push(p.to_string()),
            }
        }
        v4.sort();
        v6.sort();
        for (family, match_on, sources) in [("ipv4", "ip", v4), ("ipv6", "ip6", v6)] {
            lines.push(if sources.is_empty() {
                format!("nft add rule inet scrubline forward iifname \"{name}\" meta nfproto {family} drop")
            } else {
                format!(
                    "nft add rule inet scrubline forward iifname \"{name}\" {match_on} saddr != {{ {} }} drop",
                    sources.join(", ")
                )
            });
        }
        if t.mss_clamp > 0 {
            lines.push(format!("nft add rule inet scrubline forward iifname \"{name}\" tcp flags syn tcp option maxseg size set {}", t.mss_clamp));
        }
    }
    Ok(lines)
}
/// Holds the clean traffic going down each tunnel to this node's share of its allowance. A
/// shaper rather than a policer, so TCP sees queueing it can back off from instead of drops; the
/// burst covers 10ms at the rate, and never less than 32KiB so a slow share still passes a full
/// frame and stays within what tbf can represent.
pub fn rate_commands(tunnels: &[NodeTunnel]) -> Result<Vec<String>> {
    let mut rows: Vec<_> = tunnels.iter().filter(|t| t.rate_kbps > 0).collect();
    rows.sort_by_key(|t| &t.id);
    let mut lines = Vec::new();
    for t in rows {
        let name = interface_name(&t.id)?;
        let burst = (t.rate_kbps.saturating_mul(5) / 4).max(32768);
        lines.push(format!(
            "tc qdisc replace dev {name} root tbf rate {}kbit burst {burst} latency 50ms",
            t.rate_kbps
        ));
    }
    Ok(lines)
}
pub fn commands(tunnels: &[NodeTunnel]) -> Result<Vec<String>> {
    let mut rows: Vec<_> = tunnels.iter().collect();
    rows.sort_by_key(|t| &t.id);
    let mut lines = Vec::new();
    for t in rows {
        let name = interface_name(&t.id)?;
        if !t.interface.is_empty() && t.interface != name {
            return Err("interface does not match the tunnel id".into());
        }
        let local = t.local.parse::<Ipv4Addr>().map_err(|e| e.to_string())?;
        let remote = t.remote.parse::<Ipv4Addr>().map_err(|e| e.to_string())?;
        if local == remote {
            return Err("local and remote endpoints are the same".into());
        }
        if t.r#type != "gre" && t.r#type != "ipip" {
            return Err("unknown tunnel type".into());
        }
        if t.r#type == "ipip" && t.key != 0 {
            return Err("ipip carries no key".into());
        }
        if t.mtu < 576 {
            return Err("MTU below the IPv4 minimum".into());
        }
        let comment: String = t
            .comment
            .chars()
            .filter(|c| c.is_ascii() && (' '..='~').contains(c))
            .take(120)
            .collect();
        if !comment.trim().is_empty() {
            lines.push(format!("# {}", comment.trim()));
        }
        let key = if t.key == 0 {
            String::new()
        } else {
            format!(" key {}", t.key)
        };
        lines.push(format!(
            "ip link add {name} type {} local {local} remote {remote}{key}",
            t.r#type
        ));
        lines.push(format!("ip link set {name} mtu {} up", t.mtu));
        let mut prefixes = t.prefixes.clone();
        prefixes.sort();
        for prefix in prefixes {
            let p = prefix.parse::<IpNet>().map_err(|e| e.to_string())?;
            lines.push(format!("ip route replace {} dev {name}", p.trunc()));
        }
        if t.mss_clamp > 0 {
            lines.push(format!("nft add rule inet scrubline forward oifname \"{name}\" tcp flags syn tcp option maxseg size set {}",t.mss_clamp));
        }
    }
    Ok(lines)
}
pub fn state_of(reports: &[TunnelStatus]) -> HashMap<String, String> {
    reports
        .iter()
        .map(|r| {
            (
                r.tunnel_id.clone(),
                if r.state == "up" || r.state == "down" {
                    r.state.clone()
                } else {
                    "unknown".into()
                },
            )
        })
        .collect()
}
pub fn deliverable(t: &NodeTunnel, state: &str) -> (bool, String) {
    match state {
        "down" => (false, format!("return tunnel {} is down", t.id)),
        "up" => (true, String::new()),
        _ if t.required => (
            false,
            format!("return tunnel {} is required and has not reported up", t.id),
        ),
        _ => (true, String::new()),
    }
}
pub fn validate_status(state: &str) -> Result<()> {
    if ["up", "down", "unknown"].contains(&state) {
        Ok(())
    } else {
        Err(format!("unknown tunnel state {state:?}"))
    }
}
pub fn parse_key(s: &str) -> Result<u32> {
    if s.is_empty() {
        Ok(0)
    } else {
        s.strip_prefix('+')
            .unwrap_or(s)
            .parse::<u32>()
            .map_err(|e| e.to_string())
    }
}
