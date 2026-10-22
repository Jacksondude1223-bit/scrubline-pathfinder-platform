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
/// The MTU of a node-to-node tunnel: GRE without a key over a 1500-byte path.
pub const BACKHAUL_MTU: i64 = 1476;
/// The interface a node-to-node tunnel to `peer` compiles to: a digest of the node id, since ids
/// are longer than the kernel's 15 characters and any truncation of them could collide.
pub fn backhaul_name(peer: &str) -> String {
    use sha2::{Digest, Sha256};
    format!(
        "sbh-{}",
        &hex::encode(Sha256::digest(peer.as_bytes()))[..11]
    )
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
        sources: {
            let mut all = t.prefixes.clone();
            all.sort();
            all
        },
        // Only the whole policy says which other tunnels' prefixes sit inside this one's.
        foreign: Vec::new(),
        // The whole allowance; compiling the fabric splits it among the nodes sending.
        rate_kbps: rate_mbps(t).saturating_mul(1000),
    })
}
/// Whether the customer's replies come back up this tunnel to the node.
pub fn carries_replies(t: &NodeTunnel) -> bool {
    t.direction != "return"
}
/// The networks of one address family in `nets`, with any inside another of them left out: an
/// nftables interval set refuses overlapping elements on older releases.
fn outermost(nets: &[IpNet], v4: bool) -> Vec<IpNet> {
    let mut out: Vec<IpNet> = nets
        .iter()
        .filter(|n| matches!(n, IpNet::V4(_)) == v4)
        .filter(|n| {
            !nets
                .iter()
                .any(|o| o.prefix_len() < n.prefix_len() && o.contains(*n))
        })
        .copied()
        .collect();
    out.sort();
    out.dedup();
    out
}
/// `net` less every network in `holes`, as whole networks.
fn subtract(net: IpNet, holes: &[IpNet]) -> Vec<IpNet> {
    if holes.iter().any(|h| h.contains(&net)) {
        return vec![];
    }
    if !holes.iter().any(|h| net.contains(h)) {
        return vec![net];
    }
    net.subnets(net.prefix_len() + 1)
        .map(|halves| halves.flat_map(|half| subtract(half, holes)).collect())
        .unwrap_or_default()
}
/// Where replies up a tunnel may come from: every address whose most specific covering prefix,
/// among all the tunnels' prefixes, is one of this tunnel's. Routing goes by the most specific
/// prefix, so that is whose customer an address is.
fn owned(mine: &[IpNet], theirs: &[IpNet]) -> Vec<IpNet> {
    let all: Vec<IpNet> = mine.iter().chain(theirs).copied().collect();
    let mut out = Vec::new();
    for p in mine {
        let inside: Vec<IpNet> = all
            .iter()
            .filter(|q| q.prefix_len() > p.prefix_len() && p.contains(*q))
            .copied()
            .collect();
        out.extend(subtract(*p, &inside));
    }
    IpNet::aggregate(&out)
}
fn nets(prefixes: &[String]) -> Result<Vec<IpNet>> {
    prefixes
        .iter()
        .map(|p| Ok(p.parse::<IpNet>().map_err(|e| e.to_string())?.trunc()))
        .collect()
}
fn listed(nets: &[IpNet]) -> String {
    nets.iter()
        .map(IpNet::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}
/// The rules for traffic coming back up a tunnel: the customer's replies, which the node forwards
/// to the internet. Only the tunnel's own prefixes may be sources, or the tunnel would be an open
/// relay for anything the customer's edge sends into it, and SYNs leaving through it are clamped
/// so the far side's segments fit the tunnel too. A more specific prefix of another tunnel inside
/// one of this tunnel's is that customer's, so it is refused as a source here, whether or not
/// that tunnel is built on this node. A tunnel that carries no replies forwards nothing that
/// comes up it.
pub fn reply_commands(tunnels: &[NodeTunnel]) -> Result<Vec<String>> {
    let mut rows: Vec<_> = tunnels.iter().collect();
    rows.sort_by_key(|t| &t.id);
    let mut lines = Vec::new();
    for t in &rows {
        let name = interface_name(&t.id)?;
        let rule =
            |tail: String| format!("nft add rule inet scrubline forward iifname \"{name}\" {tail}");
        if !carries_replies(t) {
            lines.push(rule("drop".into()));
            continue;
        }
        // Replies may come from any of the tunnel's prefixes, not only the ones this node
        // announces: a customer routes them up whichever tunnel it likes. A program from a control
        // plane that sends neither list falls back to what this node knows.
        let mine = nets(if t.sources.is_empty() {
            &t.prefixes
        } else {
            &t.sources
        })?;
        let mut theirs = nets(&t.foreign)?;
        for other in rows.iter().filter(|o| o.id != t.id) {
            theirs.extend(nets(if other.sources.is_empty() {
                &other.prefixes
            } else {
                &other.sources
            })?);
        }
        let owned = owned(&mine, &theirs);
        for (family, match_on, v4) in [("ipv4", "ip", true), ("ipv6", "ip6", false)] {
            let envelope = outermost(&mine, v4);
            let foreign =
                IpNet::aggregate(&envelope.iter().flat_map(|p| subtract(*p, &owned)).collect());
            if !foreign.is_empty() {
                lines.push(rule(format!(
                    "{match_on} saddr {{ {} }} drop",
                    listed(&foreign)
                )));
            }
            lines.push(rule(if envelope.is_empty() {
                format!("meta nfproto {family} drop")
            } else {
                format!("{match_on} saddr != {{ {} }} drop", listed(&envelope))
            }));
        }
        if t.mss_clamp > 0 {
            lines.push(rule(format!(
                "tcp flags syn tcp option maxseg size set {}",
                t.mss_clamp
            )));
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
/// The node-to-node tunnels, the routes into them, and what may arrive over them: clean traffic
/// for the customers pinned to this node, and nothing else, so another node, or anyone who can
/// forge one, cannot relay through this one.
pub fn backhaul_commands(backhaul: &[Backhaul], pinned: &[String]) -> Result<Vec<String>> {
    let mut rows: Vec<_> = backhaul.iter().collect();
    rows.sort_by_key(|b| &b.interface);
    let mut lines = Vec::new();
    for b in &rows {
        let name = &b.interface;
        if name.len() != 15
            || !name.starts_with("sbh-")
            || !name[4..].bytes().all(|c| c.is_ascii_hexdigit())
        {
            return Err(format!("invalid backhaul interface {name:?}"));
        }
        let local = b.local.parse::<Ipv4Addr>().map_err(|e| e.to_string())?;
        let remote = b.remote.parse::<Ipv4Addr>().map_err(|e| e.to_string())?;
        if local == remote {
            return Err("local and remote endpoints are the same".into());
        }
        if b.mtu < 576 {
            return Err("MTU below the IPv4 minimum".into());
        }
        lines.push(format!(
            "ip link add {name} type gre local {local} remote {remote}"
        ));
        lines.push(format!("ip link set {name} mtu {} up", b.mtu));
        for net in nets(&b.prefixes)? {
            lines.push(format!("ip route replace {net} dev {name}"));
        }
        if b.mss_clamp > 0 {
            lines.push(format!("nft add rule inet scrubline forward oifname \"{name}\" tcp flags syn tcp option maxseg size set {}", b.mss_clamp));
        }
    }
    if !rows.is_empty() {
        let pinned = nets(pinned)?;
        for (family, match_on, v4) in [("ipv4", "ip", true), ("ipv6", "ip6", false)] {
            let allowed = outermost(&pinned, v4);
            lines.push(if allowed.is_empty() {
                format!("nft add rule inet scrubline forward iifname \"sbh-*\" meta nfproto {family} drop")
            } else {
                format!(
                    "nft add rule inet scrubline forward iifname \"sbh-*\" {match_on} daddr != {{ {} }} drop",
                    listed(&allowed)
                )
            });
        }
    }
    Ok(lines)
}
/// The firewall for tunnels: GRE and IPIP are accepted only from the addresses this node has
/// tunnels with. Tunnel endpoints are IPv4, so neither is accepted over IPv6 at all.
pub fn firewall_commands(peers: &[String]) -> Result<Vec<String>> {
    let mut allowed = Vec::new();
    for p in peers {
        allowed.push(p.parse::<Ipv4Addr>().map_err(|e| e.to_string())?);
    }
    allowed.sort();
    allowed.dedup();
    let mut lines = vec![if allowed.is_empty() {
        "nft add rule inet scrubline input meta l4proto { gre, ipencap } drop".to_string()
    } else {
        format!(
            "nft add rule inet scrubline input meta l4proto {{ gre, ipencap }} ip saddr != {{ {} }} drop",
            allowed
                .iter()
                .map(Ipv4Addr::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )
    }];
    lines.push(
        "nft add rule inet scrubline input meta nfproto ipv6 meta l4proto { gre, ipencap } drop"
            .into(),
    );
    Ok(lines)
}
/// Everything a node's program asks of the box for its tunnels, in the order it applies: the
/// customer tunnels and the node-to-node ones with their routes, then the forwarding and firewall
/// rules, then the shapers. The rules assume the `inet scrubline` table with its `forward` and
/// `input` chains, which the provisioner creates.
pub fn render(prog: &Program) -> Result<Vec<String>> {
    let mut lines = commands(&prog.tunnels)?;
    lines.extend(backhaul_commands(&prog.backhaul, &prog.pinned)?);
    lines.extend(reply_commands(&prog.tunnels)?);
    lines.extend(firewall_commands(&prog.tunnel_peers)?);
    lines.extend(rate_commands(&prog.tunnels)?);
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
