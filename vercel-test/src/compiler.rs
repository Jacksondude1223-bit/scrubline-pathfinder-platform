//! Anycast planning and backend-specific policy compilation.
use crate::{bgp, model::*, tunnel};
use chrono::Utc;
use ipnet::IpNet;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
};
pub const MAX_PREPENDS: i64 = 5;
pub type TunnelHealth = HashMap<String, HashMap<String, String>>;
fn capacity(n: &Node) -> f64 {
    if n.capacity_gbps.is_finite() && n.capacity_gbps >= 0.0 {
        n.capacity_gbps
    } else {
        0.0
    }
}
fn eligible(p: &Policy, n: &Node, prefix: &str) -> bool {
    p.steering
        .iter()
        .rev()
        .find(|s| s.prefix == prefix)
        .is_none_or(|s| {
            s.regions.is_empty() || s.regions.iter().any(|r| r.eq_ignore_ascii_case(&n.region))
        })
}
fn next_hop(n: &Node) -> String {
    if let Ok(addr) = n.advertise.parse::<SocketAddr>() {
        return addr.ip().to_string();
    }
    let host = if n.advertise.matches(':').count() == 1 {
        n.advertise.split(':').next().unwrap_or("")
    } else {
        n.advertise.as_str()
    };
    // Only an address can be a next hop. A hostname, which an agent on a wildcard listener
    // advertises by default, would make the speaker refuse the node's whole plan, so it is left
    // out the way an empty advertise is.
    if host.parse::<IpAddr>().is_ok() {
        host.into()
    } else {
        String::new()
    }
}
pub fn plan(
    p: &Policy,
    nodes: &[Node],
    shedding: &HashMap<String, i64>,
    health: &TunnelHealth,
) -> Vec<Announcement> {
    let mut out = Vec::new();
    for prefix in &p.protected {
        // Padding is relative to the largest node actually announcing this prefix. A node outside
        // its regions, or one that cannot deliver it, is not competing for its traffic, and
        // counting it would pad every real announcer and spend the shedding budget for nothing.
        let max = nodes
            .iter()
            .filter(|n| {
                n.status != "stale" && eligible(p, n, prefix) && deliverable(p, n, prefix, health).0
            })
            .map(capacity)
            .fold(0.0, f64::max);
        for n in nodes {
            if !eligible(p, n, prefix) {
                continue;
            }
            let mut a = Announcement {
                prefix: prefix.clone(),
                node_id: n.id.clone(),
                node_name: n.name.clone(),
                region: n.region.clone(),
                communities: p
                    .steering
                    .iter()
                    .rev()
                    .find(|s| &s.prefix == prefix)
                    .map(|s| s.communities.clone())
                    .unwrap_or_default(),
                next_hop: next_hop(n),
                ..Default::default()
            };
            let (can_deliver, why) = deliverable(p, n, prefix, health);
            if n.status == "stale" {
                a.state = "withdraw".into();
                a.reason = "node has not heartbeated within its TTL".into();
            } else if !can_deliver {
                a.state = "withdraw".into();
                a.reason = why;
            } else {
                let c = capacity(n);
                let base = if c <= 0.0 {
                    MAX_PREPENDS
                } else if max <= 0.0 || c >= max {
                    0
                } else {
                    ((max / c).log2().round() as i64).clamp(0, MAX_PREPENDS)
                };
                let extra = (*shedding.get(&n.id).unwrap_or(&0)).max(0);
                a.state = "announce".into();
                a.prepends = base.saturating_add(extra).clamp(0, MAX_PREPENDS);
                a.reason = match (a.prepends, base, extra) {
                    (0, _, _) => "anycast member at full preference".into(),
                    (t, _, 0) => format!("anycast member padded {t} to weight for capacity"),
                    (t, 0, _) => format!("anycast member padded {t}, shedding measured load"),
                    (t, b, e) => format!(
                        "anycast member padded {t}: {b} for capacity, {e} shedding measured load"
                    ),
                };
            }
            out.push(a);
        }
    }
    out.sort_by(|a, b| (&a.prefix, &a.node_id).cmp(&(&b.prefix, &b.node_id)));
    out
}
fn deliverable(p: &Policy, n: &Node, prefix: &str, health: &TunnelHealth) -> (bool, String) {
    let Some(t) = p
        .tunnels
        .iter()
        .find(|t| t.prefixes.iter().any(|v| v == prefix))
    else {
        return (true, String::new());
    };
    if t.disabled.iter().any(|id| id == &n.id) {
        return (
            false,
            format!("return tunnel {} is disabled on this node", t.id),
        );
    }
    if n.tunnel_src.is_empty() {
        return (
            false,
            "node has no tunnel_src, so it cannot build the return path for this prefix".into(),
        );
    }
    if n.tunnel_src == t.remote {
        return (
            false,
            format!(
                "return tunnel {} would end where it starts: the node's tunnel_src is its remote",
                t.id
            ),
        );
    }
    let nt = NodeTunnel {
        id: t.id.clone(),
        required: t.required,
        ..Default::default()
    };
    tunnel::deliverable(
        &nt,
        health
            .get(&n.id)
            .and_then(|h| h.get(&t.id))
            .map(String::as_str)
            .unwrap_or("unknown"),
    )
}
pub fn enforced_prefixes(p: &Policy, n: &Node) -> Vec<String> {
    p.protected
        .iter()
        .filter(|prefix| eligible(p, n, prefix))
        .cloned()
        .collect()
}
pub fn tunnels_for(p: &Policy, n: &Node, enforced: &[String]) -> Vec<NodeTunnel> {
    let mut out: Vec<_> = p
        .tunnels
        .iter()
        .filter_map(|t| {
            let mine: Vec<_> = t
                .prefixes
                .iter()
                .filter(|prefix| enforced.contains(prefix))
                .cloned()
                .collect();
            if mine.is_empty()
                || t.disabled.iter().any(|id| id == &n.id)
                || n.tunnel_src == t.remote
            {
                None
            } else {
                tunnel::for_node(t, n, &mine).ok()
            }
        })
        .collect();
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}
pub fn sessions_for(p: &Policy, n: &Node) -> Vec<Session> {
    let mut out: Vec<_> = p
        .sessions
        .iter()
        .filter(|s| bgp::terminates_on(s, n))
        .cloned()
        .collect();
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}
fn games_for(p: &Policy, prefixes: &[String], has_zc: bool) -> Vec<GameFilter> {
    if !has_zc {
        return vec![];
    }
    let enforced: Vec<IpNet> = prefixes.iter().filter_map(|p| p.parse().ok()).collect();
    p.games
        .iter()
        .filter(|g| {
            g.dst_cidr.is_empty()
                || g.dst_cidr.parse::<IpNet>().is_ok_and(|target| {
                    enforced
                        .iter()
                        .any(|p| p.contains(&target.addr()) || target.contains(&p.addr()))
                })
        })
        .cloned()
        .collect()
}
/// Splits each tunnel's clean-traffic allowance evenly across the nodes sending it, so the
/// customer never receives more than the allowance in total. A node sends a tunnel when it builds
/// it and announces one of its prefixes; one still building it while withdrawing gets the same
/// share for the traffic BGP has yet to move away.
fn share_rates(programs: &mut HashMap<String, Program>) {
    let mut senders: HashMap<String, i64> = HashMap::new();
    for prog in programs.values() {
        for t in &prog.tunnels {
            let announced = prog
                .announcements
                .iter()
                .any(|a| a.state == "announce" && t.prefixes.contains(&a.prefix));
            if announced {
                *senders.entry(t.id.clone()).or_default() += 1;
            }
        }
    }
    for prog in programs.values_mut() {
        for t in &mut prog.tunnels {
            let n = senders.get(&t.id).copied().unwrap_or(1).max(1);
            t.rate_kbps = (t.rate_kbps / n).max(1);
        }
    }
}
pub fn compile(p: &Policy, nodes: &[Node], plan: &[Announcement]) -> HashMap<String, Program> {
    let now = Utc::now();
    let mut programs: HashMap<String, Program> = nodes
        .iter()
        .map(|n| {
            let prefixes = enforced_prefixes(p, n);
            let has = |stage: &str| n.backends.is_empty() || n.backends.iter().any(|s| s == stage);
            let mut prog = Program {
                node_id: n.id.clone(),
                policy_id: p.id.clone(),
                version: p.version,
                prefixes: prefixes.clone(),
                announcements: plan.iter().filter(|a| a.node_id == n.id).cloned().collect(),
                games: games_for(p, &prefixes, has("zc")),
                challenge_secret: p.challenge_secret.clone(),
                pulse_floor_pps: p.pulse_floor_pps,
                reputation: p.reputation.clone(),
                egress: p.egress.clone(),
                tunnels: tunnels_for(p, n, &prefixes),
                sessions: sessions_for(p, n),
                tunnel_src: n.tunnel_src.clone(),
                compiled_at: now,
                ..Default::default()
            };
            for r in &p.rules {
                if !has(&r.stage) {
                    continue;
                }
                match r.stage.as_str() {
                    "asic" => prog.asic.push(ACLEntry {
                        priority: r.priority,
                        action: r.action.clone(),
                        r#match: r.r#match.clone(),
                        rule_id: r.id.clone(),
                        tcam_key: format!(
                            "v4 src={} dst={} proto={} dport={} sport={} pri={}",
                            or_any(&r.r#match.src_cidr),
                            or_any(&r.r#match.dst_cidr),
                            or_any(&r.r#match.proto),
                            r.r#match.dport,
                            r.r#match.sport,
                            r.priority
                        ),
                    }),
                    "fpga" => prog.fpga.push(FPGAEntry {
                        table: "scrub_meter".into(),
                        priority: r.priority,
                        r#match: r.r#match.clone(),
                        meter_pps: r.pps,
                        action: r.action.clone(),
                        rule_id: r.id.clone(),
                    }),
                    "zc" => prog.zc.push(ZCEntry {
                        cluster: format!("zc:{}", n.name),
                        priority: r.priority,
                        r#match: r.r#match.clone(),
                        action: r.action.clone(),
                        pps: r.pps,
                        rule_id: r.id.clone(),
                    }),
                    _ => {}
                }
            }
            prog.asic.sort_by_key(|r| r.priority);
            prog.fpga.sort_by_key(|r| r.priority);
            prog.zc.sort_by_key(|r| r.priority);
            (n.id.clone(), prog)
        })
        .collect();
    share_rates(&mut programs);
    programs
}
fn or_any(s: &str) -> &str {
    if s.is_empty() {
        "*"
    } else {
        s
    }
}
