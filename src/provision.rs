//! The node provisioner: puts what a node's agent says its tunnels should be onto the box (the
//! interfaces, routes, firewall and shapers) and reports back which customer tunnels it built.
//!
//! The agent compiles and serves; this is the part that changes the box, so it runs privileged
//! and apart from the agent. Each pass reconciles the box with the agent's rendered configuration
//! rather than replaying it, so it can run every few seconds without piling up duplicates, and
//! it removes what the agent no longer asks for.
use crate::{
    model::{ACLEntry, HostBlackhole, Match, NodeTunnel},
    tunnel::{QUEUE_MAX, QUEUE_MIN},
    Result,
};
use ipnet::IpNet;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

/// What the agent serves at `GET /tunnels`.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Desired {
    pub tunnels: Vec<NodeTunnel>,
    pub asic: Vec<ACLEntry>,
    pub blackwell: Vec<HostBlackhole>,
    #[serde(rename = "iproute2")]
    pub lines: Vec<String>,
    pub error: String,
}

/// The parts of the box a pass manages.
#[derive(Debug, Default, Clone)]
pub struct Observed {
    /// Our interfaces, by name, with the line each was built from, which is kept as its alias.
    pub links: BTreeMap<String, String>,
    /// Routes through our interfaces, as (destination, interface).
    pub routes: BTreeSet<(String, String)>,
    /// Our shapers, by interface: a token bucket at the root handle the renderers give it (`1:`).
    pub shapers: BTreeMap<String, Shaper>,
    /// Whether the `inet scrubline` table exists.
    pub table: bool,
}

/// A shaper as the box holds it.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct Shaper {
    /// The token bucket's rate, in bytes per second.
    pub rate: u64,
    /// What the flow queue under it may hold, in bytes, when that queue is ours.
    pub queue: Option<u64>,
}

/// One command of a pass, and the interface it concerns, if any.
#[derive(Debug, Clone, PartialEq)]
pub struct Step {
    pub argv: Vec<String>,
    pub link: Option<String>,
}

/// The commands that bring the box to what the agent asks for, and the ruleset that goes with it.
#[derive(Debug, Default)]
pub struct Pass {
    pub steps: Vec<Step>,
    pub nft: String,
    ingress: BTreeMap<String, (String, String)>,
    drops: BTreeMap<String, (String, String)>,
    wireguard: BTreeMap<String, NodeTunnel>,
}

/// Interfaces the provisioner owns: customer tunnels and node-to-node tunnels.
pub fn ours(name: &str) -> bool {
    name.starts_with("scr-") || name.starts_with("sbh-")
}

fn argv(line: &str) -> Vec<String> {
    line.split_whitespace().map(String::from).collect()
}

fn step(line: &str, link: &str) -> Step {
    Step {
        argv: argv(line),
        link: Some(link.into()),
    }
}

/// A destination as both the agent and `ip -j route` can spell it: a network, with a host route's
/// length written out.
fn destination(dst: &str) -> Option<String> {
    let net = if dst.contains('/') {
        dst.parse::<IpNet>().ok()?
    } else {
        IpNet::from(dst.parse::<std::net::IpAddr>().ok()?)
    };
    Some(net.trunc().to_string())
}

const TABLE: &str = "table inet scrubline
delete table inet scrubline
table inet scrubline {
\tchain incoming {
\t\ttype filter hook prerouting priority -450; policy accept;
\t}
\tchain blackwell {
\t\ttype filter hook prerouting priority -160; policy accept;
\t}
\tchain gre_acl {
\t\ttype filter hook prerouting priority -150; policy accept;
\t}
\tchain prerouting {
\t\ttype nat hook prerouting priority dstnat; policy accept;
\t}
\tchain forward {
\t\ttype filter hook forward priority 0; policy accept;
\t}
\tchain forwarded_hosts {
\t\ttype filter hook forward priority 10; policy accept;
\t}
\tchain input {
\t\ttype filter hook input priority 0; policy accept;
\t}
}
";

fn gre_acl(rules: &[ACLEntry], address: std::net::Ipv4Addr) -> Vec<(String, bool)> {
    let mut rules: Vec<_> = rules.iter().collect();
    rules.sort_by_key(|rule| rule.priority);
    let mut entries = Vec::new();
    for rule in rules {
        let m = &rule.r#match;
        if !m.dst_cidr.is_empty() {
            match m.dst_cidr.parse::<IpNet>() {
                Ok(net) if !net.contains(&std::net::IpAddr::V4(address)) => continue,
                Err(_) => break,
                _ => {}
            }
        }
        if rule.action == "count" {
            continue;
        }
        if !matches!(rule.action.as_str(), "permit" | "drop")
            || (Match {
                src_cidr: String::new(),
                dst_cidr: String::new(),
                proto: String::new(),
                dport: 0,
                dport_to: 0,
                sport: 0,
                sport_to: 0,
                ..m.clone()
            }) != Match::default()
        {
            break;
        }
        let mut terms = Vec::new();
        if !m.src_cidr.is_empty() {
            match m.src_cidr.parse::<IpNet>() {
                Ok(IpNet::V4(net)) => terms.push(format!("ip saddr {}", net.trunc())),
                Ok(IpNet::V6(_)) => continue,
                Err(_) => break,
            }
        }
        let ports = m.dport != 0 || m.sport != 0;
        match m.proto.to_ascii_lowercase().as_str() {
            "tcp" => terms.push("meta l4proto tcp".into()),
            "udp" => terms.push("meta l4proto udp".into()),
            "icmp" if !ports => terms.push("meta l4proto icmp".into()),
            "" | "any" if ports => terms.push("meta l4proto { tcp, udp }".into()),
            "" | "any" => {}
            _ => break,
        }
        for (field, from, to) in [
            ("sport", m.sport, m.sport_to),
            ("dport", m.dport, m.dport_to),
        ] {
            if (1..=65535).contains(&from) && (from..=65535).contains(&to.max(from)) {
                let port = if to > from {
                    format!("{from}-{to}")
                } else {
                    from.to_string()
                };
                terms.push(format!("th {field} {port}"));
            }
        }
        if ![m.sport, m.sport_to, m.dport, m.dport_to]
            .iter()
            .all(|p| (0..=65535).contains(p))
        {
            break;
        }
        entries.push((terms.join(" "), rule.action == "drop"));
    }
    entries
}

/// An interface the provisioner may touch, as the renderers name them.
fn interface(name: &str) -> bool {
    ours(name)
        && name.len() <= 15
        && name
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}
fn number(word: &str) -> bool {
    !word.is_empty() && word.len() <= 10 && word.bytes().all(|c| c.is_ascii_digit())
}
fn address(word: &str) -> bool {
    word.parse::<std::net::Ipv4Addr>().is_ok()
}
fn port_list(ports: &[&str]) -> bool {
    (1..=16).contains(&ports.len())
        && ports.iter().enumerate().all(|(i, port)| {
            let value = if i == ports.len() - 1 {
                Some(*port)
            } else {
                port.strip_suffix(',')
            };
            value.is_some_and(|v| number(v) && v.parse::<u16>().is_ok_and(|port| port > 0))
        })
}
/// An nft rule as the renderers write them, and nothing else: a forwarding rule scoped to one of
/// our interfaces, or a firewall rule scoped to GRE and IPIP, made of the words they use, with
/// drop the only verdict.
fn rule(words: &[&str]) -> bool {
    if let ["input", "iifname", name, "drop"] = words {
        return name
            .strip_prefix('"')
            .and_then(|name| name.strip_suffix('"'))
            .is_some_and(|name| name.starts_with("scr-") && interface(name));
    }
    let quoted = |w: &str| {
        w.strip_prefix('"')
            .and_then(|w| w.strip_suffix('"'))
            .is_some_and(|name| interface(name) || name == "sbh-*")
    };
    if let ["input", "ip", "daddr", addr, "meta", "l4proto", "!=", "47", "drop"] = words {
        return address(addr);
    }
    if let ["forward", direction @ ("iifname" | "oifname"), name, "ct", rest @ ..] = words {
        return quoted(name)
            && match (*direction, rest) {
                (_, ["status", "&", "dnat", "==", "0", "drop"]) => true,
                ("iifname", ["direction", "!=", "reply", "drop"]) => true,
                ("oifname", ["original", "ip", "daddr", "!=", addr, "drop"]) => address(addr),
                _ => false,
            };
    }
    if let ["prerouting", "iifname", "!=", "\"scr-*\"", "iifname", "!=", "\"sbh-*\"", "ip", "daddr", addr, "tcp" | "udp", "dport", "{", ports @ .., "}", "dnat", "ip", "to", backend] =
        words
    {
        return address(addr)
            && backend.parse::<std::net::Ipv4Addr>().is_ok_and(|addr| {
                let [a, b, ..] = addr.octets();
                a == 198 && (18..=19).contains(&b)
            })
            && port_list(ports);
    }
    if let ["forward", "iifname" | "oifname", name, "tcp" | "udp", "sport" | "dport", "!=", "{", ports @ .., "}", "drop"] =
        words
    {
        return quoted(name) && port_list(ports);
    }
    if let ["forwarded_hosts", rest @ ..] = words {
        return match rest {
            ["oifname", name, "ip", "daddr", backend, "ct", "status", "dnat", "return"] => {
                quoted(name) && address(backend)
            }
            _ => false,
        };
    }
    let rest = match words {
        ["forward", "oifname" | "iifname", name, rest @ ..] if quoted(name) => rest,
        ["input", "meta", "l4proto", "{", "47,", "4", "}", rest @ ..] => rest,
        ["input", "meta", "nfproto", "ipv6", "meta", "l4proto", "{", "47,", "4", "}", rest @ ..] => {
            rest
        }
        _ => return false,
    };
    const WORDS: &[&str] = &[
        "tcp", "flags", "syn", "option", "maxseg", "size", "set", "ip", "ip6", "saddr", "daddr",
        "!=", "{", "}", "drop", "meta", "nfproto", "ipv4", "ipv6",
    ];
    let clamp = matches!(rest, [.., "set", n] if number(n));
    (clamp || rest.last() == Some(&"drop"))
        && rest.iter().all(|w| {
            WORDS.contains(w) || number(w) || destination(w.trim_end_matches(',')).is_some()
        })
}
/// Works out a pass. It refuses a line it does not recognise rather than guess at it: these are
/// commands run as root, so every line must have exactly the shape the renderers give it.
pub fn plan(desired: &Desired, observed: &Observed) -> Result<Pass> {
    let mut adds: BTreeMap<String, &str> = BTreeMap::new();
    let mut sets = Vec::new();
    let mut routes: BTreeMap<(String, String), &str> = BTreeMap::new();
    let mut shapes: BTreeMap<&str, Shape> = BTreeMap::new();
    let mut nft = String::from(TABLE);
    for line in desired.lines.iter().map(|l| l.trim()) {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let refuse = || format!("refusing to apply an unrecognised line: {line:?}");
        // Nothing that could end one command and start another reaches nft or a command line.
        if !line
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b" .:/,{}!=*&\"-_".contains(&c))
        {
            return Err(refuse());
        }
        let words: Vec<&str> = line.split_whitespace().collect();
        match words.as_slice() {
            ["ip", "link", "add", name, "type", "gre" | "ipip", "local", a, "remote", b, key @ ..]
                if interface(name)
                    && address(a)
                    && address(b)
                    && matches!(key, [] | ["key", _])
                    && key.get(1).is_none_or(|k| k.parse::<u32>().is_ok()) =>
            {
                adds.insert(name.to_string(), line);
            }
            ["ip", "link", "add", name, "type", "wireguard"] if interface(name) => {
                adds.insert(name.to_string(), line);
            }
            ["ip", "link", "set", name, "mtu", mtu, "up"]
                if interface(name)
                    && mtu.parse::<u16>().is_ok_and(|m| (576..=9000).contains(&m)) =>
            {
                sets.push((*name, line))
            }
            ["ip", "route", "replace", dst, "dev", name] if interface(name) => {
                // Only the customers' networks: never a default route through a tunnel.
                let dst = destination(dst)
                    .filter(|d| !d.ends_with("/0"))
                    .ok_or_else(refuse)?;
                routes.insert((dst, name.to_string()), line);
            }
            ["nft", "add", "rule", "inet", "scrubline", tail @ ..] if rule(tail) => {
                nft.push_str(&line[4..]);
                nft.push('\n');
            }
            ["tc", "qdisc", "replace", "dev", name, "root", "handle", "1:", "tbf", "rate", rate, "burst", burst, "latency", "5ms"]
                if interface(name) && number(burst) =>
            {
                let kbit: u64 = rate
                    .strip_suffix("kbit")
                    .filter(|v| number(v))
                    .and_then(|v| v.parse().ok())
                    .ok_or_else(refuse)?;
                shapes.entry(name).or_default().bucket = Some((kbit * 125, line));
            }
            ["tc", "qdisc", "replace", "dev", name, "parent", "1:1", "handle", "10:", "fq_codel", "memory_limit", bytes]
                if interface(name) =>
            {
                // No more than the renderers ever ask for: a queue holds kernel memory.
                let bytes: u64 = Some(*bytes)
                    .filter(|b| number(b))
                    .and_then(|b| b.parse().ok())
                    .filter(|b| (QUEUE_MIN as u64..=QUEUE_MAX as u64).contains(b))
                    .ok_or_else(refuse)?;
                shapes.entry(name).or_default().queue = Some((bytes, line));
            }
            _ => return Err(refuse()),
        }
    }
    // A token bucket and its queue go together: a bucket set afresh comes with a FIFO of the
    // kernel's, and a queue has nowhere to go without its bucket.
    let mut shapers = Vec::new();
    for (name, shape) in &shapes {
        match (shape.bucket, shape.queue) {
            (Some(bucket), Some(queue)) => shapers.push((*name, bucket, queue)),
            _ => {
                return Err(format!(
                    "refusing to apply half a shaper on {name}: a token bucket and its queue go together"
                ))
            }
        }
    }
    let mut pass = Pass::default();
    for t in &desired.tunnels {
        if t.r#type == "wireguard" {
            crate::wireguard::validate_options(
                t.wireguard.as_ref().ok_or("missing wireguard options")?,
            )?;
            if t.interface != crate::tunnel::interface_name(&t.id)?
                || adds
                    .get(&t.interface)
                    .is_none_or(|line| !line.ends_with("type wireguard"))
            {
                return Err("WireGuard interface does not match rendered configuration".into());
            }
            pass.wireguard.insert(t.interface.clone(), t.clone());
        }
    }
    // Interfaces the agent no longer asks for, or asks for differently, go first: a tunnel that
    // moved to another remote has to be rebuilt, since the kernel will not retarget one in place.
    let mut rebuilt = BTreeSet::new();
    for (name, alias) in &observed.links {
        if adds.get(name).is_none_or(|line| line != alias) {
            pass.steps.push(step(&format!("ip link del {name}"), name));
            rebuilt.insert(name.clone());
        }
    }
    for (name, line) in &adds {
        if observed.links.get(name).is_none_or(|alias| alias != line) {
            pass.steps.push(step(line, name));
            pass.steps.push(Step {
                argv: ["ip", "link", "set", "dev", name, "alias"]
                    .iter()
                    .map(|s| s.to_string())
                    .chain(std::iter::once(line.to_string()))
                    .collect(),
                link: Some(name.clone()),
            });
            rebuilt.insert(name.clone());
        }
    }
    for (name, line) in sets {
        pass.steps.push(step(line, name));
    }
    // Deleting an interface takes its routes with it; the rest are removed one by one.
    for (dst, dev) in &observed.routes {
        if !routes.contains_key(&(dst.clone(), dev.clone())) && !rebuilt.contains(dev) {
            pass.steps
                .push(step(&format!("ip route del {dst} dev {dev}"), dev));
        }
    }
    for ((_, dev), line) in &routes {
        pass.steps.push(step(line, dev));
    }
    for (name, (rate, bucket), (memory, queue)) in shapers {
        let seen = observed.shapers.get(name);
        // The queue is set whenever the bucket is: a bucket set afresh has the kernel's FIFO in
        // the queue's place, and the queue's size follows the rate.
        let reshape = rebuilt.contains(name) || seen.map(|s| s.rate) != Some(rate);
        if reshape {
            pass.steps.push(step(bucket, name));
        }
        if reshape || seen.and_then(|s| s.queue) != Some(memory) {
            // Not held against the tunnel. Without its queue the bucket still holds the rate,
            // over its own short FIFO, and a tunnel reported down withdraws its prefixes.
            pass.steps.push(Step {
                argv: argv(queue),
                link: None,
            });
        }
    }
    nft.push_str(
        "add rule inet scrubline forwarded_hosts ip daddr 198.18.0.0/15 ct status dnat drop\n",
    );
    for (prefix, name) in desired
        .tunnels
        .iter()
        .filter_map(crate::tunnel::gre_counter_target)
    {
        let Some(address) = prefix
            .strip_suffix("/32")
            .and_then(|p| p.parse::<std::net::Ipv4Addr>().ok())
        else {
            continue;
        };
        let counter = format!("gre_in_{:08x}", u32::from(address));
        if pass.ingress.contains_key(&counter) {
            continue;
        }
        nft.push_str(&format!(
            "add counter inet scrubline {counter}\nadd rule inet scrubline incoming iifname != \"lo\" iifname != \"scr-*\" iifname != \"sbh-*\" ip daddr {address} ip protocol != {{ 4, 47 }} counter name {counter}\n"
        ));
        pass.ingress
            .insert(counter, (prefix.to_owned(), name.to_owned()));
    }
    render_blackwell(desired, &mut pass, &mut nft);
    let mut acl_targets = BTreeSet::new();
    for tunnel in &desired.tunnels {
        let Some((prefix, interface)) = crate::tunnel::gre_counter_target(tunnel) else {
            continue;
        };
        if tunnel.mitigation == "on_demand" {
            continue;
        }
        let Some(address) = prefix
            .strip_suffix("/32")
            .and_then(|p| p.parse::<std::net::Ipv4Addr>().ok())
        else {
            continue;
        };
        if !acl_targets.insert(address) {
            continue;
        }
        let rules = gre_acl(&desired.asic, address);
        let counter = format!("gre_drop_{:08x}", u32::from(address));
        if !rules.iter().any(|(_, drop)| *drop) {
            continue;
        }
        let chain = format!("acl_{:08x}", u32::from(address));
        if !pass.drops.contains_key(&counter) {
            nft.push_str(&format!("add counter inet scrubline {counter}\n"));
        }
        nft.push_str(&format!(
            "add chain inet scrubline {chain}\nadd rule inet scrubline gre_acl iifname != \"lo\" iifname != \"scr-*\" iifname != \"sbh-*\" ip daddr {address} ip protocol != {{ 4, 47 }} jump {chain}\n"
        ));
        for (terms, drop) in rules {
            let verdict = if drop {
                format!("counter name {counter} drop")
            } else {
                "return".into()
            };
            nft.push_str(&format!(
                "add rule inet scrubline {chain} {terms} {verdict}\n"
            ));
        }
        pass.drops
            .insert(counter, (prefix.to_owned(), interface.to_owned()));
    }
    pass.nft = nft;
    Ok(pass)
}

fn render_blackwell(desired: &Desired, pass: &mut Pass, nft: &mut String) {
    let carried: Vec<IpNet> = desired
        .tunnels
        .iter()
        .flat_map(|tunnel| &tunnel.prefixes)
        .filter_map(|prefix| prefix.parse().ok())
        .collect();
    let mut hosts = BTreeMap::new();
    for host in &desired.blackwell {
        if (1..=1_000_000_000).contains(&host.max_pps)
            && carried.iter().any(|net| net.contains(&host.address))
        {
            hosts
                .entry(host.address)
                .and_modify(|pps: &mut u64| *pps = (*pps).min(host.max_pps))
                .or_insert(host.max_pps);
        }
    }
    let dedicated: BTreeMap<_, _> = desired
        .tunnels
        .iter()
        .filter_map(crate::tunnel::gre_counter_target)
        .filter_map(|(prefix, interface)| {
            prefix
                .parse::<IpNet>()
                .ok()
                .map(|net| (net.addr(), (prefix, interface)))
        })
        .collect();
    for (ipv4, family, field, set) in [
        (true, "ipv4_addr", "ip", "bw_active4"),
        (false, "ipv6_addr", "ip6", "bw_active6"),
    ] {
        let mut matches = Vec::new();
        for (index, (host, rate)) in hosts
            .iter()
            .filter(|(host, _)| host.is_ipv4() == ipv4)
            .enumerate()
        {
            if index == 0 {
                nft.push_str(&format!("add set inet scrubline {set} {{ type {family}; flags dynamic,timeout; timeout 2s; size 1024; }}\n"));
            }
            let chain = format!("{set}_{index}");
            nft.push_str(&format!("add chain inet scrubline {chain}\n"));
            for tunnel in &desired.tunnels {
                if tunnel.port_forward.is_some()
                    && tunnel.local.parse::<std::net::IpAddr>().ok() == Some(*host)
                {
                    if let Ok(remote) = tunnel.remote.parse::<std::net::Ipv4Addr>() {
                        nft.push_str(&format!("add rule inet scrubline {chain} ip saddr {remote} meta l4proto gre return\n"));
                    }
                }
            }
            nft.push_str(&format!("add rule inet scrubline {chain} limit rate over {rate}/second burst {rate} packets update @{set} {{ {field} daddr }}\n"));
            let counter = if let (std::net::IpAddr::V4(address), Some((prefix, interface))) =
                (host, dedicated.get(host))
            {
                let name = format!("gre_drop_{:08x}", u32::from(*address));
                nft.push_str(&format!("add counter inet scrubline {name}\n"));
                pass.drops
                    .insert(name.clone(), (prefix.to_string(), interface.to_string()));
                format!("counter name {name}")
            } else {
                "counter".into()
            };
            nft.push_str(&format!(
                "add rule inet scrubline {chain} {field} daddr @{set} {counter} drop\n"
            ));
            matches.push(format!("{host} : jump {chain}"));
        }
        if !matches.is_empty() {
            let entries = matches.join(", ");
            nft.push_str(&format!("add rule inet scrubline blackwell iifname != \"lo\" iifname != \"scr-*\" iifname != \"sbh-*\" {field} daddr vmap {{ {entries} }}\n"));
        }
    }
}

/// A shaper as the agent asks for it: the token bucket's rate and line, and the queue's size and
/// line.
#[derive(Default)]
struct Shape<'a> {
    bucket: Option<(u64, &'a str)>,
    queue: Option<(u64, &'a str)>,
}

/// Runs a command, returning what it printed or why it failed.
pub trait Runner {
    fn run(&mut self, argv: &[String], stdin: Option<&str>) -> Result<String>;
}

/// Runs commands on this box.
pub struct System;

impl Runner for System {
    fn run(&mut self, argv: &[String], stdin: Option<&str>) -> Result<String> {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let (program, args) = argv.split_first().ok_or("empty command")?;
        let mut child = Command::new(program)
            .args(args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("{program}: {e}"))?;
        if let Some(input) = stdin {
            child
                .stdin
                .take()
                .ok_or("no stdin")?
                .write_all(input.as_bytes())
                .map_err(|e| e.to_string())?;
        }
        let out = child.wait_with_output().map_err(|e| e.to_string())?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            Err(format!(
                "{}: {}",
                argv.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }
}

fn json_rows(raw: &str) -> Result<Vec<Value>> {
    if raw.trim().is_empty() {
        return Ok(vec![]);
    }
    serde_json::from_str::<Vec<Value>>(raw).map_err(|e| format!("reading iproute2 output: {e}"))
}

/// Reads the parts of the box a pass manages.
pub fn observe(r: &mut impl Runner) -> Result<Observed> {
    let mut o = Observed::default();
    let words = |s: &str| s.split_whitespace().map(String::from).collect::<Vec<_>>();
    for link in json_rows(&r.run(&words("ip -j link show"), None)?)? {
        let name = link["ifname"].as_str().unwrap_or_default();
        if ours(name) {
            o.links.insert(
                name.into(),
                link["ifalias"].as_str().unwrap_or_default().into(),
            );
        }
    }
    for family in ["-4", "-6"] {
        let raw = match r.run(&words(&format!("ip -j {family} route show")), None) {
            Ok(raw) => raw,
            // A kernel booted without IPv6 has no IPv6 routes to read.
            Err(_) if family == "-6" => String::new(),
            Err(e) => return Err(e),
        };
        for route in json_rows(&raw)? {
            let dev = route["dev"].as_str().unwrap_or_default();
            if let (true, Some(dst)) = (ours(dev), route["dst"].as_str().and_then(destination)) {
                o.routes.insert((dst, dev.into()));
            }
        }
    }
    let qdiscs = json_rows(&r.run(&words("tc -j qdisc show"), None)?)?;
    // A bucket at another handle, as releases before the queue set them, is not ours to keep: it
    // is replaced, queue and all.
    for q in &qdiscs {
        let dev = q["dev"].as_str().unwrap_or_default();
        if ours(dev) && q["kind"] == "tbf" && q["root"] == true && q["handle"] == "1:" {
            if let Some(rate) = q["options"]["rate"].as_u64() {
                o.shapers.insert(dev.into(), Shaper { rate, queue: None });
            }
        }
    }
    for q in &qdiscs {
        let dev = q["dev"].as_str().unwrap_or_default();
        if q["kind"] == "fq_codel" && q["parent"] == "1:1" && q["handle"] == "10:" {
            if let Some(shaper) = o.shapers.get_mut(dev) {
                shaper.queue = q["options"]["memory_limit"].as_u64();
            }
        }
    }
    o.table = r.run(&words("nft list table inet scrubline"), None).is_ok();
    Ok(o)
}

/// The outcome of applying a pass: what failed, by interface, and whether the ruleset loaded.
#[derive(Debug, Default)]
pub struct Applied {
    pub failed: BTreeMap<String, String>,
    pub reloaded: bool,
    pub errors: Vec<String>,
    /// Why the ruleset did not load, when it did not. The pass stops there.
    pub blocked: Option<String>,
}

/// Applies a pass. The ruleset loads first, when it differs from the last one loaded or the table
/// has gone: its rules match interfaces by name, so they are in place before any interface they
/// filter comes up. If it does not load, nothing else changes, and the box keeps the last
/// consistent state it had; a tunnel is never brought up without its filters. After that a
/// failure is recorded against its interface and the pass carries on, so one bad tunnel does not
/// hold up the others.
pub fn apply(
    r: &mut impl Runner,
    pass: &Pass,
    observed: &Observed,
    last_nft: &mut String,
) -> Applied {
    let mut out = Applied::default();
    if pass.nft != *last_nft || !observed.table {
        let load = ["nft", "-f", "-"].map(String::from);
        match r.run(&load, Some(&pass.nft)) {
            Ok(_) => {
                *last_nft = pass.nft.clone();
                out.reloaded = true;
            }
            Err(e) => {
                out.blocked = Some(e);
                return out;
            }
        }
    }
    for s in &pass.steps {
        if s.link
            .as_ref()
            .is_some_and(|link| out.failed.contains_key(link) && pass.wireguard.contains_key(link))
        {
            continue;
        }
        if s.argv.get(1).is_some_and(|v| v == "link")
            && s.argv.get(2).is_some_and(|v| v == "set")
            && s.argv.get(4).is_some_and(|v| v == "mtu")
        {
            if let Some(t) = s.link.as_ref().and_then(|name| pass.wireguard.get(name)) {
                if let Err(e) = crate::wireguard::configure(
                    r,
                    t,
                    std::path::Path::new("/var/lib/scrubline-wireguard"),
                ) {
                    let _ = r.run(
                        &argv(&format!("ip link set dev {} down", t.interface)),
                        None,
                    );
                    out.failed.insert(t.interface.clone(), e);
                    continue;
                }
            }
        }
        if let Err(e) = r.run(&s.argv, None) {
            match &s.link {
                Some(link) => {
                    out.failed.entry(link.clone()).or_insert(e);
                }
                None => out.errors.push(e),
            }
        }
    }
    out
}

#[derive(Default)]
pub struct EdgeCounters {
    pub ingress: Vec<crate::wire::GreCounter>,
    pub drops: Vec<crate::wire::GreCounter>,
}

pub fn read_counters(
    runner: &mut impl Runner,
    pass: &Pass,
    applied: &Applied,
    generation: &str,
) -> Result<EdgeCounters> {
    if pass.ingress.is_empty() || applied.blocked.is_some() {
        return Ok(EdgeCounters::default());
    }
    let raw = runner.run(&argv("nft -j list table inet scrubline"), None)?;
    let value: Value = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    let rows = value["nftables"]
        .as_array()
        .ok_or("nft counters were not returned")?;
    let mut out = EdgeCounters::default();
    for row in rows {
        let counter = &row["counter"];
        let Some(name) = counter["name"].as_str() else {
            continue;
        };
        let (matches, samples) = if name.starts_with("gre_drop_") {
            (&pass.drops, &mut out.drops)
        } else {
            (&pass.ingress, &mut out.ingress)
        };
        let Some((prefix, interface)) = matches.get(name) else {
            continue;
        };
        if applied.failed.contains_key(interface) {
            continue;
        }
        if let (Some(packets), Some(bytes)) =
            (counter["packets"].as_u64(), counter["bytes"].as_u64())
        {
            samples.push(crate::wire::GreCounter {
                prefix: prefix.clone(),
                generation: generation.to_owned(),
                packets,
                bytes,
            });
        }
    }
    Ok(out)
}

/// What to tell the agent about each customer tunnel: built, or why not. Built is all it can
/// say; whether the customer's end answers is theirs to know.
pub fn report(desired: &Desired, applied: &Applied) -> Value {
    let rows: Vec<Value> = desired
        .tunnels
        .iter()
        .map(|t| {
            let failed = applied
                .blocked
                .as_ref()
                .map(|e| format!("the tunnel firewall did not load: {e}"))
                .or_else(|| applied.failed.get(&t.interface).cloned());
            match failed {
                None => json!({"tunnel_id":t.id,"state":"up"}),
                Some(e) => json!({"tunnel_id":t.id,"state":"down","detail":e}),
            }
        })
        .collect();
    json!({ "tunnels": rows })
}

/// Quotes a command for display, the way a shell would read it back.
pub fn shell(argv: &[String]) -> String {
    argv.iter()
        .map(|a| {
            if !a.is_empty()
                && a.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-_./:=@,+".contains(&c))
            {
                a.clone()
            } else {
                format!("'{}'", a.replace('\'', r"'\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    fn desired(lines: &[&str]) -> Desired {
        Desired {
            tunnels: vec![NodeTunnel {
                id: "nw".into(),
                interface: "scr-nw".into(),
                ..Default::default()
            }],
            asic: Vec::new(),
            blackwell: Vec::new(),
            lines: lines.iter().map(|l| l.to_string()).collect(),
            error: String::new(),
        }
    }
    fn shown(pass: &Pass) -> Vec<String> {
        pass.steps.iter().map(|s| shell(&s.argv)).collect()
    }
    const ADD: &str = "ip link add scr-nw type gre local 192.0.2.1 remote 198.51.100.1 key 42";
    const SET: &str = "ip link set scr-nw mtu 1472 up";
    const ROUTE: &str = "ip route replace 203.0.113.0/24 dev scr-nw";
    const BUCKET: &str =
        "tc qdisc replace dev scr-nw root handle 1: tbf rate 1000000kbit burst 1250000 latency 5ms";
    const QUEUE: &str =
        "tc qdisc replace dev scr-nw parent 1:1 handle 10: fq_codel memory_limit 12500000";
    /// What the box holds with both in place.
    const SHAPED: Shaper = Shaper {
        rate: 125_000_000,
        queue: Some(12_500_000),
    };
    #[test]
    fn a_fresh_box_gets_everything() {
        let d = desired(&[
            "# Northwind",
            ADD,
            SET,
            ROUTE,
            "nft add rule inet scrubline forward oifname \"scr-nw\" tcp flags syn tcp option maxseg size set 1432",
            BUCKET,
            QUEUE,
        ]);
        let pass = plan(&d, &Observed::default()).unwrap();
        assert_eq!(
            shown(&pass),
            [
                ADD.to_string(),
                format!("ip link set dev scr-nw alias '{ADD}'"),
                SET.into(),
                ROUTE.into(),
                BUCKET.into(),
                QUEUE.into(),
            ]
        );
        assert!(pass.nft.starts_with(TABLE));
        assert!(pass
            .nft
            .contains("add rule inet scrubline forward oifname \"scr-nw\" tcp flags syn tcp option maxseg size set 1432\n"));
    }
    #[test]
    fn a_box_already_in_step_is_left_alone() {
        let d = desired(&[ADD, SET, ROUTE, BUCKET, QUEUE]);
        let o = Observed {
            links: BTreeMap::from([("scr-nw".into(), ADD.into())]),
            routes: BTreeSet::from([("203.0.113.0/24".into(), "scr-nw".into())]),
            shapers: BTreeMap::from([("scr-nw".into(), SHAPED)]),
            table: true,
        };
        // Only the idempotent settings are reasserted: nothing is rebuilt or reshaped.
        assert_eq!(shown(&plan(&d, &o).unwrap()), [SET, ROUTE]);
    }
    #[test]
    fn a_shaper_is_set_again_where_it_differs() {
        let d = desired(&[ADD, SET, ROUTE, BUCKET, QUEUE]);
        let with = |shaper: Option<Shaper>| Observed {
            links: BTreeMap::from([("scr-nw".into(), ADD.into())]),
            routes: BTreeSet::from([("203.0.113.0/24".into(), "scr-nw".into())]),
            shapers: shaper
                .map(|s| BTreeMap::from([("scr-nw".into(), s)]))
                .unwrap_or_default(),
            table: true,
        };
        let both = [SET, ROUTE, BUCKET, QUEUE];
        // No bucket of ours: none at all, or one an older release left at another handle,
        // which observe does not count. The new one takes its place, and its queue follows.
        assert_eq!(shown(&plan(&d, &with(None)).unwrap()), both);
        // A new rate sets the bucket again, and the queue, whose size follows it.
        let slower = Shaper {
            rate: 12_500_000,
            ..SHAPED
        };
        assert_eq!(shown(&plan(&d, &with(Some(slower))).unwrap()), both);
        // The bucket in step over some other queue, or none: only the queue is set.
        for queue in [None, Some(32 << 20)] {
            let pass = plan(&d, &with(Some(Shaper { queue, ..SHAPED }))).unwrap();
            assert_eq!(shown(&pass), [SET, ROUTE, QUEUE]);
            assert_eq!(
                pass.steps[2].link, None,
                "a queue is not held against the tunnel"
            );
        }
    }
    #[test]
    fn a_shaper_comes_whole() {
        for lines in [&[ADD, BUCKET][..], &[ADD, QUEUE]] {
            let refused = plan(&desired(lines), &Observed::default()).unwrap_err();
            assert!(refused.contains("half a shaper on scr-nw"), "{refused}");
        }
        assert!(plan(&desired(&[ADD, BUCKET, QUEUE]), &Observed::default()).is_ok());
    }
    #[test]
    fn a_queue_that_will_not_load_leaves_the_tunnel_up() {
        // A kernel without fq_codel: the bucket holds the rate over its own FIFO, and the
        // tunnel delivers, so its prefixes stay announced; the pass says what failed.
        let d = desired(&[ADD, SET, ROUTE, BUCKET, QUEUE]);
        let pass = plan(&d, &Observed::default()).unwrap();
        let mut r = Fake {
            ran: vec![],
            fail: "tc qdisc replace dev scr-nw parent",
        };
        let applied = apply(&mut r, &pass, &Observed::default(), &mut String::new());
        assert!(applied.failed.is_empty(), "{applied:?}");
        assert_eq!(applied.errors.len(), 1, "{applied:?}");
        assert!(applied.errors[0].contains("fq_codel"), "{applied:?}");
        assert_eq!(report(&d, &applied)["tunnels"][0]["state"], "up");
        // The bucket failing is the tunnel failing, as it always was.
        let mut r = Fake {
            ran: vec![],
            fail: "tc qdisc replace dev scr-nw root",
        };
        let applied = apply(&mut r, &pass, &Observed::default(), &mut String::new());
        assert_eq!(report(&d, &applied)["tunnels"][0]["state"], "down");
    }
    #[test]
    fn observe_reads_our_buckets_and_the_queues_under_them() {
        let qdiscs = r#"[
            {"kind":"tbf","handle":"1:","dev":"scr-nw","root":true,"refcnt":2,
             "options":{"rate":125000000,"burst":1250000,"lat":5000}},
            {"kind":"fq_codel","handle":"10:","dev":"scr-nw","parent":"1:1",
             "options":{"limit":10240,"flows":1024,"quantum":1514,"target":4999,
                        "interval":99999,"memory_limit":12500000,"ecn":true,"drop_batch":64}},
            {"kind":"tbf","handle":"1:","dev":"scr-bare","root":true,"refcnt":2,
             "options":{"rate":125000,"burst":32768,"lat":5000}},
            {"kind":"tbf","handle":"8001:","dev":"scr-old","root":true,"refcnt":2,
             "options":{"rate":125000,"burst":32768,"lat":50000}},
            {"kind":"fq_codel","handle":"0:","dev":"eth0","root":true,"refcnt":2,
             "options":{"limit":10240,"memory_limit":33554432}}
        ]"#;
        let mut r = Canned(BTreeMap::from([("tc -j qdisc show", qdiscs)]));
        let o = observe(&mut r).unwrap();
        assert_eq!(
            o.shapers,
            BTreeMap::from([
                (
                    "scr-bare".into(),
                    Shaper {
                        rate: 125_000,
                        queue: None
                    }
                ),
                ("scr-nw".into(), SHAPED),
            ])
        );
    }
    /// Answers each command with what a box would print for it, and nothing for the rest.
    struct Canned(BTreeMap<&'static str, &'static str>);
    impl Runner for Canned {
        fn run(&mut self, argv: &[String], _: Option<&str>) -> Result<String> {
            Ok(self.0.get(shell(argv).as_str()).unwrap_or(&"").to_string())
        }
    }
    #[test]
    fn changed_or_unwanted_tunnels_and_routes_go() {
        let moved = "ip link add scr-nw type gre local 192.0.2.1 remote 198.51.100.9 key 42";
        let d = desired(&[moved, SET, ROUTE, BUCKET, QUEUE]);
        let o = Observed {
            links: BTreeMap::from([
                ("scr-nw".into(), ADD.into()),
                (
                    "scr-gone".into(),
                    "ip link add scr-gone type ipip local 192.0.2.1 remote 198.51.100.2".into(),
                ),
                ("sbh-0123456789a".into(), String::new()),
            ]),
            routes: BTreeSet::from([
                ("203.0.113.0/24".into(), "scr-nw".into()),
                ("198.51.100.0/24".into(), "scr-gone".into()),
            ]),
            shapers: BTreeMap::from([("scr-nw".into(), SHAPED)]),
            table: true,
        };
        assert_eq!(
            shown(&plan(&d, &o).unwrap()),
            [
                "ip link del sbh-0123456789a".to_string(),
                "ip link del scr-gone".into(),
                "ip link del scr-nw".into(),
                moved.into(),
                format!("ip link set dev scr-nw alias '{moved}'"),
                SET.into(),
                ROUTE.into(),
                // Rebuilt, so its shaper went with it.
                BUCKET.into(),
                QUEUE.into(),
            ]
        );
        // A route the agent stopped asking for on an interface that stays is removed alone.
        let d = desired(&[ADD, SET]);
        let o = Observed {
            links: BTreeMap::from([("scr-nw".into(), ADD.into())]),
            routes: BTreeSet::from([("198.51.100.7/32".into(), "scr-nw".into())]),
            ..Default::default()
        };
        assert_eq!(
            shown(&plan(&d, &o).unwrap()),
            [SET, "ip route del 198.51.100.7/32 dev scr-nw"]
        );
    }
    #[test]
    fn it_runs_nothing_it_does_not_recognise() {
        for line in [
            "ip link add eth0 type gre local 192.0.2.1 remote 198.51.100.1",
            "ip link add scr-nw type gre local 192.0.2.1 remote 198.51.100.1 dev eth0",
            "ip link add scr-nw type vxlan id 42 local 192.0.2.1 remote 198.51.100.1",
            "ip link set scr-nw mtu 65535 up",
            "ip route replace 0.0.0.0/0 dev eth0",
            // ip -j route lists these as "default", so they could never be taken down again.
            "ip route replace 0.0.0.0/0 dev scr-nw",
            "ip route replace ::/0 dev scr-nw",
            "nft flush ruleset",
            // Everything after the first words goes into an nft script, where ; and a newline
            // each start another command.
            "nft add rule inet scrubline input accept; flush ruleset",
            "nft add rule inet scrubline input meta l4proto { 47, 4 } drop\nflush ruleset",
            "nft add rule inet scrubline input accept",
            "nft add rule inet scrubline input meta l4proto { 47, 4 } accept",
            "nft add rule inet scrubline forward oifname \"eth0\" drop",
            "nft add rule inet scrubline forward iifname \"scr-nw\" jump elsewhere",
            "nft add rule inet scrubline forward oifname \"scr-nw\" tcp flags syn tcp option maxseg size set rt mtu",
            "rm -rf /",
            "tc qdisc del dev scr-nw root",
            "tc qdisc replace dev scr-nw root tbf rate 1000kbit burst 32768 latency 50ms limit 1",
            "tc qdisc replace dev eth0 root handle 1: tbf rate 1000kbit burst 32768 latency 5ms",
            "tc qdisc replace dev eth0 parent 1:1 handle 10: fq_codel memory_limit 131072",
        ] {
            assert!(
                plan(&desired(&[line]), &Observed::default()).is_err(),
                "{line}"
            );
        }
    }
    #[test]
    fn a_shaper_has_exactly_the_shape_the_renderers_give_it() {
        // Each beside a part that is right, so it is the line itself that is refused.
        let queue = |tail: &str| format!("tc qdisc replace dev scr-nw {tail}");
        for (bucket, queue) in [
            // The shaper as releases before the queue wrote it.
            (
                queue("root tbf rate 1000kbit burst 32768 latency 50ms"),
                QUEUE.into(),
            ),
            (
                queue("root handle 1: tbf rate 1000kbit burst 32768 latency 50ms"),
                QUEUE.into(),
            ),
            (
                queue("root handle 2: tbf rate 1000kbit burst 32768 latency 5ms"),
                QUEUE.into(),
            ),
            // A queue anywhere but under our bucket, of a size the renderers never give, tuned,
            // or of another kind.
            (
                BUCKET.into(),
                queue("root handle 10: fq_codel memory_limit 131072"),
            ),
            (
                BUCKET.into(),
                queue("parent 1:2 handle 10: fq_codel memory_limit 131072"),
            ),
            (
                BUCKET.into(),
                queue("parent 1:1 handle 10: fq_codel memory_limit 4294967295"),
            ),
            (
                BUCKET.into(),
                queue("parent 1:1 handle 10: fq_codel memory_limit 1024"),
            ),
            (
                BUCKET.into(),
                queue("parent 1:1 handle 10: fq_codel memory_limit 32Mb"),
            ),
            (
                BUCKET.into(),
                queue("parent 1:1 handle 10: fq_codel memory_limit 131072 target 1s"),
            ),
            (
                BUCKET.into(),
                queue("parent 1:1 handle 10: netem delay 100ms"),
            ),
        ] {
            let refused =
                plan(&desired(&[ADD, &bucket, &queue]), &Observed::default()).unwrap_err();
            assert!(
                refused.starts_with("refusing to apply an unrecognised line"),
                "{bucket} / {queue}: {refused}"
            );
        }
    }
    #[test]
    fn public_gre_ingress_is_counted_once_and_only_for_the_assigned_address() {
        struct Counters;
        impl Runner for Counters {
            fn run(&mut self, argv: &[String], _: Option<&str>) -> Result<String> {
                assert_eq!(shell(argv), "nft -j list table inet scrubline");
                Ok(r#"{"nftables":[{"counter":{"name":"gre_in_c0000204","packets":20,"bytes":1600}},
                    {"counter":{"name":"gre_in_c0000205","packets":99,"bytes":9900}}]}"#.into())
            }
        }
        let mut desired = desired(&[ADD, SET]);
        let tunnel = &mut desired.tunnels[0];
        tunnel.r#type = "gre".into();
        tunnel.prefixes = vec!["192.0.2.4/32".into()];
        let pass = plan(&desired, &Observed::default()).unwrap();
        assert!(pass
            .nft
            .contains("type filter hook prerouting priority -450"));
        assert!(pass
            .nft
            .contains("ip daddr 192.0.2.4 ip protocol != { 4, 47 } counter name gre_in_c0000204"));
        let mut applied = Applied::default();
        let result = read_counters(&mut Counters, &pass, &applied, "generation")
            .unwrap()
            .ingress;
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].prefix, "192.0.2.4/32");
        assert_eq!(result[0].packets, 20);
        assert_eq!(result[0].bytes, 1600);
        applied
            .failed
            .insert("scr-nw".into(), "link is down".into());
        assert!(read_counters(&mut Counters, &pass, &applied, "generation")
            .unwrap()
            .ingress
            .is_empty());
    }

    #[test]
    fn gre_acl_keeps_asic_priority_and_counts_any_protocol_port_drops() {
        let mut d = desired(&[ADD, SET]);
        d.tunnels[0].r#type = "gre".into();
        d.tunnels[0].prefixes = vec!["192.0.2.4/32".into()];
        d.asic = vec![
            ACLEntry {
                priority: 50,
                action: "drop".into(),
                r#match: Match {
                    dst_cidr: "192.0.2.4/32".into(),
                    proto: "any".into(),
                    dport: 80,
                    dport_to: 80,
                    ..Default::default()
                },
                ..Default::default()
            },
            ACLEntry {
                priority: 10,
                action: "permit".into(),
                r#match: Match {
                    src_cidr: "198.51.100.5/32".into(),
                    proto: "tcp".into(),
                    dport: 80,
                    ..Default::default()
                },
                ..Default::default()
            },
        ];
        let pass = plan(&d, &Observed::default()).unwrap();
        let permit = pass
            .nft
            .find("ip saddr 198.51.100.5/32 meta l4proto tcp th dport 80 return")
            .unwrap();
        let drop = pass
            .nft
            .find("meta l4proto { tcp, udp } th dport 80 counter name gre_drop_c0000204 drop")
            .unwrap();
        assert!(permit < drop);
        assert_eq!(pass.drops["gre_drop_c0000204"].0, "192.0.2.4/32");

        d.asic[1].r#match.payload_hex = "ff".into();
        assert!(plan(&d, &Observed::default()).unwrap().drops.is_empty());
        d.asic[1].r#match.dst_cidr = "192.0.2.5/32".into();
        assert!(!plan(&d, &Observed::default()).unwrap().drops.is_empty());
        d.tunnels[0].mitigation = "on_demand".into();
        assert!(plan(&d, &Observed::default()).unwrap().drops.is_empty());
    }

    struct Fake {
        ran: Vec<String>,
        fail: &'static str,
    }
    impl Runner for Fake {
        fn run(&mut self, argv: &[String], stdin: Option<&str>) -> Result<String> {
            let line = shell(argv);
            self.ran.push(line.clone());
            if let Some(input) = stdin {
                self.ran.push(input.into());
            }
            if !self.fail.is_empty() && line.starts_with(self.fail) {
                return Err(format!("{line}: failed"));
            }
            Ok(String::new())
        }
    }
    #[test]
    fn a_tunnel_that_fails_to_build_is_reported_down_and_the_rules_load_once() {
        let d = desired(&[ADD, SET, ROUTE]);
        let pass = plan(&d, &Observed::default()).unwrap();
        let mut r = Fake {
            ran: vec![],
            fail: "ip link add scr-nw",
        };
        let mut last = String::new();
        let applied = apply(&mut r, &pass, &Observed::default(), &mut last);
        assert_eq!(
            report(&d, &applied)["tunnels"][0]["state"],
            "down",
            "{applied:?}"
        );
        assert_eq!(last, pass.nft, "the ruleset loaded");
        let loads = |r: &Fake| r.ran.iter().filter(|l| l.as_str() == "nft -f -").count();
        assert_eq!(loads(&r), 1);
        // Unchanged rules are not reloaded while the table is there, and are when it is not.
        let present = Observed {
            table: true,
            ..Default::default()
        };
        let mut r = Fake {
            ran: vec![],
            fail: "",
        };
        let applied = apply(&mut r, &pass, &present, &mut last);
        assert_eq!(loads(&r), 0);
        assert_eq!(report(&d, &applied)["tunnels"][0]["state"], "up");
        apply(&mut r, &pass, &Observed::default(), &mut last);
        assert_eq!(loads(&r), 1);
    }
    #[test]
    fn nothing_comes_up_without_its_filters() {
        let d = desired(&[ADD, SET, ROUTE]);
        let pass = plan(&d, &Observed::default()).unwrap();
        let mut r = Fake {
            ran: vec![],
            fail: "nft -f -",
        };
        let mut last = String::new();
        let applied = apply(&mut r, &pass, &Observed::default(), &mut last);
        assert_eq!(r.ran.first().map(String::as_str), Some("nft -f -"));
        assert!(
            r.ran.iter().all(|l| !l.starts_with("ip ")),
            "no link or route changes: {:?}",
            r.ran
        );
        assert!(last.is_empty(), "a failed load is tried again next pass");
        let row = &report(&d, &applied)["tunnels"][0];
        assert_eq!(row["state"], "down");
        assert!(
            row["detail"]
                .as_str()
                .unwrap()
                .starts_with("the tunnel firewall did not load"),
            "{row}"
        );
    }
    #[test]
    fn host_routes_compare_whichever_way_they_are_written() {
        assert_eq!(destination("198.51.100.7").unwrap(), "198.51.100.7/32");
        assert_eq!(destination("203.0.113.9/24").unwrap(), "203.0.113.0/24");
        assert_eq!(destination("2001:db8::1").unwrap(), "2001:db8::1/128");
        assert!(destination("default").is_none());
    }
}
