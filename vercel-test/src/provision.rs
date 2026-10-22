//! The node provisioner: puts what a node's agent says its tunnels should be onto the box (the
//! interfaces, routes, firewall and shapers) and reports back which customer tunnels it built.
//!
//! The agent compiles and serves; this is the part that changes the box, so it runs privileged
//! and apart from the agent. Each pass reconciles the box with the agent's rendered configuration
//! rather than replaying it, so it can run every few seconds without piling up duplicates, and
//! it removes what the agent no longer asks for.
use crate::{model::NodeTunnel, Result};
use ipnet::IpNet;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

/// What the agent serves at `GET /tunnels`.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Desired {
    pub tunnels: Vec<NodeTunnel>,
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
    /// The token-bucket rate on each interface that has one, in bytes per second.
    pub shapers: BTreeMap<String, u64>,
    /// Whether the `inet scrubline` table exists.
    pub table: bool,
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
\tchain forward {
\t\ttype filter hook forward priority 0; policy accept;
\t}
\tchain input {
\t\ttype filter hook input priority 0; policy accept;
\t}
}
";

/// Works out a pass. It refuses a line it does not recognise rather than guess at it: these are
/// commands run as root.
pub fn plan(desired: &Desired, observed: &Observed) -> Result<Pass> {
    let mut adds: BTreeMap<String, &str> = BTreeMap::new();
    let mut sets = Vec::new();
    let mut routes: BTreeMap<(String, String), &str> = BTreeMap::new();
    let mut shapers = Vec::new();
    let mut nft = String::from(TABLE);
    for line in desired.lines.iter().map(|l| l.trim()) {
        let words: Vec<&str> = line.split_whitespace().collect();
        match words.as_slice() {
            [] => {}
            [first, ..] if first.starts_with('#') => {}
            ["ip", "link", "add", name, "type", ..] if ours(name) => {
                adds.insert(name.to_string(), line);
            }
            ["ip", "link", "set", name, "mtu", _, "up"] if ours(name) => sets.push((*name, line)),
            ["ip", "route", "replace", dst, "dev", name] if ours(name) => {
                let dst = destination(dst).ok_or_else(|| format!("unreadable route {line:?}"))?;
                routes.insert((dst, name.to_string()), line);
            }
            ["nft", "add", "rule", "inet", "scrubline", ..] => {
                nft.push_str(&line[4..]);
                nft.push('\n');
            }
            ["tc", "qdisc", "replace", "dev", name, "root", "tbf", "rate", rate, ..]
                if ours(name) =>
            {
                let kbit: u64 = rate
                    .strip_suffix("kbit")
                    .and_then(|v| v.parse().ok())
                    .ok_or_else(|| format!("unreadable shaper {line:?}"))?;
                shapers.push((*name, kbit * 125, line));
            }
            _ => return Err(format!("refusing to apply an unrecognised line: {line:?}")),
        }
    }
    let mut pass = Pass::default();
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
    for (name, rate, line) in shapers {
        if rebuilt.contains(name) || observed.shapers.get(name) != Some(&rate) {
            pass.steps.push(step(line, name));
        }
    }
    pass.nft = nft;
    Ok(pass)
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
    for q in json_rows(&r.run(&words("tc -j qdisc show"), None)?)? {
        let dev = q["dev"].as_str().unwrap_or_default();
        if ours(dev) && q["kind"] == "tbf" && q["root"] == true {
            if let Some(rate) = q["options"]["rate"].as_u64() {
                o.shapers.insert(dev.into(), rate);
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
    pub errors: Vec<String>,
}

/// Applies a pass, loading the ruleset when it differs from the last one loaded or the table has
/// gone. A failure is recorded against its interface and the pass carries on, so one bad tunnel
/// does not hold up the others.
pub fn apply(
    r: &mut impl Runner,
    pass: &Pass,
    observed: &Observed,
    last_nft: &mut String,
) -> Applied {
    let mut out = Applied::default();
    for s in &pass.steps {
        if let Err(e) = r.run(&s.argv, None) {
            match &s.link {
                Some(link) => {
                    out.failed.entry(link.clone()).or_insert(e);
                }
                None => out.errors.push(e),
            }
        }
    }
    if pass.nft != *last_nft || !observed.table {
        let load = ["nft", "-f", "-"].map(String::from);
        match r.run(&load, Some(&pass.nft)) {
            Ok(_) => *last_nft = pass.nft.clone(),
            Err(e) => out.errors.push(e),
        }
    }
    out
}

/// What to tell the agent about each customer tunnel: built, or why not. Built is all it can
/// say; whether the customer's end answers is theirs to know.
pub fn report(desired: &Desired, applied: &Applied) -> Value {
    let rows: Vec<Value> = desired
        .tunnels
        .iter()
        .map(|t| match applied.failed.get(&t.interface) {
            None => json!({"tunnel_id":t.id,"state":"up"}),
            Some(e) => json!({"tunnel_id":t.id,"state":"down","detail":e}),
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
    const SHAPE: &str =
        "tc qdisc replace dev scr-nw root tbf rate 1000000kbit burst 1250000 latency 50ms";
    #[test]
    fn a_fresh_box_gets_everything() {
        let d = desired(&[
            "# Northwind",
            ADD,
            SET,
            ROUTE,
            "nft add rule inet scrubline forward oifname \"scr-nw\" tcp flags syn tcp option maxseg size set 1432",
            SHAPE,
        ]);
        let pass = plan(&d, &Observed::default()).unwrap();
        assert_eq!(
            shown(&pass),
            [
                ADD.to_string(),
                format!("ip link set dev scr-nw alias '{ADD}'"),
                SET.into(),
                ROUTE.into(),
                SHAPE.into(),
            ]
        );
        assert!(pass.nft.starts_with(TABLE));
        assert!(pass
            .nft
            .ends_with("add rule inet scrubline forward oifname \"scr-nw\" tcp flags syn tcp option maxseg size set 1432\n"));
    }
    #[test]
    fn a_box_already_in_step_is_left_alone() {
        let d = desired(&[ADD, SET, ROUTE, SHAPE]);
        let o = Observed {
            links: BTreeMap::from([("scr-nw".into(), ADD.into())]),
            routes: BTreeSet::from([("203.0.113.0/24".into(), "scr-nw".into())]),
            shapers: BTreeMap::from([("scr-nw".into(), 125_000_000)]),
            table: true,
        };
        // Only the idempotent settings are reasserted: nothing is rebuilt or reshaped.
        assert_eq!(shown(&plan(&d, &o).unwrap()), [SET, ROUTE]);
    }
    #[test]
    fn changed_or_unwanted_tunnels_and_routes_go() {
        let moved = "ip link add scr-nw type gre local 192.0.2.1 remote 198.51.100.9 key 42";
        let d = desired(&[moved, SET, ROUTE, SHAPE]);
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
            shapers: BTreeMap::from([("scr-nw".into(), 125_000_000)]),
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
                SHAPE.into(),
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
            "ip route replace 0.0.0.0/0 dev eth0",
            "nft flush ruleset",
            "rm -rf /",
            "tc qdisc del dev scr-nw root",
        ] {
            assert!(
                plan(&desired(&[line]), &Observed::default()).is_err(),
                "{line}"
            );
        }
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
    fn host_routes_compare_whichever_way_they_are_written() {
        assert_eq!(destination("198.51.100.7").unwrap(), "198.51.100.7/32");
        assert_eq!(destination("203.0.113.9/24").unwrap(), "203.0.113.0/24");
        assert_eq!(destination("2001:db8::1").unwrap(), "2001:db8::1/128");
        assert!(destination("default").is_none());
    }
}
