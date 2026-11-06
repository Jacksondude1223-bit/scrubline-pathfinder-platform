//! Bounded per-prefix history, fleet gauges, and attributed attack events.
use crate::model::Program;
use ipnet::IpNet;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    hash::{Hash, Hasher},
    sync::Arc,
};
pub fn stamp(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms)
        .unwrap()
        .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
}
pub fn n(v: &Value, k: &str) -> u64 {
    v[k].as_u64().unwrap_or(0)
}
pub fn rows<'a>(v: &'a Value, k: &str) -> &'a [Value] {
    v[k].as_array().map(Vec::as_slice).unwrap_or(&[])
}
#[derive(Default, Clone)]
struct Bucket {
    counts: [u64; 5],
    rates: [u64; 3],
    pulse: bool,
}
#[derive(Default, Clone)]
struct Gauge {
    rates: [u64; 3],
    pulse: bool,
    at: i64,
}
#[derive(Clone)]
struct Scope {
    prefixes: Vec<String>,
    stage: String,
    shared: bool,
}
#[derive(Default, Clone)]
struct Event {
    start: i64,
    end: Option<i64>,
    peak: u64,
    peak_drop: u64,
    flows: u64,
    dropped: u64,
    pulse: bool,
    vectors: BTreeMap<(String, String), Value>,
}
impl Event {
    fn render(&self, p: &str, now: i64) -> Value {
        let mut v = json!({"prefix":p,"started_at":stamp(self.start),"ongoing":self.end.is_none(),"seconds":(self.end.unwrap_or(now)-self.start).max(0)as f64/1000.0,"peak_pps":self.peak,"peak_dropped_pps":self.peak_drop,"dropped":self.dropped,"flows":self.flows,"pulse":self.pulse});
        if let Some(end) = self.end {
            v["ended_at"] = json!(stamp(end));
        }
        let mut vectors: Vec<_> = self.vectors.values().cloned().collect();
        vectors.sort_by(|a, b| {
            n(b, "dropped")
                .cmp(&n(a, "dropped"))
                .then_with(|| {
                    a["rule_id"]
                        .as_str()
                        .unwrap_or("")
                        .cmp(b["rule_id"].as_str().unwrap_or(""))
                })
                .then_with(|| {
                    a["filter_id"]
                        .as_str()
                        .unwrap_or("")
                        .cmp(b["filter_id"].as_str().unwrap_or(""))
                })
        });
        if !vectors.is_empty() {
            v["vectors"] = json!(vectors);
        }
        v
    }
}
#[derive(Default)]
struct Series {
    ring: BTreeMap<i64, Bucket>,
    gauges: HashMap<String, Gauge>,
    open: Option<Event>,
    past: Vec<Event>,
    clear: i64,
}
impl Series {
    fn fleet(&self, now: i64) -> ([u64; 3], bool, usize) {
        let (mut rates, mut pulse, mut nodes) = ([0u64; 3], false, 0);
        for g in self.gauges.values().filter(|g| now - g.at <= 30000) {
            // A node still reporting the prefix after withdrawing it carries none of its traffic.
            if g.rates[0] > 0 {
                nodes += 1;
            }
            for (i, r) in rates.iter_mut().enumerate() {
                *r = (*r).saturating_add(g.rates[i]);
            }
            pulse |= g.pulse;
        }
        (rates, pulse, nodes)
    }
    fn judge(&mut self, now: i64) {
        let (r, pulse, _) = self.fleet(now);
        let peak = r[2].max(r[0]);
        let b = self.ring.entry(now / 60000).or_default();
        b.rates[0] = b.rates[0].max(r[0]);
        b.rates[1] = b.rates[1].max(r[1]);
        b.rates[2] = b.rates[2].max(peak);
        b.pulse |= pulse;
        let under = pulse || r[1] >= 5000 && r[1] as f64 >= 0.25 * r[0] as f64;
        if under {
            self.clear = 0;
            let e = self.open.get_or_insert_with(|| Event {
                start: now,
                ..Default::default()
            });
            e.peak = e.peak.max(peak);
            e.peak_drop = e.peak_drop.max(r[1]);
            e.pulse |= pulse;
        } else if self.open.is_some() {
            if self.clear == 0 {
                self.clear = now;
            }
            if now - self.clear >= 120000 {
                let mut e = self.open.take().unwrap();
                e.end = Some(self.clear);
                self.past.push(e);
                if self.past.len() > 128 {
                    self.past.remove(0);
                }
                self.clear = 0;
            }
        }
    }
}
#[derive(Default)]
pub struct Collector {
    series: BTreeMap<String, Series>,
    prefix_counters: HashMap<(String, String), [u64; 5]>,
    rule_counters: HashMap<(String, String, bool), [u64; 5]>,
    nodes: HashMap<String, i64>,
    /// What the programs nodes last reported under protect, by fingerprint (see Attribution).
    attributions: HashMap<u64, Arc<Attribution>>,
}
/// Which prefixes a program protects, and which of them each of its rules and game filters can
/// act on. Every report from a node needs both, and working them out takes every rule against
/// every prefix, so it is done once for each program rather than for each report: on a large
/// policy it was most of what handling a heartbeat cost.
struct Attribution {
    prefixes: HashSet<String>,
    scopes: HashMap<(String, bool), Scope>,
}
/// The most programs worked out at once: nodes run one policy, compiled a little differently
/// for some of them.
const ATTRIBUTIONS_MAX: usize = 16;
impl Attribution {
    fn of(program: &Program) -> Self {
        let nets: Vec<_> = program
            .prefixes
            .iter()
            .map(|p| (p, p.parse::<IpNet>().ok()))
            .collect();
        let mut scopes = HashMap::new();
        for r in &program.asic {
            scopes.insert(
                (r.rule_id.clone(), false),
                scope(&r.r#match.dst_cidr, "asic", &nets),
            );
        }
        for r in &program.fpga {
            scopes.insert(
                (r.rule_id.clone(), false),
                scope(&r.r#match.dst_cidr, "fpga", &nets),
            );
        }
        for r in &program.zc {
            scopes.insert(
                (r.rule_id.clone(), false),
                scope(&r.r#match.dst_cidr, "zc", &nets),
            );
        }
        for g in &program.games {
            scopes.insert((g.id.clone(), true), scope(&g.dst_cidr, "zc", &nets));
        }
        Self {
            prefixes: program.prefixes.iter().cloned().collect(),
            scopes,
        }
    }
    /// What an attribution is worked out from, hashed.
    fn fingerprint(program: &Program) -> u64 {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        program.prefixes.hash(&mut h);
        for r in &program.asic {
            ("asic", &r.rule_id, &r.r#match.dst_cidr).hash(&mut h);
        }
        for r in &program.fpga {
            ("fpga", &r.rule_id, &r.r#match.dst_cidr).hash(&mut h);
        }
        for r in &program.zc {
            ("zc", &r.rule_id, &r.r#match.dst_cidr).hash(&mut h);
        }
        for g in &program.games {
            ("game", &g.id, &g.dst_cidr).hash(&mut h);
        }
        h.finish()
    }
}
/// The spacing series points actually have: a step rounded up to whole minutes, in milliseconds.
pub fn resolution(step: i64) -> i64 {
    ((step.max(1) + 59999) / 60000) * 60000
}
// History is kept per minute, so a window shorter than one still covers the current bucket. Without
// the floor the bucket range runs backwards, and a reversed BTreeMap range panics while the request
// holds the control-plane lock, poisoning it for every caller after.
fn minutes(span: i64) -> i64 {
    (span / 60000).max(1)
}
fn delta(a: u64, b: u64) -> u64 {
    if b < a {
        b
    } else {
        b - a
    }
}
fn scope(dst: &str, stage: &str, nets: &[(&String, Option<IpNet>)]) -> Scope {
    let target = dst.parse::<IpNet>().ok();
    let prefixes: Vec<_> = nets
        .iter()
        .filter(|(_, p)| {
            target.is_none()
                || p.is_some_and(|p| {
                    let t = target.unwrap();
                    p.contains(&t.addr()) || t.contains(&p.addr())
                })
        })
        .map(|(p, _)| (*p).clone())
        .collect();
    Scope {
        shared: prefixes.len() > 1,
        prefixes,
        stage: stage.into(),
    }
}
impl Collector {
    pub fn forget(&mut self, live: &HashSet<String>) {
        self.series.retain(|p, _| live.contains(p));
        self.prefix_counters.retain(|(_, p), _| live.contains(p));
        self.rule_counters.retain(|(_, id, _), _| {
            ["|crafted|", "|reflection|", "|protocol|", "|ack_flood|"]
                .into_iter()
                .chain(["|syn_flood|", "|fragment|", "|icmp|"])
                .find_map(|kind| id.strip_prefix(kind))
                .and_then(|rest| rest.split_once('|'))
                .is_none_or(|(_, p)| live.contains(p))
        });
    }
    /// Forgets a node that was retired: its gauges and the baselines its counters were read from.
    pub fn forget_node(&mut self, node: &str) {
        for s in self.series.values_mut() {
            s.gauges.remove(node);
        }
        self.prefix_counters.retain(|(n, _), _| n != node);
        self.rule_counters.retain(|(n, _, _), _| n != node);
        self.nodes.remove(node);
    }
    pub fn prefixes(&self) -> Vec<String> {
        self.series.keys().cloned().collect()
    }
    /// A report given as JSON, read as a heartbeat's would be.
    pub fn observe(&mut self, node: &str, stats: &Value, program: &Program, now: i64) {
        let stats: crate::wire::Stats = serde_json::from_value(stats.clone()).unwrap_or_default();
        self.observe_stats(node, &stats, program, now);
    }
    pub fn observe_stats(
        &mut self,
        node: &str,
        stats: &crate::wire::Stats,
        program: &Program,
        now: i64,
    ) {
        let key = Attribution::fingerprint(program);
        let attr = match self.attributions.get(&key) {
            Some(a) => a.clone(),
            None => {
                if self.attributions.len() >= ATTRIBUTIONS_MAX {
                    self.attributions.clear();
                }
                let a = Arc::new(Attribution::of(program));
                self.attributions.insert(key, a.clone());
                a
            }
        };
        self.nodes.insert(node.into(), now);
        let expired: HashSet<_> = self
            .nodes
            .iter()
            .filter(|(_, at)| now - **at > 300000)
            .map(|(n, _)| n.clone())
            .collect();
        // Only the gauges of a silent node expire. Its baselines stay: the agent keeps counting
        // while it cannot report, and a counter that only counts up survives reports being missed.
        self.nodes.retain(|n, _| !expired.contains(n));
        // Every report comes through here, so the day's history is trimmed from its old end
        // rather than walked whole.
        let oldest = now / 60000 - 1439;
        for s in self.series.values_mut() {
            if !expired.is_empty() {
                s.gauges.retain(|n, _| !expired.contains(n));
            }
            while s
                .ring
                .first_key_value()
                .is_some_and(|(minute, _)| *minute < oldest)
            {
                s.ring.pop_first();
            }
        }
        let mut touched = HashSet::new();
        let mut crafted = Vec::new();
        let mut guarded = Vec::new();
        for row in &stats.prefixes {
            let p = row.prefix.as_str();
            // Only what the node is programmed to protect: a row for a prefix just removed would
            // bring its series back, and arbitrary strings would fill the series cap.
            if p.is_empty()
                || !attr.prefixes.contains(p)
                || !self.series.contains_key(p) && self.series.len() >= 256
            {
                continue;
            }
            let s = self.series.entry(p.into()).or_default();
            touched.insert(p.to_string());
            let cur = [row.flows, row.flows_dropped, row.offered, row.dropped, 0];
            // A node's first report is only a baseline. Its counters run from agent start, so
            // counting them from zero after a control-plane restart, a failover or a node's return
            // would book its lifetime traffic into this minute.
            let seen = self.prefix_counters.insert((node.into(), p.into()), cur);
            // What the crafted-packet checks dropped for the prefix, by class. A node reports a
            // class only once it has dropped one, so one that first appears after the baseline
            // counts from zero. The prefix is the packets' destination: the drops are never
            // shared.
            for c in &row.crafted {
                let class = c.class.as_str();
                if !["stack", "protocol", "buffer"].contains(&class) {
                    continue;
                }
                let counts = [0, c.flows, 0, c.dropped, 0];
                let key = (node.into(), format!("|crafted|{class}|{p}"), false);
                let prev = self.rule_counters.insert(key, counts);
                if let Some(prev) = prev.or(seen.map(|_| [0; 5])) {
                    let diff = std::array::from_fn::<_, 5, _>(|i| delta(prev[i], counts[i]));
                    if diff[1] > 0 || diff[3] > 0 {
                        crafted.push((p.to_string(), class.to_string(), diff));
                    }
                }
            }
            // What the reflection, protocol, ACK and SYN flood, fragment and ICMP guards dropped for
            // the prefix, by what each names, the same way. Only names a guard has: a counter key
            // is made of them.
            let rows = row
                .reflection
                .iter()
                .filter(|r| crate::reflection::vector(&r.vector).is_some())
                .map(|r| ("reflection", r.vector.as_str(), r.flows, r.dropped))
                .chain(
                    row.protocols
                        .iter()
                        .filter(|r| r.protocol == "gre" || r.protocol == "other")
                        .map(|r| ("protocol", r.protocol.as_str(), r.flows, r.dropped)),
                )
                .chain(
                    row.ack_flood
                        .iter()
                        .map(|r| ("ack_flood", "tcp", r.flows, r.dropped)),
                )
                .chain(
                    row.syn_flood
                        .iter()
                        .map(|r| ("syn_flood", "tcp", r.flows, r.dropped)),
                )
                .chain(
                    row.fragments
                        .iter()
                        .filter(|r| crate::guards::FRAGMENTED.contains(&r.protocol.as_str()))
                        .map(|r| ("fragment", r.protocol.as_str(), r.flows, r.dropped)),
                )
                .chain(
                    row.icmp
                        .iter()
                        .filter(|r| crate::guards::ICMP_KINDS.contains(&r.kind.as_str()))
                        .map(|r| ("icmp", r.kind.as_str(), r.flows, r.dropped)),
                );
            for (kind, name, flows, dropped) in rows {
                let counts = [0, flows, 0, dropped, 0];
                let key = (node.into(), format!("|{kind}|{name}|{p}"), false);
                let prev = self.rule_counters.insert(key, counts);
                if let Some(prev) = prev.or(seen.map(|_| [0; 5])) {
                    let diff = std::array::from_fn::<_, 5, _>(|i| delta(prev[i], counts[i]));
                    if diff[1] > 0 || diff[3] > 0 {
                        guarded.push((p.to_string(), kind, name.to_string(), diff));
                    }
                }
            }
            if let Some(prev) = seen {
                let b = s.ring.entry(now / 60000).or_default();
                for i in 0..5 {
                    b.counts[i] = b.counts[i].saturating_add(delta(prev[i], cur[i]));
                }
            }
            s.gauges.insert(
                node.into(),
                Gauge {
                    rates: [row.offered_pps, row.dropped_pps, row.peak_pps],
                    pulse: row.pulsing,
                    at: now,
                },
            );
        }
        let mut moved = Vec::new();
        let rules = stats
            .rules
            .iter()
            .map(|r| (&r.rule_id, false, [0, r.drops, 0, r.pps_dropped, 0]));
        let games = stats.games.iter().map(|g| {
            let cur = [0, g.dropped, 0, g.pps_dropped, g.challenged];
            (&g.filter_id, true, cur)
        });
        for (id, filter, cur) in rules.chain(games) {
            let id = id.as_str();
            let Some(scope) = attr.scopes.get(&(id.into(), filter)) else {
                continue;
            };
            if scope.prefixes.is_empty() {
                continue;
            }
            let Some(prev) = self
                .rule_counters
                .insert((node.into(), id.into(), filter), cur)
            else {
                continue;
            };
            let diff = std::array::from_fn::<_, 5, _>(|i| delta(prev[i], cur[i]));
            if diff[1] == 0 && diff[3] == 0 && diff[4] == 0 {
                continue;
            }
            for p in &scope.prefixes {
                if let Some(s) = self.series.get_mut(p) {
                    // A challenge count shared by several prefixes cannot be split between
                    // them; booking it to each would double it and show one customer
                    // another's. The event vectors carry it, marked shared.
                    if !scope.shared {
                        let bucket = s.ring.entry(now / 60000).or_default();
                        bucket.counts[4] = bucket.counts[4].saturating_add(diff[4]);
                    }
                    touched.insert(p.clone());
                }
            }
            moved.push((id.to_owned(), filter, scope.clone(), diff));
        }
        // An open event is judged on every report, not only when its prefix is reported, or it
        // stays open forever once no node carries the prefix any more.
        for (p, s) in self.series.iter_mut() {
            if touched.contains(p) || s.open.is_some() {
                s.judge(now);
            }
        }
        let named = crafted
            .into_iter()
            .map(|(p, class, diff)| (p, "crafted", class, diff))
            .chain(guarded);
        for (p, kind, name, diff) in named {
            if let Some(e) = self.series.get_mut(&p).and_then(|s| s.open.as_mut()) {
                let key = (format!("|{kind}|{name}"), String::new());
                if !e.vectors.contains_key(&key) && e.vectors.len() >= 32 {
                    continue;
                }
                let v = e
                    .vectors
                    .entry(key)
                    .or_insert_with(|| json!({kind:name,"flows":0,"dropped":0}));
                v["flows"] = json!(n(v, "flows").saturating_add(diff[1]));
                v["dropped"] = json!(n(v, "dropped").saturating_add(diff[3]));
                e.flows = e.flows.saturating_add(diff[1]);
                e.dropped = e.dropped.saturating_add(diff[3]);
            }
        }
        for (id, filter, scope, diff) in moved {
            for p in scope.prefixes {
                if let Some(e) = self.series.get_mut(&p).and_then(|s| s.open.as_mut()) {
                    let key = if filter {
                        (String::new(), id.clone())
                    } else {
                        (id.clone(), String::new())
                    };
                    if !e.vectors.contains_key(&key) && e.vectors.len() >= 32 {
                        continue;
                    }
                    let v = e.vectors.entry(key).or_insert_with(|| {
                        let mut v = json!({"stage":scope.stage,"flows":0,"dropped":0});
                        v[if filter { "filter_id" } else { "rule_id" }] = json!(id);
                        if scope.shared {
                            v["shared"] = json!(true);
                        }
                        v
                    });
                    v["flows"] = json!(n(v, "flows").saturating_add(diff[1]));
                    v["dropped"] = json!(n(v, "dropped").saturating_add(diff[3]));
                    e.flows = e.flows.saturating_add(diff[1]);
                    e.dropped = e.dropped.saturating_add(diff[3]);
                }
            }
        }
    }
    pub fn events(&self, p: &str, span: i64, now: i64) -> Vec<Value> {
        let Some(s) = self.series.get(p) else {
            return vec![];
        };
        let mut out = Vec::new();
        if let Some(e) = &s.open {
            out.push(e.render(p, now));
        }
        out.extend(
            s.past
                .iter()
                .rev()
                .filter(|e| e.end.unwrap_or(now) >= now - span.clamp(1, 86400000))
                .map(|e| e.render(p, now)),
        );
        out
    }
    pub fn summary(&self, p: &str, span: i64, now: i64) -> Value {
        let span = span.clamp(1, 86400000);
        let mut count = [0u64; 5];
        let mut peak = 0;
        let mut peak_drop = 0;
        let mut pulse = false;
        let mut rates = [0; 3];
        let mut nodes = 0;
        let mut under = false;
        if let Some(s) = self.series.get(p) {
            let first = now / 60000 - minutes(span) + 1;
            for (_, b) in s.ring.range(first..=now / 60000) {
                for (i, c) in count.iter_mut().enumerate() {
                    *c = (*c).saturating_add(b.counts[i]);
                }
                peak = peak.max(b.rates[2]);
                peak_drop = peak_drop.max(b.rates[1]);
                pulse |= b.pulse;
            }
            let (r, _, n) = s.fleet(now);
            rates = r;
            nodes = n;
            under = s.open.is_some();
        }
        let events = self.events(p, span, now);
        json!({"prefix":p,"from":stamp((now-span).div_euclid(60000)*60000),"to":stamp(now),"flows":count[0],"flows_dropped":count[1],"offered":count[2],"dropped":count[3],"delivered":count[2].saturating_sub(count[3]),"challenged":count[4],"mitigated_pct":if count[2]>0{100.0*count[3]as f64/count[2]as f64}else{0.0},"peak_pps":peak,"peak_dropped_pps":peak_drop,"offered_pps":rates[0],"dropped_pps":rates[1],"nodes":nodes,"under_attack":under,"pulsing":pulse,"attacks":events.len(),"attack_seconds":events.iter().map(|e|e["seconds"].as_f64().unwrap_or(0.0)).sum::<f64>()})
    }
    pub fn points(&self, p: &str, span: i64, step: i64, now: i64) -> Vec<Value> {
        let per = resolution(step) / 60000;
        let last = now / 60000;
        let first = last - minutes(span.clamp(1, 86400000)) + 1;
        let first = first - first.rem_euclid(per);
        let mut out = Vec::new();
        let mut start = first;
        while start <= last {
            let (mut c, mut r, mut pulse) = ([0u64; 5], [0u64; 3], false);
            if let Some(s) = self.series.get(p) {
                for (_, b) in s.ring.range(start..=(start + per - 1).min(last)) {
                    for (i, value) in c.iter_mut().enumerate() {
                        *value = (*value).saturating_add(b.counts[i]);
                    }
                    for (i, value) in r.iter_mut().enumerate() {
                        *value = (*value).max(b.rates[i]);
                    }
                    pulse |= b.pulse;
                }
            }
            out.push(json!({"at":stamp(start*60000),"flows":c[0],"flows_dropped":c[1],"offered":c[2],"dropped":c[3],"delivered":c[2].saturating_sub(c[3]),"challenged":c[4],"peak_pps":r[2],"offered_pps":r[0],"dropped_pps":r[1],"pulsing":pulse}));
            start += per;
        }
        out
    }
}
