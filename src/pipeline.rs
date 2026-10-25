//! Serialized per-node packet decisions and bounded counters/state.
use crate::{
    gamefilter, ml,
    model::*,
    state::{Egress, Pulse, Reputation},
};
use ipnet::IpNet;
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
};
#[derive(Clone)]
struct Matcher {
    m: Match,
    src: Option<IpNet>,
    dst: Option<IpNet>,
    never: bool,
}
impl Matcher {
    fn new(m: Match) -> Self {
        let src = m.src_cidr.parse().ok();
        let dst = m.dst_cidr.parse().ok();
        let never =
            !m.src_cidr.is_empty() && src.is_none() || !m.dst_cidr.is_empty() && dst.is_none();
        Self { m, src, dst, never }
    }
    fn matches(&self, f: &Flow) -> bool {
        !self.never
            && self
                .src
                .is_none_or(|p| f.src_ip.parse::<IpAddr>().is_ok_and(|a| p.contains(&a)))
            && self
                .dst
                .is_none_or(|p| f.dst_ip.parse::<IpAddr>().is_ok_and(|a| p.contains(&a)))
            && (self.m.proto.is_empty()
                || self.m.proto.eq_ignore_ascii_case("any")
                || self.m.proto.eq_ignore_ascii_case(&f.proto))
            && (self.m.dport == 0 || self.m.dport == f.dport)
            && (self.m.sport == 0 || self.m.sport == f.sport)
            && (self.m.tcp_flags.is_empty() || self.m.tcp_flags.eq_ignore_ascii_case(&f.flags))
    }
}
#[derive(Clone)]
struct Entry {
    matcher: Matcher,
    action: String,
    id: String,
    limit: i64,
}
#[derive(Default)]
struct Rate {
    slots: [i64; 4],
    count: [i64; 4],
}
#[derive(Default, Clone)]
struct Load {
    slots: [i64; 10],
    offered: [u64; 10],
    dropped: [u64; 10],
    flows: u64,
    flows_dropped: u64,
    total: u64,
    total_dropped: u64,
}
impl Load {
    fn observe(&mut self, now: i64, pps: u64, dropped: bool) {
        let sec = now / 1000;
        let i = sec.rem_euclid(10) as usize;
        if self.slots[i] != sec {
            self.slots[i] = sec;
            self.offered[i] = 0;
            self.dropped[i] = 0;
        }
        self.offered[i] = self.offered[i].saturating_add(pps);
        self.flows += 1;
        self.total = self.total.saturating_add(pps);
        if dropped {
            self.dropped[i] = self.dropped[i].saturating_add(pps);
            self.flows_dropped += 1;
            self.total_dropped = self.total_dropped.saturating_add(pps);
        }
    }
    fn rates(&self, now: i64) -> (u64, u64) {
        let sec = now / 1000;
        let mut o = 0u64;
        let mut d = 0u64;
        for i in 0..10 {
            if self.slots[i] >= sec - 9 && self.slots[i] <= sec {
                o = o.saturating_add(self.offered[i]);
                d = d.saturating_add(self.dropped[i]);
            }
        }
        (o / 10, d / 10)
    }
    /// The rate over the one second up to `now`: this second's so far, and the part of the last
    /// second's that a window ending now still covers. A flood shows in it within a second, where
    /// the ten-second mean takes ten to show it in full.
    fn surge(&self, now: i64) -> u64 {
        let sec = now / 1000;
        let offered = |s: i64| {
            let i = s.rem_euclid(10) as usize;
            if self.slots[i] == s {
                self.offered[i]
            } else {
                0
            }
        };
        let covered = (1000 - now.rem_euclid(1000)) as u128;
        offered(sec).saturating_add((offered(sec - 1) as u128 * covered / 1000) as u64)
    }
}
pub struct Pipeline {
    pub program: Program,
    pub model: ml::Model,
    rules: [Vec<Entry>; 3],
    prefixes: Vec<(String, IpNet)>,
    buckets: HashMap<(String, String), Rate>,
    last_sweep: i64,
    rule_stats: HashMap<String, (String, [u64; 4])>,
    /// Per filter: inspected, dropped, challenged, uninspectable, pps dropped, then for its HTTP
    /// rules requests judged, requests dropped, requests over a rate, and segments with none.
    game_stats: HashMap<String, (String, [u64; 9])>,
    stages: [[u64; 4]; 3],
    decisions: u64,
    unowned: u64,
    /// The flow model: flows scored, dropped, passed, and over its threshold but only observed.
    ml_counts: [u64; 4],
    /// The request model: requests scored, segments it dropped, and segments it would have.
    http_counts: [u64; 3],
    /// Where the classifiers run and whether they drop, from the program.
    ml: MlPolicy,
    returns: [u64; 3],
    games: gamefilter::Engine,
    pulses: Pulse,
    pub reputation: Reputation,
    egress: Egress,
    load: Load,
    loads: HashMap<String, Load>,
    lockdown: String,
    lockdown_pps: i64,
    grace: i64,
}
fn decision(action: &str, stage: usize, id: &str, reason: impl Into<String>) -> Decision {
    Decision {
        action: action.into(),
        stage: ["asic", "fpga", "zc"][stage].into(),
        rule_id: id.into(),
        reason: reason.into(),
        ..Default::default()
    }
}
impl Pipeline {
    pub fn new(program: Program) -> Self {
        let mut p = Self {
            program: Program::default(),
            model: ml::Model::default(),
            rules: Default::default(),
            prefixes: vec![],
            buckets: HashMap::new(),
            last_sweep: 0,
            rule_stats: HashMap::new(),
            game_stats: HashMap::new(),
            stages: [[0; 4]; 3],
            decisions: 0,
            unowned: 0,
            ml_counts: [0; 4],
            http_counts: [0; 3],
            ml: MlPolicy::default(),
            returns: [0; 3],
            games: Default::default(),
            pulses: Default::default(),
            reputation: Reputation::default(),
            egress: Egress::default(),
            load: Default::default(),
            loads: HashMap::new(),
            lockdown: "off".into(),
            lockdown_pps: 500,
            grace: 500,
        };
        p.load(program);
        p
    }
    pub fn load(&mut self, program: Program) {
        self.prefixes = program
            .prefixes
            .iter()
            .filter_map(|p| p.parse::<IpNet>().ok().map(|net| (p.clone(), net)))
            .collect();
        // Lookups take the first match, so the most specific prefix has to come first or a /24
        // inside a protected /22 is counted, pulse-tracked and confirmed under the /22.
        self.prefixes
            .sort_by_key(|(_, net)| std::cmp::Reverse(net.prefix_len()));
        let live: HashSet<_> = program.prefixes.iter().cloned().collect();
        self.loads.retain(|p, _| live.contains(p));
        for prefix in &program.prefixes {
            self.loads.entry(prefix.clone()).or_default();
        }
        self.pulses.forget(&live);
        self.egress.forget(&live);
        // Zero is the platform default, so a policy that drops its floor must clear the old one.
        self.pulses.floor = program.pulse_floor_pps.max(0) as u64;
        self.rules = [
            program
                .asic
                .iter()
                .map(|r| Entry {
                    matcher: Matcher::new(r.r#match.clone()),
                    action: r.action.clone(),
                    id: r.rule_id.clone(),
                    limit: 0,
                })
                .collect(),
            program
                .fpga
                .iter()
                .map(|r| Entry {
                    matcher: Matcher::new(r.r#match.clone()),
                    action: r.action.clone(),
                    id: r.rule_id.clone(),
                    limit: r.meter_pps,
                })
                .collect(),
            program
                .zc
                .iter()
                .map(|r| Entry {
                    matcher: Matcher::new(r.r#match.clone()),
                    action: r.action.clone(),
                    id: r.rule_id.clone(),
                    limit: r.pps,
                })
                .collect(),
        ];
        let bucket_live: HashSet<_> = program.zc.iter().map(|r| r.rule_id.clone()).collect();
        self.buckets.retain(|(r, _), _| bucket_live.contains(r));
        let mut stats = HashMap::new();
        for (i, rules) in self.rules.iter().enumerate() {
            for r in rules {
                let stage = ["asic", "fpga", "zc"][i];
                let old = self
                    .rule_stats
                    .get(&r.id)
                    .filter(|(s, _)| s == stage)
                    .cloned()
                    .unwrap_or((stage.into(), [0; 4]));
                stats.entry(r.id.clone()).or_insert(old);
            }
        }
        self.rule_stats = stats;
        let bindings = gamefilter::compile(&program.games).unwrap_or_else(|e| {
            eprintln!("pipeline: invalid game filters: {e}");
            vec![]
        });
        let mut stats = HashMap::new();
        for b in &bindings {
            let old = self
                .game_stats
                .get(&b.id)
                .filter(|(name, _)| name == &b.profile.name)
                .cloned()
                .unwrap_or((b.profile.name.clone(), [0; 9]));
            stats.insert(b.id.clone(), old);
        }
        self.game_stats = stats;
        self.games.load(bindings, &program.challenge_secret);
        self.reputation.proof = match program
            .reputation
            .as_ref()
            .map(|r| r.fast_pass.as_str())
            .unwrap_or("")
        {
            "handshake" => 1,
            "egress" => 2,
            _ => 3,
        };
        self.reputation.no_fast = program
            .reputation
            .as_ref()
            .is_some_and(|r| r.fast_pass == "off");
        self.reputation.boxing = program.reputation.as_ref().is_some_and(|r| r.penalty_box);
        self.lockdown = "off".into();
        self.lockdown_pps = 500;
        self.grace = 500;
        if let Some(e) = &program.egress {
            if e.lockdown == "drop" || e.lockdown == "limit" {
                self.lockdown = e.lockdown.clone();
            }
            if e.lockdown_pps > 0 {
                self.lockdown_pps = e.lockdown_pps;
            }
            if e.grace_millis > 0 {
                self.grace = e.grace_millis;
            }
        }
        self.ml = program.ml.clone().unwrap_or_default();
        self.program = program;
    }
    fn over_rate(&mut self, id: &str, limit: i64, f: &Flow, now: i64) -> bool {
        if limit <= 0 {
            return false;
        }
        let key = (id.into(), f.src_ip.clone());
        let slot = now / 250;
        if !self.buckets.contains_key(&key) && self.buckets.len() >= 65536 {
            if now - self.last_sweep < 1000 {
                return false;
            }
            self.last_sweep = now;
            self.buckets
                .retain(|_, b| b.slots.iter().any(|at| *at >= slot - 3));
            if self.buckets.len() >= 65536 {
                return false;
            }
        }
        let b = self.buckets.entry(key).or_default();
        let i = slot.rem_euclid(4) as usize;
        if b.slots[i] != slot {
            b.slots[i] = slot;
            b.count[i] = 0;
        }
        b.count[i] = b.count[i].saturating_add(f.pps);
        b.count
            .iter()
            .zip(b.slots)
            .filter(|(_, at)| *at >= slot - 3 && *at <= slot)
            .fold(0i64, |n, (v, _)| n.saturating_add(*v))
            > limit
    }
    fn seen(&mut self, id: &str, f: &Flow) {
        if let Some((_, s)) = self.rule_stats.get_mut(id) {
            s[0] += 1;
            s[2] = s[2].saturating_add(f.pps.max(0) as u64);
        }
    }
    fn record(&mut self, d: &Decision, id: Option<&str>, f: &Flow) {
        let i = match d.stage.as_str() {
            "fpga" => 1,
            "zc" => 2,
            _ => 0,
        };
        let pps = f.pps.max(0) as u64;
        if d.action == "drop" || d.action == "challenge" {
            self.stages[i][0] += 1;
            self.stages[i][2] = self.stages[i][2].saturating_add(pps);
            if let Some(id) = id {
                if let Some((_, s)) = self.rule_stats.get_mut(id) {
                    s[1] += 1;
                    s[3] = s[3].saturating_add(pps);
                }
            }
        } else {
            self.stages[i][1] += 1;
            self.stages[i][3] = self.stages[i][3].saturating_add(pps);
        }
    }
    fn inspect_game(&mut self, f: &Flow, now: i64, trusted: bool) -> Option<Decision> {
        let everywhere = self.ml.everywhere();
        let model = self.model.http.as_deref().filter(|m| m.ready && everywhere);
        let r = self
            .games
            .inspect(f, now, trusted, model, self.ml.enforcing());
        self.http_counts[0] += r.scored;
        self.http_counts[1] += u64::from(r.classified);
        self.http_counts[2] += u64::from(r.observed);
        if r.filter.is_empty() {
            return None;
        }
        if trusted && r.verdict != "drop" {
            return None;
        }
        if let Some((_, s)) = self.game_stats.get_mut(&r.filter) {
            s[0] += 1;
            match r.verdict.as_str() {
                "drop" => {
                    s[1] += 1;
                    s[4] = s[4].saturating_add(f.pps.max(0) as u64);
                    s[6] += r.requests;
                    s[7] += u64::from(r.limited);
                }
                "challenge" => s[2] += 1,
                "uninspectable" => s[3] += 1,
                _ => {}
            }
            s[5] += r.requests;
            s[8] += u64::from(r.other);
        }
        if r.cleared > 0 {
            self.reputation.promote(&f.src_ip, r.cleared, now);
        }
        if r.verdict == "drop" {
            self.reputation.strike(&f.src_ip, now);
        }
        if r.verdict == "drop" || r.verdict == "challenge" {
            let mut d = decision(
                &r.verdict,
                2,
                "",
                format!("game filter {}: {}", r.profile, r.reason),
            );
            d.filter = r.filter;
            d.reply = r.reply;
            if r.classified {
                d.score = r.score;
            }
            return Some(d);
        }
        None
    }
    /// The flow model's verdict, if it is published: a drop at its threshold, unless the policy
    /// only observes, or a pass.
    fn classify(&mut self, f: &Flow, now: i64, rule: &str) -> Option<Decision> {
        if !self.model.ready {
            return None;
        }
        let score = ml::score(&self.model, f);
        let over = score >= self.model.threshold;
        let drop = over && self.ml.enforcing();
        self.ml_counts[0] += 1;
        self.ml_counts[if drop {
            1
        } else if over {
            3
        } else {
            2
        }] += 1;
        if drop {
            self.reputation.strike(&f.src_ip, now);
        }
        let mut d = decision(
            if drop { "drop" } else { "permit" },
            2,
            rule,
            if drop {
                format!("PF_RING ZC ml score {score:.2}")
            } else if over {
                format!("PF_RING ZC ml score {score:.2}, observed only")
            } else {
                "PF_RING ZC ml pass".into()
            },
        );
        d.score = score;
        Some(d)
    }
    fn evaluate(&mut self, f: &Flow, now: i64, trusted: bool) -> (Decision, Option<String>) {
        for stage in 0..3 {
            if stage == 2 {
                if let Some(d) = self.inspect_game(f, now, trusted) {
                    return (d, None);
                }
            }
            for i in 0..self.rules[stage].len() {
                if !self.rules[stage][i].matcher.matches(f) {
                    continue;
                }
                let r = self.rules[stage][i].clone();
                if trusted {
                    // Trust skips the challenge and the classifier, nothing else. A count is still
                    // observe-only and the behavioural cap still applies, so a match that decides
                    // nothing must not end the stage and hide the rules behind it.
                    self.seen(&r.id, f);
                    if r.action == "drop" {
                        return (
                            decision(
                                "drop",
                                stage,
                                &r.id,
                                ["TCAM ACL drop", "FPGA drop", "PF_RING ZC drop"][stage],
                            ),
                            None,
                        );
                    }
                    if r.action == "permit" {
                        break;
                    }
                    if r.limit > 0 && self.over_rate(&r.id, r.limit, f, now) {
                        return (
                            decision(
                                "drop",
                                stage,
                                &r.id,
                                if stage == 1 {
                                    format!("FPGA meter {} pps exceeded", r.limit)
                                } else {
                                    format!("PF_RING ZC behavioral cap {} pps exceeded", r.limit)
                                },
                            ),
                            None,
                        );
                    }
                    // A ZC inspect or rate_limit that passes its cap ends evaluation, as it does
                    // for everyone else; the classifier it would have consulted next is skipped.
                    if stage == 2 && r.action != "count" {
                        break;
                    }
                    continue;
                }
                self.seen(&r.id, f);
                let id = Some(r.id.clone());
                if r.action == "drop" || r.action == "permit" {
                    return (
                        decision(
                            &r.action,
                            stage,
                            &r.id,
                            format!("{} {}", ["TCAM ACL", "FPGA", "PF_RING ZC"][stage], r.action),
                        ),
                        id,
                    );
                }
                if stage == 1 && r.action == "rate_limit" && r.limit > 0 && f.pps > r.limit {
                    return (
                        decision(
                            "drop",
                            1,
                            &r.id,
                            format!("FPGA meter {} pps exceeded", r.limit),
                        ),
                        id,
                    );
                }
                if stage < 2 || r.action == "count" {
                    continue;
                }
                if r.limit > 0 && self.over_rate(&r.id, r.limit, f, now) {
                    self.reputation.strike(&f.src_ip, now);
                    return (
                        decision(
                            "drop",
                            2,
                            &r.id,
                            format!("PF_RING ZC behavioral cap {} pps exceeded", r.limit),
                        ),
                        id,
                    );
                }
                if let Some(d) = self.classify(f, now, &r.id) {
                    return (d, id);
                }
                return (decision("permit", 2, &r.id, "PF_RING ZC inspect pass"), id);
            }
        }
        // Under scope all the flow model has the last word on whatever the stages let through:
        // what a game filter or the HTTP rules passed, and what no rule decided. A permit rule,
        // which ends evaluation, and a verified source skip it.
        if !trusted && self.ml.everywhere() {
            if let Some(d) = self.classify(f, now, "") {
                return (d, None);
            }
        }
        (
            if trusted {
                decision("permit", 2, "", "verified source, fast path")
            } else {
                decision("permit", 0, "", "no matching drop rule")
            },
            None,
        )
    }
    pub fn decide(&mut self, f: &Flow, now: i64) -> Decision {
        self.decisions += 1;
        let pps = f.pps.max(0) as u64;
        let owner = f.dst_ip.parse::<IpAddr>().ok().and_then(|a| {
            self.prefixes
                .iter()
                .find(|(_, p)| p.contains(&a))
                .map(|(s, _)| s.clone())
        });
        let Some(owner) = owner else {
            self.unowned += 1;
            self.load.observe(now, pps, false);
            return decision("permit", 0, "", "prefix not assigned to this node");
        };
        self.pulses.observe(&owner, pps, now);
        if self.lockdown != "off" {
            self.egress.ingress(&owner, now);
        }
        let state = self.reputation.check(&f.src_ip, now);
        let (d, by) = if state == 2 {
            (
                decision("drop", 0, "", "source is in the penalty box"),
                None,
            )
        } else if state == 1 {
            self.evaluate(f, now, true)
        } else {
            let held = self.lockdown != "off"
                && self.pulses.assess(&owner, now)["pulsing"]
                    .as_bool()
                    .unwrap_or(false)
                && self.egress.visibility(&owner, now) == "visible"
                && !self.egress.confirmed(&owner, &f.src_ip, now)
                && !self.egress.grace(&owner, &f.src_ip, self.grace, now);
            if held {
                self.returns[2] += 1;
            }
            if held
                && (self.lockdown == "drop"
                    || self.over_rate("|lockdown", self.lockdown_pps, f, now))
            {
                (
                    decision(
                        "drop",
                        2,
                        "",
                        "no return traffic confirms this source while the prefix is under attack",
                    ),
                    None,
                )
            } else {
                self.evaluate(f, now, false)
            }
        };
        self.record(&d, by.as_deref(), f);
        let mitigated = d.action == "drop" || d.action == "challenge";
        self.load.observe(now, pps, mitigated);
        self.loads
            .entry(owner)
            .or_default()
            .observe(now, pps, mitigated);
        d
    }
    pub fn observe_return(&mut self, f: &Flow, now: i64) {
        let prefix = f.src_ip.parse::<IpAddr>().ok().and_then(|a| {
            self.prefixes
                .iter()
                .find(|(_, p)| p.contains(&a))
                .map(|(s, _)| s.clone())
        });
        if let Some(prefix) = prefix {
            self.returns[0] += 1;
            // Every confirmation renews trust, not only the first: a client the origin keeps
            // answering would otherwise lose its fast path five minutes into the conversation.
            if let Some(fresh) = self
                .egress
                .observe_return(&prefix, &f.dst_ip, f.pps.max(1), now)
            {
                self.reputation.promote(&f.dst_ip, 2, now);
                if fresh {
                    self.returns[1] += 1;
                }
            }
        }
    }
    /// The node's packet rate over the last second, where offered_pps is over the last ten.
    pub fn surge(&self, now: i64) -> u64 {
        self.load.surge(now)
    }
    pub fn stats(&mut self, now: i64) -> Value {
        let (o, d) = self.load.rates(now);
        let stages:Vec<_>=self.stages.iter().enumerate().map(|(i,s)|json!({"stage":(["asic","fpga","zc"][i]),"dropped":s[0],"permitted":s[1],"pps_dropped":s[2],"pps_permitted":s[3]})).collect();
        let mut rules:Vec<_>=self.rule_stats.iter().map(|(id,(stage,s))|json!({"rule_id":id,"stage":stage,"matches":s[0],"drops":s[1],"pps_seen":s[2],"pps_dropped":s[3]})).collect();
        rules.sort_by(|a, b| a["rule_id"].as_str().cmp(&b["rule_id"].as_str()));
        let mut games:Vec<_>=self.game_stats.iter().map(|(id,(profile,s))|json!({"filter_id":id,"profile":profile,"inspected":s[0],"dropped":s[1],"challenged":s[2],"uninspectable":s[3],"pps_dropped":s[4],"http_requests":s[5],"http_dropped":s[6],"http_rate_limited":s[7],"http_other":s[8]})).collect();
        games.sort_by(|a, b| a["filter_id"].as_str().cmp(&b["filter_id"].as_str()));
        let mut pulsing = false;
        let mut peak = 0;
        let mut prefixes = Vec::new();
        for (prefix, l) in &self.loads {
            let a = self.pulses.assess(prefix, now);
            let (o, d) = l.rates(now);
            if a["pulsing"] == true {
                pulsing = true;
                peak = peak.max(a["peak_pps"].as_u64().unwrap_or(0));
            }
            prefixes.push(json!({"prefix":prefix,"flows":l.flows,"flows_dropped":l.flows_dropped,"offered":l.total,"dropped":l.total_dropped,"offered_pps":o,"dropped_pps":d,"pulsing":a["pulsing"],"peak_pps":a["peak_pps"],"mean_pps":a["mean_pps"],"crest":a["crest"],"duty_cycle":a["duty_cycle"],"bursts":a["bursts"],"held_for_seconds":a["held_for"].as_f64().unwrap_or(0.0)/1e9}));
        }
        prefixes.sort_by(|a, b| a["prefix"].as_str().cmp(&b["prefix"].as_str()));
        let mut egress = self.egress.stats(now);
        egress["seen"] = json!(self.returns[0]);
        egress["promoted"] = json!(self.returns[1]);
        egress["locked_down"] = json!(self.returns[2]);
        egress["lockdown"] = json!(self.lockdown);
        let states = self.egress.prefixes(now);
        if states.as_array().is_some_and(|a| !a.is_empty()) {
            egress["prefix_states"] = states;
        }
        json!({"decisions":self.decisions,"unowned":self.unowned,"stages":stages,"rules":rules,"games":if games.is_empty(){Value::Null}else{json!(games)},"prefixes":if prefixes.is_empty(){Value::Null}else{json!(prefixes)},"ml":{"ready":self.model.ready,"scored":self.ml_counts[0],"drops":self.ml_counts[1],"passes":self.ml_counts[2],"observed":self.ml_counts[3],"http_ready":self.model.http.as_ref().is_some_and(|h|h.ready),"http_scored":self.http_counts[0],"http_drops":self.http_counts[1],"http_observed":self.http_counts[2],"scope":if self.ml.everywhere(){"all"}else{"inspect"},"mode":if self.ml.enforcing(){"enforce"}else{"observe"}},"pulsing":pulsing,"pulse_peak_pps":peak,"game_sessions":self.games.sessions(),"game_sessions_max":65536,"game_http_windows":self.games.windows(),"game_http_windows_max":crate::httpfilter::WINDOWS_MAX,"reputation":self.reputation.stats(now),"egress":egress,"rate_buckets":self.buckets.len(),"rate_buckets_max":65536,"offered_pps":o,"dropped_pps":d,"surge_pps":self.load.surge(now),"load_window_seconds":10})
    }
}
