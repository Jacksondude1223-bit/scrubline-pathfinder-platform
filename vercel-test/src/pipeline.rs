//! Serialized per-node packet decisions and bounded counters/state.
use crate::{
    gamefilter, httpfilter, ml,
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
/// How long an on-demand tunnel's mitigation lasts after its traffic was last at a threshold.
/// Attacks come in waves, and stopping between them would let the start of every wave through.
pub const MITIGATION_HOLD: i64 = 300_000;
/// A mitigation that starts within this long of the last one ending is another wave of the same
/// attack, and holds twice as long as the wave before it, up to MITIGATION_HOLD_MAX. An attacker
/// that learns how long mitigation lasts, and times each wave to start as it ends, gets less
/// through with every wave instead of the same again.
pub const CAMPAIGN: i64 = 3_600_000;
/// The longest any wave's mitigation holds.
pub const MITIGATION_HOLD_MAX: i64 = 3_600_000;
/// What reaches a tunnel's prefixes, in packets and bits, over the last two seconds.
#[derive(Default)]
struct Meter {
    slots: [i64; 2],
    packets: [u64; 2],
    bits: [u64; 2],
}
impl Meter {
    fn observe(&mut self, now: i64, packets: u64, bits: u64) {
        let sec = now / 1000;
        let i = sec.rem_euclid(2) as usize;
        if self.slots[i] != sec {
            self.slots[i] = sec;
            self.packets[i] = 0;
            self.bits[i] = 0;
        }
        self.packets[i] = self.packets[i].saturating_add(packets);
        self.bits[i] = self.bits[i].saturating_add(bits);
    }
    /// Packets and bits a second over the one second up to `now`, read the way Load::surge reads
    /// its rate.
    fn rates(&self, now: i64) -> (u64, u64) {
        let sec = now / 1000;
        let covered = (1000 - now.rem_euclid(1000)) as u128;
        let rate = |v: &[u64; 2]| {
            let at = |s: i64| {
                let i = s.rem_euclid(2) as usize;
                if self.slots[i] == s {
                    v[i]
                } else {
                    0
                }
            };
            at(sec).saturating_add((at(sec - 1) as u128 * covered / 1000) as u64)
        };
        (rate(&self.packets), rate(&self.bits))
    }
}
/// An on-demand tunnel this node holds: the thresholds its traffic starts mitigation at, what
/// reaches it, and since and until when it is being mitigated.
struct Watch {
    tunnel: String,
    attack_pps: u64,
    attack_bps: u64,
    meter: Meter,
    since: Option<i64>,
    until: i64,
    /// Which wave of an attack the last mitigation was: 1 for one that started more than CAMPAIGN
    /// after the one before it ended.
    wave: u32,
    /// Mitigations started, and flows let through unfiltered while it was idle.
    mitigations: u64,
    unfiltered: u64,
}
impl Watch {
    /// Counts a flow to the tunnel and says whether the tunnel is being mitigated: from the moment
    /// its traffic reaches either threshold until it has stayed under both for the wave's hold.
    fn mitigating(&mut self, now: i64, packets: u64, bits: u64) -> bool {
        self.meter.observe(now, packets, bits);
        let (pps, bps) = self.meter.rates(now);
        if pps >= self.attack_pps || bps >= self.attack_bps {
            if !self.active(now) {
                self.wave = if self.since.is_some() && now - self.until <= CAMPAIGN {
                    self.wave.saturating_add(1)
                } else {
                    1
                };
                self.since = Some(now);
                self.mitigations += 1;
            }
            self.until = now + self.hold();
        }
        self.active(now)
    }
    fn active(&self, now: i64) -> bool {
        self.since.is_some() && now <= self.until
    }
    /// How long the traffic has to stay under both thresholds before this wave's mitigation ends:
    /// MITIGATION_HOLD for the first wave, doubling with each one after it.
    fn hold(&self) -> i64 {
        (MITIGATION_HOLD << self.wave.saturating_sub(1).min(4)).min(MITIGATION_HOLD_MAX)
    }
}
/// How far under its threshold a score is a near miss, and how far each step of tightening lowers
/// the thresholds a target being probed is held to.
const PROBE_MARGIN: f64 = 0.1;
/// How many steps a target's thresholds can be lowered.
const PROBE_STEPS: u8 = 2;
/// How long a step holds after the probing that set it was last seen.
pub const PROBE_HOLD: i64 = 300_000;
/// Near misses over the last ten seconds that say a target is being probed, when they are also a
/// quarter or more of what the classifiers scored for it.
const PROBE_MIN: u64 = 20;
/// What the classifiers scored for one protected prefix over the last ten seconds, how much of
/// that was a near miss, and how many steps the prefix's thresholds are lowered.
///
/// Traffic an attacker has tuned against a model, changing it until it gets through, scores just
/// under the threshold: it stops changing at the first variant that passes. Ordinary traffic has
/// no reason to gather there.
#[derive(Default)]
struct Probe {
    slots: [i64; 10],
    scored: [u64; 10],
    near: [u64; 10],
    step: u8,
    until: i64,
}
impl Probe {
    /// How far under their thresholds the classifiers drop for this prefix: a step for each level
    /// of probing seen, each lapsing PROBE_HOLD after the probing was last seen.
    fn cut(&mut self, now: i64) -> f64 {
        while self.step > 0 && now > self.until {
            self.step -= 1;
            self.until += PROBE_HOLD;
        }
        f64::from(self.step) * PROBE_MARGIN
    }
    /// Counts a flow the classifiers scored, and whether it was a near miss. Near misses at
    /// PROBE_MIN or more, and at a quarter or more of what was scored, are probing: with `tighten`
    /// they lower the thresholds a step, or hold them at the last. Says whether they lowered them.
    fn observe(&mut self, now: i64, near: bool, tighten: bool) -> bool {
        let sec = now / 1000;
        let i = sec.rem_euclid(10) as usize;
        if self.slots[i] != sec {
            self.slots[i] = sec;
            self.scored[i] = 0;
            self.near[i] = 0;
        }
        self.scored[i] += 1;
        if !near {
            return false;
        }
        self.near[i] += 1;
        let live = |v: &[u64; 10]| -> u64 {
            (0..10)
                .filter(|&j| self.slots[j] > sec - 10 && self.slots[j] <= sec)
                .map(|j| v[j])
                .sum()
        };
        let (scored, near) = (live(&self.scored), live(&self.near));
        if !tighten || near < PROBE_MIN || near * 4 < scored {
            return false;
        }
        self.until = now + PROBE_HOLD;
        if self.step >= PROBE_STEPS {
            return false;
        }
        self.step += 1;
        // The next step takes near misses under the threshold this one sets.
        self.scored = [0; 10];
        self.near = [0; 10];
        true
    }
}
/// What the classifiers made of the flow being decided, for its target's probe watch: how far
/// under their thresholds they drop for that target, whether either scored the flow, and whether
/// a score fell just under the threshold.
#[derive(Default)]
struct Scoring {
    cut: f64,
    scored: bool,
    near: bool,
}
/// The request model a game filter's HTTP rules consult, if the policy has them consult one.
fn consulted<'a>(model: &'a ml::Model, ml: &MlPolicy) -> Option<&'a ml::Model> {
    model.http.as_deref().filter(|m| m.ready && ml.everywhere())
}
/// What a game filter's HTTP rules judge a flow with besides themselves: whether its source is
/// verified, and the request model, if they consult one, with the score it drops at for the
/// flow's target, `cut` under its own threshold.
fn http_context<'a>(
    model: &'a ml::Model,
    ml: &MlPolicy,
    cut: f64,
    verified: bool,
) -> httpfilter::Context<'a> {
    let model = consulted(model, ml);
    httpfilter::Context {
        verified,
        model,
        threshold: model.map_or(0.0, |m| m.threshold - cut),
    }
}
/// A flow's bit rate: the one its record carries, or its packets' headers and payload.
fn bits(f: &Flow) -> u64 {
    if f.bps > 0 {
        return f.bps as u64;
    }
    let ip = if f.dst_ip.contains(':') { 40 } else { 20 };
    let l4 = if f.proto.eq_ignore_ascii_case("tcp") {
        20
    } else if f.proto.eq_ignore_ascii_case("udp") || f.proto.eq_ignore_ascii_case("icmp") {
        8
    } else {
        0
    };
    (f.pps.max(0) as u64).saturating_mul((ip + l4 + f.payload.len() as u64) * 8)
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
    /// rules requests judged, requests dropped, requests over a rate, segments with none, and
    /// segments dropped for a budget for everyone.
    game_stats: HashMap<String, (String, [u64; 10])>,
    stages: [[u64; 4]; 3],
    decisions: u64,
    unowned: u64,
    /// The flow model: flows scored, dropped, passed, and over its threshold but only observed.
    ml_counts: [u64; 4],
    /// The request model: requests scored, segments it dropped, and segments it would have.
    http_counts: [u64; 3],
    /// Flows either classifier scored just under the threshold in force, and the times a
    /// prefix's thresholds were lowered for it.
    probe_counts: [u64; 2],
    /// Where the classifiers run and whether they drop, from the program.
    ml: MlPolicy,
    /// Each protected prefix's probe watch, and what the classifiers made of the flow being
    /// decided.
    probes: HashMap<String, Probe>,
    scoring: Scoring,
    /// The on-demand tunnels this node holds, and which of them each of its prefixes is.
    watches: Vec<Watch>,
    watched: HashMap<String, usize>,
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
            probe_counts: [0; 2],
            ml: MlPolicy::default(),
            probes: HashMap::new(),
            scoring: Scoring::default(),
            watches: Vec::new(),
            watched: HashMap::new(),
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
        self.probes.retain(|p, _| live.contains(p));
        for prefix in &program.prefixes {
            self.loads.entry(prefix.clone()).or_default();
            self.probes.entry(prefix.clone()).or_default();
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
                .unwrap_or((b.profile.name.clone(), [0; 10]));
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
        // Programs are recompiled whenever the fabric changes, so a tunnel being mitigated stays
        // mitigated, and its meter keeps counting, across a reload.
        let mut kept: HashMap<String, Watch> = std::mem::take(&mut self.watches)
            .into_iter()
            .map(|w| (w.tunnel.clone(), w))
            .collect();
        self.watched.clear();
        for t in program
            .tunnels
            .iter()
            .filter(|t| t.mitigation == "on_demand")
        {
            let mut w = kept.remove(&t.id).unwrap_or_else(|| Watch {
                tunnel: t.id.clone(),
                attack_pps: 0,
                attack_bps: 0,
                meter: Meter::default(),
                since: None,
                until: 0,
                wave: 0,
                mitigations: 0,
                unfiltered: 0,
            });
            w.attack_pps = t.attack_pps.max(1) as u64;
            w.attack_bps = (t.attack_kbps.max(1) as u64).saturating_mul(1000);
            for prefix in &t.prefixes {
                self.watched.insert(prefix.clone(), self.watches.len());
            }
            self.watches.push(w);
        }
        self.program = program;
    }
    /// Mitigations started on this node's on-demand tunnels, for whoever wants to know at once.
    pub fn mitigations(&self) -> u64 {
        self.watches.iter().map(|w| w.mitigations).sum()
    }
    /// Judges a flow to an idle on-demand tunnel. A game filter's HTTP rules, and the request
    /// model behind them, hold whether or not the tunnel is being mitigated: application abuse
    /// takes a few requests a second, far under any attack threshold. Everything else passes
    /// unfiltered, though the other game filters still see it, so a player who connects now is
    /// known when mitigation starts.
    fn watch_only(&mut self, f: &Flow, now: i64, i: usize) -> Decision {
        let verified = self.verified(f, now);
        let r = self.games.inspect(
            f,
            now,
            false,
            http_context(&self.model, &self.ml, self.scoring.cut, verified),
            self.ml.enforcing(),
        );
        if r.profile == "http" {
            if let Some(d) = self.judged(r, f, now, false) {
                return d;
            }
        } else {
            if r.cleared > 0 {
                self.reputation.promote(&f.src_ip, r.cleared, now);
            }
            self.watches[i].unfiltered += 1;
        }
        decision(
            "permit",
            0,
            "",
            format!(
                "watching only: tunnel {} is under its attack thresholds",
                self.watches[i].tunnel
            ),
        )
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
    /// Whether a flow's source holds a proof, which only a budget for everyone, on HTTP, asks.
    fn verified(&self, f: &Flow, now: i64) -> bool {
        self.games.budgeted()
            && f.proto.eq_ignore_ascii_case("tcp")
            && self.reputation.verified(&f.src_ip, now)
    }
    fn inspect_game(&mut self, f: &Flow, now: i64, trusted: bool) -> Option<Decision> {
        let verified = self.verified(f, now);
        let r = self.games.inspect(
            f,
            now,
            trusted,
            http_context(&self.model, &self.ml, self.scoring.cut, verified),
            self.ml.enforcing(),
        );
        self.judged(r, f, now, trusted)
    }
    /// Counts what a game filter made of a flow, holds the source to it, and turns a drop or a
    /// challenge into the decision.
    fn judged(
        &mut self,
        r: gamefilter::Inspection,
        f: &Flow,
        now: i64,
        trusted: bool,
    ) -> Option<Decision> {
        self.http_counts[0] += r.scored;
        self.http_counts[1] += u64::from(r.classified);
        self.http_counts[2] += u64::from(r.observed);
        if r.scored > 0 {
            // Scored only when the request model is consulted, so it is there to read.
            let threshold = self
                .model
                .http
                .as_ref()
                .map_or(f64::INFINITY, |m| m.threshold)
                - self.scoring.cut;
            self.scoring.scored = true;
            self.scoring.near |= r.score < threshold && r.score >= threshold - PROBE_MARGIN;
        }
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
                    s[9] += u64::from(r.budget);
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
        // Turned away because everyone together spent a budget is nothing the source did, and a
        // player loading the server list mid-flood must not be boxed for it.
        if r.verdict == "drop" && !r.budget {
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
        let threshold = self.model.threshold - self.scoring.cut;
        let over = score >= threshold;
        self.scoring.scored = true;
        self.scoring.near |= !over && score >= threshold - PROBE_MARGIN;
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
        let probed = if self.scoring.cut > 0.0 {
            format!(", over the {threshold:.2} this target is held to while it is being probed")
        } else {
            String::new()
        };
        let mut d = decision(
            if drop { "drop" } else { "permit" },
            2,
            rule,
            if drop {
                format!("PF_RING ZC ml score {score:.2}{probed}")
            } else if over {
                format!("PF_RING ZC ml score {score:.2}{probed}, observed only")
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
        // Without a model there is nothing to score, and nothing to look up for it.
        let tighten = self.ml.tightens() && self.model.usable();
        self.scoring = Scoring {
            cut: self
                .probes
                .get_mut(&owner)
                .filter(|_| tighten)
                .map_or(0.0, |p| p.cut(now)),
            ..Default::default()
        };
        // An on-demand tunnel's traffic is only watched until it reaches the tunnel's thresholds.
        if let Some(&i) = self.watched.get(&owner) {
            if !self.watches[i].mitigating(now, pps, bits(f)) {
                let d = self.watch_only(f, now, i);
                self.probed(&owner, now);
                self.record(&d, None, f);
                self.load.observe(now, pps, false);
                self.loads
                    .entry(owner)
                    .or_default()
                    .observe(now, pps, false);
                return d;
            }
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
        self.probed(&owner, now);
        self.record(&d, by.as_deref(), f);
        let mitigated = d.action == "drop" || d.action == "challenge";
        self.load.observe(now, pps, mitigated);
        self.loads
            .entry(owner)
            .or_default()
            .observe(now, pps, mitigated);
        d
    }
    /// Counts what the classifiers made of the flow just decided against its target's probe watch.
    fn probed(&mut self, owner: &str, now: i64) {
        if !self.scoring.scored {
            return;
        }
        let tighten = self.ml.tightens();
        if let Some(p) = self.probes.get_mut(owner) {
            self.probe_counts[0] += u64::from(self.scoring.near);
            self.probe_counts[1] += u64::from(p.observe(now, self.scoring.near, tighten));
        }
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
        let mut games:Vec<_>=self.game_stats.iter().map(|(id,(profile,s))|json!({"filter_id":id,"profile":profile,"inspected":s[0],"dropped":s[1],"challenged":s[2],"uninspectable":s[3],"pps_dropped":s[4],"http_requests":s[5],"http_dropped":s[6],"http_rate_limited":s[7],"http_other":s[8],"http_budget_dropped":s[9]})).collect();
        games.sort_by(|a, b| a["filter_id"].as_str().cmp(&b["filter_id"].as_str()));
        let mut pulsing = false;
        let mut peak = 0;
        let mut prefixes = Vec::new();
        let tighten = self.ml.tightens();
        for (prefix, l) in &self.loads {
            let a = self.pulses.assess(prefix, now);
            let cut = self
                .probes
                .get_mut(prefix)
                .filter(|_| tighten)
                .map_or(0.0, |p| p.cut(now));
            let (o, d) = l.rates(now);
            if a["pulsing"] == true {
                pulsing = true;
                peak = peak.max(a["peak_pps"].as_u64().unwrap_or(0));
            }
            prefixes.push(json!({"prefix":prefix,"flows":l.flows,"flows_dropped":l.flows_dropped,"offered":l.total,"dropped":l.total_dropped,"offered_pps":o,"dropped_pps":d,"pulsing":a["pulsing"],"peak_pps":a["peak_pps"],"mean_pps":a["mean_pps"],"crest":a["crest"],"duty_cycle":a["duty_cycle"],"bursts":a["bursts"],"held_for_seconds":a["held_for"].as_f64().unwrap_or(0.0)/1e9,"ml_cut":cut}));
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
        let mitigation:Vec<_>=self.watches.iter().map(|w|{let(pps,bps)=w.meter.rates(now);let active=w.active(now);json!({"tunnel_id":w.tunnel,"active":active,"since":w.since.filter(|_|active).map(crate::analytics::stamp),"pps":pps,"bps":bps,"attack_pps":w.attack_pps,"attack_bps":w.attack_bps,"wave":w.wave,"hold_seconds":w.hold()/1000,"mitigations":w.mitigations,"unfiltered":w.unfiltered})}).collect();
        json!({"decisions":self.decisions,"unowned":self.unowned,"stages":stages,"rules":rules,"games":if games.is_empty(){Value::Null}else{json!(games)},"prefixes":if prefixes.is_empty(){Value::Null}else{json!(prefixes)},"ml":{"ready":self.model.ready,"scored":self.ml_counts[0],"drops":self.ml_counts[1],"passes":self.ml_counts[2],"observed":self.ml_counts[3],"http_ready":self.model.http.as_ref().is_some_and(|h|h.ready),"http_scored":self.http_counts[0],"http_drops":self.http_counts[1],"http_observed":self.http_counts[2],"scope":if self.ml.everywhere(){"all"}else{"inspect"},"mode":if self.ml.enforcing(){"enforce"}else{"observe"},"probing":if tighten{"tighten"}else{"ignore"},"near_misses":self.probe_counts[0],"tightened":self.probe_counts[1]},"pulsing":pulsing,"pulse_peak_pps":peak,"game_sessions":self.games.sessions(),"game_sessions_max":65536,"game_http_windows":self.games.windows(),"game_http_windows_max":crate::httpfilter::WINDOWS_MAX,"reputation":self.reputation.stats(now),"egress":egress,"rate_buckets":self.buckets.len(),"rate_buckets_max":65536,"offered_pps":o,"dropped_pps":d,"surge_pps":self.load.surge(now),"load_window_seconds":10,"mitigation":if mitigation.is_empty(){Value::Null}else{json!(mitigation)}})
    }
}
