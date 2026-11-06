//! Serialized per-node packet decisions and bounded counters/state.
use crate::{
    gamefilter,
    guards::{self, Key},
    httpfilter, ml,
    model::*,
    packet,
    reflection::{self, VECTORS, VECTORS_LEN},
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
    flags: Option<u16>,
    never: bool,
}
impl Matcher {
    fn new(m: Match) -> Self {
        let src = m.src_cidr.parse().ok();
        let dst = m.dst_cidr.parse().ok();
        let flags = packet::tcp_flags(&m.tcp_flags);
        let never =
            !m.src_cidr.is_empty() && src.is_none() || !m.dst_cidr.is_empty() && dst.is_none();
        Self {
            m,
            src,
            dst,
            flags,
            never,
        }
    }
    /// Flags named on both sides compare as sets (see packet::flags_meet); anything else as text.
    fn flags(&self, f: &Flow) -> bool {
        if self.m.tcp_flags.is_empty() {
            return true;
        }
        match (self.flags, packet::tcp_flags(&f.flags)) {
            (Some(rule), Some(segment)) => packet::flags_meet(rule, segment),
            _ => self.m.tcp_flags.eq_ignore_ascii_case(&f.flags),
        }
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
            && self.flags(f)
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
    /// Flows and their packets the crafted-packet checks dropped, per class: stack, protocol and
    /// buffer.
    crafted: [[u64; 2]; 3],
    /// Flows and their packets the reflection guard dropped, per vector.
    reflection: [[u64; 2]; VECTORS_LEN],
    /// Flows and their packets the protocol guard dropped, GRE and every other protocol.
    protocols: [[u64; 2]; 2],
    /// Flows and their packets the ACK and SYN flood guards dropped.
    ack_flood: [u64; 2],
    syn_flood: [u64; 2],
    /// Flows and their packets the fragment guard dropped, TCP and ICMP.
    fragments: [[u64; 2]; 2],
    /// Flows and their packets the ICMP guard dropped, per kind.
    icmp: [[u64; 2]; 3],
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
/// How long a step of tightening holds after the probing that set it was last seen. A score
/// within ml::PROBE_MARGIN under the threshold in force is a near miss, and each step lowers the
/// thresholds by as much, ml::PROBE_STEPS at most.
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
        f64::from(self.step) * ml::PROBE_MARGIN
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
        if self.step >= ml::PROBE_STEPS {
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
/// The score a model drops at for a target `cut` under the thresholds while it is being probed:
/// no further under its own than training showed it could go without dropping clean traffic.
fn held_to(m: &ml::Model, cut: f64) -> f64 {
    m.threshold - cut.min(m.max_cut)
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
        threshold: model.map_or(0.0, |m| held_to(m, cut)),
    }
}
/// A flow's bit rate: the one its record carries, or its packets' headers and payload.
fn bits(f: &Flow) -> u64 {
    if f.bps > 0 {
        return f.bps as u64;
    }
    if !f.packet.is_empty() {
        return (f.pps.max(0) as u64).saturating_mul(f.packet.len() as u64 * 8);
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
    /// The protected prefixes, most specific first, with the aggregate each one's floods are
    /// judged over.
    prefixes: Vec<(String, IpNet, Key)>,
    buckets: HashMap<(String, String), Rate>,
    last_sweep: i64,
    rule_stats: HashMap<String, (String, [u64; 4])>,
    /// Per filter: inspected, dropped, challenged, uninspectable, pps dropped, then for its HTTP
    /// rules requests judged, requests dropped, requests over a rate, segments with none,
    /// segments dropped for a budget for everyone, TLS handshakes, and segments dropped for a
    /// request that arrives too slowly.
    game_stats: HashMap<String, (String, [u64; 12])>,
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
    crafted: Crafted,
    reflection: reflection::Guard,
    protocols: guards::ProtocolGuard,
    ack_flood: guards::AckGuard,
    syn_flood: guards::SynGuard,
    fragments: guards::FragmentGuard,
    icmp: guards::IcmpGuard,
}
/// The crafted-packet checks: whether they drop, only count or are off, what each check dropped
/// and observed, in packet::Check order, and the fragments in reassembly.
struct Crafted {
    mode: String,
    dropped: [u64; 17],
    observed: [u64; 17],
    fragments: packet::Fragments,
}
impl Default for Crafted {
    fn default() -> Self {
        Self {
            mode: "enforce".into(),
            dropped: [0; 17],
            observed: [0; 17],
            fragments: Default::default(),
        }
    }
}
fn class(check: packet::Check) -> usize {
    match check.class() {
        "stack" => 0,
        "protocol" => 1,
        _ => 2,
    }
}
/// Whether an operator's permit lets a flow through the stages before anything else judges it:
/// the first rule on the asic stage, or failing one there the fpga stage, that matches it and drops
/// or permits, permits. The checks made before the stages, lockdown and the penalty box, and an
/// idle tunnel's HTTP rules honour it as the stages behind the rule do.
fn allowed(rules: &[Vec<Entry>; 3], f: &Flow) -> bool {
    rules[..2]
        .iter()
        .find_map(|stage| {
            stage
                .iter()
                .find(|r| (r.action == "drop" || r.action == "permit") && r.matcher.matches(f))
        })
        .is_some_and(|r| r.action == "permit")
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
            crafted: Crafted::default(),
            reflection: reflection::Guard::default(),
            protocols: guards::ProtocolGuard::default(),
            ack_flood: guards::AckGuard::default(),
            syn_flood: guards::SynGuard::default(),
            fragments: guards::FragmentGuard::default(),
            icmp: guards::IcmpGuard::default(),
        };
        p.load(program);
        p
    }
    pub fn load(&mut self, program: Program) {
        self.prefixes = program
            .prefixes
            .iter()
            .filter_map(|p| {
                p.parse::<IpNet>()
                    .ok()
                    .map(|net| (p.clone(), net, guards::aggregate(p, &net).into()))
            })
            .collect();
        // Lookups take the first match, so the most specific prefix has to come first or a /24
        // inside a protected /22 is counted, pulse-tracked and confirmed under the /22.
        self.prefixes
            .sort_by_key(|(_, net, _)| std::cmp::Reverse(net.prefix_len()));
        let live: HashSet<_> = program.prefixes.iter().cloned().collect();
        let aggregates: HashSet<String> = self
            .prefixes
            .iter()
            .map(|(_, _, a)| a.to_string())
            .collect();
        let kept = |a: &str| aggregates.contains(a);
        self.loads.retain(|p, _| live.contains(p));
        self.probes.retain(|p, _| live.contains(p));
        for prefix in &program.prefixes {
            self.loads.entry(prefix.clone()).or_default();
            self.probes.entry(prefix.clone()).or_default();
        }
        self.pulses.forget(&live);
        self.egress.forget(&live);
        self.protocols.load(program.protocols.as_ref());
        self.ack_flood.load(program.ack_flood.as_ref(), &kept);
        self.syn_flood.load(program.syn_flood.as_ref(), &kept);
        self.fragments.load(program.fragments.as_ref());
        self.icmp.load(program.icmp.as_ref(), &kept);
        self.reflection.load(program.reflection.as_ref(), &kept);
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
        // A behavioural cap, an FPGA meter on the trusted path and lockdown's trickle all count per
        // source, and the fabric recompiles all the time: a reload must not hand every source a
        // fresh allowance for the rules it keeps.
        let bucket_live: HashSet<&str> = program
            .zc
            .iter()
            .map(|r| r.rule_id.as_str())
            .chain(program.fpga.iter().map(|r| r.rule_id.as_str()))
            .chain(["|lockdown"])
            .collect();
        self.buckets
            .retain(|(r, _), _| bucket_live.contains(r.as_str()));
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
                .unwrap_or((b.profile.name.clone(), [0; 12]));
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
        self.crafted.mode = match program.crafted.as_ref().map(|c| c.mode.as_str()) {
            Some(mode @ ("observe" | "off")) => mode.into(),
            _ => "enforce".into(),
        };
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
        let watching = |w: &Watch| {
            decision(
                "permit",
                0,
                "",
                format!(
                    "watching only: tunnel {} is under its attack thresholds",
                    w.tunnel
                ),
            )
        };
        // What an operator permits passes a mitigating tunnel's stages unjudged, so it passes an
        // idle one's HTTP rules too.
        if allowed(&self.rules, f) {
            self.watches[i].unfiltered += 1;
            return watching(&self.watches[i]);
        }
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
        watching(&self.watches[i])
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
                .as_deref()
                .map_or(f64::INFINITY, |m| held_to(m, self.scoring.cut));
            self.scoring.scored = true;
            self.scoring.near |= r.score < threshold && r.score >= threshold - ml::PROBE_MARGIN;
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
                    s[11] += u64::from(r.slow);
                }
                "challenge" => s[2] += 1,
                "uninspectable" => s[3] += 1,
                _ => {}
            }
            s[5] += r.requests;
            s[8] += u64::from(r.other);
            s[10] += u64::from(r.handshake);
        }
        if r.cleared > 0 {
            self.reputation.promote(&f.src_ip, r.cleared, now);
        }
        // Turned away because everyone together spent a budget is nothing the source did, and a
        // player loading the server list mid-flood must not be boxed for it. Nor is a model's
        // score proof of anything: the box would turn one wrong score into every packet dropped.
        if r.verdict == "drop" && !r.budget && !r.classified {
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
    /// only observes, or a pass. A drop is no strike against the source, which the penalty box
    /// takes only on what a rule, a gate or a rate proved.
    fn classify(&mut self, f: &Flow, rule: &str) -> Option<Decision> {
        if !self.model.ready {
            return None;
        }
        let score = ml::score(&self.model, f);
        let threshold = held_to(&self.model, self.scoring.cut);
        let over = score >= threshold;
        self.scoring.scored = true;
        self.scoring.near |= !over && score >= threshold - ml::PROBE_MARGIN;
        let drop = over && self.ml.enforcing();
        self.ml_counts[0] += 1;
        self.ml_counts[if drop {
            1
        } else if over {
            3
        } else {
            2
        }] += 1;
        let probed = if threshold < self.model.threshold {
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
                    // nothing must not end the stage and hide the rules behind it. A drop or a
                    // permit ends evaluation, as it does for everyone: a permit is an operator's
                    // allow list, and trust is no reason to hold a source to the stages behind it.
                    self.seen(&r.id, f);
                    if r.action == "drop" || r.action == "permit" {
                        return (
                            decision(
                                &r.action,
                                stage,
                                &r.id,
                                format!(
                                    "{} {}",
                                    ["TCAM ACL", "FPGA", "PF_RING ZC"][stage],
                                    r.action
                                ),
                            ),
                            None,
                        );
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
                if let Some(d) = self.classify(f, &r.id) {
                    return (d, id);
                }
                return (decision("permit", 2, &r.id, "PF_RING ZC inspect pass"), id);
            }
        }
        // Under scope all the flow model has the last word on whatever the stages let through:
        // what a game filter or the HTTP rules passed, and what no rule decided. A permit rule,
        // which ends evaluation, and a verified source skip it.
        if !trusted && self.ml.everywhere() {
            if let Some(d) = self.classify(f, "") {
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
    /// Holds a flow to what a packet can legitimately be, and returns the drop and the check it
    /// broke if it is crafted. It is judged whoever sent it: a permit or a verified source vouches
    /// for an address, which a crafted packet forges as easily as the rest of itself. Nor is its
    /// source boxed for it, since that address is as likely to be the forgery.
    fn crafted(
        &mut self,
        f: &Flow,
        dst: Option<IpAddr>,
        now: i64,
    ) -> Option<(Decision, packet::Check)> {
        if self.crafted.mode == "off" {
            return None;
        }
        let (found, stage) = if f.packet.is_empty() {
            (packet::record(f, dst), 0)
        } else {
            let (p, found) = packet::parse(&f.packet);
            match found {
                Some(a) => (Some(a), 0),
                // Telling one datagram's fragments from another's takes memory a switch does not
                // have, so overlaps are judged in software.
                None if p.fragment() => (self.crafted.fragments.observe(&p, now), 2),
                None => (None, 0),
            }
        };
        let a = found?;
        let i = a.check as usize;
        if self.crafted.mode == "observe" {
            self.crafted.observed[i] += 1;
            return None;
        }
        self.crafted.dropped[i] += 1;
        let mut d = decision(
            "drop",
            stage,
            "",
            format!("crafted packet ({}): {}", a.check.class(), a.why),
        );
        d.check = a.check.name().into();
        Some((d, a.check))
    }
    /// Holds a flow to whether it is an answer reflected at the protected address, and returns
    /// its drop, with the vector it belongs to, if it is. Each vector's answers come from its
    /// port and open the way its answers do (see reflection.rs). An operator's permit vouches for
    /// the address it covers, and so does the origin having sent that address a query of the
    /// vector: an answer it asked for is no reflection. Answers of a vector the server asks
    /// itself, DNS and NTP's time, are dropped only while the aggregate is flooded with ones it
    /// never asked for. The rest of a long answer arrives in fragments that carry no port, so a
    /// source caught reflecting has its later fragments dropped too, for as long as a host would
    /// hold them. Its address is real, since a reflector answers from its own, but it is no
    /// strike: a reflector is somebody's server, put to work by the attacker.
    fn reflected(
        &mut self,
        f: &Flow,
        owner: &str,
        aggregate: &Key,
        now: i64,
    ) -> Option<(Decision, usize)> {
        let seen = self.reflection.seen(f, now, || {
            let (p, _) = packet::parse(&f.packet);
            p.fragment() && !p.transport
        });
        let (i, answer) = match seen {
            reflection::Seen::Not => return None,
            reflection::Seen::Answer(i, kind, what) => (i, Some((kind, what))),
            reflection::Seen::Fragment(i) => (i, None),
        };
        if allowed(&self.rules, f) {
            return None;
        }
        let v = &VECTORS[i];
        let mut flood = false;
        if let Some((kind, _)) = answer {
            if self.egress.asked(
                owner,
                &f.src_ip,
                reflection::bit(i),
                reflection::ASKED_WITHIN,
                now,
            ) {
                self.reflection.counts[i][2] += 1;
                return None;
            }
            if kind == reflection::Kind::Flood {
                if !self
                    .reflection
                    .flooded_by(aggregate, i, f.pps.max(0) as u64, now)
                {
                    return None;
                }
                flood = true;
            }
            self.reflection.caught(&f.src_ip, i, now);
        }
        if self.reflection.modes[i] == "observe" {
            self.reflection.counts[i][1] += 1;
            return None;
        }
        let mut d = match answer {
            Some((_, what)) => {
                self.reflection.counts[i][0] += 1;
                let what = what.map_or_else(|| format!("UDP from port {}", v.port), String::from);
                let reason = format!(
                    "{} reflection: {what} that the server never asked for{}",
                    v.label,
                    if flood {
                        ", while the prefix is flooded with them"
                    } else {
                        ""
                    }
                );
                // Whether the prefix is flooded is memory a switch does not have.
                decision("drop", if flood { 2 } else { 0 }, "", reason)
            }
            None => {
                self.reflection.counts[i][3] += 1;
                // Telling a datagram's later fragments by their source takes memory a switch does
                // not have, so they are judged in software.
                decision(
                    "drop",
                    2,
                    "",
                    format!(
                        "{} reflection: a later fragment of an answer from a source caught reflecting",
                        v.label
                    ),
                )
            }
        };
        d.reflection = v.name.into();
        Some((d, i))
    }
    /// Holds a flow to whether its protocol is one the protected addresses receive: TCP, UDP,
    /// ICMP and what the policy allows. GRE is what botnets wrap their floods in. An operator's
    /// permit vouches for what it covers, a rule naming the protocol among them.
    fn foreign(&mut self, f: &Flow) -> Option<(Decision, String)> {
        let name = self.protocols.stopped(&f.proto)?;
        if allowed(&self.rules, f) {
            return None;
        }
        let observed = self.protocols.mode == "observe";
        self.protocols.count(&name, observed);
        if observed {
            return None;
        }
        let mut d = decision("drop", 0, "", guards::why(&name));
        d.guard = "protocol".into();
        Some((d, name))
    }
    /// Holds a packet to whether it is TCP or ICMP in fragments, and returns its drop, with
    /// which of the two it is, if it is: no real sender fragments either, since TCP sizes its
    /// segments to the path and ICMP's messages are small. Fragmented ACK floods and ICMP
    /// fragmentation floods are built that way to cost reassembly. Only a packet shows it is a
    /// fragment. An operator's permit vouches for what it covers.
    fn fragmented(&mut self, f: &Flow) -> Option<(Decision, usize)> {
        if f.packet.is_empty() || self.fragments.mode == "off" {
            return None;
        }
        let (p, _) = packet::parse(&f.packet);
        let i = self.fragments.fragment(&p)?;
        if allowed(&self.rules, f) {
            return None;
        }
        if self.fragments.mode == "observe" {
            self.fragments.counts[i][1] += 1;
            return None;
        }
        self.fragments.counts[i][0] += 1;
        let mut d = decision("drop", 0, "", guards::fragment_why(i));
        d.guard = "fragment".into();
        Some((d, i))
    }
    /// Holds ICMP to what a protected address needs of it, and returns its drop, with its kind
    /// in guards::ICMP_KINDS, if it is caught. An echo reply answers a ping the server sent, so
    /// one it never asked for is dropped while the aggregate is flooded with them, as a Smurf
    /// attack floods. An error quotes the packet it is about, which the protected prefix must
    /// have sent; one that quotes nothing of the prefix's is forged, as BlackNurse floods with.
    /// Everything else, echo requests and errors that hold up among it, is held to a rate for
    /// the aggregate. An operator's permit vouches for what it covers.
    fn icmp_guard(
        &mut self,
        f: &Flow,
        owner: &str,
        net: &IpNet,
        aggregate: &Key,
        now: i64,
    ) -> Option<(Decision, usize)> {
        if self.icmp.mode == "off"
            || !f.proto.eq_ignore_ascii_case("icmp")
            || allowed(&self.rules, f)
        {
            return None;
        }
        let pps = f.pps.max(0) as u64;
        let what = if f.packet.is_empty() {
            guards::Icmp::Other
        } else {
            let (p, _) = packet::parse(&f.packet);
            // A later fragment holds no ICMP header to judge: the fragment guard's to drop.
            if !p.transport {
                return None;
            }
            guards::icmp_of(&p, net)
        };
        let i = match what {
            guards::Icmp::Reply => {
                if self.egress.asked(
                    owner,
                    &f.src_ip,
                    guards::ECHO_BIT,
                    reflection::ASKED_WITHIN,
                    now,
                ) || !self.icmp.smurfed_by(aggregate, pps, now)
                {
                    return None;
                }
                1
            }
            guards::Icmp::Error { from_prefix: false } => 2,
            _ => {
                if !self.icmp.over_limit(aggregate, pps, now) {
                    return None;
                }
                0
            }
        };
        if self.icmp.mode == "observe" {
            self.icmp.counts[i][1] += 1;
            return None;
        }
        self.icmp.counts[i][0] += 1;
        // A quote a switch can read; rates and what the server asked are memory it does not have.
        let mut d = decision(
            "drop",
            if i == 2 { 0 } else { 2 },
            "",
            guards::icmp_why(i, self.icmp.limit_pps),
        );
        d.guard = "icmp".into();
        Some((d, i))
    }
    /// Holds a TCP segment to whether it belongs to a connection the server has: every segment of
    /// one but the opening SYN comes from an address the server has sent TCP to, and a SYN-ACK
    /// answers a SYN the server sent. A SYN-ACK the server sends proves nothing, since a forged
    /// SYN draws one, so the client it answers may finish its handshake with a few segments and
    /// no more until the server's own say the connection is open: a fake session, a forged SYN
    /// followed by a stream of ACKs, gets those few. That is known only where the server's
    /// traffic passes the node, and once it has been watched long enough to have seen every
    /// connection open, so the guard waits for both. It drops such TCP only while the aggregate
    /// takes more of it than its threshold, and holds a minute after; below that, a stray
    /// segment, after a restart say, passes. An operator's permit vouches for what it covers; a
    /// player's trust does not, since its address is as easily forged.
    fn unsolicited(
        &mut self,
        f: &Flow,
        owner: &str,
        aggregate: &Key,
        now: i64,
    ) -> Option<Decision> {
        if self.ack_flood.mode == "off"
            || !f.proto.eq_ignore_ascii_case("tcp")
            || !guards::mid_connection(&f.flags)
            || self.egress.watched_for(owner, now) < guards::ACK_WARM
            // A full table may have missed a connection opened since, so the guard stands down
            // rather than drop it.
            || self.egress.saturated()
            || self
                .egress
                .talked_tcp(owner, &f.src_ip, guards::TALKED_WITHIN, now)
            || self
                .egress
                .opened_tcp(owner, &f.src_ip, guards::TALKED_WITHIN, now)
            || allowed(&self.rules, f)
        {
            return None;
        }
        if !guards::syn_ack(&f.flags)
            && self.egress.handshake(
                owner,
                &f.src_ip,
                u32::try_from(f.pps.max(0)).unwrap_or(u32::MAX),
                guards::HANDSHAKE,
                guards::HANDSHAKE_SEGMENTS,
                now,
            )
        {
            return None;
        }
        if !self
            .ack_flood
            .engaged_by(aggregate, f.pps.max(0) as u64, now)
        {
            return None;
        }
        if self.ack_flood.mode == "observe" {
            self.ack_flood.counts[1] += 1;
            return None;
        }
        self.ack_flood.counts[0] += 1;
        // Whom the server has sent TCP to is memory a switch does not have.
        let mut d = decision("drop", 2, "", guards::unsolicited_why(&f.flags));
        d.guard = "ack_flood".into();
        Some(d)
    }
    /// Holds an opening SYN to whether its source is known, or retrying, while the aggregate is
    /// flooded with SYNs from sources the server has no connection with. A source the server is
    /// talking TCP to, or has confirmed or verified, opens connections as it likes. Any other has
    /// its first SYN held back during a flood, and passes on the retry its stack sends a second or
    /// so later, which a forged SYN, sent once from a made-up address, never has. An operator's
    /// permit vouches for what it covers.
    fn syn_flood(&mut self, f: &Flow, owner: &str, aggregate: &Key, now: i64) -> Option<Decision> {
        if self.syn_flood.mode == "off"
            || !f.proto.eq_ignore_ascii_case("tcp")
            || !guards::opening(&f.flags)
            || self
                .egress
                .talked_tcp(owner, &f.src_ip, guards::TALKED_WITHIN, now)
            || self.egress.confirmed(owner, &f.src_ip, now)
            || self.reputation.verified(&f.src_ip, now)
            || allowed(&self.rules, f)
        {
            return None;
        }
        let retry = self.syn_flood.retried(f, now) && f.pps <= guards::SYN_RETRIES;
        if !self
            .syn_flood
            .engaged_by(aggregate, f.pps.max(0) as u64, now)
        {
            return None;
        }
        if retry {
            self.syn_flood.counts[2] += 1;
            return None;
        }
        if self.syn_flood.mode == "observe" {
            self.syn_flood.counts[1] += 1;
            return None;
        }
        self.syn_flood.counts[0] += 1;
        // Which connections have sent a SYN is memory a switch does not have.
        let mut d = decision("drop", 2, "", guards::SYN_WHY);
        d.guard = "syn_flood".into();
        Some(d)
    }
    /// Records a guard's drop for the node and the prefix, and returns the prefix's load for the
    /// guard to count it in.
    fn guarded(&mut self, d: &Decision, f: &Flow, owner: &str, now: i64) -> &mut Load {
        let pps = f.pps.max(0) as u64;
        self.record(d, None, f);
        self.load.observe(now, pps, true);
        let load = self.loads.entry(owner.to_string()).or_default();
        load.observe(now, pps, true);
        load
    }
    pub fn decide(&mut self, f: &Flow, now: i64) -> Decision {
        self.decisions += 1;
        let pps = f.pps.max(0) as u64;
        let dst = f.dst_ip.parse::<IpAddr>().ok();
        let owner = dst.and_then(|a| {
            self.prefixes
                .iter()
                .find(|(_, p, _)| p.contains(&a))
                .map(|(s, net, aggregate)| (s.clone(), *net, aggregate.clone()))
        });
        let Some((owner, net, aggregate)) = owner else {
            // A packet too broken to say where it is going is no one's traffic to pass.
            if !f.packet.is_empty() && dst.is_none() {
                if let Some((d, _)) = self.crafted(f, dst, now) {
                    self.record(&d, None, f);
                    self.load.observe(now, pps, true);
                    return d;
                }
            }
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
        // An on-demand tunnel's traffic is only watched until it reaches the tunnel's thresholds,
        // and its meter counts everything that reaches it, crafted or not, so mitigation starts on
        // the whole of an attack.
        let idle = self
            .watched
            .get(&owner)
            .copied()
            .filter(|&i| !self.watches[i].mitigating(now, pps, bits(f)));
        // A crafted packet is judged first, on a watched tunnel too: it needs no volume to do its
        // harm, so no threshold would ever start mitigation for it.
        if let Some((d, check)) = self.crafted(f, dst, now) {
            self.record(&d, None, f);
            self.load.observe(now, pps, true);
            let load = self.loads.entry(owner).or_default();
            load.observe(now, pps, true);
            let c = &mut load.crafted[class(check)];
            c[0] += 1;
            c[1] = c[1].saturating_add(pps);
            return d;
        }
        if let Some(i) = idle {
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
        // Reflected answers are judged before the penalty box, trust and lockdown: a reflector is
        // not a player, so neither a player's trust nor its box speaks for it. Nor do they for
        // the other guards, which judge what a packet is, whoever claims to have sent it.
        let count = |c: &mut [u64; 2], pps: u64| {
            c[0] += 1;
            c[1] = c[1].saturating_add(pps);
        };
        if let Some((d, i)) = self.reflected(f, &owner, &aggregate, now) {
            count(&mut self.guarded(&d, f, &owner, now).reflection[i], pps);
            return d;
        }
        if let Some((d, name)) = self.foreign(f) {
            let c = usize::from(name != "gre");
            count(&mut self.guarded(&d, f, &owner, now).protocols[c], pps);
            return d;
        }
        if let Some((d, i)) = self.fragmented(f) {
            count(&mut self.guarded(&d, f, &owner, now).fragments[i], pps);
            return d;
        }
        if let Some((d, i)) = self.icmp_guard(f, &owner, &net, &aggregate, now) {
            count(&mut self.guarded(&d, f, &owner, now).icmp[i], pps);
            return d;
        }
        if let Some(d) = self.unsolicited(f, &owner, &aggregate, now) {
            count(&mut self.guarded(&d, f, &owner, now).ack_flood, pps);
            return d;
        }
        if let Some(d) = self.syn_flood(f, &owner, &aggregate, now) {
            count(&mut self.guarded(&d, f, &owner, now).syn_flood, pps);
            return d;
        }
        let rules = &self.rules;
        let state = self
            .reputation
            .check_sparing(&f.src_ip, now, || allowed(rules, f));
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
                && !self.egress.grace(&owner, &f.src_ip, self.grace, now)
                && !allowed(&self.rules, f);
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
                .find(|(_, p, _)| p.contains(&a))
                .map(|(s, _, _)| s.clone())
        });
        if let Some(prefix) = prefix {
            self.returns[0] += 1;
            // Every confirmation renews trust, not only the first: a client the origin keeps
            // answering would otherwise lose its fast path five minutes into the conversation.
            let confirmed = self
                .egress
                .observe_return(&prefix, &f.dst_ip, f.pps.max(1), now);
            // A query of a vector the origin sent, and nothing else it sent, makes an answer of
            // that vector from the address one it asked for: anything else can be had from it by
            // forging a query from the reflector's address that the server answers. A ping makes
            // an echo reply one it asked for the same way.
            if let Some(i) = reflection::queried(f) {
                let bit = reflection::bit(i);
                self.egress
                    .queried(&prefix, &f.dst_ip, bit, reflection::ASKED_WITHIN, now);
            }
            if f.proto.eq_ignore_ascii_case("icmp")
                && !f.packet.is_empty()
                && guards::echo_request(&packet::parse(&f.packet).0)
            {
                let bit = guards::ECHO_BIT;
                self.egress
                    .queried(&prefix, &f.dst_ip, bit, reflection::ASKED_WITHIN, now);
            }
            // TCP of an open connection the origin sent makes TCP from the address part of a
            // connection it has. Its SYN opens one, whose SYN-ACK it then expects; its SYN-ACK
            // answers one, which a forged SYN draws as readily; and its reset says nothing of
            // one. A record that names no flags is taken at its word.
            if f.proto.eq_ignore_ascii_case("tcp") {
                use packet::{ACK, FIN, PSH, RST, SYN};
                match packet::tcp_flags(&f.flags) {
                    Some(b) if b & SYN != 0 && b & ACK == 0 => {
                        self.egress.opened(&prefix, &f.dst_ip, now)
                    }
                    Some(b) if b & SYN != 0 && b & (FIN | RST | PSH) == 0 => {
                        self.egress.answered(&prefix, &f.dst_ip, now)
                    }
                    Some(b) if b & RST != 0 && b & (FIN | PSH) == 0 => {}
                    _ => self.egress.sent_tcp(&prefix, &f.dst_ip, now),
                }
            }
            if let Some(fresh) = confirmed {
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
        let mut games:Vec<_>=self.game_stats.iter().map(|(id,(profile,s))|json!({"filter_id":id,"profile":profile,"inspected":s[0],"dropped":s[1],"challenged":s[2],"uninspectable":s[3],"pps_dropped":s[4],"http_requests":s[5],"http_dropped":s[6],"http_rate_limited":s[7],"http_other":s[8],"http_budget_dropped":s[9],"http_tls_handshakes":s[10],"http_slow_dropped":s[11]})).collect();
        games.sort_by(|a, b| a["filter_id"].as_str().cmp(&b["filter_id"].as_str()));
        let mut pulsing = false;
        let mut peak = 0;
        let mut prefixes = Vec::new();
        let tighten = self.ml.tightens();
        let aggregates: HashMap<&str, &Key> = self
            .prefixes
            .iter()
            .map(|(p, _, a)| (p.as_str(), a))
            .collect();
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
            let mut row = json!({"prefix":prefix,"flows":l.flows,"flows_dropped":l.flows_dropped,"offered":l.total,"dropped":l.total_dropped,"offered_pps":o,"dropped_pps":d,"pulsing":a["pulsing"],"peak_pps":a["peak_pps"],"mean_pps":a["mean_pps"],"crest":a["crest"],"duty_cycle":a["duty_cycle"],"bursts":a["bursts"],"held_for_seconds":a["held_for"].as_f64().unwrap_or(0.0)/1e9,"ml_cut":cut});
            let crafted: Vec<_> = ["stack", "protocol", "buffer"]
                .iter()
                .zip(l.crafted)
                .filter(|(_, [flows, _])| *flows > 0)
                .map(|(class, [flows, pps])| json!({"class":class,"flows":flows,"dropped":pps}))
                .collect();
            if !crafted.is_empty() {
                row["crafted"] = json!(crafted);
            }
            let reflected: Vec<_> = VECTORS
                .iter()
                .zip(l.reflection)
                .filter(|(_, [flows, _])| *flows > 0)
                .map(|(v, [flows, pps])| json!({"vector":v.name,"flows":flows,"dropped":pps}))
                .collect();
            if !reflected.is_empty() {
                row["reflection"] = json!(reflected);
            }
            let protocols: Vec<_> = ["gre", "other"]
                .iter()
                .zip(l.protocols)
                .filter(|(_, [flows, _])| *flows > 0)
                .map(|(p, [flows, pps])| json!({"protocol":p,"flows":flows,"dropped":pps}))
                .collect();
            if !protocols.is_empty() {
                row["protocols"] = json!(protocols);
            }
            let aggregate = aggregates.get(prefix.as_str()).map_or("", |a| &***a);
            let engaged = self.ack_flood.engaged(aggregate, now);
            if engaged || l.ack_flood[0] > 0 {
                row["ack_flood"] =
                    json!({"engaged":engaged,"flows":l.ack_flood[0],"dropped":l.ack_flood[1]});
            }
            let engaged = self.syn_flood.engaged(aggregate, now);
            if engaged || l.syn_flood[0] > 0 {
                row["syn_flood"] =
                    json!({"engaged":engaged,"flows":l.syn_flood[0],"dropped":l.syn_flood[1]});
            }
            let fragments: Vec<_> = guards::FRAGMENTED
                .iter()
                .zip(l.fragments)
                .filter(|(_, [flows, _])| *flows > 0)
                .map(|(p, [flows, pps])| json!({"protocol":p,"flows":flows,"dropped":pps}))
                .collect();
            if !fragments.is_empty() {
                row["fragments"] = json!(fragments);
            }
            let icmp: Vec<_> = guards::ICMP_KINDS
                .iter()
                .zip(l.icmp)
                .filter(|(_, [flows, _])| *flows > 0)
                .map(|(k, [flows, pps])| json!({"kind":k,"flows":flows,"dropped":pps}))
                .collect();
            if !icmp.is_empty() {
                row["icmp"] = json!(icmp);
            }
            prefixes.push(row);
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
        let checks: Vec<_> = packet::Check::ALL
            .iter()
            .enumerate()
            .map(|(i, c)| json!({"check":c.name(),"class":c.class(),"dropped":self.crafted.dropped[i],"observed":self.crafted.observed[i]}))
            .collect();
        let crafted = json!({"mode":self.crafted.mode,"dropped":self.crafted.dropped.iter().sum::<u64>(),"observed":self.crafted.observed.iter().sum::<u64>(),"fragments":self.crafted.fragments.len(),"fragments_max":packet::FRAGMENTS_MAX,"fragments_untracked":self.crafted.fragments.untracked,"checks":checks});
        let mitigation:Vec<_>=self.watches.iter().map(|w|{let(pps,bps)=w.meter.rates(now);let active=w.active(now);json!({"tunnel_id":w.tunnel,"active":active,"since":w.since.filter(|_|active).map(crate::analytics::stamp),"pps":pps,"bps":bps,"attack_pps":w.attack_pps,"attack_bps":w.attack_bps,"wave":w.wave,"hold_seconds":w.hold()/1000,"mitigations":w.mitigations,"unfiltered":w.unfiltered})}).collect();
        json!({"decisions":self.decisions,"unowned":self.unowned,"stages":stages,"rules":rules,"games":if games.is_empty(){Value::Null}else{json!(games)},"prefixes":if prefixes.is_empty(){Value::Null}else{json!(prefixes)},"ml":{"ready":self.model.ready,"scored":self.ml_counts[0],"drops":self.ml_counts[1],"passes":self.ml_counts[2],"observed":self.ml_counts[3],"http_ready":self.model.http.as_ref().is_some_and(|h|h.ready),"http_scored":self.http_counts[0],"http_drops":self.http_counts[1],"http_observed":self.http_counts[2],"scope":if self.ml.everywhere(){"all"}else{"inspect"},"mode":if self.ml.enforcing(){"enforce"}else{"observe"},"probing":if tighten{"tighten"}else{"ignore"},"near_misses":self.probe_counts[0],"tightened":self.probe_counts[1]},"pulsing":pulsing,"pulse_peak_pps":peak,"game_sessions":self.games.sessions(),"game_sessions_max":65536,"game_http_windows":self.games.windows(),"game_http_windows_max":crate::httpfilter::WINDOWS_MAX,"game_http_pending":self.games.pending().0,"game_http_pending_max":crate::httpfilter::PENDING_MAX,"game_http_pending_untracked":self.games.pending().1,"reputation":self.reputation.stats(now),"egress":egress,"rate_buckets":self.buckets.len(),"rate_buckets_max":65536,"offered_pps":o,"dropped_pps":d,"surge_pps":self.load.surge(now),"load_window_seconds":10,"crafted":crafted,"reflection":self.reflection.stats(now),"protocols":self.protocols.stats(),"ack_flood":self.ack_flood.stats(now),"syn_flood":self.syn_flood.stats(now),"fragments":self.fragments.stats(),"icmp":self.icmp.stats(now),"mitigation":if mitigation.is_empty(){Value::Null}else{json!(mitigation)}})
    }
}
