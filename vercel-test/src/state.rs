//! Bounded temporal state used by the packet pipeline. Times are Unix milliseconds.
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
#[derive(Default, Clone)]
struct PulseSeries {
    counts: Vec<u64>,
    slots: Vec<i64>,
    latched: i64,
    cached_at: i64,
    cached: Value,
    last_write: i64,
}
#[derive(Default)]
pub struct Pulse {
    series: HashMap<String, PulseSeries>,
    pub floor: u64,
    last_sweep: i64,
}
impl Pulse {
    pub fn observe(&mut self, key: &str, pps: u64, now: i64) {
        if key.is_empty() {
            return;
        }
        if !self.series.contains_key(key) && self.series.len() >= 4096 {
            if now - self.last_sweep < 60000 {
                return;
            }
            self.last_sweep = now;
            self.series
                .retain(|_, s| s.last_write >= now / 250 - 240 || s.latched >= now);
            if self.series.len() >= 4096 {
                return;
            }
        }
        let s = self
            .series
            .entry(key.into())
            .or_insert_with(|| PulseSeries {
                counts: vec![0; 240],
                slots: vec![0; 240],
                cached_at: i64::MIN,
                ..Default::default()
            });
        let slot = now / 250;
        let idx = slot.rem_euclid(240) as usize;
        if s.slots[idx] != slot {
            s.slots[idx] = slot;
            s.counts[idx] = 0;
        }
        s.counts[idx] = s.counts[idx].saturating_add(pps);
        s.last_write = slot;
    }
    pub fn assess(&mut self, key: &str, now: i64) -> Value {
        let Some(s) = self.series.get_mut(key) else {
            return json!({"pulsing":false,"peak_pps":0,"mean_pps":0,"crest":0.0,"duty_cycle":0.0,"bursts":0,"held_for":0});
        };
        let slot = now / 250;
        if s.cached_at != slot {
            let oldest = slot - 239;
            let peak = s
                .counts
                .iter()
                .zip(&s.slots)
                .filter(|(_, at)| **at >= oldest && **at <= slot)
                .map(|(n, _)| *n)
                .max()
                .unwrap_or(0);
            let floor = if self.floor == 0 { 10000 } else { self.floor };
            let loud = (peak / 2).max(floor);
            let (mut total, mut active, mut bursts, mut in_burst) = (0u64, 0, 0, false);
            for at in oldest..=slot {
                let i = at.rem_euclid(240) as usize;
                let n = if s.slots[i] == at { s.counts[i] } else { 0 };
                total = total.saturating_add(n);
                if n > 0 {
                    active += 1;
                }
                if n > 0 && n >= loud && loud > 0 {
                    if !in_burst {
                        bursts += 1;
                        in_burst = true;
                    }
                } else {
                    in_burst = false;
                }
            }
            let mean = total / 240;
            let crest = if mean > 0 {
                peak as f64 / mean as f64
            } else {
                0.0
            };
            let duty = active as f64 / 240.0;
            let shaped = crest >= 4.0 && duty <= 0.5 && peak >= floor;
            let pulsing = shaped && bursts >= 3;
            if pulsing || shaped && bursts >= 1 && s.latched > now {
                s.latched = now + 300000;
            }
            s.cached = json!({"pulsing":pulsing,"peak_pps":peak,"mean_pps":mean,"crest":crest,"duty_cycle":duty,"bursts":bursts,"held_for":0});
            s.cached_at = slot;
        }
        let mut a = s.cached.clone();
        if s.latched > now {
            a["pulsing"] = json!(true);
            a["held_for"] = json!((s.latched - now) * 1_000_000);
        }
        a
    }
    pub fn forget(&mut self, live: &HashSet<String>) {
        self.series.retain(|k, _| live.contains(k));
    }
}
#[derive(Default, Clone)]
struct RepEntry {
    trusted: i64,
    proof: u8,
    penalised: i64,
    level: usize,
    strikes: i64,
    window: i64,
    last_strike: i64,
}
#[derive(Default)]
pub struct Reputation {
    entries: HashMap<String, RepEntry>,
    pub proof: u8,
    pub no_fast: bool,
    pub boxing: bool,
    last_sweep: i64,
    counts: [u64; 8],
}
impl Reputation {
    fn create(&mut self, src: &str, now: i64) -> bool {
        if self.entries.contains_key(src) {
            return true;
        }
        if self.entries.len() >= 65536 {
            if now - self.last_sweep >= 5000 {
                self.last_sweep = now;
                self.entries.retain(|_, e| {
                    now < e.trusted
                        || now < e.penalised
                        || now < e.window
                        || e.level > 0 && now - e.last_strike.max(e.penalised) < 3600000
                });
            }
            if self.entries.len() >= 65536 {
                self.counts[6] += 1;
                return false;
            }
        }
        self.entries.insert(src.into(), RepEntry::default());
        true
    }
    pub fn check(&mut self, src: &str, now: i64) -> u8 {
        self.check_sparing(src, now, || false)
    }
    /// As check(), for a source `spared` may exempt from the box: an operator's permit rule for
    /// it, which takes effect at once even for a source boxed before the rule was written.
    pub fn check_sparing(&mut self, src: &str, now: i64, spared: impl FnOnce() -> bool) -> u8 {
        let Some(e) = self.entries.get(src) else {
            return 0;
        };
        if self.boxing && now < e.penalised && !spared() {
            self.counts[1] += 1;
            return 2;
        }
        if !self.no_fast && now < e.trusted && e.proof >= self.proof.max(1) {
            self.counts[0] += 1;
            return 1;
        }
        0
    }
    /// Whether a source holds any proof right now, whether or not it is enough for the fast path:
    /// it cleared a gate, answered a challenge or had its return traffic confirmed, in the last
    /// five minutes. A budget for everyone lets such a source through.
    pub fn verified(&self, src: &str, now: i64) -> bool {
        self.entries.get(src).is_some_and(|e| now < e.trusted)
    }
    pub fn promote(&mut self, src: &str, proof: u8, now: i64) {
        if src.is_empty() || proof == 0 || !self.create(src, now) {
            return;
        }
        let e = self.entries.get_mut(src).unwrap();
        // An address that answers for itself, by echoing a challenge or being answered at length
        // by the origin, belongs to a real client, which the box would only cut off: it is
        // released, as a trusted source could never have been boxed. A handshake can be completed
        // blind, so it frees nobody, or a spoofer could free any address it liked.
        if proof >= 2 && now < e.penalised {
            e.penalised = 0;
            self.counts[7] += 1;
        }
        // Trust is held at the proof that earned it. A weaker proof, such as a blind handshake
        // or spoofed return traffic, neither raises nor prolongs trust a challenge earned, and
        // once trust lapses the old proof is gone rather than re-armed by whatever comes next.
        if now < e.trusted && proof < e.proof {
            return;
        }
        if e.trusted < now {
            self.counts[2] += 1;
        }
        e.trusted = now + 300000;
        e.proof = proof;
        e.strikes = 0;
    }
    pub fn strike(&mut self, src: &str, now: i64) {
        if src.is_empty() {
            return;
        }
        self.counts[4] += 1;
        if self.entries.get(src).is_some_and(|e| now < e.trusted) {
            self.counts[5] += 1;
            return;
        }
        if !self.create(src, now) {
            return;
        }
        let e = self.entries.get_mut(src).unwrap();
        let mut clean = e.last_strike.max(e.penalised);
        while e.level > 0 && clean != 0 && now - clean >= 3600000 {
            e.level -= 1;
            clean += 3600000;
        }
        e.last_strike = now;
        if now > e.window {
            e.strikes = 0;
            e.window = now + 30000;
        }
        e.strikes += 1;
        if e.strikes >= 4 {
            e.strikes = 0;
            e.window = 0;
            e.penalised = now + [60000, 600000, 3600000][e.level.min(2)];
            e.level = (e.level + 1).min(2);
            self.counts[3] += 1;
        }
    }
    /// Forgives a source's strikes and lifts it out of the penalty box, reporting whether it was
    /// actually in it. A sentence already served stays on record, because escalation decays from
    /// the end of the last penalty.
    pub fn release(&mut self, src: &str, now: i64) -> bool {
        let Some(e) = self.entries.get_mut(src) else {
            return false;
        };
        e.strikes = 0;
        if now < e.penalised {
            e.penalised = 0;
            true
        } else {
            false
        }
    }
    pub fn stats(&self, now: i64) -> Value {
        json!({"tracked":self.entries.len(),"max":65536,"trusted":self.entries.values().filter(|e|now<e.trusted).count(),"penalised":self.entries.values().filter(|e|now<e.penalised).count(),"fast_passed":self.counts[0],"boxed":self.counts[1],"promotions":self.counts[2],"demotions":self.counts[3],"strikes":self.counts[4],"shielded":self.counts[5],"full":self.counts[6],"freed":self.counts[7]})
    }
    pub fn sources(&self, limit: usize, now: i64) -> Value {
        let mut rows:Vec<_>=self.entries.iter().map(|(src,e)|{let(state,until)=if now<e.trusted{("trusted",e.trusted)}else if now<e.penalised{("penalised",e.penalised)}else{("tracked",now)};let mut r=json!({"source":src,"proof":(["none","handshake","egress","challenge"][e.proof.min(3)as usize]),"state":state});if until>now{r["expires_in_seconds"]=json!((until-now)as f64/1000.0);}
if e.level>0{r["level"]=json!(e.level);}
if e.strikes>0{r["strikes"]=json!(e.strikes);}r}).collect();
        rows.sort_by(|a, b| {
            a["state"]
                .as_str()
                .cmp(&b["state"].as_str())
                .then_with(|| {
                    b["expires_in_seconds"]
                        .as_f64()
                        .unwrap_or(0.0)
                        .total_cmp(&a["expires_in_seconds"].as_f64().unwrap_or(0.0))
                })
                .then_with(|| a["source"].as_str().cmp(&b["source"].as_str()))
        });
        if limit > 0 {
            rows.truncate(limit);
        }
        json!(rows)
    }
}
/// How long the table keeps an address the origin has sent nothing but SYN-ACKs: as long as a
/// client the origin answered has to finish its handshake.
const HANDSHAKE_ONLY: i64 = 10_000;
#[derive(Default)]
struct Client {
    packets: i64,
    ticks: i64,
    last_tick: i64,
    window: i64,
    confirmed: i64,
    last_seen: i64,
    first: i64,
    /// What the origin last asked the address, one bit for each reflection vector it sent a
    /// query of and one for a ping, and when: an answer of the kind from the address is one it
    /// asked for.
    asked: u32,
    asked_at: i64,
    /// When the origin last sent the address TCP of an open connection, which makes TCP from it
    /// part of a connection the origin has.
    tcp: i64,
    /// When the origin last sent the address a SYN, opening a connection to it, which makes the
    /// SYN-ACK it answers with one the origin asked for.
    opened: i64,
    /// When the origin last answered a SYN from the address, and how many segments it has let
    /// through on that answer since: a SYN-ACK is no proof of a connection, since a forged SYN
    /// draws one.
    answered: i64,
    handshake: u32,
}
#[derive(Default)]
struct ReturnSeries {
    clients: HashMap<String, Client>,
    ingress: i64,
    egress: i64,
    /// Since when the origin's traffic has been seen without a gap of more than 30 seconds.
    egress_since: i64,
}
#[derive(Default)]
pub struct Egress {
    series: HashMap<String, ReturnSeries>,
    clients: usize,
    last_sweep: i64,
    promotions: u64,
    full: u64,
}
impl Egress {
    fn prefix(&mut self, prefix: &str) -> bool {
        // Keys are the program's own prefixes and forget() prunes them on reload, so the table is
        // bounded by the policy; a fixed cap silently turned lockdown off past the 256th prefix.
        if prefix.is_empty() {
            return false;
        }
        self.series.entry(prefix.into()).or_default();
        true
    }
    pub fn ingress(&mut self, prefix: &str, now: i64) {
        if self.prefix(prefix) {
            self.series.get_mut(prefix).unwrap().ingress = now;
        }
    }
    pub fn grace(&mut self, prefix: &str, addr: &str, grace: i64, now: i64) -> bool {
        if addr.is_empty() || !self.prefix(prefix) {
            return false;
        }
        let s = self.series.get_mut(prefix).unwrap();
        if !s.clients.contains_key(addr) {
            if self.clients >= 65536 {
                self.full += 1;
                return false;
            }
            s.clients.insert(
                addr.into(),
                Client {
                    first: now,
                    ..Default::default()
                },
            );
            self.clients += 1;
        }
        let c = s.clients.get_mut(addr).unwrap();
        if c.first == 0 {
            c.first = now;
        }
        c.last_seen = now;
        now - c.first < grace
    }
    /// Records a reply from the origin. Returns whether this reply confirms the client, and if so
    /// whether the confirmation is fresh rather than a renewal of one already standing.
    pub fn observe_return(
        &mut self,
        prefix: &str,
        addr: &str,
        packets: i64,
        now: i64,
    ) -> Option<bool> {
        if addr.is_empty() || packets <= 0 || !self.prefix(prefix) {
            return None;
        }
        let series = self.series.get_mut(prefix).unwrap();
        if series.egress == 0 || now - series.egress > 30000 {
            series.egress_since = now;
        }
        series.egress = now;
        if now - self.last_sweep >= 5000 {
            self.last_sweep = now;
            for s in self.series.values_mut() {
                s.clients.retain(|_, c| {
                    // An address the origin has sent nothing but SYN-ACKs is one a forged SYN drew
                    // them to, unless its handshake finishes: kept past the handshake, a SYN flood
                    // too small to be held back would fill the table with them.
                    let backscatter = c.answered != 0
                        && c.tcp == 0
                        && c.opened == 0
                        && c.asked == 0
                        && c.first == 0
                        && now >= c.confirmed;
                    if backscatter && now - c.answered >= HANDSHAKE_ONLY {
                        return false;
                    }
                    now < c.confirmed
                        || now < c.window
                        || now - c.last_seen < 120000
                        || c.first != 0 && now - c.first < 120000
                });
            }
            self.clients = self.series.values().map(|s| s.clients.len()).sum();
        }
        let s = self.series.get_mut(prefix).unwrap();
        if !s.clients.contains_key(addr) {
            if self.clients >= 65536 {
                self.full += 1;
                return None;
            }
            s.clients.insert(addr.into(), Client::default());
            self.clients += 1;
        }
        let c = s.clients.get_mut(addr).unwrap();
        c.last_seen = now;
        if now > c.window {
            c.packets = 0;
            c.ticks = 0;
            c.last_tick = 0;
            c.window = now + 10000;
        }
        c.packets = c.packets.saturating_add(packets);
        if now / 250 != c.last_tick {
            c.last_tick = now / 250;
            c.ticks += 1;
        }
        if c.packets < 10 || c.ticks < 3 {
            return None;
        }
        let fresh = now >= c.confirmed;
        c.confirmed = now + 120000;
        if fresh {
            self.promotions += 1;
        }
        Some(fresh)
    }
    fn client(&mut self, p: &str, a: &str) -> Option<&mut Client> {
        self.series.get_mut(p).and_then(|s| s.clients.get_mut(a))
    }
    fn known(&self, p: &str, a: &str) -> Option<&Client> {
        self.series.get(p).and_then(|s| s.clients.get(a))
    }
    /// Records that the origin sent the address a query of the kind `bit` stands for, once its
    /// reply has been observed. What it asked longer than `within` ago is forgotten first.
    pub fn queried(&mut self, p: &str, a: &str, bit: u32, within: i64, now: i64) {
        if let Some(c) = self.client(p, a) {
            if now - c.asked_at >= within {
                c.asked = 0;
            }
            c.asked |= bit;
            c.asked_at = now;
        }
    }
    /// Whether the origin sent the address a query of the kind `bit` stands for within the last
    /// `within` milliseconds. It is known only where the origin's traffic passes the node.
    pub fn asked(&self, p: &str, a: &str, bit: u32, within: i64, now: i64) -> bool {
        self.known(p, a)
            .is_some_and(|c| c.asked & bit != 0 && now - c.asked_at < within)
    }
    /// Records that the origin sent the address TCP of an open connection, once its reply has
    /// been observed.
    pub fn sent_tcp(&mut self, p: &str, a: &str, now: i64) {
        if let Some(c) = self.client(p, a) {
            c.tcp = now;
        }
    }
    /// Records that the origin sent the address a SYN.
    pub fn opened(&mut self, p: &str, a: &str, now: i64) {
        if let Some(c) = self.client(p, a) {
            c.opened = now;
        }
    }
    /// Records that the origin answered a SYN from the address, which starts its handshake over.
    pub fn answered(&mut self, p: &str, a: &str, now: i64) {
        if let Some(c) = self.client(p, a) {
            c.answered = now;
            c.handshake = 0;
        }
    }
    /// Whether the origin sent the address TCP of an open connection within the last `within`
    /// milliseconds.
    pub fn talked_tcp(&self, p: &str, a: &str, within: i64, now: i64) -> bool {
        self.known(p, a)
            .is_some_and(|c| c.tcp != 0 && now - c.tcp < within)
    }
    /// Whether the origin sent the address a SYN within the last `within` milliseconds.
    pub fn opened_tcp(&self, p: &str, a: &str, within: i64, now: i64) -> bool {
        self.known(p, a)
            .is_some_and(|c| c.opened != 0 && now - c.opened < within)
    }
    /// Lets `pps` segments from the address through on the origin's answer to its SYN: within
    /// `window` of it, and no more than `segments` in all. Says whether they may pass.
    pub fn handshake(
        &mut self,
        p: &str,
        a: &str,
        pps: u32,
        window: i64,
        segments: u32,
        now: i64,
    ) -> bool {
        let Some(c) = self.client(p, a) else {
            return false;
        };
        if c.answered == 0 || now - c.answered >= window {
            return false;
        }
        let total = c.handshake.saturating_add(pps);
        if total > segments {
            return false;
        }
        c.handshake = total;
        true
    }
    /// Whether the table is full, so that an address the origin sends to now may go unrecorded.
    pub fn saturated(&self) -> bool {
        self.clients >= 65536
    }
    /// How long the origin's traffic has been seen without a gap, or 0 when it is not seen now.
    pub fn watched_for(&self, p: &str, now: i64) -> i64 {
        match self.series.get(p) {
            Some(s) if s.egress != 0 && now - s.egress <= 30000 => now - s.egress_since,
            _ => 0,
        }
    }
    pub fn confirmed(&self, p: &str, a: &str, now: i64) -> bool {
        self.series
            .get(p)
            .and_then(|s| s.clients.get(a))
            .is_some_and(|c| now < c.confirmed)
    }
    pub fn visibility(&self, p: &str, now: i64) -> &'static str {
        let Some(s) = self.series.get(p) else {
            return "unknown";
        };
        if s.egress != 0 && now - s.egress <= 30000 {
            "visible"
        } else if s.ingress != 0 && now - s.ingress <= 30000 {
            "asymmetric"
        } else {
            "unknown"
        }
    }
    pub fn forget(&mut self, live: &HashSet<String>) {
        self.series.retain(|k, _| live.contains(k));
        self.clients = self.series.values().map(|s| s.clients.len()).sum();
    }
    pub fn stats(&self, now: i64) -> Value {
        json!({"prefixes":self.series.len(),"clients":self.clients,"clients_max":65536,"confirmed":self.series.values().flat_map(|s|s.clients.values()).filter(|c|now<c.confirmed).count(),"promotions":self.promotions,"full":self.full,"asymmetric":self.series.keys().filter(|p|self.visibility(p,now)=="asymmetric").count()})
    }
    pub fn prefixes(&self, now: i64) -> Value {
        let mut rows:Vec<_>=self.series.iter().map(|(p,s)|json!({"prefix":p,"visibility":self.visibility(p,now),"clients":s.clients.len(),"confirmed":s.clients.values().filter(|c|now<c.confirmed).count()})).collect();
        rows.sort_by(|a, b| a["prefix"].as_str().cmp(&b["prefix"].as_str()));
        json!(rows)
    }
}
