//! Protocol framing, handshake admission, and stateless HMAC challenge cookies.
use crate::{
    model::{Flow, GameFilter, GameSignature},
    Result,
};
use hmac::{Hmac, Mac};
use ipnet::IpNet;
use sha2::Sha256;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::IpAddr,
};
use subtle::ConstantTimeEq;
#[derive(Clone, Default)]
pub struct Profile {
    pub name: String,
    min: i64,
    max: i64,
    ids: Vec<u8>,
    magic: Vec<(usize, Vec<u8>)>,
    gate: String,
    open: Vec<u8>,
    complete: Vec<u8>,
}
#[derive(Clone)]
pub struct Binding {
    pub id: String,
    pub proto: String,
    pub dport: i64,
    pub dst: Option<IpNet>,
    pub observe: bool,
    pub profile: Profile,
}
#[derive(Default, Debug, Clone)]
pub struct Inspection {
    pub verdict: String,
    pub reason: String,
    pub filter: String,
    pub profile: String,
    pub reply: Vec<u8>,
    pub cleared: u8,
}
fn bytes(v: &[i64], name: &str) -> Result<Vec<u8>> {
    v.iter()
        .map(|v| u8::try_from(*v).map_err(|_| format!("{name}: {v} is not a byte")))
        .collect()
}
fn custom(s: &GameSignature) -> Result<Profile> {
    if s.min_len < 0 || s.max_len < 0 {
        return Err("lengths must not be negative".into());
    }
    if s.max_len > 0 && s.min_len > s.max_len {
        return Err(format!(
            "min_len {} is above max_len {}",
            s.min_len, s.max_len
        ));
    }
    let mut p = Profile {
        name: "custom".into(),
        min: s.min_len,
        max: s.max_len,
        ids: bytes(&s.packet_ids, "packet_ids")?,
        ..Default::default()
    };
    for (i, m) in s.magic.iter().enumerate() {
        if m.offset < 0 {
            return Err(format!("magic[{i}]: offset must not be negative"));
        }
        let lower = m.hex.to_ascii_lowercase();
        let raw = hex::decode(lower.strip_prefix("0x").unwrap_or(&lower))
            .map_err(|e| format!("magic[{i}]: {e}"))?;
        if raw.is_empty() {
            return Err(format!("magic[{i}]: empty"));
        }
        p.magic.push((m.offset as usize, raw));
    }
    p.gate=match s.gate.to_ascii_lowercase().as_str(){""|"none"=>"none","handshake"=>"handshake","challenge"=>return Err("a challenge gate cannot be described in a policy; use a built-in profile that defines one".into()),_=>return Err("unknown gate; use none or handshake".into())}.into();
    if p.gate == "handshake" {
        p.open = bytes(&s.opener_ids, "opener_ids")?;
        p.complete = bytes(&s.complete_ids, "complete_ids")?;
        if p.complete.is_empty() {
            return Err(
                "a handshake gate needs complete_ids, or no source can ever be admitted".into(),
            );
        }
    }
    Ok(p)
}
pub fn compile(filters: &[GameFilter]) -> Result<Vec<Binding>> {
    filters
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let p = if let Some(s) = &f.custom {
                if !f.profile.is_empty() {
                    return Err("set either profile or a custom signature, not both".into());
                }
                custom(s)?
            } else {
                match f.profile.to_ascii_lowercase().as_str() {
                    "raknet" => Profile {
                        name: "raknet".into(),
                        min: 1,
                        max: 1500,
                        gate: "handshake".into(),
                        open: vec![1, 2, 5, 7],
                        complete: vec![7],
                        ..Default::default()
                    },
                    "a2s" => Profile {
                        name: "a2s".into(),
                        min: 5,
                        max: 1400,
                        magic: vec![(0, vec![255; 4])],
                        gate: "challenge".into(),
                        ..Default::default()
                    },
                    _ => {
                        return Err(format!(
                            "games[{i}] ({}): unknown profile {:?}; built-ins are a2s and raknet",
                            f.id, f.profile
                        ))
                    }
                }
            };
            Ok(Binding {
                id: f.id.clone(),
                proto: f.proto.to_ascii_lowercase(),
                dport: f.dport,
                dst: if f.dst_cidr.is_empty() {
                    None
                } else {
                    Some(f.dst_cidr.parse().map_err(|e| format!("dst_cidr: {e}"))?)
                },
                observe: f.observe,
                profile: p,
            })
        })
        .collect()
}
fn framing(p: &Profile, payload: &[u8]) -> Result<()> {
    let n = payload.len() as i64;
    if p.min > 0 && n < p.min {
        return Err(format!(
            "packet is {n} bytes, shorter than the {} this protocol allows",
            p.min
        ));
    }
    if p.max > 0 && n > p.max {
        return Err(format!(
            "packet is {n} bytes, longer than the {} this protocol allows",
            p.max
        ));
    }
    if !p.ids.is_empty() {
        let id = payload
            .first()
            .ok_or("packet is empty and carries no packet id")?;
        if !p.ids.contains(id) {
            return Err(format!(
                "packet id 0x{id:02x} is not one this protocol sends"
            ));
        }
    }
    if !p.magic.is_empty()
        && !p.magic.iter().any(|(offset, bytes)| {
            offset
                .checked_add(bytes.len())
                .and_then(|end| payload.get(*offset..end))
                .is_some_and(|v| v == bytes)
        })
    {
        return Err("packet carries none of this protocol's magic sequences".into());
    }
    Ok(())
}
#[derive(Default)]
pub struct Engine {
    pub bindings: Vec<Binding>,
    secret: Vec<u8>,
    sessions: HashMap<(String, String), i64>,
    pending: HashMap<(String, String), i64>,
    order: VecDeque<(String, String)>,
    last_sweep: i64,
}
impl Engine {
    pub fn load(&mut self, bindings: Vec<Binding>, secret: &str) {
        let live: HashSet<_> = bindings.iter().map(|b| b.id.clone()).collect();
        self.sessions.retain(|(b, _), _| live.contains(b));
        self.pending.retain(|(b, _), _| live.contains(b));
        self.order.retain(|(b, _)| live.contains(b));
        self.bindings = bindings;
        self.secret = secret.as_bytes().to_vec();
    }
    pub fn sessions(&self) -> usize {
        self.sessions.len()
    }
    fn binding(&self, f: &Flow) -> Option<Binding> {
        let ip = f.dst_ip.parse::<IpAddr>().ok();
        self.bindings
            .iter()
            .find(|b| {
                (b.proto.is_empty() || b.proto == "any" || b.proto.eq_ignore_ascii_case(&f.proto))
                    && (b.dport == 0 || b.dport == f.dport)
                    && b.dst.is_none_or(|p| ip.is_some_and(|a| p.contains(&a)))
            })
            .cloned()
    }
    fn admit(&mut self, key: (String, String), now: i64) -> bool {
        if !self.sessions.contains_key(&key) && self.sessions.len() >= 65536 {
            if now - self.last_sweep < 120000 {
                return false;
            }
            self.last_sweep = now;
            self.sessions.retain(|_, until| *until >= now);
            if self.sessions.len() >= 65536 {
                return false;
            }
        }
        self.sessions.insert(key, now + 120000);
        true
    }
    pub fn cookie(&self, f: &Flow, now: i64) -> Vec<u8> {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.secret).expect("HMAC accepts all key lengths");
        mac.update(f.src_ip.as_bytes());
        mac.update(&[0]);
        mac.update(f.dst_ip.as_bytes());
        mac.update(&[0]);
        mac.update(&(f.dport as u64).to_be_bytes());
        mac.update(&((now / 1000 / 120) as u64).to_be_bytes());
        mac.finalize().into_bytes()[..4].to_vec()
    }
    pub fn inspect(&mut self, f: &Flow, now: i64, validate_only: bool) -> Inspection {
        let Some(b) = self.binding(f) else {
            return Inspection {
                verdict: "pass".into(),
                ..Default::default()
            };
        };
        let mut r = Inspection {
            filter: b.id.clone(),
            profile: b.profile.name.clone(),
            ..Default::default()
        };
        if !f.has_payload && f.payload.is_empty() {
            r.verdict = "uninspectable".into();
            r.reason = "no payload supplied, nothing to inspect".into();
        } else if let Err(e) = framing(&b.profile, &f.payload) {
            r.verdict = "drop".into();
            r.reason = e;
        } else if validate_only || b.profile.gate == "none" {
            // A trusted source skips the gate but is still connected through it. Keep its session
            // alive, or it expires under the fast path and the source is dropped as a stranger
            // the moment its trust lapses.
            if validate_only && b.profile.gate != "none" {
                let key = (b.id.clone(), f.src_ip.clone());
                if let Some(until) = self.sessions.get_mut(&key) {
                    if now <= *until {
                        *until = now + 120000;
                    }
                }
            }
            r.verdict = "pass".into();
            r.reason = format!("well-formed {}", b.profile.name);
        } else {
            let key = (b.id.clone(), f.src_ip.clone());
            let admitted = self.sessions.get(&key).is_some_and(|until| now <= *until);
            if admitted {
                self.sessions.insert(key.clone(), now + 120000);
                r.verdict = "pass".into();
                r.reason = format!(
                    "source {} the {} {}",
                    if b.profile.gate == "challenge" {
                        "answered"
                    } else {
                        "completed"
                    },
                    b.profile.name,
                    b.profile.gate
                );
            } else {
                self.sessions.remove(&key);
                if b.profile.gate == "handshake" {
                    let id = f.payload.first().copied();
                    if id.is_none() {
                        r.verdict = "drop".into();
                        r.reason = "empty packet from a source that has not connected".into();
                    } else if !b.profile.open.contains(&id.unwrap())
                        && !b.profile.complete.contains(&id.unwrap())
                    {
                        r.verdict = "drop".into();
                        r.reason = format!(
                            "packet id 0x{:02x} from a source that has not completed the handshake",
                            id.unwrap()
                        );
                    } else if b.profile.complete.contains(&id.unwrap()) {
                        r.verdict = "pass".into();
                        if self.admit(key, now) {
                            r.reason = format!("source completed the {} handshake", b.profile.name);
                            r.cleared = 1;
                        } else {
                            r.reason = "session table full, admitting without tracking".into();
                        }
                    } else {
                        if !self.pending.contains_key(&key) {
                            while self.pending.len() >= 8192 {
                                if let Some(old) = self.order.pop_front() {
                                    self.pending.remove(&old);
                                }
                            }
                            self.order.push_back(key.clone());
                        }
                        self.pending.insert(key, now + 120000);
                        r.verdict = "pass".into();
                        r.reason = "handshake in progress".into();
                    }
                } else if !f
                    .payload
                    .get(4)
                    .is_some_and(|id| [b'T', b'U', b'V'].contains(id))
                {
                    r.verdict = "drop".into();
                    r.reason =
                        "not a query this protocol challenges, from an unverified source".into();
                } else {
                    let cookie = self.cookie(f, now);
                    let previous = self.cookie(f, now - 120000);
                    let answers =
                        |v: &[u8]| bool::from(v.ct_eq(&cookie)) || bool::from(v.ct_eq(&previous));
                    // A2S_PLAYER and A2S_RULES carry the challenge straight after the header byte.
                    // A real A2S_INFO carries it after its "Source Engine Query" string, so looking
                    // only after the header challenged every server-browser query forever.
                    let valid = f.payload.get(5..9).is_some_and(answers)
                        || f.payload.get(4) == Some(&b'T')
                            && f.payload.get(5..25) == Some(&b"Source Engine Query\0"[..])
                            && f.payload.get(25..29).is_some_and(answers);
                    if valid {
                        let tracked = self.admit(key, now);
                        r.verdict = "pass".into();
                        r.cleared = 3;
                        r.reason = if tracked {
                            format!("source answered the {} challenge", b.profile.name)
                        } else {
                            "session table full, admitting without tracking".into()
                        };
                    } else {
                        r.verdict = "challenge".into();
                        r.reason = "unverified source challenged".into();
                        r.reply = vec![255, 255, 255, 255, b'A'];
                        r.reply.extend(cookie);
                    }
                }
            }
        }
        if b.observe {
            // Observing records what the binding would do and acts on nothing: a completion seen
            // in observe mode must not promote its source past the classifier and the box.
            r.cleared = 0;
            if r.verdict != "pass" && (!validate_only || r.verdict == "drop") {
                r.reason = format!("observe only: would have {} ({})", r.verdict, r.reason);
                r.verdict = "pass".into();
                r.reply.clear();
            }
        }
        r
    }
}
