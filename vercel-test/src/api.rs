//! Control-plane authorization, routing, and fabric reconciliation.
use crate::{
    analytics::{self, Collector},
    compiler, ml,
    model::*,
    pipeline::Pipeline,
    steering,
    store::{self, Store},
    validation, wire,
};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::any,
    Json, Router,
};
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::{Arc, Mutex},
};
use subtle::ConstantTimeEq;
type Error = (u16, String);
type Answer<T = Value> = std::result::Result<T, Error>;
fn bad(e: impl ToString) -> Error {
    (400, e.to_string())
}
// The API contract answers 503 for a write that could not be made durable: the change was rolled
// back, which is what a caller needs to know to retry it.
fn failed(e: impl ToString) -> Error {
    eprintln!("state operation failed: {}", e.to_string());
    (503, "could not persist control-plane state".into())
}
fn parse<T: DeserializeOwned>(body: &[u8]) -> Answer<T> {
    serde_json::from_slice(body).map_err(bad)
}
fn value<T: Serialize>(v: T) -> Value {
    serde_json::to_value(v).expect("validated wire value")
}
#[derive(Deserialize, Default)]
#[serde(default)]
struct Training {
    epochs: i64,
    lr: f64,
    threshold: f64,
    #[serde(skip)]
    samples: Vec<ml::Sample>,
}
impl Training {
    fn fit(&self) -> Answer<ml::Model> {
        ml::train(&self.samples, self.epochs, self.lr, self.threshold).map_err(bad)
    }
}
#[derive(Clone)]
struct Who {
    role: &'static str,
    id: String,
    tenant: Option<Tenant>,
}
impl Who {
    fn operator(&self) -> Answer<()> {
        if self.role == "operator" {
            Ok(())
        } else {
            Err((403, "operator credential required".into()))
        }
    }
    fn acts(&self, id: &str) -> bool {
        self.role == "operator" || self.role == "node" && self.id == id && !id.is_empty()
    }
    fn sees(&self, prefix: &str) -> bool {
        if self.role == "operator" {
            return true;
        }
        let Ok(target) = prefix.parse::<IpNet>() else {
            return false;
        };
        self.tenant.as_ref().is_some_and(|t| {
            t.prefixes.iter().any(|p| {
                p.parse::<IpNet>().is_ok_and(|p| {
                    p.prefix_len() <= target.prefix_len() && p.contains(&target.network())
                })
            })
        })
    }
}
pub struct Api {
    pub store: Store,
    pub mode: String,
    pub token: String,
    pub enroll: String,
    collector: Collector,
    steering: steering::Controller,
    pipes: HashMap<String, Pipeline>,
    last_key: String,
    recompiles: u64,
    requests: BTreeMap<(String, u16), u64>,
}
pub type Shared = Arc<Mutex<Api>>;
pub type MetricState<'a> = (
    u64,
    &'a BTreeMap<(String, u16), u64>,
    HashMap<String, steering::Level>,
);
impl Api {
    pub fn new(store: Store, token: String, enroll: String, mode: String) -> Self {
        Self {
            store,
            token,
            enroll,
            mode,
            collector: Default::default(),
            steering: Default::default(),
            pipes: HashMap::new(),
            last_key: String::new(),
            recompiles: 0,
            requests: BTreeMap::new(),
        }
    }
    fn auth(&self, headers: &HeaderMap) -> Answer<Who> {
        let h = headers
            .get("Authorization")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        let Some((scheme, token)) = h.split_once(' ') else {
            return Err((401, "unauthorized".into()));
        };
        if !scheme.eq_ignore_ascii_case("Bearer") || token.is_empty() {
            return Err((401, "unauthorized".into()));
        }
        let role = if bool::from(token.as_bytes().ct_eq(self.token.as_bytes())) {
            "operator"
        } else if bool::from(token.as_bytes().ct_eq(self.enroll.as_bytes())) {
            "enroll"
        } else {
            ""
        };
        if !role.is_empty() {
            return Ok(Who {
                role,
                id: String::new(),
                tenant: None,
            });
        }
        let hash = store::hash(token);
        if let Some((id, _)) = self
            .store
            .data
            .node_tokens
            .iter()
            .find(|(_, h)| *h == &hash)
        {
            return Ok(Who {
                role: "node",
                id: id.clone(),
                tenant: None,
            });
        }
        if let Some((id, _)) = self
            .store
            .data
            .tenant_tokens
            .iter()
            .find(|(_, h)| *h == &hash)
        {
            if let Some(t) = self.store.data.tenants.iter().find(|t| &t.id == id) {
                return Ok(Who {
                    role: "tenant",
                    id: id.clone(),
                    tenant: Some(t.clone()),
                });
            }
        }
        Err((401, "unauthorized".into()))
    }
    fn writable(&self) -> Answer<()> {
        if self.mode == "replica" {
            Err((
                409,
                "this control plane is a replica; writes must go to the primary".into(),
            ))
        } else {
            Ok(())
        }
    }
    /// Validates a training request and copies the training set out, so the fit can run without
    /// the control-plane lock.
    fn training(&self, who: &Who, body: &[u8]) -> Answer<Training> {
        who.operator()?;
        self.writable()?;
        let mut t: Training = if body.is_empty() {
            Training::default()
        } else {
            parse(body)?
        };
        if self.store.data.samples.len() < 2 {
            return Err(bad("need at least two labeled samples"));
        }
        t.samples = self.store.data.samples.clone();
        Ok(t)
    }
    fn install(&mut self, m: ml::Model) -> Answer {
        self.store
            .transaction(|d| {
                d.model = m.clone();
                Ok(())
            })
            .map_err(failed)?;
        Ok(value(m))
    }
    pub fn reconcile(&mut self, now: DateTime<Utc>, force: bool) -> crate::Result<()> {
        if self.store.data.last_policy_id.is_empty() {
            return Ok(());
        }
        let Some(policy) = self
            .store
            .data
            .policies
            .iter()
            .find(|p| p.id == self.store.data.last_policy_id)
            .cloned()
        else {
            return Ok(());
        };
        self.deploy(&policy, now, force)
    }
    fn deploy(&mut self, policy: &Policy, now: DateTime<Utc>, force: bool) -> crate::Result<()> {
        let nodes = self.store.nodes(now);
        if !nodes.iter().any(|n| n.status != "stale") {
            return Ok(());
        }
        let samples: Vec<_> = nodes
            .iter()
            .map(|n| {
                let report = self.store.reports.get(&n.id);
                let stats = report.map(|r| &r["stats"]);
                let fresh = report
                    .and_then(|r| r["reported_at"].as_str())
                    .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                    .is_some_and(|at| now.signed_duration_since(at).num_milliseconds() <= 15000);
                steering::Sample {
                    node_id: n.id.clone(),
                    capacity_pps: n.capacity_pps,
                    offered_pps: stats.map(|s| analytics::n(s, "offered_pps")).unwrap_or(0),
                    pulsing: stats.is_some_and(|s| s["pulsing"] == true),
                    peak_pps: stats
                        .map(|s| analytics::n(s, "pulse_peak_pps"))
                        .unwrap_or(0),
                    fresh,
                }
            })
            .collect();
        let shedding = self.steering.observe_at(&samples, now);
        let health: compiler::TunnelHealth = self
            .store
            .tunnels
            .iter()
            .map(|(node, rows)| {
                (
                    node.clone(),
                    rows.iter()
                        .map(|s| (s.tunnel_id.clone(), s.state.clone()))
                        .collect(),
                )
            })
            .collect();
        let mut fingerprint = nodes.clone();
        for n in &mut fingerprint {
            n.last_seen = zero_time();
        }
        let key = format!(
            "{}{:?}{:?}",
            value(&fingerprint),
            BTreeMap::<_, _>::from_iter(shedding.iter()),
            BTreeMap::<_, _>::from_iter(
                health
                    .iter()
                    .map(|(n, h)| (n, BTreeMap::<_, _>::from_iter(h.iter())))
            )
        );
        if !force && key == self.last_key {
            return Ok(());
        }
        let plan = compiler::plan(policy, &nodes, &shedding, &health);
        let programs = compiler::compile(policy, &nodes, &plan);
        if self.store.data.last_policy_id != policy.id {
            self.store.transaction(|d| {
                d.last_policy_id = policy.id.clone();
                Ok(())
            })?;
        }
        self.store.plan = plan;
        self.store.programs = programs.into_iter().collect();
        self.pipes
            .retain(|id, _| self.store.programs.contains_key(id));
        self.collector
            .forget(&policy.protected.iter().cloned().collect());
        self.last_key = key;
        self.recompiles += 1;
        Ok(())
    }
    fn visible(&self, who: &Who) -> Vec<String> {
        let mut p: HashSet<_> = self
            .collector
            .prefixes()
            .into_iter()
            .filter(|p| who.sees(p))
            .collect();
        if let Some(t) = &who.tenant {
            p.extend(t.prefixes.iter().cloned());
        }
        let mut p: Vec<_> = p.into_iter().collect();
        p.sort();
        p
    }
    fn dispatch(
        &mut self,
        method: &str,
        path: &str,
        query: &HashMap<String, String>,
        headers: &HeaderMap,
        body: &[u8],
        now: DateTime<Utc>,
    ) -> Answer {
        let who = self.auth(headers)?;
        let ms = now.timestamp_millis();
        let parts: Vec<_> = path
            .strip_prefix("/v1/")
            .unwrap_or(path)
            .split('/')
            .collect();
        let id = parts.get(1).copied().unwrap_or("");
        match (method, parts.as_slice()) {
            ("GET", ["state"]) => {
                who.operator()?;
                Ok(value(self.store.snapshot()))
            }
            ("POST", ["promote"]) => {
                who.operator()?;
                if self.mode != "replica" {
                    return Err((409, "this control plane is already the primary".into()));
                }
                self.mode = "primary".into();
                Ok(json!({"mode":"primary"}))
            }
            ("POST", ["nodes", "register"]) => {
                if who.role != "operator" && who.role != "enroll" {
                    return Err((
                        403,
                        "registering a node requires the enrollment or operator credential".into(),
                    ));
                }
                self.writable()?;
                let n: Node = parse(body)?;
                validation::node(&n).map_err(bad)?;
                let (n, token) = self.store.register(n, now).map_err(|e| {
                    if e.contains("different live node") {
                        (409, e)
                    } else {
                        eprintln!("registration failed: {e}");
                        (500, "could not issue a node credential".into())
                    }
                })?;
                self.reconcile(now, false).map_err(failed)?;
                Ok(json!({"node":n,"token":token}))
            }
            ("GET", ["nodes"]) => {
                who.operator()?;
                Ok(value(self.store.nodes(now)))
            }
            ("POST", ["nodes", _, "heartbeat"]) if !id.is_empty() => {
                if !who.acts(id) {
                    return Err((403, "a node may only heartbeat for itself".into()));
                }
                self.writable()?;
                #[derive(Deserialize, Default)]
                #[serde(default)]
                struct Heartbeat {
                    stats: wire::Stats,
                    #[serde(deserialize_with = "crate::model::null_default")]
                    tunnels: Vec<TunnelStatus>,
                }
                let hb: Heartbeat = if body.is_empty() {
                    Heartbeat::default()
                } else {
                    parse(body)?
                };
                let Some(n) = self.store.data.nodes.iter_mut().find(|n| n.id == id) else {
                    return Err((404, "unknown node".into()));
                };
                n.last_seen = now;
                n.status = "ready".into();
                let name = n.name.clone();
                let region = n.region.clone();
                for st in &hb.tunnels {
                    if st.tunnel_id.is_empty() {
                        return Err(bad("tunnel_id required"));
                    }
                    crate::tunnel::validate_status(&st.state).map_err(bad)?;
                }
                if !hb.tunnels.is_empty() {
                    let mut tunnels = hb.tunnels;
                    for t in &mut tunnels {
                        t.reported_at = now;
                    }
                    tunnels.sort_by(|a, b| a.tunnel_id.cmp(&b.tunnel_id));
                    self.store.tunnels.insert(id.into(), tunnels);
                }
                if !body.is_empty() {
                    let stats = value(hb.stats);
                    let report = json!({"node_id":id,"name":name,"region":region,"stats":stats,"reported_at":now});
                    self.store.reports.insert(id.into(), report);
                    let prog = self.store.programs.get(id).cloned().unwrap_or_default();
                    self.collector.observe(id, &stats, &prog, ms);
                }
                self.reconcile(now, false).map_err(failed)?;
                Ok(json!({"status":"ok"}))
            }
            ("GET", ["nodes", _, "program"]) if !id.is_empty() => {
                if !who.acts(id) {
                    return Err((403, "a node may only fetch its own program".into()));
                }
                self.store
                    .programs
                    .get(id)
                    .map(value)
                    .ok_or((404, "no program deployed".into()))
            }
            ("GET", ["nodes", _, "stats"]) if !id.is_empty() => {
                if !who.acts(id) {
                    return Err((403, "a node may only read its own counters".into()));
                }
                self.store
                    .reports
                    .get(id)
                    .cloned()
                    .ok_or((404, "no counters reported for this node".into()))
            }
            ("POST", ["policies"]) => {
                who.operator()?;
                self.writable()?;
                let mut p: Policy = parse(body)?;
                validation::policy(&p).map_err(bad)?;
                if p.challenge_secret.is_empty() && !p.games.is_empty() {
                    p.challenge_secret = store::secret().map_err(failed)?;
                }
                Ok(value(self.store.save_policy(p, now).map_err(failed)?))
            }
            ("GET", ["policies"]) => {
                who.operator()?;
                let mut p = self.store.data.policies.clone();
                p.sort_by(|a, b| (&a.name, &a.id).cmp(&(&b.name, &b.id)));
                Ok(value(p))
            }
            ("POST", ["policies", _, "deploy"]) if !id.is_empty() => {
                who.operator()?;
                self.writable()?;
                let Some(p) = self
                    .store
                    .data
                    .policies
                    .iter()
                    .find(|p| p.id == id)
                    .cloned()
                else {
                    return Err((404, "unknown policy".into()));
                };
                if !self.store.nodes(now).iter().any(|n| n.status == "ready") {
                    return Err((409, "no live nodes registered".into()));
                }
                self.deploy(&p, now, true).map_err(failed)?;
                Ok(
                    json!({"policy_id":p.id,"version":p.version,"announcements":self.store.plan,"nodes":self.store.programs.len(),"datapath":"asic/tcam + fpga + pf_ring zc + ml","ml_ready":self.store.data.model.ready}),
                )
            }
            ("GET", ["fabric"]) => {
                who.operator()?;
                Ok(
                    json!({"announcements":self.store.plan,"programs":self.store.programs.values().collect::<Vec<_>>(),"ml":self.store.data.model}),
                )
            }
            ("GET", ["ml", "samples"]) => {
                who.operator()?;
                Ok(value(&self.store.data.samples))
            }
            ("POST", ["ml", "samples"]) => {
                who.operator()?;
                self.writable()?;
                #[derive(Deserialize)]
                struct Batch {
                    samples: Vec<ml::Sample>,
                }
                let batch: Batch = parse(body)?;
                if batch.samples.is_empty() {
                    return Err(bad("samples required"));
                }
                for (i, s) in batch.samples.iter().enumerate() {
                    ml::validate_sample(s).map_err(|e| bad(format!("samples[{i}]: {e}")))?;
                }
                if self.store.data.samples.len() + batch.samples.len() > 200000 {
                    return Err((413, "training set is limited to 200000 samples".into()));
                }
                let stored = self
                    .store
                    .transaction(|d| {
                        d.samples.extend(batch.samples);
                        Ok(d.samples.len())
                    })
                    .map_err(failed)?;
                Ok(json!({"stored":stored}))
            }
            ("POST", ["ml", "train"]) => {
                // handler() serves this route through train(), which fits outside the lock.
                let m = self.training(&who, body)?.fit()?;
                self.install(m)
            }
            ("GET", ["ml", "model"]) => {
                if who.role != "operator" && who.role != "node" {
                    return Err((
                        403,
                        "reading the model requires a node or operator credential".into(),
                    ));
                }
                Ok(value(&self.store.data.model))
            }
            ("DELETE", ["ml", "model"]) => {
                who.operator()?;
                self.writable()?;
                let m = self
                    .store
                    .transaction(|d| {
                        d.model = ml::Model {
                            withdrawn: true,
                            ..Default::default()
                        };
                        Ok(d.model.clone())
                    })
                    .map_err(failed)?;
                Ok(value(m))
            }
            ("POST", ["ml", "score"]) => {
                who.operator()?;
                let f: Flow = parse(body)?;
                ml::validate_flow(&f).map_err(bad)?;
                let m = &self.store.data.model;
                Ok(json!({"score":ml::score(m,&f),"label":ml::predict(m,&f),"ready":m.ready}))
            }
            ("POST", ["decide"]) => {
                who.operator()?;
                #[derive(Deserialize, Default)]
                #[serde(default)]
                struct Decide {
                    node_id: String,
                    flow: Flow,
                }
                let b: Decide = parse(body)?;
                ml::validate_flow(&b.flow).map_err(bad)?;
                let prog = self
                    .store
                    .programs
                    .get(&b.node_id)
                    .cloned()
                    .ok_or((404, "node has no program".into()))?;
                let p = self
                    .pipes
                    .entry(b.node_id.clone())
                    .or_insert_with(|| Pipeline::new(prog.clone()));
                if p.program.policy_id != prog.policy_id
                    || p.program.version != prog.version
                    || p.program.compiled_at != prog.compiled_at
                {
                    p.load(prog);
                }
                p.model = self.store.data.model.clone();
                let mut d = p.decide(&b.flow, ms);
                d.node_id = b.node_id;
                Ok(value(d))
            }
            ("GET", ["tenants"]) => {
                who.operator()?;
                let mut t = self.store.data.tenants.clone();
                t.sort_by(|a, b| (&a.name, &a.id).cmp(&(&b.name, &b.id)));
                Ok(value(t))
            }
            ("POST", ["tenants"]) => {
                who.operator()?;
                self.writable()?;
                let t: Tenant = parse(body)?;
                validation::tenant(&t).map_err(bad)?;
                Ok(value(self.store.save_tenant(t, now).map_err(failed)?))
            }
            ("POST", ["tenants", _, "token"]) if !id.is_empty() => {
                who.operator()?;
                self.writable()?;
                if !self.store.data.tenants.iter().any(|t| t.id == id) {
                    return Err((404, "unknown tenant".into()));
                }
                let token = self.store.issue(id, true).map_err(failed)?;
                Ok(json!({"tenant_id":id,"token":token}))
            }
            ("DELETE", ["tenants", _]) if !id.is_empty() => {
                who.operator()?;
                self.writable()?;
                if !self.store.data.tenants.iter().any(|t| t.id == id) {
                    return Err((404, "unknown tenant".into()));
                }
                self.store
                    .transaction(|d| {
                        d.tenants.retain(|t| t.id != id);
                        d.tenant_tokens.remove(id);
                        Ok(())
                    })
                    .map_err(failed)?;
                Ok(json!({"deleted":id}))
            }
            ("GET", ["analytics", kind]) if ["overview", "series", "events"].contains(kind) => {
                if who.role != "operator" && who.role != "tenant" {
                    return Err((
                        403,
                        "reading analytics requires a tenant or operator credential".into(),
                    ));
                }
                let span = query
                    .get("window")
                    .filter(|s| !s.is_empty())
                    .map(|s| duration(s))
                    .transpose()
                    .map_err(bad)?
                    .unwrap_or(86400000);
                let window = duration_string(span);
                let prefixes = self.visible(&who);
                match *kind {
                    "overview" => {
                        let summaries: Vec<_> = prefixes
                            .iter()
                            .map(|p| self.collector.summary(p, span, ms))
                            .collect();
                        let mut v = json!({"window":window,"resolution":"1m0s","retention":"24h0m0s","generated":now,"prefixes":summaries});
                        if let Some(t) = who.tenant {
                            v["tenant"] = json!({"id":t.id,"name":t.name});
                        }
                        Ok(v)
                    }
                    "series" => {
                        let prefix = query
                            .get("prefix")
                            .filter(|p| !p.is_empty())
                            .ok_or(bad("prefix required"))?;
                        let step = query
                            .get("step")
                            .filter(|s| !s.is_empty())
                            .map(|s| duration(s))
                            .transpose()
                            .map_err(bad)?
                            .unwrap_or(span / 120);
                        if !who.sees(prefix) {
                            return Err((
                                403,
                                "this credential is not entitled to that prefix".into(),
                            ));
                        }
                        Ok(
                            json!({"prefix":prefix,"window":window,"step":duration_string(step),"points":self.collector.points(prefix,span,step,ms)}),
                        )
                    }
                    _ => {
                        let wanted = query.get("prefix").filter(|p| !p.is_empty());
                        if wanted.is_some_and(|p| !who.sees(p)) {
                            return Err((
                                403,
                                "this credential is not entitled to that prefix".into(),
                            ));
                        }
                        let prefixes = wanted.map(|p| vec![p.clone()]).unwrap_or(prefixes);
                        let mut events: Vec<_> = prefixes
                            .iter()
                            .flat_map(|p| self.collector.events(p, span, ms))
                            .collect();
                        events.sort_by(|a, b| {
                            b["started_at"]
                                .as_str()
                                .cmp(&a["started_at"].as_str())
                                .then_with(|| a["prefix"].as_str().cmp(&b["prefix"].as_str()))
                        });
                        Ok(json!({"window":window,"events":events}))
                    }
                }
            }
            _ => Err((404, "not found".into())),
        }
    }
    pub fn router(state: Shared) -> Router {
        Router::new()
            .route("/health", any(health))
            .route("/metrics", any(metrics_handler))
            .fallback(handler)
            .layer(DefaultBodyLimit::max(4 << 20))
            .with_state(state)
    }
    pub fn metrics(&self) -> crate::Result<String> {
        crate::telemetry::control(self)
    }
    pub fn metric_state(&self) -> MetricState<'_> {
        (self.recompiles, &self.requests, self.steering.levels())
    }
}
pub fn duration(raw: &str) -> crate::Result<i64> {
    let mut number = String::new();
    let mut unit = String::new();
    let mut total = 0.0;
    let flush = |number: &mut String, unit: &mut String, total: &mut f64| -> crate::Result<()> {
        let v: f64 = number.parse().map_err(|_| "invalid duration")?;
        let factor = match unit.as_str() {
            "h" => 3600000.0,
            "m" => 60000.0,
            "s" => 1000.0,
            "ms" => 1.0,
            "us" | "µs" | "μs" => 0.001,
            "ns" => 0.000001,
            _ => return Err("expected a duration such as 15m, 6h or 24h".into()),
        };
        *total += v * factor;
        number.clear();
        unit.clear();
        Ok(())
    };
    for (index, c) in raw.chars().enumerate() {
        if c.is_ascii_digit() || c == '.' || index == 0 && (c == '-' || c == '+') {
            if !unit.is_empty() {
                flush(&mut number, &mut unit, &mut total)?;
            }
            number.push(c);
        } else {
            unit.push(c);
        }
    }
    flush(&mut number, &mut unit, &mut total)?;
    if !total.is_finite() || total <= 0.0 || total > i64::MAX as f64 / 1e6 {
        return Err("duration must be positive and finite".into());
    }
    Ok(total as i64)
}
pub fn duration_string(ms: i64) -> String {
    let seconds = if ms % 1000 == 0 {
        (ms % 60000 / 1000).to_string()
    } else {
        format!("{}.{:03}", ms % 60000 / 1000, ms % 1000)
            .trim_end_matches('0')
            .to_string()
    };
    if ms >= 3600000 {
        format!("{}h{}m{seconds}s", ms / 3600000, ms % 3600000 / 60000)
    } else if ms >= 60000 {
        format!("{}m{seconds}s", ms / 60000)
    } else if ms >= 1000 {
        format!("{seconds}s")
    } else if ms > 0 {
        format!("{ms}ms")
    } else {
        "0s".into()
    }
}

// The lock can be held across a durable write, so it is only ever waited on from the blocking
// pool: waiting on it from an async handler parks one of the runtime's two worker threads.
async fn health(State(s): State<Shared>) -> Json<Value> {
    let mode = tokio::task::spawn_blocking(move || s.lock().unwrap().mode.clone())
        .await
        .unwrap_or_default();
    Json(
        json!({"status":"ok","product":"scrubline-cloud","datapath":"asic-tcam+fpga+pfring-zc+ml","mode":mode}),
    )
}
fn response(result: Answer) -> Response {
    match result {
        Ok(v) => Json(v).into_response(),
        Err((status, message)) => (
            StatusCode::from_u16(status).unwrap(),
            Json(json!({"error":message})),
        )
            .into_response(),
    }
}
async fn handler(
    State(s): State<Shared>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !uri.path().starts_with("/v1/") {
        return response(Err((404, "not found".into())));
    }
    let query: HashMap<_, _> = uri
        .query()
        .map(|q| {
            reqwest::Url::parse(&format!("http://local/?{q}"))
                .unwrap()
                .query_pairs()
                .map(|(a, b)| (a.into_owned(), b.into_owned()))
                .collect()
        })
        .unwrap_or_default();
    let result = tokio::task::spawn_blocking(move || {
        let (mut a, result) = if method == Method::POST && uri.path() == "/v1/ml/train" {
            let result = train(&s, &headers, &body);
            (s.lock().unwrap(), result)
        } else {
            let mut a = s.lock().unwrap();
            let result = a.dispatch(
                method.as_str(),
                uri.path(),
                &query,
                &headers,
                &body,
                Utc::now(),
            );
            (a, result)
        };
        let code = result.as_ref().map(|_| 200).unwrap_or_else(|e| e.0);
        let route = route_label(uri.path());
        *a.requests.entry((route, code)).or_default() += 1;
        result
    })
    .await;
    response(result.unwrap_or_else(|_| Err((500, "request worker failed".into()))))
}
/// Fitting a full training set takes seconds. Holding the lock for that long stalls every
/// heartbeat and program fetch behind it, so only reading the set and storing the model take it.
fn train(s: &Shared, headers: &HeaderMap, body: &[u8]) -> Answer {
    let job = {
        let a = s.lock().unwrap();
        let who = a.auth(headers)?;
        a.training(&who, body)?
    };
    let m = job.fit()?;
    s.lock().unwrap().install(m)
}
fn route_label(path: &str) -> String {
    let parts: Vec<_> = path
        .strip_prefix("/v1/")
        .unwrap_or(path)
        .split('/')
        .collect();
    match parts.as_slice() {
        ["nodes", _, leaf] if ["program", "stats", "heartbeat"].contains(leaf) => {
            format!("nodes/{leaf}")
        }
        ["policies", _, "deploy"] => "policies/deploy".into(),
        ["tenants", _, "token"] => "tenants/token".into(),
        ["tenants", _] => "tenants/delete".into(),
        [single]
            if [
                "state", "promote", "nodes", "policies", "fabric", "tenants", "decide",
            ]
            .contains(single) =>
        {
            (*single).into()
        }
        [group, leaf]
            if *group == "ml" && ["samples", "train", "model", "score"].contains(leaf)
                || *group == "analytics" && ["overview", "series", "events"].contains(leaf) =>
        {
            format!("{group}/{leaf}")
        }
        _ => "unknown".into(),
    }
}
async fn metrics_handler(State(s): State<Shared>, method: Method, headers: HeaderMap) -> Response {
    tokio::task::spawn_blocking(move || {
        let a = s.lock().unwrap();
        if let Err(e) = a.auth(&headers).and_then(|w| w.operator()) {
            return response(Err(e));
        }
        if method != Method::GET {
            return response(Err((405, "GET required".into())));
        }
        match a.metrics() {
            Ok(text) => ([("Content-Type", crate::metrics::CONTENT_TYPE)], text).into_response(),
            Err(e) => {
                eprintln!("metrics: {e}");
                response(Err((500, "could not render metrics".into())))
            }
        }
    })
    .await
    .unwrap_or_else(|_| response(Err((500, "request worker failed".into()))))
}
