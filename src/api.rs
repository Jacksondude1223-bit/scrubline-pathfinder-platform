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
// A string becomes {"error": ...}; an object is sent as the whole body, for the few answers the
// contract gives more than a message.
type Error = (u16, Value);
type Answer<T = Value> = std::result::Result<T, Error>;
fn bad(e: impl ToString) -> Error {
    (400, e.to_string().into())
}
// The API contract answers 503 for a write that could not be made durable: the change was rolled
// back, which is what a caller needs to know to retry it.
fn failed(e: impl ToString) -> Error {
    eprintln!("state operation failed: {}", e.to_string());
    (503, "could not persist control-plane state".into())
}
/// The protected prefixes of a policy that fall within a customer's address space.
fn tenant_prefixes(p: &Policy, tenants: &[Tenant], tenant: &str) -> Answer<Vec<String>> {
    let Some(owner) = tenants.iter().find(|t| t.id == tenant) else {
        return Err(bad(format!("unknown tenant {tenant:?}")));
    };
    let owned: Vec<IpNet> = owner
        .prefixes
        .iter()
        .filter_map(|p| p.parse().ok())
        .collect();
    let prefixes: Vec<String> = p
        .protected
        .iter()
        .filter(|prefix| {
            prefix
                .parse::<IpNet>()
                .is_ok_and(|net| owned.iter().any(|o| o.contains(&net)))
        })
        .cloned()
        .collect();
    if prefixes.is_empty() {
        return Err(bad(format!(
            "tenant {tenant} has no prefix the deployed policy protects; protect one or name the prefixes"
        )));
    }
    Ok(prefixes)
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
    /// A node as the fabric sees it, saying whether its tunnel endpoint was assigned by an operator.
    fn node_view(&self, id: &str, now: DateTime<Utc>) -> Value {
        let n = self
            .store
            .nodes(now)
            .into_iter()
            .find(|n| n.id == id)
            .unwrap_or_default();
        let mut v = value(&n);
        v["tunnel_endpoint_assigned"] = json!(self.store.data.tunnel_endpoints.contains_key(id));
        v
    }
    /// Tunnels belong to the deployed policy, so a change to one is a new version of that policy:
    /// validated whole, made durable, then compiled onto the fabric straight away.
    fn change_tunnels(
        &mut self,
        now: DateTime<Utc>,
        change: impl FnOnce(&mut Policy) -> Answer<()>,
    ) -> Answer<Policy> {
        let Some(mut p) = self
            .store
            .data
            .policies
            .iter()
            .find(|p| !p.id.is_empty() && p.id == self.store.data.last_policy_id)
            .cloned()
        else {
            return Err((
                409,
                "no policy is deployed; tunnels belong to the deployed policy, so deploy one first"
                    .into(),
            ));
        };
        change(&mut p)?;
        validation::policy(&p).map_err(bad)?;
        validation::tunnel_tenants(&p, &self.store.data.tenants).map_err(bad)?;
        let saved = self.store.save_policy(p, now).map_err(failed)?;
        self.deploy(&saved, now, true).map_err(failed)?;
        Ok(saved)
    }
    /// Takes a tunnel off some nodes, or puts it back. A node it is off withdraws its prefixes,
    /// since it has no path to deliver them on.
    fn toggle_tunnel(
        &mut self,
        id: &str,
        body: &[u8],
        disable: bool,
        now: DateTime<Utc>,
    ) -> Answer {
        #[derive(Deserialize)]
        struct Nodes {
            nodes: Vec<String>,
        }
        let req: Nodes = parse(body)?;
        if req.nodes.is_empty() {
            return Err(bad("nodes requires at least one node id"));
        }
        if let Some(unknown) = req
            .nodes
            .iter()
            .find(|n| !self.store.data.nodes.iter().any(|v| &v.id == *n))
        {
            return Err((404, format!("unknown node {unknown:?}").into()));
        }
        let p = self.change_tunnels(now, |p| {
            let Some(t) = p.tunnels.iter_mut().find(|v| v.id == id) else {
                return Err((404, "unknown tunnel".into()));
            };
            for n in &req.nodes {
                t.disabled.retain(|v| v != n);
                if disable {
                    t.disabled.push(n.clone());
                }
            }
            t.disabled.sort();
            Ok(())
        })?;
        let t = p.tunnels.iter().find(|v| v.id == id).cloned();
        Ok(json!({"policy_id":p.id,"version":p.version,"tunnel":t}))
    }
    /// Every tunnel of the deployed policy on every node that carries its prefixes: where it
    /// terminates, what the node built, what its provisioner last reported, its share of the
    /// clean-traffic allowance, and what the fabric is announcing because of it. With a tenant,
    /// only the tunnels allocated to that customer.
    fn tunnel_view(&self, now: DateTime<Utc>, tenant: Option<&str>) -> Value {
        let Some(p) = self
            .store
            .data
            .policies
            .iter()
            .find(|p| !p.id.is_empty() && p.id == self.store.data.last_policy_id)
        else {
            return json!({"policy_id":null,"version":0,"tunnels":[]});
        };
        let nodes = self.store.nodes(now);
        let tunnels: Vec<_> = p
            .tunnels
            .iter()
            .filter(|t| tenant.is_none_or(|wanted| t.tenant == wanted))
            .map(|t| {
                let rows: Vec<_> = nodes
                    .iter()
                    .filter_map(|n| {
                        let enforced = compiler::enforced_prefixes(p, n);
                        let mine: Vec<String> = t
                            .prefixes
                            .iter()
                            .filter(|prefix| enforced.contains(prefix))
                            .cloned()
                            .collect();
                        if mine.is_empty() {
                            return None;
                        }
                        let enabled = !t.disabled.iter().any(|id| id == &n.id);
                        let report = self
                            .store
                            .tunnels
                            .get(&n.id)
                            .and_then(|rows| rows.iter().find(|s| s.tunnel_id == t.id));
                        let (announced, withdrawn): (Vec<_>, Vec<_>) = self
                            .store
                            .plan
                            .iter()
                            .filter(|a| a.node_id == n.id && mine.contains(&a.prefix))
                            .partition(|a| a.state == "announce");
                        let mut row = json!({
                            "node_id": n.id,
                            "name": n.name,
                            "region": n.region,
                            "status": n.status,
                            "endpoint": n.tunnel_src,
                            "endpoint_assigned": self.store.data.tunnel_endpoints.contains_key(&n.id),
                            "enabled": enabled,
                            "state": report.map_or("unreported", |r| r.state.as_str()),
                            "prefixes": mine,
                            "announced": announced.iter().map(|a| &a.prefix).collect::<Vec<_>>(),
                            "withdrawn": withdrawn
                                .iter()
                                .map(|a| json!({"prefix": a.prefix, "reason": a.reason}))
                                .collect::<Vec<_>>(),
                        });
                        if let Some(r) = report {
                            row["reported_at"] = json!(r.reported_at);
                        }
                        if let Some(built) = self
                            .store
                            .programs
                            .get(&n.id)
                            .and_then(|prog| prog.tunnels.iter().find(|v| v.id == t.id))
                        {
                            row["rate_kbps"] = json!(built.rate_kbps);
                        }
                        let problem = if !enabled {
                            "disabled on this node".to_string()
                        } else if n.tunnel_src.is_empty() {
                            format!(
                                "no tunnel endpoint; assign one with PUT /v1/nodes/{}/tunnel-endpoint",
                                n.id
                            )
                        } else {
                            String::new()
                        };
                        match crate::tunnel::for_node(t, n, &mine) {
                            Ok(built) => {
                                row["interface"] = json!(built.interface);
                                row["mtu"] = json!(built.mtu);
                                row["mss_clamp"] = json!(built.mss_clamp);
                            }
                            Err(e) if problem.is_empty() => row["problem"] = json!(e),
                            Err(_) => {}
                        }
                        if !problem.is_empty() {
                            row["problem"] = json!(problem);
                        }
                        Some(row)
                    })
                    .collect();
                json!({
                    "id": t.id,
                    "type": if t.r#type.is_empty() { "gre" } else { t.r#type.as_str() },
                    "direction": if t.direction.is_empty() { "both" } else { t.direction.as_str() },
                    "remote": t.remote,
                    "key": t.key,
                    "prefixes": t.prefixes,
                    "required": t.required,
                    "disabled": t.disabled,
                    "tenant": t.tenant,
                    "rate_mbps": crate::tunnel::rate_mbps(t),
                    "comment": t.comment,
                    "nodes": rows,
                })
            })
            .collect();
        json!({"policy_id":p.id,"version":p.version,"tunnels":tunnels})
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
                        (409, e.into())
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
                // A tunnel reported twice would be withdrawn on one entry while scrubline_tunnel_up
                // reads the other.
                let mut seen = HashSet::new();
                for st in &hb.tunnels {
                    if st.tunnel_id.is_empty() {
                        return Err(bad("tunnel_id required"));
                    }
                    crate::tunnel::validate_status(&st.state).map_err(bad)?;
                    if !seen.insert(&st.tunnel_id) {
                        return Err(bad(format!("duplicate tunnel_id {:?}", st.tunnel_id)));
                    }
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
                validation::tunnel_tenants(&p, &self.store.data.tenants).map_err(bad)?;
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
            ("PUT", ["nodes", _, "tunnel-endpoint"]) if !id.is_empty() => {
                who.operator()?;
                self.writable()?;
                #[derive(Deserialize)]
                struct Endpoint {
                    address: String,
                }
                let e: Endpoint = parse(body)?;
                validation::tunnel_endpoint(&e.address).map_err(bad)?;
                if !self.store.data.nodes.iter().any(|n| n.id == id) {
                    return Err((404, "unknown node".into()));
                }
                // Two nodes terminating tunnels on one address would each take the other's
                // customer replies.
                if let Some(other) = self
                    .store
                    .nodes(now)
                    .into_iter()
                    .find(|n| n.id != id && n.tunnel_src == e.address)
                {
                    return Err((
                        409,
                        format!(
                            "{} is already the tunnel endpoint of {}",
                            e.address, other.id
                        )
                        .into(),
                    ));
                }
                self.store
                    .transaction(|d| {
                        d.tunnel_endpoints.insert(id.into(), e.address.clone());
                        Ok(())
                    })
                    .map_err(failed)?;
                self.reconcile(now, false).map_err(failed)?;
                Ok(value(self.node_view(id, now)))
            }
            ("DELETE", ["nodes", _, "tunnel-endpoint"]) if !id.is_empty() => {
                who.operator()?;
                self.writable()?;
                if !self.store.data.nodes.iter().any(|n| n.id == id) {
                    return Err((404, "unknown node".into()));
                }
                self.store
                    .transaction(|d| {
                        d.tunnel_endpoints.remove(id);
                        Ok(())
                    })
                    .map_err(failed)?;
                self.reconcile(now, false).map_err(failed)?;
                Ok(value(self.node_view(id, now)))
            }
            ("GET", ["tunnels"]) => {
                who.operator()?;
                let tenant = query
                    .get("tenant")
                    .map(String::as_str)
                    .filter(|t| !t.is_empty());
                Ok(self.tunnel_view(now, tenant))
            }
            ("PUT", ["tunnels", _]) if !id.is_empty() => {
                who.operator()?;
                self.writable()?;
                let mut t: Tunnel = parse(body)?;
                if !t.id.is_empty() && t.id != id {
                    return Err(bad(
                        "the tunnel id in the body differs from the one in the path",
                    ));
                }
                t.id = id.into();
                let tenants = self.store.data.tenants.clone();
                let p = self.change_tunnels(now, |p| {
                    // Allocating a tunnel to a customer without naming prefixes carries everything
                    // of theirs the policy protects.
                    if t.prefixes.is_empty() && !t.tenant.is_empty() {
                        t.prefixes = tenant_prefixes(p, &tenants, &t.tenant)?;
                    }
                    match p.tunnels.iter_mut().find(|v| v.id == t.id) {
                        Some(v) => *v = t,
                        None => p.tunnels.push(t),
                    }
                    Ok(())
                })?;
                let saved = p.tunnels.iter().find(|v| v.id == id).cloned();
                Ok(json!({"policy_id":p.id,"version":p.version,"tunnel":saved}))
            }
            ("PUT", ["tunnels", _, "rate"]) if !id.is_empty() => {
                who.operator()?;
                self.writable()?;
                #[derive(Deserialize)]
                struct Rate {
                    rate_mbps: i64,
                }
                let r: Rate = parse(body)?;
                let p = self.change_tunnels(now, |p| {
                    let Some(t) = p.tunnels.iter_mut().find(|v| v.id == id) else {
                        return Err((404, "unknown tunnel".into()));
                    };
                    t.rate_mbps = r.rate_mbps;
                    Ok(())
                })?;
                let saved = p.tunnels.iter().find(|v| v.id == id).cloned();
                Ok(json!({"policy_id":p.id,"version":p.version,"tunnel":saved}))
            }
            ("DELETE", ["tunnels", _]) if !id.is_empty() => {
                who.operator()?;
                self.writable()?;
                let p = self.change_tunnels(now, |p| {
                    if !p.tunnels.iter().any(|v| v.id == id) {
                        return Err((404, "unknown tunnel".into()));
                    }
                    p.tunnels.retain(|v| v.id != id);
                    Ok(())
                })?;
                Ok(json!({"policy_id":p.id,"version":p.version,"deleted":id}))
            }
            ("POST", ["tunnels", _, "disable"]) if !id.is_empty() => {
                who.operator()?;
                self.writable()?;
                self.toggle_tunnel(id, body, true, now)
            }
            ("POST", ["tunnels", _, "enable"]) if !id.is_empty() => {
                who.operator()?;
                self.writable()?;
                self.toggle_tunnel(id, body, false, now)
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
                    return Err((
                        413,
                        json!({"error":"training set is limited to 200000 samples","stored":self.store.data.samples.len()}),
                    ));
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
                let mut t: Tenant = parse(body)?;
                validation::tenant(&t).map_err(bad)?;
                if t.id.is_empty() {
                    t.id = store::id("ten", &[&t.name]);
                }
                // A change to a customer's prefixes must leave every tunnel allocated to them
                // carrying only their own address space.
                let mut tenants = self.store.data.tenants.clone();
                tenants.retain(|v| v.id != t.id);
                tenants.push(t.clone());
                for p in &self.store.data.policies {
                    let allocated = Policy {
                        tunnels: p
                            .tunnels
                            .iter()
                            .filter(|v| v.tenant == t.id)
                            .cloned()
                            .collect(),
                        ..Default::default()
                    };
                    validation::tunnel_tenants(&allocated, &tenants).map_err(|e| {
                        (
                            409,
                            format!("policy {}: {e}; change the tunnel first", p.id).into(),
                        )
                    })?;
                }
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
                if let Some((p, t)) = self
                    .store
                    .data
                    .policies
                    .iter()
                    .find_map(|p| p.tunnels.iter().find(|t| t.tenant == id).map(|t| (p, t)))
                {
                    return Err((
                        409,
                        format!(
                            "tunnel {} in policy {} is allocated to this tenant; delete or reallocate it first",
                            t.id, p.id
                        )
                        .into(),
                    ));
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
                    .unwrap_or(86400000)
                    .min(86400000);
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
                            json!({"prefix":prefix,"window":window,"step":duration_string(analytics::resolution(step)),"points":self.collector.points(prefix,span,step,ms)}),
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
// A lock poisoned by a panicking request fails every call after it, so health must say so: a
// liveness probe that keeps reading "ok" never restarts a control plane that has stopped working.
async fn health(State(s): State<Shared>) -> Response {
    let mode = tokio::task::spawn_blocking(move || s.lock().map(|a| a.mode.clone()).ok())
        .await
        .ok()
        .flatten();
    match mode {
        Some(mode) => Json(
            json!({"status":"ok","product":"scrubline-cloud","datapath":"asic-tcam+fpga+pfring-zc+ml","mode":mode}),
        )
        .into_response(),
        None => response(Err((
            503,
            json!({"status":"error","error":"control-plane state is unusable after an internal failure; restart this process"}),
        ))),
    }
}
fn response(result: Answer) -> Response {
    match result {
        Ok(v) => Json(v).into_response(),
        Err((status, body)) => (
            StatusCode::from_u16(status).unwrap(),
            Json(if body.is_object() {
                body
            } else {
                json!({"error":body})
            }),
        )
            .into_response(),
    }
}
/// Paths arrive percent-encoded and ids are stored decoded, so an id needing escaping would never
/// match its own route otherwise. None for an escape that is not two hex digits, or not UTF-8.
fn decode_path(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes
                .get(i + 1..i + 3)
                .filter(|h| h.iter().all(u8::is_ascii_hexdigit))?;
            out.push(u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}
async fn handler(
    State(s): State<Shared>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(path) = decode_path(uri.path()) else {
        return response(Err((400, "malformed request path".into())));
    };
    if !path.starts_with("/v1/") {
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
        let (mut a, result) = if method == Method::POST && path == "/v1/ml/train" {
            let result = train(&s, &headers, &body);
            (s.lock().unwrap(), result)
        } else {
            let mut a = s.lock().unwrap();
            let result = a.dispatch(method.as_str(), &path, &query, &headers, &body, Utc::now());
            (a, result)
        };
        let code = result.as_ref().map(|_| 200).unwrap_or_else(|e| e.0);
        let route = route_label(&path);
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
        ["nodes", _, "tunnel-endpoint"] => "nodes/tunnel-endpoint".into(),
        ["tunnels", _] => "tunnels/item".into(),
        ["tunnels", _, leaf] if ["disable", "enable", "rate"].contains(leaf) => {
            format!("tunnels/{leaf}")
        }
        [single]
            if [
                "state", "promote", "nodes", "policies", "fabric", "tenants", "decide", "tunnels",
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
