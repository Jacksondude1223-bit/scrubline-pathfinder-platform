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
/// What a tunnel allocated to a customer carries when no prefixes are named: the protected
/// prefixes that are the customer's own, not a nested customer's of theirs, and that no other
/// tunnel already carries.
fn tenant_prefixes(p: &Policy, tenants: &[Tenant], tenant: &str, id: &str) -> Answer<Vec<String>> {
    let Some(owner) = tenants.iter().find(|t| t.id == tenant) else {
        return Err(bad(format!("unknown tenant {tenant:?}")));
    };
    let prefixes: Vec<String> = p
        .protected
        .iter()
        .filter(|prefix| validation::belongs_to(prefix, owner, tenants))
        .filter(|prefix| {
            !p.tunnels
                .iter()
                .any(|t| t.id != id && t.prefixes.contains(prefix))
        })
        .cloned()
        .collect();
    if prefixes.is_empty() {
        return Err(bad(format!(
            "tenant {tenant} has no protected prefix that another tunnel does not already carry; protect one or name the prefixes"
        )));
    }
    Ok(prefixes)
}
/// The answer to a tunnel change: the policy version it made, and the tunnel as saved.
fn tunnel_answer(p: &Policy, id: &str) -> Value {
    let saved = p.tunnels.iter().find(|v| v.id == id);
    json!({"policy_id":p.id,"version":p.version,"tunnel":saved})
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
    /// Tunnel reports to ignore from each node until it fetches its program again, by tunnel id,
    /// or None for all of them: what its agent holds until then is about tunnels since changed.
    fences: HashMap<String, HashSet<Option<String>>>,
    /// Until when each node that was measured overloaded keeps the rest of the fabric helping
    /// with its pinned customers.
    overflow_until: HashMap<String, DateTime<Utc>>,
    /// The nodes the fabric is helping as of the last compile: overloaded, or not heartbeating.
    overflowing: HashSet<String>,
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
            fences: HashMap::new(),
            overflow_until: HashMap::new(),
            overflowing: HashSet::new(),
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
    /// The policy currently deployed onto the fabric, if any.
    fn deployed(&self) -> Option<&Policy> {
        self.store
            .data
            .policies
            .iter()
            .find(|p| !p.id.is_empty() && p.id == self.store.data.last_policy_id)
    }
    /// The node, other than `id`, that holds `addr` as its tunnel endpoint: by an operator's
    /// assignment, which stands whether or not the node is live, or by registration while it is
    /// live. A node that stopped heartbeating long ago does not keep an address it registered
    /// with, or a replaced box could never take its address over.
    fn endpoint_holder(&self, id: &str, addr: &str, now: DateTime<Utc>) -> Option<String> {
        self.store
            .nodes(now)
            .into_iter()
            .find(|n| {
                n.id != id
                    && n.tunnel_src == addr
                    && (n.status != "stale" || self.store.data.tunnel_endpoints.contains_key(&n.id))
            })
            .map(|n| n.id)
    }
    /// Drops what provisioners last reported about tunnels that are being rebuilt or taken down,
    /// so a required tunnel has to report up again before its prefixes are announced, rather than
    /// riding on a report about the tunnel it replaced.
    fn forget_health(&mut self, node: Option<&str>, tunnel: Option<&str>) {
        for (n, rows) in self.store.tunnels.iter_mut() {
            if node.is_none_or(|id| id == n) {
                rows.retain(|r| tunnel.is_some_and(|t| t != r.tunnel_id));
            }
        }
        self.store.tunnels.retain(|_, rows| !rows.is_empty());
        // The agent reports on every heartbeat what its provisioner last said, and only learns of
        // the change when it next fetches its program, so until then its reports are about the
        // tunnels as they were.
        for n in &self.store.data.nodes {
            if node.is_none_or(|id| id == n.id) {
                self.fences
                    .entry(n.id.clone())
                    .or_default()
                    .insert(tunnel.map(String::from));
            }
        }
    }
    /// Tunnels belong to the deployed policy, so a change to one is a new version of that policy:
    /// validated whole, made durable, then compiled onto the fabric straight away. `forget` names
    /// the (node, tunnel) reports the change makes stale, dropped before the fabric recompiles.
    fn change_tunnels(
        &mut self,
        now: DateTime<Utc>,
        forget: &[(Option<&str>, Option<&str>)],
        change: impl FnOnce(&mut Policy) -> Answer<()>,
    ) -> Answer<Policy> {
        let Some(mut p) = self.deployed().cloned() else {
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
        for (node, tunnel) in forget {
            self.forget_health(*node, *tunnel);
        }
        // With no node live, deploy compiles nothing; forgetting the last compile makes the next
        // reconcile with a live node compile this version instead of finding nothing changed.
        self.last_key.clear();
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
        let forget: Vec<_> = req
            .nodes
            .iter()
            .map(|n| (Some(n.as_str()), Some(id)))
            .collect();
        let p = self.change_tunnels(now, &forget, |p| {
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
        Ok(tunnel_answer(&p, id))
    }
    /// Every tunnel of the deployed policy on every node that carries its prefixes: where it
    /// terminates, what the node built, what its provisioner last reported, its share of the
    /// clean-traffic allowance, and what the fabric is announcing because of it. With a tenant,
    /// only the tunnels allocated to that customer.
    fn tunnel_view(&self, now: DateTime<Utc>, tenant: Option<&str>) -> Value {
        let Some(p) = self.deployed() else {
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
                        let role = if t.node.is_empty() {
                            "member"
                        } else if t.node == n.id {
                            "location"
                        } else {
                            "helper"
                        };
                        let standing_by = role == "helper" && !self.overflowing.contains(&t.node);
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
                            "role": role,
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
                            let registered = self
                                .store
                                .data
                                .nodes
                                .iter()
                                .find(|v| v.id == n.id)
                                .map(|v| v.tunnel_src.as_str())
                                .unwrap_or("");
                            if registered.is_empty() {
                                format!(
                                    "no tunnel endpoint; assign one with PUT /v1/nodes/{}/tunnel-endpoint",
                                    n.id
                                )
                            } else {
                                format!(
                                    "the tunnel endpoint it registered, {registered}, is held by another node; assign it its own with PUT /v1/nodes/{}/tunnel-endpoint",
                                    n.id
                                )
                            }
                        } else {
                            String::new()
                        };
                        if role == "helper" {
                            // A helper's part is the tunnel it forwards to the location over.
                            row["standing_by"] = json!(standing_by);
                            if let Some(b) = self.store.programs.get(&n.id).and_then(|prog| {
                                prog.backhaul.iter().find(|b| b.peer == t.node)
                            }) {
                                row["interface"] = json!(b.interface);
                                row["mtu"] = json!(b.mtu);
                                row["mss_clamp"] = json!(b.mss_clamp);
                            }
                        } else {
                            match crate::tunnel::for_node(t, n, &mine) {
                                Ok(built) => {
                                    row["interface"] = json!(built.interface);
                                    row["mtu"] = json!(built.mtu);
                                    row["mss_clamp"] = json!(built.mss_clamp);
                                }
                                Err(e) if problem.is_empty() => row["problem"] = json!(e),
                                Err(_) => {}
                            }
                        }
                        if !problem.is_empty() {
                            row["problem"] = json!(problem);
                        } else if row.get("problem").is_none() && !standing_by {
                            if let Some(a) = withdrawn.first() {
                                row["problem"] = json!(a.reason);
                            }
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
                    "node": t.node,
                    "location": nodes.iter().find(|n| n.id == t.node).map(|n| &n.name),
                    "overflow": !t.node.is_empty() && self.overflowing.contains(&t.node),
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
        for (node, level) in &shedding {
            if *level > 0 {
                self.overflow_until
                    .insert(node.clone(), now + steering::OVERFLOW_HOLD);
            }
        }
        self.overflow_until.retain(|_, until| *until > now);
        let overflowing: HashSet<String> = self
            .overflow_until
            .keys()
            .cloned()
            .chain(
                nodes
                    .iter()
                    .filter(|n| n.status == "stale")
                    .map(|n| n.id.clone()),
            )
            .collect();
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
            "{}{:?}{:?}{:?}",
            value(&fingerprint),
            std::collections::BTreeSet::<_>::from_iter(overflowing.iter()),
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
        let plan = compiler::plan_with(policy, &nodes, &shedding, &health, &overflowing);
        self.overflowing = overflowing;
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
                let nid = if n.id.is_empty() {
                    store::id("node", &[&n.name, &n.region])
                } else {
                    n.id.clone()
                };
                // A node with an operator's assignment does not use what it registers with.
                if !n.tunnel_src.is_empty() && !self.store.data.tunnel_endpoints.contains_key(&nid)
                {
                    if let Some(other) = self.endpoint_holder(&nid, &n.tunnel_src, now) {
                        return Err((
                            409,
                            format!("{} is already the tunnel endpoint of {other}", n.tunnel_src)
                                .into(),
                        ));
                    }
                }
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
                    tunnels: Option<Vec<TunnelStatus>>,
                }
                let hb: Heartbeat = if body.is_empty() {
                    Heartbeat::default()
                } else {
                    parse(body)?
                };
                let Some(n) = self.store.data.nodes.iter_mut().find(|n| n.id == id) else {
                    return Err((404, "unknown node".into()));
                };
                let fenced = self.fences.get(id);
                n.last_seen = now;
                n.status = "ready".into();
                let name = n.name.clone();
                let region = n.region.clone();
                // A tunnel reported twice would be withdrawn on one entry while scrubline_tunnel_up
                // reads the other.
                let mut seen = HashSet::new();
                for st in hb.tunnels.iter().flatten() {
                    if st.tunnel_id.is_empty() {
                        return Err(bad("tunnel_id required"));
                    }
                    crate::tunnel::validate_status(&st.state).map_err(bad)?;
                    if !seen.insert(&st.tunnel_id) {
                        return Err(bad(format!("duplicate tunnel_id {:?}", st.tunnel_id)));
                    }
                }
                // A list, even an empty one, is everything the provisioner is saying now; leaving the
                // field out says nothing.
                if let Some(mut tunnels) = hb.tunnels {
                    tunnels.retain(|t| {
                        fenced.is_none_or(|f| {
                            !f.contains(&None) && !f.contains(&Some(t.tunnel_id.clone()))
                        })
                    });
                    for t in &mut tunnels {
                        t.reported_at = now;
                    }
                    tunnels.sort_by(|a, b| a.tunnel_id.cmp(&b.tunnel_id));
                    if tunnels.is_empty() {
                        self.store.tunnels.remove(id);
                    } else {
                        self.store.tunnels.insert(id.into(), tunnels);
                    }
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
                if who.role == "node" {
                    self.fences.remove(id);
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
                if let Some(other) = self.endpoint_holder(id, &e.address, now) {
                    return Err((
                        409,
                        format!("{} is already the tunnel endpoint of {other}", e.address).into(),
                    ));
                }
                if let Some(p) = self.deployed() {
                    if let Some(t) = p.tunnels.iter().find(|t| t.remote == e.address) {
                        return Err(bad(format!(
                            "{} is the customer end of tunnel {}; a node's end must be its own address",
                            e.address, t.id
                        )));
                    }
                    // The fabric anycasts every protected prefix, so a tunnel aimed at an address
                    // inside one is drawn to the nearest scrubber rather than to this node.
                    let addr: std::net::IpAddr = e.address.parse().map_err(bad)?;
                    if let Some(prefix) = p
                        .protected
                        .iter()
                        .find(|v| v.parse::<IpNet>().is_ok_and(|net| net.contains(&addr)))
                    {
                        return Err(bad(format!(
                            "{} is inside protected prefix {prefix}, which the fabric anycasts",
                            e.address
                        )));
                    }
                }
                let before = self.node_view(id, now)["tunnel_src"].clone();
                self.store
                    .transaction(|d| {
                        d.tunnel_endpoints.insert(id.into(), e.address.clone());
                        Ok(())
                    })
                    .map_err(failed)?;
                if before != json!(e.address) {
                    self.forget_health(Some(id), None);
                }
                self.reconcile(now, false).map_err(failed)?;
                Ok(value(self.node_view(id, now)))
            }
            ("DELETE", ["nodes", _, "tunnel-endpoint"]) if !id.is_empty() => {
                who.operator()?;
                self.writable()?;
                let Some(registered) = self
                    .store
                    .data
                    .nodes
                    .iter()
                    .find(|n| n.id == id)
                    .map(|n| n.tunnel_src.clone())
                else {
                    return Err((404, "unknown node".into()));
                };
                // The node falls back to the address it registered with, which another node may
                // have been given since.
                if !registered.is_empty() {
                    if let Some(other) = self.endpoint_holder(id, &registered, now) {
                        return Err((
                            409,
                            format!(
                                "this node would fall back to {registered}, which is now the tunnel endpoint of {other}; assign it another address instead"
                            )
                            .into(),
                        ));
                    }
                }
                let assigned = self
                    .store
                    .data
                    .tunnel_endpoints
                    .get(id)
                    .is_some_and(|a| *a != registered);
                self.store
                    .transaction(|d| {
                        d.tunnel_endpoints.remove(id);
                        Ok(())
                    })
                    .map_err(failed)?;
                if assigned {
                    self.forget_health(Some(id), None);
                }
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
                if let Some(unknown) = t
                    .disabled
                    .iter()
                    .find(|n| !self.store.data.nodes.iter().any(|v| &v.id == *n))
                {
                    return Err(bad(format!(
                        "disabled lists {unknown:?}, which is not a registered node id"
                    )));
                }
                if !t.node.is_empty() && !self.store.data.nodes.iter().any(|v| v.id == t.node) {
                    return Err(bad(format!(
                        "node {:?} is not a registered node id",
                        t.node
                    )));
                }
                // A tunnel rebuilt to another remote, key or encapsulation is a new tunnel, and
                // what was reported about the old one says nothing about it. Nor does a report from
                // before a node stopped building it say anything once it builds it again.
                let old = self
                    .deployed()
                    .and_then(|p| p.tunnels.iter().find(|v| v.id == t.id))
                    .cloned();
                let toggled: Option<Vec<String>> = match &old {
                    Some(v)
                        if v.remote == t.remote
                            && v.key == t.key
                            && v.r#type == t.r#type
                            && v.node == t.node =>
                    {
                        Some(
                            v.disabled
                                .iter()
                                .filter(|n| !t.disabled.contains(n))
                                .chain(t.disabled.iter().filter(|n| !v.disabled.contains(n)))
                                .cloned()
                                .collect(),
                        )
                    }
                    _ => None,
                };
                let forget: Vec<(Option<&str>, Option<&str>)> = match &toggled {
                    Some(nodes) => nodes.iter().map(|n| (Some(n.as_str()), Some(id))).collect(),
                    None => vec![(None, Some(id))],
                };
                let tenants = self.store.data.tenants.clone();
                let p = self.change_tunnels(now, &forget, |p| {
                    // Allocating a tunnel to a customer without naming prefixes carries their own
                    // protected prefixes that no other tunnel carries.
                    if t.prefixes.is_empty() && !t.tenant.is_empty() {
                        t.prefixes = tenant_prefixes(p, &tenants, &t.tenant, &t.id)?;
                    }
                    match p.tunnels.iter_mut().find(|v| v.id == t.id) {
                        Some(v) => *v = t,
                        None => p.tunnels.push(t),
                    }
                    Ok(())
                })?;
                Ok(tunnel_answer(&p, id))
            }
            ("PUT", ["tunnels", _, "rate"]) if !id.is_empty() => {
                who.operator()?;
                self.writable()?;
                #[derive(Deserialize)]
                struct Rate {
                    rate_mbps: i64,
                }
                let r: Rate = parse(body)?;
                let p = self.change_tunnels(now, &[], |p| {
                    let Some(t) = p.tunnels.iter_mut().find(|v| v.id == id) else {
                        return Err((404, "unknown tunnel".into()));
                    };
                    t.rate_mbps = r.rate_mbps;
                    Ok(())
                })?;
                Ok(tunnel_answer(&p, id))
            }
            ("PUT", ["tunnels", _, "location"]) if !id.is_empty() => {
                who.operator()?;
                self.writable()?;
                #[derive(Deserialize)]
                struct Location {
                    node: String,
                }
                let l: Location = parse(body)?;
                if !l.node.is_empty() && !self.store.data.nodes.iter().any(|v| v.id == l.node) {
                    return Err(bad(format!(
                        "node {:?} is not a registered node id",
                        l.node
                    )));
                }
                // Moving the customer's tunnel builds it somewhere else, and nothing reported about
                // where it was says anything about where it is now.
                let p = self.change_tunnels(now, &[(None, Some(id))], |p| {
                    let Some(t) = p.tunnels.iter_mut().find(|v| v.id == id) else {
                        return Err((404, "unknown tunnel".into()));
                    };
                    t.node = l.node;
                    Ok(())
                })?;
                Ok(tunnel_answer(&p, id))
            }
            ("DELETE", ["tunnels", _]) if !id.is_empty() => {
                who.operator()?;
                self.writable()?;
                let p = self.change_tunnels(now, &[(None, Some(id))], |p| {
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
        ["tunnels", _, leaf] if ["disable", "enable", "rate", "location"].contains(leaf) => {
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
#[cfg(test)]
mod tests {
    use super::*;
    const OP: &str = "operator";
    const ENROLL: &str = "enroll";
    fn at(seconds: i64) -> DateTime<Utc> {
        "2026-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap()
            + chrono::Duration::seconds(seconds)
    }
    fn call(
        a: &mut Api,
        now: i64,
        method: &str,
        path: &str,
        token: &str,
        body: Value,
    ) -> (u16, Value) {
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", format!("Bearer {token}").parse().unwrap());
        let raw = if body.is_null() {
            vec![]
        } else {
            serde_json::to_vec(&body).unwrap()
        };
        match a.dispatch(method, path, &HashMap::new(), &headers, &raw, at(now)) {
            Ok(v) => (200, v),
            Err((code, v)) => (code, v),
        }
    }
    fn api() -> Api {
        Api::new(
            Store::open("").unwrap(),
            OP.into(),
            ENROLL.into(),
            "primary".into(),
        )
    }
    /// Registers a node and returns its id and credential.
    fn register(a: &mut Api, now: i64, name: &str, src: &str) -> (String, String) {
        let body = json!({"name":name,"region":"iad","tunnel_src":src});
        let (status, reg) = call(a, now, "POST", "/v1/nodes/register", ENROLL, body);
        assert_eq!(status, 200, "{reg}");
        (
            reg["node"]["id"].as_str().unwrap().into(),
            reg["token"].as_str().unwrap().into(),
        )
    }
    fn deploy(a: &mut Api, now: i64, tunnel: Value) {
        let policy = json!({"id":"p","name":"p","protected":["203.0.113.0/24"],"tunnels":[tunnel]});
        assert_eq!(call(a, now, "POST", "/v1/policies", OP, policy).0, 200);
        assert_eq!(
            call(a, now, "POST", "/v1/policies/p/deploy", OP, Value::Null).0,
            200
        );
    }
    fn state(a: &Api, node: &str) -> (String, String) {
        let row = a.store.plan.iter().find(|r| r.node_id == node).unwrap();
        (row.state.clone(), row.reason.clone())
    }
    fn endpoint(a: &mut Api, now: i64, method: &str, node: &str, addr: &str) -> (u16, Value) {
        let body = if addr.is_empty() {
            Value::Null
        } else {
            json!({"address":addr})
        };
        call(
            a,
            now,
            method,
            &format!("/v1/nodes/{node}/tunnel-endpoint"),
            OP,
            body,
        )
    }
    #[test]
    fn a_tunnel_change_made_while_no_node_is_live_reaches_the_fabric_when_one_returns() {
        let mut a = api();
        let (node, token) = register(&mut a, 0, "edge-a", "192.0.2.1");
        deploy(
            &mut a,
            0,
            json!({"id":"nw","remote":"198.51.100.1","prefixes":["203.0.113.0/24"]}),
        );
        assert_eq!(a.store.programs[&node].tunnels.len(), 1);
        let off = json!({"nodes":[node]});
        assert_eq!(
            call(&mut a, 45, "POST", "/v1/tunnels/nw/disable", OP, off).0,
            200
        );
        let beat = format!("/v1/nodes/{node}/heartbeat");
        assert_eq!(call(&mut a, 46, "POST", &beat, &token, Value::Null).0, 200);
        assert_eq!(a.store.programs[&node].version, 2);
        assert!(a.store.programs[&node].tunnels.is_empty());
        assert_eq!(state(&a, &node).0, "withdraw");
    }
    #[test]
    fn no_two_nodes_end_up_on_one_tunnel_address() {
        let mut a = api();
        let (na, _) = register(&mut a, 0, "edge-a", "");
        let (nb, _) = register(&mut a, 0, "edge-b", "192.0.2.2");
        assert_eq!(endpoint(&mut a, 0, "PUT", &nb, "192.0.2.3").0, 200);
        // B's registered address is shadowed by its assignment, so A may take it...
        assert_eq!(endpoint(&mut a, 0, "PUT", &na, "192.0.2.2").0, 200);
        // ...but B cannot then fall back onto it.
        let (status, body) = endpoint(&mut a, 0, "DELETE", &nb, "");
        assert_eq!(status, 409, "{body}");
        assert!(body.as_str().unwrap().contains(&na), "{body}");
        // Nor can a new node register with an address an operator assigned elsewhere.
        let taken = json!({"name":"edge-c","region":"iad","tunnel_src":"192.0.2.3"});
        assert_eq!(
            call(&mut a, 0, "POST", "/v1/nodes/register", ENROLL, taken).0,
            409
        );
        // A node that has stopped heartbeating does not hold the address it registered with, so
        // a replacement box can take it over.
        let (nd, _) = register(&mut a, 0, "edge-d", "192.0.2.4");
        let replacement = json!({"name":"edge-e","region":"iad","tunnel_src":"192.0.2.4"});
        assert_eq!(
            call(
                &mut a,
                1,
                "POST",
                "/v1/nodes/register",
                ENROLL,
                replacement.clone()
            )
            .0,
            409
        );
        assert_eq!(
            call(
                &mut a,
                60,
                "POST",
                "/v1/nodes/register",
                ENROLL,
                replacement
            )
            .0,
            200
        );
        // An assignment holds whether or not its node is live.
        assert_eq!(endpoint(&mut a, 60, "PUT", &nd, "192.0.2.5").0, 200);
        let late = json!({"name":"edge-f","region":"iad","tunnel_src":"192.0.2.5"});
        assert_eq!(
            call(&mut a, 120, "POST", "/v1/nodes/register", ENROLL, late).0,
            409
        );
    }
    #[test]
    fn an_endpoint_must_be_the_nodes_own_address() {
        let mut a = api();
        let (node, _) = register(&mut a, 0, "edge-a", "192.0.2.1");
        deploy(
            &mut a,
            0,
            json!({"id":"nw","remote":"198.51.100.1","prefixes":["203.0.113.0/24"]}),
        );
        let (status, body) = endpoint(&mut a, 0, "PUT", &node, "198.51.100.1");
        assert_eq!(status, 400, "the customer's end: {body}");
        let (status, body) = endpoint(&mut a, 0, "PUT", &node, "203.0.113.7");
        assert_eq!(status, 400, "inside an anycast prefix: {body}");
        assert_eq!(endpoint(&mut a, 0, "PUT", &node, "192.0.2.9").0, 200);
    }
    #[test]
    fn a_required_tunnel_reports_up_again_after_it_is_taken_down_or_rebuilt() {
        let mut a = api();
        let (node, token) = register(&mut a, 0, "edge-a", "192.0.2.1");
        let tunnel = json!({"id":"nw","remote":"198.51.100.1","prefixes":["203.0.113.0/24"],"required":true});
        deploy(&mut a, 0, tunnel.clone());
        let beat = format!("/v1/nodes/{node}/heartbeat");
        let fetch = format!("/v1/nodes/{node}/program");
        let up = json!({"tunnels":[{"tunnel_id":"nw","state":"up"}]});
        // The agent's loop: report what the provisioner last said, then fetch the program.
        let agent = |a: &mut Api, now: i64| {
            assert_eq!(call(a, now, "POST", &beat, &token, up.clone()).0, 200);
            assert_eq!(call(a, now, "GET", &fetch, &token, Value::Null).0, 200);
        };
        agent(&mut a, 1);
        assert_eq!(state(&a, &node).0, "announce");
        let nodes = json!({"nodes":[node]});
        let toggle = |a: &mut Api, now, action: &str| {
            let path = format!("/v1/tunnels/nw/{action}");
            assert_eq!(call(a, now, "POST", &path, OP, nodes.clone()).0, 200);
        };
        toggle(&mut a, 2, "disable");
        toggle(&mut a, 3, "enable");
        let unreported = "return tunnel nw is required and has not reported up";
        assert_eq!(state(&a, &node), ("withdraw".into(), unreported.into()));
        let (_, view) = call(&mut a, 3, "GET", "/v1/tunnels", OP, Value::Null);
        let row = &view["tunnels"][0]["nodes"][0];
        assert_eq!(
            (&row["state"], &row["problem"]),
            (&json!("unreported"), &json!(unreported))
        );
        // The heartbeat the agent sends before it learns of the change carries what it held for
        // the tunnel before it, and is not taken as a report on the tunnel now.
        agent(&mut a, 4);
        assert_eq!(state(&a, &node).0, "withdraw");
        agent(&mut a, 5);
        assert_eq!(state(&a, &node).0, "announce");
        // Changing only what does not rebuild the tunnel keeps its report...
        let mut changed = tunnel.clone();
        changed["rate_mbps"] = json!(100);
        assert_eq!(
            call(&mut a, 6, "PUT", "/v1/tunnels/nw", OP, changed.clone()).0,
            200
        );
        assert_eq!(state(&a, &node).0, "announce");
        // ...while a new remote is a new tunnel, which has to report for itself.
        changed["remote"] = json!("198.51.100.2");
        assert_eq!(call(&mut a, 7, "PUT", "/v1/tunnels/nw", OP, changed).0, 200);
        assert_eq!(state(&a, &node).0, "withdraw");
        agent(&mut a, 8);
        assert_eq!(state(&a, &node).0, "withdraw");
        agent(&mut a, 9);
        assert_eq!(state(&a, &node).0, "announce");
        // So is one built from another address.
        assert_eq!(endpoint(&mut a, 10, "PUT", &node, "192.0.2.9").0, 200);
        assert_eq!(state(&a, &node).0, "withdraw", "moved to another address");
        agent(&mut a, 11);
        agent(&mut a, 12);
        assert_eq!(state(&a, &node).0, "announce");
        // A disabled entry dropped by a whole-tunnel PUT is the same as enabling it.
        let mut off = json!({"id":"nw","remote":"198.51.100.2","prefixes":["203.0.113.0/24"],"required":true,"rate_mbps":100});
        off["disabled"] = json!([node]);
        assert_eq!(
            call(&mut a, 13, "PUT", "/v1/tunnels/nw", OP, off.clone()).0,
            200
        );
        off["disabled"] = json!([]);
        assert_eq!(call(&mut a, 14, "PUT", "/v1/tunnels/nw", OP, off).0, 200);
        assert_eq!(state(&a, &node), ("withdraw".into(), unreported.into()));
        // An empty list is the provisioner saying it holds nothing up now.
        agent(&mut a, 15);
        agent(&mut a, 16);
        assert_eq!(state(&a, &node).0, "announce");
        let none = json!({"tunnels":[]});
        assert_eq!(
            call(
                &mut a,
                17,
                "POST",
                &format!("/v1/nodes/{node}/heartbeat"),
                &token,
                none
            )
            .0,
            200
        );
        assert_eq!(state(&a, &node), ("withdraw".into(), unreported.into()));
    }
    #[test]
    fn a_node_that_comes_back_to_find_its_address_reassigned_withdraws_instead_of_sharing_it() {
        let mut a = api();
        let (na, ta) = register(&mut a, 0, "edge-a", "192.0.2.4");
        let (nb, _) = register(&mut a, 0, "edge-b", "192.0.2.5");
        deploy(
            &mut a,
            0,
            json!({"id":"nw","remote":"198.51.100.1","prefixes":["203.0.113.0/24"]}),
        );
        // edge-a goes quiet long enough to be stale, and its address is given to edge-b.
        assert_eq!(endpoint(&mut a, 40, "PUT", &nb, "192.0.2.4").0, 200);
        let beat = format!("/v1/nodes/{na}/heartbeat");
        assert_eq!(call(&mut a, 41, "POST", &beat, &ta, Value::Null).0, 200);
        let nodes = a.store.nodes(at(41));
        let src = |id: &str| {
            nodes
                .iter()
                .find(|n| n.id == id)
                .unwrap()
                .tunnel_src
                .clone()
        };
        assert_eq!((src(&na), src(&nb)), ("".into(), "192.0.2.4".into()));
        assert_eq!(state(&a, &na).0, "withdraw");
        let (_, view) = call(&mut a, 41, "GET", "/v1/tunnels", OP, Value::Null);
        let rows = view["tunnels"][0]["nodes"].as_array().unwrap().clone();
        let row = rows.iter().find(|r| r["node_id"] == na.as_str()).unwrap();
        assert!(
            row["problem"]
                .as_str()
                .unwrap()
                .contains("held by another node"),
            "{row}"
        );
    }
    #[test]
    fn an_endpoint_inside_a_protected_prefix_withdraws_however_it_got_there() {
        let mut a = api();
        let (node, _) = register(&mut a, 0, "edge-a", "198.51.100.7");
        // The policy comes to protect the prefix the node's address is in.
        let policy = json!({"id":"p","name":"p","protected":["203.0.113.0/24","198.51.100.0/24"],
            "tunnels":[{"id":"nw","remote":"192.0.2.200","prefixes":["203.0.113.0/24"]}]});
        assert_eq!(call(&mut a, 0, "POST", "/v1/policies", OP, policy).0, 200);
        assert_eq!(
            call(&mut a, 0, "POST", "/v1/policies/p/deploy", OP, Value::Null).0,
            200
        );
        let row = a
            .store
            .plan
            .iter()
            .find(|r| r.node_id == node && r.prefix == "203.0.113.0/24")
            .unwrap();
        assert_eq!(row.state, "withdraw");
        assert!(
            row.reason
                .contains("inside protected prefix 198.51.100.0/24"),
            "{}",
            row.reason
        );
        assert!(a.store.programs[&node].tunnels.is_empty());
    }
    #[test]
    fn allocating_without_prefixes_takes_only_the_customers_own() {
        let mut a = api();
        register(&mut a, 0, "edge-a", "192.0.2.1");
        let tenant = |a: &mut Api, name: &str, prefixes: Value| {
            let body = json!({"name":name,"prefixes":prefixes});
            call(a, 0, "POST", "/v1/tenants", OP, body).1["id"]
                .as_str()
                .unwrap()
                .to_string()
        };
        let reseller = tenant(&mut a, "reseller", json!(["203.0.112.0/22"]));
        let customer = tenant(&mut a, "customer", json!(["203.0.113.0/24"]));
        let policy = json!({"id":"p","name":"p",
            "protected":["203.0.112.0/24","203.0.113.0/24","203.0.114.0/24"],
            "tunnels":[{"id":"taken","remote":"198.18.0.9","prefixes":["203.0.114.0/24"]}]});
        assert_eq!(call(&mut a, 0, "POST", "/v1/policies", OP, policy).0, 200);
        assert_eq!(
            call(&mut a, 0, "POST", "/v1/policies/p/deploy", OP, Value::Null).0,
            200
        );
        // The reseller's tunnel takes neither its customer's /24, which that customer covers more
        // specifically, nor the /24 another tunnel already carries.
        let body = json!({"remote":"198.18.0.10","tenant":reseller});
        let (status, r) = call(&mut a, 0, "PUT", "/v1/tunnels/resale", OP, body);
        assert_eq!(status, 200, "{r}");
        assert_eq!(r["tunnel"]["prefixes"], json!(["203.0.112.0/24"]));
        let body = json!({"remote":"198.18.0.11","tenant":customer});
        let (status, c) = call(&mut a, 0, "PUT", "/v1/tunnels/cust", OP, body);
        assert_eq!(status, 200, "{c}");
        assert_eq!(c["tunnel"]["prefixes"], json!(["203.0.113.0/24"]));
        // Named explicitly, a reseller may still carry its customer's prefix.
        let body = json!({"remote":"198.18.0.12","tenant":reseller,"prefixes":["203.0.113.0/24"]});
        assert_eq!(call(&mut a, 0, "PUT", "/v1/tunnels/cust", OP, body).0, 200);
        // With nothing left of its own, allocation says so rather than taking a prefix in use.
        let body = json!({"remote":"198.18.0.13","tenant":customer});
        let (status, e) = call(&mut a, 0, "PUT", "/v1/tunnels/again", OP, body);
        assert_eq!(status, 400, "{e}");
    }
    #[test]
    fn other_nodes_join_in_while_a_pinned_tunnels_location_is_overloaded() {
        let mut a = api();
        let reg = |a: &mut Api, name: &str, src: &str| {
            let body =
                json!({"name":name,"region":"iad","tunnel_src":src,"capacity_pps":1_000_000});
            let (_, r) = call(a, 0, "POST", "/v1/nodes/register", ENROLL, body);
            (
                r["node"]["id"].as_str().unwrap().to_string(),
                r["token"].as_str().unwrap().to_string(),
            )
        };
        let (lhr, lhr_token) = reg(&mut a, "lhr", "192.0.2.1");
        let (fra, fra_token) = reg(&mut a, "fra", "192.0.2.2");
        deploy(
            &mut a,
            0,
            json!({"id":"nw","remote":"198.51.100.1","prefixes":["203.0.113.0/24"],"node":lhr}),
        );
        let state_of = |a: &Api, node: &str| state(a, node).0;
        assert_eq!(
            (state_of(&a, &lhr), state_of(&a, &fra)),
            ("announce".into(), "withdraw".into())
        );
        let beat = |a: &mut Api, now: i64, node: &str, token: &str, pps: u64| {
            let body = json!({"stats":{"offered_pps":pps}});
            let path = format!("/v1/nodes/{node}/heartbeat");
            assert_eq!(call(a, now, "POST", &path, token, body).0, 200);
        };
        // lhr runs at 90% of what it can take: fra starts announcing too.
        beat(&mut a, 1, &fra, &fra_token, 0);
        beat(&mut a, 1, &lhr, &lhr_token, 900_000);
        assert_eq!(state_of(&a, &fra), "announce");
        let (_, view) = call(&mut a, 1, "GET", "/v1/tunnels", OP, Value::Null);
        assert_eq!(view["tunnels"][0]["overflow"], true);
        // Help brings lhr's load down, but it goes on until lhr has been calm for a while.
        for s in (31..=300).step_by(30) {
            beat(&mut a, s, &fra, &fra_token, 0);
            beat(&mut a, s, &lhr, &lhr_token, 100_000);
        }
        assert_eq!(state_of(&a, &fra), "announce", "still inside the hold");
        for s in (330..=420).step_by(30) {
            beat(&mut a, s, &fra, &fra_token, 0);
            beat(&mut a, s, &lhr, &lhr_token, 100_000);
        }
        let (status, reason) = state(&a, &fra);
        assert_eq!(status, "withdraw");
        assert!(reason.starts_with("standing by"), "{reason}");
        let (_, view) = call(&mut a, 420, "GET", "/v1/tunnels", OP, Value::Null);
        let rows = view["tunnels"][0]["nodes"].as_array().unwrap().clone();
        let fra_row = rows.iter().find(|r| r["node_id"] == fra.as_str()).unwrap();
        assert_eq!(
            (&fra_row["role"], &fra_row["standing_by"]),
            (&json!("helper"), &json!(true))
        );
        assert!(
            fra_row.get("problem").is_none(),
            "standing by is not a problem: {fra_row}"
        );
        assert_eq!(
            fra_row["interface"],
            json!(crate::tunnel::backhaul_name(&lhr))
        );
        // A location that stops heartbeating is helped as well.
        beat(&mut a, 460, &fra, &fra_token, 0);
        assert_eq!(state_of(&a, &fra), "announce");
        assert_eq!(state_of(&a, &lhr), "withdraw");
    }
    #[test]
    fn the_panel_moves_a_tunnel_between_locations() {
        let mut a = api();
        let (lhr, _) = register(&mut a, 0, "lhr", "192.0.2.1");
        let (fra, _) = register(&mut a, 0, "fra", "192.0.2.2");
        deploy(
            &mut a,
            0,
            json!({"id":"nw","remote":"198.51.100.1","prefixes":["203.0.113.0/24"]}),
        );
        let place = |a: &mut Api, tunnel: &str, node: &str| {
            let path = format!("/v1/tunnels/{tunnel}/location");
            call(a, 0, "PUT", &path, OP, json!({ "node": node }))
        };
        assert_eq!(place(&mut a, "nw", "node-none").0, 400);
        assert_eq!(place(&mut a, "missing", &lhr).0, 404);
        let (status, moved) = place(&mut a, "nw", &lhr);
        assert_eq!(status, 200, "{moved}");
        assert_eq!(moved["tunnel"]["node"], json!(lhr));
        assert!(a.store.programs[&lhr].tunnels.len() == 1);
        assert!(a.store.programs[&fra].tunnels.is_empty());
        assert_eq!(a.store.programs[&fra].backhaul[0].peer, lhr);
        let (status, moved) = place(&mut a, "nw", &fra);
        assert_eq!(status, 200, "{moved}");
        assert!(a.store.programs[&lhr].tunnels.is_empty());
        assert_eq!(a.store.programs[&fra].tunnels.len(), 1);
        // An empty location fans the tunnel out to every node again.
        assert_eq!(place(&mut a, "nw", "").0, 200);
        assert!(a
            .store
            .programs
            .values()
            .all(|p| p.tunnels.len() == 1 && p.backhaul.is_empty()));
        let body = json!({"remote":"198.51.100.1","prefixes":["203.0.113.0/24"],"node":"nowhere"});
        assert_eq!(call(&mut a, 0, "PUT", "/v1/tunnels/nw", OP, body).0, 400);
    }
    #[test]
    fn tunnel_puts_refuse_unknown_nodes_and_ends_linux_cannot_build_twice() {
        let mut a = api();
        let (node, _) = register(&mut a, 0, "edge-a", "192.0.2.1");
        deploy(
            &mut a,
            0,
            json!({"id":"nw","remote":"198.51.100.1","prefixes":["203.0.113.0/24"]}),
        );
        let mut tunnel = json!({"remote":"198.51.100.1","prefixes":["203.0.113.0/24"]});
        tunnel["disabled"] = json!(["edge-a"]);
        let (status, body) = call(&mut a, 0, "PUT", "/v1/tunnels/nw", OP, tunnel.clone());
        assert_eq!(status, 400, "a node name is not a node id: {body}");
        tunnel["disabled"] = json!([node]);
        assert_eq!(call(&mut a, 0, "PUT", "/v1/tunnels/nw", OP, tunnel).0, 200);
        let policy = json!({"name":"q","protected":["203.0.113.0/24","198.51.100.0/24"],"tunnels":[
            {"id":"one","remote":"198.18.0.9","prefixes":["203.0.113.0/24"]},
            {"id":"two","remote":"198.18.0.9","prefixes":["198.51.100.0/24"]}]});
        let (status, body) = call(&mut a, 0, "POST", "/v1/policies", OP, policy.clone());
        assert_eq!(status, 400, "{body}");
        let mut keyed = policy;
        keyed["tunnels"][1]["key"] = json!(7);
        assert_eq!(call(&mut a, 0, "POST", "/v1/policies", OP, keyed).0, 200);
    }
}
