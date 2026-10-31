//! Control-plane authorization, routing, and fabric reconciliation.
use crate::{
    analytics::{self, Collector},
    compiler, ml,
    model::*,
    pipeline::Pipeline,
    runtime, steering,
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
    /// The share of the clean samples it is measured on that a model may drop, at its threshold or
    /// any a node tightens it to; ml::FALSE_POSITIVE_LIMIT unless set.
    max_false_positive_rate: Option<f64>,
    /// Publishes a model that drops more than that, or a known-good sample, all the same.
    force: bool,
    #[serde(skip)]
    samples: Vec<ml::Sample>,
}
impl Training {
    /// Fits both models and holds them to what they must not drop. A fit that would drop too much
    /// clean traffic, or any known-good sample, is refused with what it would have been, and the
    /// published model stays.
    fn fit(&self) -> Answer<ml::Model> {
        let limit = self
            .max_false_positive_rate
            .unwrap_or(ml::FALSE_POSITIVE_LIMIT);
        let mut m =
            ml::train(&self.samples, self.epochs, self.lr, self.threshold, limit).map_err(bad)?;
        match ml::vet(&mut m, &self.samples, limit) {
            Err(why) if !self.force => Err((
                422,
                json!({"error":format!("not published: {why}"),"model":m}),
            )),
            _ => Ok(m),
        }
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
    /// The pipelines /v1/decide judges with, by node, each with when it was last asked.
    pipes: HashMap<String, (Pipeline, u64)>,
    decides: u64,
    /// Whether a model is being fitted: one at a time, since each fit holds a copy of the samples.
    fitting: bool,
    /// How long the last recompile took, and when it finished (see deploy).
    compile_took: std::time::Duration,
    compiled_at: Option<std::time::Instant>,
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
    /// Since when this process has been taking heartbeats: from its first compile, or from its
    /// promotion. A node it has not heard from in that time is stale only for want of news.
    watching_since: Option<DateTime<Utc>>,
    /// Counts compiles for the nodes waiting on their next program, which it wakes.
    compiled: tokio::sync::watch::Sender<u64>,
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
            decides: 0,
            fitting: false,
            compile_took: std::time::Duration::ZERO,
            compiled_at: None,
            last_key: String::new(),
            recompiles: 0,
            requests: BTreeMap::new(),
            fences: HashMap::new(),
            overflow_until: HashMap::new(),
            overflowing: HashSet::new(),
            watching_since: None,
            compiled: tokio::sync::watch::Sender::new(0),
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
        if t.max_false_positive_rate
            .is_some_and(|v| !(0.0..=1.0).contains(&v))
        {
            return Err(bad("max_false_positive_rate must be between 0 and 1"));
        }
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
    /// Why a policy cannot go onto the fabric as it stands, when it cannot: it pins a tunnel to a
    /// registered node outside the steering regions of one of the tunnel's prefixes, which that
    /// node would never announce and nobody else could deliver.
    fn misplaced(&self, p: &Policy) -> Option<String> {
        p.tunnels.iter().find_map(|t| {
            let at = self.store.data.nodes.iter().find(|n| n.id == t.node)?;
            compiler::misplaced(p, at, t)
                .map(|why| format!("tunnel {} cannot have its location there: {why}", t.id))
        })
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
        self.store.forget_tunnels(node, tunnel);
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
                        // The location always has a row, so a tunnel placed where steering keeps
                        // its prefixes away still shows where it is and why.
                        if mine.is_empty() && t.node != n.id {
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
                            .tunnels()
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
                        // What the node holding an on-demand tunnel last said about its traffic.
                        if let Some(m) = self.store.reports.get(&n.id).and_then(|r| {
                            r.stats.mitigation.iter().find(|m| m.tunnel_id == t.id)
                        }) {
                            row["mitigating"] = json!(m.active);
                            if m.active {
                                row["mitigating_since"] = json!(m.since);
                                row["mitigation_wave"] = json!(m.wave);
                                row["mitigation_hold_seconds"] = json!(m.hold_seconds);
                            }
                            row["ingress_pps"] = json!(m.pps);
                            row["ingress_bps"] = json!(m.bps);
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
                        } else if role == "location" {
                            compiler::misplaced(p, n, t)
                                .map(|why| {
                                    format!("{why}, so nobody announces it while the tunnel is here")
                                })
                                .unwrap_or_default()
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
                            match compiler::build(p, t, n, &mine) {
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
                        } else if row.get("problem").is_none() {
                            // Standing by is what a helper does while its location needs no help.
                            if let Some(a) = withdrawn
                                .iter()
                                .find(|a| !a.reason.starts_with(compiler::STANDING_BY))
                            {
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
                    "mitigation": if t.mitigation == "on_demand" { "on_demand" } else { "always" },
                    "attack_pps": (t.mitigation == "on_demand").then(|| crate::tunnel::attack_thresholds(t).0),
                    "attack_mbps": (t.mitigation == "on_demand").then(|| crate::tunnel::attack_thresholds(t).1 / 1000),
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
        let since = *self.watching_since.get_or_insert(now);
        let nodes = self.store.nodes(now);
        if !nodes.iter().any(|n| n.status != "stale") {
            return Ok(());
        }
        let samples: Vec<_> = nodes
            .iter()
            .map(|n| {
                let report = self.store.reports.get(&n.id);
                let stats = report.map(|r| &r.stats);
                let fresh = report.is_some_and(|r| {
                    now.signed_duration_since(r.reported_at).num_milliseconds() <= 15000
                });
                steering::Sample {
                    node_id: n.id.clone(),
                    capacity_pps: n.capacity_pps,
                    offered_pps: stats.map_or(0, |s| s.offered_pps),
                    surge_pps: stats.map_or(0, |s| s.surge_pps),
                    pulsing: stats.is_some_and(|s| s.pulsing),
                    peak_pps: stats.map_or(0, |s| s.pulse_peak_pps),
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
        // Every node starts out stale after a restart or a promotion, and the first to heartbeat
        // would otherwise announce every other location's customers until they check in too. So
        // a node not heard from since then is helped only once it has had a heartbeat timeout
        // to check in.
        let settled = now.signed_duration_since(since) > store::STALE_AFTER;
        let overflowing: HashSet<String> = self
            .overflow_until
            .keys()
            .cloned()
            .chain(
                nodes
                    .iter()
                    .filter(|n| n.status == "stale" && (settled || n.last_seen != zero_time()))
                    .map(|n| n.id.clone()),
            )
            .collect();
        // What a recompile depends on, written out to tell whether any of it has changed. The
        // tunnels' states go in as a digest of each node's report: written out whole, they were
        // most of what a heartbeat cost on a large fabric.
        let mut fingerprint = nodes.clone();
        for n in &mut fingerprint {
            n.last_seen = zero_time();
        }
        let key = format!(
            "{}{:?}{:?}{:?}",
            serde_json::to_string(&fingerprint).unwrap_or_default(),
            std::collections::BTreeSet::<_>::from_iter(overflowing.iter()),
            BTreeMap::<_, _>::from_iter(shedding.iter()),
            self.store.tunnel_digests(),
        );
        if !force {
            if key == self.last_key {
                return Ok(());
            }
            // A recompile that takes long waits until a few of its own lengths after the last,
            // so a burst of changes (every node checking in after a restart) is folded into a few
            // recompiles rather than one each, and heartbeats are answered between them. The
            // next reconcile after that compiles whatever has changed by then.
            if self.compile_took >= SLOW_COMPILE
                && self
                    .compiled_at
                    .is_some_and(|at| at.elapsed() < self.compile_took * 4)
            {
                return Ok(());
            }
        }
        let started = std::time::Instant::now();
        let health: compiler::TunnelHealth = self
            .store
            .tunnels()
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
        self.store.programs = programs
            .into_iter()
            .map(|(id, program)| (id, Arc::new(program)))
            .collect();
        self.pipes
            .retain(|id, _| self.store.programs.contains_key(id));
        self.collector
            .forget(&policy.protected.iter().cloned().collect());
        self.last_key = key;
        self.compile_took = started.elapsed();
        self.compiled_at = Some(std::time::Instant::now());
        self.recompiles += 1;
        self.compiled.send_replace(self.recompiles);
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
            ("POST", ["promote"]) => {
                who.operator()?;
                if self.mode != "replica" {
                    return Err((409, "this control plane is already the primary".into()));
                }
                self.mode = "primary".into();
                self.watching_since = Some(now);
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
                    } else if e.starts_with(store::FABRIC_FULL) {
                        (413, e.into())
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
            ("DELETE", ["nodes", _]) if !id.is_empty() => {
                who.operator()?;
                self.writable()?;
                // A node still running enrols again with its next heartbeat, so retiring it would
                // only lose what it last reported.
                if self.store.data.nodes.iter().any(|n| {
                    n.id == id && now.signed_duration_since(n.last_seen) <= store::STALE_AFTER
                }) {
                    return Err((
                        409,
                        "this node is live; stop it before retiring it, or it enrols again".into(),
                    ));
                }
                if !self.store.retire(id).map_err(failed)? {
                    return Err((404, "unknown node".into()));
                }
                self.fences.remove(id);
                self.overflow_until.remove(id);
                self.pipes.remove(id);
                self.collector.forget_node(id);
                self.reconcile(now, true).map_err(failed)?;
                Ok(json!({"retired":id}))
            }
            ("POST", ["nodes", _, "heartbeat"]) if !id.is_empty() => {
                self.may_heartbeat(&who, id)?;
                let hb = if body.is_empty() {
                    None
                } else {
                    Some(parse(body)?)
                };
                self.heartbeat(&who, id, hb, now)
            }
            ("GET", ["nodes", _, "program"]) if !id.is_empty() => {
                self.program_for(&who, id).map(|p| value(&*p))
            }
            ("GET", ["nodes", _, "stats"]) if !id.is_empty() => {
                if !who.acts(id) {
                    return Err((403, "a node may only read its own counters".into()));
                }
                self.store
                    .reports
                    .get(id)
                    .map(value)
                    .ok_or((404, "no counters reported for this node".into()))
            }
            ("POST", ["policies"]) => {
                who.operator()?;
                self.writable()?;
                let mut p: Policy = parse(body)?;
                validation::policy(&p).map_err(bad)?;
                validation::tunnel_tenants(&p, &self.store.data.tenants).map_err(bad)?;
                if let Some(why) = self.misplaced(&p) {
                    return Err(bad(why));
                }
                if p.challenge_secret.is_empty() && !p.games.is_empty() {
                    p.challenge_secret = store::secret().map_err(failed)?;
                }
                let kept = &self.store.data.policies;
                if !kept.iter().any(|v| !p.id.is_empty() && v.id == p.id)
                    && kept.len() >= store::POLICIES_MAX
                {
                    return Err((
                        413,
                        format!(
                            "the control plane keeps at most {} policies; save over one by its id, or delete one with DELETE /v1/policies/{{id}}",
                            store::POLICIES_MAX
                        )
                        .into(),
                    ));
                }
                Ok(value(self.store.save_policy(p, now).map_err(failed)?))
            }
            ("DELETE", ["policies", _]) if !id.is_empty() => {
                who.operator()?;
                self.writable()?;
                if self.store.data.last_policy_id == id {
                    return Err((
                        409,
                        "this policy is deployed; deploy another before deleting it".into(),
                    ));
                }
                if !self.store.forget_policy(id).map_err(failed)? {
                    return Err((404, "unknown policy".into()));
                }
                Ok(json!({"deleted":id}))
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
                if let Some(why) = self.misplaced(&p) {
                    return Err((409, why.into()));
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
                let location = self
                    .store
                    .data
                    .nodes
                    .iter()
                    .find(|v| v.id == t.node)
                    .cloned();
                if !t.node.is_empty() && location.is_none() {
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
                    if let Some(why) = location.and_then(|at| compiler::misplaced(p, &at, &t)) {
                        return Err(bad(format!(
                            "tunnel {} cannot have its location there: {why}",
                            t.id
                        )));
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
            ("PUT", ["tunnels", _, "mitigation"]) if !id.is_empty() => {
                who.operator()?;
                self.writable()?;
                #[derive(Deserialize)]
                struct Mitigation {
                    mitigation: String,
                    #[serde(default)]
                    attack_pps: i64,
                    #[serde(default)]
                    attack_mbps: i64,
                }
                let m: Mitigation = parse(body)?;
                let p = self.change_tunnels(now, &[], |p| {
                    let Some(t) = p.tunnels.iter_mut().find(|v| v.id == id) else {
                        return Err((404, "unknown tunnel".into()));
                    };
                    t.mitigation = m.mitigation;
                    t.attack_pps = m.attack_pps;
                    t.attack_mbps = m.attack_mbps;
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
                let location = self
                    .store
                    .data
                    .nodes
                    .iter()
                    .find(|v| v.id == l.node)
                    .cloned();
                if !l.node.is_empty() && location.is_none() {
                    return Err(bad(format!(
                        "node {:?} is not a registered node id",
                        l.node
                    )));
                }
                let from = self
                    .deployed()
                    .and_then(|p| p.tunnels.iter().find(|v| v.id == id))
                    .map(|t| t.node.clone());
                if from.as_ref() == Some(&l.node) {
                    // Nothing moves, so everything reported about the tunnel still holds.
                    if let Some(p) = self.deployed() {
                        return Ok(tunnel_answer(p, id));
                    }
                }
                // Moving the customer's tunnel builds it somewhere else, and nothing reported about
                // where it was says anything about where it is now. Unpinned, it was or will be
                // built everywhere.
                let forget: Vec<(Option<&str>, Option<&str>)> = match from.as_deref() {
                    Some(old) if !old.is_empty() && !l.node.is_empty() => {
                        vec![(Some(old), Some(id)), (Some(l.node.as_str()), Some(id))]
                    }
                    _ => vec![(None, Some(id))],
                };
                let p = self.change_tunnels(now, &forget, |p| {
                    let Some(t) = p.tunnels.iter_mut().find(|v| v.id == id) else {
                        return Err((404, "unknown tunnel".into()));
                    };
                    t.node = l.node.clone();
                    let t = t.clone();
                    if let Some(why) = location.and_then(|at| compiler::misplaced(p, &at, &t)) {
                        return Err(bad(format!(
                            "tunnel {id} cannot have its location there: {why}"
                        )));
                    }
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
                let stored = &self.store.data.samples;
                if stored.len() + batch.samples.len() > ml::SAMPLES_MAX {
                    return Err((
                        413,
                        json!({"error":format!("training set is limited to {} samples", ml::SAMPLES_MAX),"stored":stored.len()}),
                    ));
                }
                let bytes = ml::sample_bytes(stored) + ml::sample_bytes(&batch.samples);
                if bytes > ml::SAMPLE_BYTES_MAX {
                    return Err((
                        413,
                        json!({"error":format!("training set is limited to {} MiB of payloads and packets", ml::SAMPLE_BYTES_MAX >> 20),"stored":stored.len(),"stored_bytes":ml::sample_bytes(stored)}),
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
                let mut v =
                    json!({"score":ml::score(m,&f),"label":ml::predict(m,&f),"ready":m.ready});
                // A flow carrying HTTP requests is scored by the request model too, request by
                // request, the way the layer-7 rules hand them to it.
                let requests = crate::httpfilter::requests(&f);
                if !requests.is_empty() {
                    let unfitted = ml::Model::default();
                    let h = m.http.as_deref().unwrap_or(&unfitted);
                    let scores: Vec<f64> = requests
                        .iter()
                        .map(|r| ml::score_request(h, r, f.pps))
                        .collect();
                    let top = scores.iter().copied().fold(0.0, f64::max);
                    v["http"] = json!({"ready":h.ready,"scores":scores,"score":top,"label":i64::from(h.ready && top >= h.threshold)});
                }
                Ok(v)
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
                // Each holds as much as a node's datapath can, so only the few last asked of are kept.
                if !self.pipes.contains_key(&b.node_id) && self.pipes.len() >= DECIDE_PIPELINES {
                    if let Some(oldest) = self
                        .pipes
                        .iter()
                        .min_by_key(|(_, (_, used))| *used)
                        .map(|(id, _)| id.clone())
                    {
                        self.pipes.remove(&oldest);
                    }
                }
                self.decides += 1;
                let tick = self.decides;
                let (p, used) = self
                    .pipes
                    .entry(b.node_id.clone())
                    .or_insert_with(|| (Pipeline::new((*prog).clone()), 0));
                *used = tick;
                if p.program.policy_id != prog.policy_id
                    || p.program.version != prog.version
                    || p.program.compiled_at != prog.compiled_at
                {
                    p.load((*prog).clone());
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
                let kept = &self.store.data.tenants;
                if !kept.iter().any(|v| v.id == t.id) && kept.len() >= store::TENANTS_MAX {
                    return Err((
                        413,
                        format!(
                            "the control plane keeps at most {} tenants; delete one first",
                            store::TENANTS_MAX
                        )
                        .into(),
                    ));
                }
                let entitled = t.prefixes.len()
                    + kept
                        .iter()
                        .filter(|v| v.id != t.id)
                        .map(|v| v.prefixes.len())
                        .sum::<usize>();
                if entitled > store::TENANT_PREFIXES_MAX {
                    return Err((
                        413,
                        format!(
                            "the control plane keeps at most {} prefixes between all its tenants, and this would make {entitled}",
                            store::TENANT_PREFIXES_MAX
                        )
                        .into(),
                    ));
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
    /// A node's program. The node fetching it is taking in whatever the fence it was behind
    /// waited on, so that is lifted.
    fn program_for(&mut self, who: &Who, id: &str) -> Answer<Arc<Program>> {
        if !who.acts(id) {
            return Err((403, "a node may only fetch its own program".into()));
        }
        if who.role == "node" {
            self.fences.remove(id);
        }
        self.store
            .programs
            .get(id)
            .cloned()
            .ok_or((404, "no program deployed".into()))
    }
    /// Whether a credential may heartbeat for a node, here.
    fn may_heartbeat(&self, who: &Who, id: &str) -> Answer<()> {
        if !who.acts(id) {
            return Err((403, "a node may only heartbeat for itself".into()));
        }
        self.writable()
    }
    /// A node's heartbeat: it is live, and, when it says, what its datapath counted and what its
    /// provisioner says about its tunnels.
    fn heartbeat(
        &mut self,
        who: &Who,
        id: &str,
        hb: Option<Heartbeat>,
        now: DateTime<Utc>,
    ) -> Answer {
        self.may_heartbeat(who, id)?;
        let reported = hb.is_some();
        let hb = hb.unwrap_or_default();
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
                fenced.is_none_or(|f| !f.contains(&None) && !f.contains(&Some(t.tunnel_id.clone())))
            });
            for t in &mut tunnels {
                t.reported_at = now;
            }
            tunnels.sort_by(|a, b| a.tunnel_id.cmp(&b.tunnel_id));
            self.store.report_tunnels(id, tunnels);
        }
        if reported {
            let none = Program::default();
            let prog = self.store.programs.get(id).map_or(&none, |p| &**p);
            self.collector
                .observe_stats(id, &hb.stats, prog, now.timestamp_millis());
            let report = wire::Report {
                node_id: id.into(),
                name,
                region,
                stats: hb.stats,
                reported_at: now,
            };
            self.store.reports.insert(id.into(), report);
        }
        self.reconcile(now, false).map_err(failed)?;
        Ok(json!({"status":"ok"}))
    }
    /// Answers a request. The reads that carry every policy, the whole fabric, the training set or
    /// the whole state are written straight to JSON: held as a Value first, each would take
    /// several times the memory its JSON does, all of it under the lock.
    #[allow(clippy::too_many_arguments)]
    fn answer(
        &mut self,
        method: &str,
        path: &str,
        query: &HashMap<String, String>,
        headers: &HeaderMap,
        body: &[u8],
        read: Option<Heartbeat>,
        now: DateTime<Utc>,
    ) -> Answer<Reply> {
        let parts: Vec<_> = path
            .strip_prefix("/v1/")
            .unwrap_or(path)
            .split('/')
            .collect();
        // A heartbeat read before the lock was taken (see handler).
        if let Some(hb) = read {
            let who = self.auth(headers)?;
            let id = parts.get(1).copied().unwrap_or("");
            return self.heartbeat(&who, id, Some(hb), now).map(Reply::Value);
        }
        // A node's program goes out as it is shared, written out after the lock is let go: every
        // node fetches its own after each compile.
        if let ("GET", ["nodes", id, "program"]) = (method, parts.as_slice()) {
            if !id.is_empty() {
                let who = self.auth(headers)?;
                return self.program_for(&who, id).map(Reply::Program);
            }
        }
        let written = match (method, parts.as_slice()) {
            ("GET", ["state"]) => {
                self.auth(headers)?.operator()?;
                serde_json::to_vec(&self.store.snapshot())
            }
            ("GET", ["policies"]) => {
                self.auth(headers)?.operator()?;
                let mut p: Vec<_> = self.store.data.policies.iter().collect();
                p.sort_by(|a, b| (&a.name, &a.id).cmp(&(&b.name, &b.id)));
                serde_json::to_vec(&p)
            }
            ("GET", ["fabric"]) => {
                self.auth(headers)?.operator()?;
                #[derive(Serialize)]
                struct Fabric<'a> {
                    announcements: &'a [Announcement],
                    ml: &'a ml::Model,
                    programs: Vec<&'a Program>,
                }
                serde_json::to_vec(&Fabric {
                    announcements: &self.store.plan,
                    ml: &self.store.data.model,
                    programs: self.store.programs.values().map(|p| &**p).collect(),
                })
            }
            ("GET", ["ml", "samples"]) => {
                self.auth(headers)?.operator()?;
                serde_json::to_vec(&self.store.data.samples)
            }
            _ => {
                return self
                    .dispatch(method, path, query, headers, body, now)
                    .map(Reply::Value)
            }
        };
        written.map(Reply::Json).map_err(|e| {
            eprintln!("writing an answer: {e}");
            (500, "could not write the answer".into())
        })
    }
    pub fn router(state: Shared) -> Router {
        Router::new()
            .route("/health", any(health))
            .route("/metrics", any(metrics_handler))
            .fallback(handler)
            .layer(DefaultBodyLimit::max(BODY_LIMIT))
            .layer(axum::middleware::from_fn_with_state(
                runtime::Bodies::new(BODY_BUDGET, BODY_LIMIT),
                runtime::bounded,
            ))
            .with_state(state)
    }
    /// The fabric's metrics, as GET /metrics renders them (see telemetry::Scrape).
    pub fn metrics(&self) -> crate::Result<String> {
        crate::telemetry::Scrape::fleet(self).render()
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
/// What a node sends with a heartbeat: its datapath's counters, and what its provisioner says
/// about its tunnels.
#[derive(Deserialize, Default)]
#[serde(default)]
struct Heartbeat {
    stats: wire::Stats,
    tunnels: Option<Vec<TunnelStatus>>,
}
/// The node a request heartbeats for, if it is a heartbeat.
fn heartbeat_for<'a>(method: &Method, path: &'a str) -> Option<&'a str> {
    let rest = path
        .strip_prefix("/v1/nodes/")?
        .strip_suffix("/heartbeat")?;
    (*method == Method::POST && !rest.is_empty() && !rest.contains('/')).then_some(rest)
}
/// What a request is answered with: a value, JSON already written out, or a node's program, which
/// is written out once the lock is let go (see Api::answer).
enum Reply {
    Value(Value),
    Json(Vec<u8>),
    Program(Arc<Program>),
}
fn response(result: Answer<Reply>) -> Response {
    match result {
        Ok(Reply::Value(v)) => Json(v).into_response(),
        Ok(Reply::Program(p)) => Json(&*p).into_response(),
        Ok(Reply::Json(written)) => (
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            written,
        )
            .into_response(),
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
    if method == Method::GET {
        if let Err(e) = hold(&s, &path, &query, &headers).await {
            return response(Err(e));
        }
    }
    let result = tokio::task::spawn_blocking(move || {
        // A heartbeat's body is read before the lock is taken for it: every node sends one every
        // couple of seconds, and the rest of the fabric would wait on the reading of each. Who
        // sent it is checked first, so only a node's own heartbeat is read.
        let read = match heartbeat_for(&method, &path) {
            Some(id) if !body.is_empty() => {
                let allowed = {
                    let a = s.lock().unwrap();
                    a.auth(&headers).and_then(|who| a.may_heartbeat(&who, id))
                };
                Some(allowed.and_then(|()| parse::<Heartbeat>(&body)))
            }
            _ => None,
        };
        let (mut a, result) = if method == Method::POST && path == "/v1/ml/train" {
            let result = train(&s, &headers, &body).map(Reply::Value);
            (s.lock().unwrap(), result)
        } else {
            let mut a = s.lock().unwrap();
            let result = match read {
                Some(Err(e)) => Err(e),
                read => {
                    let read = read.and_then(Result::ok);
                    let now = Utc::now();
                    a.answer(method.as_str(), &path, &query, &headers, &body, read, now)
                }
            };
            (a, result)
        };
        let code = result.as_ref().map(|_| 200).unwrap_or_else(|e| e.0);
        let route = route_label(&path);
        *a.requests.entry((route, code)).or_default() += 1;
        // The answer is written out after the lock is let go, here rather than on one of the
        // runtime's two workers.
        drop(a);
        response(result)
    })
    .await;
    result.unwrap_or_else(|_| response(Err((500, "request worker failed".into()))))
}
/// The longest a node's request for its program is held.
const LONGEST_WAIT: i64 = 30_000;
/// How many nodes' pipelines /v1/decide keeps: each can grow to what a node's datapath holds.
const DECIDE_PIPELINES: usize = 8;
/// A recompile taking at least this long is paced (see Api::deploy).
const SLOW_COMPILE: std::time::Duration = std::time::Duration::from_millis(50);
/// The most a request may carry: a policy as large as validation allows, or a batch of samples.
pub const BODY_LIMIT: usize = 4 << 20;
/// What the bodies of requests to the control plane may hold between them: a full fabric's
/// heartbeats arriving at once, under 1 MiB each at the most a node reports, with room to spare.
pub const BODY_BUDGET: usize = 256 << 20;
/// How many connections the control plane holds open: a few for every node the fabric can hold,
/// and one for each tenant, operator and scraper.
pub const CONNECTIONS: usize = 8192;
/// Whether a node holding `held` has something to fetch: a program that differs from it in more
/// than when it was compiled, one where it had none or none where it had one, or tunnel reports
/// ignored until it fetches again.
fn news(a: &Api, id: &str, held: &Option<Arc<Program>>) -> bool {
    a.fences.contains_key(id)
        || match (a.store.programs.get(id), held) {
            // The very program the node is holding: nothing has been compiled for it since.
            (Some(now), Some(held)) if Arc::ptr_eq(now, held) => false,
            (Some(now), Some(held)) => !same_but_stamp(now, held),
            (None, None) => false,
            _ => true,
        }
}
/// Whether two programs differ in nothing but when they were compiled. Every field is named, so
/// one added to Program is not left out of the comparison without a decision.
fn same_but_stamp(a: &Program, b: &Program) -> bool {
    let Program {
        node_id,
        policy_id,
        version,
        prefixes,
        asic,
        fpga,
        zc,
        announcements,
        games,
        challenge_secret,
        pulse_floor_pps,
        reputation,
        egress,
        ml,
        crafted,
        tunnels,
        sessions,
        tunnel_src,
        backhaul,
        pinned,
        tunnel_peers,
        compiled_at: _,
    } = a;
    *node_id == b.node_id
        && *policy_id == b.policy_id
        && *version == b.version
        && *prefixes == b.prefixes
        && *asic == b.asic
        && *fpga == b.fpga
        && *zc == b.zc
        && *announcements == b.announcements
        && *games == b.games
        && *challenge_secret == b.challenge_secret
        && *pulse_floor_pps == b.pulse_floor_pps
        && *reputation == b.reputation
        && *egress == b.egress
        && *ml == b.ml
        && *crafted == b.crafted
        && *tunnels == b.tunnels
        && *sessions == b.sessions
        && *tunnel_src == b.tunnel_src
        && *backhaul == b.backhaul
        && *pinned == b.pinned
        && *tunnel_peers == b.tunnel_peers
}
/// Holds a request for a node's program while the program is still the one the node has, the one
/// compiled at `since`, or none for a node that has none yet: until the fabric compiles it a new
/// one or `wait` runs out. What the control plane decides then reaches the node as it is decided
/// rather than at its next poll, and a compile that leaves a node's program as it was, restamped,
/// leaves that node waiting. A request it does not apply to, or one the caller may not make, goes
/// through at once and is answered as usual.
async fn hold(
    s: &Shared,
    path: &str,
    query: &HashMap<String, String>,
    headers: &HeaderMap,
) -> Answer<()> {
    let Some(wait) = query.get("wait").filter(|w| !w.is_empty()) else {
        return Ok(());
    };
    let Some(id) = path
        .strip_prefix("/v1/nodes/")
        .and_then(|p| p.strip_suffix("/program"))
        .filter(|id| !id.is_empty() && !id.contains('/'))
    else {
        return Ok(());
    };
    let wait = duration(wait)
        .map_err(|e| bad(format!("wait: {e}")))?
        .min(LONGEST_WAIT);
    let since = match query.get("since").map(String::as_str).unwrap_or("") {
        "" => None,
        raw => Some(
            DateTime::parse_from_rfc3339(raw)
                .map_err(|_| bad("since must be an RFC 3339 time, the compiled_at of a program"))?
                .to_utc(),
        ),
    };
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(wait as u64);
    let (shared, node, headers) = (s.clone(), id.to_string(), headers.clone());
    let waiting = tokio::task::spawn_blocking(move || {
        let a = shared.lock().ok()?;
        if !a.auth(&headers).is_ok_and(|who| who.acts(&node)) {
            return None;
        }
        let held = a.store.programs.get(&node).cloned();
        let current = held.as_ref().map(|p| p.compiled_at) == since;
        (current && !news(&a, &node, &held)).then(|| (a.compiled.subscribe(), held))
    })
    .await
    .ok()
    .flatten();
    let Some((mut changed, mut held)) = waiting else {
        return Ok(());
    };
    loop {
        tokio::select! {
            compiled = tokio::time::timeout_at(deadline, changed.changed()) => {
                if !matches!(compiled, Ok(Ok(()))) {
                    return Ok(());
                }
            }
            _ = crate::runtime::stopping() => return Ok(()),
        }
        let (shared, node) = (s.clone(), id.to_string());
        let looked = tokio::task::spawn_blocking(move || {
            let fresh = shared
                .lock()
                .map(|a| news(&a, &node, &held))
                .unwrap_or(true);
            (fresh, held)
        })
        .await;
        match looked {
            Ok((false, back)) => held = back,
            _ => return Ok(()),
        }
    }
}
/// Fitting a full training set takes seconds. Holding the lock for that long stalls every
/// heartbeat and program fetch behind it, so only reading the set and storing the model take it.
fn train(s: &Shared, headers: &HeaderMap, body: &[u8]) -> Answer {
    let job = {
        let mut a = s.lock().unwrap();
        let who = a.auth(headers)?;
        who.operator()?;
        // Each fit holds its own copy of the samples, so fits running side by side would hold one
        // each.
        if a.fitting {
            return Err((
                409,
                "a model is already being trained; try again when it is done".into(),
            ));
        }
        let job = a.training(&who, body)?;
        a.fitting = true;
        job
    };
    /// Lets the next fit start however this one ends, a panic included.
    struct Fitting<'a>(&'a Shared);
    impl Drop for Fitting<'_> {
        fn drop(&mut self) {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .fitting = false;
        }
    }
    let fitting = Fitting(s);
    let m = job.fit();
    drop(fitting);
    s.lock().unwrap().install(m?)
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
        ["tunnels", _, leaf]
            if ["disable", "enable", "rate", "location", "mitigation"].contains(leaf) =>
        {
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
/// How many scrapes are rendered at once.
pub const SCRAPES: usize = 4;
fn scrapes() -> &'static tokio::sync::Semaphore {
    static SCRAPES_AT_ONCE: std::sync::OnceLock<tokio::sync::Semaphore> =
        std::sync::OnceLock::new();
    SCRAPES_AT_ONCE.get_or_init(|| tokio::sync::Semaphore::new(SCRAPES))
}
/// The fabric's metrics, or with ?node= one node's every series. What they are built from is
/// copied under the lock and written out after it is let go, so a scrape holds up no heartbeat.
async fn metrics_handler(
    State(s): State<Shared>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let node = uri.query().and_then(|q| {
        reqwest::Url::parse(&format!("http://local/?{q}"))
            .ok()?
            .query_pairs()
            .find(|(k, _)| k == "node")
            .map(|(_, v)| v.into_owned())
    });
    // Each render holds what it renders until it is sent, so only a few run at once: a scraper
    // per node's view can arrive together.
    let Ok(_rendering) = scrapes().acquire().await else {
        return response(Err((503, "the control plane is stopping".into())));
    };
    tokio::task::spawn_blocking(move || {
        let scrape = {
            let a = s.lock().unwrap();
            if let Err(e) = a.auth(&headers).and_then(|w| w.operator()) {
                return response(Err(e));
            }
            if method != Method::GET {
                return response(Err((405, "GET required".into())));
            }
            match node {
                None => crate::telemetry::Scrape::fleet(&a),
                Some(id) => match crate::telemetry::Scrape::node(&a, &id) {
                    Some(scrape) => scrape,
                    None => return response(Err((404, "unknown node".into()))),
                },
            }
        };
        match scrape.render() {
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
    /// Registers a node in a region and returns its id and credential.
    fn register_in(a: &mut Api, name: &str, region: &str, src: &str) -> (String, String) {
        let body = json!({"name":name,"region":region,"tunnel_src":src});
        let (status, reg) = call(a, 0, "POST", "/v1/nodes/register", ENROLL, body);
        assert_eq!(status, 200, "{reg}");
        (
            reg["node"]["id"].as_str().unwrap().into(),
            reg["token"].as_str().unwrap().into(),
        )
    }
    #[test]
    fn a_location_must_be_in_the_steering_regions_of_its_prefixes() {
        let policy = |tunnel: &Value| {
            json!({"id":"p","name":"p","protected":["203.0.113.0/24"],
                "steering":[{"prefix":"203.0.113.0/24","regions":["us"]}],"tunnels":[tunnel]})
        };
        let tunnel = json!({"id":"nw","remote":"198.51.100.1","prefixes":["203.0.113.0/24"]});
        let mut a = api();
        let (lhr, _) = register_in(&mut a, "lhr", "eu", "192.0.2.1");
        let (nyc, _) = register_in(&mut a, "nyc", "us", "192.0.2.3");
        assert_eq!(
            call(&mut a, 0, "POST", "/v1/policies", OP, policy(&tunnel)).0,
            200
        );
        assert_eq!(
            call(&mut a, 0, "POST", "/v1/policies/p/deploy", OP, Value::Null).0,
            200
        );
        let place = |a: &mut Api, node: &str| {
            call(
                a,
                0,
                "PUT",
                "/v1/tunnels/nw/location",
                OP,
                json!({ "node": node }),
            )
        };
        let (status, why) = place(&mut a, &lhr);
        assert_eq!(status, 400, "{why}");
        assert!(
            why.as_str()
                .unwrap()
                .contains("steering sends 203.0.113.0/24 only to us"),
            "{why}"
        );
        let mut pinned = tunnel.clone();
        pinned["node"] = json!(lhr);
        assert_eq!(
            call(&mut a, 0, "PUT", "/v1/tunnels/nw", OP, pinned.clone()).0,
            400
        );
        assert_eq!(
            call(&mut a, 0, "POST", "/v1/policies", OP, policy(&pinned)).0,
            400
        );
        assert_eq!(place(&mut a, &nyc).0, 200);
        assert_eq!(state(&a, &nyc).0, "announce");
        // A policy saved before its location registered is caught when it is deployed.
        let mut b = api();
        let early = store::id("node", &["lhr", "eu"]);
        pinned["node"] = json!(early);
        assert_eq!(
            call(&mut b, 0, "POST", "/v1/policies", OP, policy(&pinned)).0,
            200
        );
        assert_eq!(register_in(&mut b, "lhr", "eu", "192.0.2.1").0, early);
        let (status, why) = call(&mut b, 0, "POST", "/v1/policies/p/deploy", OP, Value::Null);
        assert_eq!(status, 409, "{why}");
    }
    #[test]
    fn a_tunnel_left_outside_its_steering_regions_shows_why_nobody_announces_it() {
        let mut a = api();
        let (lhr, _) = register_in(&mut a, "lhr", "eu", "192.0.2.1");
        let (nyc, _) = register_in(&mut a, "nyc", "us", "192.0.2.3");
        let policy = json!({"id":"p","name":"p","protected":["203.0.113.0/24"],
            "steering":[{"prefix":"203.0.113.0/24","regions":["us"]}],
            "tunnels":[{"id":"nw","remote":"198.51.100.1","prefixes":["203.0.113.0/24"]}]});
        assert_eq!(call(&mut a, 0, "POST", "/v1/policies", OP, policy).0, 200);
        assert_eq!(
            call(&mut a, 0, "POST", "/v1/policies/p/deploy", OP, Value::Null).0,
            200
        );
        // Placed before locations were checked, or left there by an agent registering under the
        // same id from another region.
        a.store.data.policies[0].tunnels[0].node = lhr.clone();
        a.reconcile(at(1), true).unwrap();
        assert!(a.store.plan.iter().all(|r| r.state == "withdraw"));
        let (_, view) = call(&mut a, 1, "GET", "/v1/tunnels", OP, Value::Null);
        let rows = view["tunnels"][0]["nodes"].as_array().unwrap().clone();
        let row = |id: &str| rows.iter().find(|r| r["node_id"] == id).unwrap().clone();
        let at_lhr = row(&lhr);
        assert_eq!(at_lhr["role"], "location");
        assert!(
            at_lhr["problem"]
                .as_str()
                .unwrap()
                .ends_with("so nobody announces it while the tunnel is here"),
            "{at_lhr}"
        );
        let at_nyc = row(&nyc);
        assert_eq!(at_nyc["standing_by"], true);
        assert!(
            at_nyc["problem"]
                .as_str()
                .unwrap()
                .contains("outside this prefix's steering regions"),
            "standing by hides only standing by: {at_nyc}"
        );
    }
    #[test]
    fn naming_the_location_a_tunnel_is_already_at_changes_nothing() {
        let mut a = api();
        let (lhr, lhr_token) = register(&mut a, 0, "lhr", "192.0.2.1");
        let (fra, fra_token) = register(&mut a, 0, "fra", "192.0.2.2");
        let tunnel = json!({"id":"nw","remote":"198.51.100.1","prefixes":["203.0.113.0/24"],"required":true,"node":lhr});
        deploy(&mut a, 0, tunnel);
        let up = json!({"tunnels":[{"tunnel_id":"nw","state":"up"}]});
        let agent = |a: &mut Api, now: i64, node: &str, token: &str| {
            let beat = format!("/v1/nodes/{node}/heartbeat");
            assert_eq!(call(a, now, "POST", &beat, token, up.clone()).0, 200);
            let fetch = format!("/v1/nodes/{node}/program");
            assert_eq!(call(a, now, "GET", &fetch, token, Value::Null).0, 200);
        };
        agent(&mut a, 1, &lhr, &lhr_token);
        assert_eq!(state(&a, &lhr).0, "announce");
        let place = |a: &mut Api, now: i64, node: &str| {
            call(
                a,
                now,
                "PUT",
                "/v1/tunnels/nw/location",
                OP,
                json!({ "node": node }),
            )
        };
        let (status, same) = place(&mut a, 2, &lhr);
        assert_eq!(status, 200, "{same}");
        assert_eq!(same["version"], 1);
        assert_eq!(state(&a, &lhr).0, "announce");
        let beat = format!("/v1/nodes/{lhr}/heartbeat");
        assert_eq!(
            call(&mut a, 3, "POST", &beat, &lhr_token, up.clone()).0,
            200
        );
        assert_eq!(state(&a, &lhr).0, "announce", "nothing was fenced");
        // A move does start over at the new location.
        assert_eq!(place(&mut a, 4, &fra).0, 200);
        let unreported = "return tunnel nw is required and has not reported up";
        assert_eq!(state(&a, &fra), ("withdraw".into(), unreported.into()));
        agent(&mut a, 5, &fra, &fra_token);
        agent(&mut a, 6, &fra, &fra_token);
        assert_eq!(state(&a, &fra).0, "announce");
    }
    #[tokio::test]
    async fn a_node_waiting_on_its_program_gets_the_next_as_soon_as_a_surge_compiles_it() {
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
        for (node, token) in [(&lhr, &lhr_token), (&fra, &fra_token)] {
            let path = format!("/v1/nodes/{node}/heartbeat");
            assert_eq!(call(&mut a, 1, "POST", &path, token, json!({})).0, 200);
        }
        assert_eq!(state(&a, &fra).0, "withdraw");
        let held = a.store.programs[&fra].compiled_at.to_rfc3339();
        let s: Shared = Arc::new(Mutex::new(a));
        let path = format!("/v1/nodes/{fra}/program");
        let ask = |wait: &str, since: &str| {
            HashMap::from([
                ("wait".to_string(), wait.to_string()),
                ("since".to_string(), since.to_string()),
            ])
        };
        let by = |token: &str| {
            let mut h = HeaderMap::new();
            h.insert("Authorization", format!("Bearer {token}").parse().unwrap());
            h
        };
        let quick = |started: std::time::Instant| started.elapsed().as_millis() < 1000;
        // A node without this program, and a caller that may not read it, are answered at once.
        let started = std::time::Instant::now();
        hold(&s, &path, &ask("10s", ""), &by(&fra_token))
            .await
            .unwrap();
        hold(&s, &path, &ask("10s", &held), &by(&lhr_token))
            .await
            .unwrap();
        assert!(quick(started));
        for (wait, since) in [("soon", ""), ("10s", "yesterday")] {
            let e = hold(&s, &path, &ask(wait, since), &by(&fra_token)).await;
            assert_eq!(e.unwrap_err().0, 400);
        }
        // fra holds the program it has, so it waits for the next one.
        let waiting = tokio::spawn({
            let (s, path, query, headers) =
                (s.clone(), path.clone(), ask("10s", &held), by(&fra_token));
            async move { hold(&s, &path, &query, &headers).await }
        });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(!waiting.is_finished());
        // lhr's provisioner reports its customer's tunnel up: the fabric compiles again, but
        // fra's program comes out as it was, so fra goes on waiting.
        let compiled = {
            let mut a = s.lock().unwrap();
            let before = a.recompiles;
            let body = json!({"tunnels":[{"tunnel_id":"nw","state":"up"}]});
            let path = format!("/v1/nodes/{lhr}/heartbeat");
            assert_eq!(call(&mut a, 2, "POST", &path, &lhr_token, body).0, 200);
            a.recompiles - before
        };
        assert_eq!(compiled, 1);
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(!waiting.is_finished(), "a restamped program is nothing new");
        // A second into a flood, lhr's mean is a tenth of its last second, which is enough.
        let started = std::time::Instant::now();
        {
            let mut a = s.lock().unwrap();
            let body = json!({"stats":{"offered_pps":90_000,"surge_pps":900_000}});
            let path = format!("/v1/nodes/{lhr}/heartbeat");
            assert_eq!(call(&mut a, 3, "POST", &path, &lhr_token, body).0, 200);
        }
        waiting.await.unwrap().unwrap();
        assert!(quick(started));
        let a = s.lock().unwrap();
        assert_eq!(state(&a, &fra).0, "announce");
        assert_ne!(a.store.programs[&fra].compiled_at.to_rfc3339(), held);
        assert_eq!(
            a.steering.levels()[&lhr].reason,
            "shedding: the last second's load is 90% of capacity, above the 80% mark"
        );
    }
    #[test]
    fn a_waiting_node_is_answered_for_a_new_program_or_a_fence_but_not_a_restamp() {
        let mut a = api();
        let (node, _) = register(&mut a, 0, "edge-a", "192.0.2.1");
        deploy(
            &mut a,
            0,
            json!({"id":"nw","remote":"198.51.100.1","prefixes":["203.0.113.0/24"]}),
        );
        let held = a.store.programs.get(&node).cloned();
        assert!(!news(&a, &node, &held));
        let mut restamped = Program::clone(held.as_ref().unwrap());
        restamped.compiled_at = at(9);
        a.store
            .programs
            .insert(node.clone(), Arc::new(restamped.clone()));
        assert!(!news(&a, &node, &held));
        assert!(news(&a, &node, &None), "a first program");
        restamped.announcements.clear();
        a.store.programs.insert(node.clone(), Arc::new(restamped));
        assert!(news(&a, &node, &held));
        a.store.programs.remove(&node);
        assert!(news(&a, &node, &held), "a program withdrawn");
        assert!(!news(&a, &node, &None));
        // Its tunnel reports are ignored until it fetches again, so it is told to.
        a.fences.entry(node.clone()).or_default().insert(None);
        assert!(news(&a, &node, &None));
    }
    #[test]
    fn the_tunnel_view_shows_where_an_on_demand_customer_is_being_mitigated() {
        let mut a = api();
        let (node, token) = register(&mut a, 0, "edge-a", "192.0.2.1");
        deploy(
            &mut a,
            0,
            json!({"id":"nw","remote":"198.51.100.1","prefixes":["203.0.113.0/24"],"node":node,"rate_mbps":1000,"mitigation":"on_demand"}),
        );
        let view =
            |a: &mut Api| call(a, 1, "GET", "/v1/tunnels", OP, Value::Null).1["tunnels"][0].clone();
        let t = view(&mut a);
        assert_eq!(
            (&t["mitigation"], &t["attack_pps"], &t["attack_mbps"]),
            (&json!("on_demand"), &json!(122_070), &json!(500))
        );
        assert_eq!(
            (
                a.store.programs[&node].tunnels[0].attack_kbps,
                t["nodes"][0].get("mitigating")
            ),
            (500_000, None),
            "nothing is said until the node reports"
        );
        let body = json!({"stats":{"mitigation":[{"tunnel_id":"nw","active":true,"since":"2026-01-01T00:00:01Z","pps":400000,"bps":900000000,"attack_pps":122070,"attack_bps":500000000,"wave":2,"hold_seconds":600,"mitigations":2}]}});
        let path = format!("/v1/nodes/{node}/heartbeat");
        assert_eq!(call(&mut a, 1, "POST", &path, &token, body).0, 200);
        let row = view(&mut a)["nodes"][0].clone();
        assert_eq!(
            (
                &row["mitigating"],
                &row["mitigating_since"],
                &row["ingress_pps"],
                &row["mitigation_wave"],
                &row["mitigation_hold_seconds"]
            ),
            (
                &json!(true),
                &json!("2026-01-01T00:00:01Z"),
                &json!(400000),
                &json!(2),
                &json!(600)
            )
        );
        // The panel switches it, and sets thresholds, without restating the tunnel.
        let path = "/v1/tunnels/nw/mitigation";
        let set = json!({"mitigation":"on_demand","attack_mbps":200});
        let (status, answer) = call(&mut a, 2, "PUT", path, OP, set);
        assert_eq!(
            (status, &answer["tunnel"]["attack_mbps"]),
            (200, &json!(200)),
            "{answer}"
        );
        let t = view(&mut a);
        assert_eq!(
            (&t["attack_pps"], &t["attack_mbps"]),
            (&json!(48_828), &json!(200))
        );
        let wrong = json!({"mitigation":"always","attack_pps":5});
        assert_eq!(call(&mut a, 2, "PUT", path, OP, wrong).0, 400);
        let off = json!({"mitigation":"always"});
        assert_eq!(call(&mut a, 2, "PUT", path, OP, off).0, 200);
        let t = view(&mut a);
        assert_eq!(
            (&t["mitigation"], &t["attack_pps"]),
            (&json!("always"), &Value::Null)
        );
        assert_eq!(a.store.programs[&node].tunnels[0].mitigation, "");
    }
    #[test]
    fn training_refuses_a_model_that_would_drop_clean_traffic() {
        let mut a = api();
        let flow = |proto: &str, pps| json!({"proto":proto,"pps":pps,"dport":443});
        let wrong = json!({"samples":[{"flow":flow("udp",900000),"label":1,"known_good":true}]});
        let refused = call(&mut a, 0, "POST", "/v1/ml/samples", OP, wrong);
        assert_eq!(refused.0, 400, "{}", refused.1);
        // A clean sample that looks just like the attacks outnumbering it.
        let samples = json!({"samples":[
            {"flow":flow("udp",900000),"label":1},
            {"flow":flow("udp",900000),"label":1},
            {"flow":flow("udp",900000),"label":1},
            {"flow":flow("udp",900000),"label":0},
            {"flow":flow("tcp",40),"label":0},
        ]});
        assert_eq!(
            call(&mut a, 0, "POST", "/v1/ml/samples", OP, samples).0,
            200
        );
        let fit = json!({"epochs":300,"threshold":0.6});
        let (status, refused) = call(&mut a, 0, "POST", "/v1/ml/train", OP, fit.clone());
        assert_eq!(status, 422, "{refused}");
        assert_eq!(
            refused["error"],
            "not published: the flow model drops 50.0% of the clean samples it was measured on, over the 1.0% limit"
        );
        assert_eq!(refused["model"]["false_positive_rate"], 0.5);
        assert!(!a.store.data.model.ready, "nothing was published");
        let bad = json!({"max_false_positive_rate":1.5});
        assert_eq!(call(&mut a, 0, "POST", "/v1/ml/train", OP, bad).0, 400);
        // A limit of its own publishes it, to be tightened as far as it stays within that limit.
        let mut lenient = fit.clone();
        lenient["max_false_positive_rate"] = json!(0.5);
        let (status, published) = call(&mut a, 0, "POST", "/v1/ml/train", OP, lenient);
        assert_eq!(
            (status, &published["max_cut"]),
            (200, &json!(0.2)),
            "{published}"
        );
        // Forced past the default limit, it is published but never tightened.
        let mut forced = fit;
        forced["force"] = json!(true);
        let (status, published) = call(&mut a, 0, "POST", "/v1/ml/train", OP, forced);
        assert_eq!(
            (status, &published["max_cut"]),
            (200, &json!(0.0)),
            "{published}"
        );
        assert!(a.store.data.model.ready);
    }
    #[test]
    fn programs_carry_where_the_models_run() {
        let mut a = api();
        let (node, _) = register(&mut a, 0, "edge-a", "192.0.2.1");
        let wrong =
            json!({"id":"p","name":"p","protected":["203.0.113.0/24"],"ml":{"probing":"loosen"}});
        let refused = call(&mut a, 0, "POST", "/v1/policies", OP, wrong);
        assert_eq!(refused.0, 400);
        assert!(
            refused
                .1
                .as_str()
                .unwrap()
                .contains("use tighten or ignore"),
            "{}",
            refused.1
        );
        let policy = json!({"id":"p","name":"p","protected":["203.0.113.0/24"],"ml":{"scope":"inspect","mode":"observe","probing":"ignore"}});
        assert_eq!(call(&mut a, 0, "POST", "/v1/policies", OP, policy).0, 200);
        let deployed = call(&mut a, 0, "POST", "/v1/policies/p/deploy", OP, Value::Null);
        assert_eq!(deployed.0, 200);
        let ml = a.store.programs[&node].ml.clone().unwrap();
        assert_eq!(
            (ml.scope.as_str(), ml.mode.as_str(), ml.probing.as_str()),
            ("inspect", "observe", "ignore")
        );
    }
    #[test]
    fn nodes_get_a_heartbeat_timeout_to_check_in_before_they_are_helped() {
        let mut a = api();
        let (lhr, _) = register(&mut a, 0, "lhr", "192.0.2.1");
        let (fra, fra_token) = register(&mut a, 0, "fra", "192.0.2.2");
        deploy(
            &mut a,
            0,
            json!({"id":"nw","remote":"198.51.100.1","prefixes":["203.0.113.0/24"],"node":lhr}),
        );
        // What a restarted control plane, or a replica, starts from: every node stale.
        let mut data = a.store.data.clone();
        for n in &mut data.nodes {
            n.last_seen = zero_time();
        }
        let beat = |a: &mut Api, now: i64| {
            let path = format!("/v1/nodes/{fra}/heartbeat");
            assert_eq!(call(a, now, "POST", &path, &fra_token, Value::Null).0, 200);
        };
        let standing_by = |a: &Api| {
            let (status, reason) = state(a, &fra);
            status == "withdraw" && reason.starts_with(compiler::STANDING_BY)
        };
        let mut b = api();
        b.store.data = data.clone();
        beat(&mut b, 100);
        assert!(standing_by(&b), "{:?}", state(&b, &fra));
        beat(&mut b, 125);
        assert!(standing_by(&b));
        // lhr has had its chance and not taken it.
        beat(&mut b, 131);
        assert_eq!(state(&b, &fra).0, "announce");
        // A replica starts the clock again when it is promoted, however long it has been up.
        let mut c = api();
        c.mode = "replica".into();
        c.store.data = data;
        c.reconcile(at(0), false).unwrap();
        assert_eq!(
            call(&mut c, 500, "POST", "/v1/promote", OP, Value::Null).0,
            200
        );
        beat(&mut c, 501);
        assert!(standing_by(&c), "{:?}", state(&c, &fra));
        beat(&mut c, 531);
        assert_eq!(state(&c, &fra).0, "announce");
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
    #[test]
    fn a_full_fabric_takes_no_more_nodes_until_one_that_is_gone_is_retired() {
        let mut a = api();
        let (first, token) = register(&mut a, 0, "edge-0", "10.0.0.1");
        for i in 1..store::NODES_MAX {
            register(
                &mut a,
                0,
                &format!("edge-{i}"),
                &format!("10.{}.{}.1", i / 256, i % 256),
            );
        }
        let late = json!({"name":"edge-late","region":"iad"});
        let (status, body) = call(
            &mut a,
            0,
            "POST",
            "/v1/nodes/register",
            ENROLL,
            late.clone(),
        );
        assert_eq!(status, 413, "{body}");
        let refusal = body.as_str().unwrap();
        assert!(refusal.contains("DELETE /v1/nodes/"), "{body}");
        assert!(refusal.contains(&store::NODES_MAX.to_string()), "{body}");
        // A node already in the fabric still enrols again.
        register(&mut a, 0, "edge-0", "10.0.0.1");
        let gone = format!("/v1/nodes/{first}");
        let (status, body) = call(&mut a, 10, "DELETE", &gone, OP, Value::Null);
        assert_eq!(
            status, 409,
            "a node that is still running is not retired: {body}"
        );
        assert_eq!(
            call(&mut a, 60, "DELETE", &gone, &token, Value::Null).0,
            401
        );
        assert_eq!(
            call(&mut a, 60, "DELETE", "/v1/nodes/node-none", OP, Value::Null).0,
            404
        );
        let (_, second_token) = register(&mut a, 0, "edge-1", "10.0.1.1");
        assert_eq!(
            call(&mut a, 60, "DELETE", &gone, &second_token, Value::Null).0,
            403
        );
        assert_eq!(
            call(&mut a, 60, "DELETE", &gone, OP, Value::Null),
            (200, json!({"retired":first}))
        );
        assert!(!a.store.data.node_tokens.contains_key(&first));
        assert!(!a.store.reports.contains_key(&first));
        assert_eq!(call(&mut a, 60, "DELETE", &gone, OP, Value::Null).0, 404);
        assert_eq!(
            call(&mut a, 60, "POST", "/v1/nodes/register", ENROLL, late).0,
            200
        );
    }
    #[test]
    fn the_control_plane_keeps_a_bounded_number_of_policies_and_tenants() {
        let mut a = api();
        register(&mut a, 0, "edge-a", "192.0.2.1");
        let policy = |id: &str| json!({"id":id,"name":id,"protected":["203.0.113.0/24"]});
        for i in 0..store::POLICIES_MAX {
            assert_eq!(
                call(
                    &mut a,
                    0,
                    "POST",
                    "/v1/policies",
                    OP,
                    policy(&format!("p{i}"))
                )
                .0,
                200
            );
        }
        let (status, body) = call(&mut a, 0, "POST", "/v1/policies", OP, policy("extra"));
        assert_eq!(status, 413, "{body}");
        let unnamed = json!({"name":"unnamed","protected":["203.0.113.0/24"]});
        assert_eq!(call(&mut a, 0, "POST", "/v1/policies", OP, unnamed).0, 413);
        // Saving over one keeps no more of them.
        assert_eq!(
            call(&mut a, 0, "POST", "/v1/policies", OP, policy("p0")).0,
            200
        );
        assert_eq!(
            call(&mut a, 0, "POST", "/v1/policies/p0/deploy", OP, Value::Null).0,
            200
        );
        let (status, body) = call(&mut a, 0, "DELETE", "/v1/policies/p0", OP, Value::Null);
        assert_eq!(status, 409, "the deployed policy stays: {body}");
        assert_eq!(
            call(&mut a, 0, "DELETE", "/v1/policies/none", OP, Value::Null).0,
            404
        );
        assert_eq!(
            call(&mut a, 0, "DELETE", "/v1/policies/p1", OP, Value::Null),
            (200, json!({"deleted":"p1"}))
        );
        assert_eq!(
            call(&mut a, 0, "POST", "/v1/policies", OP, policy("extra")).0,
            200
        );
        assert_eq!(a.store.data.policies.len(), store::POLICIES_MAX);
        // Tenants: as many as the control plane keeps, with as many prefixes between them, then no
        // more of either until some go.
        let share = store::TENANT_PREFIXES_MAX / store::TENANTS_MAX;
        let entitled = |i: usize, n: usize| -> Vec<String> {
            (0..n)
                .map(|j| format!("10.{}.{}.{j}/32", i / 256, i % 256))
                .collect()
        };
        a.store.data.tenants = (0..store::TENANTS_MAX)
            .map(|i| Tenant {
                id: format!("ten-{i}"),
                name: format!("t{i}"),
                prefixes: entitled(i, share),
                ..Default::default()
            })
            .collect();
        let tenant = json!({"name":"late","prefixes":["198.51.100.0/24"]});
        let (status, body) = call(&mut a, 0, "POST", "/v1/tenants", OP, tenant);
        assert_eq!(status, 413, "{body}");
        let kept = json!({"id":"ten-7","name":"t7","prefixes":entitled(7, share)});
        assert_eq!(call(&mut a, 0, "POST", "/v1/tenants", OP, kept).0, 200);
        let grown = json!({"id":"ten-7","name":"t7","prefixes":entitled(7, share + 1)});
        let (status, body) = call(&mut a, 0, "POST", "/v1/tenants", OP, grown);
        assert_eq!(status, 413, "{body}");
        assert!(
            body.as_str().unwrap().contains("between all its tenants"),
            "{body}"
        );
    }
    #[test]
    fn a_policy_is_refused_past_what_every_node_could_be_compiled() {
        let mut a = api();
        let prefixes: Vec<String> = (0..=validation::PREFIXES_MAX)
            .map(|i| format!("10.{}.{}.0/24", i / 256, i % 256))
            .collect();
        let wide = json!({"name":"wide","protected":prefixes});
        let (status, body) = call(&mut a, 0, "POST", "/v1/policies", OP, wide);
        assert_eq!(status, 400);
        let most = format!("at most {} protected prefixes", validation::PREFIXES_MAX);
        assert!(body.as_str().unwrap().contains(&most), "{body}");
        let rules: Vec<Value> = (0..=validation::RULES_MAX)
            .map(|i| json!({"id":format!("r{i}"),"stage":"asic","action":"drop","match":{"proto":"udp","dport":i % 60000 + 1}}))
            .collect();
        let long = json!({"name":"long","protected":["203.0.113.0/24"],"rules":rules});
        let (status, body) = call(&mut a, 0, "POST", "/v1/policies", OP, long);
        assert_eq!(status, 400);
        let most = format!("at most {} rules", validation::RULES_MAX);
        assert!(body.as_str().unwrap().contains(&most), "{body}");
        let tenant = json!({"name":"wide","prefixes":prefixes});
        assert_eq!(call(&mut a, 0, "POST", "/v1/tenants", OP, tenant).0, 400);
    }
    #[test]
    fn the_training_set_is_bounded_in_bytes_as_well_as_samples() {
        use base64::Engine;
        let mut a = api();
        let carrying = |n: usize| {
            json!({"samples":[{"flow":{"src_ip":"192.0.2.1","dst_ip":"203.0.113.1","proto":"udp","dport":53,"pps":1,
                "payload":base64::engine::general_purpose::STANDARD.encode(vec![7u8; n])},"label":1}]})
        };
        let (status, body) = call(
            &mut a,
            0,
            "POST",
            "/v1/ml/samples",
            OP,
            carrying(ml::SAMPLE_MAX + 1),
        );
        assert_eq!(status, 400);
        assert!(body.as_str().unwrap().starts_with("samples[0]:"), "{body}");
        let full = ml::Sample {
            flow: Flow {
                payload: vec![7; ml::SAMPLE_MAX],
                ..Default::default()
            },
            label: 1,
            known_good: false,
        };
        a.store.data.samples = vec![full; ml::SAMPLE_BYTES_MAX / ml::SAMPLE_MAX];
        let stored = ml::sample_bytes(&a.store.data.samples);
        let room = ml::SAMPLE_BYTES_MAX - stored;
        let (status, body) = call(&mut a, 0, "POST", "/v1/ml/samples", OP, carrying(room + 1));
        assert_eq!(status, 413, "{body}");
        assert_eq!(body["stored_bytes"], json!(stored));
        assert_eq!(
            call(&mut a, 0, "POST", "/v1/ml/samples", OP, carrying(room)).0,
            200
        );
    }
    #[test]
    fn one_model_is_trained_at_a_time() {
        let shared: Shared = Arc::new(Mutex::new(api()));
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", format!("Bearer {OP}").parse().unwrap());
        shared.lock().unwrap().fitting = true;
        let (status, _) = train(&shared, &headers, b"{}").unwrap_err();
        assert_eq!(status, 409);
        shared.lock().unwrap().fitting = false;
        // A fit that fails lets the next one start.
        let refused = train(&shared, &headers, b"{}").unwrap_err();
        assert_ne!(refused.0, 409, "{refused:?}");
        assert!(!shared.lock().unwrap().fitting);
    }
    #[test]
    fn decide_keeps_the_pipelines_of_the_nodes_last_asked_about() {
        let mut a = api();
        let nodes: Vec<String> = (0..=DECIDE_PIPELINES)
            .map(|i| {
                register(
                    &mut a,
                    0,
                    &format!("edge-{i}"),
                    &format!("192.0.2.{}", i + 1),
                )
                .0
            })
            .collect();
        deploy(
            &mut a,
            0,
            json!({"id":"nw","remote":"198.51.100.1","prefixes":["203.0.113.0/24"]}),
        );
        let ask = |a: &mut Api, node: &str| {
            let body = json!({"node_id":node,"flow":{"src_ip":"192.0.2.200","dst_ip":"203.0.113.1","proto":"udp","dport":53,"pps":1}});
            assert_eq!(call(a, 1, "POST", "/v1/decide", OP, body).0, 200);
        };
        for n in &nodes {
            ask(&mut a, n);
        }
        assert_eq!(a.pipes.len(), DECIDE_PIPELINES);
        assert!(
            !a.pipes.contains_key(&nodes[0]),
            "the one asked about longest ago goes"
        );
        ask(&mut a, &nodes[1]);
        ask(&mut a, &nodes[0]);
        assert_eq!(a.pipes.len(), DECIDE_PIPELINES);
        assert!(a.pipes.contains_key(&nodes[1]) && a.pipes.contains_key(&nodes[0]));
        assert!(!a.pipes.contains_key(&nodes[2]));
    }
}
