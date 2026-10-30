//! Version-one durable state compatible with existing Go snapshots.
use crate::{ml, model::*, Result};
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    io::Write,
    path::{Path, PathBuf},
};
/// How long a node may go without heartbeating before it is stale.
pub const STALE_AFTER: chrono::Duration = chrono::Duration::seconds(30);
/// The most of each the control plane keeps, so its memory has a ceiling a 16 GB server can give
/// it. Every node is compiled a program and keeps a report, so the fabric's size multiplies the
/// policy's (see validation::PREFIXES_MAX); policies and tenants are kept whole, every one of
/// them, and written out with the rest of the state on every change.
pub const NODES_MAX: usize = 128;
pub const POLICIES_MAX: usize = 32;
pub const TENANTS_MAX: usize = 4096;
/// The most prefixes all tenants are entitled to between them: each may hold as many as a policy
/// protects, but not every one of them at once.
pub const TENANT_PREFIXES_MAX: usize = 16_384;
/// What a registration beyond NODES_MAX is refused with.
pub const FABRIC_FULL: &str = "the fabric holds at most 128 nodes";
#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Snapshot {
    pub version: i64,
    pub saved_at: DateTime<Utc>,
    pub seq: i64,
    #[serde(deserialize_with = "crate::model::null_default")]
    pub nodes: Vec<Node>,
    #[serde(deserialize_with = "crate::model::null_default")]
    pub node_tokens: BTreeMap<String, String>,
    #[serde(deserialize_with = "crate::model::null_default")]
    pub policies: Vec<Policy>,
    pub last_policy_id: String,
    #[serde(deserialize_with = "crate::model::null_default")]
    pub samples: Vec<ml::Sample>,
    pub model: ml::Model,
    #[serde(
        deserialize_with = "crate::model::null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub tenants: Vec<Tenant>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    #[serde(deserialize_with = "crate::model::null_default")]
    pub tenant_tokens: BTreeMap<String, String>,
    /// Tunnel endpoints an operator assigned, by node id. They override the address a node
    /// registers with and survive its re-registration, so the operator stays in control of
    /// which address each node's tunnels terminate on.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    #[serde(deserialize_with = "crate::model::null_default")]
    pub tunnel_endpoints: BTreeMap<String, String>,
}
impl Default for Snapshot {
    fn default() -> Self {
        Self {
            version: 1,
            saved_at: zero_time(),
            seq: 0,
            nodes: vec![],
            node_tokens: BTreeMap::new(),
            policies: vec![],
            last_policy_id: String::new(),
            samples: vec![],
            model: ml::Model::default(),
            tenants: vec![],
            tenant_tokens: BTreeMap::new(),
            tunnel_endpoints: BTreeMap::new(),
        }
    }
}
pub struct Store {
    pub data: Snapshot,
    pub programs: BTreeMap<String, Program>,
    pub plan: Vec<Announcement>,
    pub reports: BTreeMap<String, crate::wire::Report>,
    pub tunnels: BTreeMap<String, Vec<TunnelStatus>>,
    path: Option<PathBuf>,
}
pub fn hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}
pub fn id(kind: &str, parts: &[&str]) -> String {
    let mut h = Sha256::new();
    h.update(kind.as_bytes());
    for p in parts {
        h.update([0]);
        h.update(p.as_bytes());
    }
    format!("{kind}-{}", hex::encode(&h.finalize()[..8]))
}
pub fn secret() -> Result<String> {
    let mut b = [0; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut b)
        .map_err(|e| format!("generating credential: {e}"))?;
    Ok(hex::encode(b))
}
impl Store {
    pub fn open(path: &str) -> Result<Self> {
        let mut s = Self {
            data: Snapshot::default(),
            programs: BTreeMap::new(),
            plan: vec![],
            reports: BTreeMap::new(),
            tunnels: BTreeMap::new(),
            path: if path.is_empty() {
                None
            } else {
                Some(path.into())
            },
        };
        if let Some(p) = &s.path {
            if p.exists() {
                let raw = std::fs::read(p).map_err(|e| e.to_string())?;
                let format: serde_json::Value =
                    serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
                if format["version"].as_i64() != Some(1) {
                    return Err("unsupported or missing snapshot version".into());
                }
                let snap: Snapshot = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
                if snap.version != 1 {
                    return Err(format!(
                        "snapshot format version {} is unsupported",
                        snap.version
                    ));
                }
                s.data = snap;
                for n in &mut s.data.nodes {
                    n.last_seen = zero_time();
                    n.status = "stale".into();
                }
            } else {
                s.persist()?;
            }
        }
        Ok(s)
    }
    pub fn snapshot(&self) -> Snapshot {
        let mut d = self.data.clone();
        d.saved_at = Utc::now();
        for n in &mut d.nodes {
            n.last_seen = zero_time();
            n.status = "stale".into();
        }
        d.nodes.sort_by(|a, b| a.id.cmp(&b.id));
        d.policies.sort_by(|a, b| a.id.cmp(&b.id));
        d.tenants
            .sort_by(|a, b| (&a.name, &a.id).cmp(&(&b.name, &b.id)));
        d
    }
    pub fn persist(&self) -> Result<()> {
        let Some(p) = &self.path else {
            return Ok(());
        };
        let raw = serde_json::to_vec(&self.snapshot()).map_err(|e| e.to_string())?;
        let tmp = p.with_extension(format!("{}.tmp", secret()?));
        let result = (|| -> std::io::Result<()> {
            let mut options = std::fs::OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&tmp)?;
            file.write_all(&raw)?;
            file.sync_all()?;
            drop(file);
            std::fs::rename(&tmp, p)?;
            std::fs::File::open(
                p.parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or(Path::new(".")),
            )?
            .sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(tmp);
        }
        result.map_err(|e| format!("persisting state: {e}"))
    }
    pub fn transaction<T>(&mut self, f: impl FnOnce(&mut Snapshot) -> Result<T>) -> Result<T> {
        let before = self.data.clone();
        match f(&mut self.data).and_then(|v| self.persist().map(|_| v)) {
            Ok(v) => Ok(v),
            Err(e) => {
                self.data = before;
                Err(e)
            }
        }
    }
    pub fn load_snapshot(&mut self, mut snap: Snapshot) -> Result<()> {
        if snap.version != 1 {
            return Err("unsupported snapshot version".into());
        }
        for n in &mut snap.nodes {
            n.last_seen = zero_time();
            n.status = "stale".into();
        }
        self.transaction(|data| {
            *data = snap;
            Ok(())
        })?;
        self.programs.clear();
        self.plan.clear();
        self.reports.clear();
        self.tunnels.clear();
        Ok(())
    }
    /// A node as the fabric uses it: with the operator's tunnel endpoint, if one is assigned, in
    /// place of the one it registered with.
    pub fn effective(&self, mut n: Node) -> Node {
        if let Some(endpoint) = self.data.tunnel_endpoints.get(&n.id) {
            n.tunnel_src = endpoint.clone();
        }
        n
    }
    pub fn nodes(&self, now: DateTime<Utc>) -> Vec<Node> {
        let mut ns: Vec<_> = self
            .data
            .nodes
            .iter()
            .map(|n| self.effective(n.clone()))
            .collect();
        for n in &mut ns {
            n.status = if now.signed_duration_since(n.last_seen) > STALE_AFTER {
                "stale"
            } else {
                "ready"
            }
            .into();
        }
        // Two nodes on one tunnel address would each take the other's customer replies. The API
        // refuses that, but a node that went quiet can come back to find its address given away,
        // so whoever has the stronger claim keeps it: an operator's assignment, then a live node
        // over a quiet one. A claim that cannot be settled that way is void, and those nodes
        // withdraw what they cannot deliver rather than share.
        let claim = |n: &Node| {
            if self.data.tunnel_endpoints.contains_key(&n.id) {
                2
            } else {
                u8::from(n.status != "stale")
            }
        };
        let mut best: HashMap<String, (u8, usize)> = HashMap::new();
        for n in ns.iter().filter(|n| !n.tunnel_src.is_empty()) {
            let entry = best.entry(n.tunnel_src.clone()).or_insert((claim(n), 0));
            match claim(n).cmp(&entry.0) {
                std::cmp::Ordering::Greater => *entry = (claim(n), 1),
                std::cmp::Ordering::Equal => entry.1 += 1,
                std::cmp::Ordering::Less => {}
            }
        }
        for n in &mut ns {
            if let Some(&(strongest, holders)) = best.get(&n.tunnel_src) {
                if claim(n) < strongest || holders > 1 {
                    n.tunnel_src.clear();
                }
            }
        }
        ns.sort_by(|a, b| (&a.name, &a.id).cmp(&(&b.name, &b.id)));
        ns
    }
    pub fn register(&mut self, mut n: Node, now: DateTime<Utc>) -> Result<(Node, String)> {
        if n.id.is_empty() {
            n.id = id("node", &[&n.name, &n.region]);
        }
        if n.backends.is_empty() {
            n.backends = vec!["asic".into(), "fpga".into(), "zc".into()];
        }
        if let Some(old) = self.data.nodes.iter().find(|o| o.id == n.id) {
            if now.signed_duration_since(old.last_seen) <= STALE_AFTER
                && !old.advertise.is_empty()
                && !n.advertise.is_empty()
                && old.advertise != n.advertise
            {
                return Err(
                    "a different live node is already registered under this name and region".into(),
                );
            }
        }
        if !self.data.nodes.iter().any(|o| o.id == n.id) && self.data.nodes.len() >= NODES_MAX {
            return Err(format!(
                "{FABRIC_FULL}; retire one that is gone for good with DELETE /v1/nodes/{{id}}"
            ));
        }
        n.last_seen = now;
        n.status = "ready".into();
        let token = secret()?;
        self.transaction(|d| {
            d.nodes.retain(|v| v.id != n.id);
            d.nodes.push(n.clone());
            d.node_tokens.insert(n.id.clone(), hash(&token));
            Ok(())
        })?;
        // As registered: an operator's assignment reaches the node in its program, so an agent
        // never mistakes it for an address of its own to fall back to once it is cleared.
        Ok((n, token))
    }
    pub fn save_policy(&mut self, mut p: Policy, now: DateTime<Utc>) -> Result<Policy> {
        self.transaction(|d| {
            if p.id.is_empty() {
                loop {
                    d.seq += 1;
                    p.id = format!("pol-{}", d.seq);
                    if !d.policies.iter().any(|v| v.id == p.id) {
                        break;
                    }
                }
            }
            p.version = d
                .policies
                .iter()
                .find(|v| v.id == p.id)
                .map(|v| v.version + 1)
                .unwrap_or(1);
            p.updated_at = now;
            d.policies.retain(|v| v.id != p.id);
            d.policies.push(p.clone());
            Ok(p)
        })
    }
    /// Forgets a node: its record, its credential and its assigned tunnel endpoint, and what it
    /// last reported. False when there is no such node.
    pub fn retire(&mut self, id: &str) -> Result<bool> {
        if !self.data.nodes.iter().any(|n| n.id == id) {
            return Ok(false);
        }
        self.transaction(|d| {
            d.nodes.retain(|n| n.id != id);
            d.node_tokens.remove(id);
            d.tunnel_endpoints.remove(id);
            Ok(())
        })?;
        self.reports.remove(id);
        self.programs.remove(id);
        self.tunnels.remove(id);
        Ok(true)
    }
    /// Forgets a policy. False when there is no such policy.
    pub fn forget_policy(&mut self, id: &str) -> Result<bool> {
        if !self.data.policies.iter().any(|p| p.id == id) {
            return Ok(false);
        }
        self.transaction(|d| {
            d.policies.retain(|p| p.id != id);
            Ok(())
        })?;
        Ok(true)
    }
    pub fn save_tenant(&mut self, mut t: Tenant, now: DateTime<Utc>) -> Result<Tenant> {
        self.transaction(|d| {
            if t.id.is_empty() {
                t.id = id("ten", &[&t.name]);
            }
            t.created_at = d
                .tenants
                .iter()
                .find(|v| v.id == t.id)
                .map(|v| v.created_at)
                .unwrap_or(now);
            t.updated_at = now;
            d.tenants.retain(|v| v.id != t.id);
            d.tenants.push(t.clone());
            Ok(t)
        })
    }
    pub fn issue(&mut self, id: &str, tenant: bool) -> Result<String> {
        let token = secret()?;
        self.transaction(|d| {
            if tenant {
                if !d.tenants.iter().any(|v| v.id == id) {
                    return Err("unknown tenant".into());
                }
                d.tenant_tokens.insert(id.into(), hash(&token));
            } else {
                d.node_tokens.insert(id.into(), hash(&token));
            }
            Ok(())
        })?;
        Ok(token)
    }
}
