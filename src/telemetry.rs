//! Prometheus projections of the existing report and routing contracts.
use crate::{
    analytics::rows,
    api::Api,
    metrics::{Family, Label, Sample},
    model::*,
};
use serde_json::Value;
use std::{collections::BTreeMap, sync::OnceLock};
pub struct Metrics(BTreeMap<String, Family>);
fn descriptions() -> &'static Value {
    static D: OnceLock<Value> = OnceLock::new();
    D.get_or_init(|| serde_json::from_str(include_str!("metric_descriptions.json")).unwrap())
}
fn identity(node: &str, name: &str, region: &str) -> Vec<Label> {
    vec![
        label("node", node),
        label("name", name),
        label("region", region),
    ]
}
fn label(name: &str, value: &str) -> Label {
    Label {
        name: name.into(),
        value: value.into(),
    }
}
impl Metrics {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }
    pub fn add(&mut self, name: &str, labels: Vec<Label>, value: f64) {
        let d = &descriptions()[name];
        let f = self.0.entry(name.into()).or_insert_with(|| Family {
            name: name.into(),
            help: d["help"].as_str().unwrap_or("").into(),
            kind: d["kind"].as_str().unwrap_or("gauge").into(),
            samples: vec![],
        });
        f.samples.push(Sample { labels, value });
    }
    pub fn reports(&mut self, reports: &[Value], now: i64) {
        static B: OnceLock<Value> = OnceLock::new();
        let bindings =
            B.get_or_init(|| serde_json::from_str(include_str!("metric_bindings.json")).unwrap());
        for report in reports {
            let id = identity(
                report["node_id"].as_str().unwrap_or(""),
                report["name"].as_str().unwrap_or(""),
                report["region"].as_str().unwrap_or(""),
            );
            let stats = &report["stats"];
            for b in bindings.as_array().unwrap() {
                let group = b["group"].as_str().unwrap();
                let sources: Vec<&Value> = match group {
                    "" => vec![stats],
                    "reputation" | "egress" => vec![&stats[group]],
                    _ => rows(stats, group).iter().collect(),
                };
                for s in sources {
                    let mut labels = id.clone();
                    match group {
                        "stages" => labels.push(label("stage", s["stage"].as_str().unwrap_or(""))),
                        "rules" => {
                            labels.push(label("stage", s["stage"].as_str().unwrap_or("")));
                            labels.push(label("rule", s["rule_id"].as_str().unwrap_or("")));
                        }
                        "prefixes" => {
                            labels.push(label("prefix", s["prefix"].as_str().unwrap_or("")))
                        }
                        "games" => {
                            labels.push(label("filter", s["filter_id"].as_str().unwrap_or("")));
                            labels.push(label("profile", s["profile"].as_str().unwrap_or("")));
                        }
                        _ => {}
                    }
                    let mut v = s;
                    for key in b["path"].as_array().unwrap() {
                        v = &v[key.as_str().unwrap()];
                    }
                    let v = v
                        .as_f64()
                        .unwrap_or_else(|| if v == true { 1.0 } else { 0.0 });
                    self.add(b["name"].as_str().unwrap(), labels, v);
                }
            }
            if let Some(at) = report["reported_at"]
                .as_str()
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            {
                self.add(
                    "scrubline_report_age_seconds",
                    id.clone(),
                    (now - at.timestamp_millis()).max(0) as f64 / 1000.0,
                );
            }
            let mode = stats["egress"]["lockdown"]
                .as_str()
                .filter(|s| !s.is_empty())
                .unwrap_or("off");
            for candidate in ["off", "limit", "drop"] {
                let mut labels = id.clone();
                labels.push(label("mode", candidate));
                self.add(
                    "scrubline_egress_lockdown",
                    labels,
                    f64::from(candidate == mode),
                );
            }
            for p in rows(&stats["egress"], "prefix_states") {
                let mut labels = id.clone();
                labels.push(label("prefix", p["prefix"].as_str().unwrap_or("")));
                labels.push(label("state", p["visibility"].as_str().unwrap_or("")));
                self.add("scrubline_egress_visibility", labels, 1.0);
            }
        }
    }
    pub fn announcements(&mut self, plan: &[Announcement]) {
        for a in plan {
            let mut labels = identity(&a.node_id, &a.node_name, &a.region);
            labels.push(label("prefix", &a.prefix));
            self.add(
                "scrubline_bgp_announced",
                labels.clone(),
                f64::from(a.state == "announce"),
            );
            if a.state == "announce" {
                self.add("scrubline_bgp_prepends", labels, a.prepends as f64);
            }
        }
    }
    pub fn tunnels(&mut self, node: &Node, tunnels: &[NodeTunnel], reports: &[TunnelStatus]) {
        for t in tunnels {
            let mut labels = identity(&node.id, &node.name, &node.region);
            labels.push(label("tunnel", &t.id));
            labels.push(label("remote", &t.remote));
            let report = reports.iter().find(|r| r.tunnel_id == t.id);
            let state = report.map(|r| r.state.as_str()).unwrap_or("unknown");
            if state == "up" || state == "down" {
                self.add(
                    "scrubline_tunnel_up",
                    labels.clone(),
                    f64::from(state == "up"),
                );
            }
            for (name, v) in [
                // Reporting "unknown" is still a provisioner speaking, which is what this tells
                // apart from one that is not wired up at all.
                ("scrubline_tunnel_reported", f64::from(report.is_some())),
                ("scrubline_tunnel_required", f64::from(t.required)),
                ("scrubline_tunnel_mtu_bytes", t.mtu as f64),
                ("scrubline_tunnel_mss_clamp_bytes", t.mss_clamp as f64),
                ("scrubline_tunnel_prefixes", t.prefixes.len() as f64),
            ] {
                self.add(name, labels.clone(), v);
            }
            if t.rate_kbps > 0 {
                self.add(
                    "scrubline_tunnel_rate_limit_bits_per_second",
                    labels.clone(),
                    t.rate_kbps as f64 * 1000.0,
                );
            }
        }
    }
    pub fn render(self) -> crate::Result<String> {
        crate::metrics::render(&self.0.into_values().collect::<Vec<_>>())
    }
}
impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}
pub fn control(api: &Api) -> crate::Result<String> {
    let mut m = Metrics::new();
    let now = chrono::Utc::now();
    let nodes = api.store.nodes(now);
    let ready = nodes.iter().filter(|n| n.status == "ready").count();
    m.add(
        "scrubline_nodes",
        vec![label("status", "ready")],
        ready as f64,
    );
    m.add(
        "scrubline_nodes",
        vec![label("status", "stale")],
        (nodes.len() - ready) as f64,
    );
    let model = &api.store.data.model;
    let unfitted = crate::ml::Model::default();
    let http = model.http.as_deref().unwrap_or(&unfitted);
    let (recompiles, requests, levels) = api.metric_state();
    for (name, v) in [
        ("scrubline_policies", api.store.data.policies.len() as f64),
        ("scrubline_announcements", api.store.plan.len() as f64),
        ("scrubline_programs", api.store.programs.len() as f64),
        ("scrubline_fabric_recompiles_total", recompiles as f64),
        ("scrubline_control_ml_model_ready", f64::from(model.ready)),
        ("scrubline_control_ml_samples", model.samples as f64),
        (
            "scrubline_control_ml_validation_samples",
            model.validation as f64,
        ),
        ("scrubline_control_ml_accuracy", model.accuracy),
        ("scrubline_control_ml_precision", model.precision),
        ("scrubline_control_ml_recall", model.recall),
        (
            "scrubline_control_ml_http_model_ready",
            f64::from(http.ready),
        ),
        ("scrubline_control_ml_http_samples", http.samples as f64),
        (
            "scrubline_control_ml_http_validation_samples",
            http.validation as f64,
        ),
        ("scrubline_control_ml_http_accuracy", http.accuracy),
        ("scrubline_control_ml_http_precision", http.precision),
        ("scrubline_control_ml_http_recall", http.recall),
    ] {
        m.add(name, vec![], v);
    }
    for n in &nodes {
        let id = identity(&n.id, &n.name, &n.region);
        if let Some(prog) = api.store.programs.get(&n.id) {
            m.add(
                "scrubline_node_prefixes",
                id.clone(),
                prog.prefixes.len() as f64,
            );
            m.tunnels(
                n,
                &prog.tunnels,
                api.store
                    .tunnels
                    .get(&n.id)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]),
            );
        }
        if let Some(level) = levels.get(&n.id) {
            m.add(
                "scrubline_steering_escalation",
                id.clone(),
                level.prepends as f64,
            );
            m.add("scrubline_steering_load_ratio", id.clone(), level.ratio);
            m.add("scrubline_node_capacity_pps", id, n.capacity_pps as f64);
        }
    }
    for ((route, status), count) in requests {
        m.add(
            "scrubline_api_requests_total",
            vec![label("route", route), label("status", &status.to_string())],
            *count as f64,
        );
    }
    m.announcements(&api.store.plan);
    m.reports(
        &api.store.reports.values().cloned().collect::<Vec<_>>(),
        now.timestamp_millis(),
    );
    m.render()
}
