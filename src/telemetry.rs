//! Prometheus projections of the existing report and routing contracts.
use crate::{
    analytics::rows,
    api::Api,
    metrics::{write_label, Label, Written, UNSHARED},
    model::*,
};
use serde_json::Value;
use std::{
    collections::{BTreeMap, HashMap},
    sync::OnceLock,
};
/// The families being rendered, with each sample's labels written out (see metrics::Written), the
/// labels samples share, which is each node's, and the first label Prometheus would refuse, if
/// one was added.
pub struct Metrics {
    families: BTreeMap<String, Written>,
    shared: Vec<String>,
    refused: Option<String>,
}
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
        Self {
            families: BTreeMap::new(),
            shared: Vec::new(),
            refused: None,
        }
    }
    pub fn add(&mut self, name: &str, labels: Vec<Label>, value: f64) {
        let mut written = String::new();
        for l in &labels {
            self.write(&mut written, &l.name, &l.value);
        }
        self.add_written(name, UNSHARED, &written, value);
    }
    /// Writes out labels that samples will share, returning what they give to carry them.
    fn share(&mut self, labels: &[Label]) -> u32 {
        let mut written = String::new();
        for l in labels {
            self.write(&mut written, &l.name, &l.value);
        }
        self.shared.push(written);
        (self.shared.len() - 1) as u32
    }
    fn write(&mut self, out: &mut String, name: &str, value: &str) {
        if let Err(e) = write_label(out, name, value) {
            self.refused.get_or_insert(e);
        }
    }
    fn add_written(&mut self, name: &str, shared: u32, own: &str, value: f64) {
        let f = self.families.entry(name.into()).or_insert_with(|| {
            let d = &descriptions()[name];
            Written::new(
                d["help"].as_str().unwrap_or("").into(),
                d["kind"].as_str().unwrap_or("gauge").into(),
            )
        });
        f.push(shared, own, value);
    }
    pub fn reports(&mut self, reports: &[Value], now: i64) {
        for report in reports {
            self.report(report, now);
        }
    }
    /// One node's report. A fabric's are read one at a time, so a scrape holds the samples it is
    /// rendering and never every node's counters twice over.
    pub fn report(&mut self, report: &Value, now: i64) {
        static B: OnceLock<Value> = OnceLock::new();
        let bindings =
            B.get_or_init(|| serde_json::from_str(include_str!("metric_bindings.json")).unwrap());
        {
            let id = identity(
                report["node_id"].as_str().unwrap_or(""),
                report["name"].as_str().unwrap_or(""),
                report["region"].as_str().unwrap_or(""),
            );
            let shared = self.share(&id);
            let mut own = String::new();
            let stats = &report["stats"];
            for b in bindings.as_array().unwrap() {
                let group = b["group"].as_str().unwrap();
                let sources: Vec<&Value> = match group {
                    "" => vec![stats],
                    "reputation" | "egress" => vec![&stats[group]],
                    "crafted" => rows(&stats["crafted"], "checks").iter().collect(),
                    _ => rows(stats, group).iter().collect(),
                };
                for s in sources {
                    own.clear();
                    let text = |key: &str| s[key].as_str().unwrap_or("");
                    let extra: &[(&str, &str)] = match group {
                        "stages" => &[("stage", text("stage"))],
                        "rules" => &[("stage", text("stage")), ("rule", text("rule_id"))],
                        "prefixes" => &[("prefix", text("prefix"))],
                        "games" => &[("filter", text("filter_id")), ("profile", text("profile"))],
                        "mitigation" => &[("tunnel", text("tunnel_id"))],
                        "crafted" => &[("check", text("check")), ("class", text("class"))],
                        _ => &[],
                    };
                    for (name, value) in extra {
                        self.write(&mut own, name, value);
                    }
                    let mut v = s;
                    for key in b["path"].as_array().unwrap() {
                        v = &v[key.as_str().unwrap()];
                    }
                    let v = v
                        .as_f64()
                        .unwrap_or_else(|| if v == true { 1.0 } else { 0.0 });
                    self.add_written(b["name"].as_str().unwrap(), shared, &own, v);
                }
            }
            if let Some(at) = report["reported_at"]
                .as_str()
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            {
                self.add_written(
                    "scrubline_report_age_seconds",
                    shared,
                    "",
                    (now - at.timestamp_millis()).max(0) as f64 / 1000.0,
                );
            }
            let mode = stats["egress"]["lockdown"]
                .as_str()
                .filter(|s| !s.is_empty())
                .unwrap_or("off");
            for candidate in ["off", "limit", "drop"] {
                own.clear();
                self.write(&mut own, "mode", candidate);
                let on = f64::from(candidate == mode);
                self.add_written("scrubline_egress_lockdown", shared, &own, on);
            }
            // A node from before the checks reports no mode, and has none running.
            let mode = stats["crafted"]["mode"].as_str().unwrap_or("off");
            for candidate in ["enforce", "observe", "off"] {
                own.clear();
                self.write(&mut own, "mode", candidate);
                let on = f64::from(candidate == mode);
                self.add_written("scrubline_crafted_mode", shared, &own, on);
            }
            for p in rows(&stats["egress"], "prefix_states") {
                own.clear();
                self.write(&mut own, "prefix", p["prefix"].as_str().unwrap_or(""));
                self.write(&mut own, "state", p["visibility"].as_str().unwrap_or(""));
                self.add_written("scrubline_egress_visibility", shared, &own, 1.0);
            }
        }
    }
    pub fn announcements(&mut self, plan: &[Announcement]) {
        // A plan holds a row for every prefix on every node, so each node's labels are written once.
        let mut nodes = HashMap::new();
        let mut own = String::new();
        for a in plan {
            let node = (a.node_id.as_str(), a.node_name.as_str(), a.region.as_str());
            let shared = match nodes.get(&node) {
                Some(&shared) => shared,
                None => {
                    let shared = self.share(&identity(node.0, node.1, node.2));
                    *nodes.entry(node).or_insert(shared)
                }
            };
            own.clear();
            self.write(&mut own, "prefix", &a.prefix);
            let announced = f64::from(a.state == "announce");
            self.add_written("scrubline_bgp_announced", shared, &own, announced);
            if a.state == "announce" {
                self.add_written("scrubline_bgp_prepends", shared, &own, a.prepends as f64);
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
        if let Some(e) = self.refused {
            return Err(e);
        }
        crate::metrics::render_written(self.families, &self.shared)
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
        (
            "scrubline_control_resident_bytes",
            crate::runtime::resident_bytes() as f64,
        ),
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
            "scrubline_control_ml_false_positive_rate",
            model.false_positive_rate,
        ),
        ("scrubline_control_ml_max_cut", model.max_cut),
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
        (
            "scrubline_control_ml_http_false_positive_rate",
            http.false_positive_rate,
        ),
        ("scrubline_control_ml_http_max_cut", http.max_cut),
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
    for report in api.store.reports.values() {
        m.report(
            &serde_json::to_value(report).unwrap_or_default(),
            now.timestamp_millis(),
        );
    }
    m.render()
}
