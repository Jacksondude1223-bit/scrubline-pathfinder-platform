//! Prometheus projections of the existing report and routing contracts.
use crate::{
    analytics::rows,
    api::Api,
    metrics::{write_label, Label, Written, UNSHARED},
    model::*,
    wire::Report,
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
                    "reflection" => rows(&stats["reflection"], "vectors").iter().collect(),
                    "protocols" => rows(&stats["protocols"], "by_protocol").iter().collect(),
                    "fragments" => rows(&stats["fragments"], "by_protocol").iter().collect(),
                    "icmp" => rows(&stats["icmp"], "kinds").iter().collect(),
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
                        "reflection" => &[("vector", text("vector"))],
                        "protocols" | "fragments" => &[("protocol", text("protocol"))],
                        "icmp" => &[("kind", text("kind"))],
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
            // And the other guards' modes, off for a node from before them.
            for (guard, metric) in [
                ("protocols", "scrubline_protocol_mode"),
                ("ack_flood", "scrubline_ack_flood_mode"),
                ("syn_flood", "scrubline_syn_flood_mode"),
                ("fragments", "scrubline_fragment_mode"),
                ("icmp", "scrubline_icmp_mode"),
            ] {
                let mode = stats[guard]["mode"].as_str().unwrap_or("off");
                for candidate in ["enforce", "observe", "off"] {
                    own.clear();
                    self.write(&mut own, "mode", candidate);
                    let on = f64::from(candidate == mode);
                    self.add_written(metric, shared, &own, on);
                }
            }
            // Likewise a node from before the reflection guard reports no vectors.
            for v in rows(&stats["reflection"], "vectors") {
                let mode = v["mode"].as_str().unwrap_or("off");
                for candidate in ["enforce", "observe", "off"] {
                    own.clear();
                    self.write(&mut own, "vector", v["vector"].as_str().unwrap_or(""));
                    self.write(&mut own, "mode", candidate);
                    let on = f64::from(candidate == mode);
                    self.add_written("scrubline_reflection_mode", shared, &own, on);
                }
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
        let reported: HashMap<&str, &TunnelStatus> =
            reports.iter().map(|r| (r.tunnel_id.as_str(), r)).collect();
        let shared = self.share(&identity(&node.id, &node.name, &node.region));
        let mut labels = String::new();
        for t in tunnels {
            labels.clear();
            self.write(&mut labels, "tunnel", &t.id);
            self.write(&mut labels, "remote", &t.remote);
            let report = reported.get(t.id.as_str());
            let state = report.map(|r| r.state.as_str()).unwrap_or("unknown");
            if state == "up" || state == "down" {
                let up = f64::from(state == "up");
                self.add_written("scrubline_tunnel_up", shared, &labels, up);
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
                self.add_written(name, shared, &labels, v);
            }
            if t.rate_kbps > 0 {
                let bits = t.rate_kbps as f64 * 1000.0;
                let name = "scrubline_tunnel_rate_limit_bits_per_second";
                self.add_written(name, shared, &labels, bits);
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
/// A scrape of the control plane: what it renders, copied out from under the control plane's
/// lock, which is let go before the series are built and written out.
pub struct Scrape {
    metrics: Metrics,
    reports: Vec<Report>,
    detail: Option<Detail>,
    now: i64,
}
/// One node's every series, as it renders them itself: its counters, its announcements and its
/// tunnels.
struct Detail {
    node: Node,
    announcements: Vec<Announcement>,
    tunnels: Vec<NodeTunnel>,
    statuses: Vec<TunnelStatus>,
}
impl Scrape {
    /// The fabric's view: the control plane's own series and each node's counters for the node
    /// as a whole. Its counters for each prefix, rule, filter and tunnel are left to the node's
    /// own view (Scrape::node): a fabric's worth of them is millions of series, more than one
    /// scrape can carry or the control plane can render without holding up its nodes.
    pub fn fleet(api: &Api) -> Self {
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
            }
            let statuses = api
                .store
                .tunnels()
                .get(&n.id)
                .map_or(&[][..], Vec::as_slice);
            for state in ["up", "down", "unknown"] {
                let mut labels = id.clone();
                labels.push(label("state", state));
                let count = statuses.iter().filter(|s| s.state == state).count();
                m.add("scrubline_node_tunnels", labels, count as f64);
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
        // How many nodes announce each protected prefix: none means nothing is drawing its traffic
        // to the fabric.
        let mut announcers: BTreeMap<&str, usize> = api
            .store
            .data
            .policies
            .iter()
            .filter(|p| p.id == api.store.data.last_policy_id)
            .flat_map(|p| p.protected.iter().map(|v| (v.as_str(), 0)))
            .collect();
        for a in api.store.plan.iter().filter(|a| a.state == "announce") {
            *announcers.entry(a.prefix.as_str()).or_default() += 1;
        }
        for (prefix, count) in announcers {
            let labels = vec![label("prefix", prefix)];
            m.add("scrubline_prefix_announcers", labels, count as f64);
        }
        let reports = api
            .store
            .reports
            .values()
            .map(|r| Report {
                node_id: r.node_id.clone(),
                name: r.name.clone(),
                region: r.region.clone(),
                stats: r.stats.summary(),
                reported_at: r.reported_at,
            })
            .collect();
        Self {
            metrics: m,
            reports,
            detail: None,
            now: now.timestamp_millis(),
        }
    }
    /// One node's every series, as the control plane last heard of them: what the node renders
    /// itself. None for a node the control plane does not know.
    pub fn node(api: &Api, id: &str) -> Option<Self> {
        let now = chrono::Utc::now();
        let node = api.store.nodes(now).into_iter().find(|n| n.id == id)?;
        let tunnels = api
            .store
            .programs
            .get(id)
            .map(|p| p.tunnels.clone())
            .unwrap_or_default();
        Some(Self {
            metrics: Metrics::new(),
            reports: api.store.reports.get(id).cloned().into_iter().collect(),
            detail: Some(Detail {
                announcements: api
                    .store
                    .plan
                    .iter()
                    .filter(|a| a.node_id == id)
                    .cloned()
                    .collect(),
                tunnels,
                statuses: api.store.tunnels().get(id).cloned().unwrap_or_default(),
                node,
            }),
            now: now.timestamp_millis(),
        })
    }
    pub fn render(self) -> crate::Result<String> {
        let mut m = self.metrics;
        for report in &self.reports {
            m.report(&serde_json::to_value(report).unwrap_or_default(), self.now);
        }
        if let Some(d) = self.detail {
            m.announcements(&d.announcements);
            m.tunnels(&d.node, &d.tunnels, &d.statuses);
        }
        m.render()
    }
}
