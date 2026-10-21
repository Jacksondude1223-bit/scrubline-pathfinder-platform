//! Node agent: local API, authenticated enrollment, heartbeats and program/model polling.
use crate::{
    bgp, ml,
    model::*,
    pipeline::Pipeline,
    runtime::{self, Flags},
    telemetry::Metrics,
    tunnel, Result,
};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::any,
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashSet},
    sync::{Arc, Mutex},
    time::Duration,
};
use subtle::ConstantTimeEq;
pub struct Agent {
    pub node: Node,
    pub pipe: Pipeline,
    local_token: String,
    health: Vec<TunnelStatus>,
    local_as: i64,
    next_hop: String,
    // Prefixes this node announced that have since left its plan, kept as withdrawals: ExaBGP
    // holds a route until told otherwise, and the pipeline no longer scrubs what it attracts.
    retired: BTreeMap<String, Announcement>,
}
type Shared = Arc<Mutex<Agent>>;
fn json_response(code: u16, v: Value) -> Response {
    (StatusCode::from_u16(code).unwrap(), Json(v)).into_response()
}
fn error(code: u16, e: impl ToString) -> Response {
    json_response(code, json!({"error":e.to_string()}))
}
fn text(lines: Vec<String>) -> Response {
    (
        [("Content-Type", "text/plain; charset=utf-8")],
        if lines.is_empty() {
            String::new()
        } else {
            lines.join("\n") + "\n"
        },
    )
        .into_response()
}
// A text format is written straight into a daemon's configuration, so a rendering failure must not
// look like an empty plan: an empty 200 would have a speaker withdraw everything.
fn rendered(lines: Vec<String>, err: &str) -> Response {
    if err.is_empty() {
        text(lines)
    } else {
        error(500, format!("could not render: {err}"))
    }
}
fn hostname() -> String {
    // HOSTNAME is a shell variable, usually not exported, so read the kernel's name first.
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok().filter(|h| !h.is_empty()))
        .unwrap_or_else(|| "localhost".into())
}
impl Agent {
    /// Installs a newly fetched program, turning anything it stopped announcing into a withdrawal.
    pub fn install(&mut self, prog: Program) {
        let planned: HashSet<_> = prog.announcements.iter().map(|a| &a.prefix).collect();
        for a in &self.pipe.program.announcements {
            if a.state == "announce" && !planned.contains(&a.prefix) {
                self.retired.insert(
                    a.prefix.clone(),
                    Announcement {
                        state: "withdraw".into(),
                        prepends: 0,
                        reason: "no longer in this node's plan".into(),
                        ..a.clone()
                    },
                );
            }
        }
        self.retired.retain(|prefix, _| !planned.contains(prefix));
        // What the provisioner said about a tunnel stops applying once the tunnel leaves this
        // node's program or is rebuilt between other ends. It rides every heartbeat, so keeping
        // it would let a required tunnel be announced on a report about the one it replaced.
        let old = &self.pipe.program.tunnels;
        self.health.retain(|h| {
            prog.tunnels.iter().any(|t| {
                t.id == h.tunnel_id
                    && old.iter().any(|o| {
                        o.id == t.id
                            && o.local == t.local
                            && o.remote == t.remote
                            && o.key == t.key
                            && o.r#type == t.r#type
                    })
            })
        });
        self.pipe.load(prog);
    }
    /// This node with the tunnel endpoint the control plane holds for it, which an operator may
    /// have reassigned since the agent registered.
    fn peering_node(&self) -> Node {
        let mut node = self.node.clone();
        if !self.pipe.program.tunnel_src.is_empty() {
            node.tunnel_src = self.pipe.program.tunnel_src.clone();
        }
        node
    }
    fn announcements(&self) -> Vec<Announcement> {
        let mut rows = self.pipe.program.announcements.clone();
        rows.extend(self.retired.values().cloned());
        if !self.next_hop.is_empty() {
            for a in &mut rows {
                a.next_hop = self.next_hop.clone();
            }
        }
        rows
    }
    fn report(&mut self) -> Value {
        json!({"node_id":self.node.id,"name":self.node.name,"region":self.node.region,"stats":self.pipe.stats(chrono::Utc::now().timestamp_millis()),"reported_at":chrono::Utc::now()})
    }
    fn dispatch(&mut self, method: &str, uri: &Uri, headers: &HeaderMap, body: &[u8]) -> Response {
        if uri.path() == "/health" {
            return json_response(
                200,
                json!({"node":self.node.id,"name":self.node.name,"datapath":"asic-tcam+fpga+pfring-zc"}),
            );
        }
        if ![
            "/metrics",
            "/bgp",
            "/tunnels",
            "/sessions",
            "/egress",
            "/reputation",
            "/decide",
        ]
        .contains(&uri.path())
        {
            return error(404, "not found");
        }
        let auth = headers
            .get("Authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.split_once(' '));
        if !auth.is_some_and(|(scheme, token)| {
            scheme.eq_ignore_ascii_case("Bearer")
                && bool::from(token.as_bytes().ct_eq(self.local_token.as_bytes()))
        }) {
            return error(401, "missing or invalid bearer token");
        }
        let query: std::collections::HashMap<_, _> = uri
            .query()
            .map(|q| {
                reqwest::Url::parse(&format!("http://local/?{q}"))
                    .unwrap()
                    .query_pairs()
                    .map(|(a, b)| (a.into_owned(), b.into_owned()))
                    .collect()
            })
            .unwrap_or_default();
        let format = query.get("format").map(String::as_str).unwrap_or("");
        let ms = chrono::Utc::now().timestamp_millis();
        match (method, uri.path()) {
            ("GET", "/metrics") => {
                let report = self.report();
                let mut m = Metrics::new();
                m.reports(&[report], ms);
                m.announcements(&self.announcements());
                m.tunnels(&self.node, &self.pipe.program.tunnels, &self.health);
                match m.render() {
                    Ok(v) => ([("Content-Type", crate::metrics::CONTENT_TYPE)], v).into_response(),
                    Err(e) => error(500, e),
                }
            }
            ("GET", "/bgp") => {
                let announcements = self.announcements();
                let (commands, err) = match bgp::commands(&announcements, self.local_as) {
                    Ok(v) => (v, String::new()),
                    Err(e) => (vec![], e),
                };
                if format == "exabgp" {
                    return rendered(commands, &err);
                }
                json_response(
                    200,
                    json!({"node":self.node.id,"local_as":self.local_as,"announcements":announcements,"exabgp":commands,"error":err}),
                )
            }
            ("GET", "/tunnels") => {
                let tunnels = &self.pipe.program.tunnels;
                let rendered_all = tunnel::commands(tunnels).and_then(|mut lines| {
                    lines.extend(tunnel::reply_commands(tunnels)?);
                    lines.extend(tunnel::rate_commands(tunnels)?);
                    Ok(lines)
                });
                let (commands, err) = match rendered_all {
                    Ok(v) => (v, String::new()),
                    Err(e) => (vec![], e),
                };
                if format == "iproute2" {
                    return rendered(commands, &err);
                }
                json_response(
                    200,
                    json!({"node":self.node.id,"tunnels":self.pipe.program.tunnels,"iproute2":commands,"status":self.health,"error":err}),
                )
            }
            ("POST", "/tunnels") => {
                #[derive(Deserialize)]
                struct Body {
                    tunnels: Vec<TunnelStatus>,
                }
                let body: Body = match serde_json::from_slice(body) {
                    Ok(v) => v,
                    Err(e) => return error(400, e),
                };
                let mut seen = HashSet::new();
                for t in &body.tunnels {
                    if t.tunnel_id.is_empty() {
                        return error(400, "tunnel_id required");
                    }
                    if let Err(e) = tunnel::validate_status(&t.state) {
                        return error(400, e);
                    }
                    if !seen.insert(&t.tunnel_id) {
                        return error(400, format!("duplicate tunnel_id {:?}", t.tunnel_id));
                    }
                }
                self.health = body.tunnels;
                for t in &mut self.health {
                    t.reported_at = chrono::Utc::now();
                }
                self.health.sort_by(|a, b| a.tunnel_id.cmp(&b.tunnel_id));
                json_response(200, json!({"accepted":self.health.len()}))
            }
            ("GET", "/sessions") => {
                let (config, err) = if self.pipe.program.sessions.is_empty() {
                    (vec![], String::new())
                } else {
                    match bgp::session_config(
                        &self.pipe.program.sessions,
                        &self.peering_node(),
                        self.local_as,
                    ) {
                        Ok(v) => (v, String::new()),
                        Err(e) => (vec![], e),
                    }
                };
                if format == "bird" {
                    return rendered(config, &err);
                }
                json_response(
                    200,
                    json!({"node":self.node.id,"sessions":self.pipe.program.sessions,"bird":config,"error":err}),
                )
            }
            ("GET", "/reputation") => {
                let limit = match query.get("limit") {
                    Some(s) => match s.parse::<usize>() {
                        Ok(n) if n > 0 => n,
                        _ => return error(400, "limit must be a positive number"),
                    },
                    None => 100,
                };
                json_response(
                    200,
                    json!({"node":self.node.id,"stats":self.pipe.reputation.stats(ms),"sources":self.pipe.reputation.sources(limit,ms)}),
                )
            }
            ("POST", "/reputation") => {
                #[derive(Deserialize)]
                struct Body {
                    release: Vec<String>,
                }
                let body: Body = match serde_json::from_slice(body) {
                    Ok(v) => v,
                    Err(e) => return error(400, e),
                };
                if body.release.is_empty() {
                    return error(400, "release requires at least one source address");
                }
                let released = body
                    .release
                    .iter()
                    .filter(|src| self.pipe.reputation.release(src, ms))
                    .count();
                json_response(200, json!({"released":released}))
            }
            ("POST", path @ ("/decide" | "/egress")) => {
                let flow: Flow = match serde_json::from_slice(body) {
                    Ok(v) => v,
                    Err(e) => return error(400, e),
                };
                if let Err(e) = ml::validate_flow(&flow) {
                    return error(400, e);
                }
                if path == "/egress" {
                    self.pipe.observe_return(&flow, ms);
                    json_response(200, json!({"observed":true}))
                } else {
                    let mut d = self.pipe.decide(&flow, ms);
                    d.node_id = self.node.id.clone();
                    json_response(200, serde_json::to_value(d).unwrap())
                }
            }
            (_, "/tunnels" | "/reputation") => error(405, "GET or POST required"),
            (_, "/decide" | "/egress") => error(405, "POST required"),
            _ => error(405, "GET required"),
        }
    }
}
async fn handler(
    State(s): State<Shared>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    tokio::task::spawn_blocking(move || {
        s.lock()
            .unwrap()
            .dispatch(method.as_str(), &uri, &headers, &body)
    })
    .await
    .unwrap_or_else(|_| error(500, "request worker failed"))
}
#[derive(Deserialize)]
struct Enrollment {
    node: Node,
    token: String,
}
async fn enroll(
    client: &reqwest::Client,
    api: &str,
    token: &str,
    node: &Node,
) -> Result<Enrollment> {
    let r = client
        .post(format!("{api}/v1/nodes/register"))
        .bearer_auth(token)
        .json(node)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !r.status().is_success() {
        return Err(format!(
            "registration: {} {}",
            r.status(),
            r.text().await.unwrap_or_default()
        ));
    }
    r.json().await.map_err(|e| e.to_string())
}
async fn fetch<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
    token: &str,
) -> Result<T> {
    let r = client
        .get(url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !r.status().is_success() {
        return Err(format!("fetch: {}", r.status()));
    }
    r.json().await.map_err(|e| e.to_string())
}
pub async fn run() -> Result<()> {
    let f = Flags::parse(&[
        ("api", "http://127.0.0.1:8080"),
        ("name", "scrub-a"),
        ("region", "iad"),
        ("capacity", "40"),
        ("capacity-pps", "0"),
        ("listen", "127.0.0.1:9091"),
        ("advertise", ""),
        ("local-as", "0"),
        ("bgp-next-hop", ""),
        ("tunnel-src", ""),
        ("tls-cert", ""),
        ("tls-key", ""),
        ("ca", ""),
        ("insecure", "false"),
    ])?;
    let enroll_token = runtime::required_env("SCRUBLINE_ENROLL_TOKEN")?;
    let local_token = runtime::required_env("SCRUBLINE_NODE_API_TOKEN")?;
    let api = f.get("api").trim_end_matches('/').to_owned();
    let client = runtime::client(f.get("ca"), Duration::from_secs(5))?;
    let local_as = f.integer("local-as")?;
    if !(0..=u32::MAX as i64).contains(&local_as) {
        return Err("local-as out of range".into());
    }
    let next_hop = f.get("bgp-next-hop").to_string();
    if !next_hop.is_empty() {
        next_hop
            .parse::<std::net::IpAddr>()
            .map_err(|e| e.to_string())?;
    }
    let advertise = if !f.get("advertise").is_empty() {
        f.get("advertise").to_owned()
    } else {
        let listen = f.get("listen");
        if listen.starts_with("0.0.0.0:") || listen.starts_with("[::]:") {
            format!("{}:{}", hostname(), listen.rsplit(':').next().unwrap())
        } else {
            listen.into()
        }
    };
    let host = advertise
        .rsplit_once(':')
        .map_or(advertise.as_str(), |(h, _)| h)
        .trim_matches(['[', ']']);
    if next_hop.is_empty() && host.parse::<std::net::IpAddr>().is_err() {
        eprintln!(
            "warning: advertise host {host:?} is not an IP address, so announcements carry no next hop; pass -bgp-next-hop"
        );
    }
    let desired = Node {
        name: f.get("name").into(),
        region: f.get("region").into(),
        capacity_gbps: f.float("capacity")?,
        capacity_pps: f.integer("capacity-pps")?,
        advertise,
        tunnel_src: f.get("tunnel-src").into(),
        backends: vec!["asic".into(), "fpga".into(), "zc".into()],
        ..Default::default()
    };
    crate::validation::node(&desired)?;
    let mut registered = None;
    for attempt in 1..=20 {
        match enroll(&client, &api, &enroll_token, &desired).await {
            Ok(v) => {
                registered = Some(v);
                break;
            }
            Err(e) => {
                if attempt == 20 {
                    return Err(e);
                }
                eprintln!("register: {e}");
                tokio::time::sleep(Duration::from_millis((attempt * 500).min(5000))).await;
            }
        }
    }
    let reg = registered.unwrap();
    let node = reg.node;
    let mut token = reg.token;
    let state = Arc::new(Mutex::new(Agent {
        pipe: Pipeline::new(Program {
            node_id: node.id.clone(),
            ..Default::default()
        }),
        node,
        local_token,
        health: vec![],
        local_as,
        next_hop,
        retired: BTreeMap::new(),
    }));
    let s = state.clone();
    tokio::spawn(async move {
        loop {
            let (id, stats, health) = {
                let mut a = s.lock().unwrap();
                (
                    a.node.id.clone(),
                    a.pipe.stats(chrono::Utc::now().timestamp_millis()),
                    a.health.clone(),
                )
            };
            let heartbeat = client
                .post(format!("{api}/v1/nodes/{id}/heartbeat"))
                .bearer_auth(&token)
                .json(&json!({"stats":stats,"tunnels":health}))
                .send()
                .await;
            match heartbeat {
                Ok(r) if r.status().as_u16() == 401 || r.status().as_u16() == 404 => {
                    match enroll(&client, &api, &enroll_token, &desired).await {
                        Ok(reg) => {
                            token = reg.token;
                            s.lock().unwrap().node = reg.node;
                        }
                        Err(e) => eprintln!("re-enroll: {e}"),
                    }
                }
                Ok(r) if !r.status().is_success() => eprintln!("heartbeat: {}", r.status()),
                Err(e) => eprintln!("heartbeat: {e}"),
                _ => {}
            }
            if let Ok(prog) =
                fetch::<Program>(&client, &format!("{api}/v1/nodes/{id}/program"), &token).await
            {
                let mut a = s.lock().unwrap();
                if prog.policy_id != a.pipe.program.policy_id
                    || prog.version != a.pipe.program.version
                    || prog.compiled_at != a.pipe.program.compiled_at
                {
                    a.install(prog);
                }
            }
            if let Ok(model) =
                fetch::<ml::Model>(&client, &format!("{api}/v1/ml/model"), &token).await
            {
                let mut a = s.lock().unwrap();
                if model.ready {
                    a.pipe.model = model;
                } else if model.withdrawn {
                    a.pipe.model = ml::Model::default();
                }
            }
            tokio::time::sleep(runtime::jitter(Duration::from_secs(2))).await;
        }
    });
    let router = Router::new()
        .route("/health", any(handler))
        .route("/metrics", any(handler))
        .route("/bgp", any(handler))
        .route("/tunnels", any(handler))
        .route("/sessions", any(handler))
        .route("/egress", any(handler))
        .route("/reputation", any(handler))
        .route("/decide", any(handler))
        .fallback(handler)
        .layer(DefaultBodyLimit::max(1 << 20))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(60),
        ))
        .with_state(state);
    runtime::serve(
        router,
        f.get("listen"),
        f.get("tls-cert"),
        f.get("tls-key"),
        f.boolean("insecure")?,
    )
    .await
}
#[cfg(test)]
mod tests {
    use super::*;
    fn agent(announcements: Vec<Announcement>) -> Agent {
        Agent {
            node: Node {
                id: "n".into(),
                ..Default::default()
            },
            pipe: Pipeline::new(Program {
                announcements,
                ..Default::default()
            }),
            local_token: "local".into(),
            health: vec![],
            local_as: 0,
            next_hop: String::new(),
            retired: BTreeMap::new(),
        }
    }
    fn row(prefix: &str, prepends: i64) -> Announcement {
        Announcement {
            prefix: prefix.into(),
            node_id: "n".into(),
            state: "announce".into(),
            prepends,
            ..Default::default()
        }
    }
    fn call(a: &mut Agent, method: &str, uri: &str, body: &[u8]) -> u16 {
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", "Bearer local".parse().unwrap());
        a.dispatch(method, &uri.parse().unwrap(), &headers, body)
            .status()
            .as_u16()
    }
    #[test]
    fn prefixes_leaving_the_plan_are_withdrawn() {
        let mut a = agent(vec![row("203.0.113.0/24", 0), row("203.0.114.10/32", 0)]);
        a.install(Program {
            announcements: vec![row("203.0.113.0/24", 0)],
            ..Default::default()
        });
        let withdrawn: Vec<_> = a
            .announcements()
            .into_iter()
            .filter(|r| r.state == "withdraw")
            .map(|r| r.prefix)
            .collect();
        assert_eq!(withdrawn, ["203.0.114.10/32"]);
        a.install(Program {
            announcements: vec![row("203.0.113.0/24", 0), row("203.0.114.10/32", 0)],
            ..Default::default()
        });
        assert!(a.announcements().iter().all(|r| r.state == "announce"));
    }
    #[test]
    fn text_formats_fail_loudly_when_they_cannot_render() {
        let mut a = agent(vec![row("203.0.113.0/24", 2)]);
        assert_eq!(call(&mut a, "GET", "/bgp?format=exabgp", b""), 500);
        a.local_as = 64512;
        assert_eq!(call(&mut a, "GET", "/bgp?format=exabgp", b""), 200);
    }
    #[test]
    fn duplicate_tunnel_reports_are_refused() {
        let mut a = agent(vec![]);
        let twice =
            br#"{"tunnels":[{"tunnel_id":"t","state":"up"},{"tunnel_id":"t","state":"down"}]}"#;
        assert_eq!(call(&mut a, "POST", "/tunnels", twice), 400);
    }
    #[test]
    fn reports_about_tunnels_that_left_or_were_rebuilt_are_dropped() {
        let tunnel = |id: &str, remote: &str| NodeTunnel {
            id: id.into(),
            local: "192.0.2.1".into(),
            remote: remote.into(),
            r#type: "gre".into(),
            ..Default::default()
        };
        let program = |tunnels| Program {
            tunnels,
            ..Default::default()
        };
        let mut a = agent(vec![]);
        a.install(program(vec![
            tunnel("kept", "198.51.100.1"),
            tunnel("moved", "198.51.100.2"),
            tunnel("gone", "198.51.100.3"),
        ]));
        let up = br#"{"tunnels":[{"tunnel_id":"kept","state":"up"},{"tunnel_id":"moved","state":"up"},{"tunnel_id":"gone","state":"up"}]}"#;
        assert_eq!(call(&mut a, "POST", "/tunnels", up), 200);
        a.install(program(vec![
            tunnel("kept", "198.51.100.1"),
            tunnel("moved", "198.51.100.9"),
        ]));
        let left: Vec<_> = a.health.iter().map(|h| h.tunnel_id.as_str()).collect();
        assert_eq!(left, ["kept"]);
    }
    #[test]
    fn sessions_peer_from_the_endpoint_the_control_plane_holds() {
        let mut a = agent(vec![]);
        a.node.tunnel_src = "192.0.2.9".into();
        assert_eq!(a.peering_node().tunnel_src, "192.0.2.9");
        a.install(Program {
            tunnel_src: "192.0.2.1".into(),
            ..Default::default()
        });
        assert_eq!(a.peering_node().tunnel_src, "192.0.2.1");
    }
    #[tokio::test]
    async fn tunnels_render_the_reply_path_after_the_tunnel() {
        let mut a = agent(vec![]);
        a.install(Program {
            tunnels: vec![NodeTunnel {
                id: "northwind".into(),
                r#type: "gre".into(),
                local: "192.0.2.1".into(),
                remote: "198.51.100.1".into(),
                prefixes: vec!["203.0.113.0/24".into()],
                mtu: 1476,
                mss_clamp: 1436,
                rate_kbps: 833333,
                ..Default::default()
            }],
            ..Default::default()
        });
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", "Bearer local".parse().unwrap());
        let uri = "/tunnels?format=iproute2".parse().unwrap();
        let resp = a.dispatch("GET", &uri, &headers, b"");
        assert_eq!(resp.status().as_u16(), 200);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(
            lines,
            [
                "ip link add scr-northwind type gre local 192.0.2.1 remote 198.51.100.1",
                "ip link set scr-northwind mtu 1476 up",
                "ip route replace 203.0.113.0/24 dev scr-northwind",
                "nft add rule inet scrubline forward oifname \"scr-northwind\" tcp flags syn tcp option maxseg size set 1436",
                "nft add rule inet scrubline forward iifname \"scr-northwind\" ip saddr != { 203.0.113.0/24 } drop",
                "nft add rule inet scrubline forward iifname \"scr-northwind\" meta nfproto ipv6 drop",
                "nft add rule inet scrubline forward iifname \"scr-northwind\" tcp flags syn tcp option maxseg size set 1436",
                "tc qdisc replace dev scr-northwind root tbf rate 833333kbit burst 1041666 latency 50ms",
            ]
        );
    }
}
