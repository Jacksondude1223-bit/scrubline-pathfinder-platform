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
impl Agent {
    fn announcements(&self) -> Vec<Announcement> {
        let mut rows = self.pipe.program.announcements.clone();
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
                    return text(commands);
                }
                json_response(
                    200,
                    json!({"node":self.node.id,"local_as":self.local_as,"announcements":announcements,"exabgp":commands,"error":err}),
                )
            }
            ("GET", "/tunnels") => {
                let (commands, err) = match tunnel::commands(&self.pipe.program.tunnels) {
                    Ok(v) => (v, String::new()),
                    Err(e) => (vec![], e),
                };
                if format == "iproute2" {
                    return text(commands);
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
                for t in &body.tunnels {
                    if t.tunnel_id.is_empty() {
                        return error(400, "tunnel_id required");
                    }
                    if let Err(e) = tunnel::validate_status(&t.state) {
                        return error(400, e);
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
                        &self.node,
                        self.local_as,
                    ) {
                        Ok(v) => (v, String::new()),
                        Err(e) => (vec![], e),
                    }
                };
                if format == "bird" {
                    return text(config);
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
                    .filter(|src| self.pipe.reputation.release(src))
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
            format!(
                "{}:{}",
                std::env::var("HOSTNAME").unwrap_or_else(|_| "localhost".into()),
                listen.rsplit(':').next().unwrap()
            )
        } else {
            listen.into()
        }
    };
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
                    a.pipe.load(prog);
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
