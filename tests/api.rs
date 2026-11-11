use pathfinder::{
    analytics::Collector,
    api::{Api, Shared},
    model::Program,
    runtime::Deadline,
    store::Store,
};
use serde_json::{json, Value};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
const OP: &str = "test-operator";
const ENROLL: &str = "test-enroll";
// The server gets its own runtime on a detached thread, so a request still running when a test
// ends is torn down with the test binary instead of holding the test's runtime open.
fn serve(store: Store) -> String {
    serve_shared(store).0
}
fn serve_shared(store: Store) -> (String, Shared) {
    serve_as(store, "primary")
}
fn serve_as(store: Store, mode: &str) -> (String, Shared) {
    let state: Shared = Arc::new(Mutex::new(Api::new(
        store,
        OP.into(),
        ENROLL.into(),
        mode.into(),
    )));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let shared = state.clone();
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                axum::serve(listener, Api::router(state)).await.unwrap();
            });
    });
    (base, shared)
}
fn call(base: &str, method: &str, path: &str, token: Option<&str>, body: Value) -> (u16, Value) {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let mut req = client.request(method.parse().unwrap(), format!("{base}{path}"));
    if let Some(token) = token {
        req = req.bearer_auth(token);
    }
    if !body.is_null() {
        req = req.json(&body);
    }
    let resp = req.send().unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().unwrap_or(Value::Null))
}
#[test]
fn failed_durable_writes_answer_503_and_registration_500() {
    let dir = std::env::temp_dir().join(format!(
        "pathfinder-api-{}",
        pathfinder::store::secret().unwrap()
    ));
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("state.json");
    let base = serve(Store::open(path.to_str().unwrap()).unwrap());
    std::fs::remove_file(&path).unwrap();
    std::fs::remove_dir(&dir).unwrap();
    let tenant = json!({"name":"t","prefixes":["203.0.113.0/24"]});
    assert_eq!(call(&base, "POST", "/v1/tenants", Some(OP), tenant).0, 503);
    let policy = json!({"name":"p","protected":["203.0.113.0/24"]});
    assert_eq!(call(&base, "POST", "/v1/policies", Some(OP), policy).0, 503);
    let node = json!({"name":"n","region":"us"});
    let (status, body) = call(&base, "POST", "/v1/nodes/register", Some(ENROLL), node);
    assert_eq!(status, 500, "{body}");
}
#[test]
fn training_does_not_hold_the_control_plane() {
    let base = serve(Store::open("").unwrap());
    let train = |token, body| call(&base, "POST", "/v1/ml/train", token, body);
    assert_eq!(train(None, Value::Null).0, 401);
    assert_eq!(train(Some(ENROLL), Value::Null).0, 403);
    assert_eq!(train(Some(OP), Value::Null).0, 400);
    let flow = |proto: &str, pps| json!({"proto":proto,"pps":pps,"dport":443});
    let samples = json!({"samples":[
        {"flow":flow("udp",900000),"label":1},
        {"flow":flow("tcp",40),"label":0},
    ]});
    assert_eq!(
        call(&base, "POST", "/v1/ml/samples", Some(OP), samples).0,
        200
    );
    let (status, model) = train(Some(OP), json!({"epochs":50}));
    assert_eq!((status, &model["ready"]), (200, &json!(true)));
    let (_, stored) = call(&base, "GET", "/v1/ml/model", Some(OP), Value::Null);
    assert_eq!(stored["epochs"], 50);
    // A fit that will not finish while this test runs. Every other request must still be
    // answered: before training moved outside the lock they all queued behind it.
    let slow = format!("{base}/v1/ml/train");
    std::thread::spawn(move || {
        let client = reqwest::blocking::Client::builder()
            .timeout(None)
            .build()
            .unwrap();
        let _ = client
            .post(slow)
            .bearer_auth(OP)
            .json(&json!({"epochs":2_000_000_000_i64}))
            .send();
    });
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        call(&base, "GET", "/v1/nodes", Some(OP), Value::Null).0,
        200
    );
    assert_eq!(call(&base, "GET", "/health", None, Value::Null).0, 200);
    let (_, stored) = call(&base, "GET", "/v1/ml/model", Some(OP), Value::Null);
    assert_eq!(stored["epochs"], 50);
}
#[test]
fn http_samples_publish_a_request_model_that_scores_requests() {
    use base64::Engine;
    let base = serve(Store::open("").unwrap());
    let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);
    let client =
        "GET /players.json HTTP/1.1\r\nHost: s\r\nUser-Agent: CitizenFX/1\r\nAccept: */*\r\n\r\n";
    let flood = "GET /players.json?x=9 HTTP/1.0\r\n\r\n";
    let http =
        |payload: &str, pps| json!({"proto":"tcp","dport":30120,"pps":pps,"payload":b64(payload)});
    let flow = |proto: &str, pps| json!({"proto":proto,"pps":pps,"dport":443});
    let samples = json!({"samples":[
        {"flow":flow("udp",900000),"label":1},
        {"flow":flow("tcp",40),"label":0},
        {"flow":http(client,2),"label":0},
        {"flow":http(flood,500),"label":1},
    ]});
    assert_eq!(
        call(&base, "POST", "/v1/ml/samples", Some(OP), samples).0,
        200
    );
    let (status, model) = call(
        &base,
        "POST",
        "/v1/ml/train",
        Some(OP),
        json!({"epochs":200}),
    );
    assert_eq!(status, 200, "{model}");
    // Each model is fitted to its own samples.
    assert_eq!(
        (&model["samples"], &model["http"]["samples"]),
        (&json!(2), &json!(2))
    );
    assert_eq!(model["http"]["ready"], true);
    let (_, scored) = call(
        &base,
        "POST",
        "/v1/ml/score",
        Some(OP),
        http(&format!("{client}{flood}"), 500),
    );
    assert_eq!(
        scored["http"]["scores"].as_array().unwrap().len(),
        2,
        "{scored}"
    );
    assert_eq!(
        (&scored["http"]["ready"], &scored["http"]["label"]),
        (&json!(true), &json!(1))
    );
    let (_, plain) = call(&base, "POST", "/v1/ml/score", Some(OP), flow("tcp", 40));
    assert!(plain.get("http").is_none(), "{plain}");
    // Where the models run is the policy's to say.
    let policy = |ml: Value| json!({"id":"p","name":"p","protected":["203.0.113.0/24"],"ml":ml});
    for bad in [json!({"scope":"everything"}), json!({"mode":"shadow"})] {
        let (status, body) = call(&base, "POST", "/v1/policies", Some(OP), policy(bad));
        assert_eq!(status, 400, "{body}");
    }
    let (status, saved) = call(
        &base,
        "POST",
        "/v1/policies",
        Some(OP),
        policy(json!({"scope":"inspect","mode":"observe"})),
    );
    assert_eq!((status, &saved["ml"]["mode"]), (200, &json!("observe")));
}
#[test]
fn sub_minute_windows_report_the_current_minute() {
    let now = 1767225630000;
    let mut c = Collector::default();
    let program = protecting(&["203.0.113.0/24"]);
    report(
        &mut c,
        "node",
        &program,
        json!([{"prefix":"203.0.113.0/24"}]),
        now - 1000,
    );
    let stats = json!([{"prefix":"203.0.113.0/24","flows":10,"offered":5000}]);
    report(&mut c, "node", &program, stats, now);
    assert_eq!(
        c.summary("203.0.113.0/24", 30000, now + 1000)["offered"],
        5000
    );
    let points = c.points("203.0.113.0/24", 30000, 250, now + 1000);
    assert_eq!(points.len(), 1);
    assert_eq!(points[0]["offered"], 5000);
}
#[test]
fn health_reports_a_poisoned_control_plane() {
    let (base, state) = serve_shared(Store::open("").unwrap());
    assert_eq!(call(&base, "GET", "/health", None, Value::Null).0, 200);
    let _ = std::thread::spawn(move || {
        let _held = state.lock().unwrap();
        panic!("poisoning the control-plane lock on purpose");
    })
    .join();
    let (status, body) = call(&base, "GET", "/health", None, Value::Null);
    assert_eq!((status, &body["status"]), (503, &json!("error")));
}
#[test]
fn ids_needing_escapes_reach_their_routes() {
    let base = serve(Store::open("").unwrap());
    let tenant = json!({"id":"acme corp","name":"Acme","prefixes":["203.0.113.0/24"]});
    assert_eq!(call(&base, "POST", "/v1/tenants", Some(OP), tenant).0, 200);
    let (status, issued) = call(
        &base,
        "POST",
        "/v1/tenants/acme%20corp/token",
        Some(OP),
        json!({}),
    );
    assert_eq!(
        (status, issued["tenant_id"].as_str()),
        (200, Some("acme corp"))
    );
    assert_eq!(
        call(
            &base,
            "DELETE",
            "/v1/tenants/acme%20corp",
            Some(OP),
            Value::Null
        )
        .0,
        200
    );
    assert_eq!(
        call(&base, "GET", "/v1/tenants/%zz", Some(OP), Value::Null).0,
        400
    );
}
#[test]
fn a_full_training_set_answers_413_with_the_stored_count() {
    let base = serve(Store::open("").unwrap());
    let batch = |n| json!({"samples": vec![json!({"flow":{},"label":0}); n]});
    for _ in 0..2 {
        assert_eq!(
            call(&base, "POST", "/v1/ml/samples", Some(OP), batch(100000)).0,
            200
        );
    }
    let (status, body) = call(&base, "POST", "/v1/ml/samples", Some(OP), batch(1));
    assert_eq!((status, &body["stored"]), (413, &json!(200000)));
    assert!(body["error"].is_string());
}
#[tokio::test]
async fn quiet_connections_are_closed() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (first, idle) = (Duration::from_millis(100), Duration::from_millis(400));
    let (_client, server) = tokio::io::duplex(64);
    let mut conn = Deadline::new(server, first, idle);
    let started = std::time::Instant::now();
    let err = conn.read(&mut [0; 8]).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    assert!(started.elapsed() < Duration::from_secs(2));
    let (mut client, server) = tokio::io::duplex(64);
    let mut conn = Deadline::new(server, first, idle);
    client.write_all(b"x").await.unwrap();
    assert_eq!(conn.read(&mut [0; 8]).await.unwrap(), 1);
    let started = std::time::Instant::now();
    let err = conn.read(&mut [0; 8]).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    assert!(started.elapsed() >= Duration::from_millis(300));
}
#[test]
fn reads_that_carry_everything_are_written_straight_to_json_for_operators_only() {
    let base = serve(Store::open("").unwrap());
    for name in ["beta", "alpha"] {
        let policy = json!({"id":name,"name":name,"protected":["203.0.113.0/24"]});
        assert_eq!(call(&base, "POST", "/v1/policies", Some(OP), policy).0, 200);
    }
    let sample = json!({"samples":[{"flow":{"src_ip":"192.0.2.1","dst_ip":"203.0.113.1","proto":"udp","dport":53,"pps":1,"payload":"AAE="},"label":1}]});
    assert_eq!(
        call(&base, "POST", "/v1/ml/samples", Some(OP), sample).0,
        200
    );
    for path in ["/v1/state", "/v1/policies", "/v1/fabric", "/v1/ml/samples"] {
        assert_eq!(call(&base, "GET", path, None, Value::Null).0, 401, "{path}");
        assert_eq!(
            call(&base, "GET", path, Some(ENROLL), Value::Null).0,
            403,
            "{path}"
        );
        let resp = reqwest::blocking::Client::new()
            .get(format!("{base}{path}"))
            .bearer_auth(OP)
            .send()
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200, "{path}");
        assert_eq!(resp.headers()["content-type"], "application/json", "{path}");
    }
    let (_, policies) = call(&base, "GET", "/v1/policies", Some(OP), Value::Null);
    let names: Vec<_> = policies
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].clone())
        .collect();
    assert_eq!(names, [json!("alpha"), json!("beta")]);
    let (_, state) = call(&base, "GET", "/v1/state", Some(OP), Value::Null);
    let state: pathfinder::store::Snapshot = serde_json::from_value(state).unwrap();
    assert_eq!((state.policies.len(), state.samples.len()), (2, 1));
    assert_eq!(state.samples[0].flow.payload, [0, 1]);
    let (_, fabric) = call(&base, "GET", "/v1/fabric", Some(OP), Value::Null);
    assert!(
        fabric["announcements"].is_array() && fabric["programs"].is_array(),
        "{fabric}"
    );
    assert!(fabric["ml"].is_object(), "{fabric}");
    let (_, samples) = call(&base, "GET", "/v1/ml/samples", Some(OP), Value::Null);
    assert_eq!(samples[0]["flow"]["payload"], "AAE=");
}
/// Serves `router` on a port of its own, on the test's runtime.
async fn listen(router: axum::Router) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    addr
}
/// Sends `request` as written and returns the status and head of the answer.
async fn raw(addr: std::net::SocketAddr, request: &[u8]) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();
    conn.write_all(request).await.unwrap();
    let mut got = Vec::new();
    let mut buf = [0; 4096];
    while !got.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = conn.read(&mut buf).await.unwrap();
        assert!(n > 0, "closed before answering");
        got.extend_from_slice(&buf[..n]);
    }
    let head = String::from_utf8_lossy(&got).into_owned();
    (head[9..12].parse().unwrap(), head)
}
#[tokio::test]
async fn request_bodies_share_a_budget_charged_as_they_arrive() {
    use axum::{middleware::from_fn_with_state, routing::post};
    use pathfinder::runtime::{bounded, Bodies};
    // Each request holds its body until the test lets it answer.
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let (entered, mut inside) = tokio::sync::mpsc::unbounded_channel();
    let held = gate.clone();
    let router = axum::Router::new()
        .route(
            "/",
            post(move |body: axum::body::Bytes| {
                let (held, entered) = (held.clone(), entered.clone());
                async move {
                    entered.send(()).unwrap();
                    let _ = held.acquire().await.unwrap();
                    body.len().to_string()
                }
            })
            .get(|| async { "ok" }),
        )
        .layer(from_fn_with_state(Bodies::new(8 << 10, 4 << 10), bounded));
    let addr = listen(router).await;
    let base = format!("http://{addr}/");
    let client = reqwest::Client::new();
    let post = |n: usize| client.post(&base).body(vec![1u8; n]).send();
    let waiting: Vec<_> = (0..2).map(|_| tokio::spawn(post(4 << 10))).collect();
    inside.recv().await.unwrap();
    inside.recv().await.unwrap();
    // Two bodies being answered hold the whole budget: a third is turned away, not queued.
    let busy = post(1).await.unwrap();
    assert_eq!(busy.status().as_u16(), 503);
    assert_eq!(busy.headers()["retry-after"], "1");
    let error: Value = busy.json().await.unwrap();
    assert!(
        error["error"].as_str().unwrap().contains("try again"),
        "{error}"
    );
    // A request without a body takes none of it.
    assert_eq!(
        client.get(&base).send().await.unwrap().status().as_u16(),
        200
    );
    gate.add_permits(3);
    for w in waiting {
        let answered = w.await.unwrap().unwrap();
        assert_eq!(answered.text().await.unwrap(), "4096");
    }
    assert_eq!(post(4 << 10).await.unwrap().status().as_u16(), 200);
    // A body larger than one may be is refused on what it claims, or once it has sent too much.
    let claimed = format!(
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
        (4 << 10) + 1
    );
    let (status, head) = raw(addr, claimed.as_bytes()).await;
    assert_eq!(status, 413, "{head}");
    let mut chunked =
        b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n1001\r\n".to_vec();
    chunked.extend(vec![b'x'; (4 << 10) + 1]);
    chunked.extend(b"\r\n0\r\n\r\n");
    let (status, head) = raw(addr, &chunked).await;
    assert_eq!(status, 413, "{head}");
    // Only the requests answered reached the handler.
    inside.recv().await.unwrap();
    assert!(inside.try_recv().is_err());
}
#[tokio::test]
async fn the_control_plane_refuses_a_body_past_its_limit_before_reading_it() {
    let state: Shared = Arc::new(Mutex::new(Api::new(
        Store::open("").unwrap(),
        OP.into(),
        ENROLL.into(),
        "primary".into(),
    )));
    let addr = listen(Api::router(state)).await;
    let head = format!(
        "POST /v1/policies HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {OP}\r\nContent-Length: {}\r\n\r\n",
        pathfinder::api::BODY_LIMIT + 1
    );
    let (status, head) = raw(addr, head.as_bytes()).await;
    assert_eq!(status, 413, "{head}");
    assert!(head.contains("application/json"), "{head}");
}
#[tokio::test]
async fn a_server_holds_a_bounded_number_of_connections() {
    use axum_server::accept::Accept;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connect = || async {
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        (client, listener.accept().await.unwrap().0)
    };
    let first_byte = Duration::from_millis(300);
    let open = pathfinder::runtime::Deadlines::new(1, first_byte, Duration::from_secs(5));
    let (_a, server) = connect().await;
    let Ok(first) = open.accept(server, ()).await else {
        panic!("the first connection has a place");
    };
    // One past the limit waits as long as a connection may stay silent, then is closed.
    let (_b, server) = connect().await;
    let started = std::time::Instant::now();
    assert!(open.accept(server, ()).await.is_err());
    assert!(started.elapsed() >= first_byte);
    // One waiting takes the place a connection gives up when it closes.
    let (_c, server) = connect().await;
    let waiting = tokio::spawn({
        let open = open.clone();
        async move { open.accept(server, ()).await.is_ok() }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(first);
    assert!(waiting.await.unwrap());
}
fn protecting(prefixes: &[&str]) -> Program {
    Program {
        prefixes: prefixes.iter().map(|p| p.to_string()).collect(),
        ..Default::default()
    }
}
fn report(c: &mut Collector, node: &str, program: &Program, prefixes: Value, now: i64) {
    c.observe(node, &json!({ "prefixes": prefixes }), program, now);
}
const NOW: i64 = 1767225630000;
#[test]
fn a_first_report_is_a_baseline_not_traffic() {
    let mut c = Collector::default();
    let p = protecting(&["203.0.113.0/24"]);
    let row = |offered: u64| json!([{"prefix":"203.0.113.0/24","offered":offered}]);
    report(&mut c, "node", &p, row(1_000_000_000), NOW);
    report(&mut c, "node", &p, row(1_000_000_200), NOW + 2000);
    assert_eq!(
        c.summary("203.0.113.0/24", 3600000, NOW + 2000)["offered"],
        200
    );
}
#[test]
fn only_programmed_prefixes_are_tracked() {
    let mut c = Collector::default();
    let p = protecting(&["203.0.113.0/24"]);
    let rows = json!([{"prefix":"203.0.113.0/24"},{"prefix":"198.51.100.0/24"},{"prefix":"junk"}]);
    report(&mut c, "node", &p, rows, NOW);
    assert_eq!(c.prefixes(), ["203.0.113.0/24"]);
}
#[test]
fn an_attack_closes_once_no_node_reports_its_prefix() {
    let mut c = Collector::default();
    let p = protecting(&["203.0.113.0/24", "198.51.100.0/24"]);
    let flood = json!([{"prefix":"203.0.113.0/24","offered_pps":100000,"dropped_pps":90000}]);
    report(&mut c, "a", &p, flood, NOW);
    assert_eq!(c.events("203.0.113.0/24", 3600000, NOW)[0]["ongoing"], true);
    for s in 1..=20 {
        report(
            &mut c,
            "b",
            &p,
            json!([{"prefix":"198.51.100.0/24"}]),
            NOW + s * 10000,
        );
    }
    let later = NOW + 200000;
    assert_eq!(
        c.events("203.0.113.0/24", 3600000, later)[0]["ongoing"],
        false
    );
    assert_eq!(
        c.summary("203.0.113.0/24", 3600000, later)["under_attack"],
        false
    );
}
#[test]
fn shared_challenges_are_not_booked_to_every_prefix() {
    let mut c = Collector::default();
    let mut p = protecting(&["203.0.113.0/24", "198.51.100.0/24"]);
    p.games = vec![pathfinder::model::GameFilter {
        id: "bedrock".into(),
        dport: 19132,
        profile: "raknet".into(),
        ..Default::default()
    }];
    let rows = json!([{"prefix":"203.0.113.0/24"},{"prefix":"198.51.100.0/24"}]);
    for (at, challenged) in [(NOW, 0), (NOW + 2000, 500)] {
        let stats =
            json!({"prefixes": rows, "games":[{"filter_id":"bedrock","challenged":challenged}]});
        c.observe("node", &stats, &p, at);
    }
    for prefix in ["203.0.113.0/24", "198.51.100.0/24"] {
        assert_eq!(c.summary(prefix, 3600000, NOW + 2000)["challenged"], 0);
    }
}
#[test]
fn analytics_labels_describe_the_data_returned() {
    let mut c = Collector::default();
    let p = protecting(&["203.0.113.0/24"]);
    let row = |pps: u64| json!([{"prefix":"203.0.113.0/24","offered_pps":pps}]);
    report(&mut c, "busy", &p, row(5000), NOW);
    report(&mut c, "withdrawn", &p, row(0), NOW);
    let summary = c.summary("203.0.113.0/24", 3600000, NOW);
    assert_eq!(summary["nodes"], 1);
    assert_eq!(pathfinder::analytics::resolution(90000), 120000);
    let points = c.points("203.0.113.0/24", 3 * 3600000, 90000, NOW);
    let at = |i: usize| {
        chrono::DateTime::parse_from_rfc3339(points[i]["at"].as_str().unwrap())
            .unwrap()
            .timestamp()
    };
    assert_eq!(at(1) - at(0), 120);
    let base = serve(Store::open("").unwrap());
    let (_, overview) = call(
        &base,
        "GET",
        "/v1/analytics/overview?window=168h",
        Some(OP),
        Value::Null,
    );
    assert_eq!(overview["window"], "24h0m0s");
    let path = "/v1/analytics/series?prefix=203.0.113.0/24&window=3h&step=90s";
    assert_eq!(
        call(&base, "GET", path, Some(OP), Value::Null).1["step"],
        "2m0s"
    );
}
#[test]
fn a_heartbeat_reporting_a_tunnel_twice_is_refused() {
    let base = serve(Store::open("").unwrap());
    let node = json!({"name":"edge","region":"iad","tunnel_src":"192.0.2.1"});
    let (_, reg) = call(&base, "POST", "/v1/nodes/register", Some(ENROLL), node);
    let path = format!(
        "/v1/nodes/{}/heartbeat",
        reg["node"]["id"].as_str().unwrap()
    );
    let token = reg["token"].as_str().unwrap();
    let twice = json!({"tunnels":[{"tunnel_id":"customer","state":"up"},{"tunnel_id":"customer","state":"down"}]});
    assert_eq!(call(&base, "POST", &path, Some(token), twice).0, 400);
    let once = json!({"tunnels":[{"tunnel_id":"customer","state":"up"}]});
    assert_eq!(call(&base, "POST", &path, Some(token), once).0, 200);
}
#[test]
fn baselines_survive_a_silent_node() {
    let mut c = Collector::default();
    let p = protecting(&["203.0.113.0/24"]);
    let row = |offered: u64| json!([{"prefix":"203.0.113.0/24","offered":offered}]);
    report(&mut c, "a", &p, row(1000), NOW);
    report(&mut c, "a", &p, row(2000), NOW + 2000);
    report(&mut c, "b", &p, row(0), NOW + 310000);
    report(&mut c, "a", &p, row(2100), NOW + 312000);
    assert_eq!(
        c.summary("203.0.113.0/24", 3600000, NOW + 312000)["offered"],
        1100
    );
}
fn node_id(reg: &Value) -> String {
    reg["node"]["id"].as_str().unwrap().to_string()
}
fn plan_row(base: &str, node: &str, prefix: &str) -> Value {
    let (_, fabric) = call(base, "GET", "/v1/fabric", Some(OP), Value::Null);
    fabric["announcements"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["node_id"] == node && a["prefix"] == prefix)
        .cloned()
        .unwrap_or(Value::Null)
}
#[test]
fn operators_assign_each_node_its_own_tunnel_endpoint() {
    let base = serve(Store::open("").unwrap());
    let register = |body: Value| call(&base, "POST", "/v1/nodes/register", Some(ENROLL), body).1;
    let a = node_id(&register(json!({"name":"edge-a","region":"iad"})));
    let b = node_id(&register(
        json!({"name":"edge-b","region":"iad","tunnel_src":"192.0.2.2"}),
    ));
    let endpoint = |node: &str, token, body| {
        let path = format!("/v1/nodes/{node}/tunnel-endpoint");
        call(&base, "PUT", &path, token, body)
    };
    let address = |a: &str| json!({ "address": a });
    assert_eq!(endpoint(&a, None, address("192.0.2.1")).0, 401);
    assert_eq!(endpoint(&a, Some(ENROLL), address("192.0.2.1")).0, 403);
    for unusable in ["2001:db8::1", "127.0.0.1", "0.0.0.0", "224.0.0.1", "nope"] {
        assert_eq!(
            endpoint(&a, Some(OP), address(unusable)).0,
            400,
            "{unusable}"
        );
    }
    assert_eq!(endpoint("node-none", Some(OP), address("192.0.2.1")).0, 404);
    let (status, body) = endpoint(&a, Some(OP), address("192.0.2.2"));
    assert_eq!(
        status, 409,
        "two nodes on one address would take each other's replies"
    );
    assert!(body["error"].as_str().unwrap().contains(&b), "{body}");
    let (status, node) = endpoint(&a, Some(OP), address("192.0.2.1"));
    assert_eq!(status, 200, "{node}");
    assert_eq!(node["tunnel_src"], "192.0.2.1");
    assert_eq!(node["tunnel_endpoint_assigned"], true);
    // The node re-registering with an address of its own does not move its tunnels: the
    // operator's assignment stands until the operator clears it. The agent is answered with what
    // it registered, and learns the assignment from its program, so it never mistakes the
    // assignment for its own address once it is cleared.
    let again = register(json!({"name":"edge-a","region":"iad","tunnel_src":"192.0.2.9"}));
    assert_eq!(again["node"]["tunnel_src"], "192.0.2.9");
    let (_, nodes) = call(&base, "GET", "/v1/nodes", Some(OP), Value::Null);
    let listed = nodes
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["id"] == a.as_str())
        .unwrap()
        .clone();
    assert_eq!(listed["tunnel_src"], "192.0.2.1");
    let clear = format!("/v1/nodes/{a}/tunnel-endpoint");
    let (status, node) = call(&base, "DELETE", &clear, Some(OP), Value::Null);
    assert_eq!(status, 200, "{node}");
    assert_eq!(
        node["tunnel_src"], "192.0.2.9",
        "falls back to what the node registered with"
    );
    assert_eq!(node["tunnel_endpoint_assigned"], false);
    let missing = "/v1/nodes/node-none/tunnel-endpoint";
    assert_eq!(call(&base, "DELETE", missing, Some(OP), Value::Null).0, 404);
}
#[test]
fn operators_control_tunnels_on_the_deployed_policy() {
    let base = serve(Store::open("").unwrap());
    let register = |body: Value| call(&base, "POST", "/v1/nodes/register", Some(ENROLL), body).1;
    let a = node_id(&register(json!({"name":"edge-a","region":"iad"})));
    let b = node_id(&register(
        json!({"name":"edge-b","region":"fra","tunnel_src":"192.0.2.2"}),
    ));
    let prefix = "203.0.113.0/24";
    let tunnel = json!({"remote":"198.51.100.1","prefixes":[prefix],"key":42});
    let (status, fleet) = call(&base, "GET", "/v1/tunnels", Some(OP), Value::Null);
    assert_eq!((status, &fleet["policy_id"]), (200, &Value::Null));
    let put =
        |id: &str, body: Value| call(&base, "PUT", &format!("/v1/tunnels/{id}"), Some(OP), body);
    let (status, body) = put("northwind", tunnel.clone());
    assert_eq!(status, 409, "nothing deployed to change yet: {body}");
    let policy = json!({"name":"p","protected":[prefix, "198.51.100.0/24"],"tunnels":[]});
    let (_, saved) = call(&base, "POST", "/v1/policies", Some(OP), policy);
    let deploy = format!("/v1/policies/{}/deploy", saved["id"].as_str().unwrap());
    assert_eq!(call(&base, "POST", &deploy, Some(OP), Value::Null).0, 200);
    let mut wrong = tunnel.clone();
    wrong["id"] = json!("other");
    assert_eq!(put("northwind", wrong).0, 400);
    let mut bad_remote = tunnel.clone();
    bad_remote["remote"] = json!("127.0.0.1");
    assert_eq!(put("northwind", bad_remote).0, 400);
    let mut bad_direction = tunnel.clone();
    bad_direction["direction"] = json!("inbound");
    assert_eq!(put("northwind", bad_direction).0, 400);
    let (status, changed) = put("northwind", tunnel.clone());
    assert_eq!(status, 200, "{changed}");
    assert_eq!(
        changed["version"], 2,
        "a tunnel change is a new version of the policy"
    );
    assert_eq!(changed["tunnel"]["id"], "northwind");
    // A node with no endpoint cannot carry a prefix with a return path; one with an endpoint
    // gets its own tunnel to the customer from it.
    assert_eq!(plan_row(&base, &a, prefix)["state"], "withdraw");
    assert_eq!(plan_row(&base, &b, prefix)["state"], "announce");
    let program = |node: &str| {
        call(
            &base,
            "GET",
            &format!("/v1/nodes/{node}/program"),
            Some(OP),
            Value::Null,
        )
        .1
    };
    let prog = program(&b);
    assert_eq!(prog["tunnel_src"], "192.0.2.2");
    assert_eq!(prog["tunnels"][0]["local"], "192.0.2.2");
    let (_, fleet) = call(&base, "GET", "/v1/tunnels", Some(OP), Value::Null);
    let rows = fleet["tunnels"][0]["nodes"].as_array().unwrap().clone();
    let row = |node: &str| rows.iter().find(|r| r["node_id"] == node).unwrap().clone();
    assert_eq!(fleet["tunnels"][0]["direction"], "both");
    assert_eq!(row(&a)["endpoint"], "");
    assert!(row(&a)["problem"]
        .as_str()
        .unwrap()
        .contains("tunnel-endpoint"));
    assert_eq!(row(&b)["endpoint"], "192.0.2.2");
    assert_eq!(row(&b)["state"], "unreported");
    assert_eq!(row(&b)["interface"], "scr-northwind");
    assert_eq!(row(&b)["announced"], json!([prefix]));
    // Giving the node its endpoint brings it into the tunnel straight away.
    let endpoint = format!("/v1/nodes/{a}/tunnel-endpoint");
    let address = json!({"address":"192.0.2.1"});
    assert_eq!(call(&base, "PUT", &endpoint, Some(OP), address).0, 200);
    assert_eq!(plan_row(&base, &a, prefix)["state"], "announce");
    assert_eq!(program(&a)["tunnels"][0]["local"], "192.0.2.1");
    let toggle = |id: &str, action: &str, body: Value| {
        call(
            &base,
            "POST",
            &format!("/v1/tunnels/{id}/{action}"),
            Some(OP),
            body,
        )
    };
    let nodes = |ids: &[&str]| json!({ "nodes": ids });
    assert_eq!(toggle("northwind", "disable", nodes(&[])).0, 400);
    assert_eq!(toggle("northwind", "disable", nodes(&["node-none"])).0, 404);
    assert_eq!(toggle("missing", "disable", nodes(&[&a])).0, 404);
    assert_eq!(
        toggle("northwind", "disable", nodes(&[&a])).1["version"],
        3,
        "a 404 saves nothing"
    );
    let (status, off) = toggle("northwind", "disable", nodes(&[&a]));
    assert_eq!(status, 200);
    assert_eq!(
        off["tunnel"]["disabled"],
        json!([a]),
        "disabling twice lists the node once"
    );
    let withdrawn = plan_row(&base, &a, prefix);
    assert_eq!(withdrawn["state"], "withdraw");
    assert_eq!(
        withdrawn["reason"],
        "return tunnel northwind is disabled on this node"
    );
    assert_eq!(plan_row(&base, &b, prefix)["state"], "announce");
    assert!(program(&a)["tunnels"].is_null(), "{}", program(&a));
    let (status, on) = toggle("northwind", "enable", nodes(&[&a]));
    assert_eq!(status, 200);
    assert!(on["tunnel"]["disabled"].is_null(), "{on}");
    assert_eq!(plan_row(&base, &a, prefix)["state"], "announce");
    let mut second = tunnel.clone();
    second["remote"] = json!("198.51.100.2");
    assert_eq!(put("second", second).0, 400, "a prefix has one return path");
    let delete = |id: &str| {
        call(
            &base,
            "DELETE",
            &format!("/v1/tunnels/{id}"),
            Some(OP),
            Value::Null,
        )
    };
    assert_eq!(delete("missing").0, 404);
    let (status, gone) = delete("northwind");
    assert_eq!((status, &gone["deleted"]), (200, &json!("northwind")));
    let (_, fleet) = call(&base, "GET", "/v1/tunnels", Some(OP), Value::Null);
    assert_eq!(fleet["tunnels"], json!([]));
    assert_eq!(
        call(&base, "GET", "/v1/tunnels", Some(ENROLL), Value::Null).0,
        403
    );
}
#[test]
fn a_replica_refuses_tunnel_changes() {
    let (base, _) = serve_as(Store::open("").unwrap(), "replica");
    let writes = [
        (
            "PUT",
            "/v1/nodes/n/tunnel-endpoint",
            json!({"address":"192.0.2.1"}),
        ),
        ("DELETE", "/v1/nodes/n/tunnel-endpoint", Value::Null),
        (
            "PUT",
            "/v1/tunnels/t",
            json!({"remote":"198.51.100.1","prefixes":["203.0.113.0/24"]}),
        ),
        ("DELETE", "/v1/tunnels/t", Value::Null),
        ("POST", "/v1/tunnels/t/disable", json!({"nodes":["n"]})),
        ("POST", "/v1/tunnels/t/enable", json!({"nodes":["n"]})),
        ("PUT", "/v1/tunnels/t/rate", json!({"rate_mbps":100})),
    ];
    for (method, path, body) in writes {
        assert_eq!(
            call(&base, method, path, Some(OP), body).0,
            409,
            "{method} {path}"
        );
    }
    assert_eq!(
        call(&base, "GET", "/v1/tunnels", Some(OP), Value::Null).0,
        200
    );
}
#[test]
fn staff_allocate_tunnels_to_customers_with_a_clean_traffic_allowance() {
    let base = serve(Store::open("").unwrap());
    let op = |method: &str, path: &str, body: Value| call(&base, method, path, Some(OP), body);
    let register = |body: Value| call(&base, "POST", "/v1/nodes/register", Some(ENROLL), body).1;
    let a = node_id(&register(
        json!({"name":"edge-a","region":"iad","tunnel_src":"192.0.2.1"}),
    ));
    let b = node_id(&register(
        json!({"name":"edge-b","region":"fra","tunnel_src":"192.0.2.2"}),
    ));
    let (_, customer) = op(
        "POST",
        "/v1/tenants",
        json!({"name":"northwind","prefixes":["203.0.113.0/24"]}),
    );
    let tenant = customer["id"].as_str().unwrap().to_string();
    let (_, other) = op(
        "POST",
        "/v1/tenants",
        json!({"name":"contoso","prefixes":["198.51.100.0/24"]}),
    );
    let other = other["id"].as_str().unwrap().to_string();
    let theirs = json!({"name":"p","protected":["203.0.113.0/24","198.51.100.0/24"],
        "tunnels":[{"id":"t","remote":"198.18.0.9","prefixes":["198.51.100.0/24"],"tenant":tenant}]});
    let (status, body) = op("POST", "/v1/policies", theirs);
    assert_eq!(
        status, 400,
        "a customer's tunnel cannot carry another's prefix: {body}"
    );
    let policy = json!({"name":"p","protected":["203.0.113.0/24","198.51.100.0/24"]});
    let (_, saved) = op("POST", "/v1/policies", policy);
    let deploy = format!("/v1/policies/{}/deploy", saved["id"].as_str().unwrap());
    assert_eq!(op("POST", &deploy, Value::Null).0, 200);
    // Allocating without naming prefixes carries the customer's protected prefixes.
    let allocate = json!({"remote":"198.18.0.9","tenant":tenant,"rate_mbps":1000});
    let (status, allocated) = op("PUT", "/v1/tunnels/northwind", allocate);
    assert_eq!(status, 200, "{allocated}");
    assert_eq!(allocated["tunnel"]["prefixes"], json!(["203.0.113.0/24"]));
    assert_eq!(allocated["tunnel"]["tenant"], tenant.as_str());
    let unknown = json!({"remote":"198.18.0.9","tenant":"ten-none"});
    assert_eq!(op("PUT", "/v1/tunnels/other", unknown).0, 400);
    let foreign = json!({"remote":"198.18.0.10","tenant":tenant,"prefixes":["198.51.100.0/24"]});
    assert_eq!(op("PUT", "/v1/tunnels/other", foreign).0, 400);
    // The allowance is split across the nodes sending the tunnel.
    let program = |node: &str| op("GET", &format!("/v1/nodes/{node}/program"), Value::Null).1;
    assert_eq!(program(&a)["tunnels"][0]["rate_kbps"], 500_000);
    assert_eq!(program(&b)["tunnels"][0]["rate_kbps"], 500_000);
    let (_, fleet) = op("GET", &format!("/v1/tunnels?tenant={tenant}"), Value::Null);
    assert_eq!(fleet["tunnels"].as_array().unwrap().len(), 1);
    assert_eq!(fleet["tunnels"][0]["rate_mbps"], 1000);
    assert_eq!(fleet["tunnels"][0]["tenant"], tenant.as_str());
    assert_eq!(fleet["tunnels"][0]["nodes"][0]["rate_kbps"], 500_000);
    let (_, none) = op("GET", &format!("/v1/tunnels?tenant={other}"), Value::Null);
    assert_eq!(none["tunnels"], json!([]));
    // Changing only the speed.
    let rate = |id: &str, body: Value| op("PUT", &format!("/v1/tunnels/{id}/rate"), body);
    for bad in [
        json!({"rate_mbps":2501}),
        json!({"rate_mbps":-1}),
        json!({}),
    ] {
        assert_eq!(rate("northwind", bad.clone()).0, 400, "{bad}");
    }
    assert_eq!(rate("missing", json!({"rate_mbps":100})).0, 404);
    let (status, changed) = rate("northwind", json!({"rate_mbps":2500}));
    assert_eq!(
        (status, &changed["tunnel"]["rate_mbps"]),
        (200, &json!(2500))
    );
    assert_eq!(program(&a)["tunnels"][0]["rate_kbps"], 1_250_000);
    let (_, reset) = rate("northwind", json!({"rate_mbps":0}));
    assert!(reset["tunnel"]["rate_mbps"].is_null(), "{reset}");
    let (_, fleet) = op("GET", "/v1/tunnels", Value::Null);
    assert_eq!(
        fleet["tunnels"][0]["rate_mbps"], 2500,
        "no allowance set is held to the 2.5 Gbit/s maximum"
    );
    // A customer with a tunnel cannot be deleted, or lose the prefixes it carries.
    let path = format!("/v1/tenants/{tenant}");
    let (status, body) = op("DELETE", &path, Value::Null);
    assert_eq!(status, 409, "{body}");
    assert!(
        body["error"].as_str().unwrap().contains("northwind"),
        "{body}"
    );
    let shrink = json!({"id":tenant,"name":"northwind","prefixes":["192.0.2.0/24"]});
    assert_eq!(op("POST", "/v1/tenants", shrink).0, 409);
    let grow = json!({"id":tenant,"name":"northwind","prefixes":["203.0.112.0/22"]});
    assert_eq!(op("POST", "/v1/tenants", grow).0, 200);
    assert_eq!(op("DELETE", "/v1/tunnels/northwind", Value::Null).0, 200);
    assert_eq!(op("DELETE", &path, Value::Null).0, 200);
}

#[test]
fn dedicated_endpoint_capability_and_customer_configuration_are_reported() {
    let base = serve(Store::open("").unwrap());
    let (_, empty) = call(&base, "GET", "/v1/tunnels", Some(OP), Value::Null);
    assert_eq!(empty["capabilities"]["dedicated_tunnel_endpoints"], true);
    let (_, registered) = call(
        &base,
        "POST",
        "/v1/nodes/register",
        Some(ENROLL),
        json!({"name":"edge-a","region":"iad","tunnel_src":"192.0.2.1"}),
    );
    let node = node_id(&registered);
    let policy = json!({"name":"dedicated","protected":["203.0.113.0/24"],"tunnels":[{"id":"unique","remote":"198.51.100.1","local":"192.0.2.10","node":node,"prefixes":["203.0.113.0/24"]}]});
    let (status, saved) = call(&base, "POST", "/v1/policies", Some(OP), policy);
    assert_eq!(status, 200, "{saved}");
    let deploy = format!("/v1/policies/{}/deploy", saved["id"].as_str().unwrap());
    let (status, body) = call(&base, "POST", &deploy, Some(OP), Value::Null);
    assert_eq!(status, 200, "{body}");
    let (_, fleet) = call(&base, "GET", "/v1/tunnels", Some(OP), Value::Null);
    assert_eq!(fleet["tunnels"][0]["local"], "192.0.2.10");
    assert_eq!(fleet["tunnels"][0]["nodes"][0]["endpoint"], "192.0.2.10");
    let (_, program) = call(
        &base,
        "GET",
        &format!("/v1/nodes/{node}/program"),
        Some(OP),
        Value::Null,
    );
    assert_eq!(program["tunnels"][0]["local"], "192.0.2.10");
    assert_eq!(
        call(
            &base,
            "PUT",
            &format!("/v1/nodes/{node}/tunnel-endpoint"),
            Some(OP),
            json!({"address":"192.0.2.10"})
        )
        .0,
        400
    );
    assert_eq!(
        call(
            &base,
            "PUT",
            "/v1/tunnels/unique/location",
            Some(OP),
            json!({"node":""})
        )
        .0,
        400
    );
    let bad = json!({"name":"shared","protected":["203.0.113.0/24"],"tunnels":[{"id":"shared","remote":"198.51.100.1","local":"192.0.2.1","node":node,"prefixes":["203.0.113.0/24"]}]});
    assert_eq!(call(&base, "POST", "/v1/policies", Some(OP), bad).0, 400);
}
