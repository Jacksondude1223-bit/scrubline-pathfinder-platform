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
    let state: Shared = Arc::new(Mutex::new(Api::new(
        store,
        OP.into(),
        ENROLL.into(),
        "primary".into(),
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
