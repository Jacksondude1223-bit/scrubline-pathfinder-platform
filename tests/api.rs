use pathfinder::{analytics::Collector, api::Api, model::Program, store::Store};
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
    let state = Arc::new(Mutex::new(Api::new(
        store,
        OP.into(),
        ENROLL.into(),
        "primary".into(),
    )));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
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
    base
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
    let stats = json!({"prefixes":[{"prefix":"203.0.113.0/24","flows":10,"offered":5000}]});
    c.observe("node", &stats, &Program::default(), now);
    assert_eq!(
        c.summary("203.0.113.0/24", 30000, now + 1000)["offered"],
        5000
    );
    let points = c.points("203.0.113.0/24", 30000, 250, now + 1000);
    assert_eq!(points.len(), 1);
    assert_eq!(points[0]["offered"], 5000);
}
