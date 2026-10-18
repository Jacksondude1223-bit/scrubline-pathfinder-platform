use pathfinder::{
    ml,
    model::{Flow, Program},
    pipeline::Pipeline,
    state::{Egress, Pulse, Reputation},
};
use serde_json::{json, Value};
fn equal(a: &Value, b: &Value, path: &str) {
    match (a, b) {
        (Value::Number(a), Value::Number(b)) => {
            let (a, b) = (a.as_f64().unwrap(), b.as_f64().unwrap());
            assert!(
                (a - b).abs() <= 1e-9 * a.abs().max(b.abs()).max(1.0),
                "{path}: {a} != {b}"
            );
        }
        (Value::Array(a), Value::Array(b)) => {
            assert_eq!(a.len(), b.len(), "{path}");
            for (i, (a, b)) in a.iter().zip(b).enumerate() {
                equal(a, b, &format!("{path}[{i}]"));
            }
        }
        (Value::Object(a), Value::Object(b)) => {
            assert_eq!(
                a.keys().collect::<Vec<_>>(),
                b.keys().collect::<Vec<_>>(),
                "{path}: key mismatch"
            );
            for (k, a) in a {
                equal(a, &b[k], &format!("{path}.{k}"));
            }
        }
        _ => assert_eq!(a, b, "{path}"),
    }
}
#[test]
fn complete_pipeline_matches_go_recorded_sequences() {
    let cases: Value = serde_json::from_str(include_str!("fixtures/go-datapath.json")).unwrap();
    for case in cases.as_array().unwrap() {
        let program: Program = serde_json::from_value(case["program"].clone()).unwrap();
        let mut pipe = Pipeline::new(program);
        for (i, step) in case["steps"].as_array().unwrap().iter().enumerate() {
            let at = step["at"].as_i64().unwrap();
            let label = format!("{} step {i}", case["name"]);
            if let Some(model) = step.get("model") {
                pipe.model = serde_json::from_value::<ml::Model>(model.clone()).unwrap();
            }
            if let Some(program) = step.get("reload") {
                pipe.load(serde_json::from_value(program.clone()).unwrap());
            }
            if let Some(flow) = step.get("return") {
                pipe.observe_return(&serde_json::from_value::<Flow>(flow.clone()).unwrap(), at);
            }
            if let Some(flow) = step.get("flow") {
                let d = pipe.decide(&serde_json::from_value::<Flow>(flow.clone()).unwrap(), at);
                equal(&json!(d), &step["decision"], &format!("{label}.decision"));
            }
            equal(&pipe.stats(at), &step["stats"], &format!("{label}.stats"));
        }
    }
}
#[test]
fn bounded_state_expires_without_sleeping() {
    let start = 1767225600000;
    let mut p = Pulse::default();
    p.floor = 100;
    for i in 0..3 {
        p.observe("p", 1000, start + i * 1000);
        p.assess("p", start + i * 1000);
    }
    assert_eq!(p.assess("p", start + 3000)["pulsing"], true);
    assert_eq!(p.assess("p", start + 400000)["pulsing"], false);
    let mut r = Reputation::default();
    r.proof = 3;
    r.boxing = true;
    for i in 0..4 {
        r.strike("source", start + i);
    }
    assert_eq!(r.check("source", start + 5), 2);
    assert!(r.release("source"));
    assert_eq!(r.check("source", start + 6), 0);
    r.promote("source", 3, start + 7);
    assert_eq!(r.check("source", start + 8), 1);
    assert_eq!(r.check("source", start + 300008), 0);
    let mut e = Egress::default();
    for i in 0..3 {
        let fresh = e.observe_return("p", "client", 4, start + i * 250);
        assert_eq!(fresh, i == 2);
    }
    assert!(e.confirmed("p", "client", start + 501));
    assert_eq!(e.visibility("p", start + 501), "visible");
    assert!(!e.confirmed("p", "client", start + 130000));
}
#[test]
fn untrusted_state_tables_stay_bounded() {
    let now = 1767225600000;
    let mut r = Reputation::default();
    for i in 0..66000 {
        r.strike(&format!("source-{i}"), now);
    }
    assert_eq!(r.stats(now)["tracked"], 65536);
    assert!(r.stats(now)["full"].as_u64().unwrap() > 0);
    let mut p = Pulse::default();
    for i in 0..4200 {
        p.observe(&format!("prefix-{i}"), 100, now);
    }
    let mut e = Egress::default();
    for i in 0..66000 {
        e.grace("p", &format!("client-{i}"), 500, now);
    }
    assert_eq!(e.stats(now)["clients"], 65536);
}
