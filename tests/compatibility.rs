use pathfinder::{bgp, compiler, metrics, ml, model::*, steering, tunnel};
use serde_json::{json, Value};
use std::collections::HashMap;
fn reference() -> Value {
    serde_json::from_str(include_str!("fixtures/go-reference.json")).unwrap()
}
// Go nil slices encode as null; Rust uses empty arrays. Both deserialize to an
// empty collection. Compare semantic contents and ignore only that spelling.
fn normalized(v: Value) -> Value {
    match v {
        Value::Null => json!([]),
        Value::Array(a) => Value::Array(a.into_iter().map(normalized).collect()),
        Value::Object(o) => Value::Object(o.into_iter().map(|(k, v)| (k, normalized(v))).collect()),
        v => v,
    }
}
#[test]
fn compiler_and_renderers_match_go() {
    let reference = reference();
    for (i, c) in reference["cases"].as_array().unwrap().iter().enumerate() {
        let policy: Policy = serde_json::from_value(c["policy"].clone()).unwrap();
        let nodes: Vec<Node> = serde_json::from_value(c["nodes"].clone()).unwrap();
        let shedding: HashMap<String, i64> = serde_json::from_value(c["shedding"].clone()).unwrap();
        let health: compiler::TunnelHealth = serde_json::from_value(c["health"].clone()).unwrap();
        let plan = compiler::plan(&policy, &nodes, &shedding, &health);
        assert_eq!(
            normalized(json!(plan)),
            normalized(c["plan"].clone()),
            "plan case {i}"
        );
        assert_eq!(
            json!(bgp::commands(&plan, 64512).unwrap()),
            c["commands"],
            "BGP case {i}"
        );
        let mut programs = compiler::compile(&policy, &nodes, &plan);
        for node in &nodes {
            let prog = programs.get_mut(&node.id).unwrap();
            prog.compiled_at = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
                .unwrap()
                .to_utc();
            // The endpoint a node's tunnels terminate on is carried in its program since it
            // became operator-assignable, with the addresses its firewall accepts tunnels from,
            // and each tunnel its share of the clean-traffic allowance and which prefixes replies
            // may and may not come from; the Go recording predates all of them.
            let mut rust = json!(prog);
            rust.as_object_mut().unwrap().remove("tunnel_src");
            rust.as_object_mut().unwrap().remove("tunnel_peers");
            if let Some(tunnels) = rust.get_mut("tunnels").and_then(|t| t.as_array_mut()) {
                for t in tunnels {
                    let t = t.as_object_mut().unwrap();
                    t.remove("rate_kbps");
                    t.remove("sources");
                    t.remove("foreign");
                }
            }
            assert_eq!(
                normalized(rust),
                normalized(c["programs"][&node.id].clone()),
                "program case {i} node {}",
                node.id
            );
            assert_eq!(
                json!(tunnel::commands(&prog.tunnels).unwrap()),
                c["tunnels"][&node.id],
                "tunnels case {i}"
            );
            if !node.tunnel_src.is_empty() {
                assert_eq!(
                    json!(bgp::session_config(&prog.sessions, node, 64512).unwrap()),
                    c["sessions"][&node.id],
                    "sessions case {i}"
                );
            }
        }
    }
}
#[test]
fn classifier_matches_go_training_features_and_predictions() {
    let r = reference();
    let samples: Vec<ml::Sample> = serde_json::from_value(r["samples"].clone()).unwrap();
    let model = ml::train(&samples, 300, 0.2, 0.65, ml::FALSE_POSITIVE_LIMIT).unwrap();
    let expected: ml::Model = serde_json::from_value(r["model"].clone()).unwrap();
    for (a, b) in model.weights.iter().zip(expected.weights.iter()) {
        assert!((a - b).abs() < 1e-10, "{a} != {b}");
    }
    for (a, b) in [
        (model.bias, expected.bias),
        (model.loss, expected.loss),
        (model.accuracy, expected.accuracy),
        (model.precision, expected.precision),
        (model.recall, expected.recall),
    ] {
        assert!((a - b).abs() < 1e-10);
    }
    assert_eq!(model.validation, expected.validation);
    assert_eq!(model.samples, expected.samples);
    let flows: Vec<Flow> = serde_json::from_value(r["flows"].clone()).unwrap();
    for (i, f) in flows.iter().enumerate() {
        for (j, v) in ml::features(f).iter().enumerate() {
            assert!((v - r["features"][i][j].as_f64().unwrap()).abs() < 1e-12);
        }
        assert!((ml::score(&model, f) - r["scores"][i].as_f64().unwrap()).abs() < 1e-10);
    }
    assert!(ml::train(&[], 0, 0.0, 0.0, 0.0).is_err());
    assert!(ml::train(
        &[ml::Sample {
            label: 2,
            ..Default::default()
        }],
        0,
        0.0,
        0.0,
        0.0
    )
    .is_err());
    assert!(ml::validate_flow(&Flow {
        pps: -1,
        ..Default::default()
    })
    .is_err());
    assert!(ml::validate_flow(&Flow {
        dport: 65536,
        ..Default::default()
    })
    .is_err());
}
#[test]
fn steering_matches_go_dwell_recovery_and_burst_holds() {
    let r = reference();
    let mut c = steering::Controller::default();
    for round in r["rounds"].as_array().unwrap() {
        let at = chrono::DateTime::parse_from_rfc3339(round["at"].as_str().unwrap())
            .unwrap()
            .to_utc();
        c.observe_at(
            &[steering::Sample {
                node_id: "n".into(),
                offered_pps: round["offered"].as_u64().unwrap(),
                peak_pps: round["peak"].as_u64().unwrap(),
                capacity_pps: round["capacity"].as_i64().unwrap(),
                pulsing: round["pulsing"].as_bool().unwrap(),
                fresh: round["fresh"].as_bool().unwrap(),
                // Go reports no surge rate, and without one shedding goes by the mean, as there.
                surge_pps: 0,
            }],
            at,
        );
        assert_eq!(json!(c.levels()), round["levels"]);
    }
    c.observe(&[]);
    assert!(c.levels().is_empty());
}
#[test]
fn metrics_match_go_and_reject_injection() {
    use metrics::{Family, Label, Sample};
    let families = [Family {
        name: "scrub_count".into(),
        help: "line\\quote\nnext".into(),
        kind: "counter".into(),
        samples: vec![
            Sample {
                labels: vec![Label {
                    name: "node".into(),
                    value: "z\"\\\nx".into(),
                }],
                value: 42.0,
            },
            Sample {
                labels: vec![Label {
                    name: "node".into(),
                    value: "a".into(),
                }],
                value: 3.0,
            },
        ],
    }];
    assert_eq!(
        metrics::render(&families).unwrap(),
        reference()["metrics"].as_str().unwrap()
    );
    assert!(metrics::render(&[families[0].clone(), families[0].clone()]).is_err());
    let bad = Family {
        name: "bad\nname".into(),
        ..families[0].clone()
    };
    assert!(metrics::render(&[bad]).is_err());
    let special = Family {
        name: "x".into(),
        samples: vec![
            Sample {
                value: f64::INFINITY,
                ..Default::default()
            },
            Sample {
                value: f64::NEG_INFINITY,
                ..Default::default()
            },
            Sample {
                value: f64::NAN,
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    assert_eq!(
        metrics::render(&[special]).unwrap(),
        "x +Inf\nx -Inf\nx NaN\n"
    );
}
#[test]
fn models_accept_go_null_arrays_and_base64() {
    let flow: Flow = serde_json::from_value(json!({"payload":"AAEC/w=="})).unwrap();
    assert_eq!(flow.payload, vec![0, 1, 2, 255]);
    assert_eq!(json!(flow)["payload"], "AAEC/w==");
    let policy: Policy =
        serde_json::from_value(json!({"rules":null,"protected":null,"games":null})).unwrap();
    assert!(policy.rules.is_empty());
    assert!(policy.protected.is_empty());
    assert_eq!(json!(policy)["updated_at"], "0001-01-01T00:00:00Z");
    assert!(serde_json::from_value::<Flow>(json!({"payload":"not-base64!"})).is_err());
}
#[test]
fn routing_and_tunnel_inputs_reject_config_injection() {
    for c in [
        "",
        "64512:1\nwithdraw route 0.0.0.0/0",
        "65536:1",
        "4294967296:1:2",
        "a:b",
        "1::2",
    ] {
        assert!(bgp::validate_community(c).is_err(), "{c}");
    }
    for c in ["no-export", "BLACKHOLE", "64512:42", "4294967295:1:2"] {
        bgp::validate_community(c).unwrap();
    }
    for id in ["", "abc; id", "abcdefghijkl", "UPPER", "-abc"] {
        assert!(tunnel::interface_name(id).is_err());
    }
    let mut t = Tunnel {
        id: "customer".into(),
        remote: "192.0.2.2".into(),
        prefixes: vec!["203.0.113.0/24".into()],
        ..Default::default()
    };
    tunnel::validate(&t, None).unwrap();
    assert_eq!(tunnel::default_mtu(&t), 1476);
    t.key = 42;
    assert_eq!(tunnel::default_mtu(&t), 1472);
    t.r#type = "ipip".into();
    assert!(tunnel::validate(&t, None).is_err());
    t.key = 0;
    tunnel::validate(&t, None).unwrap();
    assert_eq!(tunnel::default_mtu(&t), 1480);
    t.mtu = 1600;
    assert!(tunnel::validate(&t, None).is_err());
    t.mtu = 0;
    t.remote = "127.0.0.1".into();
    assert!(tunnel::validate(&t, None).is_err());
    let required = NodeTunnel {
        id: "customer".into(),
        required: true,
        ..Default::default()
    };
    assert!(!tunnel::deliverable(&required, "unknown").0);
    assert!(tunnel::deliverable(&required, "up").0);
    assert!(!tunnel::deliverable(&required, "down").0);
    let bad = Announcement {
        prefix: "203.0.113.0/24".into(),
        state: "announce".into(),
        prepends: 1,
        ..Default::default()
    };
    assert!(bgp::commands(&[bad], 0).is_err());
    let mut s = Session {
        id: "peer".into(),
        peer_ip: "192.0.2.1".into(),
        peer_as: 64512,
        prefixes: vec!["203.0.113.0/24".into()],
        ..Default::default()
    };
    bgp::validate_session(&s, None).unwrap();
    s.password = "x\"; import all;".into();
    assert!(bgp::validate_session(&s, None).is_err());
}
