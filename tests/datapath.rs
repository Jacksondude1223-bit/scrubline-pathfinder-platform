use pathfinder::{
    ml,
    model::{Flow, GameFilter, Match, Program, ReputationPolicy, ZCEntry},
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
    assert!(r.release("source", start + 5));
    assert_eq!(r.check("source", start + 6), 0);
    r.promote("source", 3, start + 7);
    assert_eq!(r.check("source", start + 8), 1);
    assert_eq!(r.check("source", start + 300008), 0);
    let mut e = Egress::default();
    for i in 0..3 {
        let confirmed = e.observe_return("p", "client", 4, start + i * 250);
        assert_eq!(confirmed, (i == 2).then_some(true));
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
#[test]
fn trusted_sources_stay_capped_behind_observe_only_rules() {
    let now = 1767225600000;
    let rule = |id: &str, action: &str, priority, pps| ZCEntry {
        cluster: "zc:n".into(),
        priority,
        r#match: Match::default(),
        action: action.into(),
        pps,
        rule_id: id.into(),
    };
    let mut pipe = Pipeline::new(Program {
        prefixes: vec!["203.0.113.0/24".into()],
        zc: vec![
            rule("observe", "count", 1, 0),
            rule("cap", "inspect", 2, 100),
        ],
        ..Default::default()
    });
    pipe.reputation.promote("192.0.2.9", 3, now);
    let flow = Flow {
        src_ip: "192.0.2.9".into(),
        dst_ip: "203.0.113.10".into(),
        proto: "udp".into(),
        pps: 80,
        ..Default::default()
    };
    assert_eq!(pipe.decide(&flow, now).reason, "verified source, fast path");
    let d = pipe.decide(&flow, now + 1);
    assert_eq!((d.action.as_str(), d.rule_id.as_str()), ("drop", "cap"));
    let stats = pipe.stats(now + 1);
    let observe = stats["rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["rule_id"] == "observe")
        .unwrap()
        .clone();
    assert_eq!(observe["matches"], 2);
}
#[test]
fn reloading_without_a_pulse_floor_restores_the_default() {
    let start = 1767225600000;
    let program = |floor| Program {
        prefixes: vec!["203.0.113.0/24".into()],
        pulse_floor_pps: floor,
        ..Default::default()
    };
    let mut pipe = Pipeline::new(program(50000));
    pipe.load(program(0));
    let burst = Flow {
        src_ip: "192.0.2.9".into(),
        dst_ip: "203.0.113.10".into(),
        proto: "udp".into(),
        pps: 20000,
        ..Default::default()
    };
    for i in 0..3 {
        pipe.decide(&burst, start + i * 1000);
    }
    assert_eq!(pipe.stats(start + 2000)["pulsing"], true);
}
const T0: i64 = 1767225600000;
fn gated(games: Vec<GameFilter>, fast_pass: &str) -> Program {
    Program {
        prefixes: vec!["203.0.113.0/24".into()],
        games,
        challenge_secret: "secret".into(),
        reputation: Some(ReputationPolicy {
            fast_pass: fast_pass.into(),
            penalty_box: true,
        }),
        ..Default::default()
    }
}
fn game(id: &str, dport: i64, profile: &str) -> GameFilter {
    GameFilter {
        id: id.into(),
        proto: "udp".into(),
        dport,
        profile: profile.into(),
        ..Default::default()
    }
}
fn packet(src: &str, dport: i64, payload: &[u8]) -> Flow {
    Flow {
        src_ip: src.into(),
        dst_ip: "203.0.113.10".into(),
        proto: "udp".into(),
        dport,
        pps: 1,
        payload: payload.to_vec(),
        has_payload: true,
        ..Default::default()
    }
}
#[test]
fn handshake_players_stay_connected_after_their_trust_lapses() {
    let mut pipe = Pipeline::new(gated(vec![game("game", 19132, "raknet")], "handshake"));
    pipe.decide(&packet("192.0.2.1", 19132, &[0x05]), T0);
    pipe.decide(&packet("192.0.2.1", 19132, &[0x07]), T0 + 1);
    for s in 1..=40 {
        let d = pipe.decide(&packet("192.0.2.1", 19132, &[0x84, 0, 0]), T0 + s * 10000);
        assert_eq!(d.action, "permit", "t+{}s: {}", s * 10, d.reason);
    }
}
#[test]
fn clients_the_origin_keeps_answering_stay_trusted() {
    let mut pipe = Pipeline::new(gated(vec![], "egress"));
    let reply = Flow {
        src_ip: "203.0.113.10".into(),
        dst_ip: "192.0.2.9".into(),
        proto: "udp".into(),
        pps: 4,
        ..Default::default()
    };
    for s in 0..=400 {
        pipe.observe_return(&reply, T0 + s * 1000);
    }
    let client = packet("192.0.2.9", 19132, &[]);
    let d = pipe.decide(&client, T0 + 400500);
    assert_eq!(d.reason, "verified source, fast path");
    assert_eq!(pipe.stats(T0 + 400500)["egress"]["promoted"], 1);
}
#[test]
fn a_weaker_proof_neither_restores_nor_prolongs_trust() {
    let mut r = Reputation::default();
    r.proof = 3;
    r.promote("victim", 3, T0);
    assert_eq!(r.check("victim", T0 + 1), 1);
    r.promote("victim", 1, T0 + 200000);
    assert_eq!(r.check("victim", T0 + 300001), 0);
    r.promote("victim", 1, T0 + 400000);
    assert_eq!(r.check("victim", T0 + 400001), 0);
    r.promote("victim", 3, T0 + 500000);
    assert_eq!(r.check("victim", T0 + 500001), 1);
}
#[test]
fn releasing_reports_only_sources_still_in_the_box() {
    let mut r = Reputation::default();
    r.boxing = true;
    for i in 0..4 {
        r.strike("source", T0 + i);
    }
    assert!(!r.release("source", T0 + 3 + 60000 + 1));
    assert!(!r.release("never-seen", T0));
}
#[test]
fn a2s_info_queries_are_admitted_with_the_challenge_after_their_string() {
    let mut pipe = Pipeline::new(gated(vec![game("query", 27015, "a2s")], "challenge"));
    let mut info = vec![255, 255, 255, 255, b'T'];
    info.extend_from_slice(b"Source Engine Query\0");
    let d = pipe.decide(&packet("192.0.2.1", 27015, &info), T0);
    assert_eq!(d.action, "challenge");
    let mut answer = info.clone();
    answer.extend_from_slice(&d.reply[5..]);
    let d = pipe.decide(&packet("192.0.2.1", 27015, &answer), T0 + 1);
    assert_eq!(d.action, "permit", "{}", d.reason);
}
#[test]
fn observe_only_filters_promote_nobody() {
    let mut raknet = game("game", 19132, "raknet");
    raknet.observe = true;
    let mut pipe = Pipeline::new(gated(vec![raknet], "handshake"));
    pipe.decide(&packet("192.0.2.1", 19132, &[0x07]), T0);
    let d = pipe.decide(&packet("192.0.2.1", 19132, &[0x84]), T0 + 1);
    assert_ne!(d.reason, "verified source, fast path");
    assert_eq!(pipe.stats(T0 + 1)["reputation"]["promotions"], 0);
}
#[test]
fn return_paths_are_tracked_for_every_prefix_a_node_carries() {
    let mut e = Egress::default();
    for i in 0..300 {
        e.ingress(&format!("prefix-{i}"), T0);
    }
    assert_eq!(e.stats(T0)["prefixes"], 300);
}
#[test]
fn flows_are_counted_under_the_most_specific_protected_prefix() {
    let mut pipe = Pipeline::new(Program {
        prefixes: vec!["203.0.112.0/22".into(), "203.0.113.0/24".into()],
        ..Default::default()
    });
    pipe.decide(&packet("192.0.2.1", 443, &[]), T0);
    let stats = pipe.stats(T0);
    let flows = |prefix: &str| {
        stats["prefixes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["prefix"] == prefix)
            .unwrap()["flows"]
            .clone()
    };
    assert_eq!(flows("203.0.113.0/24"), 1);
    assert_eq!(flows("203.0.112.0/22"), 0);
}
