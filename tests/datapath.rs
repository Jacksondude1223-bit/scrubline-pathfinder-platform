use pathfinder::{
    ml,
    model::{
        ACLEntry, Flow, GameFilter, GameHttp, GameHttpPath, GameSignature, Match, MlPolicy,
        NodeTunnel, Program, ReputationPolicy, ZCEntry,
    },
    pipeline::{Pipeline, CAMPAIGN, MITIGATION_HOLD, MITIGATION_HOLD_MAX, PROBE_HOLD},
    state::{Egress, Pulse, Reputation},
    validation,
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
/// Stats as the Go datapath reported them: the counters for HTTP rules, the surge rate, what the
/// classifiers report beyond the flow model's counts, on-demand mitigation, the crafted-packet
/// checks and the reflection guard, none of which it had, are left out of the comparison.
fn go_shape(mut stats: Value) -> Value {
    let top = stats.as_object_mut().unwrap();
    top.remove("game_http_windows");
    top.remove("game_http_windows_max");
    top.remove("surge_pps");
    top.remove("mitigation");
    top.remove("crafted");
    top.remove("reflection");
    let ml = top["ml"].as_object_mut().unwrap();
    for key in [
        "observed",
        "http_ready",
        "http_scored",
        "http_drops",
        "http_observed",
        "scope",
        "mode",
        "probing",
        "near_misses",
        "tightened",
    ] {
        ml.remove(key);
    }
    for row in stats["games"].as_array_mut().into_iter().flatten() {
        let row = row.as_object_mut().unwrap();
        for key in [
            "http_requests",
            "http_dropped",
            "http_rate_limited",
            "http_other",
            "http_budget_dropped",
        ] {
            row.remove(key);
        }
    }
    for row in stats["prefixes"].as_array_mut().into_iter().flatten() {
        let row = row.as_object_mut().unwrap();
        row.remove("ml_cut");
        row.remove("crafted");
        row.remove("reflection");
    }
    stats["reputation"].as_object_mut().unwrap().remove("freed");
    stats
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
            equal(
                &go_shape(pipe.stats(at)),
                &step["stats"],
                &format!("{label}.stats"),
            );
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
#[test]
fn a_flood_shows_in_full_in_the_surge_rate_within_its_first_second() {
    let mut pipe = Pipeline::new(Program {
        prefixes: vec!["203.0.113.0/24".into()],
        ..Default::default()
    });
    // Five flows at 5,000 pps each, over the first half of a second.
    for i in 0..5 {
        let flow = Flow {
            pps: 5000,
            ..packet("192.0.2.1", 443, &[])
        };
        pipe.decide(&flow, T0 + 100 * i);
    }
    let rates = |pipe: &mut Pipeline, at: i64| {
        let stats = pipe.stats(at);
        (stats["surge_pps"].clone(), stats["offered_pps"].clone())
    };
    // The ten-second mean has a tenth of it so far.
    assert_eq!(rates(&mut pipe, T0 + 500), (json!(25000), json!(2500)));
    assert_eq!(pipe.surge(T0 + 500), 25000);
    // A window ending a quarter into the next second still covers three quarters of this one.
    assert_eq!(rates(&mut pipe, T0 + 1250), (json!(18750), json!(2500)));
    // Two seconds on, the flood has left the last second, though not the mean.
    assert_eq!(rates(&mut pipe, T0 + 2000), (json!(0), json!(2500)));
}

/// A game server answering HTTP on its game port, as FiveM's does: UDP for play, TCP for its
/// player list, resources and its own handlers.
fn http_server(paths: Vec<GameHttpPath>, http: GameHttp, penalty_box: bool) -> Program {
    Program {
        prefixes: vec!["203.0.113.0/24".into()],
        games: vec![GameFilter {
            id: "server".into(),
            dst_cidr: "203.0.113.20/32".into(),
            proto: "udp".into(),
            dport: 30120,
            custom: Some(GameSignature {
                min_len: 4,
                ..Default::default()
            }),
            http: Some(GameHttp { paths, ..http }),
            ..Default::default()
        }],
        challenge_secret: "secret".into(),
        reputation: Some(ReputationPolicy {
            fast_pass: "egress".into(),
            penalty_box,
        }),
        ..Default::default()
    }
}
fn path(path: &str, rate: i64) -> GameHttpPath {
    GameHttpPath {
        path: path.into(),
        rate_per_source: rate,
        ..Default::default()
    }
}
fn request(src: &str, payload: &str) -> Flow {
    Flow {
        src_ip: src.into(),
        dst_ip: "203.0.113.20".into(),
        proto: "tcp".into(),
        sport: 50000,
        dport: 30120,
        pps: 1,
        payload: payload.as_bytes().to_vec(),
        has_payload: true,
        ..Default::default()
    }
}
fn get(target: &str) -> String {
    format!("GET {target} HTTP/1.1\r\nHost: 203.0.113.20:30120\r\nUser-Agent: curl/8\r\n\r\n")
}
#[test]
fn http_requests_are_held_to_their_paths_methods_clients_and_rates() {
    let paths = vec![
        path("/players.json", 1),
        GameHttpPath {
            path: "/client".into(),
            methods: vec!["POST".into()],
            user_agents: vec!["CitizenFX/".into()],
            max_body_bytes: 2048,
            ..Default::default()
        },
        GameHttpPath {
            prefix: "/admin/".into(),
            action: "drop".into(),
            ..Default::default()
        },
    ];
    let mut pipe = Pipeline::new(http_server(paths, GameHttp::default(), false));
    let a = "192.0.2.1";
    let decide = |pipe: &mut Pipeline, src: &str, payload: &str, at: i64| {
        let d = pipe.decide(&request(src, payload), T0 + at);
        (d.action.to_string(), d.reason)
    };
    assert_eq!(decide(&mut pipe, a, &get("/players.json"), 0).0, "permit");
    let (action, reason) = decide(&mut pipe, a, &get("/players.json"), 100);
    assert_eq!(action, "drop");
    assert_eq!(
        reason,
        "game filter http: GET /players.json: more than 1 request a second to this path from this source"
    );
    // Another spelling of the path counts against the same limit.
    assert_eq!(
        decide(&mut pipe, a, &get("/%70layers.JSON?x=1"), 200).0,
        "drop"
    );
    // Other sources have their own budget, and this one's comes back a second later.
    assert_eq!(
        decide(&mut pipe, "192.0.2.2", &get("/players.json"), 300).0,
        "permit"
    );
    assert_eq!(
        decide(&mut pipe, a, &get("/players.json"), 1300).0,
        "permit"
    );
    let (action, reason) = decide(&mut pipe, a, &get("/admin/kick?id=1"), 1400);
    assert_eq!(action, "drop");
    assert!(
        reason.ends_with("GET /admin/kick: the path is blocked"),
        "{reason}"
    );
    assert_eq!(
        decide(&mut pipe, a, &get("/files/../admin/x"), 1400).0,
        "drop"
    );
    let (action, reason) = decide(&mut pipe, a, "DELETE /info.json HTTP/1.1\r\n\r\n", 1500);
    assert_eq!(action, "drop");
    assert!(
        reason.ends_with("DELETE /info.json: not a method this path allows"),
        "{reason}"
    );
    let client = |ua: &str, len: usize| {
        format!("POST /client HTTP/1.1\r\nUser-Agent: {ua}\r\nContent-Length: {len}\r\n\r\nmethod=initConnect")
    };
    let (action, reason) = decide(&mut pipe, a, &client("curl/8", 18), 1600);
    assert_eq!(action, "drop");
    assert!(
        reason.ends_with("User-Agent curl/8 is not one this path allows"),
        "{reason}"
    );
    assert_eq!(
        decide(&mut pipe, a, &client("CitizenFX/1", 18), 1700).0,
        "permit"
    );
    let (action, reason) = decide(&mut pipe, a, &client("CitizenFX/1", 99999), 1800);
    assert_eq!(action, "drop");
    assert!(
        reason.ends_with("a 99999-byte body, over the 2048 bytes allowed"),
        "{reason}"
    );
    assert_eq!(
        decide(&mut pipe, a, &get("/client"), 1900).0,
        "drop",
        "GET on a POST endpoint"
    );
    let (action, reason) = decide(&mut pipe, a, "GET /info.json HTTP/9.9\r\n\r\n", 2000);
    assert_eq!(action, "drop");
    assert!(reason.contains("a malformed request"), "{reason}");
    let stats = pipe.stats(T0 + 2000);
    let row = &stats["games"][0];
    assert_eq!(row["filter_id"], "server");
    assert_eq!(row["http_requests"], 13);
    assert_eq!(row["http_dropped"], 9);
    assert_eq!(row["http_rate_limited"], 2);
    assert_eq!(stats["game_http_windows"], 2);
}
#[test]
fn a_server_can_allow_only_the_paths_it_names_and_cap_each_source() {
    let mut pipe = Pipeline::new(http_server(
        vec![path("/info.json", 0)],
        GameHttp {
            default: "drop".into(),
            rate_per_source: 2,
            ..Default::default()
        },
        false,
    ));
    let d = pipe.decide(&request("192.0.2.1", &get("/resource/handler")), T0);
    assert_eq!(d.action, "drop");
    assert!(
        d.reason
            .ends_with("GET /resource/handler: not a path this server allows"),
        "{}",
        d.reason
    );
    for i in 0..2 {
        assert_eq!(
            pipe.decide(&request("192.0.2.1", &get("/info.json")), T0 + i)
                .action,
            "permit"
        );
    }
    let d = pipe.decide(&request("192.0.2.1", &get("/info.json")), T0 + 2);
    assert!(
        d.reason
            .ends_with("more than 2 requests a second to this server from this source"),
        "{}",
        d.reason
    );
}
#[test]
fn http_rules_look_only_where_their_filter_is_bound() {
    let mut pipe = Pipeline::new(http_server(
        vec![GameHttpPath {
            prefix: "/".into(),
            action: "drop".into(),
            ..Default::default()
        }],
        GameHttp::default(),
        false,
    ));
    let blocked = get("/anything");
    assert_eq!(
        pipe.decide(&request("192.0.2.1", &blocked), T0).action,
        "drop"
    );
    let mut elsewhere = request("192.0.2.1", &blocked);
    elsewhere.dst_ip = "203.0.113.21".into();
    assert_eq!(
        pipe.decide(&elsewhere, T0).action,
        "permit",
        "another address"
    );
    let mut other_port = request("192.0.2.1", &blocked);
    other_port.dport = 80;
    assert_eq!(
        pipe.decide(&other_port, T0).action,
        "permit",
        "another port"
    );
    // UDP on the game port is still the profile's to judge.
    let mut play = request("192.0.2.1", "ab");
    play.proto = "udp".into();
    let d = pipe.decide(&play, T0);
    assert_eq!(d.action, "drop");
    assert!(d.reason.starts_with("game filter custom:"), "{}", d.reason);
    // Ports of its own move the HTTP rules off the game port.
    let mut own = http_server(vec![], GameHttp::default(), false);
    own.games[0].http.as_mut().unwrap().ports = vec![8080];
    own.games[0].http.as_mut().unwrap().default = "drop".into();
    let mut pipe = Pipeline::new(own);
    assert_eq!(
        pipe.decide(&request("192.0.2.1", &blocked), T0).action,
        "permit"
    );
    assert_eq!(pipe.decide(&other_port, T0).action, "permit");
    let mut web = request("192.0.2.1", &blocked);
    web.dport = 8080;
    assert_eq!(pipe.decide(&web, T0).action, "drop");
}
#[test]
fn segments_that_start_no_request_pass() {
    let mut pipe = Pipeline::new(http_server(
        vec![],
        GameHttp {
            default: "drop".into(),
            ..Default::default()
        },
        false,
    ));
    let tls = String::from_utf8_lossy(&[0x16, 0x03, 0x01, 0x00, 0x05]).into_owned();
    for payload in [
        "the rest of a body",
        tls.as_str(),
        "",
        "OK then: a body that starts with capitals",
    ] {
        let d = pipe.decide(&request("192.0.2.1", payload), T0);
        assert_eq!(d.action, "permit", "{payload:?}: {}", d.reason);
    }
    // A request line hidden behind a body in the same segment is still found.
    let d = pipe.decide(
        &request("192.0.2.1", "more body\r\nGET /secret HTTP/1.1\r\n\r\n"),
        T0,
    );
    assert_eq!(d.action, "drop");
    // So is one split across segments to hide its path.
    let d = pipe.decide(&request("192.0.2.1", "GET /sec"), T0);
    assert_eq!(d.action, "drop");
    assert!(d.reason.contains("split across segments"), "{}", d.reason);
    // Cleartext HTTP/2 would carry requests no rule could read, even on a path that is allowed.
    let mut open = Pipeline::new(http_server(vec![], GameHttp::default(), false));
    for h2c in [
        "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
        "GET / HTTP/1.1\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\n\r\n",
    ] {
        let d = open.decide(&request("192.0.2.1", h2c), T0);
        assert_eq!(d.action, "drop", "{h2c:?}");
        assert!(d.reason.contains("HTTP/2"), "{}", d.reason);
    }
    let websocket = "GET /ws HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
    assert_eq!(
        open.decide(&request("192.0.2.1", websocket), T0).action,
        "permit"
    );
    let mut unsupplied = request("192.0.2.1", "");
    unsupplied.has_payload = false;
    assert_eq!(pipe.decide(&unsupplied, T0).action, "permit");
    let row = &pipe.stats(T0)["games"][0];
    assert_eq!(row["http_other"], 3);
    assert_eq!(row["uninspectable"], 1);
}
#[test]
fn an_observing_filter_only_reports_what_it_would_drop() {
    let mut program = http_server(vec![path("/players.json", 1)], GameHttp::default(), false);
    program.games[0].observe = true;
    let mut pipe = Pipeline::new(program);
    for i in 0..3 {
        let d = pipe.decide(&request("192.0.2.1", &get("/players.json")), T0 + i);
        assert_eq!(d.action, "permit");
    }
    let row = &pipe.stats(T0)["games"][0];
    assert_eq!(
        (row["http_requests"].as_u64(), row["http_dropped"].as_u64()),
        (Some(3), Some(0))
    );
}
#[test]
fn verified_sources_are_held_to_http_rates_and_abusers_are_boxed() {
    let mut pipe = Pipeline::new(http_server(
        vec![path("/players.json", 1)],
        GameHttp::default(),
        true,
    ));
    // A source the origin answers is trusted, and still held to the rate.
    let reply = Flow {
        src_ip: "203.0.113.20".into(),
        dst_ip: "192.0.2.9".into(),
        proto: "udp".into(),
        pps: 4,
        ..Default::default()
    };
    pipe.observe_return(&reply, T0);
    assert_eq!(
        pipe.decide(&request("192.0.2.9", &get("/players.json")), T0 + 1)
            .action,
        "permit"
    );
    let d = pipe.decide(&request("192.0.2.9", &get("/players.json")), T0 + 2);
    assert_eq!(d.action, "drop", "{}", d.reason);
    // An untrusted source that keeps going over lands in the penalty box, game traffic and all.
    for i in 0..5 {
        pipe.decide(&request("192.0.2.66", &get("/players.json")), T0 + 10 + i);
    }
    let mut play = request("192.0.2.66", "abcd");
    play.proto = "udp".into();
    assert_eq!(
        pipe.decide(&play, T0 + 20).reason,
        "source is in the penalty box"
    );
}
#[test]
fn http_rules_are_validated_with_the_policy() {
    let base = |http: GameHttp| pathfinder::model::Policy {
        name: "p".into(),
        protected: vec!["203.0.113.0/24".into()],
        games: vec![GameFilter {
            id: "web".into(),
            dst_cidr: "203.0.113.20/32".into(),
            dport: 30120,
            http: Some(http),
            ..Default::default()
        }],
        ..Default::default()
    };
    // HTTP rules on their own are a filter.
    validation::policy(&base(GameHttp::default())).unwrap();
    let mut only_ports = base(GameHttp {
        ports: vec![80],
        ..Default::default()
    });
    only_ports.games[0].dst_cidr.clear();
    only_ports.games[0].dport = 0;
    validation::policy(&only_ports).unwrap();
    let refused = |http: GameHttp| validation::policy(&base(http)).unwrap_err();
    for (http, want) in [
        (
            GameHttp {
                ports: vec![70000],
                ..Default::default()
            },
            "is not a port",
        ),
        (
            GameHttp {
                methods: vec!["G3T".into()],
                ..Default::default()
            },
            "is not an HTTP method",
        ),
        (
            GameHttp {
                default: "block".into(),
                ..Default::default()
            },
            "must be allow or drop",
        ),
        (
            GameHttp {
                rate_per_source: -1,
                ..Default::default()
            },
            "must not be negative",
        ),
        (
            GameHttp {
                rate_total: -1,
                ..Default::default()
            },
            "http.rate_total must not be negative",
        ),
        (
            GameHttp {
                paths: vec![GameHttpPath {
                    rate_total: -1,
                    ..path("/players.json", 1)
                }],
                ..Default::default()
            },
            "rate_per_source, rate_total and max_body_bytes must not be negative",
        ),
        (
            GameHttp {
                paths: vec![GameHttpPath {
                    prefix: "/admin".into(),
                    action: "drop".into(),
                    rate_total: 5,
                    ..Default::default()
                }],
                ..Default::default()
            },
            "a path that drops takes no methods, user agents, rates or body limit",
        ),
        (
            GameHttp {
                paths: vec![GameHttpPath {
                    path: "/a".into(),
                    prefix: "/a".into(),
                    ..Default::default()
                }],
                ..Default::default()
            },
            "set either path or prefix",
        ),
        (
            GameHttp {
                paths: vec![GameHttpPath {
                    path: "players.json".into(),
                    ..Default::default()
                }],
                ..Default::default()
            },
            "must start with /",
        ),
        (
            GameHttp {
                paths: vec![path("/Players.json", 1), path("/players.json", 2)],
                ..Default::default()
            },
            "the same path as an earlier rule",
        ),
        (
            GameHttp {
                paths: vec![GameHttpPath {
                    prefix: "/admin".into(),
                    action: "drop".into(),
                    rate_per_source: 5,
                    ..Default::default()
                }],
                ..Default::default()
            },
            "a path that drops takes no methods",
        ),
    ] {
        let e = refused(http);
        assert!(e.contains(want), "{e}");
    }
    // A TCP profile on the port the HTTP rules judge would never see a packet; one on every
    // port still judges the ports the rules leave it.
    let mut shadowed = base(GameHttp::default());
    shadowed.games[0].proto = "tcp".into();
    shadowed.games[0].profile = "raknet".into();
    let e = validation::policy(&shadowed).unwrap_err();
    assert!(e.contains("would judge the same TCP port"), "{e}");
    let mut beside = base(GameHttp {
        ports: vec![8080],
        ..Default::default()
    });
    beside.games[0].proto = "tcp".into();
    beside.games[0].profile = "raknet".into();
    beside.games[0].dport = 0;
    validation::policy(&beside).unwrap();
}

/// A flow model that goes by rate alone: 1,000 pps scores 0.5, its threshold.
fn rate_model() -> ml::Model {
    let mut weights = vec![0.0; ml::FEATURE_COUNT];
    weights[0] = 12.0;
    ml::Model {
        weights,
        bias: -(1001f64).ln(),
        threshold: 0.5,
        ready: true,
        ..Default::default()
    }
}
/// A request model that goes by whether a request names its client: one that does not scores
/// 0.98, against a threshold of 0.5.
fn client_model() -> ml::Model {
    let mut weights = vec![0.0; ml::REQUEST_FEATURES];
    weights[8] = -8.0;
    ml::Model {
        weights,
        bias: 4.0,
        threshold: 0.5,
        ready: true,
        ..Default::default()
    }
}
fn with_ml(program: Program, scope: &str, mode: &str) -> Program {
    Program {
        ml: Some(MlPolicy {
            scope: scope.into(),
            mode: mode.into(),
            ..Default::default()
        }),
        ..program
    }
}
fn at_rate(src: &str, dport: i64, pps: i64) -> Flow {
    Flow {
        pps,
        ..packet(src, dport, &[1, 2, 3, 4])
    }
}
#[test]
fn the_flow_model_has_the_last_word_on_whatever_the_stages_let_through() {
    let mut pipe = Pipeline::new(http_server(vec![], GameHttp::default(), true));
    pipe.model = rate_model();
    // Nothing matches a flood to a port no rule names, so the model decides it.
    let d = pipe.decide(&at_rate("192.0.2.1", 9000, 100_000), T0);
    assert_eq!(
        (d.action.as_str(), d.stage.as_str(), d.reason.as_str()),
        ("drop", "zc", "PF_RING ZC ml score 0.99")
    );
    let d = pipe.decide(&at_rate("192.0.2.2", 9000, 10), T0);
    assert_eq!(
        (d.action.as_str(), d.reason.as_str()),
        ("permit", "PF_RING ZC ml pass")
    );
    assert!(d.score > 0.0 && d.score < 0.5);
    // Well-formed game traffic passes its filter, and then the model.
    let mut game = at_rate("192.0.2.3", 30120, 100_000);
    game.dst_ip = "203.0.113.20".into();
    assert_eq!(pipe.decide(&game, T0).reason, "PF_RING ZC ml score 0.99");
    let stats = pipe.stats(T0);
    assert_eq!(
        (
            &stats["ml"]["scored"],
            &stats["ml"]["drops"],
            &stats["ml"]["passes"]
        ),
        (&json!(3), &json!(2), &json!(1))
    );
    assert_eq!(
        (&stats["ml"]["scope"], &stats["ml"]["mode"]),
        (&json!("all"), &json!("enforce"))
    );
    // Its drops are no strike against the source: a score proves nothing, and the box would
    // turn one wrong score into every packet from it dropped.
    for _ in 0..4 {
        pipe.decide(&at_rate("192.0.2.1", 9000, 100_000), T0);
    }
    assert_eq!(
        pipe.decide(&at_rate("192.0.2.1", 9000, 10), T0).reason,
        "PF_RING ZC ml pass"
    );
    assert_eq!(pipe.stats(T0)["reputation"]["strikes"], 0);
    // A permit rule ends evaluation before the model has a say.
    let mut program = http_server(vec![], GameHttp::default(), false);
    program.zc = vec![ZCEntry {
        rule_id: "allow".into(),
        action: "permit".into(),
        r#match: Match {
            dport: 9000,
            ..Default::default()
        },
        ..Default::default()
    }];
    pipe.load(program);
    assert_eq!(
        pipe.decide(&at_rate("192.0.2.4", 9000, 100_000), T0).reason,
        "PF_RING ZC permit"
    );
}
#[test]
fn scope_inspect_keeps_the_flow_model_to_what_zc_inspect_rules_send_it() {
    let mut program = with_ml(
        http_server(vec![], GameHttp::default(), false),
        "inspect",
        "",
    );
    program.zc = vec![ZCEntry {
        rule_id: "behaviour".into(),
        action: "inspect".into(),
        r#match: Match {
            dport: 9000,
            ..Default::default()
        },
        ..Default::default()
    }];
    let mut pipe = Pipeline::new(program);
    pipe.model = rate_model();
    let d = pipe.decide(&at_rate("192.0.2.1", 9000, 100_000), T0);
    assert_eq!(
        (d.rule_id.as_str(), d.action.as_str()),
        ("behaviour", "drop")
    );
    let d = pipe.decide(&at_rate("192.0.2.2", 9001, 100_000), T0);
    assert_eq!(
        (d.action.as_str(), d.reason.as_str()),
        ("permit", "no matching drop rule")
    );
    assert_eq!(pipe.stats(T0)["ml"]["scope"], "inspect");
}
#[test]
fn observing_models_count_what_they_would_drop_and_drop_nothing() {
    let mut pipe = Pipeline::new(with_ml(
        http_server(vec![], GameHttp::default(), true),
        "",
        "observe",
    ));
    pipe.model = ml::Model {
        http: Some(Box::new(client_model())),
        ..rate_model()
    };
    for _ in 0..6 {
        let d = pipe.decide(&at_rate("192.0.2.1", 9000, 100_000), T0);
        assert_eq!(
            (d.action.as_str(), d.reason.as_str()),
            ("permit", "PF_RING ZC ml score 0.99, observed only")
        );
    }
    let mut anonymous = request("192.0.2.2", "GET /players.json HTTP/1.1\r\n\r\n");
    anonymous.pps = 1;
    assert_ne!(pipe.decide(&anonymous, T0).action, "drop");
    let stats = pipe.stats(T0);
    // The request, at 1 pps, is under the flow model's threshold.
    assert_eq!(
        (
            &stats["ml"]["drops"],
            &stats["ml"]["observed"],
            &stats["ml"]["passes"]
        ),
        (&json!(0), &json!(6), &json!(1))
    );
    assert_eq!(
        (
            &stats["ml"]["http_drops"],
            &stats["ml"]["http_observed"],
            &stats["ml"]["mode"]
        ),
        (&json!(0), &json!(1), &json!("observe"))
    );
}
#[test]
fn the_request_model_judges_each_request_the_http_rules_allow() {
    let mut pipe = Pipeline::new(http_server(
        vec![path("/players.json", 10)],
        GameHttp::default(),
        false,
    ));
    // A published request model and no flow model, so what follows is the request model's alone.
    pipe.model = ml::Model {
        http: Some(Box::new(client_model())),
        ..Default::default()
    };
    assert_ne!(
        pipe.decide(&request("192.0.2.1", &get("/players.json")), T0)
            .action,
        "drop"
    );
    let d = pipe.decide(
        &request(
            "192.0.2.1",
            "GET /players.json HTTP/1.1\r\nHost: 203.0.113.20\r\n\r\n",
        ),
        T0,
    );
    assert_eq!(
        (d.action.as_str(), d.filter.as_str(), d.reason.as_str()),
        (
            "drop",
            "server",
            "game filter http: GET /players.json: scored 0.98 by the request model, which drops at 0.50"
        )
    );
    assert!((d.score - 0.982).abs() < 0.001);
    // A source the origin vouched for is still held to it, as to the HTTP rules.
    pipe.observe_return(
        &Flow {
            src_ip: "203.0.113.20".into(),
            dst_ip: "192.0.2.9".into(),
            proto: "tcp".into(),
            pps: 1,
            ..Default::default()
        },
        T0,
    );
    let d = pipe.decide(
        &request("192.0.2.9", "GET /players.json HTTP/1.1\r\n\r\n"),
        T0,
    );
    assert_eq!(d.action, "drop");
    let stats = pipe.stats(T0);
    assert_eq!(
        (
            &stats["ml"]["http_ready"],
            &stats["ml"]["http_scored"],
            &stats["ml"]["http_drops"]
        ),
        (&json!(true), &json!(3), &json!(2))
    );
    assert_eq!(stats["games"][0]["http_dropped"], 2);
    // A zc permit rule comes after the game filters, so it spares nothing they judge.
    let mut program = http_server(vec![path("/players.json", 10)], GameHttp::default(), false);
    program.zc = vec![ZCEntry {
        rule_id: "allow".into(),
        action: "permit".into(),
        r#match: Match {
            dport: 30120,
            ..Default::default()
        },
        ..Default::default()
    }];
    pipe.load(program);
    let d = pipe.decide(
        &request("192.0.2.5", "GET /players.json HTTP/1.1\r\n\r\n"),
        T0,
    );
    assert_eq!(d.action, "drop");
    assert!(d.reason.contains("by the request model"), "{}", d.reason);
    // Under scope inspect the HTTP rules judge alone.
    pipe.load(with_ml(
        http_server(vec![path("/players.json", 10)], GameHttp::default(), false),
        "inspect",
        "",
    ));
    let d = pipe.decide(
        &request("192.0.2.3", "GET /players.json HTTP/1.1\r\n\r\n"),
        T0,
    );
    assert_ne!(d.action, "drop");
    assert_eq!(pipe.stats(T0)["ml"]["http_scored"], 4);
    // A filter that only observes lets through what the model would drop, and counts it.
    let mut program = http_server(vec![path("/players.json", 10)], GameHttp::default(), false);
    program.games[0].observe = true;
    pipe.load(program);
    let d = pipe.decide(
        &request("192.0.2.4", "GET /players.json HTTP/1.1\r\n\r\n"),
        T0,
    );
    assert_ne!(d.action, "drop");
    assert_eq!(pipe.stats(T0)["ml"]["http_observed"], 1);
}

/// A customer's tunnel held on this node and mitigated on demand.
fn on_demand(attack_pps: i64, attack_kbps: i64) -> NodeTunnel {
    NodeTunnel {
        id: "northwind".into(),
        prefixes: vec!["203.0.113.0/24".into()],
        mitigation: "on_demand".into(),
        attack_pps,
        attack_kbps,
        ..Default::default()
    }
}
/// A node that drops DNS reflected at the customer, holding these tunnels.
fn reflection_guard(tunnels: Vec<NodeTunnel>) -> Program {
    Program {
        prefixes: vec!["203.0.113.0/24".into()],
        asic: vec![ACLEntry {
            rule_id: "dns".into(),
            action: "drop".into(),
            r#match: Match {
                sport: 53,
                ..Default::default()
            },
            ..Default::default()
        }],
        tunnels,
        ..Default::default()
    }
}
fn reflected(pps: i64) -> Flow {
    Flow {
        src_ip: "198.51.100.53".into(),
        dst_ip: "203.0.113.10".into(),
        proto: "udp".into(),
        sport: 53,
        dport: 40000,
        pps,
        ..Default::default()
    }
}
#[test]
fn an_on_demand_tunnel_is_only_watched_until_its_traffic_reaches_a_threshold() {
    let mut pipe = Pipeline::new(reflection_guard(vec![on_demand(1000, 1_000_000)]));
    // Under its thresholds nothing is filtered, not even what a rule would drop.
    let d = pipe.decide(&reflected(10), T0);
    assert_eq!(
        (d.action.as_str(), d.reason.as_str()),
        (
            "permit",
            "watching only: tunnel northwind is under its attack thresholds"
        )
    );
    // 990 pps more within the second makes 1,000, and mitigation starts with that flow.
    let d = pipe.decide(&reflected(990), T0 + 100);
    assert_eq!((d.action.as_str(), d.rule_id.as_str()), ("drop", "dns"));
    // It holds after the flood eases, while the rules do their work.
    assert_eq!(pipe.decide(&reflected(1), T0 + 60_000).action, "drop");
    let row = pipe.stats(T0 + 60_000)["mitigation"][0].clone();
    assert_eq!(
        (
            &row["active"],
            &row["since"],
            &row["mitigations"],
            &row["unfiltered"]
        ),
        (
            &json!(true),
            &json!("2026-01-01T00:00:00.100Z"),
            &json!(1),
            &json!(1)
        )
    );
    // Five minutes under both thresholds ends it.
    let quiet = T0 + 100 + MITIGATION_HOLD + 1;
    assert_eq!(pipe.decide(&reflected(1), quiet).action, "permit");
    let row = pipe.stats(quiet)["mitigation"][0].clone();
    assert_eq!(
        (&row["active"], &row["since"]),
        (&json!(false), &Value::Null)
    );
}
#[test]
fn either_threshold_starts_mitigation_and_a_flow_without_a_bit_rate_counts_its_bytes() {
    // 10 Mbit/s, and a packet rate nothing here reaches.
    let tunnel = on_demand(1_000_000, 10_000);
    let mut pipe = Pipeline::new(reflection_guard(vec![tunnel.clone()]));
    // A record that carries its bit rate is taken at its word.
    let d = pipe.decide(
        &Flow {
            bps: 20_000_000,
            ..reflected(10)
        },
        T0,
    );
    assert_eq!(d.action, "drop");
    // One that does not is counted by its headers and payload: 800 pps of 1,400-byte UDP
    // payloads is 9.1 Mbit/s, and 900 is 10.3.
    let mut pipe = Pipeline::new(reflection_guard(vec![tunnel]));
    let big = Flow {
        payload: vec![0; 1400],
        has_payload: true,
        ..reflected(800)
    };
    assert_eq!(pipe.decide(&big, T0).action, "permit");
    assert_eq!(
        pipe.decide(&Flow { pps: 100, ..big }, T0 + 10).action,
        "drop"
    );
}
#[test]
fn mitigation_carries_over_a_reload_and_ends_with_the_tunnel() {
    let program = reflection_guard(vec![on_demand(1000, 1_000_000)]);
    let mut pipe = Pipeline::new(program.clone());
    assert_eq!(pipe.decide(&reflected(5000), T0).action, "drop");
    // The fabric recompiles all the time, and a tunnel being mitigated stays mitigated.
    pipe.load(program);
    assert_eq!(pipe.decide(&reflected(1), T0 + 1000).action, "drop");
    // A node helping another with this customer holds no tunnel for it, so it filters from the
    // first packet and watches nothing.
    let mut helper = Pipeline::new(reflection_guard(vec![]));
    assert_eq!(helper.decide(&reflected(1), T0).action, "drop");
    assert!(helper.stats(T0)["mitigation"].is_null());
    // Taken off on-demand mitigation, the tunnel is filtered always.
    pipe.load(reflection_guard(vec![]));
    assert_eq!(
        pipe.decide(&reflected(1), T0 + 2 * MITIGATION_HOLD).action,
        "drop"
    );
}
#[test]
fn players_who_connect_while_a_tunnel_is_idle_are_known_when_its_mitigation_starts() {
    let mut program = gated(vec![game("game", 19132, "raknet")], "handshake");
    program.tunnels = vec![on_demand(1000, 1_000_000)];
    let mut pipe = Pipeline::new(program);
    // A player connects while the tunnel is idle, when anything would pass.
    pipe.decide(&packet("192.0.2.1", 19132, &[0x05]), T0);
    pipe.decide(&packet("192.0.2.1", 19132, &[0x07]), T0 + 1);
    let stranger = packet("192.0.2.2", 19132, &[0x84, 0, 0]);
    assert_eq!(pipe.decide(&stranger, T0 + 2).action, "permit");
    // A flood starts mitigation...
    let flood = Flow {
        pps: 5000,
        ..packet("198.51.100.9", 19132, &[0x84, 0, 0])
    };
    assert_eq!(pipe.decide(&flood, T0 + 3).action, "drop");
    // ...and the player plays on, while gameplay from a source that never connected is dropped.
    let playing = packet("192.0.2.1", 19132, &[0x84, 0, 0]);
    assert_eq!(pipe.decide(&playing, T0 + 4).action, "permit");
    assert_eq!(pipe.decide(&stranger, T0 + 5).action, "drop");
}
#[test]
fn a_game_filters_http_rules_hold_while_its_tunnel_is_idle() {
    let allow_list = GameHttp {
        default: "drop".into(),
        ..Default::default()
    };
    let mut program = http_server(vec![path("/players.json", 1)], allow_list, false);
    program.tunnels = vec![on_demand(1000, 1_000_000)];
    let mut pipe = Pipeline::new(program);
    let watching = "watching only: tunnel northwind is under its attack thresholds";
    let d = pipe.decide(&request("192.0.2.1", &get("/players.json")), T0);
    assert_eq!((d.action.as_str(), d.reason.as_str()), ("permit", watching));
    // A second request inside the second is over the path's rate, idle tunnel or not.
    let d = pipe.decide(&request("192.0.2.1", &get("/players.json")), T0 + 1);
    assert_eq!(d.action, "drop");
    assert!(
        d.reason
            .ends_with("more than 1 request a second to this path from this source"),
        "{}",
        d.reason
    );
    assert_eq!(
        pipe.decide(&request("192.0.2.2", &get("/admin")), T0 + 2)
            .action,
        "drop"
    );
    // So does the request model behind them.
    pipe.model = ml::Model {
        http: Some(Box::new(client_model())),
        ..Default::default()
    };
    let d = pipe.decide(
        &request("192.0.2.3", "GET /players.json HTTP/1.1\r\n\r\n"),
        T0 + 3,
    );
    assert!(d.reason.contains("by the request model"), "{}", d.reason);
    // Everything else still waits for an attack: a packet the game filter would drop passes.
    let mut runt = packet("192.0.2.4", 30120, &[1]);
    runt.dst_ip = "203.0.113.20".into();
    assert_eq!(pipe.decide(&runt, T0 + 4).reason, watching);
    let stats = pipe.stats(T0 + 4);
    assert_eq!(stats["games"][0]["http_dropped"], 3);
    let row = &stats["mitigation"][0];
    assert_eq!(
        (&row["active"], &row["unfiltered"]),
        (&json!(false), &json!(1))
    );
}
#[test]
fn each_wave_of_an_attack_holds_mitigation_twice_as_long_as_the_last() {
    let mut pipe = Pipeline::new(reflection_guard(vec![on_demand(1000, 1_000_000)]));
    // An attacker that has learned how long mitigation lasts starts each wave a second after the
    // last one's mitigation ends.
    let mut at = T0;
    for (wave, hold) in [
        (1, 300),
        (2, 600),
        (3, 1200),
        (4, 2400),
        (5, 3600),
        (6, 3600),
    ] {
        assert_eq!(
            pipe.decide(&reflected(1000), at).action,
            "drop",
            "wave {wave}"
        );
        let row = pipe.stats(at)["mitigation"][0].clone();
        assert_eq!(
            (&row["wave"], &row["hold_seconds"]),
            (&json!(wave), &json!(hold)),
            "wave {wave}"
        );
        // Each wave's mitigation lasts its own hold after the traffic was last at a threshold...
        assert_eq!(pipe.decide(&reflected(1), at + hold * 1000).action, "drop");
        // ...and not a moment longer.
        at += hold * 1000 + 1;
        assert_eq!(
            pipe.decide(&reflected(1), at).action,
            "permit",
            "wave {wave}"
        );
        at += 1000;
    }
    assert_eq!(MITIGATION_HOLD_MAX, 12 * MITIGATION_HOLD);
    // After an hour without one, the next mitigation is a first wave again.
    at += CAMPAIGN;
    pipe.decide(&reflected(1000), at);
    let row = pipe.stats(at)["mitigation"][0].clone();
    assert_eq!(
        (&row["wave"], &row["hold_seconds"], &row["mitigations"]),
        (&json!(1), &json!(300), &json!(7))
    );
}
/// Has the origin answer a client enough times to confirm it, which verifies it.
fn answered(pipe: &mut Pipeline, client: &str, at: i64) {
    let reply = Flow {
        src_ip: "203.0.113.20".into(),
        dst_ip: client.into(),
        proto: "tcp".into(),
        pps: 4,
        ..Default::default()
    };
    for tick in 0..3 {
        pipe.observe_return(&reply, at + tick * 250);
    }
}
#[test]
fn a_flood_spread_thin_spends_a_budget_that_verified_sources_are_spared() {
    let players = GameHttpPath {
        rate_total: 50,
        ..path("/players.json", 2)
    };
    let mut pipe = Pipeline::new(http_server(vec![players], GameHttp::default(), false));
    answered(&mut pipe, "192.0.2.9", T0);
    let t = T0 + 1000;
    // Fifty sources, each well under its own rate, take the path to its budget.
    for i in 0..50 {
        let d = pipe.decide(
            &request(&format!("198.51.100.{i}"), &get("/players.json")),
            t,
        );
        assert_eq!(d.action, "permit", "{}", d.reason);
    }
    // Past it, a source the fabric has not verified is turned away...
    let d = pipe.decide(&request("198.51.100.77", &get("/players.json")), t + 1);
    assert_eq!(
        (d.action.as_str(), d.reason.as_str()),
        (
            "drop",
            "game filter http: GET /players.json: more than 50 requests a second to this path from everyone, and this source is not verified"
        )
    );
    // ...while one the origin has been answering gets through.
    let d = pipe.decide(&request("192.0.2.9", &get("/players.json")), t + 2);
    assert_eq!(d.action, "permit", "{}", d.reason);
    // A path without a budget is not held to this one.
    let d = pipe.decide(&request("198.51.100.78", &get("/info.json")), t + 3);
    assert_eq!(d.action, "permit", "{}", d.reason);
    // And once the flood has passed, strangers are back.
    let d = pipe.decide(&request("198.51.100.79", &get("/players.json")), t + 1001);
    assert_eq!(d.action, "permit", "{}", d.reason);
    let stats = pipe.stats(t + 1001);
    let row = &stats["games"][0];
    assert_eq!(
        (
            &row["http_dropped"],
            &row["http_rate_limited"],
            &row["http_budget_dropped"]
        ),
        (&json!(1), &json!(1), &json!(1))
    );
    // Being turned away for what everyone else sent is no strike against the source.
    assert_eq!(stats["reputation"]["strikes"], 0);
}
/// A request model that goes by rate alone, as rate_model does for flows.
fn request_rate_model() -> ml::Model {
    let mut weights = vec![0.0; ml::REQUEST_FEATURES];
    weights[0] = 12.0;
    ml::Model {
        weights,
        bias: -(1001f64).ln(),
        threshold: 0.5,
        ready: true,
        ..Default::default()
    }
}
#[test]
fn traffic_tuned_to_score_just_under_a_threshold_tightens_it_for_its_target() {
    let mut program = with_ml(
        http_server(vec![], GameHttp::default(), false),
        "all",
        "enforce",
    );
    program.prefixes.push("198.18.0.0/24".into());
    let mut pipe = Pipeline::new(program);
    // Models whose training showed they stay clean of ordinary traffic two steps down.
    pipe.model = ml::Model {
        http: Some(Box::new(ml::Model {
            max_cut: 0.2,
            ..request_rate_model()
        })),
        max_cut: 0.2,
        ..rate_model()
    };
    // Ordinary traffic scores far under the threshold.
    for i in 0..100 {
        let d = pipe.decide(&at_rate(&format!("192.0.2.{i}"), 9000, 10), T0);
        assert_eq!(d.reason, "PF_RING ZC ml pass");
    }
    // An attacker changes its flood until it gets through: at 900 pps it scores 0.47, under the
    // 0.50 the model drops at. Once near misses are a quarter of what the model scored for the
    // prefix, it is being probed.
    for i in 0..34 {
        let d = pipe.decide(&at_rate(&format!("198.51.100.{i}"), 9000, 900), T0 + 1);
        assert_eq!(d.action, "permit", "flow {i}: {}", d.reason);
    }
    let d = pipe.decide(&at_rate("198.51.100.200", 9000, 900), T0 + 2);
    assert_eq!(
        (d.action.as_str(), d.reason.as_str()),
        (
            "drop",
            "PF_RING ZC ml score 0.47, over the 0.40 this target is held to while it is being probed"
        )
    );
    // The request model is held a step lower for the prefix too.
    let flood = Flow {
        pps: 900,
        ..request("198.51.100.201", &get("/players.json"))
    };
    assert_eq!(
        pipe.decide(&flood, T0 + 3).reason,
        "game filter http: GET /players.json: scored 0.47 by the request model, which drops at 0.40 while this target is being probed"
    );
    // Another customer's prefix is not, and ordinary traffic still passes.
    let elsewhere = Flow {
        dst_ip: "198.18.0.10".into(),
        ..at_rate("198.51.100.202", 9000, 900)
    };
    assert_eq!(pipe.decide(&elsewhere, T0 + 4).reason, "PF_RING ZC ml pass");
    assert_eq!(
        pipe.decide(&at_rate("192.0.2.1", 9000, 10), T0 + 5).action,
        "permit"
    );
    let stats = pipe.stats(T0 + 5);
    let cut = |stats: &Value, prefix: &str| {
        stats["prefixes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["prefix"] == prefix)
            .unwrap()["ml_cut"]
            .clone()
    };
    assert_eq!(cut(&stats, "203.0.113.0/24"), json!(0.1));
    assert_eq!(cut(&stats, "198.18.0.0/24"), json!(0.0));
    assert_eq!(
        (&stats["ml"]["near_misses"], &stats["ml"]["tightened"]),
        (&json!(35), &json!(1))
    );
    // Tuned again, to 600 pps and a score of 0.38, the flood lowers the threshold another step.
    for i in 0..20 {
        let d = pipe.decide(&at_rate(&format!("198.51.101.{i}"), 9000, 600), T0 + 10);
        assert_eq!(d.action, "permit", "flow {i}: {}", d.reason);
    }
    let d = pipe.decide(&at_rate("198.51.101.200", 9000, 600), T0 + 11);
    assert_eq!(
        d.reason,
        "PF_RING ZC ml score 0.38, over the 0.30 this target is held to while it is being probed"
    );
    // That is as far as it goes: probing under it holds the thresholds where they are.
    for i in 0..40 {
        pipe.decide(&at_rate(&format!("198.51.102.{i}"), 9000, 400), T0 + 20);
    }
    let stats = pipe.stats(T0 + 20);
    assert_eq!(cut(&stats, "203.0.113.0/24"), json!(0.2));
    assert_eq!(stats["ml"]["tightened"], 2);
    // Each step lapses five minutes after the probing was last seen.
    assert_eq!(
        cut(&pipe.stats(T0 + 20 + PROBE_HOLD + 1), "203.0.113.0/24"),
        json!(0.1)
    );
    assert_eq!(
        cut(&pipe.stats(T0 + 20 + 2 * PROBE_HOLD + 1), "203.0.113.0/24"),
        json!(0.0)
    );
}
#[test]
fn a_policy_can_keep_the_thresholds_where_they_are() {
    let mut program = with_ml(
        http_server(vec![], GameHttp::default(), false),
        "all",
        "enforce",
    );
    program.ml.as_mut().unwrap().probing = "ignore".into();
    let mut pipe = Pipeline::new(program);
    pipe.model = rate_model();
    for i in 0..40 {
        let d = pipe.decide(&at_rate(&format!("198.51.100.{i}"), 9000, 900), T0);
        assert_eq!(d.action, "permit", "flow {i}: {}", d.reason);
    }
    let stats = pipe.stats(T0);
    assert_eq!(
        (
            &stats["ml"]["probing"],
            &stats["ml"]["near_misses"],
            &stats["ml"]["tightened"],
            &stats["prefixes"][0]["ml_cut"]
        ),
        (&json!("ignore"), &json!(40), &json!(0), &json!(0.0))
    );
}
#[test]
fn a_model_tightens_no_further_than_its_training_showed_it_could() {
    let mut pipe = Pipeline::new(with_ml(
        http_server(vec![], GameHttp::default(), false),
        "all",
        "enforce",
    ));
    // A flow model training showed was safe a step under its threshold, and a request model,
    // fitted before that was measured, that scores a request at 400 pps 0.44.
    pipe.model = ml::Model {
        http: Some(Box::new(ml::Model {
            bias: -(501f64).ln(),
            ..request_rate_model()
        })),
        max_cut: 0.1,
        ..rate_model()
    };
    for i in 0..20 {
        pipe.decide(&at_rate(&format!("198.51.100.{i}"), 9000, 900), T0);
    }
    // The prefix is being probed, so the flow model drops a step under its threshold...
    let d = pipe.decide(&at_rate("198.51.100.100", 9000, 900), T0 + 1);
    assert_eq!(
        d.reason,
        "PF_RING ZC ml score 0.47, over the 0.40 this target is held to while it is being probed"
    );
    // ...and the request model keeps its own.
    let asked = Flow {
        pps: 400,
        ..request("198.51.100.101", &get("/players.json"))
    };
    let d = pipe.decide(&asked, T0 + 2);
    assert_eq!(d.action, "permit", "{}", d.reason);
    // Probing under that step takes the prefix a step further, and the flow model no further.
    for i in 0..20 {
        pipe.decide(&at_rate(&format!("198.51.101.{i}"), 9000, 600), T0 + 3);
    }
    assert_eq!(pipe.stats(T0 + 4)["prefixes"][0]["ml_cut"], json!(0.2));
    let d = pipe.decide(&at_rate("198.51.101.100", 9000, 600), T0 + 4);
    assert_eq!(d.reason, "PF_RING ZC ml pass");
}
#[test]
fn a_boxed_source_the_origin_keeps_answering_is_freed() {
    let mut pipe = Pipeline::new(http_server(
        vec![path("/players.json", 1)],
        GameHttp::default(),
        true,
    ));
    // Four requests over its rate inside thirty seconds, and a source is boxed...
    for i in 0..5 {
        pipe.decide(&request("192.0.2.9", &get("/players.json")), T0 + i);
    }
    let mut play = request("192.0.2.9", "abcd");
    play.proto = "udp".into();
    assert_eq!(
        pipe.decide(&play, T0 + 10).reason,
        "source is in the penalty box"
    );
    // ...until the server it was talking to is seen still answering it: a real client.
    answered(&mut pipe, "192.0.2.9", T0 + 20);
    let d = pipe.decide(&play, T0 + 600);
    assert_eq!(d.action, "permit", "{}", d.reason);
    let stats = pipe.stats(T0 + 600);
    assert_eq!(
        (
            &stats["reputation"]["freed"],
            &stats["reputation"]["penalised"]
        ),
        (&json!(1), &json!(0))
    );
}
#[test]
fn only_an_address_that_answers_for_itself_leaves_the_box() {
    let mut r = Reputation::default();
    r.boxing = true;
    for i in 0..4 {
        r.strike("192.0.2.9", T0 + i);
    }
    assert_eq!(r.check("192.0.2.9", T0 + 10), 2);
    // A handshake can be completed blind, by anyone claiming the address.
    r.promote("192.0.2.9", 1, T0 + 20);
    assert_eq!(r.check("192.0.2.9", T0 + 30), 2);
    // Return traffic and an answered challenge cannot be.
    r.promote("192.0.2.9", 2, T0 + 40);
    assert_eq!(r.check("192.0.2.9", T0 + 50), 1);
    assert_eq!(r.stats(T0 + 50)["freed"], 1);
}
/// A RakNet server whose players take the short path once they have connected, with an allow
/// list for one source and a meter on everything else.
fn allow_listed(meter_pps: i64) -> Program {
    let mut program = gated(vec![game("game", 19132, "raknet")], "handshake");
    program.asic = vec![ACLEntry {
        rule_id: "partner".into(),
        action: "permit".into(),
        r#match: Match {
            src_cidr: "192.0.2.7/32".into(),
            ..Default::default()
        },
        ..Default::default()
    }];
    program.fpga = vec![pathfinder::model::FPGAEntry {
        rule_id: "meter".into(),
        action: "rate_limit".into(),
        meter_pps,
        ..Default::default()
    }];
    program
}
#[test]
fn a_permit_ends_evaluation_for_a_verified_source_as_for_anyone() {
    let mut unlisted = allow_listed(100);
    unlisted.asic.clear();
    let mut pipe = Pipeline::new(unlisted);
    for (src, at) in [("192.0.2.7", T0), ("192.0.2.8", T0 + 1)] {
        pipe.decide(&packet(src, 19132, &[0x05]), at);
        pipe.decide(&packet(src, 19132, &[0x07]), at + 1);
    }
    // Both connected and are on the short path, which meters a verified source per source, when
    // the operator allow-lists one of them...
    pipe.load(allow_listed(100));
    let busy = |src: &str| Flow {
        pps: 1000,
        ..packet(src, 19132, &[0x84, 0, 0])
    };
    let d = pipe.decide(&busy("192.0.2.8"), T0 + 10);
    assert_eq!(d.reason, "FPGA meter 100 pps exceeded");
    // ...whose permit ends evaluation, trust or no trust.
    let d = pipe.decide(&busy("192.0.2.7"), T0 + 11);
    assert_eq!(
        (d.action.as_str(), d.reason.as_str()),
        ("permit", "TCAM ACL permit")
    );
}
#[test]
fn a_reload_keeps_what_each_source_has_spent_of_its_meters() {
    let program = allow_listed(100);
    let mut pipe = Pipeline::new(program.clone());
    pipe.decide(&packet("192.0.2.8", 19132, &[0x05]), T0);
    pipe.decide(&packet("192.0.2.8", 19132, &[0x07]), T0 + 1);
    let half = Flow {
        pps: 80,
        ..packet("192.0.2.8", 19132, &[0x84, 0, 0])
    };
    assert_eq!(pipe.decide(&half, T0 + 10).action, "permit");
    // The fabric recompiles in the same second, and the second half is still over the meter.
    pipe.load(program);
    let d = pipe.decide(&half, T0 + 20);
    assert_eq!(d.reason, "FPGA meter 100 pps exceeded");
}
#[test]
fn a_permit_written_for_a_boxed_source_takes_effect_at_once() {
    let mut program = allow_listed(1_000_000);
    program.asic.clear();
    let mut pipe = Pipeline::new(program.clone());
    for i in 0..4 {
        pipe.decide(&packet("192.0.2.7", 19132, &[0x84]), T0 + i);
    }
    assert_eq!(
        pipe.decide(&packet("192.0.2.7", 19132, &[0x84]), T0 + 10)
            .reason,
        "source is in the penalty box"
    );
    // The operator allow-lists it, and the box lets it go to the rule.
    pipe.load(allow_listed(1_000_000));
    let d = pipe.decide(&packet("192.0.2.7", 19132, &[0x84]), T0 + 20);
    assert_eq!(
        (d.action.as_str(), d.reason.as_str()),
        ("permit", "TCAM ACL permit")
    );
    assert_eq!(pipe.stats(T0 + 20)["reputation"]["boxed"], 1);
}
#[test]
fn a_filter_that_an_earlier_one_takes_every_packet_from_is_refused() {
    let filter = |id: &str, dst: &str, dport: i64| GameFilter {
        id: id.into(),
        dst_cidr: dst.into(),
        proto: "udp".into(),
        dport,
        profile: "raknet".into(),
        ..Default::default()
    };
    let policy = |games: Vec<GameFilter>| pathfinder::model::Policy {
        name: "p".into(),
        protected: vec!["203.0.113.0/24".into()],
        games,
        ..Default::default()
    };
    let wide = filter("wide", "203.0.113.0/24", 0);
    let narrow = filter("narrow", "203.0.113.10/32", 19132);
    // A whole prefix on every port takes what one address on one port would have judged...
    let e = validation::policy(&policy(vec![wide.clone(), narrow.clone()])).unwrap_err();
    assert!(
        e.contains("games[1] (narrow): games[0] (wide) is bound to every packet it is"),
        "{e}"
    );
    // ...though a node handed such a program, compiled before the API refused one, still judges
    // with the filter that takes the packets rather than with none...
    let mut pipe = Pipeline::new(gated(vec![wide.clone(), narrow.clone()], "handshake"));
    let d = pipe.decide(&packet("192.0.2.1", 19132, &[0x84, 0, 0]), T0);
    assert_eq!((d.action.as_str(), d.filter.as_str()), ("drop", "wide"));
    // ...while the other way round each has its own: the address's port, then everything else.
    validation::policy(&policy(vec![narrow, wide])).unwrap();
    // HTTP rules on every port of a prefix leave none for rules on one port of an address in it.
    let http = |id: &str, dst: &str, ports: Vec<i64>| GameFilter {
        id: id.into(),
        dst_cidr: dst.into(),
        http: Some(GameHttp {
            ports,
            ..Default::default()
        }),
        ..Default::default()
    };
    let e = validation::policy(&policy(vec![
        http("site", "203.0.113.0/24", vec![]),
        http("api", "203.0.113.20/32", vec![8080]),
    ]))
    .unwrap_err();
    assert!(
        e.contains("the HTTP rules of games[0] (site) cover every request"),
        "{e}"
    );
    validation::policy(&policy(vec![
        http("site", "203.0.113.0/24", vec![80]),
        http("api", "203.0.113.20/32", vec![8080]),
    ]))
    .unwrap();
}
