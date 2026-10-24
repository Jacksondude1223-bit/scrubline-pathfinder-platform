use pathfinder::{
    ml,
    model::{
        Flow, GameFilter, GameHttp, GameHttpPath, GameSignature, Match, Program, ReputationPolicy,
        ZCEntry,
    },
    pipeline::Pipeline,
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
/// Stats as the Go datapath reported them: the counters for HTTP rules and the surge rate, which
/// it never had, are left out of the comparison.
fn go_shape(mut stats: Value) -> Value {
    let top = stats.as_object_mut().unwrap();
    top.remove("game_http_windows");
    top.remove("game_http_windows_max");
    top.remove("surge_pps");
    for row in stats["games"].as_array_mut().into_iter().flatten() {
        let row = row.as_object_mut().unwrap();
        for key in [
            "http_requests",
            "http_dropped",
            "http_rate_limited",
            "http_other",
        ] {
            row.remove(key);
        }
    }
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
