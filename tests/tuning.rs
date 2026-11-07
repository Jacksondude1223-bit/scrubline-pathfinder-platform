//! Every setting the catalog lists reaches the node and changes what it does: the guards' own,
//! per profile for the addresses a profile holds, the rules' new match fields and lists, the
//! shape action, the game filters' sessions and HTTP limits. The catalog itself is served by the
//! API, a policy's settings resolved as its nodes resolve them, and a mistyped setting turned
//! down rather than passed over.
use base64::{engine::general_purpose::STANDARD, Engine};
use pathfinder::{
    api::{Api, Shared},
    compiler,
    model::*,
    pipeline::Pipeline,
    store::Store,
    tuning::{self, Kind, SETTINGS},
    validation,
};
use serde_json::{json, Value};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

mod common;

const T0: i64 = 1767225600000;
const OP: &str = "test-operator";

fn flow(v: Value) -> Flow {
    serde_json::from_value(v).unwrap()
}
fn syn(src: &str, dst: &str, pps: i64) -> Flow {
    flow(
        json!({"src_ip":src,"dst_ip":dst,"proto":"tcp","sport":40000,"dport":443,
        "flags":"syn","pps":pps}),
    )
}
fn ping(src: &str, dst: &str, pps: i64) -> Flow {
    flow(json!({"src_ip":src,"dst_ip":dst,"proto":"icmp","icmp_type":8,"icmp_code":0,"pps":pps}))
}
fn udp(src: &str, dst: &str, sport: i64, dport: i64, pps: i64) -> Flow {
    flow(json!({"src_ip":src,"dst_ip":dst,"proto":"udp","sport":sport,"dport":dport,"pps":pps}))
}
fn decided(pipe: &mut Pipeline, f: &Flow, at: i64) -> (String, String) {
    let d = pipe.decide(f, at);
    (
        d.action,
        if d.guard.is_empty() {
            d.rule_id
        } else {
            d.guard
        },
    )
}
fn drop(by: &str) -> (String, String) {
    ("drop".into(), by.into())
}
fn pass() -> (String, String) {
    ("permit".into(), String::new())
}
fn policy(v: Value) -> Policy {
    let mut base = json!({"id":"p","name":"p","protected":["203.0.113.0/24","2001:db8:100::/48"]});
    for (k, x) in v.as_object().unwrap() {
        base[k] = x.clone();
    }
    serde_json::from_value(base).unwrap()
}
/// The program a node is compiled from a policy, which validation passes.
fn program(p: &Policy) -> Program {
    validation::policy(p).unwrap_or_else(|e| panic!("{e}"));
    let nodes = vec![Node {
        id: "n1".into(),
        name: "buf-1".into(),
        region: "buf".into(),
        capacity_gbps: 10.0,
        advertise: "192.0.2.1:9091".into(),
        status: "ready".into(),
        ..Default::default()
    }];
    let plan = compiler::plan(p, &nodes, &Default::default(), &Default::default());
    compiler::compile(p, &nodes, &plan).remove("n1").unwrap()
}
fn pipeline(v: Value) -> Pipeline {
    Pipeline::new(program(&policy(v)))
}

#[test]
fn a_profile_holds_its_addresses_to_its_own_settings_and_judges_them_apart() {
    let mut pipe = pipeline(json!({
        "profiles": [
            {"name": "web", "prefixes": ["203.0.113.20/32"], "syn_flood": {"engage_pps": 20000}},
            {"name": "quiet", "prefixes": ["203.0.113.30/32"], "sensitivity": "low",
             "icmp": {"drop_types": [13]}}
        ]
    }));
    // The policy's threshold for the rest of the /24: 5,000 SYNs a second engages its guard.
    assert_eq!(
        decided(&mut pipe, &syn("100.64.0.1", "203.0.113.10", 5000), T0),
        drop("syn_flood")
    );
    // The busy site takes as many and more, judged by its own threshold, and the flood its
    // neighbours took holds no guard engaged for it.
    assert_eq!(
        decided(&mut pipe, &syn("100.64.0.2", "203.0.113.20", 15000), T0 + 1),
        pass()
    );
    assert_eq!(
        decided(&mut pipe, &syn("100.64.0.3", "203.0.113.20", 1), T0 + 2),
        pass()
    );
    assert_eq!(
        decided(&mut pipe, &syn("100.64.0.4", "203.0.113.10", 1), T0 + 2),
        drop("syn_flood")
    );
    // Past its own threshold, it engages too.
    assert_eq!(
        decided(&mut pipe, &syn("100.64.0.5", "203.0.113.20", 6000), T0 + 3),
        drop("syn_flood")
    );
    // A low sensitivity multiplies the thresholds the profile leaves unset by 16: a ping flood
    // the policy's own addresses are held to 1,000 a second of passes.
    let t = T0 + 10_000;
    assert_eq!(
        decided(&mut pipe, &ping("100.64.1.1", "203.0.113.11", 5000), t),
        drop("icmp")
    );
    assert_eq!(
        decided(&mut pipe, &ping("100.64.1.2", "203.0.113.30", 5000), t),
        pass()
    );
    // And the profile's own list of types it drops whatever their rate.
    let stamp = flow(
        json!({"src_ip":"100.64.1.3","dst_ip":"203.0.113.30","proto":"icmp",
        "icmp_type":13,"icmp_code":0,"pps":1}),
    );
    let d = pipe.decide(&stamp, t + 1);
    assert_eq!((d.action.as_str(), d.guard.as_str()), ("drop", "icmp"));
    assert_eq!(d.reason, "ICMP type 13, which the policy drops");
    let other = flow(
        json!({"src_ip":"100.64.1.3","dst_ip":"203.0.113.12","proto":"icmp",
        "icmp_type":13,"icmp_code":0,"pps":1}),
    );
    assert_eq!(decided(&mut pipe, &other, t + 2_000), pass());
}

#[test]
fn each_guard_takes_its_settings_from_the_policy() {
    // How long the SYN guard holds.
    let mut pipe = pipeline(json!({"syn_flood": {"hold_seconds": 5}}));
    assert_eq!(
        decided(&mut pipe, &syn("100.64.0.1", "203.0.113.10", 5000), T0),
        drop("syn_flood")
    );
    assert_eq!(
        decided(&mut pipe, &syn("100.64.0.2", "203.0.113.10", 1), T0 + 4_999),
        drop("syn_flood")
    );
    assert_eq!(
        decided(&mut pipe, &syn("100.64.0.3", "203.0.113.10", 1), T0 + 5_000),
        pass()
    );
    // Floods judged by the address rather than the /24 it sits in.
    let one_by_one: Vec<String> = (1..=4).map(|i| format!("198.51.100.{i}/32")).collect();
    let spread = |lengths: Value| {
        let mut pipe = pipeline(json!({"protected": one_by_one, "aggregation": lengths}));
        (1..=4)
            .map(|i| {
                decided(
                    &mut pipe,
                    &syn("100.64.2.1", &format!("198.51.100.{i}"), 900),
                    T0,
                )
                .0
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(spread(json!({})).last().unwrap(), "drop");
    assert!(spread(json!({"v4": 32})).iter().all(|a| a == "permit"));
    // Whose fragments are dropped.
    let piece = |proto: &str| {
        flow(
            json!({"src_ip":"100.64.3.1","dst_ip":"203.0.113.10","proto":proto,"dport":9000,
            "pps":1,"fragment":true,"packet": STANDARD.encode(fragment(proto))}),
        )
    };
    let mut pipe = pipeline(json!({"fragments": {"protocols": ["udp"]}}));
    assert_eq!(decided(&mut pipe, &piece("udp"), T0), drop("fragment"));
    assert_eq!(decided(&mut pipe, &piece("tcp"), T0), pass());
    let mut pipe = pipeline(json!({}));
    assert_eq!(decided(&mut pipe, &piece("udp"), T0), pass());
    assert_eq!(decided(&mut pipe, &piece("tcp"), T0), drop("fragment"));
    // How a reflection vector's unasked answers are judged, and a vector of the operator's own.
    let answer = udp("100.64.4.1", "203.0.113.10", 53, 40000, 1);
    let mut pipe = pipeline(json!({}));
    assert_eq!(decided(&mut pipe, &answer, T0), pass());
    let mut pipe = pipeline(json!({"reflection": {"judge": {"dns": "always"},
        "custom": [{"name": "arms", "port": 3283}]}}));
    let d = pipe.decide(&answer, T0);
    assert_eq!(
        (d.action.as_str(), d.reason.as_str()),
        (
            "drop",
            "DNS reflection: UDP from port 53 that the server never asked for"
        )
    );
    let d = pipe.decide(&udp("100.64.4.2", "203.0.113.10", 3283, 40000, 1), T0);
    assert_eq!(d.action, "drop", "{}", d.reason);
    assert!(d.reason.contains("arms"), "{}", d.reason);
    let st = pipe.stats(T0 + 1);
    assert!(
        st["reflection"]["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["vector"] == "arms" && v["dropped"] == 1),
        "{}",
        st["reflection"]
    );
    // A single check of the crafted-packet checks turned off.
    let land = flow(json!({"pps":1,"packet": STANDARD.encode(land())}));
    let mut pipe = pipeline(json!({}));
    assert_eq!(decided(&mut pipe, &land, T0).0, "drop");
    let mut pipe = pipeline(json!({"crafted": {"checks": {"land": "off"}}}));
    assert_eq!(decided(&mut pipe, &land, T0).0, "permit");
    // The penalty box: how many strikes, and how long the sentence.
    let mut pipe = pipeline(json!({"reputation": {"penalty_box": true, "strikes": 2,
        "penalty_seconds": [5]}}));
    pipe.reputation.strike("100.64.5.1", T0);
    pipe.reputation.strike("100.64.5.1", T0 + 1);
    let player = udp("100.64.5.1", "203.0.113.10", 50000, 19132, 1);
    let d = pipe.decide(&player, T0 + 2);
    assert_eq!(d.action, "drop", "{}", d.reason);
    assert_eq!(decided(&mut pipe, &player, T0 + 1 + 5_000), pass());
}

/// An IPv4 packet with the more-fragments bit set, carrying the start of a datagram of `proto`.
fn fragment(proto: &str) -> Vec<u8> {
    let (number, l4): (u8, Vec<u8>) = match proto {
        "tcp" => (6, {
            let mut t = vec![
                0x9c, 0x40, 0x23, 0x28, 0, 0, 0, 1, 0, 0, 0, 1, 0x50, 0x10, 0xff, 0xff,
            ];
            t.extend([0, 0, 0, 0]);
            // Every fragment but the last is a multiple of 8 bytes.
            t.extend([0x41; 1004]);
            t
        }),
        _ => (17, {
            let mut u = vec![0x9c, 0x40, 0x23, 0x28, 0x03, 0xf0, 0, 0];
            u.extend([0x41; 1000]);
            u
        }),
    };
    ipv4([100, 64, 3, 1], [203, 0, 113, 10], number, &l4, 0x2000)
}
/// A SYN from the server's own address and port to itself: LAND.
fn land() -> Vec<u8> {
    let mut t = vec![
        0x01, 0xbb, 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff,
    ];
    t.extend([0, 0, 0, 0]);
    ipv4([203, 0, 113, 10], [203, 0, 113, 10], 6, &t, 0)
}
fn ipv4(src: [u8; 4], dst: [u8; 4], proto: u8, l4: &[u8], frag: u16) -> Vec<u8> {
    let mut p = vec![0x45, 0];
    p.extend((20 + l4.len() as u16).to_be_bytes());
    p.extend([0x12, 0x34]);
    p.extend(frag.to_be_bytes());
    p.extend([64, proto, 0, 0]);
    p.extend(src);
    p.extend(dst);
    p.extend(l4);
    let mut s: u32 = p[..20]
        .chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], c[1]])))
        .sum();
    while s > 0xffff {
        s = (s & 0xffff) + (s >> 16);
    }
    p[10..12].copy_from_slice(&(!(s as u16)).to_be_bytes());
    p
}

#[test]
fn rules_match_on_ranges_lengths_ttls_icmp_fragments_payloads_and_lists() {
    let rule = |id: &str, stage: &str, m: Value| json!({"id": id, "stage": stage, "action": "drop", "match": m});
    let p = policy(json!({
        "lists": {"bad": ["100.64.0.0/16"], "servers": ["203.0.113.50/32", "2001:db8:100::50/128"]},
        "rules": [
            rule("ports", "asic", json!({"proto": "udp", "dport": 27015, "dport_to": 27030})),
            rule("sources", "asic", json!({"proto": "udp", "dport": 1000, "sport": 1000, "sport_to": 1010})),
            rule("long", "asic", json!({"proto": "udp", "dport": 2000, "length_min": 1000})),
            rule("close", "asic", json!({"proto": "udp", "dport": 3000, "ttl_max": 5})),
            rule("stamps", "asic", json!({"proto": "icmp", "icmp_type": 13})),
            rule("pieces", "fpga", json!({"proto": "udp", "dport": 4000, "fragment": "yes"})),
            rule("magic", "zc", json!({"proto": "udp", "dport": 5000, "payload_hex": "beef", "payload_offset": 2})),
            rule("banner", "zc", json!({"proto": "udp", "dport": 6000, "payload_contains": "cafe"})),
            rule("listed", "asic", json!({"proto": "udp", "dport": 7000, "src_list": "bad"})),
            rule("ssh", "asic", json!({"proto": "tcp", "dport": 22, "dst_list": "servers"})),
            rule("marked", "asic", json!({"proto": "udp", "dport": 8000, "dscp": 46})),
        ]
    }));
    let prog = program(&p);
    let key = |id: &str| {
        prog.asic
            .iter()
            .find(|r| r.rule_id == id)
            .unwrap()
            .tcam_key
            .clone()
    };
    assert_eq!(
        key("ports"),
        "any src=* dst=* proto=udp dport=27015 sport=0 pri=0 dport_to=27030"
    );
    assert!(key("long").ends_with(" len=1000-*"), "{}", key("long"));
    assert!(key("close").ends_with(" ttl=*-5"), "{}", key("close"));
    assert!(key("stamps").ends_with(" icmp=13"), "{}", key("stamps"));
    assert!(key("ssh").ends_with(" dst_list=servers"), "{}", key("ssh"));
    assert!(key("marked").ends_with(" dscp=46"), "{}", key("marked"));
    let mut pipe = Pipeline::new(prog);
    let to = |f: Value| {
        let mut base = json!({"src_ip":"192.0.2.1","dst_ip":"203.0.113.10","proto":"udp",
            "sport":40000,"pps":1});
        for (k, x) in f.as_object().unwrap() {
            base[k] = x.clone();
        }
        flow(base)
    };
    let payload = |b: &[u8]| STANDARD.encode(b);
    for (f, by) in [
        (to(json!({"dport": 27020})), drop("ports")),
        (to(json!({"dport": 27031})), pass()),
        (to(json!({"dport": 1000, "sport": 1005})), drop("sources")),
        (to(json!({"dport": 1000, "sport": 1011})), pass()),
        (to(json!({"dport": 2000, "length": 1200})), drop("long")),
        (to(json!({"dport": 2000, "length": 100})), pass()),
        (to(json!({"dport": 3000, "ttl": 3})), drop("close")),
        (to(json!({"dport": 3000, "ttl": 64})), pass()),
        (
            to(json!({"proto": "icmp", "icmp_type": 13, "icmp_code": 0})),
            drop("stamps"),
        ),
        (
            to(json!({"proto": "icmp", "icmp_type": 8, "icmp_code": 0})),
            pass(),
        ),
        (to(json!({"dport": 4000, "fragment": true})), drop("pieces")),
        (to(json!({"dport": 4000})), pass()),
        (
            to(json!({"dport": 5000, "payload": payload(&[0, 0, 0xbe, 0xef, 1])})),
            drop("magic"),
        ),
        (
            to(json!({"dport": 5000, "payload": payload(&[0xbe, 0xef, 1])})),
            pass(),
        ),
        (
            to(json!({"dport": 6000, "payload": payload(b"\x01\x02\xca\xfe\x03")})),
            drop("banner"),
        ),
        (
            to(json!({"dport": 6000, "payload": payload(b"\x01\x02\xca\x03")})),
            pass(),
        ),
        (
            to(json!({"dport": 7000, "src_ip": "100.64.9.9"})),
            drop("listed"),
        ),
        (to(json!({"dport": 7000, "src_ip": "100.65.0.1"})), pass()),
        (
            to(json!({"proto": "tcp", "dport": 22, "dst_ip": "203.0.113.50", "flags": "ack"})),
            drop("ssh"),
        ),
        (
            to(json!({"proto": "tcp", "dport": 22, "dst_ip": "203.0.113.51", "flags": "ack"})),
            pass(),
        ),
        (to(json!({"dport": 8000, "dscp": 46})), drop("marked")),
        (to(json!({"dport": 8000, "dscp": 0})), pass()),
        (to(json!({"dport": 8000})), pass()),
    ] {
        assert_eq!(decided(&mut pipe, &f, T0), by, "{f:?}");
    }
}

#[test]
fn a_rule_for_attacks_matches_only_while_its_prefix_is_under_one() {
    let mut pipe = pipeline(json!({"rules": [
        {"id": "squeeze", "stage": "zc", "action": "rate_limit", "pps": 100,
         "match": {"proto": "udp", "dport": 5000, "attack_pps": 10000}},
        {"id": "wide", "stage": "zc", "action": "drop",
         "match": {"proto": "udp", "dport": 5001, "attack_mbps": 100}}
    ]}));
    let quiet = udp("192.0.2.1", "203.0.113.10", 40000, 5000, 500);
    assert_eq!(decided(&mut pipe, &quiet, T0), pass());
    // The prefix takes 20,000 packets a second: the rule holds every source to 100 a second.
    let flood = udp("100.64.0.1", "203.0.113.11", 40000, 9, 20000);
    pipe.decide(&flood, T0 + 1_000);
    assert_eq!(decided(&mut pipe, &quiet, T0 + 1_001), drop("squeeze"));
    // Two seconds after it ends, the rule stands aside again.
    assert_eq!(decided(&mut pipe, &quiet, T0 + 3_000), pass());
    // The same by bandwidth: 200 Mbps of large packets.
    let small = udp("192.0.2.2", "203.0.113.10", 40000, 5001, 1);
    assert_eq!(decided(&mut pipe, &small, T0 + 10_000), pass());
    let wide = flow(
        json!({"src_ip":"100.64.0.2","dst_ip":"203.0.113.12","proto":"udp",
        "sport":40000,"dport":9,"pps":20000,"bps":200_000_000}),
    );
    pipe.decide(&wide, T0 + 11_000);
    assert_eq!(decided(&mut pipe, &small, T0 + 11_001), drop("wide"));
}

#[test]
fn a_shape_rule_holds_every_source_together_to_its_rate() {
    let rules = |action: &str| {
        json!({"rules": [{"id": "pings", "stage": "fpga", "action": action, "pps": 1000,
            "match": {"proto": "udp", "dport": 6000}}]})
    };
    let mut shaped = pipeline(rules("shape"));
    let mut limited = pipeline(rules("rate_limit"));
    let a = udp("192.0.2.1", "203.0.113.10", 40000, 6000, 600);
    let b = udp("192.0.2.2", "203.0.113.10", 40000, 6000, 600);
    for pipe in [&mut shaped, &mut limited] {
        assert_eq!(decided(pipe, &a, T0), pass());
    }
    // Together they are over the rate: shaped, the second source waits; limited, each source
    // has a rate of its own.
    let d = shaped.decide(&b, T0 + 1);
    assert_eq!((d.action.as_str(), d.rule_id.as_str()), ("drop", "pings"));
    assert_eq!(d.reason, "FPGA shaped to 1000 pps");
    assert_eq!(decided(&mut limited, &b, T0 + 1), pass());
    // A new second, a new budget.
    assert_eq!(decided(&mut shaped, &b, T0 + 1_000), pass());
}

#[test]
fn a_game_filter_keeps_its_players_for_its_idle_seconds() {
    let filter = |idle: Option<i64>| {
        let mut g = json!({"id":"bedrock","dst_cidr":"203.0.113.10/32","proto":"udp",
            "dport":19132,"profile":"raknet"});
        if let Some(s) = idle {
            g["idle_seconds"] = json!(s);
        }
        pipeline(json!({"games": [g], "reputation": {"fast_pass": "off"}}))
    };
    let packet = |b: &[u8]| {
        flow(
            json!({"src_ip":"192.0.2.1","dst_ip":"203.0.113.10","proto":"udp","sport":50000,
            "dport":19132,"pps":1,"payload":STANDARD.encode(b)}),
        )
    };
    for (idle, after) in [(Some(10), "drop"), (None, "permit")] {
        let mut pipe = filter(idle);
        pipe.decide(&packet(&[0x05]), T0);
        pipe.decide(&packet(&[0x07]), T0 + 1);
        let d = pipe.decide(&packet(&[0x84, 0, 0]), T0 + 9_000);
        assert_eq!(d.action, "permit", "{}", d.reason);
        let d = pipe.decide(&packet(&[0x84, 0, 0]), T0 + 30_000);
        assert_eq!(d.action, after, "{idle:?}: {}", d.reason);
    }
}

#[test]
fn a_filters_http_limits_and_slow_request_timing_are_its_own() {
    let site = |http: Value| {
        let mut h = json!({"ports": [80]});
        for (k, x) in http.as_object().unwrap() {
            h[k] = x.clone();
        }
        pipeline(
            json!({"games": [{"id":"site","dst_cidr":"203.0.113.20/32","proto":"tcp",
            "dport":80,"http":h}]}),
        )
    };
    let segment = |sport: i64, data: &[u8]| {
        flow(
            json!({"src_ip":"100.64.4.1","dst_ip":"203.0.113.20","proto":"tcp","sport":sport,
            "dport":80,"flags":"psh,ack","pps":1,"payload":STANDARD.encode(data)}),
        )
    };
    // Observed, a source leaving more requests incomplete than the filter allows passes and is
    // counted; enforced, it is dropped.
    for (mode, last) in [("observe", "permit"), ("enforce", "drop")] {
        let mut pipe = site(json!({"slow": {"mode": mode, "incomplete_max": 2}}));
        for port in 0..2 {
            let d = pipe.decide(&segment(43000 + port, b"GET / HTTP/1.1\r\n"), T0);
            assert_eq!(d.action, "permit", "{}", d.reason);
        }
        let d = pipe.decide(&segment(43002, b"GET / HTTP/1.1\r\n"), T0 + 1);
        assert_eq!(d.action, last, "{mode}: {}", d.reason);
        let g = &pipe.stats(T0 + 2)["games"][0];
        assert_eq!(
            (
                g["http_slow_observed"].clone(),
                g["http_slow_dropped"].clone()
            ),
            if mode == "observe" {
                (json!(1), json!(0))
            } else {
                (json!(0), json!(1))
            },
            "{g}"
        );
    }
    // Pipelining past the filter's own bound.
    let three = b"GET / HTTP/1.1\r\nHost: a\r\n\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\n";
    let mut pipe = site(json!({"pipelined_max": 2}));
    let d = pipe.decide(&segment(44000, three), T0);
    assert_eq!(d.action, "drop", "{}", d.reason);
    let mut pipe = site(json!({}));
    let d = pipe.decide(&segment(44000, three), T0);
    assert_eq!(d.action, "permit", "{}", d.reason);
    // TLS handshakes counted against the rate, or not.
    let hello: &[u8] = &[
        0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03,
    ];
    for (tls, second) in [("count", "drop"), ("ignore", "permit")] {
        let mut pipe = site(json!({"rate_per_source": 1, "tls": tls}));
        pipe.decide(&segment(45000, hello), T0);
        let d = pipe.decide(&segment(45001, hello), T0 + 1);
        assert_eq!(d.action, second, "{tls}: {}", d.reason);
    }
}

#[test]
fn validation_says_what_is_wrong_with_a_setting() {
    let ok = policy(json!({
        "sensitivity": "medium",
        "crafted": {"checks": {"land": "observe"}},
        "reflection": {"judge": {"ntp": "always", "arms": "flood"},
            "vectors": {"arms": "observe"},
            "custom": [{"name": "arms", "port": 3283, "payload_hex": "0001"}]},
        "lists": {"office": ["198.51.100.0/24"]},
        "rules": [{"id": "r", "stage": "zc", "action": "shape", "pps": 10,
            "match": {"src_list": "office", "dport": 1, "dport_to": 2, "payload_contains": "aa"}}],
        "profiles": [{"name": "web", "prefixes": ["203.0.113.20/32"],
            "reflection": {"vectors": {"arms": "off"}}}]
    }));
    validation::policy(&ok).unwrap();
    for (bad, says) in [
        (
            json!({"sensitivity": "extreme"}),
            "sensitivity \"extreme\": use high, medium",
        ),
        (
            json!({"crafted": {"checks": {"lands": "off"}}}),
            "crafted.checks: \"lands\" is not a check",
        ),
        (
            json!({"crafted": {"checks": {"land": "drop"}}}),
            "crafted.checks.land \"drop\"",
        ),
        (
            json!({"reflection": {"judge": {"dns": "sometimes"}}}),
            "reflection.judge.dns \"sometimes\"",
        ),
        (
            json!({"reflection": {"judge": {"quic": "always"}}}),
            "reflection.judge: \"quic\" is not a vector",
        ),
        (
            json!({"reflection": {"custom": [{"name": "Arms", "port": 3283}]}}),
            "reflection.custom[0].name \"Arms\"",
        ),
        (
            json!({"reflection": {"custom": [{"name": "dns", "port": 3283}]}}),
            "is a vector the guard knows",
        ),
        (
            json!({"reflection": {"custom": [{"name": "x", "port": 53}]}}),
            "port 53 is dns's",
        ),
        (
            json!({"reflection": {"custom": [{"name": "x", "port": 3283}, {"name": "y", "port": 3283}]}}),
            "port 3283 is also x's",
        ),
        (
            json!({"reflection": {"custom": [{"name": "x"}]}}),
            "reflection.custom[0].port 0",
        ),
        (
            json!({"reflection": {"custom": [{"name": "x", "port": 3283, "payload_hex": "abc"}]}}),
            "pairs of hex digits",
        ),
        (
            json!({"reflection": {"custom": (0..9).map(|i| json!({"name": format!("v{i}"), "port": 4000 + i})).collect::<Vec<_>>()}}),
            "at most 8 of your own",
        ),
        (
            json!({"fragments": {"protocols": ["gre"]}}),
            "fragments.protocols \"gre\"",
        ),
        (
            json!({"fragments": {"protocols": ["udp", "udp"]}}),
            "names udp twice",
        ),
        (
            json!({"icmp": {"drop_types": [300]}}),
            "icmp.drop_types: 300 is not a type",
        ),
        (
            json!({"icmp": {"errors": "ignore"}}),
            "icmp.errors \"ignore\"",
        ),
        (
            json!({"reputation": {"penalty_seconds": [0]}}),
            "reputation.penalty_seconds: 0 must be within",
        ),
        (
            json!({"reputation": {"penalty_seconds": [1, 2, 3, 4, 5, 6, 7, 8, 9]}}),
            "at most 8",
        ),
        (
            json!({"egress": {"confirm_ticks": 40, "confirm_window_seconds": 5}}),
            "do not fit in confirm_window_seconds 5",
        ),
        (
            json!({"egress": {"confirm_ticks": 41}}),
            "egress.confirm_ticks must be within 1..40",
        ),
        (
            json!({"mitigation": {"hold_seconds": 7200}}),
            "past hold_max_seconds 3600",
        ),
        (
            json!({"syn_flood": {"hold_seconds": 100000}}),
            "syn_flood.hold_seconds must be within 0..86400 seconds, not 100000",
        ),
        (
            json!({"pulse": {"duty": 2.0}}),
            "pulse.duty must be within 0.01..1",
        ),
        (
            json!({"lists": {"my list": []}}),
            "lists: \"my list\" is not a name",
        ),
        (json!({"lists": {"l": ["nowhere"]}}), "lists.l \"nowhere\""),
        (
            json!({"lists": {"l": (0..4097).map(|i| format!("10.{}.{}.0/24", i / 256, i % 256)).collect::<Vec<_>>()}}),
            "at most 4096",
        ),
        (
            json!({"rules": [{"id": "r", "stage": "asic", "match": {"dport_to": 5}}]}),
            "set dport to its first port",
        ),
        (
            json!({"rules": [{"id": "r", "stage": "asic", "match": {"dport": 9, "dport_to": 5}}]}),
            "dport_to 5 is before dport 9",
        ),
        (
            json!({"rules": [{"id": "r", "stage": "asic", "match": {"length_min": 900, "length_max": 100}}]}),
            "length_min 900 is past length_max 100",
        ),
        (
            json!({"rules": [{"id": "r", "stage": "asic", "match": {"proto": "udp", "icmp_type": 8}}]}),
            "set proto to icmp",
        ),
        (
            json!({"rules": [{"id": "r", "stage": "asic", "match": {"proto": "icmp", "icmp_code": 1}}]}),
            "set icmp_type too",
        ),
        (
            json!({"rules": [{"id": "r", "stage": "asic", "match": {"fragment": "maybe"}}]}),
            "fragment \"maybe\"",
        ),
        (
            json!({"rules": [{"id": "r", "stage": "zc", "match": {"payload_hex": "a"}}]}),
            "pairs of hex digits",
        ),
        (
            json!({"rules": [{"id": "r", "stage": "zc", "match": {"payload_hex": "aa".repeat(65)}}]}),
            "may name at most 64",
        ),
        (
            json!({"rules": [{"id": "r", "stage": "zc", "match": {"payload_offset": 4}}]}),
            "set payload_hex too",
        ),
        (
            json!({"rules": [{"id": "r", "stage": "asic", "match": {"payload_contains": "aa"}}]}),
            "the asic stage matches headers alone",
        ),
        (
            json!({"rules": [{"id": "r", "stage": "asic", "match": {"src_list": "nobody"}}]}),
            "src_list \"nobody\" is not one of the policy's lists",
        ),
        (
            json!({"rules": [{"id": "r", "stage": "asic", "action": "shape", "pps": 5}]}),
            "the asic stage cannot meter; use the fpga or zc stage for shape",
        ),
        (
            json!({"rules": [{"id": "r", "stage": "fpga", "action": "shape"}]}),
            "shape requires positive pps",
        ),
        (
            json!({"rules": [{"id": "r", "stage": "asic", "match": {"ttl_max": 300}}]}),
            "rules[0].match.ttl_max must be within 0..255",
        ),
        (
            json!({"profiles": [{"name": "", "prefixes": ["203.0.113.20/32"]}]}),
            "profiles[0].name \"\"",
        ),
        (
            json!({"profiles": [{"name": "a", "prefixes": ["203.0.113.20/32"]}, {"name": "a", "prefixes": ["203.0.113.21/32"]}]}),
            "names two profiles",
        ),
        (json!({"profiles": [{"name": "a"}]}), "holds no prefixes"),
        (
            json!({"profiles": [{"name": "a", "prefixes": ["192.0.2.0/24"]}]}),
            "outside every protected prefix",
        ),
        (
            json!({"profiles": [{"name": "a", "prefixes": ["203.0.113.1/24"]}]}),
            "has host bits set; write it as 203.0.113.0/24",
        ),
        (
            json!({"profiles": [{"name": "a", "prefixes": ["203.0.113.20/32"]}, {"name": "b", "prefixes": ["203.0.113.20/32"]}]}),
            "is in profiles \"a\" and \"b\"",
        ),
        (
            json!({"profiles": [{"name": "a", "prefixes": ["203.0.113.20/32"], "syn_flood": {"mode": "drop"}}]}),
            "profiles[0].syn_flood.mode \"drop\"",
        ),
        (
            json!({"profiles": [{"name": "a", "prefixes": ["203.0.113.20/32"], "sensitivity": "max"}]}),
            "profiles[0].sensitivity \"max\"",
        ),
        (
            json!({"profiles": [{"name": "a", "prefixes": ["203.0.113.20/32"], "reflection": {"custom": [{"name": "x", "port": 4000}]}}]}),
            "profiles[0].reflection.custom: vectors are the policy's",
        ),
        (
            json!({"profiles": [{"name": "a", "prefixes": ["203.0.113.20/32"], "reflection": {"reflecting_for_seconds": 5}}]}),
            "is the policy's alone",
        ),
        (
            json!({"profiles": [{"name": "a", "prefixes": ["203.0.113.20/32"], "ack_flood": {"handshake_segments": 5000}}]}),
            "profiles[0].ack_flood.handshake_segments must be within 0..1000",
        ),
        (
            json!({"games": [{"id": "g", "dport": 80, "http": {"tls": "maybe"}}]}),
            "http.tls \"maybe\"",
        ),
        (
            json!({"games": [{"id": "g", "dport": 80, "http": {"slow": {"mode": "drop"}}}]}),
            "http.slow.mode \"drop\"",
        ),
        (
            json!({"games": [{"id": "g", "dport": 80, "http": {"slow": {"head_seconds": 50}}}]}),
            "head_seconds 50 is past head_seconds_max 40",
        ),
        (
            json!({"games": [{"id": "g", "proto": "udp", "dport": 19132, "profile": "raknet", "idle_seconds": 0}]}),
            "games[0].idle_seconds must be within 1..86400",
        ),
    ] {
        let mut bad = bad;
        if let Some(rules) = bad.get_mut("rules").and_then(Value::as_array_mut) {
            for r in rules {
                if r.get("action").is_none() {
                    r["action"] = json!("drop");
                }
            }
        }
        let err = validation::policy(&policy(bad.clone())).unwrap_err();
        assert!(err.contains(says), "{bad}: {err}");
    }
}

/// Whether a catalog path is set in a policy: in every element of an array it passes through,
/// at least one of them.
fn set(v: &Value, path: &str) -> bool {
    let Some((head, rest)) = path.split_once('.') else {
        return v.get(path.trim_end_matches("[]")).is_some();
    };
    match head.strip_suffix("[]") {
        Some(key) => v[key]
            .as_array()
            .is_some_and(|items| items.iter().any(|i| set(i, rest))),
        None => v.get(head).is_some_and(|x| set(x, rest)),
    }
}
fn reference() -> Value {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/configs/policy.reference.json"
    ))
    .unwrap();
    serde_json::from_str(&text).unwrap()
}

#[test]
fn the_reference_policy_names_every_setting_at_its_default() {
    let raw = reference();
    tuning::check_known(&raw).unwrap();
    let p: Policy = serde_json::from_value(raw.clone()).unwrap();
    validation::policy(&p).unwrap();
    for s in SETTINGS {
        // The name CLDAP's mode had before the others; reflection.vectors.cldap sets it now.
        if s.path == "reflection.cldap" {
            continue;
        }
        assert!(
            set(&raw, s.path),
            "{} is missing from the reference",
            s.path
        );
        if s.path.contains("[]") || s.path.starts_with("lists") {
            continue;
        }
        let mut at = &raw;
        for part in s.path.split('.') {
            at = &at[part];
        }
        match s.kind {
            Kind::Number { default, .. } => {
                assert_eq!(at.as_f64(), Some(default), "{}", s.path)
            }
            Kind::Choice { default, .. } => assert_eq!(at, &json!(default), "{}", s.path),
            Kind::Flag { default } => assert_eq!(at, &json!(default), "{}", s.path),
            _ => {}
        }
    }
    // Written out, the defaults resolve as leaving them unset does.
    let set_out = tuning::effective(&tuning::program_of(&p));
    let unset = tuning::effective(&tuning::program_of(&policy(json!({}))));
    for section in [
        "sensitivity",
        "crafted",
        "protocols",
        "ack_flood",
        "syn_flood",
        "fragments",
        "icmp",
        "aggregation",
        "reputation",
        "egress",
        "pulse",
        "mitigation",
        "ml",
        "pulse_floor_pps",
    ] {
        assert_eq!(
            set_out["policy"][section], unset["policy"][section],
            "{section}"
        );
    }
    for key in [
        "engage_pps",
        "hold_seconds",
        "asked_within_seconds",
        "reflecting_for_seconds",
    ] {
        assert_eq!(
            set_out["policy"]["reflection"][key],
            unset["policy"]["reflection"][key]
        );
    }
    for v in pathfinder::reflection::VECTORS {
        let r = |e: &Value, k: &str| e["policy"]["reflection"][k][v.name].clone();
        assert_eq!(r(&set_out, "vectors"), r(&unset, "vectors"), "{}", v.name);
        assert_eq!(r(&set_out, "judge"), r(&unset, "judge"), "{}", v.name);
    }
    // And the profile's: what it sets, its sensitivity for the rest, the policy's elsewhere.
    let web = &set_out["profiles"][0];
    assert_eq!(web["name"], "web");
    assert_eq!(web["prefixes"], json!(["203.0.113.20/32"]));
    assert_eq!(web["syn_flood"]["engage_pps"], 20000);
    // The policy sets its threshold, so the profile takes it as set.
    assert_eq!(web["ack_flood"]["engage_pps"], 5000);
    assert_eq!(web["icmp"]["drop_types"], json!([8]));
    assert_eq!(web["reflection"]["vectors"]["dns"], "observe");
    assert_eq!(web["reflection"]["vectors"]["arms"], "enforce");
    assert_eq!(web["syn_flood"]["hold_seconds"], 60.0);
}

#[test]
fn every_policy_the_repository_ships_names_only_settings() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/configs");
    let mut checked = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if !name.starts_with("policy.") || !name.ends_with(".json") {
            continue;
        }
        let raw: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        tuning::check_known(&raw).unwrap_or_else(|e| panic!("{name}: {e}"));
        let p: Policy = serde_json::from_value(raw).unwrap();
        validation::policy(&p).unwrap_or_else(|e| panic!("{name}: {e}"));
        checked += 1;
    }
    assert!(checked >= 4, "{checked}");
}

fn serve() -> String {
    let state: Shared = Arc::new(Mutex::new(Api::new(
        Store::open("").unwrap(),
        OP.into(),
        "test-enroll".into(),
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
fn the_api_serves_the_catalog_and_each_policys_settings_and_turns_down_a_mistyped_one() {
    let base = serve();
    assert_eq!(call(&base, "GET", "/v1/settings", None, Value::Null).0, 401);
    let (status, catalog) = call(&base, "GET", "/v1/settings", Some(OP), Value::Null);
    assert_eq!(status, 200, "{catalog}");
    let rows = catalog["settings"].as_array().unwrap();
    assert_eq!(rows.len(), SETTINGS.len());
    let hold = rows
        .iter()
        .find(|r| r["path"] == "syn_flood.hold_seconds")
        .unwrap();
    assert_eq!(
        (
            &hold["type"],
            &hold["default"],
            &hold["min"],
            &hold["max"],
            &hold["unit"],
            &hold["profile"]
        ),
        (
            &json!("integer"),
            &json!(60.0),
            &json!(0.0),
            &json!(86400.0),
            &json!("seconds"),
            &json!(true)
        )
    );
    let action = rows.iter().find(|r| r["path"] == "rules[].action").unwrap();
    assert!(action["options"]
        .as_array()
        .unwrap()
        .contains(&json!("shape")));
    assert!(rows
        .iter()
        .all(|r| r["about"].as_str().is_some_and(|a| !a.is_empty())));

    let mistyped = json!({"name": "p", "protected": ["203.0.113.0/24"],
        "syn_flood": {"hold_secnods": 30}});
    let (status, body) = call(&base, "POST", "/v1/policies", Some(OP), mistyped);
    assert_eq!(status, 400, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .starts_with("syn_flood.hold_secnods is not a setting; syn_flood takes"),
        "{body}"
    );
    let (status, body) = call(&base, "POST", "/v1/policies", Some(OP), reference());
    assert_eq!(status, 200, "{body}");
    let (status, e) = call(
        &base,
        "GET",
        "/v1/policies/reference/settings",
        Some(OP),
        Value::Null,
    );
    assert_eq!(status, 200, "{e}");
    assert_eq!(e["policy_id"], "reference");
    assert_eq!(e["policy"]["syn_flood"]["engage_pps"], 2000);
    assert_eq!(e["policy"]["reflection"]["custom"][0]["port"], 3283);
    assert_eq!(e["policy"]["egress"]["lockdown"], "off");
    assert_eq!(e["profiles"][0]["syn_flood"]["engage_pps"], 20000);
    assert_eq!(e["profiles"][0]["sensitivity"], "high");
    assert_eq!(
        call(
            &base,
            "GET",
            "/v1/policies/nope/settings",
            Some(OP),
            Value::Null
        )
        .0,
        404
    );
}

#[test]
fn the_largest_policy_the_bounds_are_measured_at_is_one_validation_lets_through() {
    let p = common::largest_policy();
    validation::policy(&p).unwrap();
    tuning::check_known(&serde_json::to_value(&p).unwrap()).unwrap();
    assert_eq!(p.profiles.len(), validation::PROFILES_MAX);
    let held: usize = p.profiles.iter().map(|x| x.prefixes.len()).sum();
    assert_eq!(held, validation::PROFILE_PREFIXES_MAX);
    let listed: usize = p.lists.values().map(Vec::len).sum();
    assert_eq!(listed, validation::LIST_ENTRIES_MAX);
    // One more of any of them is turned down.
    let mut more = p.clone();
    more.lists
        .insert("one-more".into(), vec!["192.0.2.0/24".into()]);
    assert!(validation::policy(&more).unwrap_err().contains("at most"));
    let mut more = p.clone();
    more.profiles[0]
        .prefixes
        .push("2001:db8:100:ffff::/64".into());
    assert!(validation::policy(&more).unwrap_err().contains("at most"));
}

#[test]
fn the_readme_documents_every_setting_with_its_default() {
    let readme = include_str!("../README.md");
    let table = &readme[readme.find("### Every setting").unwrap()..];
    for s in SETTINGS {
        let row = table
            .lines()
            .find(|l| l.starts_with(&format!("| `{}` |", s.path)))
            .unwrap_or_else(|| panic!("{} is not in the README's table", s.path));
        let default = row.split('|').nth(2).unwrap().trim().trim_matches('`');
        let want = match s.kind {
            Kind::Number { default, .. } if default.is_nan() => "-".to_string(),
            Kind::Number { default, .. } => default.to_string(),
            Kind::Choice { default: "", .. } => "-".to_string(),
            Kind::Choice { default, .. } => default.to_string(),
            Kind::Flag { default } => default.to_string(),
            _ => "-".to_string(),
        };
        assert_eq!(default, want, "{}", s.path);
    }
}

/// The body each `curl ... -d '...'` in `text` sends, and the line the guide shows answering it.
fn examples(text: &str) -> Vec<(Value, String)> {
    text.split("-d '")
        .skip(1)
        .map(|rest| {
            let body = &rest[..rest.find('\'').unwrap()];
            let answer = rest[body.len() + 1..]
                .lines()
                .nth(1)
                .unwrap_or("")
                .to_string();
            (serde_json::from_str(body).unwrap(), answer)
        })
        .collect()
}

#[test]
fn the_guides_settings_examples_are_what_the_api_answers() {
    let guide = include_str!("../docs/api.md");
    let step = &guide[guide.find("### 17. Tuning every setting").unwrap()..];
    let step = &step[..step.find("## The node agent").unwrap()];
    let readme = include_str!("../README.md");
    let tuning = &readme[readme.find("## Tuning every setting").unwrap()..];
    let tuning = &tuning[..tuning.find("### When to filter").unwrap()];
    let base = serve();
    let shown = examples(step);
    assert_eq!(shown.len(), 2, "{shown:#?}");
    for (body, answer) in examples(tuning).into_iter().chain([shown[0].clone()]) {
        let (status, got) = call(&base, "POST", "/v1/policies", Some(OP), body);
        assert_eq!(status, 400);
        assert_eq!(serde_json::to_string(&got).unwrap(), answer);
    }
    let (status, saved) = call(&base, "POST", "/v1/policies", Some(OP), shown[1].0.clone());
    assert_eq!(status, 200, "{saved}");
    let (_, e) = call(
        &base,
        "GET",
        "/v1/policies/edge/settings",
        Some(OP),
        Value::Null,
    );
    for icmp in [&e["policy"]["icmp"], &e["profiles"][0]["icmp"]] {
        let icmp = format!("\"icmp\":{}", serde_json::to_string(icmp).unwrap());
        assert!(step.contains(&icmp), "{icmp}");
        assert!(tuning.contains(&icmp) || readme.contains(&icmp), "{icmp}");
    }
    // And the catalog's first rows as the guide shows them.
    let (_, catalog) = call(&base, "GET", "/v1/settings", Some(OP), Value::Null);
    let first = serde_json::to_string(&catalog["settings"][0]).unwrap();
    assert!(step.contains(&first) && readme.contains(&first), "{first}");
}

/// The fields a struct in src/model.rs declares, by the names serde gives them.
fn fields(model: &str, name: &str) -> Vec<String> {
    let start = model
        .find(&format!("pub struct {name} {{"))
        .unwrap_or_else(|| panic!("no struct {name}"));
    let body = &model[start..];
    let body = &body[..body.find("\n}").unwrap()];
    let mut out: Vec<String> = body
        .lines()
        .filter_map(|l| l.trim().strip_prefix("pub "))
        .filter_map(|l| {
            l.split_once(':')
                .map(|(f, _)| f.trim_start_matches("r#").to_string())
        })
        .filter(|f| !f.contains(' '))
        .collect();
    out.sort();
    out
}

#[test]
fn every_field_of_a_policy_is_a_setting_or_a_field_the_check_knows() {
    let model = include_str!("../src/model.rs");
    for (object, name) in [
        ("", "Policy"),
        ("crafted", "CraftedPolicy"),
        ("reflection", "ReflectionPolicy"),
        ("reflection.custom[]", "CustomVector"),
        ("protocols", "ProtocolPolicy"),
        ("ack_flood", "AckFloodPolicy"),
        ("syn_flood", "SynFloodPolicy"),
        ("fragments", "FragmentPolicy"),
        ("icmp", "IcmpPolicy"),
        ("aggregation", "AggregationPolicy"),
        ("reputation", "ReputationPolicy"),
        ("egress", "EgressPolicy"),
        ("pulse", "PulsePolicy"),
        ("mitigation", "MitigationPolicy"),
        ("ml", "MlPolicy"),
        ("games[]", "GameFilter"),
        ("games[].http", "GameHttp"),
        ("games[].http.slow", "GameHttpSlow"),
        ("games[].http.paths[]", "GameHttpPath"),
        ("rules[]", "Rule"),
        ("rules[].match", "Match"),
        ("profiles[]", "Profile"),
    ] {
        assert!(tuning::OBJECTS.contains(&object), "{object}");
        let known: Vec<String> = tuning::keys(object).iter().map(|k| k.to_string()).collect();
        assert_eq!(known, fields(model, name), "{name} at {object:?}");
    }
    // A profile's sections take what a profile may set of the policy's.
    for (section, name) in [("reflection", "ReflectionPolicy"), ("icmp", "IcmpPolicy")] {
        let known = tuning::keys(&format!("profiles[].{section}"));
        let all = fields(model, name);
        assert!(
            known.iter().all(|k| all.contains(&k.to_string())),
            "{section}"
        );
    }
    assert!(!tuning::keys("profiles[].reflection").contains(&"custom"));
}

#[test]
fn a_mistyped_section_filter_or_rule_field_is_turned_down_too() {
    for (policy, says) in [
        (
            json!({"syn_floood": {"mode": "observe"}}),
            "syn_floood is not a setting or field of a policy; a policy takes ack_flood, aggregation, challenge_secret, crafted,",
        ),
        (
            json!({"games": [{"id": "g", "dport": 1, "observ": true}]}),
            "games[0].observ is not a setting or field; games[0] takes comment, custom, dport, dst_cidr, http, id, idle_seconds, observe, profile, proto",
        ),
        (
            json!({"rules": [{"id": "r", "prioirty": 5}]}),
            "rules[0].prioirty is not a setting or field; rules[0] takes action, comment, id, match, pps, priority, stage",
        ),
        (
            json!({"games": [{"http": {"paths": [{"path": "/", "rate": 5}]}}]}),
            "games[0].http.paths[0].rate is not a setting or field;",
        ),
        (
            json!({"profiles": [{"name": "a", "pulse": {}}]}),
            "profiles[0].pulse is not a setting; profiles[0] takes ack_flood, crafted, fragments, icmp, name, prefixes, protocols, reflection, sensitivity, syn_flood",
        ),
    ] {
        let err = tuning::check_known(&policy).unwrap_err();
        assert!(err.starts_with(says), "{err}");
    }
}

#[test]
fn a_packets_dscp_is_read_from_its_header_for_rules_to_match() {
    let mut pipe = pipeline(
        json!({"rules": [{"id": "marked", "stage": "asic", "action": "drop",
        "match": {"proto": "udp", "dscp": 46}}]}),
    );
    // Expedited forwarding: DSCP 46 in the type of service's top six bits.
    let udp = [0x9c, 0x40, 0x1f, 0x40, 0, 12, 0, 0, 1, 2, 3, 4];
    let mut marked = ipv4([192, 0, 2, 1], [203, 0, 113, 10], 17, &udp, 0);
    marked[1] = 46 << 2;
    let mut s: u32 = 0;
    marked[10] = 0;
    marked[11] = 0;
    for c in marked[..20].chunks(2) {
        s += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    while s > 0xffff {
        s = (s & 0xffff) + (s >> 16);
    }
    marked[10..12].copy_from_slice(&(!(s as u16)).to_be_bytes());
    let f = flow(json!({"pps": 1, "packet": STANDARD.encode(&marked)}));
    assert_eq!(f.dscp, Some(46));
    assert_eq!(decided(&mut pipe, &f, T0), drop("marked"));
    let plain = flow(json!({"pps": 1,
        "packet": STANDARD.encode(ipv4([192, 0, 2, 1], [203, 0, 113, 10], 17, &udp, 0))}));
    assert_eq!(plain.dscp, Some(0));
    assert_eq!(decided(&mut pipe, &plain, T0), pass());
    // IPv6 carries it in the traffic class, across the first two bytes.
    let mut v6 = vec![
        0x60 | (46 >> 2),
        (46 & 3) << 6,
        0,
        0,
        0,
        udp.len() as u8,
        17,
        64,
    ];
    v6.extend(
        "2001:db8:ffff::1"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    v6.extend(
        "2001:db8:100::10"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    v6.extend(udp);
    let f = flow(json!({"pps": 1, "packet": STANDARD.encode(&v6)}));
    assert_eq!(f.dscp, Some(46));
}
