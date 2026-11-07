//! The protocol and ACK flood guards: what IoT botnets flood with beside UDP. GRE floods and other
//! protocols no game server receives are dropped unless the policy lets them in; TCP that belongs
//! to no connection the server has is dropped while a prefix is flooded with it, and only once the
//! node knows the server's connections.
use base64::{engine::general_purpose::STANDARD, Engine};
use pathfinder::{
    compiler,
    guards::{ACK_HOLD, ACK_WARM, ENGAGE_PPS},
    model::{ACLEntry, AckFloodPolicy, Flow, Match, Node, Policy, Program, ProtocolPolicy},
    pipeline::Pipeline,
    telemetry::Metrics,
    validation,
};
use serde_json::json;
use std::net::Ipv6Addr;

const T0: i64 = 1767225600000;
const SERVER: &str = "203.0.113.10";
/// A player the server has a TCP connection with.
const PLAYER: &str = "192.0.2.50";

fn seal(p: &mut [u8]) {
    p[10] = 0;
    p[11] = 0;
    let mut s: u32 = p[..20]
        .chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], c[1]])))
        .sum();
    while s > 0xffff {
        s = (s & 0xffff) + (s >> 16);
    }
    p[10..12].copy_from_slice(&(!(s as u16)).to_be_bytes());
}
fn v4(proto: u8, body: &[u8]) -> Vec<u8> {
    let mut p = vec![0x45, 0];
    p.extend((20 + body.len() as u16).to_be_bytes());
    p.extend([0x12, 0x34, 0x40, 0x00, 64, proto, 0, 0]);
    p.extend([100, 64, 0, 9]);
    p.extend([203, 0, 113, 10]);
    p.extend(body);
    seal(&mut p);
    p
}
fn v6(next: u8, body: &[u8]) -> Vec<u8> {
    let mut p = vec![0x60, 0, 0, 0];
    p.extend((body.len() as u16).to_be_bytes());
    p.extend([next, 64]);
    p.extend("2001:db8:ffff::9".parse::<Ipv6Addr>().unwrap().octets());
    p.extend("2001:db8:100::10".parse::<Ipv6Addr>().unwrap().octets());
    p.extend(body);
    p
}
/// GRE carrying an IPv4 packet, as Mirai's GRE IP flood sends it.
fn gre() -> Vec<u8> {
    let mut g = vec![0x00, 0x00, 0x08, 0x00];
    g.extend([
        0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8,
    ]);
    g.extend([0x30, 0x39, 0x30, 0x39, 0, 8, 0, 0]);
    g
}
fn wire(bytes: &[u8]) -> Flow {
    serde_json::from_value(json!({ "packet": STANDARD.encode(bytes) })).unwrap()
}
fn record(proto: &str, src: &str, flags: &str, pps: i64) -> Flow {
    serde_json::from_value(
        json!({"src_ip":src,"dst_ip":SERVER,"proto":proto,"sport":40000,
        "dport":443,"flags":flags,"pps":pps}),
    )
    .unwrap()
}
fn node(protocols: Option<ProtocolPolicy>, ack_flood: Option<AckFloodPolicy>) -> Program {
    Program {
        prefixes: vec!["203.0.113.0/24".into(), "2001:db8:100::/48".into()],
        protocols,
        ack_flood,
        ..Default::default()
    }
}
fn verdict(pipe: &mut Pipeline, f: &Flow, at: i64) -> (String, String, String) {
    let d = pipe.decide(f, at);
    (d.action, d.stage, d.guard)
}
fn dropped(stage: &str, guard: &str) -> (String, String, String) {
    ("drop".into(), stage.into(), guard.into())
}
fn passed() -> (String, String, String) {
    ("permit".into(), "asic".into(), String::new())
}

#[test]
fn gre_and_every_protocol_no_game_server_receives_are_dropped() {
    let mut pipe = Pipeline::new(node(None, None));
    let d = pipe.decide(&wire(&v4(47, &gre())), T0);
    assert_eq!(
        (d.action.as_str(), d.stage.as_str(), d.guard.as_str()),
        ("drop", "asic", "protocol")
    );
    assert!(d.reason.starts_with("GRE flood: "), "{}", d.reason);
    assert_eq!(
        verdict(&mut pipe, &wire(&v6(47, &gre())), T0),
        dropped("asic", "protocol")
    );
    // However a record names it.
    for proto in ["gre", "47", "esp", "ah", "sctp", "ipip", "4", "253"] {
        let d = pipe.decide(&record(proto, "100.64.0.9", "", 50_000), T0);
        assert_eq!(
            (d.action.as_str(), d.guard.as_str()),
            ("drop", "protocol"),
            "{proto}"
        );
    }
    let d = pipe.decide(&record("esp", "100.64.0.9", "", 1), T0);
    assert!(d.reason.starts_with("IP protocol esp "), "{}", d.reason);
    // What every protected address receives, and a record that names no protocol.
    for proto in ["tcp", "udp", "icmp", "TCP", ""] {
        let d = pipe.decide(&record(proto, "100.64.0.9", "", 1), T0);
        assert_eq!(d.guard, "", "{proto}: {}", d.reason);
    }
    // An address no prefix of the node's covers is not its to judge.
    let elsewhere = Flow {
        dst_ip: "192.0.2.99".into(),
        ..record("gre", "100.64.0.9", "", 1)
    };
    assert_eq!(pipe.decide(&elsewhere, T0).guard, "");
    let st = pipe.stats(T0)["protocols"].clone();
    assert_eq!(st["dropped"], 11, "{st}");
    let gre_row = st["by_protocol"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["protocol"] == "gre")
        .unwrap()
        .clone();
    assert_eq!(gre_row["dropped"], 4, "{st}");
}
#[test]
fn the_policy_and_a_permit_let_a_protocol_in() {
    let allow = ProtocolPolicy {
        allow: vec!["esp".into(), "51".into()],
        ..Default::default()
    };
    let mut program = node(Some(allow), None);
    program.asic = vec![ACLEntry {
        rule_id: "vpn-gre".into(),
        action: "permit".into(),
        r#match: Match {
            proto: "gre".into(),
            dst_cidr: "203.0.113.50/32".into(),
            ..Default::default()
        },
        ..Default::default()
    }];
    let mut pipe = Pipeline::new(program);
    for proto in ["esp", "50", "ah"] {
        assert_eq!(
            pipe.decide(&record(proto, "100.64.0.9", "", 1), T0).guard,
            ""
        );
    }
    assert_eq!(
        verdict(&mut pipe, &record("gre", "100.64.0.9", "", 1), T0),
        dropped("asic", "protocol")
    );
    // GRE to the one address the operator's permit names passes, as the rule says.
    let vpn = Flow {
        dst_ip: "203.0.113.50".into(),
        ..record("gre", "100.64.0.9", "", 1)
    };
    let d = pipe.decide(&vpn, T0);
    assert_eq!(
        (d.action.as_str(), d.rule_id.as_str()),
        ("permit", "vpn-gre")
    );
}
#[test]
fn observing_counts_what_would_be_dropped_and_off_does_not_look() {
    let observe = ProtocolPolicy {
        mode: "observe".into(),
        ..Default::default()
    };
    let mut pipe = Pipeline::new(node(Some(observe), None));
    assert_eq!(pipe.decide(&wire(&v4(47, &gre())), T0).action, "permit");
    let st = pipe.stats(T0)["protocols"].clone();
    assert_eq!(
        (st["observed"].clone(), st["dropped"].clone()),
        (json!(1), json!(0))
    );
    let off = ProtocolPolicy {
        mode: "off".into(),
        ..Default::default()
    };
    let mut pipe = Pipeline::new(node(Some(off), None));
    assert_eq!(pipe.decide(&wire(&v4(47, &gre())), T0).action, "permit");
    assert_eq!(pipe.stats(T0)["protocols"]["observed"], 0);
}

/// The server's own traffic seen on its way out, every ten seconds from T0 to `until`: TCP to
/// the player it has a connection with.
fn watch(pipe: &mut Pipeline, until: i64) {
    let mut at = T0;
    while at <= until {
        let reply = json!({"src_ip":SERVER,"dst_ip":PLAYER,"proto":"tcp","sport":443,"dport":50000,
            "flags":"ack","pps":10});
        pipe.observe_return(&serde_json::from_value(reply).unwrap(), at);
        at += 10_000;
    }
}
#[test]
fn an_ack_flood_is_dropped_once_the_node_knows_the_connections_and_the_prefix_is_flooded() {
    let mut pipe = Pipeline::new(node(None, None));
    let now = T0 + ACK_WARM + 10_000;
    watch(&mut pipe, now);
    // A trickle of TCP for no connection, as after a restart, passes.
    assert_eq!(
        verdict(&mut pipe, &record("tcp", "100.64.1.1", "ack", 1000), now),
        passed()
    );
    // A flood of it engages the guard, and everything else for no connection goes with it.
    let flood = record("tcp", "100.64.1.2", "ack", 10_000);
    assert_eq!(
        verdict(&mut pipe, &flood, now + 1),
        dropped("zc", "ack_flood")
    );
    for (src, flags) in [
        ("100.64.1.3", "ack"),
        ("100.64.1.4", "psh,ack"),
        ("100.64.1.5", "rst"),
        ("100.64.1.6", "fin,ack"),
        ("100.64.1.7", "syn,ack"),
    ] {
        let f = record("tcp", src, flags, 1);
        assert_eq!(
            verdict(&mut pipe, &f, now + 2),
            dropped("zc", "ack_flood"),
            "{flags}"
        );
    }
    // The player's connection carries on, a new player's SYN opens one, and a record that says
    // nothing of its flags is not judged.
    assert_eq!(
        verdict(&mut pipe, &record("tcp", PLAYER, "psh,ack", 1), now + 3),
        passed()
    );
    assert_eq!(
        verdict(&mut pipe, &record("tcp", "100.64.1.8", "syn", 1), now + 3),
        passed()
    );
    assert_eq!(
        verdict(&mut pipe, &record("tcp", "100.64.1.9", "", 1), now + 3),
        passed()
    );
    let st = pipe.stats(now + 4);
    assert_eq!(st["ack_flood"]["engaged"], 1, "{}", st["ack_flood"]);
    let row = st["prefixes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["prefix"] == "203.0.113.0/24")
        .unwrap()
        .clone();
    assert_eq!(row["ack_flood"]["engaged"], true, "{row}");
    // A minute after the last segment that found its second over the threshold, it lets go,
    // while the server's own traffic is seen throughout.
    let later = now + 2 + ACK_HOLD;
    watch(&mut pipe, later);
    assert_eq!(
        verdict(
            &mut pipe,
            &record("tcp", "100.64.1.11", "ack", 1),
            later - 1
        ),
        dropped("zc", "ack_flood")
    );
    assert_eq!(
        verdict(&mut pipe, &record("tcp", "100.64.1.10", "ack", 1), later),
        passed()
    );
}
#[test]
fn the_guard_waits_until_it_knows_the_connections() {
    let flood = record("tcp", "100.64.2.1", "ack", 100_000);
    // Without the server's own traffic, nothing tells a connection from none.
    let mut pipe = Pipeline::new(node(None, None));
    assert_eq!(verdict(&mut pipe, &flood, T0), passed());
    // Seen for less than the table keeps a quiet connection, some may not have shown yet.
    let mut pipe = Pipeline::new(node(None, None));
    watch(&mut pipe, T0 + 30_000);
    assert_eq!(verdict(&mut pipe, &flood, T0 + 30_000), passed());
    // A gap of more than 30 seconds in it starts the watch again.
    let mut pipe = Pipeline::new(node(None, None));
    watch(&mut pipe, T0 + ACK_WARM);
    let resumed = T0 + ACK_WARM + 40_000;
    let reply = json!({"src_ip":SERVER,"dst_ip":PLAYER,"proto":"tcp","flags":"ack","pps":1});
    pipe.observe_return(&serde_json::from_value(reply).unwrap(), resumed);
    assert_eq!(verdict(&mut pipe, &flood, resumed), passed());
}
#[test]
fn a_full_table_of_the_servers_peers_stands_the_guard_down() {
    let mut pipe = Pipeline::new(node(None, None));
    let now = T0 + ACK_WARM + 10_000;
    watch(&mut pipe, now);
    // The server answers more addresses than the table keeps: one it has a connection with may
    // be among those it could not record.
    for i in 0..65_536u32 {
        let reply = json!({"src_ip":SERVER,"dst_ip":format!("10.{}.{}.{}", i >> 16, (i >> 8) & 255, i & 255),
            "proto":"udp","pps":1});
        pipe.observe_return(&serde_json::from_value(reply).unwrap(), now);
    }
    let flood = record("tcp", "100.64.6.1", "ack", 100_000);
    assert_eq!(verdict(&mut pipe, &flood, now + 1), passed());
}
#[test]
fn a_forged_udp_query_opens_no_connection_but_a_permit_vouches() {
    let mut program = node(None, None);
    program.asic = vec![ACLEntry {
        rule_id: "monitor".into(),
        action: "permit".into(),
        r#match: Match {
            src_cidr: "198.18.0.1/32".into(),
            ..Default::default()
        },
        ..Default::default()
    }];
    let mut pipe = Pipeline::new(program);
    let now = T0 + ACK_WARM + 10_000;
    watch(&mut pipe, now);
    // The attacker forges a game query from its own address, and the server answers it over UDP.
    let answer = json!({"src_ip":SERVER,"dst_ip":"100.64.3.1","proto":"udp","sport":27015,"dport":27005,"pps":1});
    pipe.observe_return(&serde_json::from_value(answer).unwrap(), now);
    let flood = record("tcp", "100.64.3.1", "ack", 10_000);
    assert_eq!(
        verdict(&mut pipe, &flood, now + 1),
        dropped("zc", "ack_flood")
    );
    // An address the operator vouches for is not judged.
    let monitor = record("tcp", "198.18.0.1", "ack", 1);
    let d = pipe.decide(&monitor, now + 2);
    assert_eq!(
        (d.action.as_str(), d.rule_id.as_str()),
        ("permit", "monitor")
    );
}
#[test]
fn the_ack_guard_observes_holds_off_and_takes_its_threshold_from_the_policy() {
    let now = T0 + ACK_WARM + 10_000;
    let flood = record("tcp", "100.64.4.1", "ack", 10_000);
    let observe = AckFloodPolicy {
        mode: "observe".into(),
        engage_pps: 0,
        ..Default::default()
    };
    let mut pipe = Pipeline::new(node(None, Some(observe)));
    watch(&mut pipe, now);
    assert_eq!(verdict(&mut pipe, &flood, now), passed());
    let st = pipe.stats(now)["ack_flood"].clone();
    assert_eq!(
        (
            st["observed"].clone(),
            st["dropped"].clone(),
            st["engage_pps"].clone()
        ),
        (json!(1), json!(0), json!(ENGAGE_PPS))
    );
    let off = AckFloodPolicy {
        mode: "off".into(),
        engage_pps: 0,
        ..Default::default()
    };
    let mut pipe = Pipeline::new(node(None, Some(off)));
    watch(&mut pipe, now);
    assert_eq!(verdict(&mut pipe, &flood, now), passed());
    assert_eq!(pipe.stats(now)["ack_flood"]["observed"], 0);
    // A higher threshold, which the same flood stays under.
    let high = AckFloodPolicy {
        mode: String::new(),
        engage_pps: 50_000,
        ..Default::default()
    };
    let mut pipe = Pipeline::new(node(None, Some(high)));
    watch(&mut pipe, now);
    assert_eq!(verdict(&mut pipe, &flood, now), passed());
    assert_eq!(
        verdict(&mut pipe, &record("tcp", "100.64.4.2", "ack", 50_000), now),
        dropped("zc", "ack_flood")
    );
}
#[test]
fn policies_are_validated_and_reach_every_node() {
    let base = Policy {
        id: "p".into(),
        name: "game-edge".into(),
        protected: vec!["203.0.113.0/24".into()],
        ..Default::default()
    };
    let with = |protocols: Option<ProtocolPolicy>, ack: Option<AckFloodPolicy>| Policy {
        protocols,
        ack_flood: ack,
        ..base.clone()
    };
    let p = with(
        Some(ProtocolPolicy {
            mode: "observe".into(),
            allow: vec!["esp".into(), "47".into()],
        }),
        Some(AckFloodPolicy {
            mode: "enforce".into(),
            engage_pps: 20_000,
            ..Default::default()
        }),
    );
    validation::policy(&p).unwrap();
    for (bad, says) in [
        (
            with(
                Some(ProtocolPolicy {
                    mode: "block".into(),
                    allow: vec![],
                }),
                None,
            ),
            "protocols.mode",
        ),
        (
            with(
                Some(ProtocolPolicy {
                    mode: String::new(),
                    allow: vec!["quic".into()],
                }),
                None,
            ),
            "protocols.allow",
        ),
        (
            with(
                None,
                Some(AckFloodPolicy {
                    mode: "drop".into(),
                    engage_pps: 0,
                    ..Default::default()
                }),
            ),
            "ack_flood.mode",
        ),
        (
            with(
                None,
                Some(AckFloodPolicy {
                    mode: String::new(),
                    engage_pps: -1,
                    ..Default::default()
                }),
            ),
            "engage_pps",
        ),
    ] {
        let err = validation::policy(&bad).unwrap_err();
        assert!(err.contains(says), "{err}");
    }
    // Rules may name the protocols the guard knows, but not ports they do not have.
    let rule = |proto: &str, dport: i64| pathfinder::model::Rule {
        id: "r".into(),
        stage: "asic".into(),
        action: "permit".into(),
        r#match: Match {
            proto: proto.into(),
            dport,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut ok = base.clone();
    ok.rules = vec![rule("gre", 0)];
    validation::policy(&ok).unwrap();
    let mut bad = base.clone();
    bad.rules = vec![rule("gre", 1723)];
    let err = validation::policy(&bad).unwrap_err();
    assert!(err.contains("has no ports"), "{err}");
    let nodes = vec![Node {
        id: "n1".into(),
        name: "buf-1".into(),
        region: "buf".into(),
        capacity_gbps: 10.0,
        advertise: "192.0.2.1:9091".into(),
        status: "ready".into(),
        ..Default::default()
    }];
    let plan = compiler::plan(&p, &nodes, &Default::default(), &Default::default());
    let programs = compiler::compile(&p, &nodes, &plan);
    assert_eq!(
        (
            programs["n1"].protocols.clone(),
            programs["n1"].ack_flood.clone()
        ),
        (p.protocols.clone(), p.ack_flood.clone())
    );
}
#[test]
fn both_guards_are_counted_for_the_fabric_and_its_dashboards() {
    let mut pipe = Pipeline::new(node(None, None));
    pipe.decide(&wire(&v4(47, &gre())), T0);
    let now = T0 + ACK_WARM + 10_000;
    watch(&mut pipe, now);
    pipe.decide(&record("tcp", "100.64.5.1", "ack", 10_000), now);
    let stats = pipe.stats(now + 1);
    let kept = serde_json::to_value(
        serde_json::from_value::<pathfinder::wire::Stats>(stats.clone()).unwrap(),
    )
    .unwrap();
    assert_eq!(kept["protocols"], stats["protocols"]);
    assert_eq!(kept["ack_flood"], stats["ack_flood"]);
    let row = kept["prefixes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["prefix"] == "203.0.113.0/24")
        .unwrap()
        .clone();
    assert_eq!(
        row["protocols"],
        json!([{"protocol":"gre","flows":1,"dropped":1}])
    );
    assert_eq!(
        row["ack_flood"],
        json!({"engaged":true,"flows":1,"dropped":10_000})
    );
    let mut m = Metrics::new();
    m.reports(
        &[json!({"node_id":"n1","name":"buf-1","region":"buf","stats":stats})],
        now,
    );
    let text = m.render().unwrap();
    for line in [
        "scrubline_protocol_dropped_total{node=\"n1\",name=\"buf-1\",region=\"buf\",protocol=\"gre\"} 1",
        "scrubline_protocol_mode{node=\"n1\",name=\"buf-1\",region=\"buf\",mode=\"enforce\"} 1",
        "scrubline_ack_flood_dropped_total{node=\"n1\",name=\"buf-1\",region=\"buf\"} 1",
        "scrubline_ack_flood_engaged_prefixes{node=\"n1\",name=\"buf-1\",region=\"buf\"} 1",
        "scrubline_ack_flood_engage_pps{node=\"n1\",name=\"buf-1\",region=\"buf\"} 5000",
        "scrubline_ack_flood_mode{node=\"n1\",name=\"buf-1\",region=\"buf\",mode=\"off\"} 0",
        "scrubline_prefix_ack_flood_engaged{node=\"n1\",name=\"buf-1\",region=\"buf\",prefix=\"203.0.113.0/24\"} 1",
    ] {
        assert!(text.contains(line), "{line}\n{text}");
    }
}
