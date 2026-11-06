//! Answers reflected at a protected address. CLDAP answers are built here as a datapath hands
//! them over, whole and in fragments, and dropped; what only looks like one, an answer the server
//! asked for, and an address an operator vouches for, are passed.
use base64::{engine::general_purpose::STANDARD, Engine};
use pathfinder::{
    compiler,
    model::{ACLEntry, Flow, Match, Node, NodeTunnel, Policy, Program, ReflectionPolicy},
    pipeline::Pipeline,
    reflection::{ASKED_WITHIN, REFLECTING_FOR, SOURCES_MAX},
    telemetry::Metrics,
    validation,
};
use serde_json::json;

const T0: i64 = 1767225600000;
const UDP: u8 = 17;
/// A domain controller somewhere on the internet, and the game server it is aimed at.
const DC: [u8; 4] = [198, 18, 7, 7];
const SERVER: [u8; 4] = [203, 0, 113, 10];

fn seal(p: &mut [u8]) {
    let ihl = usize::from(p[0] & 0x0f) * 4;
    p[10] = 0;
    p[11] = 0;
    let mut s: u32 = p[..ihl]
        .chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], c[1]])))
        .sum();
    while s > 0xffff {
        s = (s & 0xffff) + (s >> 16);
    }
    p[10..12].copy_from_slice(&(!(s as u16)).to_be_bytes());
}
/// An IPv4 packet carrying `l4`: a whole datagram, or with `offset` and `more` one fragment of
/// datagram `id`.
fn v4(src: [u8; 4], proto: u8, l4: &[u8], id: u16, offset: u16, more: bool) -> Vec<u8> {
    let mut p = vec![0x45, 0];
    p.extend((20 + l4.len() as u16).to_be_bytes());
    p.extend(id.to_be_bytes());
    p.extend(((offset / 8) | if more { 0x2000 } else { 0 }).to_be_bytes());
    p.extend([64, proto, 0, 0]);
    p.extend(src);
    p.extend(SERVER);
    p.extend(l4);
    seal(&mut p);
    p
}
fn udp(sport: u16, dport: u16, total: usize, data: &[u8]) -> Vec<u8> {
    let mut u = Vec::new();
    u.extend(sport.to_be_bytes());
    u.extend(dport.to_be_bytes());
    u.extend((8 + total as u16).to_be_bytes());
    u.extend([0, 0]);
    u.extend(data);
    u
}
/// A domain controller's answer to a rootDSE query, as long as Active Directory's run: a
/// searchResEntry, its lengths written in four bytes.
fn answer() -> Vec<u8> {
    let mut a = vec![
        0x30, 0x84, 0x00, 0x00, 0x0b, 0xb0, 0x02, 0x01, 0x01, 0x64, 0x84,
    ];
    a.resize(3_000, 0x04);
    a
}
/// The answer as it arrives at the game server's port over a link of 1500 bytes: a first
/// fragment with the UDP header and the answer's opening, and the two after it with the rest.
fn fragments(src: [u8; 4], id: u16) -> [Vec<u8>; 3] {
    let a = answer();
    let first = udp(389, 27015, a.len(), &a[..1472]);
    [
        v4(src, UDP, &first, id, 0, true),
        v4(src, UDP, &a[1472..2952], id, 1480, true),
        v4(src, UDP, &a[2952..], id, 2960, false),
    ]
}
fn wire(bytes: &[u8]) -> Flow {
    serde_json::from_value(json!({ "packet": STANDARD.encode(bytes) })).unwrap()
}
/// A flow record as a datapath that summarises posts one, with or without its payload.
fn record(proto: &str, src: &str, sport: i64, dport: i64, payload: Option<&[u8]>) -> Flow {
    let mut f = json!({"src_ip":src,"dst_ip":"203.0.113.10","proto":proto,"sport":sport,"dport":dport,"pps":50_000});
    if let Some(p) = payload {
        f["payload"] = json!(STANDARD.encode(p));
    }
    serde_json::from_value(f).unwrap()
}
fn node(mode: &str) -> Program {
    Program {
        prefixes: vec!["203.0.113.0/24".into(), "198.51.100.0/24".into()],
        reflection: Some(ReflectionPolicy { cldap: mode.into() }),
        ..Default::default()
    }
}
fn verdict(pipe: &mut Pipeline, f: &Flow, at: i64) -> (String, String, String) {
    let d = pipe.decide(f, at);
    (d.action, d.stage, d.reflection)
}
fn dropped(stage: &str) -> (String, String, String) {
    ("drop".into(), stage.into(), "cldap".into())
}

#[test]
fn a_reflected_cldap_answer_is_dropped_and_the_rest_of_it_with_it() {
    let mut pipe = Pipeline::new(node(""));
    let [first, second, last] = fragments(DC, 0x4242);
    let d = pipe.decide(&wire(&first), T0);
    assert_eq!(
        (d.action.as_str(), d.stage.as_str(), d.reflection.as_str()),
        ("drop", "asic", "cldap")
    );
    assert!(d.reason.starts_with("CLDAP reflection: "), "{}", d.reason);
    // The later fragments carry no port, but come from a source caught reflecting.
    assert_eq!(verdict(&mut pipe, &wire(&second), T0 + 1), dropped("zc"));
    assert_eq!(verdict(&mut pipe, &wire(&last), T0 + 2), dropped("zc"));
    // Every answer the reflector sends after is dropped the same way, the first fragment by its
    // port and the rest by its source, until it has been quiet as long as a host holds fragments.
    let [first, second, _] = fragments(DC, 0x4243);
    let at = T0 + REFLECTING_FOR - 1;
    assert_eq!(verdict(&mut pipe, &wire(&first), at), dropped("asic"));
    assert_eq!(
        verdict(&mut pipe, &wire(&second), at + REFLECTING_FOR - 1),
        dropped("zc")
    );
    let (action, ..) = verdict(&mut pipe, &wire(&second), at + REFLECTING_FOR);
    assert_eq!(action, "permit");
    // A fragment from a source never caught reflecting is no one's answer.
    let [_, stranger, _] = fragments([198, 18, 9, 9], 0x4242);
    assert_eq!(pipe.decide(&wire(&stranger), T0 + 3).action, "permit");
    let v = &pipe.stats(T0 + 4)["reflection"];
    assert_eq!(v["vectors"][0]["dropped"], 2, "{v}");
    assert_eq!(v["vectors"][0]["fragments"], 3, "{v}");
    assert_eq!(v["sources"], 1, "{v}");
}
#[test]
fn whatever_only_looks_like_cldap_is_not_touched() {
    let mut pipe = Pipeline::new(node(""));
    // A player whose NAT mapped them to port 389, sending the game's own packets.
    let game = [0xff, 0xff, 0xff, 0xff, 0x54, 0x53, 0x6f, 0x75];
    let nat = v4(
        [192, 0, 2, 40],
        UDP,
        &udp(389, 27015, game.len(), &game),
        1,
        0,
        false,
    );
    assert_eq!(pipe.decide(&wire(&nat), T0).action, "permit");
    let src = "192.0.2.41";
    let rec = record("udp", src, 389, 27015, Some(&game));
    assert_eq!(pipe.decide(&rec, T0).action, "permit");
    // LDAP over TCP: the server's own connection to a directory, which answers from 389.
    let tcp = record("tcp", src, 389, 50123, Some(&answer()[..64]));
    assert_eq!(pipe.decide(&tcp, T0).action, "permit");
    // A query to a directory the customer runs, which arrives at 389 rather than from it.
    let query = record(
        "udp",
        src,
        50123,
        389,
        Some(&[0x30, 0x25, 0x02, 0x01, 0x01, 0x63]),
    );
    assert_eq!(pipe.decide(&query, T0).action, "permit");
    // An address no prefix of the node's covers is not its to judge.
    let elsewhere = json!({"src_ip":"198.18.7.7","dst_ip":"192.0.2.99","proto":"udp","sport":389,"dport":27015,"pps":1});
    let elsewhere: Flow = serde_json::from_value(elsewhere).unwrap();
    assert_eq!(pipe.decide(&elsewhere, T0).reflection, "");
    // A record that carries no payload has only its port to go by.
    let bare = record("udp", "198.18.7.8", 389, 27015, None);
    assert_eq!(verdict(&mut pipe, &bare, T0), dropped("asic"));
    // With its payload, an answer is an answer whichever record it comes in.
    let full = record("udp", "198.18.7.9", 389, 27015, Some(&answer()));
    assert_eq!(verdict(&mut pipe, &full, T0), dropped("asic"));
}
#[test]
fn an_answer_the_server_asked_for_is_let_through() {
    let mut pipe = Pipeline::new(node(""));
    // The game server sends its CLDAP ping to its domain controller, which the node sees on
    // the way back up the tunnel, and the controller answers.
    let ping = search_from_server(
        "198.18.7.7",
        389,
        &[0x30, 0x84, 0, 0, 0, 0x7c, 0x02, 0x01, 0x01, 0x63],
    );
    pipe.observe_return(&ping, T0);
    let [first, second, _] = fragments(DC, 7);
    assert_eq!(pipe.decide(&wire(&first), T0 + 100).action, "permit");
    // Nor is the source caught reflecting, so the rest of the answer passes too.
    assert_eq!(pipe.decide(&wire(&second), T0 + 101).action, "permit");
    assert_eq!(pipe.stats(T0)["reflection"]["vectors"][0]["asked"], 1);
    // Another controller's answer, or the same one long after, is no answer to anything.
    let [other, ..] = fragments([198, 18, 7, 8], 8);
    assert_eq!(verdict(&mut pipe, &wire(&other), T0 + 200), dropped("asic"));
    let [late, ..] = fragments(DC, 9);
    let at = T0 + ASKED_WITHIN;
    assert_eq!(verdict(&mut pipe, &wire(&late), at), dropped("asic"));
}
/// What the game server sends `to`, seen on its way back up the tunnel.
fn search_from_server(to: &str, dport: i64, payload: &[u8]) -> Flow {
    serde_json::from_value(
        json!({"src_ip":"203.0.113.10","dst_ip":to,"proto":"udp","sport":27015,
        "dport":dport,"pps":1,"payload":STANDARD.encode(payload)}),
    )
    .unwrap()
}
#[test]
fn a_forged_query_cannot_make_the_server_ask_for_an_answer() {
    let mut pipe = Pipeline::new(node(""));
    // The attacker forges game queries from each reflector's address, the reflector's port 389
    // among them, and the game server answers each: its answers are no LDAP search.
    let info = [0xff, 0xff, 0xff, 0xff, 0x49, 0x11, 0x47, 0x61];
    pipe.observe_return(&search_from_server("198.18.7.7", 27005, &info), T0);
    pipe.observe_return(&search_from_server("198.18.7.7", 389, &info), T0);
    let [first, ..] = fragments(DC, 11);
    assert_eq!(verdict(&mut pipe, &wire(&first), T0 + 100), dropped("asic"));
    assert_eq!(pipe.stats(T0)["reflection"]["vectors"][0]["asked"], 0);
}
#[test]
fn an_operator_permit_vouches_for_its_directory_but_trust_and_the_box_do_not() {
    let mut program = node("");
    program.asic = vec![ACLEntry {
        rule_id: "our-dc".into(),
        action: "permit".into(),
        r#match: Match {
            src_cidr: "198.18.7.7/32".into(),
            ..Default::default()
        },
        ..Default::default()
    }];
    let mut pipe = Pipeline::new(program);
    let [first, second, _] = fragments(DC, 1);
    assert_eq!(pipe.decide(&wire(&first), T0).action, "permit");
    assert_eq!(pipe.decide(&wire(&second), T0 + 1).action, "permit");
    // A source the node trusts as a player is still no reflector's alibi: a reflector is not a
    // player.
    let src = [198, 18, 7, 20];
    pipe.reputation.promote("198.18.7.20", 3, T0);
    let [first, ..] = fragments(src, 2);
    assert_eq!(verdict(&mut pipe, &wire(&first), T0 + 2), dropped("asic"));
    // And a reflection drop is no strike: the reflector is somebody's server, put to work.
    let r = &pipe.stats(T0 + 3)["reputation"];
    assert_eq!(
        (r["strikes"].clone(), r["penalised"].clone()),
        (json!(0), json!(0)),
        "{r}"
    );
}
#[test]
fn an_idle_on_demand_tunnel_passes_it_until_mitigation_starts() {
    let mut program = node("");
    program.tunnels = vec![NodeTunnel {
        id: "contoso".into(),
        prefixes: vec!["198.51.100.0/24".into()],
        mitigation: "on_demand".into(),
        attack_pps: 1_000_000,
        attack_kbps: 1_000_000,
        ..Default::default()
    }];
    let mut pipe = Pipeline::new(program);
    let mut f = record("udp", "198.18.7.7", 389, 27015, Some(&answer()));
    f.dst_ip = "198.51.100.10".into();
    f.pps = 10;
    assert_eq!(pipe.decide(&f, T0).action, "permit");
    // At the tunnel's thresholds it is mitigated, and the guard with it.
    f.pps = 2_000_000;
    assert_eq!(verdict(&mut pipe, &f, T0 + 1), dropped("asic"));
}
#[test]
fn observing_counts_what_would_be_dropped_and_off_does_not_look() {
    let mut pipe = Pipeline::new(node("observe"));
    let [first, second, _] = fragments(DC, 3);
    assert_eq!(pipe.decide(&wire(&first), T0).action, "permit");
    assert_eq!(pipe.decide(&wire(&second), T0 + 1).action, "permit");
    let v = pipe.stats(T0)["reflection"]["vectors"][0].clone();
    assert_eq!(
        (
            v["mode"].clone(),
            v["observed"].clone(),
            v["dropped"].clone()
        ),
        (json!("observe"), json!(2), json!(0))
    );
    let mut pipe = Pipeline::new(node("off"));
    assert_eq!(pipe.decide(&wire(&first), T0).action, "permit");
    assert_eq!(pipe.decide(&wire(&second), T0 + 1).action, "permit");
    let st = pipe.stats(T0);
    let v = &st["reflection"];
    assert_eq!(
        (v["vectors"][0]["observed"].clone(), v["sources"].clone()),
        (json!(0), json!(0))
    );
    // A program from before the guard has it on.
    let mut pipe = Pipeline::new(Program {
        prefixes: vec!["203.0.113.0/24".into()],
        ..Default::default()
    });
    assert_eq!(verdict(&mut pipe, &wire(&first), T0), dropped("asic"));
}
#[test]
fn a_flood_of_reflectors_costs_the_node_a_bounded_table() {
    let mut pipe = Pipeline::new(node(""));
    let a = answer();
    for i in 0..SOURCES_MAX + 10 {
        let src = [100, 64 + (i >> 16) as u8, (i >> 8) as u8, i as u8];
        let p = v4(src, UDP, &udp(389, 27015, a.len(), &a[..256]), 1, 0, true);
        pipe.decide(&wire(&p), T0);
    }
    let v = &pipe.stats(T0)["reflection"];
    assert_eq!(v["sources"], SOURCES_MAX, "{v}");
    assert_eq!(v["sources_untracked"], 10, "{v}");
    assert_eq!(v["vectors"][0]["dropped"], SOURCES_MAX + 10, "{v}");
}
#[test]
fn policies_are_validated_and_reach_every_node() {
    let policy = |mode: &str| Policy {
        id: "p".into(),
        name: "game-edge".into(),
        protected: vec!["203.0.113.0/24".into()],
        reflection: Some(ReflectionPolicy { cldap: mode.into() }),
        ..Default::default()
    };
    for mode in ["", "enforce", "observe", "off"] {
        validation::policy(&policy(mode)).unwrap();
    }
    let err = validation::policy(&policy("block")).unwrap_err();
    assert!(err.contains("reflection.cldap"), "{err}");
    let nodes = vec![Node {
        id: "n1".into(),
        name: "buf-1".into(),
        region: "buf".into(),
        capacity_gbps: 10.0,
        advertise: "192.0.2.1:9091".into(),
        status: "ready".into(),
        ..Default::default()
    }];
    let p = policy("observe");
    let plan = compiler::plan(&p, &nodes, &Default::default(), &Default::default());
    let programs = compiler::compile(&p, &nodes, &plan);
    assert_eq!(programs["n1"].reflection, p.reflection);
}
#[test]
fn the_guard_is_counted_for_the_fabric_and_its_dashboards() {
    let mut pipe = Pipeline::new(node(""));
    for (i, f) in fragments(DC, 5).iter().enumerate() {
        pipe.decide(&wire(f), T0 + i as i64);
    }
    let stats = pipe.stats(T0 + 10);
    let kept = serde_json::to_value(
        serde_json::from_value::<pathfinder::wire::Stats>(stats.clone()).unwrap(),
    )
    .unwrap();
    assert_eq!(kept["reflection"], stats["reflection"]);
    let row = kept["prefixes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["prefix"] == "203.0.113.0/24")
        .unwrap();
    assert_eq!(
        row["reflection"],
        json!([{"vector":"cldap","flows":3,"dropped":3}])
    );
    let mut m = Metrics::new();
    m.reports(
        &[json!({"node_id":"n1","name":"buf-1","region":"buf","stats":stats})],
        T0,
    );
    let text = m.render().unwrap();
    for line in [
        "scrubline_reflection_dropped_total{node=\"n1\",name=\"buf-1\",region=\"buf\",vector=\"cldap\"} 1",
        "scrubline_reflection_fragments_dropped_total{node=\"n1\",name=\"buf-1\",region=\"buf\",vector=\"cldap\"} 2",
        "scrubline_reflection_asked_total{node=\"n1\",name=\"buf-1\",region=\"buf\",vector=\"cldap\"} 0",
        "scrubline_reflection_mode{node=\"n1\",name=\"buf-1\",region=\"buf\",vector=\"cldap\",mode=\"enforce\"} 1",
        "scrubline_reflection_mode{node=\"n1\",name=\"buf-1\",region=\"buf\",vector=\"cldap\",mode=\"off\"} 0",
        "scrubline_reflection_sources{node=\"n1\",name=\"buf-1\",region=\"buf\"} 1",
        "scrubline_reflection_sources_max{node=\"n1\",name=\"buf-1\",region=\"buf\"} 65536",
    ] {
        assert!(text.contains(line), "{line}\n{text}");
    }
}
