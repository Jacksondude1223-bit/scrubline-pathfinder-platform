//! The floods booters sell beside UDP and reflection: SYN floods from forged sources, fragmented
//! ACK and ICMP floods, ping floods, Smurf's echo replies and BlackNurse's forged errors, SYN-ACK
//! and RST/FIN floods, fake sessions, IP NULL, and any of them spread thin across addresses
//! protected one by one. Each is built here as a datapath hands it over and dropped; what a real
//! client, a real router and the server's own traffic send passes.
use base64::{engine::general_purpose::STANDARD, Engine};
use pathfinder::{
    analytics::Collector,
    compiler,
    guards::{ACK_WARM, HANDSHAKE_SEGMENTS, ICMP_LIMIT_PPS, SMURF_HOLD, SYN_ENGAGE_PPS, SYN_HOLD},
    model::{ACLEntry, FragmentPolicy, IcmpPolicy, Match, Node, Policy, Program, SynFloodPolicy},
    pipeline::Pipeline,
    telemetry::Metrics,
    validation,
};
use serde_json::json;
use std::net::Ipv6Addr;

const T0: i64 = 1767225600000;
const TCP: u8 = 6;
const UDP: u8 = 17;
const ICMP: u8 = 1;
const ICMPV6: u8 = 58;
const SERVER: [u8; 4] = [203, 0, 113, 10];
const CLIENT: [u8; 4] = [192, 0, 2, 1];
const SERVER6: &str = "2001:db8:100::10";
const CLIENT6: &str = "2001:db8:ffff::1";

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
/// An IPv4 packet carrying `l4`, whole, or as the piece of datagram `id` at `offset`.
fn v4(src: [u8; 4], dst: [u8; 4], proto: u8, l4: &[u8], offset: u16, more: bool) -> Vec<u8> {
    let mut p = vec![0x45, 0];
    p.extend((20 + l4.len() as u16).to_be_bytes());
    p.extend([0x12, 0x34]);
    p.extend(((offset / 8) | if more { 0x2000 } else { 0 }).to_be_bytes());
    p.extend([64, proto, 0, 0]);
    p.extend(src);
    p.extend(dst);
    p.extend(l4);
    seal(&mut p);
    p
}
fn v6(src: &str, dst: &str, next: u8, rest: &[u8]) -> Vec<u8> {
    let mut p = vec![0x60, 0, 0, 0];
    p.extend((rest.len() as u16).to_be_bytes());
    p.extend([next, 64]);
    p.extend(src.parse::<Ipv6Addr>().unwrap().octets());
    p.extend(dst.parse::<Ipv6Addr>().unwrap().octets());
    p.extend(rest);
    p
}
/// An IPv6 fragment header and the piece of datagram 7 after it.
fn frag6(next: u8, offset: u16, more: bool, piece: &[u8]) -> Vec<u8> {
    let mut h = vec![next, 0];
    h.extend((offset | u16::from(more)).to_be_bytes());
    h.extend(7u32.to_be_bytes());
    h.extend(piece);
    h
}
fn tcp(sport: u16, dport: u16, flags: u8, data: &[u8]) -> Vec<u8> {
    let mut t = Vec::new();
    t.extend(sport.to_be_bytes());
    t.extend(dport.to_be_bytes());
    t.extend([0, 0, 0, 1, 0, 0, 0, 1, 0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
    t.extend(data);
    t
}
fn icmp(kind: u8, code: u8, data: &[u8]) -> Vec<u8> {
    let mut m = vec![kind, code, 0, 0, 0, 0, 0, 0];
    m.extend(data);
    m
}
const ACK: u8 = 0x10;
const PSH: u8 = 0x08;
fn wire(bytes: &[u8], pps: i64) -> pathfinder::model::Flow {
    serde_json::from_value(json!({ "packet": STANDARD.encode(bytes), "pps": pps })).unwrap()
}
fn record(
    proto: &str,
    src: &str,
    dst: &str,
    sport: i64,
    flags: &str,
    pps: i64,
) -> pathfinder::model::Flow {
    serde_json::from_value(
        json!({"src_ip":src,"dst_ip":dst,"proto":proto,"sport":sport,
        "dport":443,"flags":flags,"pps":pps}),
    )
    .unwrap()
}
fn syn(src: &str, sport: i64, pps: i64) -> pathfinder::model::Flow {
    record("tcp", src, "203.0.113.10", sport, "syn", pps)
}
fn node() -> Program {
    Program {
        prefixes: vec!["203.0.113.0/24".into(), "2001:db8:100::/48".into()],
        ..Default::default()
    }
}
fn verdict(pipe: &mut Pipeline, f: &pathfinder::model::Flow, at: i64) -> (String, String) {
    let d = pipe.decide(f, at);
    (d.action, d.guard)
}
fn dropped(guard: &str) -> (String, String) {
    ("drop".into(), guard.into())
}
fn passed() -> (String, String) {
    ("permit".into(), String::new())
}
/// The server's own traffic seen on its way out: `flags` to `to`, from its port 443.
fn sent(pipe: &mut Pipeline, to: &str, flags: &str, at: i64) {
    let f = json!({"src_ip":"203.0.113.10","dst_ip":to,"proto":"tcp","sport":443,
        "dport":40000,"flags":flags,"pps":1});
    pipe.observe_return(&serde_json::from_value(f).unwrap(), at);
}

#[test]
fn a_syn_flood_from_forged_sources_is_held_back_and_a_real_client_retries_through() {
    let mut pipe = Pipeline::new(node());
    // Under the threshold, a busy moment's SYNs pass, retries or not.
    assert_eq!(
        verdict(&mut pipe, &syn("100.64.0.1", 40000, 1500), T0),
        passed()
    );
    // Over it, the guard engages: the SYN that took the second over is held back, and so is
    // every first SYN from a source the server has no connection with.
    let t = T0 + 10_000;
    assert_eq!(
        verdict(
            &mut pipe,
            &syn("100.64.0.2", 40000, SYN_ENGAGE_PPS as i64 + 1),
            t
        ),
        dropped("syn_flood")
    );
    for i in 0..50 {
        let forged = syn(&format!("100.64.1.{i}"), 1024 + i, 1);
        assert_eq!(verdict(&mut pipe, &forged, t + 1), dropped("syn_flood"));
    }
    let d = pipe.decide(&syn("100.64.2.1", 40001, 1), t + 2);
    assert!(d.reason.starts_with("SYN flood: "), "{}", d.reason);
    assert_eq!(d.stage, "zc");
    // A real client's stack sends its SYN again a second on: that passes, the first did not.
    let client = syn("192.0.2.77", 51000, 1);
    assert_eq!(verdict(&mut pipe, &client, t + 100), dropped("syn_flood"));
    assert_eq!(verdict(&mut pipe, &client, t + 1_100), passed());
    // A retry that comes again on another port is another connection, which waits its turn.
    assert_eq!(
        verdict(&mut pipe, &syn("192.0.2.77", 51001, 1), t + 1_100),
        dropped("syn_flood")
    );
    // A record of more SYNs a second on one connection than a client retries is no client.
    let burst = syn("100.64.3.1", 40000, 500);
    assert_eq!(verdict(&mut pipe, &burst, t + 200), dropped("syn_flood"));
    assert_eq!(verdict(&mut pipe, &burst, t + 1_200), dropped("syn_flood"));
    // A source the server is talking TCP to, one it has verified, and one an operator's permit
    // names open connections as they like.
    sent(&mut pipe, "192.0.2.80", "psh,ack", t);
    assert_eq!(
        verdict(&mut pipe, &syn("192.0.2.80", 52000, 1), t + 300),
        passed()
    );
    pipe.reputation.promote("192.0.2.81", 3, t);
    assert_eq!(
        verdict(&mut pipe, &syn("192.0.2.81", 52000, 1), t + 300),
        passed()
    );
    let mut program = node();
    program.asic = vec![ACLEntry {
        rule_id: "monitor".into(),
        action: "permit".into(),
        r#match: Match {
            src_cidr: "198.18.0.1/32".into(),
            ..Default::default()
        },
        ..Default::default()
    }];
    pipe.load(program);
    let d = pipe.decide(&syn("198.18.0.1", 52000, 1), t + 400);
    assert_eq!(
        (d.action.as_str(), d.rule_id.as_str()),
        ("permit", "monitor")
    );
    let st = pipe.stats(t + 2_000);
    let g = &st["syn_flood"];
    assert_eq!(
        (g["engaged"].clone(), g["retried"].clone()),
        (json!(1), json!(1)),
        "{g}"
    );
    assert_eq!(g["dropped"], 56, "{g}");
    let row = st["prefixes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["prefix"] == "203.0.113.0/24")
        .unwrap()
        .clone();
    assert_eq!(row["syn_flood"]["engaged"], true, "{row}");
    // A minute after the last second over the threshold, it lets go.
    let quiet = t + 1_200 + SYN_HOLD;
    assert_eq!(
        verdict(&mut pipe, &syn("100.64.4.1", 40000, 1), quiet),
        passed()
    );
}
#[test]
fn the_syn_guard_observes_holds_off_and_takes_its_threshold_from_the_policy() {
    let with = |mode: &str, engage_pps: i64| {
        Pipeline::new(Program {
            syn_flood: Some(SynFloodPolicy {
                mode: mode.into(),
                engage_pps,
            }),
            ..node()
        })
    };
    let flood = syn("100.64.0.9", 40000, 3000);
    let mut pipe = with("observe", 0);
    assert_eq!(verdict(&mut pipe, &flood, T0), passed());
    assert_eq!(pipe.stats(T0)["syn_flood"]["observed"], 1);
    let mut pipe = with("off", 0);
    assert_eq!(verdict(&mut pipe, &flood, T0), passed());
    assert_eq!(pipe.stats(T0)["syn_flood"]["observed"], 0);
    let mut pipe = with("", 10_000);
    assert_eq!(verdict(&mut pipe, &flood, T0), passed());
    assert_eq!(pipe.stats(T0)["syn_flood"]["engage_pps"], 10_000);
    assert_eq!(
        verdict(&mut pipe, &syn("100.64.0.9", 40000, 8000), T0),
        dropped("syn_flood")
    );
}
#[test]
fn tcp_and_icmp_in_fragments_are_dropped_and_udp_in_fragments_is_not() {
    let mut pipe = Pipeline::new(node());
    // A fragmented ACK flood: 1,500-byte ACKs split in two, as booters send them.
    let ack = tcp(40000, 443, ACK, &[0x41; 2000]);
    let first = v4(CLIENT, SERVER, TCP, &ack[..1480], 0, true);
    let rest = v4(CLIENT, SERVER, TCP, &ack[1480..], 1480, false);
    let d = pipe.decide(&wire(&first, 1), T0);
    assert_eq!(
        (d.action.as_str(), d.guard.as_str(), d.stage.as_str()),
        ("drop", "fragment", "asic")
    );
    assert!(
        d.reason.starts_with("fragmented ACK flood: "),
        "{}",
        d.reason
    );
    assert_eq!(verdict(&mut pipe, &wire(&rest, 1), T0), dropped("fragment"));
    // An ICMP fragmentation flood: echo requests too large for one packet.
    let ping = icmp(8, 0, &[0x61; 3000]);
    let first = v4(CLIENT, SERVER, ICMP, &ping[..1480], 0, true);
    let d = pipe.decide(&wire(&first, 1), T0);
    assert!(
        d.reason.starts_with("ICMP fragmentation flood: "),
        "{}",
        d.reason
    );
    let later = v4(CLIENT, SERVER, ICMP, &ping[1480..2960], 1480, true);
    assert_eq!(
        verdict(&mut pipe, &wire(&later, 1), T0),
        dropped("fragment")
    );
    // IPv6 says so in its fragment header.
    let ack6 = tcp(40000, 443, ACK, &[0x41; 2000]);
    let first6 = v6(CLIENT6, SERVER6, 44, &frag6(TCP, 0, true, &ack6[..1232]));
    assert_eq!(
        verdict(&mut pipe, &wire(&first6, 1), T0),
        dropped("fragment")
    );
    let ping6 = icmp(128, 0, &[0x61; 2000]);
    let later6 = v6(
        CLIENT6,
        SERVER6,
        44,
        &frag6(ICMPV6, 1232, false, &ping6[1232..]),
    );
    assert_eq!(
        verdict(&mut pipe, &wire(&later6, 1), T0),
        dropped("fragment")
    );
    // A game's large datagram is fragmented, as UDP may be; and a whole segment is no fragment.
    let datagram = [0x09; 3000];
    let mut udp = vec![0xd4, 0x31, 0x4a, 0xbc];
    udp.extend((8 + datagram.len() as u16).to_be_bytes());
    udp.extend([0, 0]);
    udp.extend(datagram);
    let first = v4(CLIENT, SERVER, UDP, &udp[..1480], 0, true);
    assert_eq!(verdict(&mut pipe, &wire(&first, 1), T0), passed());
    let whole = v4(
        CLIENT,
        SERVER,
        TCP,
        &tcp(40000, 443, ACK | PSH, &[1; 100]),
        0,
        false,
    );
    assert_eq!(verdict(&mut pipe, &wire(&whole, 1), T0), passed());
    // The last fragment of an ACK, as docs/api.md sends it.
    let doc = "RQAAPACZALlABs/iZEAJPcsAcQpBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB";
    let d = pipe.decide(&serde_json::from_value(json!({"packet": doc})).unwrap(), T0);
    assert_eq!(
        (d.action.as_str(), d.stage.as_str(), d.guard.as_str()),
        ("drop", "asic", "fragment"),
        "{}",
        d.reason
    );
    let st = pipe.stats(T0)["fragments"].clone();
    assert_eq!(st["dropped"], 7, "{st}");
    assert_eq!(
        st["by_protocol"],
        json!([{"protocol":"tcp","dropped":4,"observed":0},{"protocol":"icmp","dropped":3,"observed":0}])
    );
    // Observing counts what enforcing would drop; off does not look.
    let first = v4(CLIENT, SERVER, TCP, &ack[..1480], 0, true);
    for (mode, observed) in [("observe", 1), ("off", 0)] {
        let mut pipe = Pipeline::new(Program {
            fragments: Some(FragmentPolicy { mode: mode.into() }),
            ..node()
        });
        assert_eq!(verdict(&mut pipe, &wire(&first, 1), T0), passed());
        assert_eq!(pipe.stats(T0)["fragments"]["observed"], observed, "{mode}");
    }
}
/// What an error quotes of the packet it is about: an IPv4 header and the first eight bytes after
/// it, from `src`.
fn quote4(src: [u8; 4]) -> Vec<u8> {
    v4(
        src,
        CLIENT,
        TCP,
        &tcp(443, 40000, ACK | PSH, &[1; 1400]),
        0,
        false,
    )[..28]
        .to_vec()
}
#[test]
fn icmp_is_held_to_a_rate_and_echo_replies_and_errors_to_what_the_server_sent() {
    let mut pipe = Pipeline::new(node());
    // A ping flood: the aggregate takes its rate, and the rest is dropped.
    let pings = record("icmp", "100.64.5.1", "203.0.113.10", 0, "", 800);
    assert_eq!(verdict(&mut pipe, &pings, T0), passed());
    let more = record("icmp", "100.64.5.2", "203.0.113.20", 0, "", 300);
    let d = pipe.decide(&more, T0 + 100);
    assert_eq!((d.action.as_str(), d.guard.as_str()), ("drop", "icmp"));
    assert_eq!(
        d.reason,
        format!("ICMP flood: more than {ICMP_LIMIT_PPS} ICMP packets a second to the prefix, echo replies aside")
    );
    // A new second starts the count over.
    assert_eq!(verdict(&mut pipe, &more, T0 + 1_000), passed());
    // Smurf: echo replies to pings the server never sent, a flood of them.
    let reply = v4(
        [198, 18, 0, 255],
        SERVER,
        ICMP,
        &icmp(0, 0, &[0x61; 56]),
        0,
        false,
    );
    assert_eq!(verdict(&mut pipe, &wire(&reply, 10), T0 + 2_000), passed());
    let d = pipe.decide(&wire(&reply, 5_000), T0 + 2_001);
    assert_eq!((d.action.as_str(), d.guard.as_str()), ("drop", "icmp"));
    assert!(d.reason.starts_with("Smurf: "), "{}", d.reason);
    // While it lasts, a reply to a ping the server did send still passes.
    let ping = v4(
        SERVER,
        [198, 51, 200, 1],
        ICMP,
        &icmp(8, 0, &[0x61; 56]),
        0,
        false,
    );
    pipe.observe_return(&wire(&ping, 1), T0 + 2_100);
    let answer = v4(
        [198, 51, 200, 1],
        SERVER,
        ICMP,
        &icmp(0, 0, &[0x61; 56]),
        0,
        false,
    );
    assert_eq!(verdict(&mut pipe, &wire(&answer, 1), T0 + 2_200), passed());
    assert_eq!(
        verdict(&mut pipe, &wire(&reply, 1), T0 + 2_200),
        dropped("icmp")
    );
    // The hold runs from the last reply in a second over the threshold.
    assert_eq!(
        verdict(&mut pipe, &wire(&reply, 1), T0 + 2_200 + SMURF_HOLD - 1),
        dropped("icmp")
    );
    assert_eq!(
        verdict(&mut pipe, &wire(&reply, 1), T0 + 2_200 + SMURF_HOLD),
        passed()
    );
    // An error quotes the packet it is about: one about the server's own passes, one about a
    // packet the prefix never sent is forged, as BlackNurse floods with.
    let real = v4(
        [198, 51, 200, 9],
        SERVER,
        ICMP,
        &icmp(3, 4, &quote4(SERVER)),
        0,
        false,
    );
    assert_eq!(verdict(&mut pipe, &wire(&real, 1), T0 + 3_000), passed());
    for quote in [quote4([10, 9, 8, 7]), vec![0; 28], vec![]] {
        let forged = v4(
            [198, 51, 200, 9],
            SERVER,
            ICMP,
            &icmp(3, 3, &quote),
            0,
            false,
        );
        let d = pipe.decide(&wire(&forged, 1), T0 + 3_000);
        assert_eq!(
            (d.action.as_str(), d.guard.as_str(), d.stage.as_str()),
            ("drop", "icmp", "asic")
        );
        assert!(d.reason.starts_with("forged ICMP error: "), "{}", d.reason);
    }
    let quote6 = v6(
        SERVER6,
        CLIENT6,
        TCP,
        &tcp(443, 40000, ACK | PSH, &[1; 1400]),
    )[..1232]
        .to_vec();
    let too_big = v6(CLIENT6, SERVER6, ICMPV6, &icmp(2, 0, &quote6));
    assert_eq!(verdict(&mut pipe, &wire(&too_big, 1), T0 + 3_000), passed());
    let forged6 = v6(CLIENT6, SERVER6, ICMPV6, &icmp(1, 4, &[0; 48]));
    assert_eq!(
        verdict(&mut pipe, &wire(&forged6, 1), T0 + 3_000),
        dropped("icmp")
    );
    let st = pipe.stats(T0 + 3_000)["icmp"].clone();
    assert_eq!(
        st["kinds"],
        json!([
            {"kind":"flood","dropped":1,"observed":0},
            {"kind":"smurf","dropped":3,"observed":0},
            {"kind":"error","dropped":4,"observed":0}
        ]),
        "{st}"
    );
    // The policy sets the rates, and an operator's permit vouches for what it covers.
    let mut program = Program {
        icmp: Some(IcmpPolicy {
            limit_pps: 100_000,
            ..Default::default()
        }),
        ..node()
    };
    program.asic = vec![ACLEntry {
        rule_id: "probe".into(),
        action: "permit".into(),
        r#match: Match {
            proto: "icmp".into(),
            src_cidr: "198.18.0.1/32".into(),
            ..Default::default()
        },
        ..Default::default()
    }];
    let mut pipe = Pipeline::new(program);
    assert_eq!(
        verdict(
            &mut pipe,
            &record("icmp", "100.64.5.1", "203.0.113.10", 0, "", 50_000),
            T0
        ),
        passed()
    );
    let forged = v4(
        [198, 18, 0, 1],
        SERVER,
        ICMP,
        &icmp(3, 3, &[0; 28]),
        0,
        false,
    );
    let d = pipe.decide(&wire(&forged, 1), T0);
    assert_eq!((d.action.as_str(), d.rule_id.as_str()), ("permit", "probe"));
}
/// The server's traffic, seen every ten seconds from T0 to `until`, to a player it talks to.
fn watch(pipe: &mut Pipeline, until: i64) {
    let mut at = T0;
    while at <= until {
        sent(pipe, "192.0.2.50", "ack", at);
        at += 10_000;
    }
}
#[test]
fn a_syn_ack_answers_only_a_syn_the_server_sent_and_a_fake_session_gets_its_handshake_and_no_more()
{
    let mut pipe = Pipeline::new(node());
    let now = T0 + ACK_WARM + 10_000;
    watch(&mut pipe, now);
    let tcp =
        |src: &str, flags: &str, pps: i64| record("tcp", src, "203.0.113.10", 40000, flags, pps);
    // A flood of TCP for no connection engages the guard.
    assert_eq!(
        verdict(&mut pipe, &tcp("100.64.6.1", "ack", 10_000), now),
        dropped("ack_flood")
    );
    // A SYN-ACK answers a SYN: from a peer the server opened a connection to, it passes; from
    // anyone else it is a SYN-ACK flood.
    sent(&mut pipe, "198.51.100.200", "syn", now);
    assert_eq!(
        verdict(&mut pipe, &tcp("198.51.100.200", "syn,ack", 1), now + 1),
        passed()
    );
    let d = pipe.decide(&tcp("100.64.6.2", "syn,ack", 1), now + 1);
    assert_eq!((d.action.as_str(), d.guard.as_str()), ("drop", "ack_flood"));
    assert!(d.reason.starts_with("SYN-ACK flood: "), "{}", d.reason);
    let d = pipe.decide(&tcp("100.64.6.3", "rst", 1), now + 1);
    assert!(d.reason.starts_with("RST/FIN flood: "), "{}", d.reason);
    // A fake session: a forged SYN, which the server answers, then a stream of ACKs. The
    // client's end of the handshake passes, and nothing past it until the server's own segments
    // say the connection is open.
    let fake = "100.64.7.1";
    assert_eq!(verdict(&mut pipe, &tcp(fake, "syn", 1), now + 2), passed());
    sent(&mut pipe, fake, "syn,ack", now + 2);
    for i in 0..HANDSHAKE_SEGMENTS {
        let flags = if i == 0 { "ack" } else { "psh,ack" };
        assert_eq!(
            verdict(&mut pipe, &tcp(fake, flags, 1), now + 3),
            passed(),
            "{i}"
        );
    }
    assert_eq!(
        verdict(&mut pipe, &tcp(fake, "ack", 1), now + 3),
        dropped("ack_flood")
    );
    // A real client's handshake goes the same way, and once the server answers it the
    // connection is the client's.
    let real = "192.0.2.60";
    assert_eq!(verdict(&mut pipe, &tcp(real, "syn", 1), now + 4), passed());
    sent(&mut pipe, real, "syn,ack", now + 4);
    assert_eq!(verdict(&mut pipe, &tcp(real, "ack", 1), now + 5), passed());
    assert_eq!(
        verdict(&mut pipe, &tcp(real, "psh,ack", 1), now + 5),
        passed()
    );
    sent(&mut pipe, real, "psh,ack", now + 6);
    for _ in 0..20 {
        assert_eq!(
            verdict(&mut pipe, &tcp(real, "psh,ack", 1), now + 7),
            passed()
        );
    }
    // A reset the server sends says nothing of a connection.
    sent(&mut pipe, "100.64.7.2", "rst,ack", now + 8);
    assert_eq!(
        verdict(&mut pipe, &tcp("100.64.7.2", "ack", 1), now + 9),
        dropped("ack_flood")
    );
}
#[test]
fn a_flood_spread_across_addresses_protected_one_by_one_is_judged_whole() {
    // Twenty game servers, each protected as its own /32, and a SYN flood spread across them so
    // that each takes a fraction of the threshold.
    let program = Program {
        prefixes: (1..=20).map(|i| format!("203.0.113.{i}/32")).collect(),
        ..Default::default()
    };
    let share = SYN_ENGAGE_PPS as i64 / 10;
    let mut pipe = Pipeline::new(program.clone());
    let mut drops = 0;
    for i in 1..=20 {
        let f = record(
            "tcp",
            &format!("100.64.8.{i}"),
            &format!("203.0.113.{i}"),
            40000,
            "syn",
            share,
        );
        drops += u32::from(pipe.decide(&f, T0).guard == "syn_flood");
    }
    assert_eq!(
        drops, 10,
        "the tenth address took the /24 over the threshold"
    );
    let st = pipe.stats(T0);
    let engaged: Vec<_> = st["prefixes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["syn_flood"]["engaged"] == true)
        .collect();
    assert_eq!(engaged.len(), 20, "every address of the /24 is engaged");
    assert_eq!(st["syn_flood"]["engaged"], 1, "one aggregate");
    // One address alone at its share engages nothing.
    let mut pipe = Pipeline::new(program);
    let alone = record("tcp", "100.64.8.1", "203.0.113.1", 40000, "syn", share);
    assert_eq!(verdict(&mut pipe, &alone, T0), passed());
}
#[test]
fn ip_null_is_dropped_as_protocol_zero() {
    let mut pipe = Pipeline::new(node());
    let null = v4(CLIENT, SERVER, 0, &[0; 32], 0, false);
    let d = pipe.decide(&wire(&null, 1), T0);
    assert_eq!((d.action.as_str(), d.guard.as_str()), ("drop", "protocol"));
    assert!(d.reason.starts_with("IP NULL: "), "{}", d.reason);
    let rec = record("0", "192.0.2.1", "203.0.113.10", 0, "", 50_000);
    assert_eq!(verdict(&mut pipe, &rec, T0), dropped("protocol"));
}
#[test]
fn policies_are_validated_and_reach_every_node() {
    let base = Policy {
        id: "p".into(),
        name: "game-edge".into(),
        protected: vec!["203.0.113.0/24".into()],
        ..Default::default()
    };
    let p = Policy {
        syn_flood: Some(SynFloodPolicy {
            mode: "observe".into(),
            engage_pps: 50_000,
        }),
        fragments: Some(FragmentPolicy { mode: "off".into() }),
        icmp: Some(IcmpPolicy {
            mode: "enforce".into(),
            limit_pps: 2_000,
            smurf_pps: 500,
        }),
        ..base.clone()
    };
    validation::policy(&p).unwrap();
    for (bad, says) in [
        (
            Policy {
                syn_flood: Some(SynFloodPolicy {
                    mode: "drop".into(),
                    engage_pps: 0,
                }),
                ..base.clone()
            },
            "syn_flood.mode",
        ),
        (
            Policy {
                syn_flood: Some(SynFloodPolicy {
                    mode: String::new(),
                    engage_pps: -5,
                }),
                ..base.clone()
            },
            "syn_flood.engage_pps",
        ),
        (
            Policy {
                fragments: Some(FragmentPolicy {
                    mode: "strict".into(),
                }),
                ..base.clone()
            },
            "fragments.mode",
        ),
        (
            Policy {
                icmp: Some(IcmpPolicy {
                    mode: "block".into(),
                    ..Default::default()
                }),
                ..base.clone()
            },
            "icmp.mode",
        ),
        (
            Policy {
                icmp: Some(IcmpPolicy {
                    limit_pps: 2_000_000_000,
                    ..Default::default()
                }),
                ..base.clone()
            },
            "icmp.limit_pps",
        ),
        (
            Policy {
                icmp: Some(IcmpPolicy {
                    smurf_pps: -1,
                    ..Default::default()
                }),
                ..base.clone()
            },
            "icmp.smurf_pps",
        ),
    ] {
        let err = validation::policy(&bad).unwrap_err();
        assert!(err.contains(says), "{err}");
    }
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
    let n1 = &programs["n1"];
    assert_eq!(
        (n1.syn_flood.clone(), n1.fragments.clone(), n1.icmp.clone()),
        (p.syn_flood.clone(), p.fragments.clone(), p.icmp.clone())
    );
}
#[test]
fn the_guards_are_counted_for_the_fabric_its_dashboards_and_its_customers() {
    let program = node();
    let mut pipe = Pipeline::new(program.clone());
    // The fabric's analytics takes a node's first report as its baseline.
    let mut c = Collector::default();
    c.observe("n1", &pipe.stats(T0), &program, T0);
    pipe.decide(&syn("100.64.9.1", 40000, 10_000), T0 + 1_000);
    let ack = tcp(40000, 443, ACK, &[0x41; 2000]);
    pipe.decide(
        &wire(&v4(CLIENT, SERVER, TCP, &ack[..1480], 0, true), 1),
        T0 + 1_000,
    );
    pipe.decide(
        &record("icmp", "100.64.9.2", "203.0.113.10", 0, "", 100_000),
        T0 + 1_000,
    );
    let stats = pipe.stats(T0 + 1_000);
    let kept = serde_json::to_value(
        serde_json::from_value::<pathfinder::wire::Stats>(stats.clone()).unwrap(),
    )
    .unwrap();
    for guard in ["syn_flood", "fragments", "icmp"] {
        assert_eq!(kept[guard], stats[guard], "{guard}");
    }
    let row = kept["prefixes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["prefix"] == "203.0.113.0/24")
        .unwrap()
        .clone();
    assert_eq!(
        row["syn_flood"],
        json!({"engaged":true,"flows":1,"dropped":10_000})
    );
    assert_eq!(
        row["fragments"],
        json!([{"protocol":"tcp","flows":1,"dropped":1}])
    );
    assert_eq!(
        row["icmp"],
        json!([{"kind":"flood","flows":1,"dropped":100_000}])
    );
    let mut m = Metrics::new();
    m.reports(
        &[json!({"node_id":"n1","name":"buf-1","region":"buf","stats":stats})],
        T0 + 1_000,
    );
    let text = m.render().unwrap();
    let labels = "node=\"n1\",name=\"buf-1\",region=\"buf\"";
    for line in [
        format!("scrubline_syn_flood_dropped_total{{{labels}}} 1"),
        format!("scrubline_syn_flood_engaged_prefixes{{{labels}}} 1"),
        format!("scrubline_syn_flood_engage_pps{{{labels}}} 2000"),
        format!("scrubline_syn_flood_mode{{{labels},mode=\"enforce\"}} 1"),
        format!("scrubline_prefix_syn_flood_engaged{{{labels},prefix=\"203.0.113.0/24\"}} 1"),
        format!("scrubline_fragment_dropped_total{{{labels},protocol=\"tcp\"}} 1"),
        format!("scrubline_fragment_mode{{{labels},mode=\"enforce\"}} 1"),
        format!("scrubline_icmp_dropped_total{{{labels},kind=\"flood\"}} 1"),
        format!("scrubline_icmp_limit_pps{{{labels}}} 1000"),
        format!("scrubline_icmp_mode{{{labels},mode=\"off\"}} 0"),
    ] {
        assert!(text.contains(&line), "{line}\n{text}");
    }
    // The customer's attack names every guard that stopped part of it.
    c.observe("n1", &stats, &program, T0 + 1_000);
    let events = c.events("203.0.113.0/24", 3_600_000, T0 + 1_000);
    let vectors = events[0]["vectors"].clone();
    for (kind, name) in [("syn_flood", "tcp"), ("fragment", "tcp"), ("icmp", "flood")] {
        assert!(
            vectors.as_array().unwrap().iter().any(|v| v[kind] == name),
            "{kind}: {vectors}"
        );
    }
}
#[test]
fn the_servers_answers_to_forged_syns_do_not_fill_its_table_of_peers() {
    let mut pipe = Pipeline::new(node());
    let start = T0 + ACK_WARM + 10_000;
    watch(&mut pipe, start);
    // A SYN flood under the SYN flood guard's threshold, for 40 seconds: the server answers every
    // forged SYN with a SYN-ACK, to a fresh address each time.
    let rate = SYN_ENGAGE_PPS as i64 - 100;
    for second in 0..40 {
        let at = start + second * 1_000;
        sent(&mut pipe, "192.0.2.50", "ack", at);
        for i in 0..rate {
            let n = second * rate + i;
            let forged = format!("10.{}.{}.{}", n >> 16, (n >> 8) & 255, n & 255);
            sent(&mut pipe, &forged, "syn,ack", at + i / 4);
        }
    }
    let end = start + 40_000;
    let clients = pipe.stats(end)["egress"]["clients"].as_u64().unwrap();
    assert!(
        clients < 65_536 / 2,
        "{clients} peers kept: the table only needs a handshake's worth of backscatter"
    );
    // So the ACK flood guard is still on watch, and drops an ACK flood that comes with it.
    let flood = record("tcp", "100.64.10.1", "203.0.113.10", 40000, "ack", 10_000);
    assert_eq!(verdict(&mut pipe, &flood, end), dropped("ack_flood"));
}
#[test]
fn the_api_guides_guard_examples_are_decided_as_it_says() {
    // Each example the node decides, and the answer the guide shows under it, for the guards a
    // fresh node judges without having seen anything before: the rest take state to engage.
    let guide = include_str!("../docs/api.md");
    let examples: Vec<(&str, &str)> = guide
        .split("node:9091/decide \\\n    -d '")
        .skip(1)
        .map(|rest| {
            let body = &rest[..rest.find('\'').unwrap()];
            let answer = rest[body.len() + 1..]
                .trim_start()
                .lines()
                .next()
                .unwrap_or("");
            (body, answer)
        })
        .filter(|(_, answer)| {
            [
                "\"guard\":\"protocol\"",
                "\"guard\":\"syn_flood\"",
                "\"guard\":\"fragment\"",
                "\"guard\":\"icmp\"",
                "\"reflection\":",
            ]
            .iter()
            .any(|g| answer.contains(g))
        })
        .collect();
    assert_eq!(examples.len(), 6, "{examples:#?}");
    for (body, answer) in examples {
        let mut pipe = Pipeline::new(node());
        let f: pathfinder::model::Flow = serde_json::from_str(body).unwrap();
        let d = pipe.decide(&f, T0);
        assert_eq!(serde_json::to_string(&d).unwrap(), answer, "{body}");
    }
}
