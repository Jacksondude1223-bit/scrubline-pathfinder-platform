//! HTTP attacks that cost a server its connections or its handshakes rather than its bandwidth:
//! HTTPS floods, Slowloris and the HTTP fragmentation it is made of, R.U.D.Y.'s slow bodies, and
//! slow reads. Each is sent here the way its tools send it and cut off; a real client's request,
//! however it is split, and an upload on a slow link pass.
use base64::{engine::general_purpose::STANDARD, Engine};
use pathfinder::{
    model::{Flow, GameFilter, GameHttp, Program, ReputationPolicy},
    pipeline::Pipeline,
    telemetry::Metrics,
};
use serde_json::json;

const T0: i64 = 1767225600000;
const SITE: &str = "203.0.113.20";

fn program(http: GameHttp) -> Program {
    Program {
        prefixes: vec!["203.0.113.0/24".into()],
        games: vec![GameFilter {
            id: "site".into(),
            dst_cidr: format!("{SITE}/32"),
            proto: "tcp".into(),
            dport: 80,
            http: Some(GameHttp {
                ports: vec![80, 443],
                ..http
            }),
            ..Default::default()
        }],
        reputation: Some(ReputationPolicy {
            penalty_box: true,
            ..Default::default()
        }),
        ..Default::default()
    }
}
/// A segment from `src`'s port `sport` to the site's `dport`, carrying `data`.
fn segment(src: &str, sport: i64, dport: i64, data: &[u8]) -> Flow {
    Flow {
        src_ip: src.into(),
        dst_ip: SITE.into(),
        proto: "tcp".into(),
        sport,
        dport,
        flags: "psh,ack".into(),
        pps: 1,
        payload: data.to_vec(),
        has_payload: true,
        ..Default::default()
    }
}
fn verdict(pipe: &mut Pipeline, f: &Flow, at: i64) -> (String, String) {
    let d = pipe.decide(f, at);
    (d.action, d.reason)
}
fn site(pipe: &mut Pipeline, at: i64) -> serde_json::Value {
    pipe.stats(at)["games"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["filter_id"] == "site")
        .unwrap()
        .clone()
}
/// A ClientHello's first bytes: a handshake record, and a ClientHello in it.
const HELLO: &[u8] = &[
    0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03,
];
/// What follows a handshake: application data, encrypted.
const DATA: &[u8] = &[0x17, 0x03, 0x03, 0x00, 0x40, 0x9a, 0x11];

#[test]
fn an_https_flood_is_held_to_the_servers_rates_at_its_handshakes() {
    let mut pipe = Pipeline::new(program(GameHttp {
        rate_per_source: 5,
        rate_total: 20,
        ..Default::default()
    }));
    // Each ClientHello opens a session the server spends a handshake on: one source gets as
    // many a second as the server's rate.
    for i in 0..5 {
        let (action, reason) =
            verdict(&mut pipe, &segment("100.64.0.1", 40000 + i, 443, HELLO), T0);
        assert_eq!(action, "permit", "{reason}");
    }
    let (action, reason) = verdict(&mut pipe, &segment("100.64.0.1", 40010, 443, HELLO), T0 + 1);
    assert_eq!(
        (action.as_str(), reason.as_str()),
        (
            "drop",
            "game filter http: a TLS handshake: more than 5 requests a second to this server from this source"
        )
    );
    // What a session carries after its handshake is encrypted, and passes.
    let (action, _) = verdict(&mut pipe, &segment("100.64.0.1", 40000, 443, DATA), T0 + 2);
    assert_eq!(action, "permit");
    // Spread across sources, the flood meets the budget for everyone, past which only the
    // sources the fabric has verified get through.
    for i in 0..15 {
        verdict(
            &mut pipe,
            &segment(&format!("100.64.1.{i}"), 40000, 443, HELLO),
            T0 + 3,
        );
    }
    let (action, reason) = verdict(&mut pipe, &segment("100.64.2.1", 40000, 443, HELLO), T0 + 4);
    assert_eq!(action, "drop");
    assert!(
        reason.contains("from everyone, and this source is not verified"),
        "{reason}"
    );
    pipe.reputation.promote("192.0.2.9", 3, T0);
    let (action, _) = verdict(&mut pipe, &segment("192.0.2.9", 40000, 443, HELLO), T0 + 5);
    assert_eq!(action, "permit");
    // The filter counts every handshake but the verified source's, which took the fast path,
    // and the two its rates held back: one source's own, and everyone's.
    let g = site(&mut pipe, T0 + 6);
    assert_eq!(g["http_tls_handshakes"], 22, "{g}");
    assert_eq!(
        (
            g["http_rate_limited"].clone(),
            g["http_budget_dropped"].clone()
        ),
        (json!(2), json!(1)),
        "{g}"
    );
}
#[test]
fn slowloris_is_cut_off_once_its_head_runs_past_what_a_server_waits() {
    let mut pipe = Pipeline::new(program(GameHttp::default()));
    let src = "100.64.3.1";
    // The head opens, and arrives a header line at a time.
    let (action, _) = verdict(
        &mut pipe,
        &segment(src, 41000, 80, b"GET / HTTP/1.1\r\nHost: a\r\n"),
        T0,
    );
    assert_eq!(action, "permit");
    let (action, _) = verdict(
        &mut pipe,
        &segment(src, 41000, 80, b"X-a: 1\r\n"),
        T0 + 10_000,
    );
    assert_eq!(action, "permit");
    // Twenty seconds on, it is longer than a server waits for a head.
    let (action, reason) = verdict(
        &mut pipe,
        &segment(src, 41000, 80, b"X-a: 2\r\n"),
        T0 + 25_000,
    );
    assert_eq!(action, "drop");
    assert!(
        reason.starts_with("game filter http: a slow request: its head still arriving 25 seconds"),
        "{reason}"
    );
    // A source that holds several such connections is boxed: its address is real, since each
    // connection took a handshake.
    for port in 41001..41004 {
        verdict(
            &mut pipe,
            &segment(src, port, 80, b"GET / HTTP/1.1\r\n"),
            T0 + 1_000,
        );
        let (action, _) = verdict(
            &mut pipe,
            &segment(src, port, 80, b"X-b: 1\r\n"),
            T0 + 25_000,
        );
        assert_eq!(action, "drop", "{port}");
    }
    let (_, reason) = verdict(
        &mut pipe,
        &segment(src, 41009, 80, b"GET / HTTP/1.1\r\n\r\n"),
        T0 + 26_000,
    );
    assert_eq!(reason, "source is in the penalty box");
    // A real client's head split across segments, as a large cookie makes it, completes at once;
    // and one the network delays completes within what a server waits.
    let client = "192.0.2.20";
    let mut head = b"GET /players.json HTTP/1.1\r\nHost: a\r\nCookie: ".to_vec();
    head.extend([b'c'; 1400]);
    verdict(&mut pipe, &segment(client, 42000, 80, &head), T0);
    let (action, _) = verdict(
        &mut pipe,
        &segment(client, 42000, 80, b"\r\nAccept: */*\r\n\r\n"),
        T0 + 50,
    );
    assert_eq!(action, "permit");
    verdict(
        &mut pipe,
        &segment(client, 42001, 80, b"GET / HTTP/1.1\r\nHost: a\r\n"),
        T0,
    );
    let (action, _) = verdict(&mut pipe, &segment(client, 42001, 80, b"\r\n"), T0 + 5_000);
    assert_eq!(action, "permit");
    // The blank line split across the two counts as one.
    verdict(
        &mut pipe,
        &segment(client, 42002, 80, b"GET / HTTP/1.1\r\nHost: a\r\n\r"),
        T0,
    );
    verdict(&mut pipe, &segment(client, 42002, 80, b"\n"), T0 + 100);
    let (action, _) = verdict(
        &mut pipe,
        &segment(client, 42002, 80, b"GET /next HTTP/1.1\r\n\r\n"),
        T0 + 30_000,
    );
    assert_eq!(action, "permit");
    let g = site(&mut pipe, T0 + 30_000);
    assert_eq!(g["http_slow_dropped"], 4, "{g}");
    assert_eq!(
        pipe.stats(T0 + 30_000)["game_http_pending"],
        4,
        "Slowloris's four, still tracked"
    );
}
#[test]
fn more_requests_left_incomplete_at_once_than_any_client_leaves_is_slowloris() {
    let mut pipe = Pipeline::new(program(GameHttp::default()));
    let src = "100.64.4.1";
    for port in 0..32 {
        let (action, _) = verdict(
            &mut pipe,
            &segment(src, 43000 + port, 80, b"GET / HTTP/1.1\r\n"),
            T0,
        );
        assert_eq!(action, "permit", "{port}");
    }
    let (action, reason) = verdict(
        &mut pipe,
        &segment(src, 43100, 80, b"GET / HTTP/1.1\r\n"),
        T0 + 1,
    );
    assert_eq!(
        (action.as_str(), reason.as_str()),
        (
            "drop",
            "game filter http: more than 32 requests from this source left incomplete at once, as Slowloris holds connections open"
        )
    );
    // Another source is no part of it.
    let (action, _) = verdict(
        &mut pipe,
        &segment("100.64.4.2", 43100, 80, b"GET / HTTP/1.1\r\n"),
        T0 + 1,
    );
    assert_eq!(action, "permit");
    // A head that completes, and a connection the client closes, leave room.
    verdict(
        &mut pipe,
        &segment(src, 43000, 80, b"Host: a\r\n\r\n"),
        T0 + 2,
    );
    let fin = Flow {
        flags: "fin,ack".into(),
        payload: vec![],
        ..segment(src, 43001, 80, b"")
    };
    verdict(&mut pipe, &fin, T0 + 2);
    for port in [43100, 43101] {
        let (action, _) = verdict(
            &mut pipe,
            &segment(src, port, 80, b"GET / HTTP/1.1\r\n"),
            T0 + 3,
        );
        assert_eq!(action, "permit", "{port}");
    }
}
#[test]
fn a_body_that_trickles_in_is_cut_off_as_rudy_and_an_upload_on_a_slow_link_is_not() {
    let mut pipe = Pipeline::new(program(GameHttp::default()));
    let src = "100.64.5.1";
    let post = b"POST /login HTTP/1.1\r\nHost: a\r\nContent-Length: 100000\r\n\r\nuser=";
    let (action, _) = verdict(&mut pipe, &segment(src, 44000, 80, post), T0);
    assert_eq!(action, "permit");
    for at in [5_000, 15_000] {
        let (action, _) = verdict(&mut pipe, &segment(src, 44000, 80, b"a"), T0 + at);
        assert_eq!(action, "permit", "{at}");
    }
    let (action, reason) = verdict(&mut pipe, &segment(src, 44000, 80, b"a"), T0 + 21_000);
    assert_eq!(action, "drop");
    assert!(
        reason.starts_with("game filter http: a slow body: 3 bytes in 21 seconds"),
        "{reason}"
    );
    // An upload at 1.4 KB a second keeps ahead of what a server holds a body to, and once all
    // of it has arrived nothing is left to wait for.
    let client = "192.0.2.30";
    let upload = b"POST /upload HTTP/1.1\r\nHost: a\r\nContent-Length: 70000\r\n\r\n";
    verdict(&mut pipe, &segment(client, 45000, 80, upload), T0);
    for i in 1..=50 {
        let (action, reason) = verdict(
            &mut pipe,
            &segment(client, 45000, 80, &[b'x'; 1400]),
            T0 + i * 1_000,
        );
        assert_eq!(action, "permit", "{i}: {reason}");
    }
    assert_eq!(
        pipe.stats(T0 + 51_000)["game_http_pending"],
        1,
        "only R.U.D.Y. is left"
    );
    // A chunked body ends at its last chunk.
    let chunked =
        b"POST /c HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n";
    verdict(&mut pipe, &segment(client, 45001, 80, chunked), T0);
    verdict(
        &mut pipe,
        &segment(client, 45001, 80, b"0\r\n\r\n"),
        T0 + 100,
    );
    assert_eq!(pipe.stats(T0 + 200)["game_http_pending"], 1);
}
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
/// A TCP segment from 192.0.2.40:46000 to the site's port 80, advertising `window`.
fn packet(flags: u8, window: u16, data: &[u8]) -> Flow {
    let mut t = vec![0xb3, 0xb0, 0x00, 0x50, 0, 0, 0, 9, 0, 0, 0, 9, 0x50, flags];
    t.extend(window.to_be_bytes());
    t.extend([0, 0, 0, 0]);
    t.extend(data);
    let mut p = vec![0x45, 0];
    p.extend((20 + t.len() as u16).to_be_bytes());
    p.extend([
        0x12, 0x34, 0x40, 0x00, 64, 6, 0, 0, 192, 0, 2, 40, 203, 0, 113, 20,
    ]);
    p.extend(t);
    seal(&mut p);
    serde_json::from_value(json!({"packet": STANDARD.encode(p)})).unwrap()
}
#[test]
fn a_slow_read_is_cut_off_once_its_window_stays_too_small_to_read_the_answer() {
    let mut pipe = Pipeline::new(program(GameHttp::default()));
    let request = packet(0x18, 512, b"GET /big HTTP/1.1\r\nHost: a\r\n\r\n");
    assert_eq!(request.window, Some(512));
    assert_eq!(pipe.decide(&request, T0).action, "permit");
    // The client takes the answer a few bytes at a time, its window shut or nearly.
    for (at, window) in [(1_000, 0), (10_000, 8), (29_000, 0)] {
        let d = pipe.decide(&packet(0x10, window, b""), T0 + at);
        assert_eq!(d.action, "permit", "{at}: {}", d.reason);
    }
    let d = pipe.decide(&packet(0x10, 0, b""), T0 + 31_000);
    assert_eq!(d.action, "drop");
    assert!(
        d.reason.starts_with("game filter http: a slow read: the client has advertised a window of under 64 bytes for 30 seconds"),
        "{}",
        d.reason
    );
    // A reader whose window opens again is reading.
    let mut pipe = Pipeline::new(program(GameHttp::default()));
    pipe.decide(&packet(0x10, 0, b""), T0);
    pipe.decide(&packet(0x10, 4096, b""), T0 + 20_000);
    pipe.decide(&packet(0x10, 0, b""), T0 + 25_000);
    assert_eq!(
        pipe.decide(&packet(0x10, 0, b""), T0 + 40_000).action,
        "permit"
    );
    // Its reset ends it.
    pipe.decide(&packet(0x04, 0, b""), T0 + 41_000);
    assert_eq!(pipe.stats(T0 + 41_000)["game_http_pending"], 0);
}
#[test]
fn the_connections_watched_are_bounded_and_counted() {
    let mut pipe = Pipeline::new(program(GameHttp::default()));
    let max = pathfinder::httpfilter::PENDING_MAX;
    for i in 0..max + 10 {
        let src = format!("10.{}.{}.{}", i >> 16, (i >> 8) & 255, i & 255);
        pipe.decide(&segment(&src, 47000, 80, b"GET / HTTP/1.1\r\n"), T0);
    }
    let st = pipe.stats(T0);
    assert_eq!(
        (
            st["game_http_pending"].clone(),
            st["game_http_pending_untracked"].clone()
        ),
        (json!(max), json!(10))
    );
    // A connection that goes quiet for a minute leaves the table.
    pipe.decide(
        &segment("192.0.2.99", 47000, 80, b"GET / HTTP/1.1\r\n"),
        T0 + 70_000,
    );
    assert_eq!(pipe.stats(T0 + 70_000)["game_http_pending"], 1);
    let mut m = Metrics::new();
    m.reports(
        &[json!({"node_id":"n1","name":"buf-1","region":"buf","stats":pipe.stats(T0 + 70_000)})],
        T0,
    );
    let text = m.render().unwrap();
    for line in [
        "scrubline_game_http_pending{node=\"n1\",name=\"buf-1\",region=\"buf\"} 1",
        "scrubline_game_http_pending_max{node=\"n1\",name=\"buf-1\",region=\"buf\"} 16384",
        "scrubline_game_http_pending_untracked_total{node=\"n1\",name=\"buf-1\",region=\"buf\"} 10",
        "scrubline_game_http_slow_dropped_total{node=\"n1\",name=\"buf-1\",region=\"buf\",filter=\"site\",profile=\"http\"} 0",
        "scrubline_game_http_tls_handshakes_total{node=\"n1\",name=\"buf-1\",region=\"buf\",filter=\"site\",profile=\"http\"} 0",
    ] {
        assert!(text.contains(line), "{line}\n{text}");
    }
}
