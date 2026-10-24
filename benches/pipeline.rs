use pathfinder::{model::*, pipeline::Pipeline};
use std::{hint::black_box, time::Instant};
fn run(verified: bool) {
    let mut p = Pipeline::new(Program {
        prefixes: vec!["203.0.113.0/24".into()],
        games: vec![GameFilter {
            id: "game".into(),
            profile: "raknet".into(),
            dport: 19132,
            ..Default::default()
        }],
        reputation: Some(ReputationPolicy {
            fast_pass: "handshake".into(),
            ..Default::default()
        }),
        ..Default::default()
    });
    let now = 1767225600000;
    let mut f = Flow {
        src_ip: "192.0.2.1".into(),
        dst_ip: "203.0.113.1".into(),
        proto: "udp".into(),
        dport: 19132,
        pps: 1,
        ..Default::default()
    };
    if verified {
        f.payload = vec![7];
        f.has_payload = true;
        p.decide(&f, now);
    }
    let start = Instant::now();
    let count = 100000;
    for _ in 0..count {
        black_box(p.decide(black_box(&f), now));
    }
    println!(
        "{}: {:.1} ns/flow",
        if verified { "verified" } else { "unverified" },
        start.elapsed().as_nanos() as f64 / count as f64
    );
}
/// A request held to a server's HTTP rules: a path with no rate, then one over its rate.
fn http(path: &str) {
    let mut p = Pipeline::new(Program {
        prefixes: vec!["203.0.113.0/24".into()],
        games: vec![GameFilter {
            id: "web".into(),
            dst_cidr: "203.0.113.1/32".into(),
            dport: 30120,
            http: Some(GameHttp {
                rate_per_source: 1000000000,
                paths: vec![
                    GameHttpPath {
                        path: "/players.json".into(),
                        rate_per_source: 1,
                        ..Default::default()
                    },
                    GameHttpPath {
                        prefix: "/files/".into(),
                        rate_per_source: 1000000000,
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }),
            ..Default::default()
        }],
        ..Default::default()
    });
    let now = 1767225600000;
    let f = Flow {
        src_ip: "192.0.2.1".into(),
        dst_ip: "203.0.113.1".into(),
        proto: "tcp".into(),
        dport: 30120,
        pps: 1,
        payload: format!(
            "GET {path} HTTP/1.1\r\nHost: 203.0.113.1:30120\r\nUser-Agent: CitizenFX/1\r\nAccept: */*\r\n\r\n"
        )
        .into_bytes(),
        has_payload: true,
        ..Default::default()
    };
    let start = Instant::now();
    let count = 100000;
    for _ in 0..count {
        black_box(p.decide(black_box(&f), now));
    }
    println!(
        "http {path}: {:.1} ns/request",
        start.elapsed().as_nanos() as f64 / count as f64
    );
}
fn main() {
    run(false);
    run(true);
    http("/files/map/stream.rpf");
    http("/players.json");
}
