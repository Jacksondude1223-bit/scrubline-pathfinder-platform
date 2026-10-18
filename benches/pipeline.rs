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
fn main() {
    run(false);
    run(true);
}
