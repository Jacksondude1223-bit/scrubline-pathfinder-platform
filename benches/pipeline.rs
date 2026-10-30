use pathfinder::{ml, model::*, pipeline::Pipeline};
use std::{hint::black_box, time::Instant};
/// Both classifiers published, at a threshold nothing reaches, so every flow and request is scored
/// and nothing is dropped for it.
fn models() -> ml::Model {
    let fitted = |n| ml::Model {
        weights: vec![0.1; n],
        threshold: 0.999,
        ready: true,
        ..Default::default()
    };
    ml::Model {
        http: Some(Box::new(fitted(ml::REQUEST_FEATURES))),
        ..fitted(ml::FEATURE_COUNT)
    }
}
fn label(what: &str, scored: bool) -> String {
    if scored {
        format!("{what}, scored by the models")
    } else {
        what.into()
    }
}
fn run(verified: bool, scored: bool) {
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
    if scored {
        p.model = models();
    }
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
        label(if verified { "verified" } else { "unverified" }, scored),
        start.elapsed().as_nanos() as f64 / count as f64
    );
}
/// A request held to a server's HTTP rules: a path with no rate, then one over its rate.
fn http(path: &str, scored: bool) {
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
    if scored {
        p.model = models();
    }
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
        "{}: {:.1} ns/request",
        label(&format!("http {path}"), scored),
        start.elapsed().as_nanos() as f64 / count as f64
    );
}
/// An IPv4 packet from 192.0.2.1 to 203.0.113.1 carrying `l4`.
fn ipv4(proto: u8, l4: &[u8]) -> Vec<u8> {
    let mut p = vec![0x45, 0, 0, 0, 0x12, 0x34, 0x40, 0, 64, proto, 0, 0];
    p[2..4].copy_from_slice(&((20 + l4.len()) as u16).to_be_bytes());
    p.extend([192, 0, 2, 1, 203, 0, 113, 1]);
    let mut sum: u32 = p
        .chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], c[1]])))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    p[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    p.extend(l4);
    p
}
/// Whole packets as a datapath hands them over, read and checked by the node: a datagram the game
/// filter judges, and a SYN-FIN the crafted-packet checks drop.
fn packets() {
    let mut p = Pipeline::new(Program {
        prefixes: vec!["203.0.113.0/24".into()],
        games: vec![GameFilter {
            id: "game".into(),
            profile: "raknet".into(),
            dport: 19132,
            ..Default::default()
        }],
        ..Default::default()
    });
    let now = 1767225600000;
    let udp = [0xc3, 0x50, 0x4a, 0xbc, 0, 9, 0, 0, 0x05];
    let mut tcp = [0u8; 20];
    tcp[..4].copy_from_slice(&[0x9c, 0x40, 0x01, 0xbb]);
    tcp[12] = 5 << 4;
    tcp[13] = 0x03;
    for (what, packet) in [
        ("a game datagram", ipv4(17, &udp)),
        ("a crafted SYN-FIN", ipv4(6, &tcp)),
    ] {
        let start = Instant::now();
        let count = 100000;
        for _ in 0..count {
            let mut f = Flow {
                packet: packet.clone(),
                pps: 1,
                ..Default::default()
            };
            pathfinder::packet::fill(&mut f);
            black_box(p.decide(black_box(&f), now));
        }
        println!(
            "packet, {what}: {:.1} ns/packet",
            start.elapsed().as_nanos() as f64 / count as f64
        );
    }
}
fn main() {
    for scored in [false, true] {
        run(false, scored);
        run(true, scored);
        http("/files/map/stream.rpf", scored);
        http("/players.json", scored);
    }
    packets();
}
