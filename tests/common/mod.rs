//! What the tests of the fabric at its bounds build it from.
#![allow(dead_code)]
use pathfinder::{model::*, pipeline::Pipeline, validation};
pub const T0: i64 = 1767225600000;
/// The prefix the game servers and the capped service sit in.
pub const V6: &str = "2001:db8:100::/48";
/// A source address written as long as one is: every table keyed by one holds its longest key.
pub fn source(i: usize) -> String {
    format!(
        "2001:db8:aaaa:bbbb:cccc:dddd:{:04x}:{:04x}",
        i >> 16,
        i & 0xffff
    )
}
pub fn flow(src: &str, proto: &str, dport: i64, payload: &[u8]) -> Flow {
    Flow {
        src_ip: src.into(),
        dst_ip: "2001:db8:100::10".into(),
        proto: proto.into(),
        sport: 50000,
        dport,
        pps: 1,
        payload: payload.to_vec(),
        has_payload: !payload.is_empty(),
        ..Default::default()
    }
}
/// A policy holding as much of everything as validation lets one.
pub fn largest_policy() -> Policy {
    let mut protected: Vec<String> = (0..validation::PREFIXES_MAX - 1)
        .map(|i| format!("10.{}.{}.0/24", i / 256, i % 256))
        .collect();
    protected.push(V6.into());
    let mut rules: Vec<Rule> = (0..validation::RULES_MAX)
        .map(|i| Rule {
            id: format!("rule-{i}"),
            stage: ["asic", "fpga", "zc"][i % 3].into(),
            action: if i % 3 == 0 { "drop" } else { "rate_limit" }.into(),
            pps: if i % 3 == 0 { 0 } else { 1000 },
            priority: i as i64,
            r#match: Match {
                dst_cidr: protected[i].clone(),
                proto: "udp".into(),
                dport: (i % 60000) as i64 + 1,
                ..Default::default()
            },
            ..Default::default()
        })
        .collect();
    rules[validation::RULES_MAX - 1] = Rule {
        id: "cap".into(),
        stage: "zc".into(),
        action: "rate_limit".into(),
        pps: 1_000_000,
        r#match: Match {
            dst_cidr: V6.into(),
            proto: "tcp".into(),
            dport: 443,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut games: Vec<GameFilter> = (0..validation::GAMES_MAX)
        .map(|i| GameFilter {
            id: format!("game-{i}"),
            dst_cidr: protected[i].clone(),
            proto: "udp".into(),
            dport: 19132,
            profile: "raknet".into(),
            ..Default::default()
        })
        .collect();
    games[0].dst_cidr = V6.into();
    games[1] = GameFilter {
        id: "site".into(),
        dst_cidr: V6.into(),
        proto: "tcp".into(),
        dport: 80,
        http: Some(GameHttp {
            rate_per_source: 1000,
            ..Default::default()
        }),
        ..Default::default()
    };
    Policy {
        id: "largest".into(),
        name: "largest".into(),
        rules,
        games,
        tunnels: (0..validation::TUNNELS_MAX)
            .map(|i| Tunnel {
                id: format!("tunnel-{i}"),
                prefixes: vec![protected[i].clone()],
                r#type: "gre".into(),
                remote: format!("198.18.{}.{}", i / 256, i % 256),
                rate_mbps: 1000,
                mitigation: "on_demand".into(),
                ..Default::default()
            })
            .collect(),
        sessions: (0..validation::SESSIONS_MAX)
            .map(|i| Session {
                id: format!("session-{i}"),
                peer_ip: format!("198.19.{}.{}", i / 256, i % 256),
                peer_as: 64512 + i as i64,
                prefixes: vec![protected[i].clone()],
                ..Default::default()
            })
            .collect(),
        protected,
        reputation: Some(ReputationPolicy {
            fast_pass: "egress".into(),
            penalty_box: true,
        }),
        challenge_secret: "secret".into(),
        ..Default::default()
    }
}
/// Sends a flow to every prefix, so each has its counters.
pub fn touch(pipe: &mut Pipeline, policy: &Policy) {
    for p in policy.protected.iter().filter(|p| p.ends_with(".0/24")) {
        let mut f = flow("192.0.2.1", "udp", 9, &[]);
        f.dst_ip = p.replace(".0/24", ".1");
        pipe.decide(&f, T0);
    }
}
