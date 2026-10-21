use chrono::{DateTime, Duration, Utc};
use pathfinder::{bgp, compiler, model::*, steering, telemetry::Metrics, tunnel};
use std::collections::HashMap;
fn node(id: &str, region: &str, gbps: f64, advertise: &str) -> Node {
    Node {
        id: id.into(),
        name: id.into(),
        region: region.into(),
        capacity_gbps: gbps,
        advertise: advertise.into(),
        status: "ready".into(),
        ..Default::default()
    }
}
#[test]
fn capacity_padding_is_relative_to_the_nodes_announcing_the_prefix() {
    let p = Policy {
        protected: vec!["203.0.113.0/24".into()],
        steering: vec![Steering {
            prefix: "203.0.113.0/24".into(),
            regions: vec!["sin".into()],
            ..Default::default()
        }],
        ..Default::default()
    };
    let nodes = [node("a", "iad", 100.0, ""), node("c", "sin", 40.0, "")];
    let plan = compiler::plan(&p, &nodes, &HashMap::new(), &HashMap::new());
    assert_eq!(plan.len(), 1);
    assert_eq!((plan[0].node_id.as_str(), plan[0].prepends), ("c", 0));
}
#[test]
fn only_an_address_becomes_a_next_hop() {
    let p = Policy {
        protected: vec!["203.0.113.0/24".into()],
        ..Default::default()
    };
    let nodes = [
        node("a", "iad", 100.0, "node-a:9091"),
        node("b", "iad", 100.0, "198.51.100.1:9091"),
    ];
    let plan = compiler::plan(&p, &nodes, &HashMap::new(), &HashMap::new());
    let hops: Vec<_> = plan.iter().map(|a| a.next_hop.as_str()).collect();
    assert_eq!(hops, ["", "198.51.100.1"]);
    bgp::commands(&plan, 64512).unwrap();
}
#[test]
fn communities_render_the_way_exabgp_reads_them() {
    assert!(bgp::validate_community("+64512:100").is_err());
    assert!(bgp::validate_community("64512:+100").is_err());
    let a = Announcement {
        prefix: "203.0.113.0/24".into(),
        node_id: "a".into(),
        state: "announce".into(),
        communities: vec!["64512:100".into(), "64512:1:2".into(), "no-export".into()],
        ..Default::default()
    };
    assert_eq!(
        bgp::commands(&[a], 64512).unwrap(),
        ["announce route 203.0.113.0/24 community [ 64512:100 no-export ] large-community [ 64512:1:2 ]"]
    );
}
#[test]
fn session_import_limits_fit_bird() {
    let mut s = Session {
        id: "peer".into(),
        peer_ip: "192.0.2.9".into(),
        peer_as: 64512,
        prefixes: vec!["203.0.113.0/24".into()],
        max_prefixes: u32::MAX as i64,
        ..Default::default()
    };
    bgp::validate_session(&s, None).unwrap();
    s.max_prefixes += 1;
    assert!(bgp::validate_session(&s, None).is_err());
}
#[test]
fn tunnels_carrying_ipv6_clamp_for_ipv6_and_refuse_ipip() {
    let t = Tunnel {
        id: "v6".into(),
        remote: "198.18.0.10".into(),
        prefixes: vec!["2001:db8::/32".into()],
        ..Default::default()
    };
    tunnel::validate(&t, None).unwrap();
    let n = Node {
        id: "n".into(),
        tunnel_src: "192.0.2.1".into(),
        ..Default::default()
    };
    let nt = tunnel::for_node(&t, &n, &t.prefixes).unwrap();
    assert_eq!((nt.mtu, nt.mss_clamp), (1476, 1416));
    for bad in [
        Tunnel {
            r#type: "ipip".into(),
            ..t.clone()
        },
        Tunnel {
            mss_clamp: 1436,
            ..t.clone()
        },
    ] {
        assert!(tunnel::validate(&bad, None).is_err());
    }
}
#[test]
fn load_padding_unwinds_when_a_node_stops_declaring_capacity() {
    let t0: DateTime<Utc> = "2026-01-01T00:00:00Z".parse().unwrap();
    let mut c = steering::Controller::default();
    let mut s = steering::Sample {
        node_id: "n".into(),
        offered_pps: 95000,
        capacity_pps: 100000,
        fresh: true,
        ..Default::default()
    };
    for i in 0..4 {
        c.observe_at(&[s.clone()], t0 + Duration::seconds(31 * i));
    }
    assert_eq!(c.levels()["n"].prepends, 3);
    s.capacity_pps = 0;
    let out = c.observe_at(&[s], t0 + Duration::seconds(130));
    assert_eq!(out["n"], 0);
}
#[test]
fn a_tunnel_reported_unknown_still_counts_as_reported() {
    let n = Node {
        id: "n".into(),
        name: "n".into(),
        region: "r".into(),
        ..Default::default()
    };
    let t = NodeTunnel {
        id: "t".into(),
        remote: "198.18.0.9".into(),
        mtu: 1476,
        ..Default::default()
    };
    let mut m = Metrics::new();
    m.tunnels(
        &n,
        &[t],
        &[TunnelStatus {
            tunnel_id: "t".into(),
            state: "unknown".into(),
            ..Default::default()
        }],
    );
    let text = m.render().unwrap();
    assert!(text.contains(
        "scrubline_tunnel_reported{node=\"n\",name=\"n\",region=\"r\",tunnel=\"t\",remote=\"198.18.0.9\"} 1"
    ));
    assert!(!text.contains("scrubline_tunnel_up"));
}
fn node_tunnel(id: &str, prefixes: &[&str], direction: &str) -> NodeTunnel {
    NodeTunnel {
        id: id.into(),
        r#type: "gre".into(),
        local: "192.0.2.1".into(),
        remote: "198.51.100.1".into(),
        prefixes: prefixes.iter().map(|p| p.to_string()).collect(),
        mtu: 1476,
        direction: direction.into(),
        ..Default::default()
    }
}
#[test]
fn replies_up_a_tunnel_may_only_come_from_its_own_prefixes() {
    let rule = |name: &str, tail: &str| {
        format!("nft add rule inet scrubline forward iifname \"scr-{name}\" {tail}")
    };
    let tunnels = [
        node_tunnel("zeta", &["203.0.113.0/24"], "return"),
        NodeTunnel {
            mss_clamp: 1396,
            ..node_tunnel(
                "mixed",
                &["2001:db8::/32", "198.51.100.0/24", "203.0.113.0/25"],
                "both",
            )
        },
        node_tunnel("alpha", &["2001:db8:1::/48"], ""),
    ];
    assert_eq!(
        tunnel::reply_commands(&tunnels).unwrap(),
        [
            rule("alpha", "meta nfproto ipv4 drop"),
            rule("alpha", "ip6 saddr != { 2001:db8:1::/48 } drop"),
            rule(
                "mixed",
                "ip saddr != { 198.51.100.0/24, 203.0.113.0/25 } drop"
            ),
            rule("mixed", "ip6 saddr != { 2001:db8::/32 } drop"),
            rule("mixed", "tcp flags syn tcp option maxseg size set 1396"),
        ],
        "a return-only tunnel carries nothing back, so it gets no reply rules"
    );
    assert!(tunnel::carries_replies(&node_tunnel("t", &[], "")));
    assert!(!tunnel::carries_replies(&node_tunnel("t", &[], "return")));
    let mut bad = node_tunnel("t", &["not-a-prefix"], "both");
    assert!(tunnel::reply_commands(std::slice::from_ref(&bad)).is_err());
    bad.prefixes = vec!["203.0.113.0/24".into()];
    bad.id = "Not-Valid".into();
    assert!(tunnel::reply_commands(&[bad]).is_err());
}
#[test]
fn tunnel_direction_and_disabled_nodes_are_validated() {
    let t = Tunnel {
        id: "t".into(),
        remote: "198.51.100.1".into(),
        prefixes: vec!["203.0.113.0/24".into()],
        ..Default::default()
    };
    for direction in ["", "both", "return"] {
        let ok = Tunnel {
            direction: direction.into(),
            disabled: vec!["node-a".into(), "node-b".into()],
            ..t.clone()
        };
        tunnel::validate(&ok, None).unwrap();
    }
    for bad in [
        Tunnel {
            direction: "inbound".into(),
            ..t.clone()
        },
        Tunnel {
            disabled: vec!["node-a".into(), "node-a".into()],
            ..t.clone()
        },
        Tunnel {
            disabled: vec![" ".into()],
            ..t.clone()
        },
    ] {
        assert!(tunnel::validate(&bad, None).is_err(), "{bad:?}");
    }
}
#[test]
fn disabling_a_tunnel_on_a_node_withdraws_its_prefixes_there() {
    let prefix = "203.0.113.0/24";
    let p = Policy {
        protected: vec![prefix.into(), "198.51.100.0/24".into()],
        tunnels: vec![Tunnel {
            id: "northwind".into(),
            remote: "198.18.0.9".into(),
            prefixes: vec![prefix.into()],
            disabled: vec!["a".into()],
            ..Default::default()
        }],
        ..Default::default()
    };
    let with_endpoint = |id: &str, src: &str| Node {
        tunnel_src: src.into(),
        ..node(id, "iad", 100.0, "")
    };
    let nodes = [
        with_endpoint("a", "192.0.2.1"),
        with_endpoint("b", "192.0.2.2"),
    ];
    let plan = compiler::plan(&p, &nodes, &HashMap::new(), &HashMap::new());
    let row = |node: &str, prefix: &str| {
        plan.iter()
            .find(|a| a.node_id == node && a.prefix == prefix)
            .unwrap()
            .clone()
    };
    assert_eq!(row("a", prefix).state, "withdraw");
    assert_eq!(
        row("a", prefix).reason,
        "return tunnel northwind is disabled on this node"
    );
    assert_eq!(
        row("a", "198.51.100.0/24").state,
        "announce",
        "other prefixes are untouched"
    );
    assert_eq!(row("b", prefix).state, "announce");
    let programs = compiler::compile(&p, &nodes, &plan);
    assert!(programs["a"].tunnels.is_empty());
    assert_eq!(programs["a"].tunnel_src, "192.0.2.1");
    let built = &programs["b"].tunnels;
    assert_eq!(built.len(), 1);
    assert_eq!(
        (built[0].local.as_str(), built[0].remote.as_str()),
        ("192.0.2.2", "198.18.0.9")
    );
    assert_eq!(programs["b"].tunnel_src, "192.0.2.2");
}
