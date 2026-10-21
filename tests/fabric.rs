use chrono::{DateTime, Duration, Utc};
use pathfinder::{bgp, compiler, model::*, steering, telemetry::Metrics, tunnel, validation};
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
    assert!(!text.contains("scrubline_tunnel_rate_limit"));
    let mut m = Metrics::new();
    let limited = NodeTunnel {
        id: "t".into(),
        remote: "198.18.0.9".into(),
        rate_kbps: 833333,
        ..Default::default()
    };
    m.tunnels(&n, &[limited], &[]);
    assert!(m.render().unwrap().contains(
        "scrubline_tunnel_rate_limit_bits_per_second{node=\"n\",name=\"n\",region=\"r\",tunnel=\"t\",remote=\"198.18.0.9\"} 8.33333e+08"
    ));
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
        node_tunnel("zeta", &["192.0.2.128/25"], "return"),
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
            // alpha's /48 sits inside mixed's /32 but is alpha's customer's, so mixed's customer
            // may not source from it.
            rule("mixed", "ip6 saddr { 2001:db8:1::/48 } drop"),
            rule("mixed", "ip6 saddr != { 2001:db8::/32 } drop"),
            rule("mixed", "tcp flags syn tcp option maxseg size set 1396"),
            // A return-only tunnel carries nothing back, so nothing coming up it is forwarded.
            rule("zeta", "drop"),
        ]
    );
    // Replies may come from every prefix of the tunnel, including ones steered away from this
    // node, and a prefix nested in another of the same tunnel is not repeated.
    let steered = NodeTunnel {
        sources: vec![
            "203.0.113.0/24".into(),
            "203.0.113.0/25".into(),
            "198.51.100.0/24".into(),
        ],
        ..node_tunnel("steered", &["203.0.113.0/24"], "")
    };
    assert_eq!(
        tunnel::reply_commands(&[steered]).unwrap()[0],
        rule(
            "steered",
            "ip saddr != { 198.51.100.0/24, 203.0.113.0/24 } drop"
        )
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
#[test]
fn a_tunnels_clean_traffic_allowance_is_capped_and_validated() {
    let t = Tunnel {
        id: "t".into(),
        remote: "198.51.100.1".into(),
        prefixes: vec!["203.0.113.0/24".into()],
        ..Default::default()
    };
    assert_eq!(tunnel::rate_mbps(&t), tunnel::MAX_RATE_MBPS);
    assert_eq!(tunnel::MAX_RATE_MBPS, 2500, "2.5 Gbit/s");
    for ok in [0, 1, 1000, 2500] {
        let v = Tunnel {
            rate_mbps: ok,
            ..t.clone()
        };
        tunnel::validate(&v, None).unwrap();
    }
    for bad in [-1, 2501, i64::MAX] {
        let v = Tunnel {
            rate_mbps: bad,
            ..t.clone()
        };
        assert!(tunnel::validate(&v, None).is_err(), "{bad}");
    }
    let n = Node {
        id: "n".into(),
        tunnel_src: "192.0.2.1".into(),
        ..Default::default()
    };
    let whole = |rate| {
        tunnel::for_node(
            &Tunnel {
                rate_mbps: rate,
                ..t.clone()
            },
            &n,
            &t.prefixes,
        )
        .unwrap()
        .rate_kbps
    };
    assert_eq!(whole(0), 2_500_000);
    assert_eq!(whole(1000), 1_000_000);
}
#[test]
fn the_allowance_is_split_across_the_nodes_sending_the_tunnel() {
    let prefix = "203.0.113.0/24";
    let policy = |rate_mbps, disabled: &[&str]| Policy {
        protected: vec![prefix.into()],
        tunnels: vec![Tunnel {
            id: "northwind".into(),
            remote: "198.18.0.9".into(),
            prefixes: vec![prefix.into()],
            rate_mbps,
            disabled: disabled.iter().map(|d| d.to_string()).collect(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let with_endpoint = |id: &str, src: &str| Node {
        tunnel_src: src.into(),
        ..node(id, "iad", 100.0, "")
    };
    let mut nodes = vec![
        with_endpoint("a", "192.0.2.1"),
        with_endpoint("b", "192.0.2.2"),
        with_endpoint("c", "192.0.2.3"),
    ];
    let shares = |p: &Policy, nodes: &[Node]| {
        let plan = compiler::plan(p, nodes, &HashMap::new(), &HashMap::new());
        let programs = compiler::compile(p, nodes, &plan);
        let mut out: Vec<_> = programs
            .values()
            .map(|prog| {
                (
                    prog.node_id.clone(),
                    prog.tunnels.first().map(|t| t.rate_kbps),
                )
            })
            .collect();
        out.sort();
        out
    };
    let three = |kbps| {
        vec![
            ("a".to_string(), Some(kbps)),
            ("b".to_string(), Some(kbps)),
            ("c".to_string(), Some(kbps)),
        ]
    };
    assert_eq!(shares(&policy(1500, &[]), &nodes), three(500_000));
    assert_eq!(
        shares(&policy(0, &[]), &nodes),
        three(833_333),
        "no allowance set is the 2.5 Gbit/s maximum, never more in total"
    );
    assert_eq!(
        shares(&policy(1500, &["c"]), &nodes),
        vec![
            ("a".to_string(), Some(750_000)),
            ("b".to_string(), Some(750_000)),
            ("c".to_string(), None),
        ],
        "a node the tunnel is disabled on sends nothing, so the others share the whole allowance"
    );
    // A node that stopped heartbeating is withdrawn: it is not sending, so it does not take a
    // share away from the nodes that are, but it gets the same share for what is still in flight.
    nodes[2].status = "stale".into();
    assert_eq!(shares(&policy(1500, &[]), &nodes), three(750_000),);
}
#[test]
fn rate_limits_render_as_a_shaper_on_the_tunnel() {
    let limited = |id: &str, kbps| NodeTunnel {
        rate_kbps: kbps,
        ..node_tunnel(id, &["203.0.113.0/24"], "")
    };
    assert_eq!(
        tunnel::rate_commands(&[
            limited("zeta", 0),
            limited("slow", 1000),
            limited("fast", 833_333)
        ])
        .unwrap(),
        [
            "tc qdisc replace dev scr-fast root tbf rate 833333kbit burst 1041666 latency 50ms",
            "tc qdisc replace dev scr-slow root tbf rate 1000kbit burst 32768 latency 50ms",
        ]
    );
}
#[test]
fn tunnels_allocated_to_a_customer_carry_only_their_prefixes() {
    let tenant = Tenant {
        id: "ten-1".into(),
        name: "northwind".into(),
        prefixes: vec!["203.0.112.0/22".into()],
        ..Default::default()
    };
    let p = |prefixes: &[&str], tenant: &str| Policy {
        tunnels: vec![Tunnel {
            id: "t".into(),
            prefixes: prefixes.iter().map(|p| p.to_string()).collect(),
            tenant: tenant.into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let tenants = [tenant];
    validation::tunnel_tenants(&p(&["203.0.113.0/24", "203.0.112.0/22"], "ten-1"), &tenants)
        .unwrap();
    validation::tunnel_tenants(&p(&["198.51.100.0/24"], ""), &tenants).unwrap();
    for (prefixes, tenant) in [
        (&["198.51.100.0/24"][..], "ten-1"),
        (&["203.0.112.0/21"][..], "ten-1"),
        (&["2001:db8::/32"][..], "ten-1"),
        (&["203.0.113.0/24"][..], "ten-2"),
    ] {
        assert!(
            validation::tunnel_tenants(&p(prefixes, tenant), &tenants).is_err(),
            "{prefixes:?} {tenant}"
        );
    }
}
#[test]
fn a_node_whose_address_is_the_tunnels_remote_withdraws_rather_than_breaking_its_tunnels() {
    let p = Policy {
        protected: vec!["203.0.113.0/24".into(), "198.51.100.0/24".into()],
        tunnels: vec![
            Tunnel {
                id: "loop".into(),
                remote: "192.0.2.1".into(),
                prefixes: vec!["203.0.113.0/24".into()],
                ..Default::default()
            },
            Tunnel {
                id: "fine".into(),
                remote: "198.18.0.9".into(),
                prefixes: vec!["198.51.100.0/24".into()],
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let n = Node {
        tunnel_src: "192.0.2.1".into(),
        ..node("a", "iad", 100.0, "")
    };
    let plan = compiler::plan(
        &p,
        std::slice::from_ref(&n),
        &HashMap::new(),
        &HashMap::new(),
    );
    let looped = plan.iter().find(|a| a.prefix == "203.0.113.0/24").unwrap();
    assert_eq!(looped.state, "withdraw");
    assert!(
        looped.reason.contains("would end where it starts"),
        "{}",
        looped.reason
    );
    let programs = compiler::compile(&p, &[n], &plan);
    let built: Vec<_> = programs["a"]
        .tunnels
        .iter()
        .map(|t| t.id.as_str())
        .collect();
    assert_eq!(built, ["fine"]);
    // The node's other tunnels still render; one impossible tunnel no longer fails them all.
    assert!(tunnel::commands(&programs["a"].tunnels).is_ok());
}
#[test]
fn replies_belong_to_the_tunnel_with_the_most_specific_prefix() {
    let rule = |name: &str, tail: &str| {
        format!("nft add rule inet scrubline forward iifname \"scr-{name}\" {tail}")
    };
    // a: 10.0.0.0/8 and 10.1.2.128/25; b: 10.1.2.0/24 between them.
    let a = node_tunnel("a", &["10.0.0.0/8", "10.1.2.128/25"], "");
    let b = node_tunnel("b", &["10.1.2.0/24"], "");
    let lines = tunnel::reply_commands(&[a.clone(), b]).unwrap();
    assert_eq!(
        &lines[..2],
        [
            rule("a", "ip saddr { 10.1.2.0/25 } drop"),
            rule("a", "ip saddr != { 10.0.0.0/8 } drop"),
        ],
        "a keeps its own /25 inside b's /24"
    );
    assert_eq!(
        &lines[3..5],
        [
            rule("b", "ip saddr { 10.1.2.128/25 } drop"),
            rule("b", "ip saddr != { 10.1.2.0/24 } drop"),
        ]
    );
    // Another customer's prefix is refused even when its tunnel is not built on this node: the
    // control plane names it.
    let alone = NodeTunnel {
        foreign: vec!["10.1.2.0/24".into()],
        ..node_tunnel("a", &["10.0.0.0/8"], "")
    };
    assert_eq!(
        tunnel::reply_commands(&[alone]).unwrap()[0],
        rule("a", "ip saddr { 10.1.2.0/24 } drop")
    );
}
#[test]
fn the_compiler_names_other_tunnels_prefixes_inside_each_tunnel() {
    let p = Policy {
        protected: vec!["10.0.0.0/8".into(), "10.1.2.0/24".into()],
        tunnels: vec![
            Tunnel {
                id: "wide".into(),
                remote: "198.18.0.9".into(),
                prefixes: vec!["10.0.0.0/8".into()],
                ..Default::default()
            },
            Tunnel {
                id: "narrow".into(),
                remote: "198.18.0.10".into(),
                prefixes: vec!["10.1.2.0/24".into()],
                disabled: vec!["a".into()],
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let n = Node {
        tunnel_src: "192.0.2.1".into(),
        ..node("a", "iad", 100.0, "")
    };
    let plan = compiler::plan(
        &p,
        std::slice::from_ref(&n),
        &HashMap::new(),
        &HashMap::new(),
    );
    let programs = compiler::compile(&p, &[n], &plan);
    let built = &programs["a"].tunnels;
    assert_eq!(built.len(), 1, "narrow is disabled here");
    assert_eq!(built[0].foreign, ["10.1.2.0/24"]);
}
#[test]
fn with_no_node_announcing_the_live_nodes_building_a_tunnel_split_it() {
    let p = Policy {
        protected: vec!["203.0.113.0/24".into()],
        tunnels: vec![Tunnel {
            id: "nw".into(),
            remote: "198.18.0.9".into(),
            prefixes: vec!["203.0.113.0/24".into()],
            required: true,
            rate_mbps: 1000,
            ..Default::default()
        }],
        ..Default::default()
    };
    let nodes: Vec<Node> = ["a", "b"]
        .iter()
        .enumerate()
        .map(|(i, id)| Node {
            tunnel_src: format!("192.0.2.{}", i + 1),
            ..node(id, "iad", 100.0, "")
        })
        .collect();
    // Required and never reported up: every node withdraws, but still builds the tunnel.
    let plan = compiler::plan(&p, &nodes, &HashMap::new(), &HashMap::new());
    assert!(plan.iter().all(|a| a.state == "withdraw"));
    let programs = compiler::compile(&p, &nodes, &plan);
    for id in ["a", "b"] {
        assert_eq!(programs[id].tunnels[0].rate_kbps, 500_000, "{id}");
    }
}
