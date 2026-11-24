use pathfinder::{
    inline::{self, Verdict},
    model::{Flow, GameFilter, NodeTunnel, PortForward, Program, ReputationPolicy},
    packet,
    pipeline::Pipeline,
    provision, tunnel,
};

const T0: i64 = 1767225600000;

fn game(id: &str, proto: &str, dport: i64, profile: &str) -> GameFilter {
    GameFilter {
        id: id.into(),
        proto: proto.into(),
        dport,
        profile: profile.into(),
        ..Default::default()
    }
}
fn tunnel(id: &str, prefixes: &[&str]) -> NodeTunnel {
    NodeTunnel {
        id: id.into(),
        interface: format!("scr-{id}"),
        prefixes: prefixes.iter().map(|p| p.to_string()).collect(),
        ..Default::default()
    }
}
fn program(games: Vec<GameFilter>) -> Program {
    Program {
        prefixes: vec!["203.0.113.0/24".into()],
        tunnels: vec![tunnel("game", &["203.0.113.0/24"])],
        games,
        challenge_secret: "secret".into(),
        reputation: Some(ReputationPolicy {
            penalty_box: true,
            ..Default::default()
        }),
        ..Default::default()
    }
}
fn udp(src: &str, dst: &str, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let src: std::net::Ipv4Addr = src.parse().unwrap();
    let dst: std::net::Ipv4Addr = dst.parse().unwrap();
    let mut p = vec![0x45, 0];
    p.extend(((28 + payload.len()) as u16).to_be_bytes());
    p.extend([0, 1, 0x40, 0, 64, 17, 0, 0]);
    p.extend(src.octets());
    p.extend(dst.octets());
    p.extend(sport.to_be_bytes());
    p.extend(dport.to_be_bytes());
    p.extend(((8 + payload.len()) as u16).to_be_bytes());
    p.extend([0, 0]);
    p.extend(payload);
    let mut sum: u32 = p[..20]
        .chunks(2)
        .map(|b| u32::from(u16::from_be_bytes([b[0], b[1]])))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    p[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    p
}
fn judge(pipe: &mut Pipeline, src: &str, dport: u16, payload: &[u8], now: i64) -> String {
    let f = inline::flow(&udp(src, "203.0.113.10", 50000, dport, payload)).unwrap();
    pipe.inline_game(&f, now).action.to_string()
}

#[test]
fn only_enforcing_udp_profiles_on_a_port_are_queued() {
    let mut observing = game("watch", "udp", 7777, "raknet");
    observing.observe = true;
    let mut http_only = game("web", "tcp", 0, "");
    http_only.http = Some(Default::default());
    let mut prog = program(vec![
        game("mc", "udp", 19132, "raknet"),
        game("src", "", 27015, "a2s"),
        game("tcp", "tcp", 25565, "raknet"),
        game("everywhere", "udp", 0, "raknet"),
        observing,
        http_only,
    ]);
    prog.tunnels.push(NodeTunnel {
        port_forward: Some(PortForward {
            backend: "198.18.0.2".parse().unwrap(),
            ports: vec![19132],
        }),
        ..tunnel("fwd", &["203.0.113.50/32"])
    });
    prog.tunnels.push(NodeTunnel {
        direction: "return".into(),
        ..tunnel("ret", &["203.0.113.60/32"])
    });
    assert_eq!(
        tunnel::inline_commands(&prog, 3).unwrap(),
        vec![
            "nft add rule inet scrubline game_inline oifname \"scr-game\" ip daddr 203.0.113.0/24 udp dport 19132 queue num 3 bypass",
            "nft add rule inet scrubline game_inline oifname \"scr-game\" ip daddr 203.0.113.0/24 udp dport 27015 queue num 3 bypass",
        ]
    );
}

#[test]
fn a_filter_bound_to_an_address_is_queued_only_where_that_address_is_routed() {
    let mut inside = game("one", "udp", 19132, "raknet");
    inside.dst_cidr = "203.0.113.10/32".into();
    let mut elsewhere = game("other", "udp", 19133, "raknet");
    elsewhere.dst_cidr = "198.51.100.0/24".into();
    let mut prog = program(vec![inside, elsewhere]);
    prog.tunnels.push(tunnel("v6", &["2001:db8::/48"]));
    let mut v6 = game("six", "udp", 19134, "raknet");
    v6.dst_cidr = "2001:db8::1/128".into();
    prog.games.push(v6);
    assert_eq!(
        tunnel::inline_commands(&prog, 0).unwrap(),
        vec![
            "nft add rule inet scrubline game_inline oifname \"scr-game\" ip daddr 203.0.113.10/32 udp dport 19132 queue num 0 bypass",
            "nft add rule inet scrubline game_inline oifname \"scr-v6\" ip6 daddr 2001:db8::1/128 udp dport 19134 queue num 0 bypass",
        ]
    );
}

#[test]
fn the_provisioner_applies_queue_rules_and_refuses_anything_else_in_their_chain() {
    let prog = program(vec![game("mc", "udp", 19132, "raknet")]);
    let lines = tunnel::inline_commands(&prog, 0).unwrap();
    let desired = provision::Desired {
        lines: lines.clone(),
        ..Default::default()
    };
    let pass = provision::plan(&desired, &provision::Observed::default()).unwrap();
    assert!(pass
        .nft
        .contains("type filter hook forward priority 20; policy accept;"));
    assert!(pass.nft.contains(
        "add rule inet scrubline game_inline oifname \"scr-game\" ip daddr 203.0.113.0/24 udp dport 19132 queue num 0 bypass\n"
    ));
    for bad in [
        // Without bypass a stopped agent would black-hole the customers' game traffic.
        "nft add rule inet scrubline game_inline oifname \"scr-game\" ip daddr 203.0.113.0/24 udp dport 19132 queue num 0",
        "nft add rule inet scrubline game_inline oifname \"eth0\" ip daddr 203.0.113.0/24 udp dport 19132 queue num 0 bypass",
        "nft add rule inet scrubline game_inline oifname \"sbh-*\" ip daddr 203.0.113.0/24 udp dport 19132 queue num 0 bypass",
        "nft add rule inet scrubline game_inline oifname \"scr-game\" ip6 daddr 203.0.113.0/24 udp dport 19132 queue num 0 bypass",
        "nft add rule inet scrubline game_inline oifname \"scr-game\" ip daddr 203.0.113.0/24 udp dport 0 queue num 0 bypass",
        "nft add rule inet scrubline game_inline oifname \"scr-game\" ip daddr 203.0.113.0/24 udp dport 19132 queue num 70000 bypass",
        "nft add rule inet scrubline game_inline oifname \"scr-game\" ip daddr 203.0.113.0/24 udp dport 19132 accept",
        "nft add rule inet scrubline game_inline oifname \"scr-game\" ip daddr 203.0.113.0/24 tcp dport 19132 queue num 0 bypass",
    ] {
        let desired = provision::Desired {
            lines: vec![bad.into()],
            ..Default::default()
        };
        assert!(
            provision::plan(&desired, &provision::Observed::default()).is_err(),
            "{bad}"
        );
    }
}

#[test]
fn a_handshake_gate_drops_strangers_and_admits_players_who_complete_it() {
    let mut pipe = Pipeline::new(program(vec![game("mc", "udp", 19132, "raknet")]));
    // Game data from a source that never connected.
    assert_eq!(
        judge(&mut pipe, "192.0.2.1", 19132, &[0x84, 0, 0], T0),
        "drop"
    );
    // A player opening and completing the handshake, then playing.
    assert_eq!(judge(&mut pipe, "192.0.2.2", 19132, &[0x05], T0), "permit");
    assert_eq!(
        judge(&mut pipe, "192.0.2.2", 19132, &[0x07], T0 + 1),
        "permit"
    );
    for i in 0..20 {
        assert_eq!(
            judge(&mut pipe, "192.0.2.2", 19132, &[0x84, 0, 0], T0 + 2 + i),
            "permit"
        );
    }
    // Ports and addresses no filter is bound to are not judged.
    assert_eq!(judge(&mut pipe, "192.0.2.1", 19133, &[0x84], T0), "permit");
    let f = inline::flow(&udp("192.0.2.1", "198.51.100.1", 50000, 19132, &[0x84])).unwrap();
    assert_eq!(pipe.inline_game(&f, T0).action, "permit");
}

#[test]
fn an_a2s_query_is_challenged_and_passes_once_it_carries_the_cookie() {
    let mut pipe = Pipeline::new(program(vec![game("src", "udp", 27015, "a2s")]));
    let query = b"\xff\xff\xff\xffTSource Engine Query\0";
    let f = inline::flow(&udp("192.0.2.5", "203.0.113.10", 50000, 27015, query)).unwrap();
    let d = pipe.inline_game(&f, T0);
    assert_eq!(d.action, "challenge");
    assert_eq!(&d.reply[..5], b"\xff\xff\xff\xffA");
    let mut answered = query.to_vec();
    answered.extend_from_slice(&d.reply[5..9]);
    let f = inline::flow(&udp("192.0.2.5", "203.0.113.10", 50000, 27015, &answered)).unwrap();
    assert_eq!(pipe.inline_game(&f, T0 + 10).action, "permit");
    // Once admitted, the server's own challenge round passes too.
    let mut server_cookie = query.to_vec();
    server_cookie.extend_from_slice(&[1, 2, 3, 4]);
    let f = inline::flow(&udp(
        "192.0.2.5",
        "203.0.113.10",
        50000,
        27015,
        &server_cookie,
    ))
    .unwrap();
    assert_eq!(pipe.inline_game(&f, T0 + 20).action, "permit");
    // Junk without the protocol's header is dropped.
    assert_eq!(
        judge(&mut pipe, "192.0.2.6", 27015, b"junkjunk", T0),
        "drop"
    );
}

#[test]
fn an_observing_filter_never_drops_inline() {
    let mut g = game("mc", "udp", 19132, "raknet");
    g.observe = true;
    let mut pipe = Pipeline::new(program(vec![g]));
    assert_eq!(
        judge(&mut pipe, "192.0.2.1", 19132, &[0x84, 0, 0], T0),
        "permit"
    );
}

#[test]
fn queued_tcp_and_unreadable_packets_are_not_judged() {
    let mut tcp = udp("192.0.2.1", "203.0.113.10", 50000, 19132, &[]);
    tcp[9] = 6;
    assert!(inline::flow(&tcp).is_none());
    assert!(inline::flow(&[0x45, 0, 0]).is_none());
    assert!(inline::flow(&udp("192.0.2.1", "203.0.113.10", 50000, 19132, &[1])).is_some());
}

#[test]
fn challenge_replies_come_from_the_protected_address_with_valid_checksums() {
    let f = inline::flow(&udp(
        "192.0.2.5",
        "203.0.113.10",
        50000,
        27015,
        b"\xff\xff\xff\xffTx",
    ))
    .unwrap();
    let reply = inline::reply_packet(&f, b"\xff\xff\xff\xffA1234").unwrap();
    let (p, anomaly) = packet::parse(&reply);
    assert!(anomaly.is_none(), "{anomaly:?}");
    assert_eq!(p.src, Some("203.0.113.10".parse().unwrap()));
    assert_eq!(p.dst, Some("192.0.2.5".parse().unwrap()));
    assert_eq!((p.sport, p.dport), (27015, 50000));
    assert_eq!(p.payload, b"\xff\xff\xff\xffA1234");
    // The UDP checksum over the pseudo-header sums to all ones.
    let udp = &reply[20..];
    let mut pseudo = reply[12..20].to_vec();
    pseudo.extend([0, 17]);
    pseudo.extend((udp.len() as u16).to_be_bytes());
    pseudo.extend(udp);
    let mut sum: u32 = pseudo
        .chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    assert_eq!(sum, 0xffff);

    let v6 = Flow {
        src_ip: "2001:db8::5".into(),
        dst_ip: "2001:db8:1::10".into(),
        proto: "udp".into(),
        sport: 50000,
        dport: 27015,
        ..Default::default()
    };
    let reply = inline::reply_packet(&v6, b"\xff\xff\xff\xffA1234").unwrap();
    assert_eq!(reply[0] >> 4, 6);
    assert_eq!(u16::from_be_bytes([reply[4], reply[5]]), 17);
    assert_eq!(
        &reply[8..24],
        &"2001:db8:1::10"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets()
    );
}

#[test]
fn kernel_queue_counters_and_the_queue_flag_are_read_exactly() {
    let table = "    0  12345     0 2 65535     0     0       10  1\n    3  12346     5 2 65535    17     4       99  1\n";
    assert_eq!(inline::kernel_counters(table, 3), Some((17, 4)));
    assert_eq!(inline::kernel_counters(table, 1), None);
    assert_eq!(inline::queue_number("").unwrap(), None);
    assert_eq!(inline::queue_number("7").unwrap(), Some(7));
    assert!(inline::queue_number("70000").is_err());
    assert!(inline::queue_number("-1").is_err());
}

#[test]
fn verdicts_compare_by_value() {
    assert_eq!(Verdict::Challenge(vec![1]), Verdict::Challenge(vec![1]));
    assert_ne!(Verdict::Accept, Verdict::Drop);
}

/// Runs the real queue: iptables hands loopback UDP to NFQUEUE 7 (this kernel test box has no
/// nft queue expression; production renders the nft rule), the reader judges it with an A2S
/// filter, the unverified query is dropped and challenged from the server's address, and the
/// query carrying the cookie reaches the server.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires root in an isolated network namespace with 192.0.2.10 and 203.0.113.10 on lo and an iptables NFQUEUE rule for udp dport 27015 to queue 7; run each alone"]
fn the_queue_reader_enforces_verdicts_on_real_packets() {
    use std::{
        net::UdpSocket,
        sync::{Arc, Mutex},
        time::Duration,
    };
    let pipe = Arc::new(Mutex::new(Pipeline::new(program(vec![game(
        "src", "udp", 27015, "a2s",
    )]))));
    let status = Arc::new(Mutex::new(inline::Status::default()));
    {
        let pipe = pipe.clone();
        let status = status.clone();
        std::thread::spawn(move || {
            inline::run(
                7,
                |flows, now| {
                    let mut p = pipe.lock().unwrap();
                    flows
                        .iter()
                        .map(|f| match f {
                            None => Verdict::Accept,
                            Some(f) => {
                                let d = p.inline_game(f, now);
                                match d.action.as_str() {
                                    "drop" => Verdict::Drop,
                                    "challenge" => Verdict::Challenge(d.reply),
                                    _ => Verdict::Accept,
                                }
                            }
                        })
                        .collect()
                },
                |s| *status.lock().unwrap() = s.clone(),
            )
        });
    }
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        status.lock().unwrap().active,
        "{:?}",
        status.lock().unwrap()
    );
    let client = UdpSocket::bind("192.0.2.10:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let server = UdpSocket::bind("203.0.113.10:27015").unwrap();
    server
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let query = b"\xff\xff\xff\xffTSource Engine Query\0";
    let mut buffer = [0u8; 256];

    client.send_to(query, "203.0.113.10:27015").unwrap();
    let (n, from) = client.recv_from(&mut buffer).unwrap();
    assert_eq!(from.to_string(), "203.0.113.10:27015");
    assert_eq!(n, 9);
    assert_eq!(&buffer[..5], b"\xff\xff\xff\xffA");
    let cookie = buffer[5..9].to_vec();
    assert!(
        server.recv_from(&mut [0u8; 256]).is_err(),
        "the unverified query reached the server"
    );

    let mut answered = query.to_vec();
    answered.extend(cookie);
    client.send_to(&answered, "203.0.113.10:27015").unwrap();
    let (n, _) = server.recv_from(&mut buffer).unwrap();
    assert_eq!(&buffer[..n], &answered[..]);

    let junk = UdpSocket::bind("192.0.2.10:0").unwrap();
    junk.send_to(b"junkjunk", "203.0.113.10:27015").unwrap();
    assert!(
        server.recv_from(&mut buffer).is_err(),
        "junk reached the server"
    );
    std::thread::sleep(Duration::from_millis(1100));
    let s = status.lock().unwrap().clone();
    assert_eq!((s.accepted, s.dropped, s.challenged), (1, 1, 1), "{s:?}");
    assert_eq!(s.replies_failed, 0);
}

/// An agent that stops answering (held up on its lock, say) holds the packets already queued, and
/// the kernel forwards the rest unjudged once the queue is full.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires root in an isolated network namespace with 192.0.2.10 and 203.0.113.10 on lo and an iptables NFQUEUE rule for udp dport 27015 to queue 7; run each alone"]
fn a_stuck_agent_fails_open_once_its_queue_is_full() {
    use std::{net::UdpSocket, time::Duration};
    std::thread::spawn(|| {
        inline::run(
            7,
            |_, _| loop {
                std::thread::sleep(Duration::from_secs(3600));
            },
            |_| {},
        )
    });
    std::thread::sleep(Duration::from_millis(300));
    let server = UdpSocket::bind("203.0.113.10:27015").unwrap();
    server
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    // A packet held in the queue is charged to the local socket that sent it, so one socket's
    // buffer would fill before the queue does; forwarded packets have no such socket.
    let mut total = 0;
    for _ in 0..64 {
        let client = UdpSocket::bind("192.0.2.10:0").unwrap();
        client.set_nonblocking(true).unwrap();
        for _ in 0..200 {
            if client.send_to(b"junkjunk", "203.0.113.10:27015").is_ok() {
                total += 1;
            }
        }
    }
    assert!(
        total > inline::QUEUE_MAXLEN as usize + 100,
        "only {total} sent"
    );
    let mut received = 0;
    while server.recv_from(&mut [0u8; 64]).is_ok() {
        received += 1;
    }
    assert!(received >= 50, "only {received} of {total} were forwarded");
}
