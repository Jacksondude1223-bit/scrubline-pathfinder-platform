use pathfinder::{
    discovery_capture::{self, Direction},
    model::{NodeTunnel, Program},
    pipeline::Pipeline,
};

const IFACE: &str = "scr-test";
const CLIENT: [u8; 4] = [192, 0, 2, 10];
const SERVER: [u8; 4] = [203, 0, 113, 10];
fn program() -> Program {
    Program {
        prefixes: vec!["203.0.113.10/32".into()],
        tunnels: vec![NodeTunnel {
            interface: IFACE.into(),
            prefixes: vec!["203.0.113.10/32".into()],
            ..Default::default()
        }],
        ..Default::default()
    }
}
fn seal(p: &mut [u8]) {
    p[10] = 0;
    p[11] = 0;
    let mut sum: u32 = p[..20]
        .chunks(2)
        .map(|b| u32::from(u16::from_be_bytes([b[0], b[1]])))
        .sum();
    while sum > 65535 {
        sum = (sum & 65535) + (sum >> 16);
    }
    p[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
}
fn packet(reply: bool, payload: &[u8], tcp: Option<u8>) -> Vec<u8> {
    let (src, dst, sport, dport) = if reply {
        (SERVER, CLIENT, 27015u16, 49152u16)
    } else {
        (CLIENT, SERVER, 49152u16, 27015u16)
    };
    let mut l4 = vec![];
    l4.extend(sport.to_be_bytes());
    l4.extend(dport.to_be_bytes());
    if let Some(flags) = tcp {
        l4.extend([0, 0, 0, 1, 0, 0, 0, 0, 0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
    } else {
        l4.extend(((8 + payload.len()) as u16).to_be_bytes());
        l4.extend([0, 0]);
    }
    l4.extend(payload);
    let mut ip = vec![0x45, 0];
    ip.extend(((20 + l4.len()) as u16).to_be_bytes());
    ip.extend([0, 1, 0x40, 0, 64, if tcp.is_some() { 6 } else { 17 }, 0, 0]);
    ip.extend(src);
    ip.extend(dst);
    ip.extend(l4);
    seal(&mut ip);
    ip
}
fn exchange(pipe: &mut Pipeline, request: &[u8], reply: &[u8], now: i64) {
    assert_eq!(
        pipe.observe_discovery_packet(IFACE, Direction::ToOrigin, request, now),
        Some(true)
    );
    assert_eq!(
        pipe.observe_discovery_packet(IFACE, Direction::FromOrigin, reply, now + 1),
        Some(true)
    );
}
fn discoveries(pipe: &mut Pipeline, now: i64) -> serde_json::Value {
    pipe.stats(now)["discovered_ports"].clone()
}

#[test]
fn real_ip_packets_feed_discovery_without_changing_inspection_counters() {
    let mut pipe = Pipeline::new(program());
    exchange(
        &mut pipe,
        &packet(false, b"hello", None),
        &packet(true, b"world", None),
        100_000,
    );
    let stats = pipe.stats(100_002);
    assert_eq!(stats["discovered_ports"][0]["protocol"], "unknown");
    assert_eq!(
        stats["discovered_ports"][0]["destination"],
        "203.0.113.10/32"
    );
    assert_eq!(stats["decisions"], 0);
    assert_eq!(stats["game_sessions"], 0);
    assert_eq!(stats["rate_buckets"], 0);
    assert_eq!(stats["egress"]["seen"], 0);
}

#[test]
fn captured_a2s_exchanges_produce_two_fresh_confirmations() {
    let mut pipe = Pipeline::new(program());
    let request = packet(false, b"\xff\xff\xff\xffTSource Engine Query\0", None);
    let reply = packet(true, b"\xff\xff\xff\xffA1234", None);
    for i in 1..=2 {
        exchange(&mut pipe, &request, &reply, 100_000 + i * 100);
        let rows = discoveries(&mut pipe, 100_000 + i * 100 + 2);
        assert_eq!(rows[0]["protocol"], "a2s");
        assert_eq!(rows[0]["confirmations"], i);
    }
}

#[test]
fn captured_raknet_ping_and_pong_are_classified() {
    let magic = [
        0, 255, 255, 0, 254, 254, 254, 254, 253, 253, 253, 253, 18, 52, 86, 120,
    ];
    let mut ping = vec![1];
    ping.extend([1u8; 8]);
    ping.extend(magic);
    ping.extend([2u8; 8]);
    let mut pong = vec![0x1c];
    pong.extend([1u8; 8]);
    pong.extend([3u8; 8]);
    pong.extend(magic);
    pong.extend([0, 0]);
    let mut pipe = Pipeline::new(program());
    exchange(
        &mut pipe,
        &packet(false, &ping, None),
        &packet(true, &pong, None),
        100_000,
    );
    assert_eq!(discoveries(&mut pipe, 100_002)[0]["protocol"], "raknet");
}

#[test]
fn only_the_protected_addresses_assigned_to_this_interface_are_observed() {
    let request = packet(false, b"hello", None);
    for config in [
        Program {
            tunnels: vec![],
            ..program()
        },
        Program {
            prefixes: vec![],
            ..program()
        },
    ] {
        assert_eq!(
            Pipeline::new(config).observe_discovery_packet(
                IFACE,
                Direction::ToOrigin,
                &request,
                100_000
            ),
            Some(false)
        );
    }
    let mut pipe = Pipeline::new(program());
    assert_eq!(
        pipe.observe_discovery_packet("scr-other", Direction::ToOrigin, &request, 100_000),
        Some(false)
    );
    assert_eq!(
        pipe.observe_discovery_packet(IFACE, Direction::FromOrigin, &request, 100_000),
        Some(false)
    );
    assert_eq!(discoveries(&mut pipe, 100_001), serde_json::json!([]));
}

#[test]
fn unsolicited_and_stale_replies_cannot_create_discoveries() {
    let mut pipe = Pipeline::new(program());
    let reply = packet(true, b"reply", None);
    pipe.observe_discovery_packet(IFACE, Direction::FromOrigin, &reply, 100_000);
    assert_eq!(discoveries(&mut pipe, 100_001), serde_json::json!([]));
    pipe.observe_discovery_packet(
        IFACE,
        Direction::ToOrigin,
        &packet(false, b"query", None),
        100_001,
    );
    pipe.observe_discovery_packet(IFACE, Direction::FromOrigin, &reply, 110_002);
    assert_eq!(discoveries(&mut pipe, 110_003), serde_json::json!([]));
}

#[test]
fn tcp_requires_syn_and_matching_syn_ack() {
    let mut pipe = Pipeline::new(program());
    exchange(
        &mut pipe,
        &packet(false, b"", Some(0x02)),
        &packet(true, b"", Some(0x12)),
        100_000,
    );
    assert_eq!(discoveries(&mut pipe, 100_002)[0]["transport"], "tcp");
    let mut pipe = Pipeline::new(program());
    exchange(
        &mut pipe,
        &packet(false, b"", Some(0x10)),
        &packet(true, b"", Some(0x10)),
        100_000,
    );
    assert_eq!(discoveries(&mut pipe, 100_002), serde_json::json!([]));
}

#[test]
fn malformed_fragments_and_truncated_packets_are_rejected() {
    let p = packet(false, b"query", None);
    for length in 0..p.len() {
        assert!(discovery_capture::flow(&p[..length]).is_none());
    }
    let mut malformed = p.clone();
    malformed[10] ^= 0xff;
    assert!(discovery_capture::flow(&malformed).is_none());
    let mut fragment = p;
    fragment[6] = 0x20;
    seal(&mut fragment);
    assert!(discovery_capture::flow(&fragment).is_none());
}

#[test]
fn removing_the_assignment_forgets_the_observed_service() {
    let mut pipe = Pipeline::new(program());
    exchange(
        &mut pipe,
        &packet(false, b"hello", None),
        &packet(true, b"reply", None),
        100_000,
    );
    assert_eq!(discoveries(&mut pipe, 100_002).as_array().unwrap().len(), 1);
    pipe.load(Program::default());
    assert_eq!(discoveries(&mut pipe, 100_003), serde_json::json!([]));
}

#[test]
fn capture_configuration_is_explicit_bounded_and_rejects_unsafe_names() {
    assert!(discovery_capture::interfaces("").unwrap().is_empty());
    assert_eq!(
        discovery_capture::interfaces("scr-a,scr-b,scr-a").unwrap(),
        ["scr-a", "scr-b"]
    );
    for value in [
        "lo",
        "../eno1",
        "scr-a,",
        "scr a",
        "scr-abcdefghijklmnop",
        "scr-a;id",
    ] {
        assert!(discovery_capture::interfaces(value).is_err());
    }
    assert!(discovery_capture::interfaces(
        &(0..17)
            .map(|i| format!("scr-{i}"))
            .collect::<Vec<_>>()
            .join(",")
    )
    .is_err());
}

#[test]
fn ipv6_udp_packets_are_scoped_and_discovered() {
    fn ipv6(reply: bool) -> Vec<u8> {
        let server = "2001:db8:100::10".parse::<std::net::Ipv6Addr>().unwrap();
        let client = "2001:db8:200::10".parse::<std::net::Ipv6Addr>().unwrap();
        let (src, dst, sp, dp) = if reply {
            (server, client, 27015u16, 49152u16)
        } else {
            (client, server, 49152u16, 27015u16)
        };
        let mut packet = vec![0x60, 0, 0, 0, 0, 9, 17, 64];
        packet.extend(src.octets());
        packet.extend(dst.octets());
        packet.extend(sp.to_be_bytes());
        packet.extend(dp.to_be_bytes());
        packet.extend([0, 9, 0, 1, 42]);
        packet
    }
    let mut p = program();
    p.prefixes = vec!["2001:db8:100::10/128".into()];
    p.tunnels[0].prefixes = p.prefixes.clone();
    let mut pipe = Pipeline::new(p);
    exchange(&mut pipe, &ipv6(false), &ipv6(true), 100_000);
    assert_eq!(
        discoveries(&mut pipe, 100_002)[0]["destination"],
        "2001:db8:100::10/128"
    );
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires an isolated Linux network namespace with 192.0.2.10 and 203.0.113.10 assigned to lo"]
fn linux_socket_observes_real_bidirectional_udp_exchanges() {
    use std::{
        net::UdpSocket,
        thread,
        time::{Duration, Instant},
    };
    let socket = discovery_capture::Socket::open("lo").unwrap();
    let client = UdpSocket::bind("192.0.2.10:0").unwrap();
    let server = UdpSocket::bind("203.0.113.10:27015").unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut p = program();
    p.tunnels[0].interface = "lo".into();
    let mut pipe = Pipeline::new(p);
    let mut buffer = vec![0u8; discovery_capture::PACKET_MAX];
    for _ in 0..2 {
        client
            .send_to(
                b"\xff\xff\xff\xffTSource Engine Query\0",
                "203.0.113.10:27015",
            )
            .unwrap();
        let (_, from) = server.recv_from(&mut buffer).unwrap();
        server.send_to(b"\xff\xff\xff\xffA1234", from).unwrap();
        let until = Instant::now() + Duration::from_millis(100);
        while Instant::now() < until {
            if let Some((length, Some(direction))) = socket.receive(&mut buffer).unwrap() {
                pipe.observe_discovery_packet("lo", direction, &buffer[..length], 100_000);
            } else {
                thread::sleep(Duration::from_millis(1));
            }
        }
    }
    let rows = discoveries(&mut pipe, 100_001);
    assert_eq!(rows[0]["protocol"], "a2s");
    assert_eq!(rows[0]["confirmations"], 2);
    assert!(socket.current("lo"));
    assert_eq!(socket.dropped().unwrap(), 0);
}

#[test]
fn capture_status_survives_the_typed_heartbeat_and_stays_out_of_global_summaries() {
    let value = serde_json::json!({"discovery_capture":{"scr-test":{"active":true,"packets":12,"observed":8,"kernel_dropped":3}}});
    let stats: pathfinder::wire::Stats = serde_json::from_value(value).unwrap();
    assert!(stats.discovery_capture.as_ref().unwrap()["scr-test"].active);
    assert_eq!(
        serde_json::to_value(&stats).unwrap()["discovery_capture"]["scr-test"]["observed"],
        8
    );
    assert!(stats.summary().discovery_capture.is_none());
}
