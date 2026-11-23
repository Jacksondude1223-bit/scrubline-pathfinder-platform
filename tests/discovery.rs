use pathfinder::{
    discovery::{Discovery, RETENTION_MS},
    model::Flow,
};

fn request(proto: &str) -> Flow {
    Flow {
        src_ip: "192.0.2.10".into(),
        dst_ip: "203.0.113.10".into(),
        proto: proto.into(),
        sport: 49152,
        dport: 27015,
        flags: if proto == "tcp" {
            "syn".into()
        } else {
            "".into()
        },
        pps: 1,
        ..Default::default()
    }
}
fn reply(request: &Flow) -> Flow {
    Flow {
        src_ip: request.dst_ip.clone(),
        dst_ip: request.src_ip.clone(),
        sport: request.dport,
        dport: request.sport,
        flags: if request.proto == "tcp" {
            "syn,ack".into()
        } else {
            "".into()
        },
        ..request.clone()
    }
}

#[test]
fn the_first_valid_tcp_or_udp_reply_is_visible_immediately() {
    for proto in ["tcp", "udp"] {
        let mut discovery = Discovery::default();
        let request = request(proto);
        discovery.request(&request, 100_000);
        assert!(discovery.report(100_000).is_empty());
        discovery.reply(&reply(&request), 100_001);
        let rows = discovery.report(100_001);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].confirmations, 1);
        assert_eq!(rows[0].port, 27015);
        assert_eq!(rows[0].transport, proto);
    }
}

#[test]
fn scans_unsolicited_replies_resets_and_mismatched_exchanges_do_not_qualify() {
    for proto in ["tcp", "udp"] {
        let mut discovery = Discovery::default();
        let request = request(proto);
        let response = reply(&request);
        discovery.reply(&response, 100_000);
        assert!(discovery.report(100_000).is_empty());
        discovery.request(&request, 100_001);
        let wrong_port = Flow {
            dport: 49153,
            ..response.clone()
        };
        discovery.reply(&wrong_port, 100_002);
        assert!(discovery.report(100_002).is_empty());
        if proto == "tcp" {
            let reset = Flow {
                flags: "rst,ack".into(),
                ..response.clone()
            };
            discovery.reply(&reset, 100_003);
            assert!(discovery.report(100_003).is_empty());
        }
        discovery.reply(&response, 100_004);
        assert_eq!(discovery.report(100_004)[0].confirmations, 1);
        discovery.reply(&response, 100_005);
        assert_eq!(discovery.report(100_005)[0].confirmations, 1);
    }
}

#[test]
fn stale_exchanges_are_rejected_and_discovered_ports_expire() {
    let request = request("udp");
    let response = reply(&request);
    let mut discovery = Discovery::default();
    discovery.request(&request, 100_000);
    discovery.reply(&response, 110_001);
    assert!(discovery.report(110_001).is_empty());
    discovery.request(&request, 120_000);
    discovery.reply(&response, 120_001);
    assert_eq!(discovery.report(120_001).len(), 1);
    assert!(discovery.report(120_002 + RETENTION_MS).is_empty());
}

#[test]
fn a_query_is_classified_on_its_first_reply_and_confirmation_counts_keep_growing() {
    let mut request = request("udp");
    request.payload = b"\xff\xff\xff\xffTSource Engine Query\0".to_vec();
    let mut response = reply(&request);
    response.payload = b"\xff\xff\xff\xffA1234".to_vec();
    let mut discovery = Discovery::default();
    for count in 1..=2 {
        let now = 100_000 + count * 10;
        discovery.request(&request, now);
        discovery.reply(&response, now + 1);
        let rows = discovery.report(now + 1);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].protocol, "a2s");
        assert_eq!(rows[0].confirmations, count as u64);
    }
}
