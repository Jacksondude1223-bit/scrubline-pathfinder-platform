use pathfinder::{
    discovery::{a2s_info, auto_filter, raknet_pong},
    wire::{DiscoveredPort, GameMetadata},
};

const MAGIC: [u8; 16] = [
    0, 255, 255, 0, 254, 254, 254, 254, 253, 253, 253, 253, 18, 52, 86, 120,
];

/// An A2S_INFO answer as a Source server sends it, with the extra data flags `edf` and the game
/// port they may carry.
fn info(app: u16, edf: Option<(u8, u16)>) -> Vec<u8> {
    let mut p = b"\xff\xff\xff\xffI\x11".to_vec();
    for s in ["My Server", "de_dust2", "cstrike", "Counter-Strike: Source"] {
        p.extend(s.as_bytes());
        p.push(0);
    }
    p.extend(app.to_le_bytes());
    p.extend([12, 32, 0, b'd', b'l', 0, 1]);
    p.extend(b"1.0.0.71\0");
    if let Some((flags, port)) = edf {
        p.push(flags);
        if flags & 0x80 != 0 {
            p.extend(port.to_le_bytes());
        }
        if flags & 0x10 != 0 {
            p.extend(76561197960287930u64.to_le_bytes());
        }
        if flags & 0x20 != 0 {
            p.extend(b"secure,tags\0");
        }
        if flags & 0x01 != 0 {
            p.extend(240u64.to_le_bytes());
        }
    }
    p
}
fn pong(advertised: &str) -> Vec<u8> {
    let mut p = vec![0x1c];
    p.extend([0; 8]);
    p.extend([7; 8]);
    p.extend(MAGIC);
    p.extend((advertised.len() as u16).to_be_bytes());
    p.extend(advertised.as_bytes());
    p
}
fn row(protocol: &str, port: u16, metadata: Option<GameMetadata>) -> DiscoveredPort {
    DiscoveredPort {
        destination: "203.0.113.10/32".into(),
        port,
        transport: "udp".into(),
        protocol: protocol.into(),
        first_seen_ms: 0,
        last_seen_ms: 0,
        confirmations: 2,
        metadata,
        auto_filter: None,
    }
}

#[test]
fn an_a2s_info_answer_describes_the_server_and_its_game_port() {
    let m = a2s_info(&info(240, Some((0x80 | 0x10 | 0x20 | 0x01, 27015)))).unwrap();
    assert_eq!(m.game.as_deref(), Some("Counter-Strike: Source"));
    assert_eq!(m.folder.as_deref(), Some("cstrike"));
    assert_eq!(m.name.as_deref(), Some("My Server"));
    assert_eq!(m.version.as_deref(), Some("1.0.0.71"));
    assert_eq!((m.players, m.max_players), (Some(12), Some(32)));
    assert_eq!(m.app_id, Some(240));
    assert_eq!(m.game_port, Some(27015));
    assert_eq!(m.dedicated, Some(true));
    // Without extra data the port is unknown, and a truncated answer is still described as far as
    // it goes.
    assert_eq!(a2s_info(&info(240, None)).unwrap().game_port, None);
    let cut = info(240, Some((0x80, 27015)));
    assert_eq!(a2s_info(&cut[..cut.len() - 1]).unwrap().game_port, None);
    assert!(a2s_info(b"\xff\xff\xff\xffA1234").is_none());
    assert!(a2s_info(b"\xff\xff\xff\xffI\x11no terminator").is_none());
}

#[test]
fn hostile_metadata_is_bounded_and_printable() {
    let mut p = b"\xff\xff\xff\xffI\x11".to_vec();
    p.extend(format!("<b>{}\x07\x1b[31m", "x".repeat(500)).as_bytes());
    p.push(0);
    p.extend(b"m\0f\0g\0");
    p.extend([0, 0, 1, 2, 0, b'd', b'l', 0, 0]);
    let m = a2s_info(&p).unwrap();
    let name = m.name.unwrap();
    assert_eq!(name.chars().count(), pathfinder::wire::METADATA_TEXT_MAX);
    assert!(!name.chars().any(char::is_control));
    assert_eq!(m.app_id, None);
}

#[test]
fn a_bedrock_pong_identifies_the_edition_and_its_port() {
    let m = raknet_pong(&pong(
        "MCPE;Dedicated Server;712;1.21.20;3;10;13253860892328930865;Bedrock level;Survival;1;19132;19133;",
    ))
    .unwrap();
    assert_eq!(m.game.as_deref(), Some("Minecraft: Bedrock Edition"));
    assert_eq!(m.edition.as_deref(), Some("MCPE"));
    assert_eq!(m.name.as_deref(), Some("Dedicated Server"));
    assert_eq!(m.version.as_deref(), Some("1.21.20"));
    assert_eq!((m.players, m.max_players), (Some(3), Some(10)));
    assert_eq!(m.game_port, Some(19132));
    let other = raknet_pong(&pong("SomeOtherGame;hello")).unwrap();
    assert_eq!(other.game.as_deref(), Some("SomeOtherGame"));
    assert_eq!(other.edition, None);
}

#[test]
fn a2s_filters_only_a_dedicated_query_port_the_metadata_names() {
    let described = |port| a2s_info(&info(240, Some((0x80, port))));
    let d = auto_filter(&row("a2s", 27016, described(27015)));
    assert!(d.eligible, "{}", d.reason);
    assert_eq!(d.profile.as_deref(), Some("a2s"));
    // The game's own traffic on the query port: an A2S filter would drop players.
    let d = auto_filter(&row("a2s", 27015, described(27015)));
    assert!(!d.eligible);
    assert!(d.reason.contains("would drop players"), "{}", d.reason);
    // No game port in the answer, or only a challenge seen: not proven dedicated.
    assert!(!auto_filter(&row("a2s", 27015, a2s_info(&info(240, None)))).eligible);
    let d = auto_filter(&row("a2s", 27015, None));
    assert!(!d.eligible);
    assert!(d.reason.contains("A2S_INFO"), "{}", d.reason);
}

#[test]
fn raknet_filters_only_an_identified_bedrock_server_on_its_own_port() {
    let advertised = |port: u16| {
        raknet_pong(&pong(&format!(
            "MCPE;Server;712;1.21.20;0;10;1;level;Survival;1;{port};{port};"
        )))
    };
    let d = auto_filter(&row("raknet", 19132, advertised(19132)));
    assert!(d.eligible, "{}", d.reason);
    assert_eq!(d.profile.as_deref(), Some("raknet"));
    assert!(!auto_filter(&row("raknet", 19132, advertised(19200))).eligible);
    assert!(!auto_filter(&row("raknet", 19132, raknet_pong(&pong("SomeOtherGame;x")))).eligible);
    assert!(!auto_filter(&row("raknet", 19132, None)).eligible);
}

#[test]
fn unclassified_and_tcp_ports_never_qualify() {
    assert!(!auto_filter(&row("unknown", 7777, None)).eligible);
    let mut tcp = row("unknown", 25565, None);
    tcp.transport = "tcp".into();
    assert!(!auto_filter(&tcp).eligible);
}
