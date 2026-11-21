use base64::{engine::general_purpose::STANDARD, Engine};
use pathfinder::{
    model::*,
    provision::{self, Desired, Observed, Runner},
    tunnel, validation, wireguard,
};
use std::{collections::BTreeMap, os::unix::fs::PermissionsExt};

fn tunnel() -> Tunnel {
    Tunnel {
        id: "wg1".into(),
        r#type: "wireguard".into(),
        node: "a".into(),
        local: "192.0.2.2".into(),
        prefixes: vec!["203.0.113.10/32".into()],
        wireguard: Some(WireGuard {
            public_key: STANDARD.encode([1u8; 32]),
            listen_port: 20000,
        }),
        ..Default::default()
    }
}
fn node_tunnel() -> NodeTunnel {
    tunnel::for_node(
        &tunnel(),
        &Node {
            id: "a".into(),
            ..Default::default()
        },
        &tunnel().prefixes,
    )
    .unwrap()
}
fn desired() -> Desired {
    let t = node_tunnel();
    Desired {
        lines: tunnel::commands(std::slice::from_ref(&t))
            .unwrap()
            .into_iter()
            .chain(tunnel::reply_commands(std::slice::from_ref(&t)).unwrap())
            .collect(),
        tunnels: vec![t],
        ..Default::default()
    }
}
#[test]
fn nat_peers_compile_with_safe_mtu_and_source_bound_return_rules() {
    tunnel::validate(&tunnel(), None).unwrap();
    let t = node_tunnel();
    assert_eq!((t.mtu, t.mss_clamp), (1420, 1380));
    let d = desired();
    let pass = provision::plan(&d, &Observed::default()).unwrap();
    assert!(pass
        .steps
        .iter()
        .any(|s| s.argv == ["ip", "link", "add", "scr-wg1", "type", "wireguard"]));
    assert!(pass.nft.contains("ip saddr != { 203.0.113.10/32 } drop"));
    let mut observed = Observed::default();
    observed.links = BTreeMap::from([(
        "scr-wg1".into(),
        "ip link add scr-wg1 type wireguard".into(),
    )]);
    let second = provision::plan(&d, &observed).unwrap();
    assert!(!second.steps.iter().any(|s| s.argv.starts_with(&[
        "ip".into(),
        "link".into(),
        "del".into()
    ])));
}
#[test]
fn keys_ports_and_incompatible_transports_are_rejected() {
    let mut t = tunnel();
    t.wireguard.as_mut().unwrap().public_key = "not a key".into();
    assert!(tunnel::validate(&t, None).is_err());
    let mut t = tunnel();
    t.key = 42;
    assert!(tunnel::validate(&t, None).is_err());
    let mut t = tunnel();
    t.node.clear();
    assert!(tunnel::validate(&t, None).is_err());
    let mut t = tunnel();
    t.r#type = "gre".into();
    assert!(tunnel::validate(&t, None).is_err());
    let mut t = tunnel();
    t.wireguard.as_mut().unwrap().listen_port = 0;
    assert!(tunnel::validate(&t, None).is_err());
    let first = tunnel();
    let mut second = first.clone();
    second.id = "wg2".into();
    second.local = "192.0.2.3".into();
    second.prefixes = vec!["203.0.113.11/32".into()];
    let p = Policy {
        name: "WireGuard".into(),
        protected: [first.prefixes.clone(), second.prefixes.clone()].concat(),
        tunnels: vec![first, second],
        ..Default::default()
    };
    assert!(validation::policy(&p).unwrap_err().contains("listen ports"));
}
#[derive(Default)]
struct Fake {
    calls: Vec<(Vec<String>, Option<String>)>,
    handshake: u64,
    fail: bool,
}
impl Runner for Fake {
    fn run(&mut self, argv: &[String], stdin: Option<&str>) -> pathfinder::Result<String> {
        self.calls.push((argv.to_vec(), stdin.map(String::from)));
        if argv == ["wg", "genkey"] {
            return Ok(STANDARD.encode([2u8; 32]));
        }
        match argv.last().map(String::as_str) {
            Some("public-key") => Ok(STANDARD.encode([3u8; 32])),
            Some("listen-port") => Ok("20000".into()),
            Some("latest-handshakes") => Ok(format!(
                "{}\t{}\n",
                STANDARD.encode([1u8; 32]),
                self.handshake
            )),
            _ if self.fail => Err(format!("failure containing {}", stdin.unwrap_or_default())),
            _ => Ok(String::new()),
        }
    }
}
#[test]
fn node_keys_persist_with_private_permissions_and_errors_do_not_leak_them() {
    let directory = std::env::temp_dir().join(format!("wg-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    let t = node_tunnel();
    let mut fake = Fake::default();
    wireguard::configure(&mut fake, &t, &directory).unwrap();
    wireguard::configure(&mut fake, &t, &directory).unwrap();
    assert_eq!(
        fake.calls
            .iter()
            .filter(|(args, _)| args == &["wg", "genkey"])
            .count(),
        1
    );
    let path = directory.join("scr-wg1.key");
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let config = fake.calls.last().unwrap().1.as_ref().unwrap();
    assert!(config.contains("AllowedIPs = 203.0.113.10/32"));
    assert!(!config.contains("Endpoint"));
    fake.fail = true;
    let error = wireguard::configure(&mut fake, &t, &directory).unwrap_err();
    assert!(!error.contains(&STANDARD.encode([2u8; 32])));
    std::fs::remove_dir_all(directory).unwrap();
}
#[test]
fn reported_up_requires_a_recent_authenticated_handshake_and_exposes_only_public_data() {
    let d = desired();
    let mut fake = Fake::default();
    for (age, up) in [(0, true), (180, true), (181, false)] {
        fake.handshake = chrono::Utc::now().timestamp() as u64 - age;
        let mut report = provision::report(&d, &provision::Applied::default());
        wireguard::report(&mut fake, &d, &mut report);
        assert_eq!(
            report["tunnels"][0]["state"],
            if up { "up" } else { "down" }
        );
        assert_eq!(
            report["tunnels"][0]["wireguard"]["public_key"],
            STANDARD.encode([3u8; 32])
        );
        assert!(!report.to_string().contains("private"));
    }
    fake.handshake = 0;
    let mut report = provision::report(&d, &provision::Applied::default());
    wireguard::report(&mut fake, &d, &mut report);
    assert_eq!(report["tunnels"][0]["state"], "down");
}
