use pathfinder::{
    model::{Node, Policy, Tenant},
    store::{hash, Store},
    validation,
};
use std::path::PathBuf;
fn temp() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "pathfinder-store-{}",
        pathfinder::store::secret().unwrap()
    ));
    std::fs::create_dir(&dir).unwrap();
    dir
}
#[test]
fn loads_go_snapshots_and_preserves_identity_and_credentials() {
    let dir = temp();
    let path = dir.join("state.json");
    std::fs::write(&path, include_bytes!("fixtures/go-snapshot.json")).unwrap();
    let mut store = Store::open(path.to_str().unwrap()).unwrap();
    assert_eq!(store.data.version, 1);
    assert_eq!(store.data.last_policy_id, "pol-1");
    assert_eq!(store.data.nodes[0].status, "stale");
    assert_eq!(
        store.data.node_tokens[&store.data.nodes[0].id],
        hash("fixture-node-token")
    );
    assert_eq!(
        store.data.tenant_tokens[&store.data.tenants[0].id],
        hash("fixture-tenant-token")
    );
    let previous = store.data.nodes[0].clone();
    let (node, token) = store
        .register(
            Node {
                name: "snapshot-node".into(),
                region: "us".into(),
                capacity_gbps: 100.0,
                tunnel_src: "192.0.2.1".into(),
                ..Default::default()
            },
            chrono::Utc::now(),
        )
        .unwrap();
    assert_eq!(node.id, previous.id);
    assert_eq!(store.data.node_tokens[&node.id], hash(&token));
    let raw = std::fs::read_to_string(&path).unwrap();
    assert!(!raw.contains(&token));
    let restored = Store::open(path.to_str().unwrap()).unwrap();
    assert_eq!(restored.data.node_tokens[&node.id], hash(&token));
    assert_eq!(restored.data.nodes[0].status, "stale");
    std::fs::remove_dir_all(dir).unwrap();
}
#[test]
fn failed_durable_writes_roll_back_mutations_and_credentials() {
    let dir = temp();
    let path = dir.join("state.json");
    let mut store = Store::open(path.to_str().unwrap()).unwrap();
    let (node, token) = store
        .register(
            Node {
                name: "n".into(),
                region: "us".into(),
                ..Default::default()
            },
            chrono::Utc::now(),
        )
        .unwrap();
    let old_hash = hash(&token);
    std::fs::remove_file(&path).unwrap();
    std::fs::remove_dir(&dir).unwrap();
    assert!(store.issue(&node.id, false).is_err());
    assert_eq!(store.data.node_tokens[&node.id], old_hash);
    assert!(store
        .save_policy(
            Policy {
                name: "p".into(),
                protected: vec!["203.0.113.0/24".into()],
                ..Default::default()
            },
            chrono::Utc::now()
        )
        .is_err());
    assert!(store.data.policies.is_empty());
    assert!(store
        .save_tenant(
            Tenant {
                name: "t".into(),
                prefixes: vec!["203.0.113.0/24".into()],
                ..Default::default()
            },
            chrono::Utc::now()
        )
        .is_err());
    assert!(store.data.tenants.is_empty());
}
#[test]
fn rejects_unknown_missing_and_invalid_snapshot_formats() {
    let dir = temp();
    let path = dir.join("state.json");
    for raw in ["{}", "{\"version\":2}", "broken"] {
        std::fs::write(&path, raw).unwrap();
        assert!(
            Store::open(path.to_str().unwrap()).is_err(),
            "accepted {raw}"
        );
    }
    std::fs::remove_dir_all(dir).unwrap();
}
#[test]
fn policy_validation_rejects_unenforceable_configurations() {
    let mut p = Policy {
        name: "test".into(),
        protected: vec!["203.0.113.0/24".into()],
        ..Default::default()
    };
    validation::policy(&p).unwrap();
    p.rules.push(pathfinder::model::Rule {
        id: "r".into(),
        stage: "asic".into(),
        action: "rate_limit".into(),
        pps: 100,
        ..Default::default()
    });
    assert!(validation::policy(&p).is_err());
    p.rules[0].stage = "zc".into();
    validation::policy(&p).unwrap();
    p.rules[0].action = "count".into();
    assert!(validation::policy(&p).is_err());
    p.rules.clear();
    p.egress = Some(pathfinder::model::EgressPolicy {
        lockdown: "drop".into(),
        grace_millis: 1,
        ..Default::default()
    });
    assert!(validation::policy(&p).is_err());
}
#[test]
fn policy_validation_rejects_configurations_that_render_broken() {
    let base = Policy {
        name: "test".into(),
        protected: vec!["203.0.113.0/24".into(), "2001:db8::/32".into()],
        ..Default::default()
    };
    validation::policy(&base).unwrap();
    let mut p = base.clone();
    p.protected.push("203.0.113.0/24".into());
    assert!(validation::policy(&p).is_err());
    let session = |id: &str, peer: &str, prefix: &str| pathfinder::model::Session {
        id: id.into(),
        peer_ip: peer.into(),
        peer_as: 64512,
        prefixes: vec![prefix.into()],
        ..Default::default()
    };
    let mut p = base.clone();
    p.sessions = vec![session("peer", "192.0.2.9", "203.0.113.0/24")];
    validation::policy(&p).unwrap();
    p.sessions = vec![session("peer", "2001:db8::9", "203.0.113.0/24")];
    assert!(validation::policy(&p).is_err());
    p.sessions = vec![session("peer", "192.0.2.9", "2001:db8::/32")];
    assert!(validation::policy(&p).is_err());
    p.sessions = vec![
        session("peer-a", "192.0.2.9", "203.0.113.0/24"),
        session("peer_a", "192.0.2.10", "203.0.113.0/24"),
    ];
    assert!(validation::policy(&p).is_err());
}
#[test]
fn policy_validation_rejects_rules_that_never_match_and_respelled_prefixes() {
    let rule = |proto: &str, flags: &str| pathfinder::model::Rule {
        id: "r".into(),
        stage: "asic".into(),
        action: "drop".into(),
        r#match: pathfinder::model::Match {
            proto: proto.into(),
            tcp_flags: flags.into(),
            ..Default::default()
        },
        ..Default::default()
    };
    let mut p = Policy {
        name: "test".into(),
        protected: vec!["203.0.113.0/24".into()],
        ..Default::default()
    };
    for (proto, flags, ok) in [
        ("UDP", "", true),
        ("tcp", "syn,ack", true),
        ("UPD sport=53 pri=0", "", false),
        ("6", "", false),
        ("tcp", "syn ack", false),
    ] {
        p.rules = vec![rule(proto, flags)];
        assert_eq!(validation::policy(&p).is_ok(), ok, "{proto:?} {flags:?}");
    }
    p.rules.clear();
    for protected in [
        ["2001:db8::/32", "2001:DB8::/32"],
        ["203.0.113.0/24", "203.0.113.7/24"],
    ] {
        p.protected = protected.iter().map(|s| s.to_string()).collect();
        assert!(validation::policy(&p).is_err(), "{protected:?}");
    }
}
#[test]
fn assigned_tunnel_endpoints_survive_a_restart_and_reregistration() {
    let dir = temp();
    let path = dir.join("state.json");
    let mut store = Store::open(path.to_str().unwrap()).unwrap();
    let edge = || Node {
        name: "edge".into(),
        region: "iad".into(),
        tunnel_src: "192.0.2.9".into(),
        ..Default::default()
    };
    let (node, _) = store.register(edge(), chrono::Utc::now()).unwrap();
    store
        .transaction(|d| {
            d.tunnel_endpoints
                .insert(node.id.clone(), "192.0.2.1".into());
            Ok(())
        })
        .unwrap();
    let mut restored = Store::open(path.to_str().unwrap()).unwrap();
    let now = chrono::Utc::now();
    assert_eq!(restored.nodes(now)[0].tunnel_src, "192.0.2.1");
    let (again, _) = restored.register(edge(), now).unwrap();
    assert_eq!(
        again.tunnel_src, "192.0.2.9",
        "answered with what it registered"
    );
    assert_eq!(restored.nodes(now)[0].tunnel_src, "192.0.2.1");
    assert_eq!(
        restored.data.nodes[0].tunnel_src, "192.0.2.9",
        "the registered address is kept to fall back to"
    );
    std::fs::remove_dir_all(dir).unwrap();
}
#[test]
fn a_tunnel_address_two_live_nodes_registered_is_neither_of_theirs() {
    let mut store = Store::open("").unwrap();
    let now = chrono::Utc::now();
    for name in ["edge-a", "edge-b"] {
        let n = Node {
            name: name.into(),
            region: "iad".into(),
            tunnel_src: "192.0.2.9".into(),
            ..Default::default()
        };
        store.register(n, now).unwrap();
    }
    assert!(store.nodes(now).iter().all(|n| n.tunnel_src.is_empty()));
    // Once one goes quiet, the live one keeps it.
    let later = now + chrono::Duration::seconds(31);
    let b = store
        .data
        .nodes
        .iter()
        .find(|n| n.name == "edge-b")
        .unwrap()
        .id
        .clone();
    store
        .data
        .nodes
        .iter_mut()
        .find(|n| n.id == b)
        .unwrap()
        .last_seen = later;
    let nodes = store.nodes(later);
    let src = |name: &str| {
        nodes
            .iter()
            .find(|n| n.name == name)
            .unwrap()
            .tunnel_src
            .clone()
    };
    assert_eq!(
        (src("edge-a"), src("edge-b")),
        ("".into(), "192.0.2.9".into())
    );
}
