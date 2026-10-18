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
