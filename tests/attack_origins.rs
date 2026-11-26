use pathfinder::{
    analytics::Collector,
    model::{Flow, GameFilter, Program},
    pipeline::Pipeline,
};
use serde_json::{json, Value};
const PREFIX: &str = "203.0.113.20/32";
fn program() -> Program {
    Program {
        prefixes: vec![PREFIX.into()],
        games: vec![GameFilter {
            id: "game".into(),
            profile: "raknet".into(),
            proto: "udp".into(),
            dport: 19132,
            dst_cidr: PREFIX.into(),
            ..Default::default()
        }],
        ..Default::default()
    }
}
fn report(samples: u64, packets: u64, rate: u64) -> Value {
    json!({"prefixes":[{"prefix":PREFIX,"flows":packets,"flows_dropped":packets,"offered":packets,"dropped":packets,"offered_pps":rate,"dropped_pps":rate}],"origin_samples":{"epoch":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","provider":"dbip","destination":{"longitude":-78.87,"latitude":42.89,"label":"Buffalo"},"limited":0,"prefixes":[{"prefix":PREFIX,"generation":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","countries":{"MX":samples},"unknown":samples/2}]}})
}
#[test]
fn countries_follow_an_open_attack_without_importing_pre_attack_or_tail_samples() {
    let mut collector = Collector::default();
    let program = program();
    collector.observe("n", &report(100, 1000, 0), &program, 1000);
    collector.observe("n", &report(200, 60000, 10000), &program, 2000);
    let first = collector.events(PREFIX, 86400000, 2000);
    assert!(first[0].get("origin_samples").is_none());
    collector.observe("n", &report(220, 120000, 10000), &program, 3000);
    let event = collector.events(PREFIX, 86400000, 3000).remove(0);
    assert_eq!(event["origin_samples"]["countries"][0]["packets"], 20);
    assert_eq!(event["origin_samples"]["unknownPackets"], 10);
    collector.observe("n", &report(220, 120000, 10000), &program, 4000);
    collector.observe("n", &report(400, 120100, 0), &program, 40000);
    collector.observe("n", &report(500, 120200, 0), &program, 161000);
    let ended = collector.events(PREFIX, 86400000, 161000).remove(0);
    assert_eq!(ended["origin_samples"]["countries"][0]["packets"], 20);
    assert!(!ended["ongoing"].as_bool().unwrap());
}
#[test]
fn unknown_prefix_samples_never_become_another_prefixs_origins() {
    let mut collector = Collector::default();
    let program = program();
    let mut data = report(10, 0, 10000);
    data["origin_samples"]["prefixes"][0]["prefix"] = json!("198.51.100.0/24");
    collector.observe("n", &data, &program, 1000);
    data["origin_samples"]["prefixes"][0]["countries"]["MX"] = json!(20);
    collector.observe("n", &data, &program, 2000);
    assert!(collector.events(PREFIX, 86400000, 2000)[0]
        .get("origin_samples")
        .is_none());
    assert!(collector
        .events("198.51.100.0/24", 86400000, 2000)
        .is_empty());
}
#[test]
fn inline_verdicts_feed_actual_per_prefix_attack_counters() {
    let mut pipe = Pipeline::new(program());
    let flow = Flow {
        src_ip: "81.2.69.160".into(),
        dst_ip: "203.0.113.20".into(),
        proto: "udp".into(),
        dport: 19132,
        sport: 45000,
        has_payload: true,
        payload: vec![0xff],
        pps: 1,
        ..Default::default()
    };
    assert_eq!(pipe.inline_game(&flow, 1000).action, "drop");
    let stats = pipe.stats(1000);
    assert_eq!(stats["prefixes"][0]["offered"], 1);
    assert_eq!(stats["prefixes"][0]["dropped"], 1);
    assert_eq!(stats["decisions"], 1);
    assert_eq!(pipe.origin_prefix("203.0.113.20").as_deref(), Some(PREFIX));
    assert_eq!(pipe.origin_prefix("198.51.100.1"), None);
}

#[test]
fn resuming_an_attack_does_not_import_samples_from_the_quiet_interval() {
    let mut collector = Collector::default();
    let program = program();
    collector.observe("n", &report(100, 1000, 0), &program, 1000);
    collector.observe("n", &report(200, 60000, 10000), &program, 2000);
    collector.observe("n", &report(220, 120000, 10000), &program, 3000);
    collector.observe("n", &report(240, 120100, 0), &program, 4000);
    collector.observe("n", &report(260, 180000, 10000), &program, 5000);
    collector.observe("n", &report(280, 240000, 10000), &program, 6000);
    assert_eq!(
        collector.events(PREFIX, 86400000, 6000)[0]["origin_samples"]["countries"][0]["packets"],
        40
    );
}
