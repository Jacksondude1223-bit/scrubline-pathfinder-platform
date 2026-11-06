//! The fabric at the most it is built to hold, against what a 16 GB server gives each part:
//! scripts/install.sh lets the node agent have 2G, reclaiming from it past 1536M, and the control
//! plane 10G, reclaiming past 8G. This builds every part at its bounds, works out the control
//! plane for the largest fabric from a few of its nodes, and holds each to three quarters of
//! where reclaiming starts or less, which leaves room for what the allocator keeps that it is not
//! using.
//!
//! Every byte the allocator is asked for counts while it is held, and a reallocation as both what
//! it moves from and to. It takes optimisations to run in reasonable time:
//! `cargo test --release --test memory -- --nocapture` prints what each part holds.
mod common;
use common::{flow, largest_policy, source, touch, T0, V6};
use pathfinder::{
    analytics::Collector, api, compiler, ml, model::*, node, packet, pipeline::Pipeline, store,
    telemetry::Metrics, validation, wire,
};
use serde_json::json;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    collections::HashMap,
    sync::atomic::{AtomicUsize, Ordering::Relaxed},
};

/// Counts the bytes allocated and not yet freed, and the most there have been since PEAK was set.
struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
fn grew(n: usize) {
    let now = LIVE.fetch_add(n, Relaxed) + n;
    PEAK.fetch_max(now, Relaxed);
}
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(l) };
        if !p.is_null() {
            grew(l.size());
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) };
        LIVE.fetch_sub(l.size(), Relaxed);
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc_zeroed(l) };
        if !p.is_null() {
            grew(l.size());
        }
        p
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, size: usize) -> *mut u8 {
        let q = unsafe { System.realloc(p, l, size) };
        if !q.is_null() {
            grew(size);
            LIVE.fetch_sub(l.size(), Relaxed);
        }
        q
    }
}
#[global_allocator]
static HEAP: Counting = Counting;

const MIB: usize = 1 << 20;
const GIB: usize = 1 << 30;
/// How many nodes the control plane is measured with: the largest fabric is this many times over.
const MEASURED: usize = 16;
/// The most one open connection holds: hyper's read and write buffers, and a TLS session.
const CONNECTION: usize = 128 << 10;

/// What building `T` leaves held.
fn held<T>(build: impl FnOnce() -> T) -> (T, usize) {
    let before = LIVE.load(Relaxed);
    let v = build();
    (v, LIVE.load(Relaxed).saturating_sub(before))
}
/// The most `run` holds at once beyond what was held before it.
fn peak<T>(run: impl FnOnce() -> T) -> (T, usize) {
    let before = LIVE.load(Relaxed);
    PEAK.store(before, Relaxed);
    let v = run();
    (v, PEAK.load(Relaxed) - before)
}
/// Fills every table a node's pipeline keeps by source past its bound, through every kind of
/// traffic: a game server, a capped service, a SYN, a site behind an HTTP filter and a request
/// to it left unfinished, a reflected CLDAP answer, the penalty box and return traffic.
fn fill(pipe: &mut Pipeline) {
    for i in 0..70_000 {
        let src = source(i);
        pipe.decide(&flow(&src, "udp", 19132, &[0x05]), T0 + 1);
        pipe.decide(&flow(&src, "udp", 19132, &[0x07]), T0 + 1);
        pipe.decide(&flow(&src, "tcp", 443, &[]), T0 + 1);
        let syn = Flow {
            flags: "syn".into(),
            ..flow(&src, "tcp", 443, &[])
        };
        pipe.decide(&syn, T0 + 1);
        let request = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n";
        pipe.decide(&flow(&src, "tcp", 80, request), T0 + 1);
        let unfinished = Flow {
            sport: 50001,
            ..flow(&src, "tcp", 80, b"GET / HTTP/1.1\r\nHost: a\r\n")
        };
        pipe.decide(&unfinished, T0 + 1);
        let answer = [0x30, 0x84, 0x00, 0x00, 0x0b, 0xb0, 0x02, 0x01, 0x01, 0x64];
        let reflected = Flow {
            sport: 389,
            ..flow(&src, "udp", 27015, &answer)
        };
        pipe.decide(&reflected, T0 + 1);
        pipe.reputation.strike(&src, T0 + 1);
        let reply = Flow {
            src_ip: "2001:db8:100::10".into(),
            dst_ip: src,
            proto: "udp".into(),
            pps: 1,
            ..Default::default()
        };
        pipe.observe_return(&reply, T0 + 1);
    }
}
/// A day of attacks on as many prefixes as analytics follows: every one of them attacked as often
/// as their history keeps, each attack by as many vectors as it keeps.
fn history() -> Collector {
    let prefixes: Vec<String> = (0..256).map(|i| format!("10.0.{i}.0/24")).collect();
    let rules: Vec<String> = (0..32).map(|i| format!("rule-{i}")).collect();
    let program = Program {
        prefixes: prefixes.clone(),
        asic: rules
            .iter()
            .map(|id| ACLEntry {
                rule_id: id.clone(),
                r#match: Match {
                    dst_cidr: "10.0.0.0/16".into(),
                    ..Default::default()
                },
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    };
    let mut c = Collector::default();
    let mut counted = 0u64;
    // Rules are reported only while their drops are an attack's vectors: between attacks they
    // would only slow this down.
    let mut report = |c: &mut Collector, at: i64, attacked: bool, rules_too: bool| {
        counted += 1_000_000;
        let dropped = if attacked { 50_000 } else { 0 };
        let mut stats = json!({
            "prefixes": prefixes.iter().map(|p| json!({"prefix":p,"flows":counted,"flows_dropped":counted,"offered":counted,"dropped":counted,"offered_pps":100_000,"dropped_pps":dropped})).collect::<Vec<_>>(),
        });
        if rules_too {
            stats["rules"] = rules
                .iter()
                .map(
                    |id| json!({"rule_id":id,"stage":"asic","drops":counted,"pps_dropped":counted}),
                )
                .collect();
        }
        c.observe("node-0", &stats, &program, at);
    };
    let mut at = T0;
    report(&mut c, at, false, true);
    for _ in 0..130 {
        for attacked in [true, true, false, false, false, false, false] {
            at += 30_000;
            report(&mut c, at, attacked, attacked);
        }
    }
    while at < T0 + 25 * 3_600_000 {
        at += 60_000;
        report(&mut c, at, false, false);
    }
    c
}
fn breakdown(parts: &[(&str, usize)]) -> String {
    parts
        .iter()
        .map(|(what, bytes)| format!("  {what}: {} MiB", bytes / MIB))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "measures the fabric at its bounds, which takes a release build"
)]
fn the_fabric_at_its_bounds_fits_a_16_gb_server() {
    let policy = largest_policy();
    let fleet: Vec<Node> = (0..MEASURED)
        .map(|i| Node {
            id: format!("node-{i}"),
            name: format!("node-{i}"),
            region: format!("r{}", i % 8),
            capacity_gbps: 40.0,
            advertise: format!("192.0.2.{}:9091", i + 1),
            tunnel_src: format!("192.0.2.{}", i + 1),
            status: "ready".into(),
            ..Default::default()
        })
        .collect();
    let ((plan, programs), compiled) = held(|| {
        let plan = compiler::plan(&policy, &fleet, &HashMap::new(), &HashMap::new());
        let programs = compiler::compile(&policy, &fleet, &plan);
        (plan, programs)
    });
    let program = programs["node-0"].clone();
    let program_json = serde_json::to_vec(&program).unwrap().len();

    // A node: its pipeline with every table full, the fragments in reassembly past their bound,
    // and what its API may hold. The tables keyed by source have bounds of their own, whatever
    // the program, so they are filled through a program with only what the traffic reaches,
    // which the datapath judges far faster than the largest.
    let (mut pipe, programmed) = held(|| {
        let mut pipe = Pipeline::new(program.clone());
        touch(&mut pipe, &policy);
        pipe
    });
    let small = Policy {
        rules: vec![policy.rules[validation::RULES_MAX - 1].clone()],
        games: policy.games[..2].to_vec(),
        tunnels: vec![],
        sessions: vec![],
        protected: vec![V6.into()],
        ..policy.clone()
    };
    let one = &fleet[..1];
    let small = compiler::compile(
        &small,
        one,
        &compiler::plan(&small, one, &HashMap::new(), &HashMap::new()),
    );
    let (_empty, empty) = held(|| Pipeline::new(small["node-0"].clone()));
    let (mut filled, tables) = held(|| {
        let mut pipe = Pipeline::new(small["node-0"].clone());
        fill(&mut pipe);
        pipe
    });
    let full = filled.stats(T0 + 2);
    for (table, bound) in [
        (&full["game_sessions"], 65536),
        (&full["game_http_windows"], 65536),
        (&full["reputation"]["tracked"], 65536),
        (&full["egress"]["clients"], 65536),
        (&full["rate_buckets"], 65536),
        (&full["reflection"]["sources"], 65536),
        (&full["game_http_pending"], 16384),
    ] {
        assert_eq!(table, &json!(bound), "a table was not filled");
    }
    let pipeline = programmed + tables - empty;
    let stats = pipe.stats(T0 + 2);
    for (group, rows) in [
        ("prefixes", validation::PREFIXES_MAX),
        ("games", validation::GAMES_MAX),
        ("mitigation", validation::TUNNELS_MAX),
    ] {
        assert_eq!(stats[group].as_array().map_or(0, Vec::len), rows, "{group}");
    }
    let (_fragments, fragments) = held(|| {
        let mut f = packet::Fragments::default();
        for id in 0..4096u32 {
            for piece in 0..64u32 {
                let p = packet::Packet {
                    src: Some("2001:db8::1".parse().unwrap()),
                    dst: Some("2001:db8:100::1".parse().unwrap()),
                    v6: true,
                    proto: 17,
                    id,
                    offset: piece * 1024,
                    more: true,
                    data: 512,
                    ..Default::default()
                };
                f.observe(&p, T0);
            }
        }
        f
    });
    // What it sends the control plane every couple of seconds must be an answer it takes.
    let heartbeat = serde_json::to_vec(&json!({"stats":stats,"tunnels":[]})).unwrap();
    assert!(
        heartbeat.len() < api::BODY_LIMIT,
        "a full node's heartbeat is {} KiB, past what the control plane reads",
        heartbeat.len() >> 10
    );
    let agent = [
        ("pipeline, every table full", pipeline),
        ("fragments in reassembly", fragments),
        ("its program as fetched", 2 * program_json),
        ("its heartbeat being sent", 2 * heartbeat.len()),
        ("request bodies", node::BODY_BUDGET),
        ("connections", node::CONNECTIONS * CONNECTION),
    ];
    let agent_total: usize = agent.iter().map(|(_, b)| b).sum();
    println!(
        "node agent: {} MiB at the most\n{}",
        agent_total / MIB,
        breakdown(&agent)
    );
    assert!(
        agent_total < 1024 * MIB,
        "the node agent needs more than its unit leaves it room for"
    );

    // The control plane, at the largest fabric: what it keeps for each node, measured at
    // MEASURED of them, and what it keeps whatever the fabric's size.
    let scale = store::NODES_MAX / MEASURED;
    let typed: wire::Stats = serde_json::from_value(stats.clone()).unwrap();
    let (reports, kept_reports) = held(|| {
        fleet
            .iter()
            .map(|n| wire::Report {
                node_id: n.id.clone(),
                name: n.name.clone(),
                region: n.region.clone(),
                stats: typed.clone(),
                reported_at: chrono::DateTime::from_timestamp_millis(T0).unwrap(),
            })
            .collect::<Vec<_>>()
    });
    let (mut collector, counters) = held(|| {
        let mut c = Collector::default();
        for r in &reports {
            let stats = serde_json::to_value(&r.stats).unwrap();
            c.observe(&r.node_id, &stats, &programs[&r.node_id], T0);
        }
        c
    });
    let (_history, days) = held(history);
    let ((), heartbeat_read) = peak(|| {
        #[derive(serde::Deserialize)]
        struct Heartbeat {
            stats: wire::Stats,
        }
        let typed: Heartbeat = serde_json::from_slice(&heartbeat).unwrap();
        collector.observe_stats("node-0", &typed.stats, &program, T0 + 2000);
    });
    // What every node's provisioner last said about its tunnels.
    let statuses: Vec<TunnelStatus> = program
        .tunnels
        .iter()
        .map(|t| TunnelStatus {
            tunnel_id: t.id.clone(),
            state: "up".into(),
            ..Default::default()
        })
        .collect();
    let (_statuses, kept_statuses) = held(|| vec![statuses.clone(); MEASURED]);
    // The fabric's view of every node as a whole, and one node's every series.
    let (fleet_text, fleet_scrape) = peak(|| {
        let mut m = Metrics::new();
        for r in &reports {
            let summary = wire::Report {
                stats: r.stats.summary(),
                ..r.clone()
            };
            m.report(&serde_json::to_value(&summary).unwrap(), T0);
        }
        m.render().unwrap()
    });
    let (node_text, node_scrape) = peak(|| {
        let mut m = Metrics::new();
        m.report(&serde_json::to_value(&reports[0]).unwrap(), T0);
        m.announcements(&program.announcements);
        m.tunnels(&fleet[0], &program.tunnels, &statuses);
        m.render().unwrap()
    });
    let (fabric, fabric_read) =
        peak(|| serde_json::to_vec(&(&plan, programs.values().collect::<Vec<_>>())).unwrap());
    let (_policy, one_policy) = held(largest_policy);
    let carried = ml::SAMPLE_BYTES_MAX / ml::SAMPLES_MAX;
    let (samples, kept_samples) = held(|| {
        (0..ml::SAMPLES_MAX)
            .map(|i| ml::Sample {
                flow: Flow {
                    payload: vec![(i % 251) as u8; carried],
                    ..flow(&source(i), "udp", 53, &[])
                },
                label: (i % 2) as i64,
                known_good: false,
            })
            .collect::<Vec<_>>()
    });
    assert!(ml::sample_bytes(&samples) <= ml::SAMPLE_BYTES_MAX);
    let ((), fit) = peak(|| {
        let copy = samples.clone();
        ml::train(&copy, 1, 0.1, 0.5, 1.0).unwrap();
    });
    let (tenants, kept_tenants) = held(|| {
        let share = store::TENANT_PREFIXES_MAX / store::TENANTS_MAX;
        (0..store::TENANTS_MAX)
            .map(|i| Tenant {
                id: format!("ten-{i}"),
                name: format!("tenant-{i}"),
                prefixes: (0..share)
                    .map(|j| format!("10.{}.{}.{j}/32", i / 256, i % 256))
                    .collect(),
                ..Default::default()
            })
            .collect::<Vec<_>>()
    });
    let mut state = store::Store::open("").unwrap();
    state.data.policies = vec![policy.clone(); store::POLICIES_MAX];
    state.data.samples = samples;
    state.data.tenants = tenants;
    state.data.nodes = (0..store::NODES_MAX)
        .map(|i| Node {
            id: format!("node-{i}"),
            ..fleet[i % MEASURED].clone()
        })
        .collect();
    let ((), write) = peak(|| {
        serde_json::to_vec(&state.snapshot()).unwrap();
    });
    let kept = [
        ("programs and the plan", compiled * scale),
        ("node reports", kept_reports * scale),
        ("tunnel reports", kept_statuses * scale),
        ("analytics counters", counters * scale),
        ("analytics history", days),
        ("policies", one_policy * store::POLICIES_MAX),
        ("training set", kept_samples),
        ("tenants", kept_tenants),
    ];
    // Each of these runs under the control plane's lock, so one at a time.
    let one_at_a_time = [
        ("GET /v1/fabric", fabric_read * scale),
        ("a recompile", compiled * scale),
        ("writing the state, or GET /v1/state", write),
        ("a fit", fit),
        ("a heartbeat", heartbeat_read),
    ];
    let (worst, worst_bytes) = one_at_a_time.iter().max_by_key(|(_, b)| *b).unwrap();
    let beside = [
        (
            "metrics scrapes, rendered a few at a time",
            api::SCRAPES * (fleet_scrape * scale).max(node_scrape),
        ),
        (
            "the last answer still being sent",
            (fleet_text.len() * scale)
                .max(node_text.len())
                .max(fabric.len() * scale),
        ),
        ("request bodies", api::BODY_BUDGET),
        ("connections", api::CONNECTIONS * CONNECTION),
    ];
    let sum = |parts: &[(&str, usize)]| parts.iter().map(|(_, b)| b).sum::<usize>();
    let total = sum(&kept) + worst_bytes + sum(&beside);
    println!(
        "control plane, {} nodes: {} MiB at the most\nkept:\n{}\nrunning one at a time, the largest being {worst}:\n{}\nbeside them:\n{}",
        store::NODES_MAX,
        total / MIB,
        breakdown(&kept),
        breakdown(&one_at_a_time),
        breakdown(&beside)
    );
    assert!(
        total < 6 * GIB,
        "the control plane needs more than its unit leaves it room for"
    );
}
