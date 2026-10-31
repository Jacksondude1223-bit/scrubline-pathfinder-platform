//! The largest fabric talking to its control plane at once, the way its agents do: every node
//! heartbeating about every two seconds with as much as it can report, every tunnel's state among
//! it, fetching the model after each heartbeat and holding a request open for its program, while
//! an operator deploys a new version of the policy every ten seconds and a scraper reads the
//! fabric's metrics. Every heartbeat must be answered, well within what an agent waits, no node
//! may go stale, and every node must have each new program within seconds.
//!
//! It takes optimisations to run in reasonable time: `cargo test --release --test load --
//! --nocapture` prints how it went.
mod common;
use common::{largest_policy, touch, T0};
use pathfinder::{
    api::{Api, Shared},
    pipeline::Pipeline,
    runtime,
    store::{self, Store},
};
use serde_json::{json, Value};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
const OP: &str = "load-operator";
const ENROLL: &str = "load-enroll";
/// How long the fabric runs.
const RUN: Duration = Duration::from_secs(30);
/// What an agent waits for an answer before giving up on a heartbeat.
const AGENT_TIMEOUT: Duration = Duration::from_secs(5);

/// A control plane served the way scrub-api serves one: two runtime workers, with the lock
/// waited on from the blocking pool.
fn serve() -> (String, Shared) {
    let state: Shared = Arc::new(Mutex::new(Api::new(
        Store::open("").unwrap(),
        OP.into(),
        ENROLL.into(),
        "primary".into(),
    )));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let shared = state.clone();
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                axum::serve(listener, Api::router(state)).await.unwrap();
            });
    });
    (base, shared)
}
fn percentile(sorted: &[Duration], p: f64) -> Duration {
    sorted[((sorted.len() - 1) as f64 * p).round() as usize]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(
    debug_assertions,
    ignore = "runs the largest fabric against a control plane, which takes a release build"
)]
async fn the_largest_fabric_heartbeats_without_falling_behind() {
    let (base, shared) = serve();
    let client = reqwest::Client::new();
    let mut nodes = vec![];
    for i in 0..store::NODES_MAX {
        let body = json!({
            "name": format!("edge-{i}"),
            "region": format!("r{}", i % 8),
            "advertise": format!("192.0.2.{}:9091", i + 1),
            "tunnel_src": format!("192.0.2.{}", i + 1),
            "capacity_gbps": 40,
        });
        let reg: Value = client
            .post(format!("{base}/v1/nodes/register"))
            .bearer_auth(ENROLL)
            .json(&body)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let id = reg["node"]["id"].as_str().unwrap().to_string();
        nodes.push((id, reg["token"].as_str().unwrap().to_string()));
    }
    let policy = largest_policy();
    let program = {
        let mut a = shared.lock().unwrap();
        let now = chrono::Utc::now();
        let saved = a.store.save_policy(policy.clone(), now).unwrap();
        a.store.data.last_policy_id = saved.id;
        a.reconcile(now, true).unwrap();
        a.store.programs[&nodes[0].0].clone()
    };
    assert!(!program.tunnels.is_empty(), "the nodes build the tunnels");
    let mut pipe = Pipeline::new(pathfinder::model::Program::clone(&program));
    touch(&mut pipe, &policy);
    let tunnels: Vec<Value> = program
        .tunnels
        .iter()
        .map(|t| json!({"tunnel_id": t.id, "state": "up"}))
        .collect();
    let report = json!({"stats": pipe.stats(T0 + 2), "tunnels": tunnels});
    let body = axum::body::Bytes::from(serde_json::to_vec(&report).unwrap());
    let started = Instant::now();
    let until = started + RUN;
    // Each agent holds a request for its program open, as the agent does, and takes each one the
    // fabric compiles it.
    let mut fetchers = vec![];
    for (id, token) in nodes.clone() {
        let (client, base) = (client.clone(), base.clone());
        fetchers.push(tokio::spawn(async move {
            let (mut since, mut received, mut failed) = (String::new(), vec![], 0);
            while Instant::now() < until {
                let asked = client
                    .get(format!("{base}/v1/nodes/{id}/program"))
                    .bearer_auth(&token)
                    .query(&[("wait", "20s"), ("since", since.as_str())])
                    .timeout(Duration::from_secs(30))
                    .send();
                let answer = tokio::select! {
                    a = asked => a,
                    _ = tokio::time::sleep_until(until.into()) => break,
                };
                match answer {
                    Ok(r) if r.status().is_success() => {
                        let program: Value = r.json().await.unwrap();
                        since = program["compiled_at"].as_str().unwrap_or("").to_string();
                        received.push((since.clone(), Instant::now()));
                    }
                    _ => {
                        failed += 1;
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    }
                }
            }
            (received, failed)
        }));
    }
    // An operator deploying a new version of the policy every ten seconds, which every node
    // fetches.
    let deployer = {
        let (shared, policy) = (shared.clone(), policy.clone());
        tokio::spawn(async move {
            let mut deployed = vec![];
            while Instant::now() + Duration::from_secs(12) < until {
                tokio::time::sleep(Duration::from_secs(10)).await;
                let (shared, policy) = (shared.clone(), policy.clone());
                let stamp = tokio::task::spawn_blocking(move || {
                    let mut a = shared.lock().unwrap();
                    let now = chrono::Utc::now();
                    a.store.save_policy(policy, now).unwrap();
                    a.reconcile(now, true).unwrap();
                    let program = a.store.programs.values().next().unwrap();
                    program
                        .compiled_at
                        .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
                })
                .await
                .unwrap();
                deployed.push((stamp, Instant::now()));
            }
            deployed
        })
    };
    let mut agents = vec![];
    for (id, token) in nodes.clone() {
        let (client, base, body) = (client.clone(), base.clone(), body.clone());
        agents.push(tokio::spawn(async move {
            let mut beats = vec![];
            tokio::time::sleep(runtime::jitter(Duration::from_secs(1))).await;
            while Instant::now() < until {
                let sent = Instant::now();
                let answer = client
                    .post(format!("{base}/v1/nodes/{id}/heartbeat"))
                    .bearer_auth(&token)
                    .header("content-type", "application/json")
                    .body(body.clone())
                    .timeout(AGENT_TIMEOUT)
                    .send()
                    .await;
                let status = answer.map_or(0, |r| r.status().as_u16());
                beats.push((sent.elapsed(), status));
                let _ = client
                    .get(format!("{base}/v1/ml/model"))
                    .bearer_auth(&token)
                    .timeout(AGENT_TIMEOUT)
                    .send()
                    .await;
                tokio::time::sleep(runtime::jitter(Duration::from_secs(2))).await;
            }
            beats
        }));
    }
    // An operator's scraper beside them.
    let scraper = {
        let (client, base) = (client.clone(), base.clone());
        tokio::spawn(async move {
            let mut scrapes = vec![];
            while Instant::now() < until {
                tokio::time::sleep(Duration::from_secs(10)).await;
                let sent = Instant::now();
                let r = client
                    .get(format!("{base}/metrics"))
                    .bearer_auth(OP)
                    .send()
                    .await
                    .unwrap();
                let status = r.status().as_u16();
                let size = r.bytes().await.unwrap().len();
                scrapes.push((sent.elapsed(), status, size));
            }
            scrapes
        })
    };
    let mut latencies = vec![];
    let mut failed = vec![];
    for a in agents {
        for (took, status) in a.await.unwrap() {
            latencies.push(took);
            if status != 200 {
                failed.push(status);
            }
        }
    }
    let scrapes = scraper.await.unwrap();
    let deployed = deployer.await.unwrap();
    let mut received = vec![];
    let mut fetch_failures = 0;
    for f in fetchers {
        let (got, failed) = f.await.unwrap();
        received.push(got);
        fetch_failures += failed;
    }
    for (stamp, at) in &deployed {
        let delays: Vec<Duration> = received
            .iter()
            .filter_map(|got| {
                got.iter()
                    .find(|(s, _)| s.as_str() >= stamp.as_str())
                    .map(|(_, when)| when.saturating_duration_since(*at))
            })
            .collect();
        println!(
            "deploy {stamp}: {} of {} nodes fetched it, the last after {:?}",
            delays.len(),
            nodes.len(),
            delays.iter().max()
        );
        assert_eq!(delays.len(), nodes.len(), "a node never fetched {stamp}");
        let last = delays.iter().max().copied().unwrap_or_default();
        assert!(
            last < Duration::from_secs(5),
            "{stamp} took {last:?} to reach every node"
        );
    }
    assert!(!deployed.is_empty());
    println!("program fetches failed: {fetch_failures}");
    assert_eq!(fetch_failures, 0);
    latencies.sort();
    let elapsed = started.elapsed();
    println!(
        "{} nodes, {} KiB heartbeats with {} tunnels: {} heartbeats in {:.0?} ({:.0}/s), {} failed {:?}",
        nodes.len(),
        body.len() >> 10,
        tunnels.len(),
        latencies.len(),
        elapsed,
        latencies.len() as f64 / elapsed.as_secs_f64(),
        failed.len(),
        &failed[..failed.len().min(10)]
    );
    println!(
        "heartbeat latency: p50 {:?}, p90 {:?}, p99 {:?}, max {:?}",
        percentile(&latencies, 0.5),
        percentile(&latencies, 0.9),
        percentile(&latencies, 0.99),
        latencies.last().unwrap()
    );
    for (took, status, size) in &scrapes {
        println!("scrape: {status} in {took:?}, {} KiB", size >> 10);
        assert_eq!(*status, 200);
        assert!(*took < Duration::from_secs(2), "a scrape took {took:?}");
    }
    assert!(failed.is_empty(), "heartbeats failed: {failed:?}");
    let p99 = percentile(&latencies, 0.99);
    assert!(
        p99 < AGENT_TIMEOUT / 2,
        "heartbeats took {p99:?} at the 99th percentile, too near the {AGENT_TIMEOUT:?} an agent waits"
    );
    let fleet: Value = client
        .get(format!("{base}/v1/nodes"))
        .bearer_auth(OP)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let stale = fleet
        .as_array()
        .unwrap()
        .iter()
        .filter(|n| n["status"] != "ready")
        .count();
    println!("stale nodes: {stale}");
    assert_eq!(stale, 0);
}
