//! Synthetic flow-record generator for demo node agents; sends records to /decide.
use pathfinder::{
    model::Flow,
    runtime::{self, Flags},
    Result,
};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::{sync::Arc, time::Duration};
struct Generator {
    client: reqwest::Client,
    token: String,
    targets: Vec<String>,
    protected: String,
    quiet: String,
    game_port: i64,
}
fn source(r: &mut StdRng) -> String {
    format!(
        "{}.{}.{}.{}",
        r.gen_range(1..224),
        r.gen_range(0..256),
        r.gen_range(0..256),
        r.gen_range(1..255)
    )
}
fn host(prefix: &str, r: &mut StdRng) -> String {
    let base = prefix.split('/').next().unwrap_or(prefix);
    let mut parts: Vec<_> = base.split('.').map(String::from).collect();
    if parts.len() != 4 {
        return base.into();
    }
    parts[3] = r.gen_range(1..255).to_string();
    parts.join(".")
}
fn flow(g: &Generator, r: &mut StdRng, kind: u8) -> Flow {
    let mut f = Flow {
        src_ip: source(r),
        dst_ip: host(if kind == 2 { &g.quiet } else { &g.protected }, r),
        proto: if matches!(kind, 1 | 2 | 6) {
            "tcp"
        } else {
            "udp"
        }
        .into(),
        sport: 1024 + r.gen_range(0..60000),
        dport: if matches!(kind, 1 | 2 | 6) {
            443
        } else {
            g.game_port
        },
        ..Default::default()
    };
    match kind {
        0 => {
            f.pps = 40 + r.gen_range(0..120);
            f.payload = vec![0; 16];
            f.payload[0] = 1;
            f.has_payload = true;
        }
        1 => {
            f.pps = 20 + r.gen_range(0..80);
            f.flags = "ack".into();
        }
        2 => {
            f.pps = 10 + r.gen_range(0..50);
            f.flags = "ack".into();
        }
        3 => {
            f.sport = 53;
            f.dport = 1024 + r.gen_range(0..60000);
            f.pps = 180000 + r.gen_range(0..120000);
        }
        4 => {
            f.pps = 60000 + r.gen_range(0..40000);
            f.payload = vec![255; 4];
            f.has_payload = true;
        }
        // SYN and FIN together, which no stack sends: the crafted-packet checks drop it.
        6 => {
            f.pps = 20000 + r.gen_range(0..20000);
            f.flags = "syn,fin".into();
        }
        // A botnet's GRE flood, as Mirai sends: the protocol guard drops it.
        8 => {
            f.proto = "gre".into();
            f.sport = 0;
            f.dport = 0;
            f.pps = 60000 + r.gen_range(0..40000);
        }
        // Domain controllers' CLDAP answers to a rootDSE query forged from the protected address:
        // the reflection guard drops them.
        7 => {
            f.sport = 389;
            f.pps = 80000 + r.gen_range(0..40000);
            f.payload = vec![0x30, 0x84, 0x00, 0x00, 0x0b, 0x9f, 0x02, 0x01, 0x01, 0x64];
            f.has_payload = true;
        }
        // A SYN flood from forged sources, each sending its SYN once: the SYN flood guard holds
        // them back, since none of them retries.
        9 => {
            f.proto = "tcp".into();
            f.dport = 443;
            f.flags = "syn".into();
            f.pps = 50000 + r.gen_range(0..50000);
        }
        // NTP servers' monlist answers, memcached's values and SSDP's discovery answers, to
        // queries forged from the protected address: the reflection guard drops them all.
        10 => {
            f.sport = 123;
            f.pps = 60000 + r.gen_range(0..40000);
            f.payload = vec![0xd7, 0x00, 0x03, 0x2a, 0x00, 0x06, 0x00, 0x48];
            f.payload.resize(440, 0);
            f.has_payload = true;
        }
        11 => {
            f.sport = 11211;
            f.pps = 60000 + r.gen_range(0..40000);
            f.payload = vec![0, 1, 0, 0, 0, 1, 0, 0];
            f.payload.extend(b"VALUE a 0 1000000\r\n");
            f.has_payload = true;
        }
        12 => {
            f.sport = 1900;
            f.pps = 40000 + r.gen_range(0..20000);
            f.payload = b"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\n".to_vec();
            f.has_payload = true;
        }
        // A ping flood: the ICMP guard holds the prefix to its rate.
        13 => {
            f.proto = "icmp".into();
            f.sport = 0;
            f.dport = 0;
            f.pps = 50000 + r.gen_range(0..50000);
        }
        _ => {
            f.pps = 400000 + r.gen_range(0..200000);
            f.payload = vec![0];
            f.has_payload = true;
        }
    }
    f
}
async fn send(g: &Generator, r: &mut StdRng, kinds: &[u8]) {
    for target in &g.targets {
        for kind in kinds {
            let f = flow(g, r, *kind);
            let _ = g
                .client
                .post(format!("{target}/decide"))
                .bearer_auth(&g.token)
                .json(&f)
                .send()
                .await;
        }
    }
}
async fn stop() {
    #[cfg(unix)]
    {
        let mut term =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
        tokio::select! {_=tokio::signal::ctrl_c()=>{},_=term.recv()=>{}}
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
async fn run() -> Result<()> {
    let f = Flags::parse(&[
        ("nodes", "http://127.0.0.1:9091"),
        ("ca", ""),
        ("protected", "203.0.113.0/24"),
        ("quiet", "198.51.100.0/24"),
        ("game-port", "19132"),
        // Baseline traffic has to leave most 250ms slots quiet, or the burst train never reads as
        // one: the detector counts every slot with traffic in it toward the duty cycle.
        ("interval", "1s"),
        ("attack-every", "4m"),
        ("attack-for", "90s"),
        ("burst-every", "7m"),
        ("burst-for", "3m"),
        ("seed", "0"),
    ])?;
    let token = runtime::required_env("SCRUBLINE_NODE_API_TOKEN")?;
    let game_port = f.integer("game-port")?;
    if !(0..=65535).contains(&game_port) {
        return Err("game-port must be within 0..65535".into());
    }
    let targets: Vec<_> = f
        .get("nodes")
        .split(',')
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .collect();
    for target in &targets {
        reqwest::Url::parse(target).map_err(|e| e.to_string())?;
    }
    for p in [f.get("protected"), f.get("quiet")] {
        p.parse::<ipnet::IpNet>().map_err(|e| e.to_string())?;
    }
    let g = Arc::new(Generator {
        client: runtime::client(f.get("ca"), Duration::from_secs(5))?,
        token,
        targets,
        protected: f.get("protected").into(),
        quiet: f.get("quiet").into(),
        game_port,
    });
    let seed = f.integer("seed")?;
    let seed = if seed == 0 {
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64
    } else {
        seed as u64
    };
    let interval = f.duration("interval")?;
    let every = f.duration("attack-every")?;
    let duration = f.duration("attack-for")?;
    let burst_every = f.duration("burst-every")?;
    let burst_for = f.duration("burst-for")?;
    let base = g.clone();
    let baseline = tokio::spawn(async move {
        let mut r = StdRng::seed_from_u64(seed);
        loop {
            tokio::time::sleep(interval).await;
            send(&base, &mut r, &[0, 1, 2]).await;
        }
    });
    let flood = g.clone();
    let floods = tokio::spawn(async move {
        let mut r = StdRng::seed_from_u64(seed.wrapping_add(1));
        tokio::time::sleep(Duration::from_secs(20)).await;
        loop {
            let started = tokio::time::Instant::now();
            while tokio::time::Instant::now() < started + duration {
                tokio::time::sleep(Duration::from_millis(250)).await;
                send(&flood, &mut r, &[3, 4, 6, 7, 8, 9, 10, 11, 12, 13]).await;
            }
            // Attacks recur on a period, so "every four minutes" means four minutes apart.
            tokio::time::sleep_until(started + every).await;
        }
    });
    let bursts = tokio::spawn(async move {
        let mut r = StdRng::seed_from_u64(seed.wrapping_add(2));
        tokio::time::sleep(Duration::from_secs(120)).await;
        loop {
            let started = tokio::time::Instant::now();
            while tokio::time::Instant::now() < started + burst_for {
                for _ in 0..4 {
                    send(&g, &mut r, &[5]).await;
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
                tokio::time::sleep(Duration::from_secs(18)).await;
            }
            tokio::time::sleep_until(started + burst_every).await;
        }
    });
    stop().await;
    baseline.abort();
    floods.abort();
    bursts.abort();
    Ok(())
}
#[tokio::main(worker_threads = 2)]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
