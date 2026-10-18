use pathfinder::{
    api::{Api, Shared},
    model::zero_time,
    runtime::{self, Flags},
    store::{self, Snapshot, Store},
    Result,
};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
async fn run() -> Result<()> {
    let f = Flags::parse(&[
        ("addr", "127.0.0.1:8080"),
        ("tls-cert", ""),
        ("tls-key", ""),
        ("insecure", "false"),
        ("state", ""),
        ("role", "primary"),
        ("primary", ""),
        ("ca", ""),
        ("follow-interval", "10s"),
    ])?;
    let token = runtime::required_env("SCRUBLINE_API_TOKEN")?;
    let enroll = runtime::required_env("SCRUBLINE_ENROLL_TOKEN")?;
    if token == enroll {
        return Err("SCRUBLINE_ENROLL_TOKEN must differ from SCRUBLINE_API_TOKEN".into());
    }
    let role = f.get("role");
    if role != "primary" && role != "replica" {
        return Err("-role must be primary or replica".into());
    }
    if (role == "replica") == f.get("primary").is_empty() {
        return Err("-primary must be provided only for a replica".into());
    }
    let state: Shared = Arc::new(Mutex::new(Api::new(
        Store::open(f.get("state"))?,
        token.clone(),
        enroll,
        role.into(),
    )));
    let task_state = state.clone();
    tokio::spawn(async move {
        loop {
            let s = task_state.clone();
            if let Err(e) = tokio::task::spawn_blocking(move || {
                let mut a = s.lock().unwrap();
                if let Err(e) = a.reconcile(chrono::Utc::now(), false) {
                    eprintln!("reconcile: {e}");
                }
            })
            .await
            {
                eprintln!("reconcile worker: {e}");
            }
            tokio::time::sleep(runtime::jitter(Duration::from_secs(5))).await;
        }
    });
    if role == "replica" {
        let client = runtime::client(f.get("ca"), Duration::from_secs(30))?;
        let url = format!("{}/v1/state", f.get("primary").trim_end_matches('/'));
        let interval = f.duration("follow-interval")?;
        let state = state.clone();
        tokio::spawn(async move {
            let mut last = None;
            loop {
                if state.lock().unwrap().mode != "replica" {
                    break;
                }
                match client.get(&url).bearer_auth(&token).send().await {
                    Ok(r) if r.status().is_success() => match r.json::<Snapshot>().await {
                        Ok(mut snap) => {
                            // The primary stamps saved_at on every read, so it cannot say whether
                            // anything changed. Compare the content instead, or every poll
                            // rewrites and fsyncs the whole state file, training set included.
                            snap.saved_at = zero_time();
                            let digest = serde_json::to_string(&snap)
                                .map(|raw| store::hash(&raw))
                                .unwrap_or_default();
                            if last.as_ref() != Some(&digest) {
                                let shared = state.clone();
                                let loaded = tokio::task::spawn_blocking(move || {
                                    let mut a = shared.lock().unwrap();
                                    if a.mode != "replica" {
                                        return Ok(());
                                    }
                                    a.store.load_snapshot(snap)
                                })
                                .await;
                                match loaded {
                                    Ok(Ok(())) => last = Some(digest),
                                    Ok(Err(e)) => eprintln!("replica state: {e}"),
                                    Err(e) => eprintln!("replica worker: {e}"),
                                }
                            }
                        }
                        Err(e) => eprintln!("replica response: {e}"),
                    },
                    Ok(r) => eprintln!("replica request: {}", r.status()),
                    Err(e) => eprintln!("replica request: {e}"),
                }
                tokio::time::sleep(runtime::jitter(interval)).await;
            }
        });
    }
    let router = Api::router(state).layer(tower_http::timeout::TimeoutLayer::with_status_code(
        axum::http::StatusCode::REQUEST_TIMEOUT,
        Duration::from_secs(60),
    ));
    eprintln!("Rust control plane listening on {}", f.get("addr"));
    runtime::serve(
        router,
        f.get("addr"),
        f.get("tls-cert"),
        f.get("tls-key"),
        f.boolean("insecure")?,
    )
    .await
}
#[tokio::main(worker_threads = 2)]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
