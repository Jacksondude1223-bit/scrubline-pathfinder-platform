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
    if f.get("state").is_empty() {
        eprintln!(
            "warning: no -state file, so policies, node and tenant credentials and the model live in memory and are lost on restart"
        );
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
                let shared = state.clone();
                match tokio::task::spawn_blocking(move || {
                    shared.lock().map(|a| a.mode == "replica").ok()
                })
                .await
                {
                    Ok(Some(true)) => {}
                    Ok(Some(false)) => break,
                    _ => {
                        eprintln!("replica: control-plane state is unusable; no longer following");
                        break;
                    }
                }
                match client.get(&url).bearer_auth(&token).send().await {
                    Ok(r) if r.status().is_success() => match r.bytes().await {
                        Ok(raw) => {
                            let shared = state.clone();
                            let seen = last.clone();
                            match tokio::task::spawn_blocking(move || follow(&shared, &raw, seen))
                                .await
                            {
                                Ok(Ok(Some(digest))) => last = Some(digest),
                                Ok(Ok(None)) => {}
                                Ok(Err(e)) => eprintln!("replica state: {e}"),
                                Err(e) => eprintln!("replica worker: {e}"),
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
/// Loads one snapshot from the primary unless it matches the last one loaded, returning the digest
/// of what it loaded. It decodes and hashes the whole state, training set included, and waits on
/// the control-plane lock, so it runs on the blocking pool rather than a runtime worker.
fn follow(state: &Shared, raw: &[u8], last: Option<String>) -> Result<Option<String>> {
    let mut snap: Snapshot =
        serde_json::from_slice(raw).map_err(|e| format!("decoding the primary's state: {e}"))?;
    // The primary stamps saved_at on every read, so it cannot say whether anything changed.
    // Compare the content instead, or every poll rewrites and fsyncs the whole state file.
    snap.saved_at = zero_time();
    let digest = store::hash(&serde_json::to_string(&snap).map_err(|e| e.to_string())?);
    if last.as_ref() == Some(&digest) {
        return Ok(None);
    }
    let mut a = state
        .lock()
        .map_err(|_| "control-plane state is unusable".to_string())?;
    if a.mode != "replica" {
        return Ok(None);
    }
    a.store.load_snapshot(snap)?;
    Ok(Some(digest))
}
#[tokio::main(worker_threads = 2)]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
