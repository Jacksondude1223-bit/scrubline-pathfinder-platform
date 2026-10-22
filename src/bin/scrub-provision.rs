//! Keeps a node's tunnels, routes, firewall and shapers in step with what its agent serves.
use pathfinder::{
    provision::{self, Desired, System},
    runtime::{self, Flags},
    transport, Result,
};
use std::time::Duration;
fn run() -> Result<()> {
    let f = Flags::parse(&[
        ("agent", "http://127.0.0.1:9091"),
        ("ca", ""),
        ("interval", "5s"),
        ("once", "false"),
        ("dry-run", "false"),
    ])?;
    let token = runtime::required_env("SCRUBLINE_NODE_API_TOKEN")?;
    let agent = f.get("agent").trim_end_matches('/').to_owned();
    let ca = f.get("ca");
    let client = transport::client(
        (!ca.is_empty()).then(|| std::path::Path::new(ca)),
        Duration::from_secs(10),
    )?;
    let interval = f.duration("interval")?;
    let once = f.boolean("once")?;
    let dry_run = f.boolean("dry-run")?;
    let mut last_nft = String::new();
    loop {
        if let Err(e) = pass(&client, &agent, &token, dry_run, &mut last_nft) {
            eprintln!("provision: {e}");
            if once {
                return Err(e);
            }
        }
        if once {
            return Ok(());
        }
        std::thread::sleep(runtime::jitter(interval));
    }
}
fn pass(
    client: &reqwest::blocking::Client,
    agent: &str,
    token: &str,
    dry_run: bool,
    last_nft: &mut String,
) -> Result<()> {
    let r = client
        .get(format!("{agent}/tunnels"))
        .bearer_auth(token)
        .send()
        .map_err(|e| format!("reading the agent: {e}"))?;
    if !r.status().is_success() {
        return Err(format!("reading the agent: {}", r.status()));
    }
    let desired: Desired = r.json().map_err(|e| e.to_string())?;
    if !desired.error.is_empty() {
        // Leave the box as it is: a configuration the agent cannot render is no reason to tear
        // down tunnels that were working.
        return Err(format!("the agent could not render: {}", desired.error));
    }
    let mut system = System;
    let observed = provision::observe(&mut system)?;
    let plan = provision::plan(&desired, &observed)?;
    if dry_run {
        for step in &plan.steps {
            println!("{}", provision::shell(&step.argv));
        }
        println!("nft -f - <<'EOF'\n{}EOF", plan.nft);
        return Ok(());
    }
    let applied = provision::apply(&mut system, &plan, &observed, last_nft);
    for (link, e) in &applied.failed {
        eprintln!("provision {link}: {e}");
    }
    for e in &applied.errors {
        eprintln!("provision: {e}");
    }
    let r = client
        .post(format!("{agent}/tunnels"))
        .bearer_auth(token)
        .json(&provision::report(&desired, &applied))
        .send()
        .map_err(|e| format!("reporting to the agent: {e}"))?;
    if !r.status().is_success() {
        return Err(format!("reporting to the agent: {}", r.status()));
    }
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
