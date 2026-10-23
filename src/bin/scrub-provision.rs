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
        ("status", ""),
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
    let status = f.get("status");
    let mut last_nft = String::new();
    let mut last = String::new();
    loop {
        let outcome = pass(&client, &agent, &token, dry_run, &mut last_nft);
        let line = match &outcome {
            Ok(v) => v.clone(),
            Err(e) => format!("error: {e}"),
        };
        // Every pass writes how it went for whoever is watching, the install script among them;
        // the log gets it when it changes, so a fabric with nothing deployed yet does not fill it.
        if !status.is_empty() {
            let tmp = format!("{status}.tmp");
            if let Err(e) = std::fs::write(&tmp, format!("{line}\n"))
                .and_then(|_| std::fs::rename(&tmp, status))
            {
                eprintln!("provision: writing {status}: {e}");
            }
        }
        if line != last {
            eprintln!("provision: {line}");
            last = line;
        }
        if once {
            return outcome.map(|_| ());
        }
        std::thread::sleep(runtime::jitter(interval));
    }
}
/// One pass: how it went, or why it could not run.
fn pass(
    client: &reqwest::blocking::Client,
    agent: &str,
    token: &str,
    dry_run: bool,
    last_nft: &mut String,
) -> Result<String> {
    // The box first, so a provisioner that cannot read it says so whether or not there is
    // anything to apply yet.
    let mut system = System;
    let observed = provision::observe(&mut system)?;
    let r = client
        .get(format!("{agent}/tunnels"))
        .bearer_auth(token)
        .send()
        .map_err(|e| format!("reading the agent: {e}"))?;
    if r.status() == reqwest::StatusCode::SERVICE_UNAVAILABLE {
        // The agent has yet to hear from the control plane, so it cannot say what this node
        // holds, and the box stays as it is.
        return Ok("waiting: the agent has no program from the control plane yet".into());
    }
    if !r.status().is_success() {
        return Err(format!("reading the agent: {}", r.status()));
    }
    let desired: Desired = r.json().map_err(|e| e.to_string())?;
    if !desired.error.is_empty() {
        // Leave the box as it is: a configuration the agent cannot render is no reason to tear
        // down tunnels that were working.
        return Err(format!("the agent could not render: {}", desired.error));
    }
    let plan = provision::plan(&desired, &observed)?;
    if dry_run {
        for step in &plan.steps {
            println!("{}", provision::shell(&step.argv));
        }
        println!("nft -f - <<'EOF'\n{}EOF", plan.nft);
        return Ok("ok: dry run".into());
    }
    let applied = provision::apply(&mut system, &plan, &observed, last_nft);
    let r = client
        .post(format!("{agent}/tunnels"))
        .bearer_auth(token)
        .json(&provision::report(&desired, &applied))
        .send()
        .map_err(|e| format!("reporting to the agent: {e}"))?;
    if !r.status().is_success() {
        return Err(format!("reporting to the agent: {}", r.status()));
    }
    if let Some(e) = &applied.blocked {
        return Err(format!("the tunnel firewall did not load: {e}"));
    }
    let failed: Vec<String> = applied
        .failed
        .iter()
        .map(|(link, e)| format!("{link}: {e}"))
        .chain(applied.errors.iter().cloned())
        .collect();
    if !failed.is_empty() {
        return Err(failed.join("; "));
    }
    let backhaul = desired
        .lines
        .iter()
        .filter(|l| l.starts_with("ip link add sbh-"))
        .count();
    Ok(format!(
        "ok: {} customer and {backhaul} node-to-node tunnels in place",
        desired.tunnels.len()
    ))
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
