use crate::{
    model::{NodeTunnel, Tunnel, WireGuard, WireGuardStatus},
    provision::{Desired, Runner},
    Result,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::{
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

pub fn validate_options(wg: &WireGuard) -> Result<()> {
    let key = STANDARD
        .decode(&wg.public_key)
        .map_err(|_| "WireGuard public key must be base64")?;
    if key.len() != 32 || key.iter().all(|b| *b == 0) || STANDARD.encode(&key) != wg.public_key {
        return Err("WireGuard public key must be a canonical nonzero 32-byte key".into());
    }
    if wg.listen_port < 1024 {
        return Err("WireGuard listen_port must be within 1024..65535".into());
    }
    Ok(())
}

pub fn validate(t: &Tunnel) -> Result<()> {
    validate_options(t.wireguard.as_ref().ok_or("wireguard options required")?)?;
    if t.key != 0 || t.node.is_empty() || t.port_forward.is_some() || t.direction == "return" {
        return Err("WireGuard requires a pinned node, bidirectional routing, no GRE key and no port forwarding".into());
    }
    Ok(())
}

fn words(s: &str) -> Vec<String> {
    s.split_whitespace().map(String::from).collect()
}

pub fn configuration(t: &NodeTunnel, private: &str) -> Result<String> {
    let wg = t.wireguard.as_ref().ok_or("missing WireGuard options")?;
    validate_options(wg)?;
    let mut ips = t.sources.clone();
    ips.extend(t.prefixes.clone());
    ips.sort();
    ips.dedup();
    if ips.iter().any(|p| p.parse::<ipnet::IpNet>().is_err()) {
        return Err("invalid WireGuard allowed IPs".into());
    }
    Ok(format!("[Interface]\nPrivateKey = {}\nListenPort = {}\n\n[Peer]\nPublicKey = {}\nAllowedIPs = {}\n", private.trim(), wg.listen_port, wg.public_key, ips.join(", ")))
}

pub fn configure(r: &mut impl Runner, t: &NodeTunnel, directory: &Path) -> Result<()> {
    if crate::tunnel::interface_name(&t.id)? != t.interface {
        return Err("invalid WireGuard interface".into());
    }
    fs::create_dir_all(directory).map_err(|e| format!("creating WireGuard key directory: {e}"))?;
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    let path = directory.join(format!("{}.key", t.interface));
    let private = match fs::read_to_string(&path) {
        Ok(key) => key,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let key = r.run(&words("wg genkey"), None)?;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .map_err(|e| e.to_string())?;
            file.write_all(key.as_bytes())
                .and_then(|_| file.sync_all())
                .map_err(|e| e.to_string())?;
            key
        }
        Err(e) => return Err(format!("reading WireGuard key: {e}")),
    };
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    if !STANDARD
        .decode(private.trim())
        .is_ok_and(|key| key.len() == 32)
    {
        return Err("invalid node WireGuard key".into());
    }
    let config = configuration(t, &private)?;
    r.run(
        &words(&format!("wg syncconf {} /dev/stdin", t.interface)),
        Some(&config),
    )
    .map_err(|_| "could not configure WireGuard peer".to_string())?;
    Ok(())
}

pub fn status(r: &mut impl Runner, t: &NodeTunnel) -> Result<WireGuardStatus> {
    let get = |r: &mut dyn Runner, field: &str| {
        r.run(&words(&format!("wg show {} {field}", t.interface)), None)
    };
    let public_key = get(r, "public-key")?.trim().to_string();
    let listen_port = get(r, "listen-port")?
        .trim()
        .parse::<u16>()
        .map_err(|e| e.to_string())?;
    let peer = &t
        .wireguard
        .as_ref()
        .ok_or("missing WireGuard options")?
        .public_key;
    let latest_handshake = get(r, "latest-handshakes")?
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next() == Some(peer.as_str()))
                .then(|| fields.next().and_then(|s| s.parse::<u64>().ok()))
                .flatten()
        })
        .unwrap_or(0);
    validate_options(&WireGuard {
        public_key: public_key.clone(),
        listen_port,
    })?;
    Ok(WireGuardStatus {
        public_key,
        listen_port,
        latest_handshake,
    })
}

pub fn report(r: &mut impl Runner, desired: &Desired, report: &mut serde_json::Value) {
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    let Some(rows) = report["tunnels"].as_array_mut() else {
        return;
    };
    for t in desired.tunnels.iter().filter(|t| t.r#type == "wireguard") {
        let Some(row) = rows.iter_mut().find(|row| row["tunnel_id"] == t.id) else {
            continue;
        };
        if row["state"] == "down" {
            continue;
        }
        match status(r, t) {
            Ok(status) => {
                let live = status.latest_handshake > 0
                    && status.latest_handshake <= now
                    && now.saturating_sub(status.latest_handshake) <= 180;
                row["wireguard"] = serde_json::json!(status);
                row["state"] = serde_json::json!(if live { "up" } else { "down" });
                if !live {
                    row["detail"] =
                        serde_json::json!("Waiting for a recent authenticated WireGuard handshake");
                }
            }
            Err(_) => {
                row["state"] = serde_json::json!("down");
                row["detail"] = serde_json::json!("Could not read WireGuard connection status");
            }
        }
    }
}
