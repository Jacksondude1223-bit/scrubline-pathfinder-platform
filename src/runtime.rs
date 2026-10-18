//! Shared flag parsing, TLS listeners, verified clients, and jittered timers.
use crate::Result;
use rand::Rng;
use std::{
    collections::HashMap,
    net::{SocketAddr, ToSocketAddrs},
    path::Path,
    time::Duration,
};
pub struct Flags(HashMap<String, String>);
impl Flags {
    pub fn parse(defaults: &[(&str, &str)]) -> Result<Self> {
        let mut values: HashMap<_, _> = defaults
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            if ["-h", "--help", "-help"].contains(&arg.as_str()) {
                println!("Options:");
                for (k, v) in defaults {
                    println!("  -{k} {v}");
                }
                std::process::exit(0);
            }
            let key = arg.trim_start_matches('-');
            let (key, inline) = key
                .split_once('=')
                .map(|(a, b)| (a, Some(b)))
                .unwrap_or((key, None));
            if !arg.starts_with('-') || !values.contains_key(key) {
                return Err(format!("unknown option {arg}"));
            }
            let value = if let Some(v) = inline {
                v.into()
            } else if key == "insecure" {
                "true".into()
            } else {
                args.next()
                    .ok_or_else(|| format!("-{key} requires a value"))?
            };
            values.insert(key.into(), value);
        }
        Ok(Self(values))
    }
    pub fn get(&self, key: &str) -> &str {
        self.0.get(key).map(String::as_str).unwrap_or("")
    }
    pub fn integer(&self, key: &str) -> Result<i64> {
        self.get(key).parse().map_err(|e| format!("-{key}: {e}"))
    }
    pub fn float(&self, key: &str) -> Result<f64> {
        let v = self.get(key).parse::<f64>().map_err(|e| e.to_string())?;
        if !v.is_finite() {
            return Err(format!("-{key} must be finite"));
        }
        Ok(v)
    }
    pub fn boolean(&self, key: &str) -> Result<bool> {
        match self.get(key) {
            "true" | "1" | "t" | "TRUE" | "True" => Ok(true),
            "false" | "0" | "f" | "FALSE" | "False" => Ok(false),
            _ => Err(format!("-{key} requires a boolean")),
        }
    }
    pub fn duration(&self, key: &str) -> Result<Duration> {
        Ok(Duration::from_millis(
            crate::api::duration(self.get(key))? as u64
        ))
    }
}
pub fn required_env(key: &str) -> Result<String> {
    std::env::var(key)
        .ok()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| format!("{key} is required"))
}
pub fn jitter(interval: Duration) -> Duration {
    let fraction = rand::rngs::OsRng.gen_range(0.8..=1.2);
    interval.mul_f64(fraction)
}
pub fn client(ca: &str, timeout: Duration) -> Result<reqwest::Client> {
    let mut b = reqwest::Client::builder()
        .timeout(timeout)
        .min_tls_version(reqwest::tls::Version::TLS_1_2);
    if !ca.is_empty() {
        let raw = std::fs::read(ca).map_err(|e| format!("reading CA bundle: {e}"))?;
        let certs = reqwest::Certificate::from_pem_bundle(&raw).map_err(|e| e.to_string())?;
        if certs.is_empty() {
            return Err("CA bundle contains no certificates".into());
        }
        b = b.tls_built_in_root_certs(false);
        for c in certs {
            b = b.add_root_certificate(c);
        }
    }
    b.build().map_err(|e| e.to_string())
}
pub async fn serve(
    router: axum::Router,
    addr: &str,
    cert: &str,
    key: &str,
    insecure: bool,
) -> Result<()> {
    if cert.is_empty() != key.is_empty() {
        return Err("TLS needs both a certificate and a key, or neither".into());
    }
    let host = addr
        .rsplit_once(':')
        .map(|(h, _)| h.trim_matches(['[', ']']))
        .unwrap_or(addr);
    let loopback = host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|a| a.is_loopback());
    if cert.is_empty() && !insecure && !loopback {
        return Err(format!(
            "refusing to serve {addr} without TLS: pass a certificate and key, or -insecure"
        ));
    }
    let addr: SocketAddr = addr
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or("listen address resolved to nothing")?;
    let handle = axum_server::Handle::new();
    let shutdown = handle.clone();
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("signal handler");
            tokio::select! {_=tokio::signal::ctrl_c()=>{},_=term.recv()=>{}}
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        shutdown.graceful_shutdown(Some(Duration::from_secs(10)));
    });
    if cert.is_empty() {
        let mut server = axum_server::bind(addr).handle(handle);
        server
            .http_builder()
            .http1()
            .header_read_timeout(Duration::from_secs(10))
            .max_buf_size(65536)
            .timer(hyper_util::rt::TokioTimer::new());
        server
            .serve(router.into_make_service())
            .await
            .map_err(|e| e.to_string())
    } else {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let config =
            axum_server::tls_rustls::RustlsConfig::from_pem_file(Path::new(cert), Path::new(key))
                .await
                .map_err(|e| e.to_string())?;
        let mut server = axum_server::bind_rustls(addr, config).handle(handle);
        server
            .http_builder()
            .http1()
            .header_read_timeout(Duration::from_secs(10))
            .max_buf_size(65536)
            .timer(hyper_util::rt::TokioTimer::new());
        server
            .serve(router.into_make_service())
            .await
            .map_err(|e| e.to_string())
    }
}
