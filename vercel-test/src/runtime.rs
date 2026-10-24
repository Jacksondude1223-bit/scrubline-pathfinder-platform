//! Shared flag parsing, TLS listeners, verified clients, and jittered timers.
use crate::Result;
use axum_server::{accept::Accept, tls_rustls::RustlsAcceptor};
use rand::Rng;
use std::{
    collections::HashMap,
    future::{Future, Ready},
    io,
    net::{SocketAddr, ToSocketAddrs},
    path::Path,
    pin::Pin,
    sync::OnceLock,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    time::{Instant, Sleep},
};
/// Whether the process has been asked to stop.
fn stop() -> &'static tokio::sync::watch::Sender<bool> {
    static STOP: OnceLock<tokio::sync::watch::Sender<bool>> = OnceLock::new();
    STOP.get_or_init(|| tokio::sync::watch::Sender::new(false))
}
/// Completes once the process has been asked to stop, for a request held open on something that
/// will no longer happen: answered then, it lets the server shut down instead of waiting it out.
pub async fn stopping() {
    let _ = stop().subscribe().wait_for(|stopping| *stopping).await;
}
/// How long a new connection may stay silent before sending its first byte.
pub const FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long an established connection may go without reading or writing anything.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// A connection closed when it goes quiet: no first byte within `first`, then no I/O in either
/// direction for `idle`. Hyper's header timeout only starts once bytes arrive and nothing bounds
/// an idle HTTP/2 connection, so without this a silent client holds a socket and a task forever.
pub struct Deadline<S> {
    inner: S,
    idle: Duration,
    timer: Pin<Box<Sleep>>,
}
impl<S> Deadline<S> {
    pub fn new(inner: S, first: Duration, idle: Duration) -> Self {
        Self {
            inner,
            idle,
            timer: Box::pin(tokio::time::sleep(first)),
        }
    }
    fn touch(&mut self) {
        let at = Instant::now() + self.idle;
        self.timer.as_mut().reset(at);
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for Deadline<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                if buf.filled().len() > before {
                    this.touch();
                }
                Poll::Ready(Ok(()))
            }
            Poll::Pending if this.timer.as_mut().poll(cx).is_ready() => {
                Poll::Ready(Err(io::ErrorKind::TimedOut.into()))
            }
            other => other,
        }
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Deadline<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let written = Pin::new(&mut this.inner).poll_write(cx, data);
        if matches!(written, Poll::Ready(Ok(n)) if n > 0) {
            this.touch();
        }
        written
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let written = Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        if matches!(written, Poll::Ready(Ok(n)) if n > 0) {
            this.touch();
        }
        written
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
/// Puts every accepted connection under a [`Deadline`].
#[derive(Clone, Copy, Debug, Default)]
pub struct Deadlines;
impl<S> Accept<TcpStream, S> for Deadlines {
    type Stream = Deadline<TcpStream>;
    type Service = S;
    type Future = Ready<io::Result<(Self::Stream, S)>>;
    fn accept(&self, stream: TcpStream, service: S) -> Self::Future {
        std::future::ready(Ok((
            Deadline::new(stream, FIRST_BYTE_TIMEOUT, IDLE_TIMEOUT),
            service,
        )))
    }
}
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
            // A flag that is off by default is a switch: naming it turns it on, the way Go's flag
            // package reads one, so it never swallows the argument after it.
            let switch = defaults.iter().any(|(k, v)| *k == key && *v == "false");
            let value = if let Some(v) = inline {
                v.into()
            } else if switch {
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
        stop().send_replace(true);
        shutdown.graceful_shutdown(Some(Duration::from_secs(10)));
    });
    if cert.is_empty() {
        let mut server = axum_server::bind(addr).acceptor(Deadlines).handle(handle);
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
        let mut server = axum_server::bind(addr)
            .acceptor(RustlsAcceptor::new(config).acceptor(Deadlines))
            .handle(handle);
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
