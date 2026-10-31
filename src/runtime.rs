//! Shared flag parsing, TLS listeners, verified clients, and jittered timers.
use crate::Result;
use axum::{
    body::{Body, HttpBody},
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use axum_server::{accept::Accept, tls_rustls::RustlsAcceptor};
use rand::Rng;
use std::{
    collections::HashMap,
    future::Future,
    io,
    net::{SocketAddr, ToSocketAddrs},
    path::Path,
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    sync::{OwnedSemaphorePermit, Semaphore},
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
    /// The connection's place among those a server holds open, given back when it closes.
    _open: Option<OwnedSemaphorePermit>,
}
impl<S> Deadline<S> {
    pub fn new(inner: S, first: Duration, idle: Duration) -> Self {
        Self {
            inner,
            idle,
            timer: Box::pin(tokio::time::sleep(first)),
            _open: None,
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
/// Puts every accepted connection under a [`Deadline`], and holds a server to a number of open
/// connections: each holds buffers and, over TLS, a session, so a flood of them could otherwise
/// take more memory than the server has. One past the limit waits as long as a connection may
/// stay silent for a place to open up, holding only its socket, and is closed if none does.
#[derive(Clone, Debug)]
pub struct Deadlines {
    open: Arc<Semaphore>,
    first: Duration,
    idle: Duration,
}
impl Deadlines {
    pub fn new(open: usize, first: Duration, idle: Duration) -> Self {
        Self {
            open: Arc::new(Semaphore::new(open)),
            first,
            idle,
        }
    }
}
impl<S: Send + 'static> Accept<TcpStream, S> for Deadlines {
    type Stream = Deadline<TcpStream>;
    type Service = S;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, S)>> + Send>>;
    fn accept(&self, stream: TcpStream, service: S) -> Self::Future {
        let Self { open, first, idle } = self.clone();
        Box::pin(async move {
            let place = tokio::time::timeout(first, open.acquire_owned())
                .await
                .ok()
                .and_then(|p| p.ok())
                .ok_or_else(|| io::Error::other("too many open connections"))?;
            let mut conn = Deadline::new(stream, first, idle);
            conn._open = Some(place);
            Ok((conn, service))
        })
    }
}
/// How long a request's body may take to arrive in full.
pub const BODY_WAIT: Duration = Duration::from_secs(30);
/// What the bodies of the requests a server is reading and answering may hold between them, and
/// what one may hold. A body is charged for the bytes that have arrived rather than the length it
/// claims, so a sender holds only what it has sent, and one that finds the budget spent is turned
/// away rather than queued: bodies waiting on each other's bytes would hold the budget between
/// them and none would finish.
pub struct Bodies {
    budget: Arc<Semaphore>,
    limit: usize,
}
impl Bodies {
    pub fn new(budget: usize, limit: usize) -> Arc<Self> {
        Arc::new(Self {
            budget: Arc::new(Semaphore::new(budget.div_ceil(1024))),
            limit,
        })
    }
}
/// Reads a request's body under its server's [`Bodies`] before handing the request on, holding
/// the budget it took until the answer is ready.
pub async fn bounded(State(bodies): State<Arc<Bodies>>, req: Request, next: Next) -> Response {
    let (parts, mut body) = req.into_parts();
    if body.is_end_stream() {
        return next.run(Request::from_parts(parts, body)).await;
    }
    let refuse = |status: StatusCode, error: String| {
        (status, Json(serde_json::json!({ "error": error }))).into_response()
    };
    let too_large = || {
        refuse(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("a request body may hold at most {} bytes", bodies.limit),
        )
    };
    let claimed = parts
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok()?.parse::<u64>().ok());
    if claimed.is_some_and(|n| n > bodies.limit as u64) {
        return too_large();
    }
    enum Refused {
        TooLarge,
        Busy,
        Unreadable,
    }
    let mut held: Option<OwnedSemaphorePermit> = None;
    let mut buf = Vec::with_capacity(claimed.map_or(0, |n| n as usize).min(64 << 10));
    let read = tokio::time::timeout(BODY_WAIT, async {
        while let Some(frame) = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await
        {
            let Ok(data) = frame.map_err(|_| Refused::Unreadable)?.into_data() else {
                continue;
            };
            if buf.len() + data.len() > bodies.limit {
                return Err(Refused::TooLarge);
            }
            buf.extend_from_slice(&data);
            let owed = buf.len().div_ceil(1024) - held.as_ref().map_or(0, |p| p.num_permits());
            if owed > 0 {
                let more = bodies
                    .budget
                    .clone()
                    .try_acquire_many_owned(owed as u32)
                    .map_err(|_| Refused::Busy)?;
                match held.as_mut() {
                    Some(p) => p.merge(more),
                    None => held = Some(more),
                }
            }
        }
        Ok(())
    })
    .await;
    match read {
        Ok(Ok(())) => {}
        Ok(Err(Refused::TooLarge)) => return too_large(),
        Ok(Err(Refused::Busy)) => {
            let mut busy = refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "the server is holding as many request bodies as it has room for; try again shortly"
                    .into(),
            );
            busy.headers_mut()
                .insert(header::RETRY_AFTER, header::HeaderValue::from_static("1"));
            return busy;
        }
        Ok(Err(Refused::Unreadable)) => {
            return refuse(
                StatusCode::BAD_REQUEST,
                "the request body could not be read".into(),
            )
        }
        Err(_) => {
            return refuse(
                StatusCode::REQUEST_TIMEOUT,
                format!(
                    "a request body must arrive within {} seconds",
                    BODY_WAIT.as_secs()
                ),
            )
        }
    }
    let answer = next.run(Request::from_parts(parts, Body::from(buf))).await;
    drop(held);
    answer
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
/// The memory this process holds, as the kernel counts it (its resident set), or 0 where there is
/// no /proc to read it from.
pub fn resident_bytes() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            let line = status.lines().find_map(|l| l.strip_prefix("VmRSS:"))?;
            line.trim().strip_suffix("kB")?.trim().parse::<u64>().ok()
        })
        .map_or(0, |kb| kb * 1024)
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
/// Serves `router` on `addr`, holding at most `connections` open at once (see [`Deadlines`]).
pub async fn serve(
    router: axum::Router,
    addr: &str,
    cert: &str,
    key: &str,
    insecure: bool,
    connections: usize,
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
    let deadlines = Deadlines::new(connections, FIRST_BYTE_TIMEOUT, IDLE_TIMEOUT);
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
        let mut server = axum_server::bind(addr).acceptor(deadlines).handle(handle);
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
            .acceptor(RustlsAcceptor::new(config).acceptor(deadlines))
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
