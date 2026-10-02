//! Proxy server, certificate download page and events (package 1C).
//!
//! An iPhone or iPad routes all of its traffic through this proxy for a few minutes. Exactly
//! two host names are TLS-intercepted, [`AUTHY_HOST`] (forwarded to Authy, responses watched
//! for the encrypted backup) and [`CHECK_HOST`] (answered here, never forwarded). Every other
//! CONNECT is a blind tunnel: the bytes are copied in both directions and nothing about the
//! connection is inspected, kept or logged. Plain HTTP is forwarded, also without a log line.
//!
//! Built directly on hyper and tokio-rustls, not on `hudsucker::Proxy`, for two reasons: the
//! handshake with the device is ours, so a refused certificate is seen as `TlsRejected`; and
//! the tunnel and plain-HTTP paths contain no logging, so tunnelled hosts never reach a log.
//! `hudsucker` is used only for `decode_response`. The device is offered HTTP/1.1 only.

use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::header::{
    HeaderMap, HeaderName, HeaderValue, CACHE_CONTROL, CONNECTION, CONTENT_DISPOSITION,
    CONTENT_ENCODING, CONTENT_TYPE, HOST, LOCATION,
};
use http::{Method, Request, Response, StatusCode, Uri, Version};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty, Full, Limited};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::client::conn::http1 as client;
use hyper::server::conn::http1 as server;
use hyper::service::service_fn;
use hyper_rustls::ConfigBuilderExt;
use hyper_util::rt::{TokioIo, TokioTimer};
use rustls::crypto::aws_lc_rs;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio_rustls::{LazyConfigAcceptor, TlsConnector};

use crate::ca::{Authority, CaError};
use crate::capture;
use crate::types::CapturedBackup;

/// Authy's API host: the only host whose traffic is decrypted and forwarded.
pub const AUTHY_HOST: &str = "api.authy.com";
/// Answered by the proxy itself, never forwarded. A device that loads `https://CHECK_HOST/`
/// proves it trusts the certificate. It sits under `authy.com` so the name-constrained root
/// can vouch for it.
pub const CHECK_HOST: &str = "authexodus-check.api.authy.com";

const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
/// A response larger than this is passed through but not searched for the backup.
const CAPTURE_LIMIT: usize = 16 * 1024 * 1024;

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

const INDEX_PAGE: &str = concat!(
    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
    "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
    "<title>authexodus</title><style>",
    "body{font:17px -apple-system,system-ui,sans-serif;margin:2.5em 1.5em;text-align:center}",
    ".button{display:inline-block;padding:.8em 1.4em;border-radius:.7em;background:#0a64d8;",
    "color:#fff;text-decoration:none;font-weight:600}",
    "</style></head><body><h1>authexodus</h1>",
    "<p><a class=\"button\" href=\"/cert\">Download certificate</a></p>",
    "<p><a href=\"https://authexodus-check.api.authy.com/\">Test</a></p>",
    "</body></html>",
);

const CHECK_PAGE: &str = concat!(
    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
    "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
    "<title>authexodus</title><style>",
    "body{font:17px -apple-system,system-ui,sans-serif;margin:2.5em 1.5em;text-align:center}",
    "</style></head><body><h1>Certificate is trusted</h1>",
    "<p>You can go back to authexodus.</p></body></html>",
);

/// What the proxy noticed. The wizard advances on these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyEvent {
    /// The first connection from something other than this computer.
    DeviceConnected,
    /// The first completed TLS handshake for an intercepted host: the device trusts the root.
    TrustWorking,
    /// The device saw our certificate for an intercepted host and aborted the handshake.
    /// Sent every time it happens.
    TlsRejected,
    /// The captured backup grew. `count` is the number of encrypted tokens now held.
    BackupCaptured { count: usize },
    /// Authy answered with a 4xx or 5xx. `path` has no query string.
    AuthyError { status: u16, path: String },
}

/// For tests only: where Authy "is", and the root that signed that stand-in's certificate.
///
/// With a test upstream, connections for [`AUTHY_HOST`] are dialled at `addr` instead of the
/// real host, and the stand-in's certificate (which must name `api.authy.com`) is verified
/// against `root_cert_der` alone. A test upstream also lifts the rule that the proxy refuses
/// loopback destinations, because test servers live on loopback. Production passes `None`.
#[derive(Debug, Clone)]
pub struct TestUpstream {
    pub addr: SocketAddr,
    pub root_cert_der: Vec<u8>,
}

pub struct ProxyConfig {
    /// The address to listen on: the computer's address on the network it shares with the
    /// iPhone or iPad.
    pub listen_ip: IpAddr,
    /// Tried first. If it cannot be bound, any free port is used: see [`ProxyHandle::port`].
    pub preferred_port: u16,
    /// `None` in production.
    pub upstream: Option<TestUpstream>,
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("could not listen for connections: {0}")]
    Bind(#[source] io::Error),
    #[error(transparent)]
    Ca(#[from] CaError),
    #[error("could not set up TLS: {0}")]
    Tls(String),
}

/// A running proxy. Dropping it stops the proxy; [`ProxyHandle::shutdown`] also waits for it.
pub struct ProxyHandle {
    port: u16,
    shared: Arc<Shared>,
    stop: watch::Sender<bool>,
    accept: JoinHandle<()>,
    drained: mpsc::Receiver<()>,
}

impl ProxyHandle {
    /// The port actually bound.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// A clone of what has been captured so far.
    pub fn backup(&self) -> CapturedBackup {
        self.shared.lock_backup().clone()
    }

    /// Stop listening, close every connection and tunnel, and wait for them to end.
    pub async fn shutdown(mut self) {
        let _ = self.stop.send(true);
        let _ = (&mut self.accept).await;
        // `recv` yields `None` once every task has dropped its sender.
        let _ = tokio::time::timeout(DRAIN_TIMEOUT, self.drained.recv()).await;
    }
}

/// Start the proxy. Must be called from within a tokio runtime.
pub async fn start(
    cfg: ProxyConfig,
    ca: Arc<Authority>,
    events: mpsc::UnboundedSender<ProxyEvent>,
) -> Result<ProxyHandle, ProxyError> {
    let dial = Dial {
        authy_at: cfg.upstream.as_ref().map(|u| u.addr),
        allow_loopback: cfg.upstream.is_some(),
    };
    let test_root = cfg.upstream.as_ref().map(|u| u.root_cert_der.as_slice());
    let tls = upstream_tls(test_root)?;
    let leaf_authy = ca.leaf_server_config(AUTHY_HOST)?;
    let leaf_check = ca.leaf_server_config(CHECK_HOST)?;

    let listener = bind(cfg.listen_ip, cfg.preferred_port).await?;
    let port = listener.local_addr().map_err(ProxyError::Bind)?.port();

    let (stop_tx, stop_rx) = watch::channel(false);
    let (alive_tx, drained) = mpsc::channel::<()>(1);
    let shared = Arc::new(Shared {
        port,
        listen_ip: cfg.listen_ip,
        cert_der: Bytes::from(ca.cert_der()),
        leaf_authy,
        leaf_check,
        tls,
        dial,
        events,
        backup: Mutex::new(CapturedBackup::default()),
        device: Once::default(),
        trust: Once::default(),
        stop: stop_rx,
    });
    let accept = tokio::spawn(accept_loop(listener, Arc::clone(&shared), alive_tx));

    Ok(ProxyHandle {
        port,
        shared,
        stop: stop_tx,
        accept,
        drained,
    })
}

/// Bind the preferred port; if that fails for any reason, let the system pick one.
async fn bind(ip: IpAddr, preferred_port: u16) -> Result<TcpListener, ProxyError> {
    match TcpListener::bind((ip, preferred_port)).await {
        Ok(listener) => Ok(listener),
        Err(_) if preferred_port != 0 => TcpListener::bind((ip, 0)).await.map_err(ProxyError::Bind),
        Err(e) => Err(ProxyError::Bind(e)),
    }
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type ProxyBody = UnsyncBoxBody<Bytes, BoxError>;
/// One HTTP/1.1 connection to an upstream server.
type Sender = client::SendRequest<ProxyBody>;
/// The connection to Authy that belongs to one intercepted connection from the device.
type AuthyLink = Arc<tokio::sync::Mutex<Option<Sender>>>;

struct Shared {
    port: u16,
    listen_ip: IpAddr,
    cert_der: Bytes,
    leaf_authy: Arc<ServerConfig>,
    leaf_check: Arc<ServerConfig>,
    /// Verifies Authy's certificate on the connections the proxy opens to it.
    tls: TlsConnector,
    dial: Dial,
    events: mpsc::UnboundedSender<ProxyEvent>,
    backup: Mutex<CapturedBackup>,
    device: Once,
    trust: Once,
    stop: watch::Receiver<bool>,
}

impl Shared {
    fn emit(&self, event: ProxyEvent) {
        // Nobody listening is not an error: the proxy keeps working.
        let _ = self.events.send(event);
    }

    fn lock_backup(&self) -> std::sync::MutexGuard<'_, CapturedBackup> {
        self.backup.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn note_peer(&self, peer: IpAddr, local: IpAddr) {
        if is_device(peer, local) && self.device.first() {
            self.emit(ProxyEvent::DeviceConnected);
        }
    }

    /// Resolves when the proxy is told to stop, or its handle is dropped.
    async fn stopped(&self) {
        let mut stop = self.stop.clone();
        while !*stop.borrow_and_update() {
            if stop.changed().await.is_err() {
                return;
            }
        }
    }

    /// `None` if the proxy stopped first.
    async fn unless_stopped<T>(&self, fut: impl Future<Output = T>) -> Option<T> {
        tokio::select! {
            value = fut => Some(value),
            _ = self.stopped() => None,
        }
    }
}

/// True the first time it is asked, false ever after.
#[derive(Default)]
struct Once(AtomicBool);

impl Once {
    fn first(&self) -> bool {
        !self.0.swap(true, Ordering::SeqCst)
    }
}

/// Is this peer the iPhone or iPad, rather than this computer talking to itself? Anything that
/// is not loopback and is not the very address it connected to counts as a device.
fn is_device(peer: IpAddr, local: IpAddr) -> bool {
    let peer = peer.to_canonical();
    !peer.is_loopback() && peer != local.to_canonical()
}

/// One accepted connection's context. Every task that outlives the request holds a clone, and
/// through `alive` keeps [`ProxyHandle::shutdown`] waiting until it has ended.
#[derive(Clone)]
struct Conn {
    shared: Arc<Shared>,
    local: SocketAddr,
    alive: mpsc::Sender<()>,
}

async fn accept_loop(listener: TcpListener, shared: Arc<Shared>, alive: mpsc::Sender<()>) {
    loop {
        let accepted = match shared.unless_stopped(listener.accept()).await {
            None => return,
            Some(accepted) => accepted,
        };
        let (tcp, peer) = match accepted {
            Ok(pair) => pair,
            Err(_) => {
                // Out of file descriptors, most likely: do not spin.
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(local) = tcp.local_addr() else {
            continue;
        };
        let _ = tcp.set_nodelay(true);
        shared.note_peer(peer.ip(), local.ip());

        let conn = Conn {
            shared: Arc::clone(&shared),
            local,
            alive: alive.clone(),
        };
        tokio::spawn(async move {
            let shared = Arc::clone(&conn.shared);
            let service = service_fn(move |req| {
                let conn = conn.clone();
                async move { Ok::<_, Infallible>(route(conn, req).await) }
            });
            let serving = server::Builder::new()
                .timer(TokioTimer::new())
                .preserve_header_case(true)
                .serve_connection(TokioIo::new(tcp), service)
                .with_upgrades();
            // An error here is the device's connection breaking. For a tunnelled or forwarded
            // request there must be no trace of it, so it is dropped unseen.
            let _ = shared.unless_stopped(serving).await;
        });
    }
}

async fn route(conn: Conn, req: Request<Incoming>) -> Response<ProxyBody> {
    if req.method() == Method::CONNECT {
        return connect(conn, req).await;
    }
    let Some(authority) = req.uri().authority() else {
        // Origin form: the request was sent straight to us.
        return own_page(&conn.shared, req.method(), req.uri().path());
    };
    if req.uri().scheme_str() != Some("http") {
        return plain(StatusCode::BAD_REQUEST);
    }
    let host = bare_host(authority.host());
    let port = authority.port_u16().unwrap_or(80);
    if is_own_address(&conn, host, port) {
        // Absolute form naming us: the device already has the proxy configured.
        return own_page(&conn.shared, req.method(), req.uri().path());
    }
    if host.eq_ignore_ascii_case(CHECK_HOST) {
        // Never forwarded, and over plain HTTP it proves nothing: send it to the real check.
        return redirect_to_check();
    }
    forward_plain(&conn, req).await
}

fn is_own_address(conn: &Conn, host: &str, port: u16) -> bool {
    if port != conn.shared.port {
        return false;
    }
    host.parse::<IpAddr>().is_ok_and(|ip| {
        let ip = ip.to_canonical();
        ip == conn.local.ip().to_canonical() || ip == conn.shared.listen_ip.to_canonical()
    })
}

/// A URI host without the brackets of an IPv6 literal or a trailing dot.
fn bare_host(host: &str) -> &str {
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Intercepted {
    Authy,
    Check,
}

fn intercepted(host: &str) -> Option<Intercepted> {
    let host = bare_host(host);
    if host.eq_ignore_ascii_case(AUTHY_HOST) {
        Some(Intercepted::Authy)
    } else if host.eq_ignore_ascii_case(CHECK_HOST) {
        Some(Intercepted::Check)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------------------------
// The proxy's own pages
// ---------------------------------------------------------------------------------------------

fn own_page(shared: &Shared, method: &Method, path: &str) -> Response<ProxyBody> {
    let res = if method != Method::GET && method != Method::HEAD {
        plain(StatusCode::METHOD_NOT_ALLOWED)
    } else {
        match path {
            "/" => html(INDEX_PAGE),
            "/cert" => certificate(shared),
            _ => plain(StatusCode::NOT_FOUND),
        }
    };
    tracing::info!(%method, %path, status = res.status().as_u16(), "own page");
    res
}

/// The root certificate, in the form an iPhone or iPad offers to install as a profile.
fn certificate(shared: &Shared) -> Response<ProxyBody> {
    let mut res = Response::new(full(shared.cert_der.clone()));
    let headers = res.headers_mut();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-x509-ca-cert"),
    );
    headers.insert(
        CONTENT_DISPOSITION,
        HeaderValue::from_static("inline; filename=\"authexodus.cer\""),
    );
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

fn html(page: &'static str) -> Response<ProxyBody> {
    let mut res = Response::new(full(Bytes::from_static(page.as_bytes())));
    let headers = res.headers_mut();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

fn plain(status: StatusCode) -> Response<ProxyBody> {
    let mut res = Response::new(empty());
    *res.status_mut() = status;
    res
}

fn redirect_to_check() -> Response<ProxyBody> {
    let mut res = plain(StatusCode::FOUND);
    res.headers_mut().insert(
        LOCATION,
        HeaderValue::from_static("https://authexodus-check.api.authy.com/"),
    );
    res
}

fn empty() -> ProxyBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed_unsync()
}

fn full(bytes: Bytes) -> ProxyBody {
    Full::new(bytes)
        .map_err(|never| match never {})
        .boxed_unsync()
}

// ---------------------------------------------------------------------------------------------
// CONNECT: intercept two hosts, tunnel the rest
// ---------------------------------------------------------------------------------------------

async fn connect(conn: Conn, req: Request<Incoming>) -> Response<ProxyBody> {
    let Some(authority) = req.uri().authority().cloned() else {
        return plain(StatusCode::BAD_REQUEST);
    };
    let host = bare_host(authority.host()).to_owned();
    let port = authority.port_u16().unwrap_or(443);

    if let Some(which) = intercepted(&host) {
        tokio::spawn(intercept(conn, req, which, port));
        return plain(StatusCode::OK);
    }

    // Everything below is the blind tunnel. It must not log, emit events or keep anything.
    let shared = Arc::clone(&conn.shared);
    let mut server = match shared
        .unless_stopped(shared.dial.connect(&host, port))
        .await
    {
        Some(Ok(server)) => server,
        Some(Err(e)) if e.kind() == io::ErrorKind::PermissionDenied => {
            return plain(StatusCode::FORBIDDEN)
        }
        Some(Err(_)) | None => return plain(StatusCode::BAD_GATEWAY),
    };
    tokio::spawn(async move {
        let _alive = conn.alive;
        let Ok(upgraded) = hyper::upgrade::on(req).await else {
            return;
        };
        let mut device = TokioIo::new(upgraded);
        let _ = shared
            .unless_stopped(tokio::io::copy_bidirectional(&mut device, &mut server))
            .await;
    });
    plain(StatusCode::OK)
}

/// Terminate TLS for an intercepted host and serve the requests inside it.
async fn intercept(conn: Conn, req: Request<Incoming>, connect_host: Intercepted, port: u16) {
    let shared = Arc::clone(&conn.shared);
    let Ok(upgraded) = hyper::upgrade::on(req).await else {
        return;
    };
    let acceptor =
        LazyConfigAcceptor::new(rustls::server::Acceptor::default(), TokioIo::new(upgraded));
    // No ClientHello (the device opened the connection and dropped it, or is not speaking TLS):
    // it never saw our certificate, so nothing was rejected.
    let Some(Ok(Ok(start))) = shared
        .unless_stopped(tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor))
        .await
    else {
        return;
    };
    // The name the device asks for in the handshake decides, when it is one of ours.
    let which = start
        .client_hello()
        .server_name()
        .and_then(intercepted)
        .unwrap_or(connect_host);
    let config = match which {
        Intercepted::Authy => Arc::clone(&shared.leaf_authy),
        Intercepted::Check => Arc::clone(&shared.leaf_check),
    };
    let tls = match shared
        .unless_stopped(tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            start.into_stream(config),
        ))
        .await
    {
        Some(Ok(Ok(tls))) => tls,
        Some(Ok(Err(error))) => {
            // The device was shown our certificate and ended the handshake.
            tracing::info!(%error, "TLS handshake for an intercepted host was rejected");
            shared.emit(ProxyEvent::TlsRejected);
            return;
        }
        Some(Err(_)) | None => return, // stalled, or the proxy stopped
    };
    if shared.trust.first() {
        shared.emit(ProxyEvent::TrustWorking);
    }

    let link = AuthyLink::default();
    let service = service_fn(move |req| {
        let conn = conn.clone();
        let link = Arc::clone(&link);
        async move { Ok::<_, Infallible>(intercepted_request(conn, which, port, link, req).await) }
    });
    let serving = server::Builder::new()
        .timer(TokioTimer::new())
        .preserve_header_case(true)
        .serve_connection(TokioIo::new(tls), service);
    let _ = shared.unless_stopped(serving).await;
}

/// One decrypted request. Only here and for the proxy's own pages is a request logged: method,
/// path without its query string, status.
async fn intercepted_request(
    conn: Conn,
    which: Intercepted,
    port: u16,
    link: AuthyLink,
    req: Request<Incoming>,
) -> Response<ProxyBody> {
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let res = match which {
        Intercepted::Check if method == Method::GET || method == Method::HEAD => html(CHECK_PAGE),
        Intercepted::Check => plain(StatusCode::METHOD_NOT_ALLOWED),
        Intercepted::Authy => forward_authy(&conn, port, &link, &path, req).await,
    };
    tracing::info!(%method, %path, status = res.status().as_u16(), "intercepted request");
    res
}

async fn forward_authy(
    conn: &Conn,
    port: u16,
    link: &AuthyLink,
    path: &str,
    req: Request<Incoming>,
) -> Response<ProxyBody> {
    let shared = &conn.shared;
    let res = {
        // Requests on one device connection arrive one at a time, so this lock is never
        // contended; it is held until the response head is in.
        let mut link = link.lock().await;
        let mut reusable = link.take();
        if let Some(sender) = reusable.as_mut() {
            if sender.ready().await.is_err() {
                reusable = None; // Authy closed it while it sat idle
            }
        }
        let mut sender = match reusable {
            Some(sender) => sender,
            None => match open(conn, AUTHY_HOST, port, true).await {
                Ok(sender) => sender,
                Err(_) => return plain(StatusCode::BAD_GATEWAY),
            },
        };
        match sender.send_request(outbound(req, AUTHY_HOST)).await {
            Ok(res) => {
                *link = Some(sender);
                res
            }
            Err(_) => return plain(StatusCode::BAD_GATEWAY),
        }
    };

    let status = res.status();
    if status.is_client_error() || status.is_server_error() {
        shared.emit(ProxyEvent::AuthyError {
            status: status.as_u16(),
            path: path.to_owned(),
        });
    }
    let (mut parts, body) = res.into_parts();
    let body = if status.is_success() {
        let encodings = parts
            .headers
            .get_all(CONTENT_ENCODING)
            .iter()
            .cloned()
            .collect();
        CaptureBody {
            inner: body,
            copy: Some(Vec::new()),
            sink: Some(CaptureSink {
                conn: conn.clone(),
                encodings,
            }),
        }
        .map_err(BoxError::from)
        .boxed_unsync()
    } else {
        body.map_err(BoxError::from).boxed_unsync()
    };
    strip_hop_by_hop(&mut parts.headers);
    Response::from_parts(parts, body)
}

// ---------------------------------------------------------------------------------------------
// Plain HTTP: forwarded, never logged
// ---------------------------------------------------------------------------------------------

async fn forward_plain(conn: &Conn, req: Request<Incoming>) -> Response<ProxyBody> {
    let Some(authority) = req.uri().authority().cloned() else {
        return plain(StatusCode::BAD_REQUEST);
    };
    let port = authority.port_u16().unwrap_or(80);
    let mut sender = match open(conn, authority.host(), port, false).await {
        Ok(sender) => sender,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            return plain(StatusCode::FORBIDDEN)
        }
        Err(_) => return plain(StatusCode::BAD_GATEWAY),
    };
    match sender.send_request(outbound(req, authority.as_str())).await {
        Ok(res) => {
            let (mut parts, body) = res.into_parts();
            strip_hop_by_hop(&mut parts.headers);
            // One upstream connection per request: it stays open exactly as long as the body.
            let body = Holding {
                inner: body,
                _held: sender,
            };
            Response::from_parts(parts, body.map_err(BoxError::from).boxed_unsync())
        }
        Err(_) => plain(StatusCode::BAD_GATEWAY),
    }
}

/// The device's request as the origin server should see it: origin-form target, a `Host`
/// header, and nothing that was meant for the proxy.
fn outbound(req: Request<Incoming>, authority: &str) -> Request<ProxyBody> {
    let (mut parts, body) = req.into_parts();
    let target = parts.uri.path_and_query().map_or("/", |pq| pq.as_str());
    parts.uri = target.parse().unwrap_or_else(|_| Uri::from_static("/"));
    parts.version = Version::HTTP_11;
    strip_hop_by_hop(&mut parts.headers);
    if !parts.headers.contains_key(HOST) {
        if let Ok(host) = HeaderValue::from_str(authority) {
            parts.headers.insert(HOST, host);
        }
    }
    Request::from_parts(parts, body.map_err(BoxError::from).boxed_unsync())
}

/// Remove the headers that belong to one hop (RFC 9110 section 7.6.1), including whatever the
/// `Connection` header names, and anything addressed to a proxy.
fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let named: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in named {
        headers.remove(name);
    }
    for name in HOP_BY_HOP {
        headers.remove(*name);
    }
}

/// A body that keeps something alive until it is dropped.
struct Holding<T> {
    inner: Incoming,
    _held: T,
}

impl<T: Unpin> Body for Holding<T> {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        Pin::new(&mut self.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

// ---------------------------------------------------------------------------------------------
// Outbound connections
// ---------------------------------------------------------------------------------------------

/// Opens every outbound TCP connection the proxy makes: tunnels, plain HTTP and Authy.
#[derive(Clone)]
struct Dial {
    /// Test upstream: where connections for [`AUTHY_HOST`] really go.
    authy_at: Option<SocketAddr>,
    /// Production refuses loopback destinations, so a device on the network cannot use the
    /// proxy to reach services that listen only on this computer.
    allow_loopback: bool,
}

impl Dial {
    fn allows(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.allow_loopback || !(ip.is_loopback() || ip.is_unspecified())
    }

    async fn connect(&self, host: &str, port: u16) -> io::Result<TcpStream> {
        let host = bare_host(host);
        if let Some(addr) = self.authy_at {
            if host.eq_ignore_ascii_case(AUTHY_HOST) {
                return connect_to(addr).await;
            }
        }
        let mut last = io::Error::new(io::ErrorKind::NotFound, "no address");
        for addr in tokio::net::lookup_host((host, port)).await? {
            if !self.allows(addr.ip()) {
                last = io::Error::new(io::ErrorKind::PermissionDenied, "destination refused");
                continue;
            }
            match connect_to(addr).await {
                Ok(stream) => return Ok(stream),
                Err(e) => last = e,
            }
        }
        Err(last)
    }
}

async fn connect_to(addr: SocketAddr) -> io::Result<TcpStream> {
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timed out"))??;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

/// Open an HTTP/1.1 connection to `host`, over TLS when `tls` is set. The connection is driven
/// by its own task until it ends or the proxy stops.
async fn open(conn: &Conn, host: &str, port: u16, tls: bool) -> io::Result<Sender> {
    let shared = &conn.shared;
    let tcp = shared.dial.connect(host, port).await?;
    if !tls {
        return handshake(conn, tcp).await;
    }
    let name = ServerName::try_from(bare_host(host).to_owned())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, shared.tls.connect(name, tcp))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out"))??;
    handshake(conn, stream).await
}

async fn handshake<I>(conn: &Conn, io: I) -> io::Result<Sender>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sender, connection) = client::Builder::new()
        .preserve_header_case(true)
        .handshake(TokioIo::new(io))
        .await
        .map_err(io::Error::other)?;
    let conn = conn.clone();
    tokio::spawn(async move {
        let _ = conn.shared.unless_stopped(connection).await;
    });
    Ok(sender)
}

/// The TLS client side of the proxy's own connections to Authy. Production trusts the public
/// web roots; a test trusts its stand-in's root and nothing else.
fn upstream_tls(test_root: Option<&[u8]>) -> Result<TlsConnector, ProxyError> {
    let tls_error = |e: rustls::Error| ProxyError::Tls(e.to_string());
    let builder = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(tls_error)?;
    let mut config = match test_root {
        Some(der) => {
            let mut roots = RootCertStore::empty();
            roots
                .add(CertificateDer::from(der.to_vec()))
                .map_err(tls_error)?;
            builder.with_root_certificates(roots)
        }
        None => builder.with_webpki_roots(),
    }
    .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsConnector::from(Arc::new(config)))
}

// ---------------------------------------------------------------------------------------------
// Watching Authy's responses for the backup
// ---------------------------------------------------------------------------------------------

/// Passes a response body through untouched while keeping a copy. When the body ends, the copy
/// goes to [`CaptureSink::finish`]. The device never waits on the capture.
struct CaptureBody {
    inner: Incoming,
    /// `None` once the body has outgrown [`CAPTURE_LIMIT`].
    copy: Option<Vec<u8>>,
    sink: Option<CaptureSink>,
}

impl CaptureBody {
    fn finish(&mut self) {
        if let (Some(sink), Some(copy)) = (self.sink.take(), self.copy.take()) {
            tokio::spawn(sink.finish(copy));
        }
    }
}

impl Body for CaptureBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        let this = &mut *self;
        let polled = Pin::new(&mut this.inner).poll_frame(cx);
        match &polled {
            Poll::Ready(Some(Ok(frame))) => {
                if let (Some(data), Some(copy)) = (frame.data_ref(), this.copy.as_mut()) {
                    if copy.len() + data.len() > CAPTURE_LIMIT {
                        this.copy = None;
                    } else {
                        copy.extend_from_slice(data);
                    }
                }
                // hyper may not poll again after the last frame.
                if this.inner.is_end_stream() {
                    this.finish();
                }
            }
            Poll::Ready(None) => this.finish(),
            // A body that broke half-way is not a backup.
            Poll::Ready(Some(Err(_))) => this.sink = None,
            Poll::Pending => {}
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

struct CaptureSink {
    conn: Conn,
    encodings: Vec<HeaderValue>,
}

impl CaptureSink {
    async fn finish(self, body: Vec<u8>) {
        let shared = &self.conn.shared;
        let Some(body) = decoded(body, self.encodings).await else {
            return;
        };
        let Some(captured) = capture::inspect(&body) else {
            return;
        };
        let count = {
            let mut backup = shared.lock_backup();
            if !capture::merge(&mut backup, captured) {
                return;
            }
            backup.tokens.len()
        };
        shared.emit(ProxyEvent::BackupCaptured { count });
    }
}

/// Undo `Content-Encoding` (gzip, deflate, brotli, zstd). `None` if it cannot be undone.
async fn decoded(body: Vec<u8>, encodings: Vec<HeaderValue>) -> Option<Bytes> {
    if encodings.is_empty() {
        return Some(Bytes::from(body));
    }
    let mut res = Response::new(hudsucker::Body::from(Full::new(Bytes::from(body))));
    for encoding in encodings {
        res.headers_mut().append(CONTENT_ENCODING, encoding);
    }
    let res = hudsucker::decode_response(res).ok()?;
    let body = Limited::new(res.into_body(), CAPTURE_LIMIT);
    Some(body.collect().await.ok()?.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn a_device_is_any_peer_that_is_not_this_computer() {
        let local = ip("192.168.1.20");
        assert!(is_device(ip("192.168.1.57"), local), "a phone on the LAN");
        assert!(is_device(ip("10.0.0.9"), ip("10.0.0.2")));
        assert!(is_device(ip("fe80::1c2d:3e4f:5a6b:7c8d"), ip("fe80::1")));

        assert!(!is_device(ip("127.0.0.1"), ip("127.0.0.1")), "loopback");
        assert!(!is_device(ip("127.8.9.10"), local));
        assert!(!is_device(ip("::1"), ip("::1")));
        assert!(
            !is_device(ip("::ffff:127.0.0.1"), ip("::")),
            "mapped loopback"
        );
        assert!(
            !is_device(local, local),
            "this computer reaching its own LAN address"
        );
        assert!(!is_device(ip("::ffff:192.168.1.20"), local));
    }

    #[tokio::test]
    async fn device_connected_fires_once_for_the_first_non_loopback_peer() {
        let ca =
            Arc::new(Authority::load_or_create(&crate::ca::MemoryKeyStore::new(), true).unwrap());
        let (tx, mut events) = mpsc::unbounded_channel();
        let handle = start(
            ProxyConfig {
                listen_ip: ip("127.0.0.1"),
                preferred_port: 0,
                upstream: None,
            },
            ca,
            tx,
        )
        .await
        .unwrap();
        let local = ip("192.168.1.20");

        handle.shared.note_peer(ip("127.0.0.1"), ip("127.0.0.1"));
        handle.shared.note_peer(local, local);
        assert!(events.try_recv().is_err(), "this computer is not a device");

        handle.shared.note_peer(ip("192.168.1.57"), local);
        assert_eq!(events.try_recv(), Ok(ProxyEvent::DeviceConnected));

        handle.shared.note_peer(ip("192.168.1.57"), local);
        handle.shared.note_peer(ip("192.168.1.99"), local);
        assert!(
            events.try_recv().is_err(),
            "only the first one is announced"
        );
        handle.shutdown().await;
    }

    #[test]
    fn once_is_true_only_the_first_time() {
        let once = Once::default();
        assert!(once.first());
        assert!(!once.first());
        assert!(!once.first());
    }

    #[test]
    fn only_the_two_authy_hosts_are_intercepted() {
        assert_eq!(intercepted("api.authy.com"), Some(Intercepted::Authy));
        assert_eq!(intercepted("API.Authy.com."), Some(Intercepted::Authy));
        assert_eq!(
            intercepted("authexodus-check.api.authy.com"),
            Some(Intercepted::Check)
        );
        for other in [
            "authy.com",
            "www.authy.com",
            "evil-api.authy.com",
            "api.authy.com.example.org",
            "xapi.authy.com",
            "example.com",
            "127.0.0.1",
            "",
        ] {
            assert_eq!(intercepted(other), None, "{other}");
        }
    }

    #[test]
    fn production_refuses_loopback_destinations() {
        let production = Dial {
            authy_at: None,
            allow_loopback: false,
        };
        for refused in [
            "127.0.0.1",
            "127.1.2.3",
            "::1",
            "0.0.0.0",
            "::",
            "::ffff:127.0.0.1",
        ] {
            assert!(!production.allows(ip(refused)), "{refused}");
        }
        for allowed in [
            "192.168.1.1",
            "10.0.0.1",
            "93.184.216.34",
            "2606:4700::1111",
        ] {
            assert!(production.allows(ip(allowed)), "{allowed}");
        }
        let test = Dial {
            authy_at: None,
            allow_loopback: true,
        };
        assert!(test.allows(ip("127.0.0.1")));
    }

    #[test]
    fn hop_by_hop_headers_are_stripped() {
        let mut headers = HeaderMap::new();
        for (name, value) in [
            ("connection", "keep-alive, x-only-this-hop"),
            ("x-only-this-hop", "1"),
            ("proxy-connection", "keep-alive"),
            ("proxy-authorization", "Basic c2VjcmV0"),
            ("keep-alive", "timeout=5"),
            ("transfer-encoding", "chunked"),
            ("upgrade", "websocket"),
            ("te", "trailers"),
            ("host", "example.com"),
            ("authorization", "Bearer kept"),
            ("accept-encoding", "gzip"),
        ] {
            headers.append(
                HeaderName::from_static(name),
                HeaderValue::from_static(value),
            );
        }
        strip_hop_by_hop(&mut headers);
        let mut left: Vec<_> = headers.keys().map(|k| k.as_str()).collect();
        left.sort_unstable();
        assert_eq!(left, ["accept-encoding", "authorization", "host"]);
    }

    #[test]
    fn pages_say_what_the_brief_asks() {
        assert!(INDEX_PAGE.contains(">Download certificate</a>"));
        assert!(INDEX_PAGE.contains("href=\"/cert\""));
        assert!(INDEX_PAGE.contains(&format!("href=\"https://{CHECK_HOST}/\">Test</a>")));
        assert_eq!(
            INDEX_PAGE.matches("class=\"button\"").count(),
            1,
            "one button"
        );
        assert!(CHECK_PAGE.contains("Certificate is trusted"));
    }
}
