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
//!
//! The proxy listens on a shared network, so it assumes strangers can connect to it:
//!
//! * It will not connect to this computer, the local network or any other private, link-local
//!   or special-purpose address on a peer's behalf (see [`special_purpose`]).
//! * The first peer that is not this computer to complete a TLS handshake for an intercepted
//!   host becomes "the device". From then on no other peer may use the intercepted hosts, so
//!   only the device's traffic can reach the captured backup; a second device that tries is
//!   refused and reported as `DeviceRefused`. Tunnels and plain HTTP stay open to everyone, so
//!   a stray peer cannot lock the real device out of anything but Authy before it gets there
//!   first. This computer talking to its own proxy is served until there is a device, but it
//!   can never become the device, so it can never lock the iPhone or iPad out.
//! * Connections are capped, idle tunnels are closed, and outbound dials time out.

use std::collections::{HashMap, HashSet};
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
use rustls::{AlertDescription, ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::Instant;
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

/// Authy is always reached on this port, whatever port the device's CONNECT named.
const AUTHY_PORT: u16 = 443;
/// For an outbound connection: name lookup and TCP connect together, and separately the TLS
/// handshake with Authy.
const DIAL_TIMEOUT: Duration = Duration::from_secs(15);
/// One address of a name gets this long to answer before the next one is tried, so an address
/// that swallows packets (a broken IPv6 route) cannot use up the whole of [`DIAL_TIMEOUT`].
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// At most one [`ProxyEvent::DeviceRefused`] in this long.
const REFUSED_EVERY: Duration = Duration::from_secs(2);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
/// A blind tunnel that carries no bytes in either direction for this long is closed.
const TUNNEL_IDLE: Duration = Duration::from_secs(10 * 60);
/// Connections served at once, tunnels included. Further ones wait in the listen queue.
const MAX_CONNECTIONS: usize = 256;
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
    /// The first time something other than this computer uses the proxy as a proxy: a CONNECT,
    /// an absolute-form request, or a request for the proxy's own `/` or `/cert`. Merely
    /// opening a connection (a port scanner) does not count. Sent once.
    DeviceConnected,
    /// The first completed TLS handshake for an intercepted host: the peer that made it trusts
    /// the root. Unless that peer is this computer itself, it is from now on "the device", the
    /// only peer allowed on the intercepted hosts. Sent once.
    TrustWorking,
    /// A peer was shown our certificate for an intercepted host and answered with a TLS alert
    /// that says it does not accept it (unknown issuer, bad certificate and the like). A
    /// connection that merely drops during the handshake is not reported. Sent every time.
    TlsRejected,
    /// The captured backup grew. `count` is the number of encrypted tokens now held.
    BackupCaptured { count: usize },
    /// Authy answered with a 4xx or 5xx. `path` has no query string, and its all-digit
    /// segments (account and device ids) are replaced by `:id`.
    AuthyError { status: u16, path: String },
    /// A device other than the accepted one asked for an intercepted host and was refused.
    /// Usually the same iPhone or iPad under a new address (it rejoined the Wi-Fi), which only
    /// a restarted proxy will accept. Sent at most once every two seconds.
    DeviceRefused,
}

/// For tests only: where Authy "is", and the root that signed that stand-in's certificate.
///
/// With a test upstream, connections for [`AUTHY_HOST`] are dialled at the stand-in instead of
/// the real host, the stand-in's certificate (which must name `api.authy.com`) is verified
/// against the given root alone, and the proxy's destination rules are lifted, because test
/// servers live on loopback.
///
/// It can only be built with the cargo feature `test-upstream`. Without that feature there is
/// no constructor and the fields are private, so production code can only ever write
/// `upstream: None`.
#[derive(Debug, Clone)]
pub struct TestUpstream {
    addr: SocketAddr,
    root_cert_der: Vec<u8>,
    /// Source port of a connection to the proxy -> the peer address to treat it as.
    peers: Arc<Mutex<HashMap<u16, IpAddr>>>,
    /// The port of every connection the proxy opened for [`AUTHY_HOST`], as it asked for it
    /// (before the stand-in's address was substituted).
    authy_ports: Arc<Mutex<Vec<u16>>>,
    max_connections: usize,
    tunnel_idle: Duration,
}

#[cfg(any(test, feature = "test-upstream"))]
impl TestUpstream {
    /// `addr` is the stand-in for Authy; `root_cert_der` signed its certificate.
    pub fn new(addr: SocketAddr, root_cert_der: Vec<u8>) -> TestUpstream {
        TestUpstream {
            addr,
            root_cert_der,
            peers: Arc::default(),
            authy_ports: Arc::default(),
            max_connections: MAX_CONNECTIONS,
            tunnel_idle: TUNNEL_IDLE,
        }
    }

    /// Treat the connection to the proxy that comes from local port `source_port` as if it
    /// came from `peer`. Tests run on one loopback address; this lets them be several
    /// devices. Clones share the mapping, so it can be called after the proxy has started,
    /// any time before that connection's first request.
    pub fn pretend_peer(&self, source_port: u16, peer: IpAddr) {
        self.peers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(source_port, peer);
    }

    /// The port the proxy asked for each time it opened a connection for [`AUTHY_HOST`]: what
    /// it would have dialled had the stand-in not been substituted. Clones share the record.
    pub fn authy_ports_dialled(&self) -> Vec<u16> {
        self.authy_ports
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Serve at most this many connections at once (the default is the production limit).
    pub fn with_max_connections(mut self, max: usize) -> TestUpstream {
        self.max_connections = max;
        self
    }

    /// Close blind tunnels idle for this long (the default is the production limit).
    pub fn with_tunnel_idle(mut self, idle: Duration) -> TestUpstream {
        self.tunnel_idle = idle;
        self
    }
}

pub struct ProxyConfig {
    /// The address to listen on: the computer's address on the network it shares with the
    /// iPhone or iPad.
    pub listen_ip: IpAddr,
    /// Tried first. If it cannot be bound, any free port is used: see [`ProxyHandle::port`].
    pub preferred_port: u16,
    /// `None` in production. A value can only be built with the `test-upstream` feature.
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

    /// Tell the proxy about addresses that belong to this computer, so it refuses to connect
    /// to them on a peer's behalf. The listen address, every address a connection arrives on,
    /// and all private and link-local ranges are refused already; this is for a public
    /// address on another interface. Takes effect for connections opened from now on.
    pub fn add_local_addresses(&self, addrs: impl IntoIterator<Item = IpAddr>) {
        self.shared.dial.add_own(addrs);
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
        authy_ports: cfg.upstream.as_ref().map(|u| Arc::clone(&u.authy_ports)),
        unrestricted: cfg.upstream.is_some(),
        own: Arc::default(),
    };
    dial.add_own([cfg.listen_ip]);
    let test_root = cfg.upstream.as_ref().map(|u| u.root_cert_der.as_slice());
    let tls = upstream_tls(test_root)?;
    let max_connections = cfg
        .upstream
        .as_ref()
        .map_or(MAX_CONNECTIONS, |u| u.max_connections);
    let tunnel_idle = cfg.upstream.as_ref().map_or(TUNNEL_IDLE, |u| u.tunnel_idle);
    let pretend_peers = cfg.upstream.as_ref().map(|u| Arc::clone(&u.peers));
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
        device_connected: Once::default(),
        trust_working: Once::default(),
        device: Mutex::new(None),
        refused: Throttle::new(REFUSED_EVERY),
        pretend_peers,
        tunnel_idle,
        stop: stop_rx,
    });
    let accept = tokio::spawn(accept_loop(
        listener,
        Arc::clone(&shared),
        alive_tx,
        Arc::new(Semaphore::new(max_connections)),
    ));

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
    device_connected: Once,
    trust_working: Once,
    /// The first peer other than this computer to complete a TLS handshake for an intercepted
    /// host.
    device: Mutex<Option<IpAddr>>,
    refused: Throttle,
    /// Tests only: source port -> pretended peer address.
    pretend_peers: Option<Arc<Mutex<HashMap<u16, IpAddr>>>>,
    tunnel_idle: Duration,
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

    /// A peer has used the proxy as a proxy. Announce the first one that is not this computer.
    fn note_proxy_use(&self, peer: IpAddr, local: IpAddr) {
        if is_device(peer, local) && self.device_connected.first() {
            self.emit(ProxyEvent::DeviceConnected);
        }
    }

    fn lock_device(&self) -> std::sync::MutexGuard<'_, Option<IpAddr>> {
        self.device.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// May this peer open a connection to an intercepted host? Anyone, until there is a
    /// device; then only the device.
    fn may_intercept(&self, peer: IpAddr) -> bool {
        self.lock_device()
            .is_none_or(|device| device == peer.to_canonical())
    }

    /// A peer was turned away from an intercepted host because another peer is the device.
    /// Reported when the peer is a device itself (not this computer), and not too often. The
    /// log line names neither the peer nor the host.
    fn note_refused(&self, peer: IpAddr, local: IpAddr) {
        if is_device(peer, local) && self.refused.ready() {
            tracing::info!("refused a second device on an intercepted host");
            self.emit(ProxyEvent::DeviceRefused);
        }
    }

    /// The address the proxy treats this connection as coming from.
    fn peer_of(&self, peer: SocketAddr) -> IpAddr {
        self.pretend_peers
            .as_ref()
            .and_then(|map| {
                map.lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .get(&peer.port())
                    .copied()
            })
            .unwrap_or(peer.ip())
            .to_canonical()
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

/// True at most once in every `every`.
struct Throttle {
    every: Duration,
    last: Mutex<Option<Instant>>,
}

impl Throttle {
    fn new(every: Duration) -> Throttle {
        Throttle {
            every,
            last: Mutex::new(None),
        }
    }

    fn ready(&self) -> bool {
        let now = Instant::now();
        let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
        if last.is_some_and(|last| now.duration_since(last) < self.every) {
            return false;
        }
        *last = Some(now);
        true
    }
}

/// Is this peer the iPhone or iPad, rather than this computer talking to itself? Anything that
/// is not loopback and is not the very address it connected to counts as a device.
fn is_device(peer: IpAddr, local: IpAddr) -> bool {
    let peer = peer.to_canonical();
    !peer.is_loopback() && peer != local.to_canonical()
}

/// The outcome of a completed TLS handshake for an intercepted host.
#[derive(Debug, PartialEq, Eq)]
enum Claim {
    /// There was no device yet: this peer is now it.
    Became,
    /// This peer already is the device.
    Is,
    /// Another peer is the device. This one is turned away.
    Other,
    /// There is no device yet and this peer is this computer itself: it is served, but it
    /// does not become the device.
    NotADevice,
}

/// The first peer to complete a handshake becomes the device and stays it, unless that peer
/// is this computer talking to its own proxy (see [`is_device`]): that never takes the slot,
/// so it cannot lock the iPhone or iPad out. `local` is the address the peer connected to.
fn claim_device(device: &mut Option<IpAddr>, peer: IpAddr, local: IpAddr) -> Claim {
    let canonical = peer.to_canonical();
    match *device {
        None if is_device(peer, local) => {
            *device = Some(canonical);
            Claim::Became
        }
        None => Claim::NotADevice,
        Some(device) if device == canonical => Claim::Is,
        Some(_) => Claim::Other,
    }
}

/// One accepted connection's context. Every task that outlives the request holds a clone, and
/// through `_alive` keeps [`ProxyHandle::shutdown`] waiting until it has ended. The connection
/// counts against [`MAX_CONNECTIONS`] until the last clone is gone, which for a tunnel is when
/// the tunnel closes.
#[derive(Clone)]
struct Conn {
    shared: Arc<Shared>,
    peer: SocketAddr,
    local: SocketAddr,
    _alive: mpsc::Sender<()>,
    _slot: Arc<OwnedSemaphorePermit>,
}

impl Conn {
    fn peer(&self) -> IpAddr {
        self.shared.peer_of(self.peer)
    }

    fn note_proxy_use(&self) {
        self.shared.note_proxy_use(self.peer(), self.local.ip());
    }
}

async fn accept_loop(
    listener: TcpListener,
    shared: Arc<Shared>,
    alive: mpsc::Sender<()>,
    slots: Arc<Semaphore>,
) {
    loop {
        // Wait for a free slot before accepting, so the excess queues in the kernel.
        let slot = match shared
            .unless_stopped(Arc::clone(&slots).acquire_owned())
            .await
        {
            Some(Ok(slot)) => slot,
            Some(Err(_)) | None => return,
        };
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
        // Whatever address a peer reached us on is this computer's.
        shared.dial.add_own([local.ip()]);

        let conn = Conn {
            shared: Arc::clone(&shared),
            peer,
            local,
            _alive: alive.clone(),
            _slot: Arc::new(slot),
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
        conn.note_proxy_use();
        return connect(conn, req).await;
    }
    let Some(authority) = req.uri().authority() else {
        // Origin form: the request was sent straight to us.
        if matches!(req.uri().path(), "/" | "/cert") {
            conn.note_proxy_use();
        }
        return own_page(&conn.shared, req.method(), req.uri().path());
    };
    conn.note_proxy_use();
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
        if !conn.shared.may_intercept(conn.peer()) {
            // Someone else is the device. Authy is theirs alone.
            conn.shared.note_refused(conn.peer(), conn.local.ip());
            return plain(StatusCode::FORBIDDEN);
        }
        tokio::spawn(intercept(conn, req, which));
        return plain(StatusCode::OK);
    }

    // Everything below is the blind tunnel. It must not log, emit events or keep anything.
    let shared = Arc::clone(&conn.shared);
    let server = match shared
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
        let _conn = conn; // holds the connection's slot until the tunnel closes
        let Ok(upgraded) = hyper::upgrade::on(req).await else {
            return;
        };
        let mut device = TokioIo::new(upgraded);
        // Every byte of the tunnel, in either direction, is a read or a write on `server`.
        let activity = Arc::new(Mutex::new(Instant::now()));
        let mut server = Watched {
            inner: server,
            activity: Arc::clone(&activity),
        };
        let copying = tokio::io::copy_bidirectional(&mut device, &mut server);
        tokio::select! {
            _ = shared.unless_stopped(copying) => {}
            _ = idle_for(&activity, shared.tunnel_idle) => {}
        }
    });
    plain(StatusCode::OK)
}

/// A stream that notes when bytes last moved through it.
struct Watched<T> {
    inner: T,
    activity: Arc<Mutex<Instant>>,
}

impl<T> Watched<T> {
    fn touch(&self) {
        *self.activity.lock().unwrap_or_else(PoisonError::into_inner) = Instant::now();
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Watched<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        if buf.filled().len() > before {
            self.touch();
        }
        polled
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Watched<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_write(cx, buf);
        if matches!(polled, Poll::Ready(Ok(n)) if n > 0) {
            self.touch();
        }
        polled
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Resolves once `limit` has passed since the last recorded activity.
async fn idle_for(activity: &Mutex<Instant>, limit: Duration) {
    loop {
        let deadline = *activity.lock().unwrap_or_else(PoisonError::into_inner) + limit;
        if Instant::now() >= deadline {
            return;
        }
        tokio::time::sleep_until(deadline).await;
    }
}

/// Did the peer answer our certificate with an alert that says it does not accept it? That is
/// what a device without the root installed, or without full trust switched on, sends. An
/// end of stream, a reset, or any other failure says nothing about trust.
fn certificate_refused(error: &io::Error) -> bool {
    let alert = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>());
    matches!(
        alert,
        Some(rustls::Error::AlertReceived(
            AlertDescription::BadCertificate
                | AlertDescription::UnsupportedCertificate
                | AlertDescription::CertificateRevoked
                | AlertDescription::CertificateExpired
                | AlertDescription::CertificateUnknown
                | AlertDescription::UnknownCA
                | AlertDescription::AccessDenied
                | AlertDescription::DecryptError
        ))
    )
}

/// Terminate TLS for an intercepted host and serve the requests inside it.
async fn intercept(conn: Conn, req: Request<Incoming>, connect_host: Intercepted) {
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
            let refused = certificate_refused(&error);
            tracing::info!(%error, refused, "TLS handshake for an intercepted host failed");
            if refused {
                shared.emit(ProxyEvent::TlsRejected);
            }
            return;
        }
        Some(Err(_)) | None => return, // stalled, or the proxy stopped
    };
    let claim = claim_device(&mut shared.lock_device(), conn.peer(), conn.local.ip());
    if claim == Claim::Other {
        // Lost a race with the device; see `connect`.
        shared.note_refused(conn.peer(), conn.local.ip());
        return;
    }
    if shared.trust_working.first() {
        shared.emit(ProxyEvent::TrustWorking);
    }

    let link = AuthyLink::default();
    let service = service_fn(move |req| {
        let conn = conn.clone();
        let link = Arc::clone(&link);
        async move { Ok::<_, Infallible>(intercepted_request(conn, which, link, req).await) }
    });
    let serving = server::Builder::new()
        .timer(TokioTimer::new())
        .preserve_header_case(true)
        .serve_connection(TokioIo::new(tls), service);
    let _ = shared.unless_stopped(serving).await;
}

/// One decrypted request. Only here and for the proxy's own pages is a request logged: method,
/// path without its query string and with ids redacted, status.
async fn intercepted_request(
    conn: Conn,
    which: Intercepted,
    link: AuthyLink,
    req: Request<Incoming>,
) -> Response<ProxyBody> {
    let method = req.method().clone();
    let path = redact_ids(req.uri().path());
    let res = if method == Method::CONNECT {
        // A proxy request inside the decrypted stream goes nowhere.
        plain(StatusCode::METHOD_NOT_ALLOWED)
    } else if !conn.shared.may_intercept(conn.peer()) {
        // A connection this computer opened before there was a device: the device has
        // arrived since, and the intercepted hosts are now its alone.
        plain(StatusCode::FORBIDDEN)
    } else {
        match which {
            Intercepted::Check if method == Method::GET || method == Method::HEAD => {
                html(CHECK_PAGE)
            }
            Intercepted::Check => plain(StatusCode::METHOD_NOT_ALLOWED),
            Intercepted::Authy => forward_authy(&conn, &link, &path, req).await,
        }
    };
    tracing::info!(%method, %path, status = res.status().as_u16(), "intercepted request");
    res
}

/// A path with every all-digit segment replaced by `:id`. Authy's paths carry the account id
/// and device id; neither belongs in a log or an event.
fn redact_ids(path: &str) -> String {
    path.split('/')
        .map(|segment| {
            if !segment.is_empty() && segment.bytes().all(|b| b.is_ascii_digit()) {
                ":id"
            } else {
                segment
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// `path` is the redacted path, for the event; the request itself is forwarded as it came.
async fn forward_authy(
    conn: &Conn,
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
            None => match open(conn, AUTHY_HOST, AUTHY_PORT, true).await {
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
    /// Test upstream: the port asked for on each connection for [`AUTHY_HOST`].
    authy_ports: Option<Arc<Mutex<Vec<u16>>>>,
    /// Test upstream: no destination is refused (test servers live on loopback).
    unrestricted: bool,
    /// Addresses of this computer's own interfaces, as far as the proxy knows them.
    own: Arc<Mutex<HashSet<IpAddr>>>,
}

impl Dial {
    fn add_own(&self, addrs: impl IntoIterator<Item = IpAddr>) {
        let mut own = self.own.lock().unwrap_or_else(PoisonError::into_inner);
        own.extend(
            addrs
                .into_iter()
                .map(|ip| ip.to_canonical())
                .filter(|ip| !ip.is_unspecified()),
        );
    }

    /// May the proxy connect to `ip` on a peer's behalf? Only to public addresses that are not
    /// this computer's own.
    fn allows(&self, ip: IpAddr) -> bool {
        if self.unrestricted {
            return true;
        }
        let ip = ip.to_canonical();
        !special_purpose(ip)
            && !self
                .own
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .contains(&ip)
    }

    /// Resolve and connect, within [`DIAL_TIMEOUT`] overall and [`CONNECT_TIMEOUT`] for each
    /// address. Every resolved address is checked and only a checked address is dialled, so a
    /// name cannot smuggle in a refused address.
    async fn connect(&self, host: &str, port: u16) -> io::Result<TcpStream> {
        within_dial_timeout(self.connect_unbounded(host, port)).await
    }

    async fn connect_unbounded(&self, host: &str, port: u16) -> io::Result<TcpStream> {
        let host = bare_host(host);
        if host.eq_ignore_ascii_case(AUTHY_HOST) {
            if let Some(ports) = &self.authy_ports {
                ports
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(port);
            }
            if let Some(addr) = self.authy_at {
                return first_reachable([addr], |_| true, connect_to).await;
            }
        }
        let addrs = tokio::net::lookup_host((host, port)).await?;
        first_reachable(addrs, |ip| self.allows(ip), connect_to).await
    }
}

async fn within_dial_timeout<T>(dial: impl Future<Output = io::Result<T>>) -> io::Result<T> {
    tokio::time::timeout(DIAL_TIMEOUT, dial)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timed out"))?
}

/// Try each allowed address in turn, giving each [`CONNECT_TIMEOUT`], and return the first
/// connection. The error is the last one met: `PermissionDenied` for an address that is not
/// allowed, `TimedOut` for one that did not answer, `NotFound` when there was no address.
async fn first_reachable<T, F>(
    addrs: impl IntoIterator<Item = SocketAddr>,
    allowed: impl Fn(IpAddr) -> bool,
    connect: impl Fn(SocketAddr) -> F,
) -> io::Result<T>
where
    F: Future<Output = io::Result<T>>,
{
    let mut last = io::Error::new(io::ErrorKind::NotFound, "no address");
    for addr in addrs {
        if !allowed(addr.ip()) {
            last = io::Error::new(io::ErrorKind::PermissionDenied, "destination refused");
            continue;
        }
        match tokio::time::timeout(CONNECT_TIMEOUT, connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => last = e,
            Err(_) => last = io::Error::new(io::ErrorKind::TimedOut, "connect timed out"),
        }
    }
    Err(last)
}

/// Addresses that are never a legitimate destination for a device's traffic through this
/// proxy, because they name this computer, its local network, or no host at all: loopback,
/// unspecified, link-local, private (RFC 1918), carrier-grade NAT (100.64.0.0/10), unique
/// local (fc00::/7), multicast, broadcast and reserved space, and IPv6 forms that embed an
/// IPv4 address. Expects a canonical address (an IPv4-mapped one already unwrapped).
fn special_purpose(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            v4.is_loopback()
                || v4.is_unspecified()
                || a == 0
                || v4.is_link_local()
                || v4.is_private()
                || (a == 100 && (b & 0xc0) == 64)
                || v4.is_multicast()
                || a >= 240 // reserved, and 255.255.255.255
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || (segments[0] & 0xffc0) == 0xfe80
                || (segments[0] & 0xfe00) == 0xfc00
                || v6.is_multicast()
                // ::a.b.c.d (deprecated "IPv4-compatible") and anything else under ::/96
                || segments[..6] == [0; 6]
                // an IPv4-mapped address that was not unwrapped
                || v6.to_ipv4_mapped().is_some()
        }
    }
}

async fn connect_to(addr: SocketAddr) -> io::Result<TcpStream> {
    let stream = TcpStream::connect(addr).await?;
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
    let stream = tokio::time::timeout(DIAL_TIMEOUT, shared.tls.connect(name, tcp))
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

        handle
            .shared
            .note_proxy_use(ip("127.0.0.1"), ip("127.0.0.1"));
        handle.shared.note_proxy_use(local, local);
        assert!(events.try_recv().is_err(), "this computer is not a device");

        handle.shared.note_proxy_use(ip("192.168.1.57"), local);
        assert_eq!(events.try_recv(), Ok(ProxyEvent::DeviceConnected));

        handle.shared.note_proxy_use(ip("192.168.1.57"), local);
        handle.shared.note_proxy_use(ip("192.168.1.99"), local);
        assert!(
            events.try_recv().is_err(),
            "only the first one is announced"
        );
        handle.shutdown().await;
    }

    #[test]
    fn the_first_peer_to_complete_a_handshake_is_the_device_for_good() {
        let local = ip("192.168.1.20");
        let mut device = None;
        let mut claim = |peer: &str| claim_device(&mut device, ip(peer), local);
        assert_eq!(claim("192.168.1.57"), Claim::Became);
        assert_eq!(claim("192.168.1.57"), Claim::Is);
        assert_eq!(
            claim("::ffff:192.168.1.57"),
            Claim::Is,
            "the same peer over a mapped address"
        );
        assert_eq!(claim("192.168.1.99"), Claim::Other);
        assert_eq!(claim("127.0.0.1"), Claim::Other);
        assert_eq!(claim("192.168.1.20"), Claim::Other);
        assert_eq!(device, Some(ip("192.168.1.57")), "never replaced");
    }

    #[test]
    fn this_computer_never_becomes_the_device() {
        let local = ip("192.168.1.20");
        let mut device = None;
        for own in [
            "127.0.0.1",
            "::1",
            "::ffff:127.0.0.1",
            "192.168.1.20",
            "::ffff:192.168.1.20",
        ] {
            assert_eq!(
                claim_device(&mut device, ip(own), local),
                Claim::NotADevice,
                "{own}"
            );
            assert_eq!(device, None, "{own} did not take the slot");
        }
        // The iPhone or iPad arrives afterwards and is not locked out.
        assert_eq!(
            claim_device(&mut device, ip("192.168.1.57"), local),
            Claim::Became
        );
        assert_eq!(
            claim_device(&mut device, ip("127.0.0.1"), local),
            Claim::Other,
            "and from then on this computer is turned away like anyone else"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_refusal_is_reported_at_most_once_in_two_seconds() {
        let throttle = Throttle::new(REFUSED_EVERY);
        assert_eq!(REFUSED_EVERY, Duration::from_secs(2));
        assert!(throttle.ready());
        assert!(!throttle.ready());
        tokio::time::advance(Duration::from_millis(1999)).await;
        assert!(!throttle.ready());
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(throttle.ready());
        assert!(!throttle.ready());
    }

    #[tokio::test(start_paused = true)]
    async fn a_blackholed_address_does_not_starve_the_next_one() {
        let blackhole: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let good: SocketAddr = "203.0.113.9:443".parse().unwrap();
        // An address that swallows packets never answers; the good one answers at once.
        let connect = move |addr: SocketAddr| async move {
            if addr == good {
                Ok(addr)
            } else {
                std::future::pending::<io::Result<SocketAddr>>().await
            }
        };

        let started = Instant::now();
        let reached =
            within_dial_timeout(first_reachable([blackhole, good], |_| true, connect)).await;
        assert_eq!(reached.unwrap(), good, "the second address is still tried");
        assert_eq!(started.elapsed(), CONNECT_TIMEOUT);
        assert_eq!(CONNECT_TIMEOUT, Duration::from_secs(5));

        // Two dead addresses still leave time for a third.
        let other_blackhole: SocketAddr = "[2001:db8::2]:443".parse().unwrap();
        let reached = within_dial_timeout(first_reachable(
            [blackhole, other_blackhole, good],
            |_| true,
            connect,
        ))
        .await;
        assert_eq!(reached.unwrap(), good);

        // Nothing answers: the overall budget still ends it.
        let started = Instant::now();
        let none = within_dial_timeout(first_reachable(
            std::iter::repeat_n(blackhole, 10),
            |_| true,
            connect,
        ))
        .await;
        assert_eq!(none.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(started.elapsed(), DIAL_TIMEOUT);

        // A refused address is never dialled, and says so when nothing else worked.
        let refused = first_reachable([good], |_| false, connect).await;
        assert_eq!(refused.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        let empty = first_reachable([], |_| true, connect).await;
        assert_eq!(empty.unwrap_err().kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn only_certificate_alerts_count_as_a_rejection() {
        let alert = |description| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                rustls::Error::AlertReceived(description),
            )
        };
        for refused in [
            AlertDescription::BadCertificate,
            AlertDescription::UnknownCA,
            AlertDescription::CertificateUnknown,
            AlertDescription::UnsupportedCertificate,
            AlertDescription::CertificateExpired,
            AlertDescription::CertificateRevoked,
            AlertDescription::AccessDenied,
            AlertDescription::DecryptError,
        ] {
            assert!(certificate_refused(&alert(refused)), "{refused:?}");
        }
        for benign in [
            AlertDescription::CloseNotify,
            AlertDescription::UserCanceled,
            AlertDescription::HandshakeFailure,
            AlertDescription::ProtocolVersion,
            AlertDescription::NoApplicationProtocol,
            AlertDescription::InternalError,
        ] {
            assert!(!certificate_refused(&alert(benign)), "{benign:?}");
        }
        for kind in [
            io::ErrorKind::UnexpectedEof,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::TimedOut,
        ] {
            assert!(!certificate_refused(&io::Error::from(kind)), "{kind:?}");
        }
        let ours = io::Error::new(
            io::ErrorKind::InvalidData,
            rustls::Error::NoApplicationProtocol,
        );
        assert!(!certificate_refused(&ours), "our own failure, not an alert");
    }

    #[test]
    fn numeric_path_segments_are_redacted() {
        assert_eq!(
            redact_ids("/json/users/10000001/devices/20000002/apps"),
            "/json/users/:id/devices/:id/apps"
        );
        assert_eq!(
            redact_ids("/json/users/1/authenticator_tokens"),
            "/json/users/:id/authenticator_tokens"
        );
        assert_eq!(redact_ids("/"), "/");
        assert_eq!(redact_ids("/json/v2/ios/7"), "/json/v2/ios/:id");
        assert_eq!(redact_ids("/a//b/12a/"), "/a//b/12a/");
    }

    #[tokio::test(start_paused = true)]
    async fn idle_timer_restarts_on_activity() {
        let activity = Mutex::new(Instant::now());
        let limit = Duration::from_secs(600);
        let idle = idle_for(&activity, limit);
        tokio::pin!(idle);

        // Nine minutes of silence, then a byte: the clock starts again.
        assert!(tokio::time::timeout(Duration::from_secs(540), &mut idle)
            .await
            .is_err());
        *activity.lock().unwrap() = Instant::now();
        assert!(
            tokio::time::timeout(Duration::from_secs(599), &mut idle)
                .await
                .is_err(),
            "still open 599 s after the last byte"
        );
        tokio::time::timeout(Duration::from_secs(2), &mut idle)
            .await
            .expect("closed ten minutes after the last byte");
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
            authy_ports: None,
            unrestricted: false,
            own: Arc::default(),
        };
        let refused = [
            // loopback and unspecified
            "127.0.0.1",
            "127.1.2.3",
            "::1",
            "0.0.0.0",
            "0.1.2.3",
            "::",
            // link-local, including the cloud metadata address
            "169.254.169.254",
            "169.254.0.1",
            "fe80::1",
            "febf::1",
            // RFC 1918
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.0.1",
            "192.168.1.20",
            // carrier-grade NAT
            "100.64.0.1",
            "100.127.255.254",
            // unique local
            "fc00::1",
            "fd12:3456:789a::1",
            // multicast, broadcast, reserved
            "224.0.0.251",
            "239.255.255.250",
            "255.255.255.255",
            "240.0.0.1",
            "ff02::1",
            "ff05::2",
            // IPv4 inside IPv6
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:192.168.1.1",
            "::ffff:169.254.169.254",
            "::ffff:100.64.0.1",
            "::ffff:224.0.0.1",
            "::10.0.0.1",
            "::127.0.0.1",
        ];
        for address in refused {
            assert!(!production.allows(ip(address)), "{address}");
        }
        let allowed = [
            "93.184.216.34",
            "1.1.1.1",
            "100.63.255.255",
            "100.128.0.1",
            "172.15.255.255",
            "172.32.0.1",
            "169.253.0.1",
            "192.167.1.1",
            "223.255.255.254",
            "2606:4700::1111",
            "2001:db8::1",
            "::ffff:93.184.216.34",
        ];
        for address in allowed {
            assert!(production.allows(ip(address)), "{address}");
        }

        // This computer's own addresses, however public.
        production.add_own([ip("203.0.113.7"), ip("2001:db8::7"), ip("0.0.0.0")]);
        assert!(!production.allows(ip("203.0.113.7")));
        assert!(!production.allows(ip("::ffff:203.0.113.7")));
        assert!(!production.allows(ip("2001:db8::7")));
        assert!(
            production.allows(ip("203.0.113.8")),
            "its neighbour is fine"
        );

        let test = Dial {
            authy_at: None,
            authy_ports: None,
            unrestricted: true,
            own: Arc::default(),
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
