//! Proxy integration tests (package 1C).
//!
//! Everything runs on loopback with synthetic data: a stand-in for Authy (an HTTPS server whose
//! certificate names `api.authy.com`), a stand-in for "any other site" with its own certificate
//! authority, and a plain-HTTP server. Clients are `reqwest` where a real HTTP client matters and
//! raw sockets where the exact bytes on the wire matter.

use std::convert::Infallible;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use authexodus_core::ca::{Authority, MemoryKeyStore};
use authexodus_core::proxy::{
    self, ProxyConfig, ProxyEvent, ProxyHandle, TestUpstream, AUTHY_HOST, CHECK_HOST,
};
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::crypto::aws_lc_rs;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio_rustls::{TlsAcceptor, TlsConnector};

const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const WAIT: Duration = Duration::from_secs(10);
const QUIET: Duration = Duration::from_millis(300);

// ---------------------------------------------------------------------------------------------
// Certificates for the stand-in servers
// ---------------------------------------------------------------------------------------------

struct TestCa {
    cert_der: Vec<u8>,
    issuer: Issuer<'static, KeyPair>,
}

fn test_ca(name: &str) -> TestCa {
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let key = KeyPair::generate().unwrap();
    let cert_der = params.self_signed(&key).unwrap().der().to_vec();
    TestCa {
        cert_der,
        issuer: Issuer::new(params, key),
    }
}

/// A server configuration with a leaf for `names`, and that leaf's DER.
fn leaf(ca: &TestCa, names: &[&str]) -> (Arc<ServerConfig>, Vec<u8>) {
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, names[0]);
    for name in names {
        params.subject_alt_names.push(match name.parse::<IpAddr>() {
            Ok(ip) => SanType::IpAddress(ip),
            Err(_) => SanType::DnsName((*name).try_into().unwrap()),
        });
    }
    let key = KeyPair::generate().unwrap();
    let der = params.signed_by(&key, &ca.issuer).unwrap().der().to_vec();
    let config = ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(der.clone())],
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap();
    (Arc::new(config), der)
}

fn client_tls(roots: &[&[u8]]) -> Arc<ClientConfig> {
    let mut store = RootCertStore::empty();
    for root in roots {
        store.add(CertificateDer::from(root.to_vec())).unwrap();
    }
    Arc::new(
        ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(store)
            .with_no_client_auth(),
    )
}

// ---------------------------------------------------------------------------------------------
// Stand-in servers
// ---------------------------------------------------------------------------------------------

/// What a stand-in server saw: one line per request, `METHOD target proxy-authorization=bool`.
type Seen = Arc<Mutex<Vec<String>>>;

type Handler =
    Arc<dyn Fn(&str, &str, &http::HeaderMap, &[u8]) -> Response<Full<Bytes>> + Send + Sync>;

async fn serve(tls: Option<Arc<ServerConfig>>, handler: Handler) -> (SocketAddr, Seen) {
    let listener = TcpListener::bind((LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Seen::default();
    let record = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let handler = Arc::clone(&handler);
            let record = Arc::clone(&record);
            let tls = tls.clone();
            tokio::spawn(async move {
                let service = service_fn(move |req: Request<Incoming>| {
                    let handler = Arc::clone(&handler);
                    let record = Arc::clone(&record);
                    async move {
                        let (parts, body) = req.into_parts();
                        let body = body.collect().await.unwrap().to_bytes();
                        let target = parts.uri.to_string();
                        record.lock().unwrap().push(format!(
                            "{} {} proxy-authorization={}",
                            parts.method,
                            target,
                            parts.headers.contains_key("proxy-authorization")
                        ));
                        Ok::<_, Infallible>(handler(
                            parts.method.as_str(),
                            &target,
                            &parts.headers,
                            &body,
                        ))
                    }
                });
                let http = hyper::server::conn::http1::Builder::new();
                match tls {
                    Some(config) => {
                        let Ok(stream) = TlsAcceptor::from(config).accept(tcp).await else {
                            return;
                        };
                        let _ = http.serve_connection(TokioIo::new(stream), service).await;
                    }
                    None => {
                        let _ = http.serve_connection(TokioIo::new(tcp), service).await;
                    }
                }
            });
        }
    });
    (addr, seen)
}

fn ok(body: impl Into<Bytes>) -> Response<Full<Bytes>> {
    Response::new(Full::new(body.into()))
}

/// A synthetic backup in the real response's shape. Nothing in it is real.
fn tokens_body(n: usize) -> Vec<u8> {
    let tokens: Vec<serde_json::Value> = (0..n)
        .map(|i| {
            serde_json::json!({
                "account_type": "authenticator",
                "digits": 6,
                "encrypted_seed": format!("c3ludGhldGljLXNlZWQt{i}"),
                "issuer": "Example",
                "key_derivation_iterations": 100000,
                "logo": null,
                "name": format!("Example: user{i}@example.com"),
                "original_name": format!("Example: user{i}@example.com"),
                "password_timestamp": 1700000000,
                "salt": format!("salt{i}"),
                "unique_id": 5000 + i,
                "unique_iv": "000102030405060708090a0b0c0d0e0f",
            })
        })
        .collect();
    serde_json::to_vec(&serde_json::json!({
        "message": "success", "authenticator_tokens": tokens, "deleted": [], "success": true,
    }))
    .unwrap()
}

const APPS_BODY: &str = r#"{"message":"success","apps":[{"name":"Synthetic Native","digits":7,"secret_seed":"00112233445566778899aabbccddeeff"},{"name":"Another Native","digits":7,"secret_seed":"ffeeddccbbaa99887766554433221100"}],"deleted":[],"success":true}"#;

/// The stand-in for Authy's API.
fn authy_handler() -> Handler {
    Arc::new(|method, target, headers, body| {
        let path = target.split('?').next().unwrap();
        if path.ends_with("/authenticator_tokens") {
            if path.contains("/users/2/") {
                return ok(r#"{"message":"success","authenticator_tokens":[],"success":true}"#);
            }
            let body = tokens_body(3);
            let wants_gzip = headers
                .get("accept-encoding")
                .is_some_and(|v| v.to_str().unwrap().contains("gzip"));
            if wants_gzip {
                let mut res = ok(gzip(&body));
                res.headers_mut()
                    .insert("content-encoding", "gzip".parse().unwrap());
                return res;
            }
            return ok(body);
        }
        if path.ends_with("/apps") {
            return ok(APPS_BODY);
        }
        if path.ends_with("/echo") {
            return ok(format!("{method} {}", String::from_utf8_lossy(body)));
        }
        if path.ends_with("/big") {
            return ok(big_body());
        }
        if path.ends_with("/close") {
            // Authy ends the connection after this response.
            let mut res = ok("closing");
            res.headers_mut()
                .insert("connection", "close".parse().unwrap());
            return res;
        }
        if path.ends_with("/fail") {
            let mut res = ok(r#"{"success":false,"message":"denied"}"#);
            *res.status_mut() = StatusCode::UNAUTHORIZED;
            return res;
        }
        ok(r#"{"success":true}"#)
    })
}

/// Two mebibytes that are not a repeat of one byte.
fn big_body() -> Vec<u8> {
    (0..2 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect()
}

/// gzip with stored (uncompressed) blocks: a valid gzip stream without a compression library.
fn gzip(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff];
    let chunks: Vec<&[u8]> = data.chunks(0xffff).collect();
    for (i, chunk) in chunks.iter().enumerate() {
        out.push(u8::from(i + 1 == chunks.len()));
        let len = chunk.len() as u16;
        out.extend(len.to_le_bytes());
        out.extend((!len).to_le_bytes());
        out.extend(*chunk);
    }
    let mut crc = !0u32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    out.extend((!crc).to_le_bytes());
    out.extend((data.len() as u32).to_le_bytes());
    out
}

// ---------------------------------------------------------------------------------------------
// The rig: a proxy in front of a stand-in Authy
// ---------------------------------------------------------------------------------------------

struct Rig {
    handle: ProxyHandle,
    events: UnboundedReceiver<ProxyEvent>,
    /// The proxy's root certificate: what the device installs.
    ca_der: Vec<u8>,
    proxy: SocketAddr,
    /// Requests the stand-in Authy received.
    authy_seen: Seen,
}

async fn rig() -> Rig {
    let upstream_ca = test_ca("stand-in upstream CA");
    let (config, _) = leaf(&upstream_ca, &[AUTHY_HOST]);
    let (authy, authy_seen) = serve(Some(config), authy_handler()).await;
    rig_with(Some(TestUpstream {
        addr: authy,
        root_cert_der: upstream_ca.cert_der.clone(),
    }))
    .await
    .with_seen(authy_seen)
}

async fn rig_with(upstream: Option<TestUpstream>) -> Rig {
    let ca = Arc::new(Authority::load_or_create(&MemoryKeyStore::new(), true).unwrap());
    let (tx, events) = tokio::sync::mpsc::unbounded_channel();
    let handle = proxy::start(
        ProxyConfig {
            listen_ip: LOCALHOST,
            preferred_port: 0,
            upstream,
        },
        Arc::clone(&ca),
        tx,
    )
    .await
    .unwrap();
    Rig {
        proxy: SocketAddr::new(LOCALHOST, handle.port()),
        handle,
        events,
        ca_der: ca.cert_der(),
        authy_seen: Seen::default(),
    }
}

impl Rig {
    fn with_seen(mut self, seen: Seen) -> Rig {
        self.authy_seen = seen;
        self
    }

    /// An HTTP client that uses the proxy and trusts exactly `roots`.
    fn client(&self, roots: &[&[u8]]) -> reqwest::Client {
        reqwest::Client::builder()
            .no_proxy()
            .proxy(reqwest::Proxy::all(format!("http://{}", self.proxy)).unwrap())
            .tls_certs_only(
                roots
                    .iter()
                    .map(|der| reqwest::Certificate::from_der(der).unwrap()),
            )
            .build()
            .unwrap()
    }

    /// A client like the iPhone or iPad after the certificate is installed and trusted.
    fn trusting_client(&self) -> reqwest::Client {
        self.client(&[&self.ca_der])
    }

    /// Every event up to and including the first that matches.
    async fn wait_for(&mut self, what: impl Fn(&ProxyEvent) -> bool) -> Vec<ProxyEvent> {
        let mut seen = Vec::new();
        loop {
            match tokio::time::timeout(WAIT, self.events.recv()).await {
                Ok(Some(event)) => {
                    let done = what(&event);
                    seen.push(event);
                    if done {
                        return seen;
                    }
                }
                Ok(None) => panic!("event channel closed; saw {seen:?}"),
                Err(_) => panic!("timed out waiting for an event; saw {seen:?}"),
            }
        }
    }

    /// Whatever arrives during a short quiet period.
    async fn drain(&mut self) -> Vec<ProxyEvent> {
        let mut seen = Vec::new();
        while let Ok(Some(event)) = tokio::time::timeout(QUIET, self.events.recv()).await {
            seen.push(event);
        }
        seen
    }

    fn authy_requests(&self) -> Vec<String> {
        self.authy_seen.lock().unwrap().clone()
    }
}

// ---------------------------------------------------------------------------------------------
// Raw clients
// ---------------------------------------------------------------------------------------------

/// Send `CONNECT host:port` to the proxy. Returns the status line and the open stream.
async fn connect_via(proxy: SocketAddr, host: &str, port: u16) -> (String, TcpStream) {
    let mut tcp = TcpStream::connect(proxy).await.unwrap();
    tcp.write_all(
        format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(tcp.read_u8().await.unwrap());
    }
    let head = String::from_utf8(head).unwrap();
    (head.lines().next().unwrap().to_owned(), tcp)
}

/// Send raw bytes, read until the peer closes. Returns (head, body).
async fn raw_http(to: SocketAddr, request: &str) -> (String, Vec<u8>) {
    let mut tcp = TcpStream::connect(to).await.unwrap();
    tcp.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(WAIT, tcp.read_to_end(&mut response))
        .await
        .expect("response")
        .unwrap();
    let split = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("a complete response head");
    (
        String::from_utf8(response[..split].to_vec()).unwrap(),
        response[split + 4..].to_vec(),
    )
}

/// One HTTPS request through the proxy with nothing but sockets and rustls: CONNECT, TLS
/// trusting `roots`, the request, read until close. Returns (head, body).
async fn raw_https(
    proxy: SocketAddr,
    host: &str,
    port: u16,
    roots: &[&[u8]],
    method: &str,
    target: &str,
) -> (String, Vec<u8>) {
    let (status, tcp) = connect_via(proxy, host, port).await;
    assert_eq!(status, "HTTP/1.1 200 OK");
    let mut tls = TlsConnector::from(client_tls(roots))
        .connect(ServerName::try_from(host.to_owned()).unwrap(), tcp)
        .await
        .expect("TLS handshake");
    tls.write_all(
        format!(
            "{method} {target} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\n\
             Connection: close\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut response = Vec::new();
    // A peer that closes without a TLS close_notify is fine here: the head says how much to
    // expect, and these bodies are compared by the caller.
    let _ = tokio::time::timeout(WAIT, tls.read_to_end(&mut response))
        .await
        .expect("response");
    let split = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("a complete response head");
    (
        String::from_utf8(response[..split].to_vec()).unwrap(),
        response[split + 4..].to_vec(),
    )
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|line| {
        let (n, v) = line.split_once(':')?;
        n.eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

// ---------------------------------------------------------------------------------------------
// Log capture
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Default)]
struct LogBuffer(Arc<Mutex<Vec<u8>>>);

impl LogBuffer {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

impl Write for LogBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuffer {
    type Writer = LogBuffer;
    fn make_writer(&'a self) -> LogBuffer {
        self.clone()
    }
}

/// Record everything `tracing` emits on this thread, at every level and from every crate, with
/// span open/close lines too: the most talkative subscriber an app could install. The tests
/// that use it run on a current-thread runtime, so every task of the proxy is on this thread.
/// Those tests drive the proxy with raw sockets only, so that the one thing writing to the log
/// is the proxy (an HTTP client library in the test would log its own view of the hosts).
fn capture_logs() -> (LogBuffer, tracing::subscriber::DefaultGuard) {
    let buffer = LogBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .with_ansi(false)
        .with_writer(buffer.clone())
        .finish();
    (buffer, tracing::subscriber::set_default(subscriber))
}

// ---------------------------------------------------------------------------------------------
// Tests named in the plan
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn intercepts_authy_and_captures_backup() {
    let mut rig = rig().await;
    assert_eq!(rig.handle.backup().tokens.len(), 0);

    let res = rig
        .trusting_client()
        .get(format!(
            "https://{AUTHY_HOST}/json/users/1/authenticator_tokens?api_key=synthetic&locale=en"
        ))
        .send()
        .await
        .expect("a client that trusts the proxy's root reaches Authy through it");
    assert_eq!(res.status(), 200);
    assert_eq!(
        res.bytes().await.unwrap(),
        tokens_body(3),
        "the device gets Authy's response unchanged"
    );

    let events = rig
        .wait_for(|e| matches!(e, ProxyEvent::BackupCaptured { .. }))
        .await;
    assert_eq!(
        events,
        [
            ProxyEvent::TrustWorking,
            ProxyEvent::BackupCaptured { count: 3 }
        ]
    );
    let backup = rig.handle.backup();
    assert_eq!(backup.tokens.len(), 3);
    assert_eq!(backup.tokens[0].unique_id, "5000");
    assert_eq!(backup.tokens[2].name, "Example: user2@example.com");
    assert_eq!(backup.tokens[1].encrypted_seed, "c3ludGhldGljLXNlZWQt1");
    assert!(backup.native_apps.is_empty());

    assert_eq!(
        rig.authy_requests(),
        ["GET /json/users/1/authenticator_tokens?api_key=synthetic&locale=en proxy-authorization=false"],
        "Authy receives the request as the device sent it, query string included"
    );
    rig.handle.shutdown().await;
}

#[tokio::test]
async fn other_hosts_are_tunnelled_untouched() {
    let mut rig = rig().await;
    // "Any other site": its own CA, and a body that would be captured if it were ever read.
    let other_ca = test_ca("other-site CA");
    let (config, other_leaf) = leaf(&other_ca, &["localhost"]);
    let (other, _) = serve(Some(config), Arc::new(|_, _, _, _| ok(tokens_body(7)))).await;

    // The certificate the client is shown is the other server's own leaf, byte for byte.
    let (status, tcp) = connect_via(rig.proxy, "localhost", other.port()).await;
    assert_eq!(status, "HTTP/1.1 200 OK");
    let tls = TlsConnector::from(client_tls(&[&other_ca.cert_der]))
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .expect("handshake with the other server, end to end");
    let shown = tls.get_ref().1.peer_certificates().unwrap()[0].to_vec();
    assert_eq!(shown, other_leaf);
    drop(tls);

    // A client that trusts only the proxy's root cannot be fooled about that host...
    let err = rig
        .trusting_client()
        .get(format!("https://localhost:{}/x", other.port()))
        .send()
        .await;
    assert!(
        err.is_err(),
        "the proxy does not mint a leaf for other hosts"
    );
    // ...and one that trusts the other site's CA gets its content through the tunnel.
    let body = rig
        .client(&[&other_ca.cert_der])
        .get(format!(
            "https://localhost:{}/json/users/1/authenticator_tokens",
            other.port()
        ))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_eq!(body, tokens_body(7));

    assert_eq!(rig.drain().await, [], "a tunnel produces no events");
    assert_eq!(
        rig.handle.backup().tokens.len(),
        0,
        "nothing inside a tunnel is read"
    );
    assert!(rig.authy_requests().is_empty());
    rig.handle.shutdown().await;
}

#[tokio::test]
async fn plain_http_is_forwarded() {
    let mut rig = rig().await;
    let (site, seen) = serve(
        None,
        Arc::new(|method, target, _, body| {
            ok(format!(
                "{method} {target} body={}",
                String::from_utf8_lossy(body)
            ))
        }),
    )
    .await;

    // Exactly what a device with the proxy configured sends: an absolute-form request.
    let (head, body) = raw_http(
        rig.proxy,
        &format!(
            "GET http://{site}/plain?x=1&y=two HTTP/1.1\r\nHost: {site}\r\n\
             Proxy-Authorization: Basic c3ludGhldGlj\r\nProxy-Connection: keep-alive\r\n\
             Connection: close\r\n\r\n"
        ),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(body, b"GET /plain?x=1&y=two body=");

    // And through a real client, with a request body.
    let echoed = rig
        .trusting_client()
        .post(format!("http://{site}/submit"))
        .body("hello upstream")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(echoed, "POST /submit body=hello upstream");

    assert_eq!(
        *seen.lock().unwrap(),
        [
            "GET /plain?x=1&y=two proxy-authorization=false",
            "POST /submit proxy-authorization=false"
        ],
        "origin-form to the server, and nothing addressed to the proxy is passed on"
    );
    assert_eq!(rig.drain().await, [], "plain HTTP produces no events");
    rig.handle.shutdown().await;
}

#[tokio::test]
async fn untrusting_client_emits_tls_rejected() {
    let mut rig = rig().await;

    // A device that has not installed (or not trusted) the certificate: it is shown the
    // proxy's leaf and aborts the handshake.
    let stranger = test_ca("some other root");
    let (status, tcp) = connect_via(rig.proxy, AUTHY_HOST, 443).await;
    assert_eq!(status, "HTTP/1.1 200 OK");
    let refused = TlsConnector::from(client_tls(&[&stranger.cert_der]))
        .connect(ServerName::try_from(AUTHY_HOST).unwrap(), tcp)
        .await;
    assert!(
        refused.is_err(),
        "the client must not trust the proxy's leaf"
    );

    let events = rig.wait_for(|e| *e == ProxyEvent::TlsRejected).await;
    assert_eq!(events, [ProxyEvent::TlsRejected]);
    assert_eq!(rig.drain().await, [], "and no TrustWorking");
    assert!(rig.authy_requests().is_empty(), "Authy was never contacted");

    // A connection that is opened and dropped before any TLS is not a rejection: the device
    // never saw the certificate.
    let (_, tcp) = connect_via(rig.proxy, AUTHY_HOST, 443).await;
    drop(tcp);
    assert_eq!(rig.drain().await, []);

    // Once the device trusts the root, the same connection succeeds.
    let (_, tcp) = connect_via(rig.proxy, AUTHY_HOST, 443).await;
    TlsConnector::from(client_tls(&[&rig.ca_der]))
        .connect(ServerName::try_from(AUTHY_HOST).unwrap(), tcp)
        .await
        .expect("trusted now");
    assert_eq!(
        rig.wait_for(|e| *e == ProxyEvent::TrustWorking).await,
        [ProxyEvent::TrustWorking]
    );
    rig.handle.shutdown().await;
}

#[tokio::test]
async fn serves_certificate_and_check_page() {
    let mut rig = rig().await;
    let proxy = rig.proxy;
    let direct = reqwest::Client::builder().no_proxy().build().unwrap();

    // Origin form: the device's browser goes straight to the address in the QR code.
    let page = direct.get(format!("http://{proxy}/")).send().await.unwrap();
    assert_eq!(page.status(), 200);
    assert!(page.headers()["content-type"]
        .to_str()
        .unwrap()
        .starts_with("text/html"));
    let page = page.text().await.unwrap();
    assert!(page.contains("<a class=\"button\" href=\"/cert\">Download certificate</a>"));
    assert!(page.contains(&format!("<a href=\"https://{CHECK_HOST}/\">Test</a>")));

    let cert = direct
        .get(format!("http://{proxy}/cert"))
        .send()
        .await
        .unwrap();
    assert_eq!(cert.status(), 200);
    assert_eq!(cert.headers()["content-type"], "application/x-x509-ca-cert");
    assert_eq!(cert.headers()["cache-control"], "no-store");
    assert_eq!(cert.bytes().await.unwrap(), rig.ca_der, "DER, as issued");

    assert_eq!(
        direct
            .get(format!("http://{proxy}/nothing-here"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );

    // Absolute form: the device already has the proxy set, so its browser asks the proxy for
    // the proxy's own address.
    let (head, body) = raw_http(
        proxy,
        &format!("GET http://{proxy}/cert HTTP/1.1\r\nHost: {proxy}\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(
        header(&head, "content-type"),
        Some("application/x-x509-ca-cert")
    );
    assert_eq!(body, rig.ca_der);
    let (head, body) = raw_http(
        proxy,
        &format!("GET http://{proxy}/ HTTP/1.1\r\nHost: {proxy}\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(String::from_utf8(body)
        .unwrap()
        .contains("Download certificate"));

    assert_eq!(
        rig.drain().await,
        [],
        "loopback is not a device; no TLS yet"
    );

    // The check host is answered by the proxy itself over intercepted TLS.
    let check = rig
        .trusting_client()
        .get(format!("https://{CHECK_HOST}/"))
        .send()
        .await
        .expect("the name-constrained root vouches for the check host");
    assert_eq!(check.status(), 200);
    assert!(check
        .text()
        .await
        .unwrap()
        .contains("Certificate is trusted"));
    assert_eq!(
        rig.wait_for(|e| *e == ProxyEvent::TrustWorking).await,
        [ProxyEvent::TrustWorking]
    );

    // Over plain HTTP the check host proves nothing, so it only points at the real check.
    let (head, _) = raw_http(
        proxy,
        &format!(
            "GET http://{CHECK_HOST}/ HTTP/1.1\r\nHost: {CHECK_HOST}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 302"), "{head}");
    assert_eq!(
        header(&head, "location"),
        Some(format!("https://{CHECK_HOST}/").as_str())
    );

    assert!(
        rig.authy_requests().is_empty(),
        "nothing above was forwarded to Authy"
    );
    rig.handle.shutdown().await;
}

#[tokio::test]
async fn falls_back_when_port_in_use() {
    let blocker = std::net::TcpListener::bind((LOCALHOST, 0)).unwrap();
    let taken = blocker.local_addr().unwrap().port();

    let ca = Arc::new(Authority::load_or_create(&MemoryKeyStore::new(), true).unwrap());
    let (tx, _events) = tokio::sync::mpsc::unbounded_channel();
    let handle = proxy::start(
        ProxyConfig {
            listen_ip: LOCALHOST,
            preferred_port: taken,
            upstream: None,
        },
        Arc::clone(&ca),
        tx,
    )
    .await
    .expect("a taken port is not an error");
    let port = handle.port();
    assert_ne!(port, taken);
    assert_ne!(port, 0, "the real port is reported");

    // The proxy really is listening where it says.
    let page = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get(format!("http://127.0.0.1:{port}/"))
        .send()
        .await
        .unwrap();
    assert_eq!(page.status(), 200);
    handle.shutdown().await;
    drop(blocker);

    // A free preferred port is used as asked. (Another process could grab the port between
    // finding it and binding it, so allow a few goes.)
    let mut honoured = false;
    for _ in 0..5 {
        let free = {
            let probe = std::net::TcpListener::bind((LOCALHOST, 0)).unwrap();
            probe.local_addr().unwrap().port()
        };
        let (tx, _events) = tokio::sync::mpsc::unbounded_channel();
        let handle = proxy::start(
            ProxyConfig {
                listen_ip: LOCALHOST,
                preferred_port: free,
                upstream: None,
            },
            Arc::clone(&ca),
            tx,
        )
        .await
        .unwrap();
        honoured = handle.port() == free;
        handle.shutdown().await;
        if honoured {
            break;
        }
    }
    assert!(honoured, "the preferred port is bound when it is free");
}

#[tokio::test]
async fn logs_never_contain_query_strings() {
    let (logs, _guard) = capture_logs();
    let mut rig = rig().await;
    let (site, site_seen) = serve(None, Arc::new(|_, _, _, _| ok("plain"))).await;
    let ca = rig.ca_der.clone();

    // Intercepted and successful; intercepted and refused by Authy; the check page; the
    // proxy's own pages (origin form and absolute form); plain HTTP.
    let (head, body) = raw_https(
        rig.proxy,
        AUTHY_HOST,
        443,
        &[&ca],
        "GET",
        "/json/users/1/authenticator_tokens?api_key=SECRET1&otp1=SECRET2",
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(body, tokens_body(3));
    let (head, _) = raw_https(
        rig.proxy,
        AUTHY_HOST,
        443,
        &[&ca],
        "POST",
        "/json/fail?api_key=SECRET3",
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 401"), "{head}");
    let (head, _) = raw_https(rig.proxy, CHECK_HOST, 443, &[&ca], "GET", "/?token=SECRET4").await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let (head, _) = raw_http(
        rig.proxy,
        "GET /cert?who=SECRET5 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let (head, _) = raw_http(
        rig.proxy,
        &format!(
            "GET http://{0}/missing?who=SECRET6 HTTP/1.1\r\nHost: {0}\r\nConnection: close\r\n\r\n",
            rig.proxy
        ),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 404"), "{head}");
    let (head, _) = raw_http(
        rig.proxy,
        &format!(
            "GET http://{site}/page?session=SECRET7 HTTP/1.1\r\nHost: {site}\r\n\
             Connection: close\r\n\r\n"
        ),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");

    rig.wait_for(|e| matches!(e, ProxyEvent::BackupCaptured { .. }))
        .await;
    rig.handle.shutdown().await;

    // The secrets did travel: Authy and the plain site received their query strings intact.
    assert!(rig.authy_seen.lock().unwrap()[0].contains("?api_key=SECRET1&otp1=SECRET2"));
    assert!(site_seen.lock().unwrap()[0].contains("?session=SECRET7"));

    let logs = logs.text();
    // The log is recording: requests show as method, path, status.
    for expected in [
        "method=GET path=/json/users/1/authenticator_tokens status=200",
        "method=POST path=/json/fail status=401",
        "method=GET path=/ status=200",
        "method=GET path=/cert status=200",
        "method=GET path=/missing status=404",
    ] {
        assert!(logs.contains(expected), "missing {expected:?} in:\n{logs}");
    }
    for forbidden in [
        "SECRET", "api_key", "otp1", "token=", "session", "who=", "?",
    ] {
        assert!(
            !logs.contains(forbidden),
            "{forbidden:?} leaked into:\n{logs}"
        );
    }
    // Bodies are not logged either.
    for forbidden in ["encrypted_seed", "c3ludGhldGljLXNlZWQt", "salt0"] {
        assert!(
            !logs.contains(forbidden),
            "{forbidden:?} leaked into:\n{logs}"
        );
    }
    // Nor is the plain-HTTP request, at all.
    assert!(!logs.contains("/page"), "plain HTTP leaked into:\n{logs}");
}

#[tokio::test]
async fn logs_never_name_tunnelled_or_forwarded_hosts() {
    let (logs, _guard) = capture_logs();
    let mut rig = rig().await;
    let other_ca = test_ca("other-site CA");
    let (config, _) = leaf(&other_ca, &["localhost"]);
    let (tunnelled, _) = serve(Some(config), Arc::new(|_, _, _, _| ok("tunnelled"))).await;
    let (plain, _) = serve(None, Arc::new(|_, _, _, _| ok("plain"))).await;

    // A tunnel that works.
    let (head, body) = raw_https(
        rig.proxy,
        "localhost",
        tunnelled.port(),
        &[&other_ca.cert_der],
        "GET",
        "/private/path?q=1",
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(body, b"tunnelled");

    // A tunnel that breaks mid-flight: the device vanishes after its first bytes.
    let (status, mut tcp) = connect_via(rig.proxy, "localhost", tunnelled.port()).await;
    assert_eq!(status, "HTTP/1.1 200 OK");
    tcp.write_all(b"\x16\x03\x01 not really a handshake")
        .await
        .unwrap();
    drop(tcp);

    // Tunnels that cannot be opened: a name that does not resolve, a port nobody listens on.
    let (status, _) = connect_via(rig.proxy, "tunnelled-host.invalid", 443).await;
    assert_eq!(status, "HTTP/1.1 502 Bad Gateway");
    let closed = {
        let probe = std::net::TcpListener::bind((LOCALHOST, 0)).unwrap();
        probe.local_addr().unwrap().port()
    };
    let (status, _) = connect_via(rig.proxy, "localhost", closed).await;
    assert_eq!(status, "HTTP/1.1 502 Bad Gateway");

    // Plain HTTP that works, and plain HTTP that cannot be delivered.
    let (head, body) = raw_http(
        rig.proxy,
        &format!(
            "GET http://localhost:{0}/forwarded/path HTTP/1.1\r\nHost: localhost:{0}\r\n\
             Connection: close\r\n\r\n",
            plain.port()
        ),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(body, b"plain");
    let (head, _) = raw_http(
        rig.proxy,
        "GET http://forwarded-host.invalid/gone HTTP/1.1\r\nHost: forwarded-host.invalid\r\n\
         Connection: close\r\n\r\n",
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 502"), "{head}");

    // One intercepted request, so the log is known to be recording.
    let ca = rig.ca_der.clone();
    let (head, _) = raw_https(rig.proxy, AUTHY_HOST, 443, &[&ca], "GET", "/json/ping").await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(rig.drain().await, [ProxyEvent::TrustWorking]);
    rig.handle.shutdown().await;

    let logs = logs.text();
    assert!(
        logs.contains("method=GET path=/json/ping status=200"),
        "the log is recording:\n{logs}"
    );
    for forbidden in [
        "localhost",
        "127.0.0.1",
        "tunnelled-host",
        "forwarded-host",
        ".invalid",
        "/private/path",
        "/forwarded/path",
        "/gone",
        &tunnelled.port().to_string(),
        &plain.port().to_string(),
        &closed.to_string(),
    ] {
        assert!(
            !logs.contains(forbidden),
            "{forbidden:?} leaked into:\n{logs}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Behaviour the plan describes without naming a test
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn gzip_encoded_backup_is_captured_and_passed_through_untouched() {
    let mut rig = rig().await;
    let res = rig
        .trusting_client()
        .get(format!(
            "https://{AUTHY_HOST}/json/users/1/authenticator_tokens"
        ))
        .header("accept-encoding", "gzip")
        .send()
        .await
        .unwrap();
    assert_eq!(res.headers()["content-encoding"], "gzip");
    assert_eq!(
        res.bytes().await.unwrap(),
        gzip(&tokens_body(3)),
        "the device gets the encoded bytes exactly as Authy sent them"
    );
    let events = rig
        .wait_for(|e| matches!(e, ProxyEvent::BackupCaptured { .. }))
        .await;
    assert_eq!(
        events.last(),
        Some(&ProxyEvent::BackupCaptured { count: 3 })
    );
    assert_eq!(rig.handle.backup().tokens.len(), 3);
    rig.handle.shutdown().await;
}

#[tokio::test]
async fn later_empty_backup_does_not_clobber_and_native_apps_are_added() {
    let mut rig = rig().await;
    let client = rig.trusting_client();
    let get = |path: &str| client.get(format!("https://{AUTHY_HOST}{path}")).send();

    get("/json/users/1/authenticator_tokens").await.unwrap();
    rig.wait_for(|e| *e == ProxyEvent::BackupCaptured { count: 3 })
        .await;

    // The same backup again, then an empty one: neither grows it, neither shrinks it.
    get("/json/users/1/authenticator_tokens").await.unwrap();
    get("/json/users/2/authenticator_tokens").await.unwrap();
    assert_eq!(rig.drain().await, []);
    assert_eq!(rig.handle.backup().tokens.len(), 3);

    // The Authy-native app list arrives separately: names and digits only.
    get("/json/users/1/devices/9/apps").await.unwrap();
    assert_eq!(
        rig.wait_for(|e| matches!(e, ProxyEvent::BackupCaptured { .. }))
            .await,
        [ProxyEvent::BackupCaptured { count: 3 }]
    );
    let backup = rig.handle.backup();
    assert_eq!(backup.tokens.len(), 3);
    let names: Vec<_> = backup.native_apps.iter().map(|a| a.name.as_str()).collect();
    assert_eq!(names, ["Synthetic Native", "Another Native"]);
    assert!(!format!("{backup:?}").contains("00112233445566778899aabbccddeeff"));
    rig.handle.shutdown().await;
}

#[tokio::test]
async fn authy_errors_are_reported_without_the_query_string() {
    let mut rig = rig().await;
    let res = rig
        .trusting_client()
        .get(format!("https://{AUTHY_HOST}/json/fail?api_key=synthetic"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401, "the device still gets Authy's answer");
    assert_eq!(
        res.text().await.unwrap(),
        r#"{"success":false,"message":"denied"}"#
    );

    let events = rig
        .wait_for(|e| matches!(e, ProxyEvent::AuthyError { .. }))
        .await;
    assert_eq!(
        events.last(),
        Some(&ProxyEvent::AuthyError {
            status: 401,
            path: "/json/fail".into()
        })
    );
    rig.handle.shutdown().await;
}

#[tokio::test]
async fn production_refuses_to_reach_this_computers_loopback() {
    // No test upstream: this is the production configuration.
    let mut rig = rig_with(None).await;
    let (local_service, seen) = serve(None, Arc::new(|_, _, _, _| ok("private"))).await;
    let port = local_service.port();

    for host in ["127.0.0.1", "localhost", "[::1]"] {
        let (status, _) = connect_via(rig.proxy, host, port).await;
        assert_eq!(status, "HTTP/1.1 403 Forbidden", "CONNECT {host}");
    }
    let (head, _) = raw_http(
        rig.proxy,
        &format!(
            "GET http://127.0.0.1:{port}/ HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\
             Connection: close\r\n\r\n"
        ),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 403"), "{head}");
    assert!(
        seen.lock().unwrap().is_empty(),
        "the local service was never reached"
    );

    // The proxy's own pages are not a "destination" and still work.
    let (head, body) = raw_http(
        rig.proxy,
        &format!(
            "GET http://{0}/cert HTTP/1.1\r\nHost: {0}\r\nConnection: close\r\n\r\n",
            rig.proxy
        ),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(body, rig.ca_der);
    assert_eq!(rig.drain().await, []);
    rig.handle.shutdown().await;
}

#[tokio::test]
async fn shutdown_closes_the_listener_and_open_tunnels() {
    let rig = rig().await;
    let (site, _) = serve(None, Arc::new(|_, _, _, _| ok("still here"))).await;

    let (status, mut tunnel) = connect_via(rig.proxy, "127.0.0.1", site.port()).await;
    assert_eq!(status, "HTTP/1.1 200 OK");

    tokio::time::timeout(WAIT, rig.handle.shutdown())
        .await
        .expect("shutdown does not wait for an idle tunnel to end by itself");

    let mut buf = [0u8; 16];
    let read = tokio::time::timeout(WAIT, tunnel.read(&mut buf))
        .await
        .expect("the tunnel was closed");
    assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
    assert!(
        TcpStream::connect(rig.proxy).await.is_err(),
        "nothing listens on the port any more"
    );
}

#[tokio::test]
async fn request_bodies_and_large_responses_pass_through_intact() {
    let mut rig = rig().await;
    let (site, _) = serve(None, Arc::new(|_, _, _, _| ok(big_body()))).await;
    let client = rig.trusting_client();

    // To Authy: the device's request body arrives, and a large response comes back whole.
    let echoed = client
        .post(format!("https://{AUTHY_HOST}/json/echo"))
        .body("phone_number=synthetic")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(echoed, "POST phone_number=synthetic");
    let big = client
        .get(format!("https://{AUTHY_HOST}/json/big"))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_eq!(big.len(), big_body().len());
    assert!(big == big_body());

    // Plain HTTP: the same, on a connection the proxy opens per request.
    let big = client
        .get(format!("http://{site}/big"))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert!(big == big_body());

    assert_eq!(rig.drain().await, [ProxyEvent::TrustWorking]);
    assert_eq!(rig.handle.backup().tokens.len(), 0);
    rig.handle.shutdown().await;
}

#[tokio::test]
async fn reconnects_when_authy_closes_the_connection() {
    let mut rig = rig().await;
    let client = rig.trusting_client();
    for path in [
        "/json/close",
        "/json/close",
        "/json/users/1/authenticator_tokens",
    ] {
        let res = client
            .get(format!("https://{AUTHY_HOST}{path}"))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200, "{path}");
        assert!(
            !res.headers().contains_key("connection"),
            "Authy's hop-by-hop header is not the device's business"
        );
        res.bytes().await.unwrap();
    }
    rig.wait_for(|e| *e == ProxyEvent::BackupCaptured { count: 3 })
        .await;
    assert_eq!(rig.authy_requests().len(), 3);
    rig.handle.shutdown().await;
}

#[tokio::test]
async fn unreachable_authy_is_a_bad_gateway_not_an_authy_error() {
    // The stand-in's address is a port nobody listens on.
    let closed = {
        let probe = std::net::TcpListener::bind((LOCALHOST, 0)).unwrap();
        probe.local_addr().unwrap()
    };
    let mut rig = rig_with(Some(TestUpstream {
        addr: closed,
        root_cert_der: test_ca("unused").cert_der,
    }))
    .await;
    let res = rig
        .trusting_client()
        .get(format!(
            "https://{AUTHY_HOST}/json/anything?api_key=synthetic"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 502);
    assert_eq!(
        rig.drain().await,
        [ProxyEvent::TrustWorking],
        "the proxy's own 502 did not come from Authy"
    );
    rig.handle.shutdown().await;
}

#[tokio::test]
async fn authy_certificate_is_verified() {
    // A stand-in whose certificate chains to a root the proxy was not told to trust: the proxy
    // must refuse to talk to it rather than hand the device's requests to an impostor.
    let real_root = test_ca("the root the proxy trusts");
    let impostor_root = test_ca("some other root");
    let (config, _) = leaf(&impostor_root, &[AUTHY_HOST]);
    let (impostor, seen) = serve(Some(config), authy_handler()).await;
    let mut rig = rig_with(Some(TestUpstream {
        addr: impostor,
        root_cert_der: real_root.cert_der,
    }))
    .await;
    let res = rig
        .trusting_client()
        .get(format!(
            "https://{AUTHY_HOST}/json/users/1/authenticator_tokens"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 502);
    assert!(
        seen.lock().unwrap().is_empty(),
        "no request reached the impostor"
    );
    assert_eq!(rig.drain().await, [ProxyEvent::TrustWorking]);
    assert_eq!(rig.handle.backup().tokens.len(), 0);
    rig.handle.shutdown().await;
}

#[tokio::test]
async fn dropping_the_handle_stops_the_proxy() {
    let rig = rig().await;
    let proxy = rig.proxy;
    assert!(TcpStream::connect(proxy).await.is_ok());
    drop(rig);
    let mut stopped = false;
    for _ in 0..100 {
        if TcpStream::connect(proxy).await.is_err() {
            stopped = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(stopped, "nothing listens once the handle is gone");
}
