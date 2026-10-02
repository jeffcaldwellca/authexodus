//! THROWAWAY proxy spike. Proves, with hudsucker 0.25, that:
//!   (a) a CONNECT to the intercepted host (api.authy.com) is TLS-intercepted with a leaf
//!       signed by a *name-constrained* CA, and the upstream response body is readable;
//!   (b) a CONNECT to any other host is blind-tunnelled: the client sees that server's own
//!       certificate, not one minted by the proxy;
//!   (c) plain-HTTP requests are forwarded.
//! Nothing here is reused; package 1C reimplements what it needs against core's types.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use hudsucker::{
    certificate_authority::RcgenAuthority,
    hyper::{self, body::Incoming, service::service_fn, Request, Response},
    hyper_util::rt::TokioIo,
    rcgen::{
        BasicConstraints, CertificateParams, DnType, GeneralSubtree, IsCa, Issuer, KeyPair,
        KeyUsagePurpose, NameConstraints, SanType,
    },
    rustls::{
        self,
        crypto::aws_lc_rs,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
        ClientConfig, RootCertStore, ServerConfig,
    },
    Body, HttpContext, HttpHandler, Proxy, RequestOrResponse,
};
use http_body_util::{BodyExt, Full};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

pub const AUTHY_HOST: &str = "api.authy.com";
pub const CHECK_HOST: &str = "authexodus-check.api.authy.com";

type Bytes = hudsucker::hyper::body::Bytes;

/// A self-signed CA plus its PEM, optionally with an `authy.com` DNS name constraint.
struct TestCa {
    key: KeyPair,
    cert_pem: String,
    cert_der: Vec<u8>,
}

fn make_ca(cn: &str, constrain_to: Option<&str>) -> Result<TestCa> {
    let mut p = CertificateParams::new(Vec::<String>::new())?;
    p.distinguished_name.push(DnType::CommonName, cn);
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    if let Some(d) = constrain_to {
        p.name_constraints = Some(NameConstraints {
            permitted_subtrees: vec![GeneralSubtree::DnsName(d.to_string())],
            excluded_subtrees: vec![],
        });
    }
    let key = KeyPair::generate()?;
    let cert = p.self_signed(&key)?;
    Ok(TestCa { cert_pem: cert.pem(), cert_der: cert.der().to_vec(), key })
}

/// Leaf for `names`, signed by `ca`, as a rustls server config.
fn leaf_server_config(ca: &TestCa, names: &[&str]) -> Result<(Arc<ServerConfig>, Vec<u8>)> {
    let issuer = Issuer::from_ca_cert_pem(&ca.cert_pem, KeyPair::from_pem(&ca.key.serialize_pem())?)?;
    let mut p = CertificateParams::new(Vec::<String>::new())?;
    p.distinguished_name.push(DnType::CommonName, names[0]);
    for n in names {
        p.subject_alt_names.push(match n.parse::<std::net::IpAddr>() {
            Ok(ip) => SanType::IpAddress(ip),
            Err(_) => SanType::DnsName((*n).try_into()?),
        });
    }
    let key = KeyPair::generate()?;
    let leaf = p.signed_by(&key, &issuer)?;
    let der = leaf.der().to_vec();
    let cfg = ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(der.clone())],
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )?;
    Ok((Arc::new(cfg), der))
}

/// An HTTPS server answering every request with `body`.
async fn https_server(cfg: Arc<ServerConfig>, body: &'static str) -> Result<SocketAddr> {
    let l = TcpListener::bind("127.0.0.1:0").await?;
    let addr = l.local_addr()?;
    let acceptor = TlsAcceptor::from(cfg);
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = l.accept().await else { return };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else { return };
                let svc = service_fn(move |_r: Request<Incoming>| async move {
                    Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from(body))))
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    Ok(addr)
}

async fn http_server(body: &'static str) -> Result<SocketAddr> {
    let l = TcpListener::bind("127.0.0.1:0").await?;
    let addr = l.local_addr()?;
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = l.accept().await else { return };
            tokio::spawn(async move {
                let svc = service_fn(move |_r: Request<Incoming>| async move {
                    Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from(body))))
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), svc)
                    .await;
            });
        }
    });
    Ok(addr)
}

/// Upstream connector: `api.authy.com` is dialled at the local stand-in server A (this is the
/// shape of core's `TestUpstream`); everything else is dialled as addressed.
#[derive(Clone)]
struct Dial {
    authy_at: SocketAddr,
}

impl tower_service::Service<hyper::Uri> for Dial {
    type Response = TokioIo<TcpStream>;
    type Error = std::io::Error;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    fn poll_ready(&mut self, _: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn call(&mut self, uri: hyper::Uri) -> Self::Future {
        let authy_at = self.authy_at;
        Box::pin(async move {
            let host = uri.host().unwrap_or_default().to_string();
            let tcp = if host == AUTHY_HOST {
                TcpStream::connect(authy_at).await?
            } else {
                let port = uri.port_u16().unwrap_or(80);
                TcpStream::connect((host.as_str(), port)).await?
            };
            Ok(TokioIo::new(tcp))
        })
    }
}

/// The decision API: `HttpHandler::should_intercept_connect` (per CONNECT, by authority).
/// When it returns false hudsucker does `TcpStream::connect(authority)` +
/// `copy_bidirectional` -- a blind tunnel, no TLS termination, nothing inspected.
#[derive(Clone)]
struct Handler {
    captured: Arc<Mutex<Vec<(String, Vec<u8>)>>>,
    intercepted_hosts: Arc<Mutex<Vec<String>>>,
}

impl HttpHandler for Handler {
    async fn should_intercept_connect(&mut self, _ctx: &HttpContext, req: &Request<Body>) -> bool {
        let host = req.uri().host().unwrap_or_default();
        let yes = host == AUTHY_HOST || host == CHECK_HOST;
        if yes {
            self.intercepted_hosts.lock().unwrap().push(host.to_string());
        }
        yes
    }

    async fn handle_request(&mut self, _ctx: &HttpContext, req: Request<Body>) -> RequestOrResponse {
        req.into()
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<hudsucker::Body> {
        let (parts, body) = res.into_parts();
        let bytes = body.collect().await.map(|c| c.to_bytes()).unwrap_or_default();
        self.captured.lock().unwrap().push(("response".into(), bytes.to_vec()));
        Response::from_parts(parts, Body::from(Full::new(bytes)))
    }
}

#[derive(Debug)]
pub struct Report {
    pub hudsucker: &'static str,
    pub a_body: String,
    pub a_peer_cert_issued_by_spike_ca: bool,
    pub a_captured_by_proxy: bool,
    pub b_body: String,
    pub b_peer_cert_is_servers_own: bool,
    pub b_was_not_intercepted: bool,
    pub c_body: String,
}

pub async fn run() -> Result<Report> {
    // CAs: the spike CA is name-constrained to authy.com, like the real one will be.
    let spike_ca = make_ca("spike CA (remove after use)", Some("authy.com"))?;
    let upstream_ca = make_ca("stand-in upstream CA", None)?;
    let b_ca = make_ca("other-site CA", None)?;

    // A: stand-in for Authy. B: stand-in for any other site. C: plain HTTP.
    let (a_cfg, _) = leaf_server_config(&upstream_ca, &[AUTHY_HOST])?;
    let a = https_server(a_cfg, r#"{"authenticator_tokens":["from A"]}"#).await?;
    let (b_cfg, b_leaf_der) = leaf_server_config(&b_ca, &["localhost", "127.0.0.1"])?;
    let b = https_server(b_cfg, "from B").await?;
    let c = http_server("from C").await?;

    // Proxy. Its upstream TLS client trusts only the stand-in upstream CA.
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(upstream_ca.cert_der.clone()))?;
    let up_cfg = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = hyper_rustls_connector(up_cfg, Dial { authy_at: a });

    let proxy_ca = RcgenAuthority::new(
        Issuer::from_ca_cert_pem(&spike_ca.cert_pem, KeyPair::from_pem(&spike_ca.key.serialize_pem())?)?,
        100,
        aws_lc_rs::default_provider(),
    );
    let handler = Handler { captured: Default::default(), intercepted_hosts: Default::default() };
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let proxy_addr = listener.local_addr()?;
    let proxy = Proxy::builder()
        .with_listener(listener)
        .with_ca(proxy_ca)
        .with_http_connector(connector)
        .with_http_handler(handler.clone())
        .build()?;
    tokio::spawn(async move {
        let _ = proxy.start().await;
    });

    // Client trusts ONLY the spike CA and B's own CA.
    let client = reqwest::Client::builder()
        .no_proxy()
        .proxy(reqwest::Proxy::all(format!("http://{proxy_addr}"))?)
        .tls_certs_only([
            reqwest::Certificate::from_pem(spike_ca.cert_pem.as_bytes())?,
            reqwest::Certificate::from_pem(b_ca.cert_pem.as_bytes())?,
        ])
        .build()?;

    // (a) intercepted: reqwest gets the body; a raw CONNECT+TLS probe shows who signed the cert.
    let r = client.get(format!("https://{AUTHY_HOST}/json/ios/authenticator_tokens")).send().await.context("a")?;
    let a_body = r.text().await?;
    let roots = [spike_ca.cert_der.clone(), b_ca.cert_der.clone()];
    let a_peer = peer_cert_via_proxy(proxy_addr, AUTHY_HOST, AUTHY_HOST, 443, &roots).await.context("a probe")?;
    let a_issued_by_spike = contains(&a_peer, b"spike CA");

    // (b) tunnelled: the cert the client sees is B's own leaf, byte for byte.
    let r = client.get(format!("https://localhost:{}/x", b.port())).send().await.context("b")?;
    let b_body = r.text().await?;
    let b_peer = peer_cert_via_proxy(proxy_addr, "localhost", "localhost", b.port(), &roots).await.context("b probe")?;

    // (c) plain http
    let c_body = client.get(format!("http://127.0.0.1:{}/plain", c.port())).send().await.context("c")?.text().await?;

    let captured = handler.captured.lock().unwrap().clone();
    let hosts = handler.intercepted_hosts.lock().unwrap().clone();
    Ok(Report {
        hudsucker: "0.25.0",
        a_body,
        a_peer_cert_issued_by_spike_ca: a_issued_by_spike,
        a_captured_by_proxy: captured.iter().any(|(_, b)| b.starts_with(b"{\"authenticator_tokens\"")),
        b_body,
        b_peer_cert_is_servers_own: b_peer == b_leaf_der,
        b_was_not_intercepted: !hosts.iter().any(|h| h == "localhost"),
        c_body,
    })
    .and_then(|r| {
        if r.a_body.contains("from A")
            && r.a_peer_cert_issued_by_spike_ca
            && r.a_captured_by_proxy
            && r.b_body == "from B"
            && r.b_peer_cert_is_servers_own
            && r.b_was_not_intercepted
            && r.c_body == "from C"
        {
            Ok(r)
        } else {
            Err(anyhow!("spike failed: {r:?}"))
        }
    })
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn hyper_rustls_connector<C>(cfg: ClientConfig, inner: C) -> impl hudsucker::hyper_util::client::legacy::connect::Connect + Clone
where
    C: tower_service::Service<hyper::Uri, Response = TokioIo<TcpStream>, Error = std::io::Error> + Clone + Send + Sync + 'static,
    C::Future: Send + 'static,
{
    hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(cfg)
        .https_or_http()
        .enable_http1()
        .wrap_connector(inner)
}

#[allow(dead_code)]
fn _assert_rustls_is_used(_: &rustls::ClientConfig) {}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn spike_proves_intercept_tunnel_and_plain_http() {
        let report = super::run().await.expect("spike");
        println!("{report:#?}");
    }
}

/// Raw client: CONNECT through the proxy, TLS handshake trusting only `roots`, return the leaf
/// the peer presented. `connect_port` is what the CONNECT names (443 for the intercepted host).
async fn peer_cert_via_proxy(
    proxy: SocketAddr,
    connect_host: &str,
    sni: &str,
    connect_port: u16,
    roots: &[Vec<u8>],
) -> Result<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut tcp = TcpStream::connect(proxy).await?;
    tcp.write_all(format!("CONNECT {connect_host}:{connect_port} HTTP/1.1\r\nHost: {connect_host}:{connect_port}\r\n\r\n").as_bytes()).await?;
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(tcp.read_u8().await?);
    }
    anyhow::ensure!(head.starts_with(b"HTTP/1.1 200"), "CONNECT refused");
    let mut store = RootCertStore::empty();
    for r in roots {
        store.add(CertificateDer::from(r.clone()))?;
    }
    let cfg = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(store)
        .with_no_client_auth();
    let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(sni.to_string().try_into()?, tcp)
        .await
        .context("tls handshake")?;
    let peer = tls.get_ref().1.peer_certificates().ok_or_else(|| anyhow!("no peer certs"))?[0].to_vec();
    Ok(peer)
}
