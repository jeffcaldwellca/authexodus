//! Proxy server, certificate download page and events (package 1C).
//!
//! # Batch 0 spike result (2026-10-02): `hudsucker` PASSES. Use it.
//!
//! Code: `spikes/proxy/` (throwaway; `cargo run` / `cargo test` there). Crate: `hudsucker`
//! **0.25.0** (features `rcgen-ca`, `rustls-client`, `decoder`; edition 2024, MSRV 1.86),
//! with `rcgen` 0.14.10, `rustls` 0.23 (aws-lc-rs), `hyper` 1.11, `hyper-rustls` 0.27.
//!
//! Proven, with a client that trusts only the spike CA (+ the other site's own CA):
//!
//! * (a) **Intercept.** A CONNECT to the intercepted host (stand-in for `api.authy.com`) is
//!   TLS-terminated with a leaf minted by the spike CA, which was *name-constrained to the DNS
//!   subtree `authy.com`* and re-loaded through `Issuer::from_ca_cert_pem` (so the constraint
//!   survives rcgen's parse/sign round trip); rustls/webpki accepted the chain. The upstream
//!   response body was read in `HttpHandler::handle_response` (`BodyExt::collect`), and handed
//!   back to the client rebuilt with `Body::from(Full<Bytes>)`.
//! * (b) **Blind tunnel for everything else.** hudsucker CAN do this. The decision API is
//!   `HttpHandler::should_intercept_connect(&mut self, &HttpContext, &Request<Body>) -> bool`,
//!   called once per CONNECT with the authority (`req.uri().host()`). Returning `false` makes
//!   hudsucker `TcpStream::connect(authority)` and `tokio::io::copy_bidirectional` the raw
//!   bytes: no TLS termination and no handler callbacks for that connection. The client saw
//!   the other server's own leaf certificate, byte for byte. (There is also
//!   `should_intercept_tls(&ClientHello)` for deciding by SNI after the hello is read; the
//!   CONNECT hook is enough and runs earlier.) Caveat: hudsucker's own `tracing` logs
//!   `error!`/`warn!` lines that name the authority on tunnel failures; 1C must filter or
//!   avoid installing a subscriber that records those, to honour "nothing about
//!   non-intercepted hosts is logged".
//! * (c) **Plain HTTP is forwarded** (absolute-URI request to the proxy -> upstream).
//!
//! Findings 1C should know:
//!
//! * `RcgenAuthority::new(issuer: Issuer<'static, KeyPair>, cache_size, CryptoProvider)`; leaf
//!   certs carry a DNS SAN only (no IP SAN), CN = host, ~1 week validity, ServerAuth EKU.
//! * Upstream connections go through whatever connector is passed to
//!   `with_http_connector`. The spike wrapped `hyper_rustls::HttpsConnectorBuilder::...
//!   .wrap_connector(inner)` around a custom `tower_service::Service<Uri, Response =
//!   TokioIo<TcpStream>>` that dials the stand-in server for `api.authy.com` and the
//!   addressed host otherwise. That is the shape for `TestUpstream`: TLS verification of the
//!   upstream still uses the URI host as server name, so the test upstream's cert needs the
//!   real host name as its SAN and its CA in the connector's root store.
//!   `with_rustls_connector` (default webpki roots) is the production choice; it cannot trust
//!   a test CA, hence the custom connector in tests.
//! * The server side is HTTP/1.1 only unless hudsucker's `http2` feature is enabled; the ALPN
//!   offered to the device is `http/1.1`. NOT verified against Authy's real iOS client (the
//!   spike has no device); if it insists on h2, enable the feature (Batch 4 will tell).
//! * `HttpHandler` methods return `impl Future` (Rust 2024 RPITIT); no `async_trait` needed.
//! * Requests addressed to the proxy itself (the `/` and `/cert` pages) are NOT exercised by
//!   the spike. `handle_request` runs for every non-CONNECT request before forwarding and may
//!   return `RequestOrResponse::Response`, which is the intended hook; 1C confirms it
//!   (`serves_certificate_and_check_page`).
//!
//! The hand-rolled CONNECT fallback in the plan is therefore NOT needed.
