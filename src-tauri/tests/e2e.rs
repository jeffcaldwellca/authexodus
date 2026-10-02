//! The whole flow, minus the real device (Batch 3).
//!
//! A session is driven through the same plain functions the Tauri commands wrap, with:
//!
//! * a stand-in for Authy: a TLS server on loopback whose certificate names `api.authy.com`,
//!   serving a synthetic backup encrypted here with a known password;
//! * a simulated phone: a socket that uses the session's proxy, downloads the certificate the
//!   way a phone does, trusts it and nothing else, and asks Authy for its tokens;
//! * an in-memory key store and a temporary directory.
//!
//! No Tauri runtime, no Keychain, no dialog, no Bitwarden, no network beyond this computer.
//! Every name, secret and password in this file is made up.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use aes::Aes256;
use authexodus_core::ca::{KeyStore, MemoryKeyStore};
use authexodus_core::proxy::{TestUpstream, AUTHY_HOST};
use authexodus_core::totp;
use authexodus_lib::commands::finish_export;
use authexodus_lib::dto::{DestinationDto, ExportOutcome, ProxyEventDto, Step};
use authexodus_lib::network::{Candidate, Network};
use authexodus_lib::session::{EmitProxy, Session, RELEASES_URL};
use base64::Engine;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockEncryptMut, KeyIvInit};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::crypto::aws_lc_rs;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use sha1::Sha1;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use zeroize::Zeroizing;

const WAIT: Duration = Duration::from_secs(10);
const QUIET: Duration = Duration::from_millis(300);

/// The backup password, used exactly as typed: the spaces are part of it.
const PASSWORD: &str = " synthetic backup pässword ";
const PHONE: &str = "192.168.1.57";
/// The same phone after it rejoined the Wi-Fi under a new address.
const PHONE_AGAIN: &str = "192.168.1.99";

// ---------------------------------------------------------------------------------------------
// A synthetic backup, encrypted the way Authy's are

struct Account {
    id: u32,
    name: &'static str,
    issuer: Option<&'static str>,
    logo: Option<&'static str>,
    digits: u32,
    /// What the encrypted seed decrypts to.
    seed: &'static str,
    /// Per-token IV; `None` means the zero IV older tokens use.
    iv: Option<[u8; 16]>,
    rounds: u32,
}

const ACCOUNTS: &[Account] = &[
    Account {
        id: 7001,
        name: "Example Git: octo@example.com",
        issuer: Some("Example Git"),
        logo: None,
        digits: 6,
        seed: "JBSWY3DPEHPK3PXP",
        iv: Some([0x11; 16]),
        // One token with the round count of a real backup.
        rounds: 100_000,
    },
    Account {
        id: 7002,
        name: "Example Mail",
        issuer: None,
        logo: Some("examplemail"),
        digits: 6,
        seed: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        iv: None,
        rounds: 1000,
    },
    Account {
        id: 7003,
        name: "Seven Digit Co",
        issuer: Some("Seven Digit Co"),
        logo: None,
        digits: 7,
        seed: "MFRGGZDFMZTWQ2LKNNWG23TPOBYXE43U",
        iv: Some([0x33; 16]),
        rounds: 1000,
    },
    Account {
        id: 7004,
        name: "Hostile, \"Name\" & Co: a+b@example.com",
        issuer: Some("Hostile, \"Name\" & Co"),
        logo: None,
        digits: 6,
        seed: "ON4W45DIMV2GSYZAORSXG5BANNSXSIBU",
        iv: Some([0x44; 16]),
        rounds: 1000,
    },
    Account {
        id: 7005,
        name: "Broken Entry",
        issuer: None,
        logo: None,
        digits: 6,
        // Decrypts fine, but is not an authenticator key.
        seed: "this is not base32!",
        iv: Some([0x55; 16]),
        rounds: 1000,
    },
];

/// The accounts whose seed is a usable key: the ones that come out as tokens.
fn usable() -> impl Iterator<Item = &'static Account> {
    ACCOUNTS.iter().filter(|a| a.id != 7005)
}

/// PBKDF2-HMAC-SHA1 over the password as typed, then AES-256-CBC with PKCS7, base64.
fn encrypt(account: &Account, salt: &str) -> String {
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha1>(
        PASSWORD.as_bytes(),
        salt.as_bytes(),
        account.rounds,
        &mut key,
    );
    let iv = account.iv.unwrap_or([0u8; 16]);
    let ciphertext = cbc::Encryptor::<Aes256>::new_from_slices(&key, &iv)
        .unwrap()
        .encrypt_padded_vec_mut::<Pkcs7>(account.seed.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(ciphertext)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The `authenticator_tokens` response, in the real response's shape.
fn tokens_body() -> Vec<u8> {
    let tokens: Vec<serde_json::Value> = ACCOUNTS
        .iter()
        .map(|a| {
            let salt = format!("synthetic-salt-{}", a.id);
            serde_json::json!({
                "account_type": "authenticator",
                "digits": a.digits,
                "encrypted_seed": encrypt(a, &salt),
                "issuer": a.issuer,
                "key_derivation_iterations": a.rounds,
                "logo": a.logo,
                "name": a.name,
                "original_name": a.name,
                "password_timestamp": 1_700_000_000,
                "salt": salt,
                "unique_id": a.id,
                "unique_iv": a.iv.map(|iv| hex(&iv)),
            })
        })
        .collect();
    serde_json::to_vec(&serde_json::json!({
        "message": "success", "authenticator_tokens": tokens, "deleted": [], "success": true,
    }))
    .unwrap()
}

const APPS_BODY: &str = r#"{"message":"success","apps":[{"name":"Synthetic Native","digits":7,"secret_seed":"00112233445566778899aabbccddeeff"}],"deleted":[],"success":true}"#;

// ---------------------------------------------------------------------------------------------
// The stand-in for Authy

struct StandIn {
    addr: SocketAddr,
    /// The root that signed the stand-in's certificate: what the proxy is told to trust.
    root_der: Vec<u8>,
}

/// A TLS server whose certificate names `api.authy.com`. It answers one request per
/// connection: the tokens, the native apps, or `{"success":true}`.
async fn stand_in_authy(tokens: Vec<u8>) -> StandIn {
    let mut root = CertificateParams::default();
    root.distinguished_name
        .push(DnType::CommonName, "stand-in upstream CA");
    root.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let root_key = KeyPair::generate().unwrap();
    let root_der = root.self_signed(&root_key).unwrap().der().to_vec();
    let issuer = Issuer::new(root, root_key);

    let mut leaf = CertificateParams::default();
    leaf.distinguished_name.push(DnType::CommonName, AUTHY_HOST);
    leaf.subject_alt_names
        .push(SanType::DnsName(AUTHY_HOST.try_into().unwrap()));
    let leaf_key = KeyPair::generate().unwrap();
    let leaf_der = leaf.signed_by(&leaf_key, &issuer).unwrap().der().to_vec();
    let config = ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(leaf_der)],
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        )
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let tokens = Arc::new(tokens);
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let tokens = Arc::clone(&tokens);
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    let Ok(byte) = tls.read_u8().await else {
                        return;
                    };
                    head.push(byte);
                }
                let head = String::from_utf8_lossy(&head).into_owned();
                let target = head.split_whitespace().nth(1).unwrap_or("/");
                let path = target.split('?').next().unwrap_or("/");
                let body: &[u8] = if path.ends_with("/authenticator_tokens") {
                    &tokens
                } else if path.ends_with("/apps") {
                    APPS_BODY.as_bytes()
                } else {
                    br#"{"success":true}"#
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = tls.write_all(response.as_bytes()).await;
                let _ = tls.write_all(body).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    StandIn { addr, root_der }
}

// ---------------------------------------------------------------------------------------------
// The simulated phone

/// A device that reaches the proxy from `address` (the proxy is told to treat its connections
/// as coming from there; everything really runs on loopback).
struct Phone {
    proxy: SocketAddr,
    upstream: TestUpstream,
    address: IpAddr,
    /// The certificate it installed and trusts, once it has.
    trusted: Option<Vec<u8>>,
}

impl Phone {
    fn new(port: u16, upstream: &TestUpstream, address: &str) -> Phone {
        Phone {
            proxy: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            upstream: upstream.clone(),
            address: address.parse().unwrap(),
            trusted: None,
        }
    }

    async fn connect(&self) -> TcpStream {
        let tcp = TcpStream::connect(self.proxy).await.unwrap();
        self.upstream
            .pretend_peer(tcp.local_addr().unwrap().port(), self.address);
        tcp
    }

    /// Open the certificate address shown as a QR code, follow the page's button to `/cert`,
    /// and install what comes back. Returns the page.
    async fn install_certificate(&mut self, cert_url: &str) -> String {
        let authority = cert_url
            .strip_prefix("http://")
            .and_then(|rest| rest.strip_suffix('/'))
            .expect("the certificate address is plain http");
        assert_eq!(authority, self.proxy.to_string());
        let (head, page) = self.plain_get("/").await;
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        let (head, der) = self.plain_get("/cert").await;
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        assert!(head
            .to_ascii_lowercase()
            .contains("application/x-x509-ca-cert"));
        self.trusted = Some(der);
        String::from_utf8(page).unwrap()
    }

    async fn plain_get(&self, path: &str) -> (String, Vec<u8>) {
        let mut tcp = self.connect().await;
        tcp.write_all(
            format!(
                "GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                self.proxy
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(WAIT, tcp.read_to_end(&mut response))
            .await
            .expect("a response")
            .unwrap();
        split(response)
    }

    /// `CONNECT api.authy.com:443` through the proxy. Returns the status line and the tunnel.
    async fn connect_to_authy(&self) -> (String, TcpStream) {
        let mut tcp = self.connect().await;
        tcp.write_all(
            format!("CONNECT {AUTHY_HOST}:443 HTTP/1.1\r\nHost: {AUTHY_HOST}:443\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(tcp.read_u8().await.unwrap());
        }
        let status = String::from_utf8(head).unwrap();
        (status.lines().next().unwrap().to_owned(), tcp)
    }

    /// An HTTPS request to Authy through the proxy, trusting only the installed certificate.
    async fn authy_get(&self, target: &str) -> (String, Vec<u8>) {
        let (status, tcp) = self.connect_to_authy().await;
        assert_eq!(status, "HTTP/1.1 200 OK");
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(
                self.trusted.clone().expect("a certificate is installed"),
            ))
            .unwrap();
        let config = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut tls = TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from(AUTHY_HOST).unwrap(), tcp)
            .await
            .expect("the phone trusts the session's certificate for Authy");
        tls.write_all(
            format!("GET {target} HTTP/1.1\r\nHost: {AUTHY_HOST}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
        let mut response = Vec::new();
        // A close without close_notify is fine: the bodies are compared by the caller.
        let _ = tokio::time::timeout(WAIT, tls.read_to_end(&mut response))
            .await
            .expect("a response");
        split(response)
    }
}

fn split(response: Vec<u8>) -> (String, Vec<u8>) {
    let at = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("a complete response head");
    (
        String::from_utf8(response[..at].to_vec()).unwrap(),
        response[at + 4..].to_vec(),
    )
}

// ---------------------------------------------------------------------------------------------
// What the UI would hear

struct Events(UnboundedReceiver<ProxyEventDto>);

fn events() -> (EmitProxy, Events) {
    let (tx, rx) = unbounded_channel();
    let emit: EmitProxy = Arc::new(move |event| {
        let _ = tx.send(event);
    });
    (emit, Events(rx))
}

impl Events {
    /// Every event up to and including the first that matches.
    async fn until(&mut self, what: impl Fn(&ProxyEventDto) -> bool) -> Vec<ProxyEventDto> {
        let mut seen = Vec::new();
        loop {
            match tokio::time::timeout(WAIT, self.0.recv()).await {
                Ok(Some(event)) => {
                    let done = what(&event);
                    seen.push(event);
                    if done {
                        return seen;
                    }
                }
                Ok(None) => panic!("the event stream ended; saw {seen:?}"),
                Err(_) => panic!("timed out waiting for an event; saw {seen:?}"),
            }
        }
    }

    /// Whatever arrives during a short quiet period.
    async fn drain(&mut self) -> Vec<ProxyEventDto> {
        let mut seen = Vec::new();
        while let Ok(Some(event)) = tokio::time::timeout(QUIET, self.0.recv()).await {
            seen.push(event);
        }
        seen
    }
}

fn password(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_string())
}

fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// The `secret` parameter of an otpauth URI.
fn secret_of(otpauth: &str) -> &str {
    let query = otpauth.split_once('?').expect("a query").1;
    query
        .split('&')
        .find_map(|pair| pair.strip_prefix("secret="))
        .expect("a secret")
}

// ---------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_whole_flow_with_a_simulated_phone() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("app-data");
    std::fs::create_dir(&data_dir).unwrap();
    let store = Arc::new(MemoryKeyStore::new());
    let session = Session::new(store.clone(), data_dir.clone());

    let expected_body = tokens_body();
    let authy = stand_in_authy(expected_body.clone()).await;
    let upstream = TestUpstream::new(authy.addr, authy.root_der.clone());
    session.tune_proxy(0, Some(upstream.clone()));
    let net = Network {
        candidates: vec![
            Candidate {
                ip: Ipv4Addr::LOCALHOST,
                label: "Test network".into(),
            },
            Candidate {
                ip: Ipv4Addr::UNSPECIFIED,
                label: "Another network".into(),
            },
        ],
        own: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
    };

    // ---- Welcome: a fresh launch.
    let state = session.get_state();
    assert_eq!(state.step, Step::Welcome);
    assert!(!state.resume_cleanup);
    assert_eq!(state.releases_url, RELEASES_URL);
    assert_eq!(store.load().unwrap(), None);

    // ---- Connect: the proxy starts, on the default address.
    let (emit, mut heard) = events();
    let info = session.start_proxy(None, &net, emit.clone()).await.unwrap();
    assert_eq!(info.ip, "127.0.0.1");
    assert_eq!(info.cert_url, format!("http://127.0.0.1:{}/", info.port));
    assert!(info.cert_qr_svg.contains("<svg"));
    assert_eq!(info.addresses.len(), 2);
    assert!(
        store.load().unwrap().is_some(),
        "the certificate key is stored"
    );
    assert!(
        data_dir.join("session.json").exists(),
        "and the marker says so"
    );
    assert_eq!(session.get_state().step, Step::Connect);
    // Asking again changes nothing.
    let again = session
        .start_proxy(Some("127.0.0.1"), &net, emit.clone())
        .await
        .unwrap();
    assert_eq!(again.port, info.port);

    // ---- Certificate: the phone opens the address, downloads and trusts the certificate.
    let mut phone = Phone::new(info.port, &upstream, PHONE);
    let page = phone.install_certificate(&info.cert_url).await;
    assert!(page.contains("Download certificate"));
    assert_eq!(
        heard.until(|e| *e == ProxyEventDto::DeviceConnected).await,
        [ProxyEventDto::DeviceConnected]
    );
    assert_eq!(session.get_state().step, Step::Certificate);

    // ---- Authy: the phone signs in; the backup passes through the proxy.
    let (head, body) = phone
        .authy_get("/json/users/424242/authenticator_tokens?apps=7&api_key=synthetic")
        .await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(
        body, expected_body,
        "the phone gets Authy's answer unchanged"
    );
    assert_eq!(
        heard
            .until(|e| matches!(e, ProxyEventDto::BackupCaptured { .. }))
            .await,
        [
            ProxyEventDto::TrustWorking,
            ProxyEventDto::BackupCaptured {
                count: ACCOUNTS.len()
            }
        ]
    );
    assert_eq!(session.get_state().step, Step::Unlock);
    let (head, _) = phone.authy_get("/json/users/424242/devices/99/apps").await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    // The native apps add no tokens, so the count is unchanged if this is reported at all.
    for event in heard.drain().await {
        assert_eq!(
            event,
            ProxyEventDto::BackupCaptured {
                count: ACCOUNTS.len()
            }
        );
    }

    // The same phone under a new address is refused, and the UI is told.
    let stranger = Phone::new(info.port, &upstream, PHONE_AGAIN);
    let (status, _) = stranger.connect_to_authy().await;
    assert_eq!(status, "HTTP/1.1 403 Forbidden");
    assert_eq!(heard.drain().await, [ProxyEventDto::DeviceRefused]);
    assert_eq!(
        serde_json::to_string(&ProxyEventDto::DeviceRefused).unwrap(),
        r#"{"kind":"deviceRefused"}"#
    );

    // With a backup captured, `start_proxy` will not move to another address...
    let refused = session
        .start_proxy(Some("0.0.0.0"), &net, emit.clone())
        .await;
    assert!(refused.is_err(), "the capture is not silently discarded");
    // ...and is still idempotent for the address it is on.
    let same = session
        .start_proxy(Some("127.0.0.1"), &net, emit.clone())
        .await
        .unwrap();
    assert_eq!(same.port, info.port);

    // ---- Unlock.
    let wrong = session
        .unlock(password(PASSWORD.trim()))
        .await
        .expect("a wrong password is an answer, not a failure");
    assert_eq!(
        serde_json::to_string(&wrong).unwrap(),
        r#"{"error":"wrongPassword"}"#,
        "the password is used exactly as typed: without its spaces it is wrong"
    );
    assert!(session.live_codes().is_err(), "nothing is unlocked yet");

    let summary = session.unlock(password(PASSWORD)).await.unwrap();
    let summary = serde_json::to_value(&summary).unwrap();
    let ids: Vec<&str> = summary["tokens"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["7001", "7002", "7003", "7004"]);
    assert_eq!(summary["tokens"][0]["username"], "octo@example.com");
    assert_eq!(
        summary["invalid"],
        serde_json::json!([{ "name": "Broken Entry", "reason": "notBase32" }])
    );
    assert_eq!(
        summary["native"],
        serde_json::json!([{ "name": "Synthetic Native" }])
    );
    for account in ACCOUNTS {
        assert!(
            !summary.to_string().contains(account.seed),
            "the summary carries no secret"
        );
    }
    assert_eq!(session.get_state().step, Step::Destination);
    let titles: Vec<String> = summary["tokens"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["title"].as_str().unwrap().to_owned())
        .collect();

    // ---- Destination: QR codes, the Google list, and a Bitwarden file.
    assert!(session.token_qr("7001").unwrap().contains("<svg"));
    assert!(
        session.token_qr("7005").is_err(),
        "the broken entry is not a token"
    );
    assert_eq!(
        session.google_unsupported().unwrap(),
        [titles[2].clone()],
        "Google Authenticator cannot take the seven-digit account"
    );
    assert!(!session.google_migration_qrs().unwrap().is_empty());

    let file = session.prepare_export(DestinationDto::Bitwarden).unwrap();
    assert_eq!(file.suggested_name, "authy-bitwarden-import.csv");
    // The person cancels the save dialog...
    assert_eq!(
        serde_json::to_string(&finish_export(&file, None).unwrap()).unwrap(),
        r#"{"cancelled":true}"#
    );
    // ...then picks a place, where a file already is.
    let chosen = dir.path().join(&file.suggested_name);
    std::fs::write(&chosen, b"an older export").unwrap();
    let saved = finish_export(&file, Some(chosen.clone())).unwrap();
    assert_eq!(
        saved,
        ExportOutcome::Saved {
            saved: chosen.to_string_lossy().into_owned()
        }
    );
    assert_eq!(mode(&chosen), 0o600, "readable by its owner only");
    let mut reader = csv::Reader::from_path(&chosen).unwrap();
    let headers = reader.headers().unwrap().clone();
    let column = |name: &str| headers.iter().position(|h| h == name).unwrap();
    let (name_at, totp_at, user_at) = (
        column("name"),
        column("login_totp"),
        column("login_username"),
    );
    let rows: Vec<csv::StringRecord> = reader.records().map(Result::unwrap).collect();
    assert_eq!(rows.len(), usable().count());
    for ((row, account), title) in rows.iter().zip(usable()).zip(&titles) {
        assert_eq!(&row[name_at], title);
        assert!(row[totp_at].starts_with("otpauth://totp/"));
        assert_eq!(secret_of(&row[totp_at]), account.seed, "{}", account.name);
        assert!(row[totp_at].contains(&format!("digits={}", account.digits)));
    }
    assert_eq!(&rows[0][user_at], "octo@example.com");
    assert_eq!(&rows[3][user_at], "a+b@example.com");
    assert_eq!(
        std::fs::read_dir(dir.path()).unwrap().count(),
        2,
        "the app data folder and the export: no temporary file is left"
    );

    // ---- Verify: the live codes are the codes any authenticator would show.
    let instant = 1_760_000_000;
    let codes = session.live_codes_at(instant).unwrap();
    assert_eq!(codes.len(), usable().count());
    for (code, account) in codes.iter().zip(usable()) {
        assert_eq!(code.id, account.id.to_string());
        assert_eq!(
            code.code,
            totp::code(account.seed, account.digits, 30, instant).unwrap(),
            "{}",
            account.name
        );
        assert_eq!(code.code.len(), account.digits as usize);
        assert_eq!(u64::from(code.seconds_left), 30 - instant % 30);
    }
    assert_eq!(session.live_codes().unwrap().len(), codes.len());
    assert_eq!(session.get_state().step, Step::Verify);

    // ---- Start over: the phone came back under a new address.
    let (emit, mut heard) = events();
    let restarted = session.restart_proxy(None, &net, emit).await.unwrap();
    assert_eq!(restarted.ip, "127.0.0.1");
    assert_eq!(session.get_state().step, Step::Connect);
    assert!(
        session.live_codes().is_err(),
        "what was unlocked is discarded"
    );
    assert!(
        session.unlock(password(PASSWORD)).await.is_err(),
        "and so is the captured backup: there is nothing to unlock"
    );
    assert!(session.prepare_export(DestinationDto::Bitwarden).is_err());

    // The certificate is the same one, so the phone does not install anything again, and
    // the address that was refused a moment ago is now accepted as the device.
    let installed = phone.trusted.clone();
    let mut phone = Phone::new(restarted.port, &upstream, PHONE_AGAIN);
    let (head, served) = phone.plain_get("/cert").await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(
        Some(&served),
        installed.as_ref(),
        "the restarted proxy serves the certificate the phone already trusts"
    );
    phone.trusted = installed;
    let (head, body) = phone
        .authy_get("/json/users/424242/authenticator_tokens")
        .await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(body, expected_body);
    let after = heard
        .until(|e| matches!(e, ProxyEventDto::BackupCaptured { .. }))
        .await;
    assert_eq!(
        after,
        [
            ProxyEventDto::DeviceConnected,
            ProxyEventDto::TrustWorking,
            ProxyEventDto::BackupCaptured {
                count: ACCOUNTS.len()
            }
        ]
    );
    let summary = session.unlock(password(PASSWORD)).await.unwrap();
    let summary = serde_json::to_value(&summary).unwrap();
    assert_eq!(summary["tokens"].as_array().unwrap().len(), 4);

    // ---- Clean up.
    session.cleanup().await.unwrap();
    assert_eq!(
        store.load().unwrap(),
        None,
        "the certificate key is destroyed"
    );
    assert!(session.live_codes().is_err(), "the secrets are dropped");
    assert!(session.token_qr("7001").is_err());
    assert!(
        TcpStream::connect((Ipv4Addr::LOCALHOST, restarted.port))
            .await
            .is_err(),
        "nothing is listening any more"
    );
    assert_eq!(session.get_state().step, Step::Cleanup);
    // Until the person has ticked everything off, a new launch comes back to cleanup.
    assert!(data_dir.join("session.json").exists());
    assert!(
        Session::new(store.clone(), data_dir.clone())
            .get_state()
            .resume_cleanup
    );

    // ---- Done.
    session.finish().await.unwrap();
    assert!(
        !data_dir.join("session.json").exists(),
        "the marker is cleared"
    );
    assert_eq!(session.get_state().step, Step::Done);
    let next = Session::new(store.clone(), data_dir.clone());
    assert!(!next.get_state().resume_cleanup);
    assert_eq!(next.get_state().step, Step::Welcome);
    assert_eq!(store.load().unwrap(), None);
}
