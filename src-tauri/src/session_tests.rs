//! Tests of `session.rs`: a fake Bitwarden client, a temporary directory and loopback. Nothing
//! here touches a real Bitwarden or the network beyond this computer. All data is synthetic.

use super::*;
use crate::awake::{KeepAwake, KeepAwakeCommand};
use crate::errors::ErrorCode;
use async_trait::async_trait;
use authexodus_core::bitwarden::{BwError, Region, SetTotp, VaultLogin};
use authexodus_core::types::{EncryptedToken, Secret, Token};
use std::sync::atomic::AtomicUsize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Notify;

fn session(dir: &Path) -> Session {
    Session::new(dir.to_path_buf())
}

fn candidate(ip: Ipv4Addr, label: &str) -> Candidate {
    Candidate {
        ip,
        label: label.into(),
    }
}

/// A computer whose only address is loopback.
fn loopback() -> Network {
    Network {
        candidates: vec![candidate(Ipv4Addr::LOCALHOST, "Test")],
        own: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
    }
}

/// Loopback, plus "every address" as a second one to move the proxy to (macOS has no second
/// loopback address).
fn two_addresses() -> Network {
    let mut net = loopback();
    net.candidates
        .push(candidate(Ipv4Addr::UNSPECIFIED, "Other"));
    net
}

fn no_emit() -> EmitProxy {
    Arc::new(|_| {})
}

fn password(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_string())
}

/// One token, "JBSWY3DPEHPK3PXP", encrypted with password "hunter2" (PBKDF2-SHA1, 1000
/// rounds, salt "saltsalt", zero IV, AES-256-CBC) outside this codebase with Python and
/// OpenSSL, so the test does not lean on the core's own encryption.
fn fixture_backup() -> CapturedBackup {
    CapturedBackup {
        tokens: vec![EncryptedToken {
            unique_id: "1".into(),
            name: "Example: jeff@example.com".into(),
            issuer: Some("Example".into()),
            logo: None,
            account_type: "authenticator".into(),
            digits: 6,
            encrypted_seed: "0iR0u266eu94XfqUtL8TzqoH44rbZbtn6tSYELbShRY=".into(),
            salt: "saltsalt".into(),
            unique_iv: None,
            key_derivation_iterations: 1000,
        }],
        native_apps: vec![],
    }
}

fn token(id: &str, title: &str, digits: u32) -> Token {
    Token {
        id: id.into(),
        title: title.into(),
        name: title.into(),
        issuer: None,
        username: None,
        secret: Secret::new("JBSWY3DPEHPK3PXP".into()),
        digits,
        period: 30,
    }
}

fn unlocked_one() -> Unlocked {
    Unlocked {
        tokens: vec![token("1", "Example", 6)],
        invalid: vec![],
        native: vec![],
    }
}

async fn connect_status(port: u16, target: &str) -> String {
    let mut tcp = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    tcp.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(tcp.read_u8().await.unwrap());
    }
    String::from_utf8(head)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .to_owned()
}

// ---------------------------------------------------------------------------------------------
// The resume marker and the certificate key (S6)

#[tokio::test]
async fn marker_makes_next_launch_resume_cleanup() {
    let dir = tempfile::tempdir().unwrap();
    let first = session(dir.path());
    assert!(!first.get_state(&loopback()).resume_cleanup);
    assert_eq!(first.get_state(&loopback()).step, Step::Welcome);

    first.ensure_ca().await.unwrap();
    assert_eq!(
        std::fs::read_to_string(dir.path().join("session.json")).unwrap(),
        r#"{"caCreated":true}"#
    );
    drop(first); // the app quits without cleaning up

    let second = session(dir.path());
    let state = second.get_state(&loopback());
    assert!(state.resume_cleanup);
    assert_eq!(state.step, Step::Cleanup);
}

/// Every file under `dir`, with what it holds.
fn files_under(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            found.extend(files_under(&path));
        } else {
            let bytes = std::fs::read(&path).unwrap();
            found.push((path, bytes));
        }
    }
    found
}

#[tokio::test]
async fn the_certificate_key_lives_in_memory_only() {
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path());
    s.tune_proxy(0, None);
    s.start_proxy(Some("127.0.0.1"), &loopback(), no_emit())
        .await
        .unwrap();
    let certificate = s.ensure_ca().await.unwrap().cert_der();

    // On disk there is the marker and nothing else, and it says only that a run began: not
    // the certificate, and no key.
    let files = files_under(dir.path());
    assert_eq!(files.len(), 1, "{files:?}");
    assert_eq!(files[0].0, dir.path().join("session.json"));
    assert_eq!(files[0].1, br#"{"caCreated":true}"#);
    assert!(!files[0]
        .1
        .windows(certificate.len())
        .any(|w| w == certificate.as_slice()));
    s.cleanup().await.unwrap();
}

#[tokio::test]
async fn a_marker_that_cannot_be_written_means_no_key_is_made() {
    let dir = tempfile::tempdir().unwrap();
    // Something that is not a file sits where the marker goes.
    std::fs::create_dir(dir.path().join("session.json")).unwrap();
    let s = session(dir.path());
    assert!(s.ensure_ca().await.is_err());
    assert!(lock(&s.authority).is_none());
}

#[tokio::test]
async fn a_root_that_cannot_be_made_is_refused_and_takes_back_only_its_own_marker() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("session.json");
    let s = session(dir.path());
    s.fail_ca.store(true, Ordering::SeqCst);

    let error = s.ensure_ca().await.err().expect("no certificate authority");
    assert_eq!(error, CmdError(Reject::CaNotCreated));
    assert_eq!(error.code(), ErrorCode::Internal);
    assert!(error.to_string().starts_with("internal: "), "{error}");
    assert!(
        !error.to_string().contains("refused by the test"),
        "what went wrong in detail is for the log: {error}"
    );
    assert!(lock(&s.authority).is_none());
    assert!(
        !marker.exists(),
        "no marker claims a certificate that was never made"
    );
    assert!(!session(dir.path()).get_state(&loopback()).resume_cleanup);
}

#[tokio::test]
async fn a_root_that_cannot_be_made_on_a_resumed_launch_keeps_the_earlier_marker() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("session.json");
    session(dir.path()).ensure_ca().await.unwrap(); // a launch that quit mid-run
    assert!(marker.exists());

    let resumed = session(dir.path());
    assert!(resumed.get_state(&loopback()).resume_cleanup);
    resumed.fail_ca.store(true, Ordering::SeqCst);
    assert_eq!(
        resumed.ensure_ca().await.err(),
        Some(CmdError(Reject::CaNotCreated))
    );
    assert!(
        marker.exists(),
        "the earlier run's certificate may still be on a device: cleanup stays due"
    );
    assert!(session(dir.path()).get_state(&loopback()).resume_cleanup);
}

#[tokio::test]
async fn finish_clears_the_marker_for_the_next_launch() {
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path());
    s.ensure_ca().await.unwrap();
    s.cleanup().await.unwrap();
    s.finish().await.unwrap();
    assert!(!s.get_state(&loopback()).resume_cleanup);
    assert!(!dir.path().join("session.json").exists());
    assert!(!session(dir.path()).get_state(&loopback()).resume_cleanup);
}

#[tokio::test]
async fn finish_without_cleanup_still_drops_the_key() {
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path());
    s.ensure_ca().await.unwrap();
    let authority = held_authority(&s);
    s.finish().await.unwrap();
    assert!(authority.upgrade().is_none());
}

#[test]
fn state_carries_the_releases_address() {
    assert_eq!(
        RELEASES_URL,
        "https://github.com/jeffcaldwellca/authexodus/releases"
    );
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path());
    let json = serde_json::to_value(s.get_state(&loopback())).unwrap();
    assert_eq!(json["releasesUrl"], RELEASES_URL);
    assert_eq!(json["version"], env!("CARGO_PKG_VERSION"));
}

// ---------------------------------------------------------------------------------------------
// A fake Bitwarden

#[derive(Clone)]
struct FakeBw {
    wiped: Arc<AtomicBool>,
    outcome: LoginOutcome,
    vault: Vec<VaultLogin>,
    /// Every write asked of the vault, as `attach <item>` or `create <title>`.
    writes: Arc<Mutex<Vec<String>>>,
    /// When set: `login` says it has begun, then waits to be let go.
    entered: Option<Arc<Notify>>,
    release: Option<Arc<Notify>>,
    /// When set, `login` fails with this instead of answering `outcome`.
    error: Option<BwError>,
    /// How many times `login` was called.
    logins: Arc<AtomicUsize>,
    /// The two-step code of the last `login`, if one was sent.
    code_sent: Arc<Mutex<Option<String>>>,
    /// The API key of the last `login_with_api_key`, and the password that came with it.
    api_key_sent: Arc<Mutex<Option<(String, String, String)>>>,
    /// When set, the session has ended: every call after sign-in says so.
    expired: Arc<AtomicBool>,
}

fn login(id: &str, name: &str, has_totp: bool) -> VaultLogin {
    VaultLogin {
        id: id.into(),
        name: name.into(),
        username: None,
        hosts: vec![format!("{}.com", name.to_lowercase())],
        has_totp,
        code: None,
    }
}

impl FakeBw {
    fn new() -> FakeBw {
        FakeBw {
            wiped: Arc::default(),
            outcome: LoginOutcome::Ok,
            vault: vec![login("item-1", "Example", false)],
            writes: Arc::default(),
            entered: None,
            release: None,
            error: None,
            logins: Arc::default(),
            code_sent: Arc::default(),
            api_key_sent: Arc::default(),
            expired: Arc::default(),
        }
    }

    /// A sign-in that waits inside `login` until the returned handle is notified. The first
    /// handle is notified when `login` has begun.
    fn held(mut self) -> (FakeBw, Arc<Notify>, Arc<Notify>) {
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        self.entered = Some(entered.clone());
        self.release = Some(release.clone());
        (self, entered, release)
    }

    fn was_wiped(&self) -> bool {
        self.wiped.load(Ordering::SeqCst)
    }

    /// What every call after sign-in answers: an ended session, when that is set.
    fn alive(&self) -> Result<(), BwError> {
        if self.expired.load(Ordering::SeqCst) {
            return Err(BwError::SessionExpired);
        }
        Ok(())
    }

    async fn answer(&self) -> Result<LoginOutcome, BwError> {
        self.logins.fetch_add(1, Ordering::SeqCst);
        if let (Some(entered), Some(release)) = (&self.entered, &self.release) {
            entered.notify_one();
            release.notified().await;
        }
        match &self.error {
            Some(error) => Err(error.clone()),
            None => Ok(self.outcome),
        }
    }
}

#[async_trait]
impl BwClient for FakeBw {
    async fn login(
        &mut self,
        _: &str,
        _: &str,
        _: &Region,
        code: Option<&str>,
    ) -> Result<LoginOutcome, BwError> {
        *lock(&self.code_sent) = code.map(str::to_owned);
        self.answer().await
    }
    async fn login_with_api_key(
        &mut self,
        client_id: &str,
        client_secret: &str,
        password: &str,
        _: &Region,
    ) -> Result<LoginOutcome, BwError> {
        *lock(&self.api_key_sent) = Some((
            client_id.to_owned(),
            client_secret.to_owned(),
            password.to_owned(),
        ));
        self.answer().await
    }
    async fn sync(&self) -> Result<(), BwError> {
        self.alive()
    }
    async fn list_logins(&self) -> Result<Vec<VaultLogin>, BwError> {
        self.alive()?;
        Ok(self.vault.clone())
    }
    async fn import_folder_titles(&self) -> Result<Vec<String>, BwError> {
        self.alive()?;
        Ok(vec![])
    }
    async fn set_totp(&self, item: &str, _: &str) -> Result<SetTotp, BwError> {
        self.alive()?;
        lock(&self.writes).push(format!("attach {item}"));
        Ok(SetTotp::Attached)
    }
    async fn create_in_import_folder(
        &self,
        title: &str,
        _: Option<&str>,
        _: &str,
    ) -> Result<(), BwError> {
        self.alive()?;
        lock(&self.writes).push(format!("create {title}"));
        Ok(())
    }
    async fn logout_and_wipe(&mut self) -> Result<(), BwError> {
        self.wiped.store(true, Ordering::SeqCst);
        Ok(())
    }
}

fn login_input() -> BwLoginInput {
    serde_json::from_str(r#"{"email":"a@example.com","password":"pw","region":{"kind":"us"}}"#)
        .unwrap()
}

fn no_progress() -> EmitProgress {
    Arc::new(|_| {})
}

// ---------------------------------------------------------------------------------------------
// Cleanup, and closing the app (S7)

#[tokio::test]
async fn cleanup_drops_the_key_and_the_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path());
    s.tune_proxy(0, None);

    s.start_proxy(Some("127.0.0.1"), &loopback(), no_emit())
        .await
        .unwrap();
    let authority = held_authority(&s);
    *lock(&s.unlocked) = Some(Arc::new(unlocked_one()));
    let bw = FakeBw::new();
    let result = s
        .bw_login(Box::new(bw.clone()), login_input())
        .await
        .unwrap();
    assert_eq!(result, BwLoginResult::Ok);
    s.bw_propose().await.unwrap();
    std::fs::create_dir_all(dir.path().join("bw-data")).unwrap();

    s.cleanup().await.unwrap();

    assert!(
        authority.upgrade().is_none(),
        "the certificate authority, and its key, are gone"
    );
    assert!(s.proxy.lock().await.is_none(), "the proxy is stopped");
    assert!(lock(&s.unlocked).is_none(), "secrets are dropped");
    assert!(lock(&s.proposals).is_none());
    assert!(
        s.bw.lock().await.is_none(),
        "the Bitwarden client is dropped"
    );
    assert!(bw.was_wiped(), "the Bitwarden session was wiped");
    assert!(!dir.path().join("bw-data").exists());
    assert!(s.live_codes().is_err());

    // Running it again is fine.
    s.cleanup().await.unwrap();
}

#[tokio::test]
async fn cleanup_on_fresh_launch_with_only_the_marker() {
    let dir = tempfile::tempdir().unwrap();
    {
        let earlier = session(dir.path());
        earlier.ensure_ca().await.unwrap();
    }

    let fresh = session(dir.path());
    assert!(fresh.get_state(&loopback()).resume_cleanup);
    assert!(
        lock(&fresh.authority).is_none(),
        "the earlier launch's key went with it"
    );
    // Bitwarden data that turns up with no client to wipe it.
    std::fs::create_dir_all(dir.path().join("bw-data")).unwrap();
    std::fs::write(dir.path().join("bw-data").join("data.json"), b"{}").unwrap();
    fresh.cleanup().await.unwrap();
    fresh.finish().await.unwrap();

    assert!(
        lock(&fresh.authority).is_none(),
        "no key was made to clean up"
    );
    assert!(!dir.path().join("bw-data").exists());
    assert!(!dir.path().join("session.json").exists());
}

#[test]
fn a_launch_removes_bitwarden_data_an_earlier_one_left() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("bw-data")).unwrap();
    std::fs::write(dir.path().join("bw-data").join("data.json"), b"{}").unwrap();
    let _s = session(dir.path());
    assert!(!dir.path().join("bw-data").exists());
}

#[tokio::test]
async fn closing_the_app_mid_flow_stops_the_proxy_and_keeps_the_marker_for_cleanup() {
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path());
    s.tune_proxy(0, None);
    let info = s
        .start_proxy(Some("127.0.0.1"), &loopback(), no_emit())
        .await
        .unwrap();
    *lock(&s.unlocked) = Some(Arc::new(unlocked_one()));
    let bw = FakeBw::new();
    s.bw_login(Box::new(bw.clone()), login_input())
        .await
        .unwrap();
    std::fs::create_dir_all(dir.path().join("bw-data")).unwrap();
    std::fs::write(dir.path().join("bw-data").join("data.json"), b"{}").unwrap();
    assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, info.port))
        .await
        .is_ok());

    // Not async: the exit hook cannot wait.
    s.on_exit();

    assert!(s.proxy.lock().await.is_none());
    assert!(s.bw.lock().await.is_none());
    assert!(lock(&s.unlocked).is_none());
    assert!(
        !dir.path().join("bw-data").exists(),
        "the Bitwarden folder is gone"
    );
    let mut stopped = false;
    for _ in 0..100 {
        if TcpStream::connect((Ipv4Addr::LOCALHOST, info.port))
            .await
            .is_err()
        {
            stopped = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(stopped, "nothing is listening any more");

    // The marker stays: the next launch opens on cleanup, so that the person removes the
    // profile and turns the proxy off, and finishes the job without the key.
    assert!(lock(&s.authority).is_none(), "the key is dropped");
    assert!(dir.path().join("session.json").exists());
    s.on_exit(); // twice is fine
    drop(s);
    let next = session(dir.path());
    assert!(next.get_state(&loopback()).resume_cleanup);
    assert_eq!(next.get_state(&loopback()).step, Step::Cleanup);
    next.cleanup().await.unwrap();
    next.finish().await.unwrap();
    assert!(!dir.path().join("session.json").exists());
    assert!(!next.get_state(&loopback()).resume_cleanup);
}

/// A handle on the certificate authority the session holds, that does not keep it alive: once
/// nothing else holds it either, it has been dropped (and its key wiped).
fn held_authority(s: &Session) -> std::sync::Weak<Authority> {
    Arc::downgrade(
        lock(&s.authority)
            .as_ref()
            .expect("a certificate authority"),
    )
}

#[tokio::test]
async fn closing_the_app_drops_the_certificate_key_from_memory() {
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path());
    s.tune_proxy(0, None);
    s.start_proxy(Some("127.0.0.1"), &loopback(), no_emit())
        .await
        .unwrap();
    let authority = held_authority(&s);

    s.on_exit();

    assert!(
        authority.upgrade().is_none(),
        "nothing holds the certificate authority once the app is closing"
    );
    assert!(
        dir.path().join("session.json").exists(),
        "the marker stays, so the next launch opens on cleanup"
    );
}

// ---------------------------------------------------------------------------------------------
// Starting, moving and restarting the proxy (C1, C2, S10)

#[tokio::test]
async fn start_proxy_is_idempotent_and_moves_only_while_nothing_is_captured() {
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path());
    s.tune_proxy(0, None);
    let net = two_addresses();

    let first = s
        .start_proxy(Some("127.0.0.1"), &net, no_emit())
        .await
        .unwrap();
    assert_ne!(first.port, 0);
    assert_eq!(first.cert_url, format!("http://127.0.0.1:{}/", first.port));
    assert_eq!(first.check_url, "https://authexodus-check.api.authy.com/");
    assert!(first.cert_qr_svg.starts_with("<?xml") || first.cert_qr_svg.contains("<svg"));
    assert_eq!(first.addresses.len(), 2);
    assert_eq!(s.get_state(&loopback()).step, Step::Connect);

    // The same address, or no address at all: the running proxy, untouched.
    for again in [Some("127.0.0.1"), None, Some("  ")] {
        let again = s.start_proxy(again, &net, no_emit()).await.unwrap();
        assert_eq!((again.ip.as_str(), again.port), ("127.0.0.1", first.port));
    }

    // Not one of this computer's addresses, or not an address: an error, and nothing moves.
    assert!(s
        .start_proxy(Some("8.8.8.8"), &net, no_emit())
        .await
        .is_err());
    assert!(s
        .start_proxy(Some("nonsense"), &net, no_emit())
        .await
        .is_err());
    assert_eq!(
        s.start_proxy(None, &net, no_emit()).await.unwrap().port,
        first.port
    );

    // A different address before anything is captured: the proxy moves there.
    let moved = s
        .start_proxy(Some("0.0.0.0"), &net, no_emit())
        .await
        .unwrap();
    assert_eq!(moved.ip, "0.0.0.0");
    let back = s
        .start_proxy(Some("127.0.0.1"), &net, no_emit())
        .await
        .unwrap();
    assert_eq!(back.ip, "127.0.0.1");

    // Once there is something to lose, a different address is refused and nothing is lost.
    *lock(&s.unlocked) = Some(Arc::new(unlocked_one()));
    let refused = s
        .start_proxy(Some("0.0.0.0"), &net, no_emit())
        .await
        .unwrap_err();
    assert_eq!(refused, CmdError(Reject::CaptureWouldBeLost));
    assert!(refused.to_string().starts_with("capture_would_be_lost: "));
    assert!(refused.sentence().contains("starting over"), "{refused}");
    assert!(lock(&s.unlocked).is_some(), "what was unlocked is kept");
    let still = s.start_proxy(None, &net, no_emit()).await.unwrap();
    assert_eq!((still.ip.as_str(), still.port), ("127.0.0.1", back.port));
    s.cleanup().await.unwrap();
}

#[tokio::test]
async fn restart_proxy_starts_over_with_the_same_certificate() {
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path());
    s.tune_proxy(0, None);
    let net = two_addresses();

    // Restarting with nothing running simply starts.
    let first = s
        .restart_proxy(Some("127.0.0.1"), &net, no_emit())
        .await
        .unwrap();
    assert_eq!(first.ip, "127.0.0.1");
    let certificate = s.ensure_ca().await.unwrap().cert_der();
    let authority = held_authority(&s);

    *lock(&s.unlocked) = Some(Arc::new(unlocked_one()));
    s.bw_login(Box::new(FakeBw::new()), login_input())
        .await
        .unwrap();
    s.bw_propose().await.unwrap();
    s.live_codes().unwrap();
    assert_eq!(s.get_state(&loopback()).step, Step::Destination);

    // An address that cannot be used is refused before anything is thrown away.
    assert!(s
        .restart_proxy(Some("8.8.8.8"), &net, no_emit())
        .await
        .is_err());
    assert!(lock(&s.unlocked).is_some());

    // Unlike `start_proxy`, this goes ahead with something unlocked, on another address too.
    let again = s
        .restart_proxy(Some("0.0.0.0"), &net, no_emit())
        .await
        .unwrap();
    assert_eq!(again.ip, "0.0.0.0");
    assert!(lock(&s.unlocked).is_none(), "what was unlocked is gone");
    assert!(lock(&s.proposals).is_none());
    assert!(s.live_codes().is_err());
    assert_eq!(
        s.get_state(&loopback()).step,
        Step::Connect,
        "back to connecting"
    );
    assert_eq!(
        s.ensure_ca().await.unwrap().cert_der(),
        certificate,
        "the device keeps the certificate it installed"
    );
    assert!(
        Arc::ptr_eq(&authority.upgrade().unwrap(), &s.ensure_ca().await.unwrap()),
        "the same authority, key and all"
    );
    // A fresh proxy holds no backup.
    assert!(s.unlock(password("hunter2")).await.is_err());

    // And once more on the same address: a new proxy there, still listening.
    let third = s.restart_proxy(Some("0.0.0.0"), &net, no_emit()).await;
    let third = third.unwrap();
    assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, third.port))
        .await
        .is_ok());
    s.cleanup().await.unwrap();
}

#[tokio::test]
async fn the_proxy_is_told_every_address_of_this_computer() {
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path());
    // No test upstream: the production destination rules apply.
    s.tune_proxy(0, None);
    let mut net = loopback();
    // Public addresses (documentation ranges) on some other interface of this computer: the
    // proxy cannot know they are its own unless it is told.
    net.own.push("203.0.113.7".parse().unwrap());
    net.own.push("2001:db8:1:2::109".parse().unwrap());

    let info = s
        .start_proxy(Some("127.0.0.1"), &net, no_emit())
        .await
        .unwrap();
    for target in ["203.0.113.7:5432", "[2001:db8:1:2::109]:5432"] {
        assert_eq!(
            connect_status(info.port, target).await,
            "HTTP/1.1 403 Forbidden",
            "{target}"
        );
    }

    // A restarted proxy is told again.
    let info = s.restart_proxy(None, &net, no_emit()).await.unwrap();
    assert_eq!(
        connect_status(info.port, "203.0.113.7:5432").await,
        "HTTP/1.1 403 Forbidden"
    );
    s.cleanup().await.unwrap();
}

// ---------------------------------------------------------------------------------------------
// Unlocking (S2, S9)

#[tokio::test]
async fn unlock_command_maps_wrong_password_to_error_variant() {
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path());
    let result = s
        .unlock_backup(fixture_backup(), password("not the password"))
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_string(&result).unwrap(),
        r#"{"error":"wrongPassword"}"#
    );
    assert!(
        s.unlocked().is_err(),
        "nothing is kept after a wrong password"
    );
}

#[tokio::test]
async fn unlock_with_the_right_password_returns_the_summary_and_keeps_secrets_in_memory() {
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path());
    let result = s
        .unlock_backup(fixture_backup(), password("hunter2"))
        .await
        .unwrap();
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["tokens"][0]["id"], "1");
    assert_eq!(json["tokens"][0]["username"], "jeff@example.com");
    assert_eq!(json["invalid"], serde_json::json!([]));
    assert_eq!(json["native"], serde_json::json!([]));
    assert!(!json.to_string().contains("JBSWY3DPEHPK3PXP"));
    assert_eq!(s.get_state(&loopback()).step, Step::Destination);

    assert!(s.token_qr("1").unwrap().contains("<svg"));
    assert!(s.token_qr("nope").is_err());
    assert_eq!(s.get_state(&loopback()).step, Step::Destination);

    // Asking for the live codes does not move the step: the shell cannot tell the Verify
    // screen from the Destination one, and does not pretend to.
    let codes = s.live_codes().unwrap();
    assert_eq!(codes.len(), 1);
    assert_eq!(codes[0].code.len(), 6);
    assert_eq!(s.get_state(&loopback()).step, Step::Destination);
}

#[tokio::test]
async fn unlock_before_any_backup_is_an_error_not_a_wrong_password() {
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path());
    assert!(s
        .unlock_backup(CapturedBackup::default(), password("x"))
        .await
        .is_err());
    assert!(s.unlock(password("x")).await.is_err(), "no proxy running");
}

/// One thread runs everything here. If the key derivation ran on it, nothing else could run
/// until it was done.
#[tokio::test(flavor = "current_thread")]
async fn unlocking_does_not_hold_up_the_rest_of_the_app() {
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path());
    // The round count of a real backup. (The fixture was encrypted with 1000, so this is a
    // "wrong password"; the work is the same.)
    let mut backup = fixture_backup();
    backup.tokens[0].key_derivation_iterations = 100_000;

    let ticks = Arc::new(AtomicUsize::new(0));
    let counter = ticks.clone();
    let ticker = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(1)).await;
            counter.fetch_add(1, Ordering::SeqCst);
        }
    });
    tokio::task::yield_now().await;

    let before = ticks.load(Ordering::SeqCst);
    let result = s.unlock_backup(backup, password("hunter2")).await.unwrap();
    let during = ticks.load(Ordering::SeqCst) - before;
    ticker.abort();

    assert_eq!(
        serde_json::to_string(&result).unwrap(),
        r#"{"error":"wrongPassword"}"#
    );
    assert!(
        during >= 3,
        "other work ran {during} times while the backup was being unlocked"
    );
}

#[tokio::test]
async fn an_unlock_that_finishes_after_a_start_over_keeps_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path());
    // The right password: it would be kept, had nothing happened meanwhile. The start-over
    // lands while the key derivation is on the blocking pool.
    let unlocking = s.unlock_backup(fixture_backup(), password("hunter2"));
    let (result, ()) = tokio::join!(unlocking, async { s.discard_secrets() });
    assert!(result.is_err(), "the unlock reports that it was overtaken");
    assert!(s.unlocked().is_err(), "and nothing is kept");
}

trait AmbiguousIfDebug<A> {
    fn check() {}
}
impl<T: ?Sized> AmbiguousIfDebug<()> for T {}
impl<T: ?Sized + std::fmt::Debug> AmbiguousIfDebug<u8> for T {}

#[test]
fn passwords_and_codes_are_held_in_wiping_strings_without_debug() {
    let input: BwLoginInput = serde_json::from_str(
        r#"{"email":"e","password":"p","region":{"kind":"eu"},"twoFactorCode":"123456"}"#,
    )
    .unwrap();
    // These lines compile only while the fields are `Zeroizing`, which wipes on drop.
    let password: &Zeroizing<String> = &input.password;
    let code: &Option<Zeroizing<String>> = &input.two_factor_code;
    assert_eq!(password.as_str(), "p");
    assert_eq!(code.as_ref().unwrap().as_str(), "123456");
    // And this one only while `BwLoginInput` has no `Debug` (see `types.rs` for the trick).
    <BwLoginInput as AmbiguousIfDebug<_>>::check();

    // The `unlock` command's argument arrives the same way.
    let typed: Zeroizing<String> = serde_json::from_str(r#"" spaces kept ""#).unwrap();
    assert_eq!(typed.as_str(), " spaces kept ");
}

#[test]
fn live_codes_match_the_core_and_count_down() {
    let u = unlocked_one();
    let codes = live_codes(&u, 59);
    // RFC 6238 test vector secret differs; compare against the core directly.
    assert_eq!(
        codes[0].code,
        totp::code("JBSWY3DPEHPK3PXP", 6, 30, 59).unwrap()
    );
    assert_eq!(codes[0].seconds_left, 1);
    assert_eq!(live_codes(&u, 60)[0].seconds_left, 30);
}

// ---------------------------------------------------------------------------------------------
// Proxy events

#[test]
fn tls_rejected_is_debounced_to_one_per_two_seconds() {
    let mut b = Bridge::default();
    let t0 = Instant::now();
    let ms = Duration::from_millis;
    assert_eq!(
        b.map(&ProxyEvent::TlsRejected, t0),
        Some(ProxyEventDto::TlsRejected)
    );
    assert_eq!(b.map(&ProxyEvent::TlsRejected, t0 + ms(500)), None);
    assert_eq!(b.map(&ProxyEvent::TlsRejected, t0 + ms(1999)), None);
    assert_eq!(
        b.map(&ProxyEvent::TlsRejected, t0 + ms(2000)),
        Some(ProxyEventDto::TlsRejected)
    );
    // Other events are never held back.
    assert_eq!(
        b.map(&ProxyEvent::BackupCaptured { count: 3 }, t0 + ms(2001)),
        Some(ProxyEventDto::BackupCaptured { count: 3 })
    );
    assert_eq!(
        b.map(&ProxyEvent::DeviceRefused, t0 + ms(2002)),
        Some(ProxyEventDto::DeviceRefused)
    );
}

#[test]
fn proxy_events_serialise_to_the_ui_union() {
    let j = |e: ProxyEvent| serde_json::to_string(&ProxyEventDto::from(&e)).unwrap();
    assert_eq!(
        j(ProxyEvent::DeviceConnected),
        r#"{"kind":"deviceConnected"}"#
    );
    assert_eq!(j(ProxyEvent::TrustWorking), r#"{"kind":"trustWorking"}"#);
    assert_eq!(j(ProxyEvent::TlsRejected), r#"{"kind":"tlsRejected"}"#);
    assert_eq!(j(ProxyEvent::DeviceRefused), r#"{"kind":"deviceRefused"}"#);
    assert_eq!(
        j(ProxyEvent::BackupCaptured { count: 4 }),
        r#"{"kind":"backupCaptured","count":4}"#
    );
    assert_eq!(
        j(ProxyEvent::AuthyError {
            status: 403,
            path: "/x".into()
        }),
        r#"{"kind":"authyError","status":403,"path":"/x"}"#
    );
}

// ---------------------------------------------------------------------------------------------
// Writing the export file (S5)

fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn names_in(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn export_file_is_written_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();

    let fresh = dir.path().join("fresh.csv");
    write_owner_only(&fresh, b"secret,data").unwrap();
    assert_eq!(std::fs::read(&fresh).unwrap(), b"secret,data");
    assert_eq!(mode(&fresh), 0o600);

    // Over a world-readable file the person chose to replace.
    let old = dir.path().join("old.csv");
    std::fs::write(&old, b"old and much longer content").unwrap();
    std::fs::set_permissions(&old, std::fs::Permissions::from_mode(0o644)).unwrap();
    write_owner_only(&old, b"new").unwrap();
    assert_eq!(std::fs::read(&old).unwrap(), b"new");
    assert_eq!(mode(&old), 0o600);

    assert_eq!(
        names_in(dir.path()),
        ["fresh.csv", "old.csv"],
        "no temporary file stays behind"
    );
}

#[test]
fn a_failed_export_leaves_the_old_file_whole_and_no_partial_one() {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let old = dir.path().join("old.csv");
    std::fs::write(&old, b"what the person had before").unwrap();
    std::fs::set_permissions(&old, std::fs::Permissions::from_mode(0o644)).unwrap();

    // The disk fills up half-way through.
    let failed = write_owner_only_with(&old, |file| {
        file.write_all(b"otpauth://totp/half-a-secr")?;
        Err(std::io::Error::other("no space left on device"))
    });
    assert!(failed.is_err());
    assert_eq!(
        std::fs::read(&old).unwrap(),
        b"what the person had before",
        "the existing file is neither truncated nor half replaced"
    );
    assert_eq!(mode(&old), 0o644);
    assert_eq!(
        names_in(dir.path()),
        ["old.csv"],
        "nothing with part of a secret in it is left"
    );

    // The same when there was no file: nothing appears.
    let fresh = dir.path().join("fresh.csv");
    assert!(write_owner_only_with(&fresh, |file| {
        file.write_all(b"half")?;
        Err(std::io::Error::other("unplugged"))
    })
    .is_err());
    assert_eq!(names_in(dir.path()), ["old.csv"]);

    // And when the last step fails (the chosen name is a folder).
    let folder = dir.path().join("folder");
    std::fs::create_dir(&folder).unwrap();
    std::fs::write(folder.join("inside.txt"), b"kept").unwrap();
    assert!(write_owner_only(&folder, b"secret").is_err());
    assert_eq!(names_in(dir.path()), ["folder", "old.csv"]);
    assert_eq!(std::fs::read(folder.join("inside.txt")).unwrap(), b"kept");
}

#[test]
fn export_replaces_a_symbolic_link_instead_of_writing_through_it() {
    let dir = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let victim = elsewhere.path().join("victim.txt");
    std::fs::write(&victim, b"someone else's file").unwrap();
    let chosen = dir.path().join("export.csv");
    std::os::unix::fs::symlink(&victim, &chosen).unwrap();

    write_owner_only(&chosen, b"secret,data").unwrap();

    assert_eq!(
        std::fs::read(&victim).unwrap(),
        b"someone else's file",
        "the file the link pointed at is untouched"
    );
    let meta = std::fs::symlink_metadata(&chosen).unwrap();
    assert!(
        meta.file_type().is_file(),
        "the link was replaced by the file"
    );
    assert_eq!(std::fs::read(&chosen).unwrap(), b"secret,data");
    assert_eq!(mode(&chosen), 0o600);
    assert_eq!(names_in(elsewhere.path()), ["victim.txt"]);
}

#[test]
fn a_symbolic_link_at_the_temporary_name_is_refused_not_followed() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let victim = dir.path().join("victim.txt");
    std::fs::write(&victim, b"someone else's file").unwrap();
    let chosen = dir.path().join("export.csv");
    let temp = dir.path().join(".export.csv.planted");
    std::os::unix::fs::symlink(&victim, &temp).unwrap();

    let mut write = Some(|file: &mut std::fs::File| file.write_all(b"secret"));
    let refused = write_via(&chosen, &temp, &mut write).unwrap_err();
    assert_eq!(refused.kind(), std::io::ErrorKind::AlreadyExists);
    assert!(write.is_some(), "nothing was written anywhere");
    assert_eq!(std::fs::read(&victim).unwrap(), b"someone else's file");
    assert!(!chosen.exists());
    // The planted link is not ours to remove.
    assert!(std::fs::symlink_metadata(&temp).is_ok());

    // The real thing just picks another name.
    write_owner_only(&chosen, b"secret").unwrap();
    assert_eq!(std::fs::read(&chosen).unwrap(), b"secret");
    assert_eq!(std::fs::read(&victim).unwrap(), b"someone else's file");
}

#[tokio::test]
async fn export_prepares_the_files_and_refuses_google() {
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path());
    assert!(
        s.prepare_export(DestinationDto::Bitwarden).is_err(),
        "locked"
    );
    assert!(s.google_unsupported().is_err(), "locked");
    s.unlock_backup(fixture_backup(), password("hunter2"))
        .await
        .unwrap();
    let f = s.prepare_export(DestinationDto::Bitwarden).unwrap();
    assert_eq!(f.suggested_name, "authy-bitwarden-import.csv");
    assert!(s
        .prepare_export(DestinationDto::GoogleAuthenticator)
        .is_err());
    assert_eq!(s.google_migration_qrs().unwrap().len(), 1);
    assert_eq!(s.google_unsupported().unwrap(), Vec::<String>::new());
}

#[test]
fn google_unsupported_lists_what_the_qr_codes_cannot_carry() {
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path());
    *lock(&s.unlocked) = Some(Arc::new(Unlocked {
        tokens: vec![
            token("1", "Six Digits", 6),
            token("2", "Seven Digits", 7),
            token("3", "Eight Digits", 8),
        ],
        invalid: vec![],
        native: vec![],
    }));
    assert_eq!(s.google_unsupported().unwrap(), ["Seven Digits"]);
    assert_eq!(s.google_migration_qrs().unwrap().len(), 1);
}

// ---------------------------------------------------------------------------------------------
// Bitwarden (S3, S8)

fn attach(token: &str, item: &str) -> DecisionEntry {
    DecisionEntry {
        token_id: token.into(),
        decision: DecisionDto::Attach {
            item_id: item.into(),
        },
    }
}

fn decide(token: &str, decision: DecisionDto) -> DecisionEntry {
    DecisionEntry {
        token_id: token.into(),
        decision,
    }
}

#[tokio::test]
async fn propose_joins_candidates_against_the_vault() {
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path());
    *lock(&s.unlocked) = Some(Arc::new(unlocked_one()));
    s.bw_login(Box::new(FakeBw::new()), login_input())
        .await
        .unwrap();
    let proposals = s.bw_propose().await.unwrap();
    assert_eq!(proposals.len(), 1);
    let json = serde_json::to_value(&proposals[0]).unwrap();
    assert_eq!(json["tokenId"], "1");
    for c in json["candidates"].as_array().unwrap() {
        assert_eq!(c["itemId"], "item-1");
        assert_eq!(c["name"], "Example");
        assert_eq!(c["hasCode"], false);
    }
    let lines = Arc::new(Mutex::new(Vec::new()));
    let sink = lines.clone();
    let report = s
        .bw_apply(
            vec![attach("1", "item-1")],
            Arc::new(move |l| lock(&sink).push(l)),
        )
        .await
        .unwrap();
    assert_eq!(report.attached, 1);
    assert!(!lock(&lines).is_empty());
    assert_eq!(report.failed, None);
}

#[tokio::test]
async fn apply_attaches_to_any_login_without_a_code_and_refuses_the_rest_whole() {
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path());
    let mut sample = token("2", "Sample", 6);
    sample.secret = Secret::new("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into());
    *lock(&s.unlocked) = Some(Arc::new(Unlocked {
        tokens: vec![token("1", "Example", 6), sample],
        invalid: vec![],
        native: vec![],
    }));
    let mut bw = FakeBw::new();
    bw.vault = vec![
        login("item-example", "Example", false),
        login("item-sample-full", "Sample", true),
        login("item-unrelated", "Bank", false),
    ];
    s.bw_login(Box::new(bw.clone()), login_input())
        .await
        .unwrap();
    let writes = || lock(&bw.writes).clone();

    // Before the vault has been read there is nothing an attach could be checked against.
    assert_eq!(
        s.bw_apply(vec![attach("1", "item-example")], no_progress())
            .await
            .unwrap_err(),
        CmdError(Reject::DecisionUnknownLogin)
    );

    // The whole vault, for the person to pick from by hand: no passwords, no codes.
    let logins = s.bw_logins().await.unwrap();
    assert_eq!(
        serde_json::to_value(&logins).unwrap(),
        serde_json::json!([
            { "itemId": "item-example", "name": "Example", "username": null, "hasCode": false },
            { "itemId": "item-sample-full", "name": "Sample", "username": null, "hasCode": true },
            { "itemId": "item-unrelated", "name": "Bank", "username": null, "hasCode": false },
        ])
    );
    let proposals = s.bw_propose().await.unwrap();
    let candidates = |token: &str| -> Vec<(String, bool)> {
        proposals
            .iter()
            .find(|p| p.token_id == token)
            .unwrap()
            .candidates
            .iter()
            .map(|c| (c.item_id.clone(), c.has_code))
            .collect()
    };
    assert_eq!(candidates("1"), [("item-example".to_string(), false)]);
    assert_eq!(candidates("2"), [("item-sample-full".to_string(), true)]);

    let refused: Vec<(Vec<DecisionEntry>, Reject)> = vec![
        // A login that does not exist at all.
        (vec![attach("1", "made-up")], Reject::DecisionUnknownLogin),
        // A login that already has a code.
        (
            vec![attach("2", "item-sample-full")],
            Reject::DecisionLoginHasCode,
        ),
        // A token that is not in the unlocked backup, whatever the decision.
        (
            vec![decide("99", DecisionDto::CreateNew)],
            Reject::DecisionUnknownAccount,
        ),
        (
            vec![decide("99", DecisionDto::Skip)],
            Reject::DecisionUnknownAccount,
        ),
        (
            vec![attach("99", "item-example")],
            Reject::DecisionUnknownAccount,
        ),
        // Two tokens attached to one login: it can hold only one code.
        (
            vec![attach("1", "item-unrelated"), attach("2", "item-unrelated")],
            Reject::DecisionLoginTwice,
        ),
        // One bad entry spoils the list: the good ones before it are not applied either.
        (
            vec![
                attach("1", "item-example"),
                decide("2", DecisionDto::CreateNew),
                attach("1", "made-up"),
            ],
            Reject::DecisionUnknownLogin,
        ),
    ];
    for (decisions, reason) in refused {
        let described = format!("{decisions:?}");
        let error = s.bw_apply(decisions, no_progress()).await.unwrap_err();
        assert_eq!(error, CmdError(reason), "{described}");
        assert_eq!(error.code(), ErrorCode::BwFailed);
        assert!(error.sentence().ends_with("Nothing was changed."));
        assert_eq!(writes(), Vec::<String>::new(), "{described}");
    }

    // A login the matcher never offered for this token, picked by hand: it is in the vault
    // and holds no code, so it goes through. So does one that was a candidate for another
    // token.
    let report = s
        .bw_apply(
            vec![attach("1", "item-unrelated"), attach("2", "item-example")],
            no_progress(),
        )
        .await
        .unwrap();
    assert_eq!((report.attached, report.created), (2, 0));
    assert_eq!(writes(), ["attach item-unrelated", "attach item-example"]);

    // Running the same decisions again is still allowed (the apply itself is idempotent).
    assert!(s
        .bw_apply(vec![attach("1", "item-unrelated")], no_progress())
        .await
        .is_ok());
}

#[tokio::test]
async fn a_login_that_already_holds_this_very_code_may_be_chosen_again() {
    use authexodus_core::bitwarden::CodeMark;
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path());
    *lock(&s.unlocked) = Some(Arc::new(unlocked_one()));
    // An earlier run attached the code; the vault, read again since, says so.
    let mut bw = FakeBw::new();
    let mut done = login("item-1", "Example", true);
    done.code = CodeMark::of_secret("JBSWY3DPEHPK3PXP");
    let mut other = login("item-2", "Other", true);
    other.code = CodeMark::of_secret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    bw.vault = vec![done, other, login("item-3", "Unreadable", true)];
    s.bw_login(Box::new(bw.clone()), login_input())
        .await
        .unwrap();
    s.bw_logins().await.unwrap();
    assert!(
        s.bw_apply(vec![attach("1", "item-1")], no_progress())
            .await
            .is_ok(),
        "running the same choice again after the vault was re-read is not refused"
    );
    for held_elsewhere in ["item-2", "item-3"] {
        assert_eq!(
            s.bw_apply(vec![attach("1", held_elsewhere)], no_progress())
                .await
                .unwrap_err(),
            CmdError(Reject::DecisionLoginHasCode)
        );
    }
}

#[tokio::test]
async fn bw_login_that_needs_two_factor_keeps_no_client() {
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path());
    let mut bw = FakeBw::new();
    bw.outcome = LoginOutcome::NeedsTwoFactor;
    let r = s
        .bw_login(Box::new(bw.clone()), login_input())
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_string(&r).unwrap(),
        r#"{"kind":"needsTwoFactor"}"#
    );
    assert!(s.bw.lock().await.is_none());
    assert!(bw.was_wiped());
}

#[tokio::test]
async fn a_second_sign_in_wipes_the_first() {
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path());
    *lock(&s.unlocked) = Some(Arc::new(unlocked_one()));
    let first = FakeBw::new();
    s.bw_login(Box::new(first.clone()), login_input())
        .await
        .unwrap();
    s.bw_propose().await.unwrap();
    assert!(!first.was_wiped());

    let mut second = FakeBw::new();
    second.outcome = LoginOutcome::BadCredentials;
    let result = s
        .bw_login(Box::new(second.clone()), login_input())
        .await
        .unwrap();
    assert_eq!(result, BwLoginResult::BadCredentials);
    assert!(first.was_wiped(), "the first client's state is wiped");
    assert!(second.was_wiped());
    assert!(s.bw.lock().await.is_none(), "neither is kept");
    assert!(
        lock(&s.proposals).is_some(),
        "the same account signing in again keeps what was proposed for it"
    );

    // Another account: what was read from the first one's vault is dropped.
    let other: BwLoginInput =
        serde_json::from_str(r#"{"email":"b@example.com","password":"pw","region":{"kind":"us"}}"#)
            .unwrap();
    s.bw_login(Box::new(FakeBw::new()), other).await.unwrap();
    assert!(lock(&s.proposals).is_none());
    assert!(lock(&s.vault).is_none());
    // The same address on another server is another account too.
    s.bw_propose().await.unwrap();
    let elsewhere: BwLoginInput =
        serde_json::from_str(r#"{"email":"B@example.com","password":"pw","region":{"kind":"eu"}}"#)
            .unwrap();
    s.bw_login(Box::new(FakeBw::new()), elsewhere)
        .await
        .unwrap();
    assert!(lock(&s.proposals).is_none());
}

#[tokio::test]
async fn cleanup_stops_a_sign_in_that_is_under_way_and_nothing_of_it_is_left() {
    let dir = tempfile::tempdir().unwrap();
    let s = Arc::new(session(dir.path()));
    let (bw, entered, _release) = FakeBw::new().held();
    let bw_data = dir.path().join("bw-data");

    let signing_in = {
        let s = Arc::clone(&s);
        let client = Box::new(bw.clone());
        tokio::spawn(async move { s.bw_login(client, login_input()).await })
    };
    entered.notified().await;
    // The Bitwarden tool has started filling its folder.
    std::fs::create_dir_all(&bw_data).unwrap();
    std::fs::write(bw_data.join("data.json"), b"{}").unwrap();

    // Cleanup does not wait for the sign-in to end by itself (this one never would).
    tokio::time::timeout(Duration::from_secs(5), s.cleanup())
        .await
        .expect("cleanup stops a sign-in instead of waiting for it")
        .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), signing_in)
        .await
        .expect("the sign-in has ended")
        .unwrap();

    assert_eq!(result.unwrap_err(), CmdError(Reject::BwStopped));
    assert!(s.bw.lock().await.is_none(), "no client is kept");
    assert!(bw.was_wiped(), "its session was signed out and wiped");
    assert!(!bw_data.exists(), "and its folder is gone");
}

#[tokio::test]
async fn a_sign_in_overtaken_by_the_app_closing_keeps_no_client() {
    let dir = tempfile::tempdir().unwrap();
    let s = Arc::new(session(dir.path()));
    // A client that does not notice it was told to stop: it answers "signed in" anyway.
    struct Deaf(FakeBw);
    #[async_trait]
    impl BwClient for Deaf {
        async fn login(
            &mut self,
            a: &str,
            b: &str,
            c: &Region,
            d: Option<&str>,
        ) -> Result<LoginOutcome, BwError> {
            self.0.login(a, b, c, d).await
        }
        async fn login_with_api_key(
            &mut self,
            a: &str,
            b: &str,
            c: &str,
            d: &Region,
        ) -> Result<LoginOutcome, BwError> {
            self.0.login_with_api_key(a, b, c, d).await
        }
        async fn sync(&self) -> Result<(), BwError> {
            self.0.sync().await
        }
        async fn list_logins(&self) -> Result<Vec<VaultLogin>, BwError> {
            self.0.list_logins().await
        }
        async fn import_folder_titles(&self) -> Result<Vec<String>, BwError> {
            self.0.import_folder_titles().await
        }
        async fn set_totp(&self, a: &str, b: &str) -> Result<SetTotp, BwError> {
            self.0.set_totp(a, b).await
        }
        async fn create_in_import_folder(
            &self,
            a: &str,
            b: Option<&str>,
            c: &str,
        ) -> Result<(), BwError> {
            self.0.create_in_import_folder(a, b, c).await
        }
        async fn logout_and_wipe(&mut self) -> Result<(), BwError> {
            self.0.logout_and_wipe().await
        }
    }
    let bw = FakeBw::new();
    // The secrets are thrown away (as a start-over does) with no stop signal given: the
    // sign-in that then succeeds must still not be kept.
    let discarding = {
        let s = Arc::clone(&s);
        async move { s.discard_secrets() }
    };
    let (bw_held, entered, release) = bw.clone().held();
    let signing_in = {
        let s = Arc::clone(&s);
        tokio::spawn(async move { s.bw_login(Box::new(Deaf(bw_held)), login_input()).await })
    };
    entered.notified().await;
    discarding.await;
    release.notify_one();
    let result = signing_in.await.unwrap();
    assert_eq!(result.unwrap_err(), CmdError(Reject::BwOvertaken));
    assert!(s.bw.lock().await.is_none());
    assert!(bw.was_wiped());
}

#[tokio::test]
async fn sign_ins_run_one_at_a_time() {
    let dir = tempfile::tempdir().unwrap();
    let s = Arc::new(session(dir.path()));
    let (first, entered, release) = FakeBw::new().held();
    let one = {
        let s = Arc::clone(&s);
        let client = Box::new(first.clone());
        tokio::spawn(async move { s.bw_login(client, login_input()).await })
    };
    entered.notified().await;

    let second = FakeBw::new();
    let two = {
        let s = Arc::clone(&s);
        let client = Box::new(second.clone());
        tokio::spawn(async move { s.bw_login(client, login_input()).await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!two.is_finished(), "the second waits for the first");

    release.notify_one();
    assert_eq!(one.await.unwrap().unwrap(), BwLoginResult::Ok);
    assert_eq!(two.await.unwrap().unwrap(), BwLoginResult::Ok);
    assert!(
        first.was_wiped(),
        "the first was wiped when the second began"
    );
    assert!(!second.was_wiped(), "the second is the one kept");
    assert!(s.bw.lock().await.is_some());
}

#[test]
fn decisions_and_login_deserialise_from_the_ui_shapes() {
    let d: DecisionDto = serde_json::from_str(r#"{"kind":"attach","itemId":"x"}"#).unwrap();
    assert_eq!(
        d,
        DecisionDto::Attach {
            item_id: "x".into()
        }
    );
    let d: DecisionDto = serde_json::from_str(r#"{"kind":"createNew"}"#).unwrap();
    assert_eq!(d, DecisionDto::CreateNew);
    let l: BwLoginInput = serde_json::from_str(
        r#"{"email":"e","password":"p","region":{"kind":"selfHosted","url":"https://h"},"twoFactorCode":"123456"}"#,
    )
    .unwrap();
    assert_eq!(
        l.two_factor_code.as_ref().map(|c| c.as_str()),
        Some("123456")
    );
    let e: DecisionEntry =
        serde_json::from_str(r#"{"tokenId":"1","decision":{"kind":"skip"}}"#).unwrap();
    assert_eq!(e.decision, DecisionDto::Skip);
}

// ---------------------------------------------------------------------------------------------
// Final review fixes

#[tokio::test]
async fn sign_in_input_is_checked_before_the_tool_is_asked() {
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path());
    let bw = FakeBw::new();
    for (input, message) in [
        (
            r#"{"email":"a@example.com","password":"pw","region":{"kind":"selfHosted","url":"http://vault.example.test"}}"#,
            Reject::BadServerUrl,
        ),
        (
            r#"{"email":"a@example.com","password":"pw","region":{"kind":"selfHosted","url":"https://me:pw@vault.example.test"}}"#,
            Reject::BadServerUrl,
        ),
        (
            r#"{"email":"--raw","password":"pw","region":{"kind":"us"}}"#,
            Reject::BadEmail,
        ),
        (
            r#"{"email":"nobody","password":"pw","region":{"kind":"eu"}}"#,
            Reject::BadEmail,
        ),
        // With an API key the email is not sent anywhere, but the server still counts.
        (
            r#"{"email":"","password":"pw","region":{"kind":"selfHosted","url":"http://vault.example.test"},"apiKey":{"clientId":"user.11111111-0000-4000-8000-000000000001","clientSecret":"synthetic0secret0value"}}"#,
            Reject::BadServerUrl,
        ),
    ] {
        let input: BwLoginInput = serde_json::from_str(input).unwrap();
        let refused = s.bw_login(Box::new(bw.clone()), input).await.unwrap_err();
        assert_eq!(refused, CmdError(message));
        assert!(
            !refused.to_string().contains("example"),
            "what was typed is not repeated: {refused}"
        );
    }
    assert_eq!(
        CmdError(Reject::BadEmail).to_string(),
        "bad_email: That does not look like an email address."
    );
    assert!(CmdError(Reject::BadServerUrl)
        .to_string()
        .starts_with("bad_server_url: The server address must start with https://"));
    assert_eq!(
        bw.logins.load(Ordering::SeqCst),
        0,
        "the tool was never asked"
    );

    // Spaces around the address are not a reason to refuse it.
    let input: BwLoginInput = serde_json::from_str(
        r#"{"email":"  a@example.com ","password":"pw","region":{"kind":"selfHosted","url":" https://vault.example.test/ "}}"#,
    )
    .unwrap();
    assert_eq!(
        s.bw_login(Box::new(bw.clone()), input).await.unwrap(),
        BwLoginResult::Ok
    );
}

#[tokio::test]
async fn a_refused_two_step_code_is_its_own_answer_and_unsupported_methods_say_so() {
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path());
    let with_code = || -> BwLoginInput {
        serde_json::from_str(
            r#"{"email":"a@example.com","password":"pw","region":{"kind":"us"},"twoFactorCode":" 123456 "}"#,
        )
        .unwrap()
    };

    // A code was sent and refused.
    let mut bw = FakeBw::new();
    bw.outcome = LoginOutcome::BadTwoFactorCode;
    let r = s.bw_login(Box::new(bw.clone()), with_code()).await.unwrap();
    assert_eq!(r, BwLoginResult::BadTwoFactorCode);
    assert_eq!(
        serde_json::to_string(&r).unwrap(),
        r#"{"kind":"badTwoFactorCode"}"#
    );
    assert_eq!(lock(&bw.code_sent).as_deref(), Some("123456"), "trimmed");
    assert!(bw.was_wiped());
    // A client that answers "needs a code" although one was sent: that is a refused code too.
    bw.outcome = LoginOutcome::NeedsTwoFactor;
    assert_eq!(
        s.bw_login(Box::new(bw.clone()), with_code()).await.unwrap(),
        BwLoginResult::BadTwoFactorCode
    );
    // Without a code it is the question it always was.
    assert_eq!(
        s.bw_login(Box::new(bw.clone()), login_input())
            .await
            .unwrap(),
        BwLoginResult::NeedsTwoFactor
    );

    // What a password sign-in cannot get past (an emailed code, a method the tool cannot
    // do) is an answer of its own, not a failure: the way through is an API key.
    let mut bw = FakeBw::new();
    bw.outcome = LoginOutcome::NeedsApiKey;
    for input in [with_code(), login_input()] {
        let r = s.bw_login(Box::new(bw.clone()), input).await.unwrap();
        assert_eq!(r, BwLoginResult::NeedsApiKey);
        assert_eq!(
            serde_json::to_string(&r).unwrap(),
            r#"{"kind":"needsApiKey"}"#
        );
        assert!(bw.was_wiped());
    }
    assert!(s.bw.lock().await.is_none());

    // What the tool says when it fails some other way stays off the screen.
    let mut bw = FakeBw::new();
    bw.error = Some(BwError::Cli(
        "Username sam@example.test could not log in to https://vault.example.test".into(),
    ));
    let error = s
        .bw_login(Box::new(bw.clone()), login_input())
        .await
        .unwrap_err();
    assert_eq!(error, CmdError(Reject::BwSignInFailed));
    assert_eq!(error.code(), ErrorCode::BwFailed);
    bw.error = Some(BwError::Server(
        "getaddrinfo ENOTFOUND vault.example.test".into(),
    ));
    let error = s
        .bw_login(Box::new(bw.clone()), login_input())
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::BwUnreachable);
    assert!(!error.to_string().contains("example"), "{error}");
    bw.error = Some(BwError::ChecksumMismatch);
    let error = s
        .bw_login(Box::new(bw.clone()), login_input())
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::BwChecksumMismatch);
}

#[test]
fn the_unconstrained_root_is_only_ever_asked_for_by_name() {
    assert!(ca_constrained(None));
    assert!(ca_constrained(Some("")));
    assert!(ca_constrained(Some("0")));
    assert!(ca_constrained(Some("true")));
    assert!(ca_constrained(Some("yes")));
    assert!(!ca_constrained(Some("1")));
    assert!(!ca_constrained(Some(" 1 ")));
    assert_eq!(UNCONSTRAINED_ENV, "AUTHEXODUS_UNCONSTRAINED_CA");
}

#[tokio::test]
async fn the_proxy_serves_the_certificate_whose_fingerprint_it_reports() {
    for constrained in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let s = Session::with_ca_mode(dir.path().to_path_buf(), constrained);
        assert_eq!(s.ca_is_constrained(), constrained);
        s.tune_proxy(0, None);
        let info = s
            .start_proxy(Some("127.0.0.1"), &loopback(), no_emit())
            .await
            .unwrap();
        let ca = s.ensure_ca().await.unwrap();
        assert_eq!(ca.is_constrained(), constrained);
        assert_eq!(info.cert_fingerprint, ca.fingerprint());
        assert_eq!(info.cert_fingerprint.len(), 95);
        assert_eq!(
            info.cert_constrained, constrained,
            "the UI is told which kind of certificate this is"
        );
        assert_eq!(
            serde_json::to_value(&info).unwrap()["certConstrained"],
            constrained
        );
        // The same certificate after a start-over, so the same fingerprint.
        let again = s.restart_proxy(None, &loopback(), no_emit()).await.unwrap();
        assert_eq!(again.cert_fingerprint, info.cert_fingerprint);
        s.cleanup().await.unwrap();
    }
}

#[tokio::test]
async fn the_proxy_never_listens_where_the_internet_can_reach_it() {
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path());
    s.tune_proxy(0, None);
    // A computer whose only usable address is public (as if plugged straight into a modem).
    let public_only = Network {
        candidates: vec![candidate(Ipv4Addr::new(198, 51, 100, 23), "Ethernet (en0)")],
        own: vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 23))],
    };
    let none = s
        .start_proxy(None, &public_only, no_emit())
        .await
        .unwrap_err();
    assert_eq!(none, CmdError(Reject::NoPrivateAddress));
    assert_eq!(none.code().as_str(), "no_private_address");
    assert!(none
        .sentence()
        .contains("not on a home or office Wi-Fi network"));
    let asked = s
        .start_proxy(Some("198.51.100.23"), &public_only, no_emit())
        .await
        .unwrap_err();
    assert_eq!(
        asked,
        CmdError(Reject::AddressPublic),
        "refused even when asked for by name"
    );
    assert_eq!(asked.code().as_str(), "address_not_private");
    let restart = s
        .restart_proxy(Some("198.51.100.23"), &public_only, no_emit())
        .await
        .unwrap_err();
    assert_eq!(restart, CmdError(Reject::AddressPublic));
    assert!(s.proxy.lock().await.is_none(), "nothing was started");
    assert!(
        !dir.path().join("session.json").exists(),
        "and no certificate was made for it"
    );

    // An address that is not this computer's.
    let not_ours = s
        .start_proxy(Some("10.9.8.7"), &loopback(), no_emit())
        .await
        .unwrap_err();
    assert_eq!(not_ours, CmdError(Reject::AddressNotOurs));
    assert_eq!(not_ours.code().as_str(), "address_changed");
    let nonsense = s
        .start_proxy(Some("nonsense"), &loopback(), no_emit())
        .await
        .unwrap_err();
    assert_eq!(nonsense.code().as_str(), "internal");
}

#[tokio::test]
async fn a_start_over_without_an_address_stays_on_the_one_in_use() {
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path());
    s.tune_proxy(0, None);
    let net = two_addresses();
    // The person chose the second address, not the first.
    let chosen = s
        .start_proxy(Some("0.0.0.0"), &net, no_emit())
        .await
        .unwrap();
    assert_eq!(chosen.ip, "0.0.0.0");
    let restarted = s.restart_proxy(None, &net, no_emit()).await.unwrap();
    assert_eq!(restarted.ip, "0.0.0.0", "the phone only has to reconnect");
    // Named, it moves.
    let moved = s
        .restart_proxy(Some("127.0.0.1"), &net, no_emit())
        .await
        .unwrap();
    assert_eq!(moved.ip, "127.0.0.1");
    s.cleanup().await.unwrap();
}

#[test]
fn a_code_and_its_seconds_left_come_from_the_same_instant() {
    let unlocked = unlocked_one();
    // The last second of one period, and the first of the next.
    let last = 1_760_000_009 - 1_760_000_009 % 30 + 29;
    let at_last = live_codes(&unlocked, last);
    let at_next = live_codes(&unlocked, last + 1);
    assert_eq!(at_last[0].seconds_left, 1);
    assert_eq!(at_next[0].seconds_left, 30);
    assert_eq!(
        at_last[0].code,
        totp::code("JBSWY3DPEHPK3PXP", 6, 30, last).unwrap()
    );
    assert_eq!(
        at_next[0].code,
        totp::code("JBSWY3DPEHPK3PXP", 6, 30, last + 1).unwrap()
    );
    assert_ne!(
        at_last[0].code, at_next[0].code,
        "a new code with a full count"
    );
    // Every second of a period shows the same code, counting down from 30 to 1.
    let start = last + 1;
    for t in start..start + 30 {
        let codes = live_codes(&unlocked, t);
        assert_eq!(codes[0].code, at_next[0].code);
        assert_eq!(u64::from(codes[0].seconds_left), 30 - (t - start));
    }
}

#[tokio::test]
async fn a_launch_after_a_quit_never_finds_the_old_key_and_a_new_run_gets_a_new_one() {
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path());
    s.tune_proxy(0, None);
    s.start_proxy(Some("127.0.0.1"), &loopback(), no_emit())
        .await
        .unwrap();
    let installed = s.ensure_ca().await.unwrap().cert_der();
    s.on_exit();
    drop(s);

    // The next launch opens on cleanup with nothing of the old key: cleanup and finish go
    // through without it.
    let resumed = session(dir.path());
    assert!(resumed.get_state(&loopback()).resume_cleanup);
    assert!(lock(&resumed.authority).is_none());
    resumed.cleanup().await.unwrap();
    resumed.finish().await.unwrap();

    // A new run makes a new root: the certificate left on the device is never served again.
    let next = session(dir.path());
    next.tune_proxy(0, None);
    next.start_proxy(Some("127.0.0.1"), &loopback(), no_emit())
        .await
        .unwrap();
    assert_ne!(next.ensure_ca().await.unwrap().cert_der(), installed);
    next.cleanup().await.unwrap();
}

// ---------------------------------------------------------------------------------------------
// Completeness fixes

fn events() -> (
    EmitProxy,
    tokio::sync::mpsc::UnboundedReceiver<ProxyEventDto>,
) {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let emit: EmitProxy = Arc::new(move |event| {
        let _ = tx.send(event);
    });
    (emit, rx)
}

/// Is there a process with this id? (Signal 0 delivers nothing; it only asks.)
fn alive(pid: u32) -> bool {
    // SAFETY: `kill` with signal 0 has no effect on the target.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

fn sleeper() -> Option<KeepAwakeCommand> {
    Some(KeepAwakeCommand {
        program: PathBuf::from("/bin/sleep"),
        args: vec!["600".into()],
    })
}

async fn awake_pid(s: &Session) -> Option<u32> {
    s.proxy
        .lock()
        .await
        .as_ref()
        .and_then(|run| run._awake.as_ref().map(KeepAwake::pid))
}

#[tokio::test]
async fn the_state_says_what_the_shell_knows_so_a_reloaded_window_can_carry_on() {
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path());
    s.tune_proxy(0, None);
    let net = loopback();

    // Nothing yet.
    let fresh = s.get_state(&net);
    assert_eq!(fresh.step, Step::Welcome);
    assert_eq!(
        serde_json::to_value(&fresh.session).unwrap(),
        serde_json::json!({
            "proxy": null, "deviceConnected": false, "trustWorking": false,
            "captured": 0, "summary": null
        })
    );

    // The proxy runs: the very description `start_proxy` gave is there to be had again.
    s.set_device(Device::Ipad);
    let info = s
        .start_proxy(Some("127.0.0.1"), &net, no_emit())
        .await
        .unwrap();
    let running = s.get_state(&net);
    assert_eq!(running.step, Step::Connect);
    assert_eq!(running.device, Some(Device::Ipad));
    assert_eq!(running.session.proxy.as_ref(), Some(&info));
    assert!(!running.session.device_connected && !running.session.trust_working);
    assert_eq!(running.session.captured, 0);

    // What the proxy reports is remembered for this run of it...
    {
        let slot = s.proxy.lock().await;
        let facts = &slot.as_ref().unwrap().facts;
        facts.note(&ProxyEvent::TlsRejected);
        assert_eq!(
            s.get_state(&net).step,
            Step::Welcome,
            "busy: not waited for"
        );
        facts.note(&ProxyEvent::DeviceConnected);
    }
    let connected = s.get_state(&net);
    assert!(connected.session.device_connected && !connected.session.trust_working);
    assert_eq!(connected.step, Step::Certificate);
    s.proxy
        .lock()
        .await
        .as_ref()
        .unwrap()
        .facts
        .note(&ProxyEvent::TrustWorking);
    let trusted = s.get_state(&net);
    assert!(trusted.session.trust_working);
    assert_eq!(trusted.step, Step::Authy);

    // ...and starts again from nothing when the proxy is started over.
    s.restart_proxy(None, &net, no_emit()).await.unwrap();
    let restarted = s.get_state(&net);
    assert!(!restarted.session.device_connected && !restarted.session.trust_working);
    assert_eq!(restarted.step, Step::Connect);

    // Unlocked: the summary is there too, and it carries no secret.
    s.unlock_backup(fixture_backup(), password("hunter2"))
        .await
        .unwrap();
    let unlocked = s.get_state(&net);
    assert_eq!(unlocked.step, Step::Destination);
    let summary = serde_json::to_value(&unlocked.session.summary).unwrap();
    assert_eq!(summary["tokens"][0]["id"], "1");
    assert!(!serde_json::to_string(&unlocked)
        .unwrap()
        .contains("JBSWY3DPEHPK3PXP"));

    // Cleanup, then done; and a new start after that begins again.
    s.cleanup().await.unwrap();
    let cleaned = s.get_state(&net);
    assert_eq!(cleaned.step, Step::Cleanup);
    assert_eq!(cleaned.session.proxy, None);
    assert_eq!(cleaned.session.summary, None);
    s.finish().await.unwrap();
    assert_eq!(s.get_state(&net).step, Step::Done);
    s.start_proxy(Some("127.0.0.1"), &net, no_emit())
        .await
        .unwrap();
    assert_eq!(s.get_state(&net).step, Step::Connect);
    s.cleanup().await.unwrap();
}

#[tokio::test]
async fn a_backup_of_only_authy_native_tokens_unlocks_to_their_names_without_a_password() {
    use authexodus_core::types::NativeApp;
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path());
    let native_only = CapturedBackup {
        tokens: vec![],
        native_apps: vec![
            NativeApp {
                name: "Synthetic Native".into(),
                digits: 7,
            },
            NativeApp {
                name: "Another Native".into(),
                digits: 7,
            },
        ],
    };
    // There is nothing to decrypt, so whatever is typed, the answer is the list.
    for typed in ["", "anything at all"] {
        let result = s
            .unlock_backup(native_only.clone(), password(typed))
            .await
            .unwrap();
        assert_eq!(
            serde_json::to_value(&result).unwrap(),
            serde_json::json!({
                "tokens": [], "invalid": [],
                "native": [{ "name": "Synthetic Native" }, { "name": "Another Native" }]
            })
        );
    }
    let state = s.get_state(&loopback());
    assert_eq!(state.step, Step::Destination);
    assert_eq!(state.session.summary.unwrap().native.len(), 2);
    // With no tokens there is nothing to draw, and that is said, not shown as an empty list.
    assert_eq!(s.live_codes().unwrap().len(), 0);
    assert_eq!(
        s.google_migration_qrs().unwrap_err(),
        CmdError(Reject::NoGoogleCodes)
    );

    // Nothing at all captured is still "not arrived".
    let nothing = s
        .unlock_backup(CapturedBackup::default(), password("x"))
        .await
        .unwrap_err();
    assert_eq!(nothing, CmdError(Reject::BackupNotArrived));
    assert_eq!(nothing.code().as_str(), "no_backup");
    let fresh = session(dir.path());
    assert_eq!(
        fresh
            .unlock(password("x"))
            .await
            .unwrap_err()
            .code()
            .as_str(),
        "no_backup"
    );

    // The proxy's "no accounts" notice reaches the UI as its own kind.
    let mut bridge = Bridge::default();
    assert_eq!(
        bridge.map(&ProxyEvent::EmptyBackup, Instant::now()),
        Some(ProxyEventDto::EmptyBackup)
    );
    assert_eq!(event_kind(&ProxyEvent::EmptyBackup), "emptyBackup");
}

#[tokio::test]
async fn a_code_that_cannot_be_drawn_is_an_error_not_an_empty_picture() {
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path());
    assert_eq!(s.token_qr("1").unwrap_err(), CmdError(Reject::NotUnlocked));
    assert_eq!(s.token_qr("1").unwrap_err().code().as_str(), "not_unlocked");

    // A name so long that no QR code can hold the account, and a seven-digit account, which
    // Google Authenticator cannot take.
    let mut endless = token("long", "Endless", 6);
    endless.name = "n".repeat(4000);
    *lock(&s.unlocked) = Some(Arc::new(Unlocked {
        tokens: vec![endless, token("seven", "Seven Digits", 7)],
        invalid: vec![],
        native: vec![],
    }));
    let undrawn = s.token_qr("long").unwrap_err();
    assert_eq!(undrawn, CmdError(Reject::QrNotDrawn));
    assert_eq!(undrawn.code().as_str(), "export_failed");
    assert!(s.token_qr("seven").unwrap().contains("<svg"));
    let unknown = s.token_qr("nobody").unwrap_err();
    assert_eq!(unknown.code().as_str(), "export_failed");

    // Neither account fits a Google transfer code: an error, and the list of what cannot go
    // says which.
    let none = s.google_migration_qrs().unwrap_err();
    assert_eq!(none, CmdError(Reject::NoGoogleCodes));
    assert_eq!(none.code().as_str(), "export_failed");
    assert_eq!(s.google_unsupported().unwrap(), ["Endless", "Seven Digits"]);
    assert_eq!(
        s.prepare_export(DestinationDto::GoogleAuthenticator)
            .unwrap_err()
            .code()
            .as_str(),
        "export_failed"
    );
}

#[tokio::test]
async fn an_address_missing_from_one_look_only_is_not_a_change() {
    // What each look at this computer's addresses finds, in order; after the script, the
    // address is there.
    let script = [
        true, false, true, true, // one look without it (a Wi-Fi blip): nothing said
        false, false, false, true, // gone on two looks in a row: said once
        false, true, // one look again: nothing
        false, false, // two in a row again: said a second time
    ];
    let looks = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&looks);
    let addresses: AddressSource = Arc::new(move || {
        let n = counter.fetch_add(1, Ordering::SeqCst);
        if script.get(n).copied().unwrap_or(true) {
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]
        } else {
            vec![]
        }
    });
    let (emit, mut heard) = events();
    let watch = tokio::spawn(watch_address(
        Ipv4Addr::LOCALHOST,
        Duration::from_millis(2),
        addresses,
        emit,
    ));
    while looks.load(Ordering::SeqCst) < script.len() + 3 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    watch.abort();
    let mut said = Vec::new();
    while let Ok(event) = heard.try_recv() {
        said.push(event);
    }
    assert_eq!(
        said,
        [ProxyEventDto::AddressChanged, ProxyEventDto::AddressChanged]
    );
}

#[tokio::test]
async fn a_changed_address_is_noticed_once_and_the_stale_proxy_is_not_described_again() {
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path());
    s.tune_proxy(0, None);
    let own = Arc::new(Mutex::new(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]));
    let source = Arc::clone(&own);
    s.tune_address_watch(
        Duration::from_millis(15),
        Arc::new(move || lock(&source).clone()),
    );
    let (emit, mut heard) = events();
    let net = loopback();
    let info = s
        .start_proxy(Some("127.0.0.1"), &net, emit.clone())
        .await
        .unwrap();

    // Nothing is said while the address is where it was.
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert!(heard.try_recv().is_err());

    // The computer moves to another network: its old address is gone.
    let elsewhere = Network {
        candidates: vec![candidate(Ipv4Addr::new(10, 0, 0, 5), "Wi-Fi (en0)")],
        own: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))],
    };
    *lock(&own) = elsewhere.own.clone();
    let event = tokio::time::timeout(Duration::from_secs(5), heard.recv())
        .await
        .expect("the change is noticed");
    assert_eq!(event, Some(ProxyEventDto::AddressChanged));
    assert_eq!(
        serde_json::to_string(&ProxyEventDto::AddressChanged).unwrap(),
        r#"{"kind":"addressChanged"}"#
    );
    // Once per change, not once per look.
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(heard.try_recv().is_err(), "said once");

    // Asked for the proxy now, the shell does not hand back the address nothing can reach.
    for asked in [None, Some("127.0.0.1")] {
        let stale = s
            .start_proxy(asked, &elsewhere, emit.clone())
            .await
            .unwrap_err();
        assert_eq!(stale, CmdError(Reject::AddressChanged));
        assert!(stale.to_string().starts_with("address_changed: "));
        assert!(stale.sentence().contains("Restart the connection"));
    }
    // A capture, had there been one, is still in memory: nothing was torn down.
    assert!(s.proxy.lock().await.is_some());

    // The address comes back (the same Wi-Fi again): the proxy is described as before...
    *lock(&own) = net.own.clone();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let again = s.start_proxy(None, &net, emit.clone()).await.unwrap();
    assert_eq!(again.port, info.port);
    assert!(heard.try_recv().is_err());
    // ...and a second loss is a second change.
    *lock(&own) = elsewhere.own.clone();
    let event = tokio::time::timeout(Duration::from_secs(5), heard.recv())
        .await
        .expect("the second change is noticed");
    assert_eq!(event, Some(ProxyEventDto::AddressChanged));

    // The way out is the start-over, which does not insist on the address that is gone.
    let gone = s
        .restart_proxy(Some("127.0.0.1"), &elsewhere, emit.clone())
        .await
        .unwrap_err();
    assert_eq!(gone.code().as_str(), "address_changed");
    // (10.0.0.5 is not really this computer's, so the listener cannot be opened there; the
    // point is that the default was chosen and tried.)
    let tried = s.restart_proxy(None, &elsewhere, emit.clone()).await;
    assert_eq!(tried.unwrap_err(), CmdError(Reject::ListenFailed));

    // A stopped proxy is no longer watched.
    s.cleanup().await.unwrap();
    *lock(&own) = vec![];
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(heard.try_recv().is_err());
}

#[tokio::test]
async fn the_computer_is_kept_awake_exactly_while_the_proxy_runs() {
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path());
    s.tune_proxy(0, None);
    s.tune_keep_awake(sleeper());
    let net = two_addresses();
    assert_eq!(awake_pid(&s).await, None);

    s.start_proxy(Some("127.0.0.1"), &net, no_emit())
        .await
        .unwrap();
    let first = awake_pid(&s).await.expect("a helper runs with the proxy");
    assert!(alive(first));
    // Asking again starts no second helper.
    s.start_proxy(None, &net, no_emit()).await.unwrap();
    assert_eq!(awake_pid(&s).await, Some(first));

    // Moving and starting over each stop the old helper and start one for the new proxy.
    s.start_proxy(Some("0.0.0.0"), &net, no_emit())
        .await
        .unwrap();
    let second = awake_pid(&s).await.unwrap();
    assert!(!alive(first), "the old helper was stopped and collected");
    assert!(alive(second));
    s.restart_proxy(None, &net, no_emit()).await.unwrap();
    let third = awake_pid(&s).await.unwrap();
    assert!(!alive(second));
    assert!(alive(third));

    // Cleanup stops the proxy, and the helper with it.
    s.cleanup().await.unwrap();
    assert_eq!(awake_pid(&s).await, None);
    assert!(!alive(third));

    // So does closing the app, which cannot wait.
    s.start_proxy(Some("127.0.0.1"), &net, no_emit())
        .await
        .unwrap();
    let fourth = awake_pid(&s).await.unwrap();
    assert!(alive(fourth));
    s.on_exit();
    assert!(!alive(fourth));

    // A helper that cannot be started is not a reason to refuse to run.
    s.tune_keep_awake(Some(KeepAwakeCommand {
        program: PathBuf::from("/nonexistent/keep-awake"),
        args: vec![],
    }));
    s.start_proxy(Some("127.0.0.1"), &net, no_emit())
        .await
        .unwrap();
    assert_eq!(awake_pid(&s).await, None);
    // And a session that is simply dropped takes its helper with it.
    s.tune_keep_awake(sleeper());
    s.restart_proxy(None, &net, no_emit()).await.unwrap();
    let last = awake_pid(&s).await.unwrap();
    drop(s);
    assert!(!alive(last));
}

fn api_key_input() -> BwLoginInput {
    serde_json::from_str(
        r#"{"email":"a@example.com","password":"master pw","region":{"kind":"us"},
            "apiKey":{"clientId":"user.11111111-0000-4000-8000-000000000001","clientSecret":"synthetic0secret0value"}}"#,
    )
    .unwrap()
}

#[tokio::test]
async fn an_api_key_signs_in_by_the_key_and_unlocks_with_the_password() {
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path());
    *lock(&s.unlocked) = Some(Arc::new(unlocked_one()));
    let bw = FakeBw::new();
    let result = s
        .bw_login(Box::new(bw.clone()), api_key_input())
        .await
        .unwrap();
    assert_eq!(result, BwLoginResult::Ok);
    assert_eq!(
        lock(&bw.api_key_sent).clone(),
        Some((
            "user.11111111-0000-4000-8000-000000000001".to_string(),
            "synthetic0secret0value".to_string(),
            "master pw".to_string()
        ))
    );
    assert_eq!(
        *lock(&bw.code_sent),
        None,
        "the password sign-in was not used"
    );
    assert_eq!(bw.logins.load(Ordering::SeqCst), 1);
    assert!(s.bw.lock().await.is_some());
    s.bw_propose().await.unwrap();

    // A key or a master password Bitwarden refuses is "the details are wrong".
    let mut refused = FakeBw::new();
    refused.outcome = LoginOutcome::BadCredentials;
    assert_eq!(
        s.bw_login(Box::new(refused.clone()), api_key_input())
            .await
            .unwrap(),
        BwLoginResult::BadCredentials
    );
    assert!(refused.was_wiped());

    // The key is held the way the password is: wiped when dropped, and never printable.
    let input = api_key_input();
    let key = input.api_key.as_ref().unwrap();
    let _id: &Zeroizing<String> = &key.client_id;
    let _secret: &Zeroizing<String> = &key.client_secret;
    <BwApiKeyInput as AmbiguousIfDebug<_>>::check();
    // Without one, the field is simply absent.
    assert!(login_input().api_key.is_none());
}

#[tokio::test]
async fn an_ended_session_is_its_own_error_and_the_choices_survive_signing_in_again() {
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path());
    let mut second = token("2", "Sample", 6);
    second.secret = Secret::new("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into());
    *lock(&s.unlocked) = Some(Arc::new(Unlocked {
        tokens: vec![token("1", "Example", 6), second],
        invalid: vec![],
        native: vec![],
    }));
    let mut bw = FakeBw::new();
    bw.vault = vec![
        login("item-1", "Example", false),
        login("item-2", "Bank", false),
    ];

    // Not signed in at all is the same thing to the person: sign in.
    for error in [
        s.bw_propose().await.unwrap_err(),
        s.bw_logins().await.unwrap_err(),
        s.bw_apply(vec![], no_progress()).await.unwrap_err(),
    ] {
        assert_eq!(error.code().as_str(), "bw_session_expired");
    }

    s.bw_login(Box::new(bw.clone()), login_input())
        .await
        .unwrap();
    let proposals = s.bw_propose().await.unwrap();
    s.bw_logins().await.unwrap();
    // What the person chose on the review screen.
    let chosen = vec![attach("1", "item-1"), attach("2", "item-2")];

    // The session ends before the apply gets anywhere.
    bw.expired.store(true, Ordering::SeqCst);
    for error in [
        s.bw_apply(chosen.clone(), no_progress()).await.unwrap_err(),
        s.bw_propose().await.unwrap_err(),
        s.bw_logins().await.unwrap_err(),
    ] {
        assert_eq!(error, CmdError(Reject::BwSessionExpired));
        assert!(error.to_string().starts_with("bw_session_expired: "));
    }
    assert_eq!(lock(&bw.writes).len(), 0);
    assert_eq!(
        lock(&s.proposals).as_ref(),
        Some(&proposals),
        "what was proposed is still there"
    );

    // Signing in again to the same account, then running the very same choices: no new
    // review, no new reading of the vault.
    let fresh = FakeBw {
        vault: bw.vault.clone(),
        ..FakeBw::new()
    };
    assert_eq!(
        s.bw_login(Box::new(fresh.clone()), login_input())
            .await
            .unwrap(),
        BwLoginResult::Ok
    );
    assert_eq!(lock(&s.proposals).as_ref(), Some(&proposals));
    let report = s.bw_apply(chosen, no_progress()).await.unwrap();
    assert_eq!((report.attached, report.failed), (2, None));
    assert_eq!(*lock(&fresh.writes), ["attach item-1", "attach item-2"]);

    // A vault that cannot be read for some other reason is not a sign-in failure.
    struct Unreadable(FakeBw);
    #[async_trait]
    impl BwClient for Unreadable {
        async fn login(
            &mut self,
            a: &str,
            b: &str,
            c: &Region,
            d: Option<&str>,
        ) -> Result<LoginOutcome, BwError> {
            self.0.login(a, b, c, d).await
        }
        async fn login_with_api_key(
            &mut self,
            a: &str,
            b: &str,
            c: &str,
            d: &Region,
        ) -> Result<LoginOutcome, BwError> {
            self.0.login_with_api_key(a, b, c, d).await
        }
        async fn sync(&self) -> Result<(), BwError> {
            Ok(())
        }
        async fn list_logins(&self) -> Result<Vec<VaultLogin>, BwError> {
            Err(BwError::Cli(
                "unexpected output from `bw list items`".into(),
            ))
        }
        async fn import_folder_titles(&self) -> Result<Vec<String>, BwError> {
            Ok(vec![])
        }
        async fn set_totp(&self, _: &str, _: &str) -> Result<SetTotp, BwError> {
            Ok(SetTotp::Attached)
        }
        async fn create_in_import_folder(
            &self,
            _: &str,
            _: Option<&str>,
            _: &str,
        ) -> Result<(), BwError> {
            Ok(())
        }
        async fn logout_and_wipe(&mut self) -> Result<(), BwError> {
            Ok(())
        }
    }
    s.bw_login(Box::new(Unreadable(FakeBw::new())), login_input())
        .await
        .unwrap();
    for error in [
        s.bw_propose().await.unwrap_err(),
        s.bw_logins().await.unwrap_err(),
    ] {
        assert_eq!(error, CmdError(Reject::BwVaultReadFailed));
        assert_eq!(error.code().as_str(), "bw_vault_read_failed");
    }
}

/// A zip that holds one entry, `bw`, with `program` in it.
fn bw_zip(program: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut buffer = std::io::Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(&mut buffer);
    let stored =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    writer.start_file("bw", stored).unwrap();
    writer.write_all(program).unwrap();
    writer.finish().unwrap();
    buffer.into_inner()
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

/// Serve `body` to every request on a local port, announcing `length` bytes. With a `length`
/// larger than the body, the connection is then held open and silent. Returns the base URL.
async fn download_server(body: Vec<u8>, length: usize) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let body = body.clone();
            tokio::spawn(async move {
                let mut seen = Vec::new();
                while !seen.ends_with(b"\r\n\r\n") {
                    match sock.read_u8().await {
                        Ok(byte) => seen.push(byte),
                        Err(_) => return,
                    }
                }
                let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {length}\r\n\r\n");
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(&body).await;
                if length > body.len() {
                    tokio::time::sleep(Duration::from_secs(120)).await;
                }
                let _ = sock.shutdown().await;
            });
        }
    });
    format!("http://127.0.0.1:{port}")
}

fn collect_lines() -> (EmitProgress, Arc<Mutex<Vec<String>>>) {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&lines);
    (Arc::new(move |line| lock(&sink).push(line)), lines)
}

fn names_under(dir: &Path) -> Vec<String> {
    if dir.exists() {
        names_in(dir)
    } else {
        Vec::new()
    }
}

#[tokio::test]
async fn preparing_the_tool_reports_progress_in_plain_lines() {
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path());
    assert_eq!(
        s.new_cli_client().err(),
        Some(CmdError(Reject::BwNotPrepared))
    );
    // A megabyte and a half of "program".
    let program: Vec<u8> = (0..1_500_000u32).map(|i| (i % 251) as u8).collect();
    let zip = bw_zip(&program);
    let base = download_server(zip.clone(), zip.len()).await;
    s.tune_bw_download(&base, "bw-test.zip", &sha256_hex(&zip));

    let (progress, lines) = collect_lines();
    s.bw_prepare(progress).await.unwrap();
    assert_eq!(
        *lock(&lines),
        [
            "Downloading… 0 of 2 MB",
            "Downloading… 1 of 2 MB",
            "Checking the download",
            "Ready"
        ]
    );
    assert!(s.new_cli_client().is_ok());
    assert_eq!(names_in(&dir.path().join("bw-cli")), ["bw", "bw-test.zip"]);

    // Again, with the verified download still there: nothing to download.
    let (progress, lines) = collect_lines();
    s.bw_prepare(progress).await.unwrap();
    assert_eq!(*lock(&lines), ["Checking the download", "Ready"]);

    // A download that is not the file expected, and one that cannot be had at all, are
    // told apart by their codes.
    s.tune_bw_download(&base, "bw-other.zip", &sha256_hex(b"something else"));
    let mismatch = s.bw_prepare(no_progress()).await.unwrap_err();
    assert_eq!(mismatch, CmdError(Reject::BwChecksumMismatch));
    assert_eq!(mismatch.code().as_str(), "bw_checksum_mismatch");
    s.tune_bw_download("http://127.0.0.1:1", "bw-none.zip", &sha256_hex(b"x"));
    let unreachable = s.bw_prepare(no_progress()).await.unwrap_err();
    assert_eq!(unreachable.code().as_str(), "bw_download_failed");
    assert!(
        !unreachable.to_string().contains("127.0.0.1"),
        "no address in what the person is told: {unreachable}"
    );
    assert_eq!(names_in(&dir.path().join("bw-cli")), ["bw", "bw-test.zip"]);
}

#[tokio::test]
async fn a_download_or_a_sign_in_can_be_stopped_and_leaves_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let s = Arc::new(session(dir.path()));
    // With nothing under way, stopping is a no-op, as often as it is asked.
    s.bw_cancel().await;
    s.bw_cancel().await;

    // ---- a download that would never end by itself
    let base = download_server(vec![7u8; 1_572_864], 3 * 1024 * 1024).await;
    s.tune_bw_download(&base, "bw-test.zip", &sha256_hex(b"x"));
    let (progress, lines) = collect_lines();
    let preparing = {
        let s = Arc::clone(&s);
        tokio::spawn(async move { s.bw_prepare(progress).await })
    };
    let part = dir.path().join("bw-cli").join("bw-test.zip.part");
    for _ in 0..500 {
        if lock(&lines).iter().any(|l| l == "Downloading… 1 of 3 MB") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        part.exists(),
        "the download is under way: {:?}",
        lock(&lines)
    );
    tokio::time::timeout(Duration::from_secs(5), s.bw_cancel())
        .await
        .expect("stopping does not hang");
    // By the time the stop returns, the work is over and its leavings are gone.
    assert_eq!(
        names_under(&dir.path().join("bw-cli")),
        Vec::<String>::new()
    );
    let stopped = preparing.await.unwrap().unwrap_err();
    assert_eq!(stopped, CmdError(Reject::BwStopped));
    assert_eq!(stopped.code().as_str(), "bw_failed");
    assert_eq!(
        s.new_cli_client().err(),
        Some(CmdError(Reject::BwNotPrepared)),
        "nothing was prepared"
    );
    s.bw_cancel().await;

    // ---- a sign-in that would never end by itself
    let (bw, entered, _release) = FakeBw::new().held();
    let bw_data = dir.path().join("bw-data");
    let signing_in = {
        let s = Arc::clone(&s);
        let client = Box::new(bw.clone());
        tokio::spawn(async move { s.bw_login(client, login_input()).await })
    };
    entered.notified().await;
    std::fs::create_dir_all(&bw_data).unwrap();
    std::fs::write(bw_data.join("data.json"), b"{}").unwrap();
    tokio::time::timeout(Duration::from_secs(5), s.bw_cancel())
        .await
        .expect("stopping does not hang");
    assert!(bw.was_wiped(), "signed out and wiped");
    assert!(!bw_data.exists(), "its data folder is gone");
    assert!(s.bw.lock().await.is_none(), "no client is left behind");
    assert_eq!(
        signing_in.await.unwrap().unwrap_err(),
        CmdError(Reject::BwStopped)
    );
    s.bw_cancel().await;

    // A sign-in after a stopped one works as if nothing had happened.
    assert_eq!(
        s.bw_login(Box::new(FakeBw::new()), login_input())
            .await
            .unwrap(),
        BwLoginResult::Ok
    );
    // And stopping when the work has already finished changes nothing.
    s.bw_cancel().await;
    assert!(s.bw.lock().await.is_some());
}

#[tokio::test]
async fn the_downloaded_tool_is_removed_and_finish_leaves_the_data_folder_empty() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("app-data");
    std::fs::create_dir(&data).unwrap();
    let zip = bw_zip(b"#!/bin/sh\necho pretend bw\n");
    let base = download_server(zip.clone(), zip.len()).await;
    let prepared = || {
        let (base, hash, data) = (base.clone(), sha256_hex(&zip), data.clone());
        async move {
            let s = session(&data);
            s.tune_proxy(0, None);
            s.tune_bw_download(&base, "bw-test.zip", &hash);
            s.start_proxy(Some("127.0.0.1"), &loopback(), no_emit())
                .await
                .unwrap();
            s.bw_prepare(no_progress()).await.unwrap();
            std::fs::create_dir_all(data.join("bw-data")).unwrap();
            std::fs::write(data.join("bw-data").join("data.json"), b"{}").unwrap();
            assert_eq!(names_in(&data), ["bw-cli", "bw-data", "session.json"]);
            s
        }
    };

    // Cleanup removes the tool; finish then leaves nothing of the app's own making.
    let s = prepared().await;
    s.cleanup().await.unwrap();
    assert_eq!(
        names_in(&data),
        ["session.json"],
        "only the marker, until Finish"
    );
    assert_eq!(
        s.new_cli_client().err(),
        Some(CmdError(Reject::BwNotPrepared))
    );
    s.finish().await.unwrap();
    assert_eq!(names_in(&data), Vec::<String>::new());

    // Finish without a cleanup first does the same.
    let s = prepared().await;
    s.finish().await.unwrap();
    assert_eq!(names_in(&data), Vec::<String>::new());

    // Closing the app mid-flow removes the tool too; the marker stays for the next launch,
    // whose cleanup has nothing of Bitwarden's left to find.
    let s = prepared().await;
    s.on_exit();
    assert_eq!(names_in(&data), ["session.json"]);
    drop(s);

    // A launch after a crash (nothing was removed): the leftovers go at once, and the
    // resumed cleanup and finish leave the folder empty.
    std::fs::create_dir_all(data.join("bw-cli")).unwrap();
    std::fs::write(data.join("bw-cli").join("bw"), b"left by a crash").unwrap();
    std::fs::create_dir_all(data.join("bw-data")).unwrap();
    let resumed = session(&data);
    assert!(resumed.get_state(&loopback()).resume_cleanup);
    assert_eq!(names_in(&data), ["session.json"]);
    // Something puts the folder back before the cleanup runs: cleanup removes it itself.
    std::fs::create_dir_all(data.join("bw-cli")).unwrap();
    std::fs::write(data.join("bw-cli").join("bw"), b"again").unwrap();
    resumed.cleanup().await.unwrap();
    assert_eq!(names_in(&data), ["session.json"]);
    resumed.finish().await.unwrap();
    assert_eq!(names_in(&data), Vec::<String>::new());
}

#[cfg(unix)]
#[tokio::test]
async fn a_tool_that_cannot_be_removed_fails_the_cleanup_in_a_full_sentence() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path());
    s.ensure_ca().await.unwrap();
    // A folder that cannot be emptied: its owner may not write to it.
    let tool = dir.path().join("bw-cli");
    std::fs::create_dir_all(&tool).unwrap();
    std::fs::write(tool.join("bw"), b"x").unwrap();
    std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o500)).unwrap();

    let error = s.cleanup().await.unwrap_err();
    std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(error, CmdError(Reject::CleanupBwToolNotRemoved));
    assert_eq!(error.code().as_str(), "cleanup_failed");
    assert!(error.sentence().starts_with("The Bitwarden tool"));
    assert!(error.sentence().ends_with('.'));
    assert!(
        !error.to_string().contains(&*dir.path().to_string_lossy()),
        "no path in what the person is told"
    );
    // Finish refuses for the same reason, and goes through once the cause is gone.
    assert!(dir.path().join("session.json").exists());
    s.finish().await.unwrap();
    assert_eq!(names_in(dir.path()), Vec::<String>::new());
}
