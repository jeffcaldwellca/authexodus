//! Tests of `session.rs`: a `MemoryKeyStore`, a fake Bitwarden client, a temporary directory and
//! loopback. Nothing here touches the Keychain, a real Bitwarden or the network beyond this
//! computer. All data is synthetic.

use super::*;
use async_trait::async_trait;
use authexodus_core::bitwarden::{BwError, Region, SetTotp, VaultLogin};
use authexodus_core::ca::{CaError, MemoryKeyStore};
use authexodus_core::types::{EncryptedToken, Secret, Token};
use std::sync::atomic::AtomicUsize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Notify;

fn session(dir: &Path, store: Arc<MemoryKeyStore>) -> Session {
    Session::new(store, dir.to_path_buf())
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
    let store = Arc::new(MemoryKeyStore::new());
    let first = session(dir.path(), store.clone());
    assert!(!first.get_state().resume_cleanup);
    assert_eq!(first.get_state().step, Step::Welcome);

    first.ensure_ca().await.unwrap();
    assert_eq!(
        std::fs::read_to_string(dir.path().join("session.json")).unwrap(),
        r#"{"caCreated":true}"#
    );
    drop(first); // the app quits without cleaning up

    let second = session(dir.path(), store);
    let state = second.get_state();
    assert!(state.resume_cleanup);
    assert_eq!(state.step, Step::Cleanup);
}

/// A key store that cannot store.
struct BrokenStore;

impl KeyStore for BrokenStore {
    fn load(&self) -> Result<Option<Vec<u8>>, CaError> {
        Ok(None)
    }
    fn store(&self, _: &[u8]) -> Result<(), CaError> {
        Err(CaError::Store("the keychain is locked".into()))
    }
    fn delete(&self) -> Result<(), CaError> {
        Ok(())
    }
}

#[tokio::test]
async fn a_key_that_could_not_be_stored_leaves_no_marker() {
    let dir = tempfile::tempdir().unwrap();
    let s = Session::new(Arc::new(BrokenStore), dir.path().to_path_buf());
    assert!(s.ensure_ca().await.is_err());
    assert!(
        !dir.path().join("session.json").exists(),
        "no marker claims a certificate that was never created"
    );
    assert!(
        !Session::new(Arc::new(BrokenStore), dir.path().to_path_buf())
            .get_state()
            .resume_cleanup
    );
}

#[tokio::test]
async fn a_marker_that_cannot_be_written_takes_the_key_with_it() {
    let dir = tempfile::tempdir().unwrap();
    // Something that is not a file sits where the marker goes.
    std::fs::create_dir(dir.path().join("session.json")).unwrap();
    let store = Arc::new(MemoryKeyStore::new());
    let s = session(dir.path(), store.clone());
    assert!(s.ensure_ca().await.is_err());
    assert_eq!(
        store.load().unwrap(),
        None,
        "no key is left that the next launch would not know about"
    );
    assert!(lock(&s.authority).is_none());
}

#[tokio::test]
async fn finish_clears_the_marker_for_the_next_launch() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemoryKeyStore::new());
    let s = session(dir.path(), store.clone());
    s.ensure_ca().await.unwrap();
    s.cleanup().await.unwrap();
    s.finish().await.unwrap();
    assert!(!s.get_state().resume_cleanup);
    assert!(!dir.path().join("session.json").exists());
    assert!(!session(dir.path(), store).get_state().resume_cleanup);
}

#[tokio::test]
async fn finish_without_cleanup_still_destroys_the_key() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemoryKeyStore::new());
    let s = session(dir.path(), store.clone());
    s.ensure_ca().await.unwrap();
    s.finish().await.unwrap();
    assert_eq!(store.load().unwrap(), None);
}

#[test]
fn state_carries_the_releases_address() {
    assert_eq!(
        RELEASES_URL,
        "https://github.com/jeffcaldwellca/authexodus/releases"
    );
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path(), Arc::new(MemoryKeyStore::new()));
    let json = serde_json::to_value(s.get_state()).unwrap();
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
        self.logins.fetch_add(1, Ordering::SeqCst);
        *lock(&self.code_sent) = code.map(str::to_owned);
        if let (Some(entered), Some(release)) = (&self.entered, &self.release) {
            entered.notify_one();
            release.notified().await;
        }
        match &self.error {
            Some(error) => Err(error.clone()),
            None => Ok(self.outcome),
        }
    }
    async fn sync(&self) -> Result<(), BwError> {
        Ok(())
    }
    async fn list_logins(&self) -> Result<Vec<VaultLogin>, BwError> {
        Ok(self.vault.clone())
    }
    async fn import_folder_titles(&self) -> Result<Vec<String>, BwError> {
        Ok(vec![])
    }
    async fn set_totp(&self, item: &str, _: &str) -> Result<SetTotp, BwError> {
        lock(&self.writes).push(format!("attach {item}"));
        Ok(SetTotp::Attached)
    }
    async fn create_in_import_folder(
        &self,
        title: &str,
        _: Option<&str>,
        _: &str,
    ) -> Result<(), BwError> {
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
async fn cleanup_destroys_key_and_drops_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemoryKeyStore::new());
    let s = session(dir.path(), store.clone());
    s.tune_proxy(0, None);

    s.start_proxy(Some("127.0.0.1"), &loopback(), no_emit())
        .await
        .unwrap();
    assert!(store.load().unwrap().is_some(), "the key is stored");
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

    assert_eq!(store.load().unwrap(), None, "the key is gone");
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
async fn cleanup_on_fresh_launch_with_only_marker_and_key() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemoryKeyStore::new());
    {
        let earlier = session(dir.path(), store.clone());
        earlier.ensure_ca().await.unwrap();
    }

    let fresh = session(dir.path(), store.clone());
    assert!(fresh.get_state().resume_cleanup);
    // Bitwarden data that turns up with no client to wipe it.
    std::fs::create_dir_all(dir.path().join("bw-data")).unwrap();
    std::fs::write(dir.path().join("bw-data").join("data.json"), b"{}").unwrap();
    fresh.cleanup().await.unwrap();
    fresh.finish().await.unwrap();

    assert_eq!(store.load().unwrap(), None);
    assert!(!dir.path().join("bw-data").exists());
    assert!(!dir.path().join("session.json").exists());
}

#[test]
fn a_launch_removes_bitwarden_data_an_earlier_one_left() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("bw-data")).unwrap();
    std::fs::write(dir.path().join("bw-data").join("data.json"), b"{}").unwrap();
    let _s = session(dir.path(), Arc::new(MemoryKeyStore::new()));
    assert!(!dir.path().join("bw-data").exists());
}

#[tokio::test]
async fn closing_the_app_mid_flow_stops_the_proxy_and_keeps_the_key_for_cleanup() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemoryKeyStore::new());
    let s = session(dir.path(), store.clone());
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

    // The key and the marker stay: the next launch opens on cleanup and finishes the job.
    assert!(store.load().unwrap().is_some());
    assert!(dir.path().join("session.json").exists());
    s.on_exit(); // twice is fine
    drop(s);
    let next = session(dir.path(), store.clone());
    assert!(next.get_state().resume_cleanup);
    assert_eq!(next.get_state().step, Step::Cleanup);
    next.cleanup().await.unwrap();
    next.finish().await.unwrap();
    assert_eq!(store.load().unwrap(), None);
}

// ---------------------------------------------------------------------------------------------
// Starting, moving and restarting the proxy (C1, C2, S10)

#[tokio::test]
async fn start_proxy_is_idempotent_and_moves_only_while_nothing_is_captured() {
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path(), Arc::new(MemoryKeyStore::new()));
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
    assert_eq!(s.get_state().step, Step::Connect);

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
    assert!(refused.0.contains("starting over"), "{}", refused.0);
    assert!(lock(&s.unlocked).is_some(), "what was unlocked is kept");
    let still = s.start_proxy(None, &net, no_emit()).await.unwrap();
    assert_eq!((still.ip.as_str(), still.port), ("127.0.0.1", back.port));
    s.cleanup().await.unwrap();
}

#[tokio::test]
async fn restart_proxy_starts_over_with_the_same_certificate() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemoryKeyStore::new());
    let s = session(dir.path(), store.clone());
    s.tune_proxy(0, None);
    let net = two_addresses();

    // Restarting with nothing running simply starts.
    let first = s
        .restart_proxy(Some("127.0.0.1"), &net, no_emit())
        .await
        .unwrap();
    assert_eq!(first.ip, "127.0.0.1");
    let certificate = s.ensure_ca().await.unwrap().cert_der();
    let key = store.load().unwrap();

    *lock(&s.unlocked) = Some(Arc::new(unlocked_one()));
    s.bw_login(Box::new(FakeBw::new()), login_input())
        .await
        .unwrap();
    s.bw_propose().await.unwrap();
    s.live_codes().unwrap();
    assert_eq!(s.get_state().step, Step::Verify);

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
    assert_eq!(s.get_state().step, Step::Connect, "back to connecting");
    assert_eq!(
        s.ensure_ca().await.unwrap().cert_der(),
        certificate,
        "the device keeps the certificate it installed"
    );
    assert_eq!(store.load().unwrap(), key);
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
    let s = session(dir.path(), Arc::new(MemoryKeyStore::new()));
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
    let s = session(dir.path(), Arc::new(MemoryKeyStore::new()));
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
    let s = session(dir.path(), Arc::new(MemoryKeyStore::new()));
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
    assert_eq!(s.get_state().step, Step::Destination);

    assert!(s.token_qr("1").unwrap().contains("<svg"));
    assert!(s.token_qr("nope").is_err());
    assert_eq!(s.get_state().step, Step::Destination);

    // Asking for the live codes is the Verify screen.
    let codes = s.live_codes().unwrap();
    assert_eq!(codes.len(), 1);
    assert_eq!(codes[0].code.len(), 6);
    assert_eq!(s.get_state().step, Step::Verify);
}

#[tokio::test]
async fn unlock_before_any_backup_is_an_error_not_a_wrong_password() {
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path(), Arc::new(MemoryKeyStore::new()));
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
    let s = session(dir.path(), Arc::new(MemoryKeyStore::new()));
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
    let s = session(dir.path(), Arc::new(MemoryKeyStore::new()));
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
    let s = session(dir.path(), Arc::new(MemoryKeyStore::new()));
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
    let s = session(dir.path(), Arc::new(MemoryKeyStore::new()));
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
    let s = session(dir.path(), Arc::new(MemoryKeyStore::new()));
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
async fn apply_refuses_what_was_never_offered_and_applies_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path(), Arc::new(MemoryKeyStore::new()));
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

    // Before any proposal there is nothing an attach could have been chosen from.
    assert!(s
        .bw_apply(vec![attach("1", "item-example")], no_progress())
        .await
        .is_err());

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

    let refused: Vec<Vec<DecisionEntry>> = vec![
        // A login that was in the vault but never a candidate for this token.
        vec![attach("1", "item-unrelated")],
        // A login that does not exist at all.
        vec![attach("1", "made-up")],
        // A candidate for another token.
        vec![attach("2", "item-example")],
        // A candidate that already has a code.
        vec![attach("2", "item-sample-full")],
        // A token that is not in the unlocked backup, whatever the decision.
        vec![decide("99", DecisionDto::CreateNew)],
        vec![decide("99", DecisionDto::Skip)],
        // One bad entry spoils the list: the good ones before it are not applied either.
        vec![
            attach("1", "item-example"),
            decide("2", DecisionDto::CreateNew),
            attach("1", "item-unrelated"),
        ],
    ];
    for decisions in refused {
        let described = format!("{decisions:?}");
        assert!(
            s.bw_apply(decisions, no_progress()).await.is_err(),
            "{described}"
        );
        assert_eq!(writes(), Vec::<String>::new(), "{described}");
    }

    // What was offered goes through.
    let report = s
        .bw_apply(
            vec![
                attach("1", "item-example"),
                decide("2", DecisionDto::CreateNew),
            ],
            no_progress(),
        )
        .await
        .unwrap();
    assert_eq!((report.attached, report.created), (1, 1));
    assert_eq!(writes(), ["attach item-example", "create Sample"]);

    // Running the same decisions again is still allowed (the apply itself is idempotent).
    assert!(s
        .bw_apply(vec![attach("1", "item-example")], no_progress())
        .await
        .is_ok());
}

#[tokio::test]
async fn bw_login_that_needs_two_factor_keeps_no_client() {
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path(), Arc::new(MemoryKeyStore::new()));
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
    let s = session(dir.path(), Arc::new(MemoryKeyStore::new()));
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
        lock(&s.proposals).is_none(),
        "proposals from the first vault are dropped"
    );
}

#[tokio::test]
async fn a_sign_in_that_finishes_after_cleanup_leaves_nothing_behind() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemoryKeyStore::new());
    let s = Arc::new(session(dir.path(), store));
    let (bw, entered, release) = FakeBw::new().held();
    let bw_data = dir.path().join("bw-data");

    let signing_in = {
        let s = Arc::clone(&s);
        let client = Box::new(bw.clone());
        tokio::spawn(async move { s.bw_login(client, login_input()).await })
    };
    entered.notified().await;
    // The Bitwarden tool has started filling its folder.
    std::fs::create_dir_all(&bw_data).unwrap();

    // Cleanup does not wait for the sign-in.
    tokio::time::timeout(Duration::from_secs(5), s.cleanup())
        .await
        .expect("cleanup does not wait for a sign-in")
        .unwrap();
    assert!(!bw_data.exists());

    // The sign-in then succeeds, and writes its session into the folder as it does.
    std::fs::create_dir_all(&bw_data).unwrap();
    std::fs::write(bw_data.join("data.json"), b"{}").unwrap();
    release.notify_one();
    let result = signing_in.await.unwrap();

    assert!(result.is_err(), "the sign-in reports that it was overtaken");
    assert!(s.bw.lock().await.is_none(), "no client is kept");
    assert!(bw.was_wiped(), "its session was signed out and wiped");
    assert!(!bw_data.exists(), "and its folder is gone");
}

#[tokio::test]
async fn sign_ins_run_one_at_a_time() {
    let dir = tempfile::tempdir().unwrap();
    let s = Arc::new(session(dir.path(), Arc::new(MemoryKeyStore::new())));
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

/// A key store whose deletion can be made to fail, as a Keychain item can refuse to go.
#[derive(Default)]
struct StubbornStore {
    inner: MemoryKeyStore,
    refuse_delete: AtomicBool,
    /// Whether the marker file existed at the moment the key was stored.
    marker_when_stored: Mutex<Vec<bool>>,
    marker: Mutex<Option<PathBuf>>,
}

impl KeyStore for StubbornStore {
    fn load(&self) -> Result<Option<Vec<u8>>, CaError> {
        self.inner.load()
    }
    fn store(&self, blob: &[u8]) -> Result<(), CaError> {
        if let Some(marker) = lock(&self.marker).as_ref() {
            lock(&self.marker_when_stored).push(marker.exists());
        }
        self.inner.store(blob)
    }
    fn delete(&self) -> Result<(), CaError> {
        // Like the Keychain: an item that is gone is deleted already, refusal or not.
        let present = self.inner.load()?.is_some();
        if present && self.refuse_delete.load(Ordering::SeqCst) {
            return Err(CaError::Store("User interaction is not allowed.".into()));
        }
        self.inner.delete()
    }
}

#[tokio::test]
async fn the_marker_is_on_disk_before_the_key_is_stored() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(StubbornStore::default());
    *lock(&store.marker) = Some(dir.path().join("session.json"));
    let s = Session::new(store.clone(), dir.path().to_path_buf());
    s.ensure_ca().await.unwrap();
    assert_eq!(
        *lock(&store.marker_when_stored),
        [true],
        "a crash between the two can only leave a marker without a key, never the reverse"
    );
}

#[tokio::test]
async fn a_key_that_will_not_go_is_reported_with_the_way_to_remove_it_by_hand() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(StubbornStore::default());
    let s = Session::new(store.clone(), dir.path().to_path_buf());
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
    store.refuse_delete.store(true, Ordering::SeqCst);

    let error = s.cleanup().await.unwrap_err().0;
    assert!(
        error.contains("(User interaction is not allowed)"),
        "the reason: {error}"
    );
    assert!(error.contains("Keychain Access"), "{error}");
    assert!(error.contains("\"dev.somecorp.authexodus\""), "{error}");
    assert_eq!(error, key_not_removed("User interaction is not allowed."));

    // Everything else was still done.
    assert!(s.proxy.lock().await.is_none(), "the proxy is stopped");
    assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, info.port))
        .await
        .is_err());
    assert!(bw.was_wiped());
    assert!(!dir.path().join("bw-data").exists(), "Bitwarden data wiped");
    assert!(lock(&s.unlocked).is_none());
    // Nothing can be finished while the key is there; the marker stays for the next launch.
    assert!(s.finish().await.is_err());
    assert!(dir.path().join("session.json").exists());

    // Once the person has removed it by hand, cleanup and finish go through.
    store.inner.delete().unwrap();
    s.cleanup().await.unwrap();
    s.finish().await.unwrap();
    assert!(!dir.path().join("session.json").exists());
}

#[tokio::test]
async fn sign_in_input_is_checked_before_the_tool_is_asked() {
    use authexodus_core::bitwarden::{BAD_EMAIL, BAD_SERVER_URL};
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path(), Arc::new(MemoryKeyStore::new()));
    let bw = FakeBw::new();
    for (input, message) in [
        (
            r#"{"email":"a@example.com","password":"pw","region":{"kind":"selfHosted","url":"http://vault.example.test"}}"#,
            BAD_SERVER_URL,
        ),
        (
            r#"{"email":"a@example.com","password":"pw","region":{"kind":"selfHosted","url":"https://me:pw@vault.example.test"}}"#,
            BAD_SERVER_URL,
        ),
        (
            r#"{"email":"--raw","password":"pw","region":{"kind":"us"}}"#,
            BAD_EMAIL,
        ),
        (
            r#"{"email":"nobody","password":"pw","region":{"kind":"eu"}}"#,
            BAD_EMAIL,
        ),
    ] {
        let input: BwLoginInput = serde_json::from_str(input).unwrap();
        let refused = s.bw_login(Box::new(bw.clone()), input).await.unwrap_err();
        assert_eq!(refused.0, message);
    }
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
    use authexodus_core::bitwarden::cli::{EMAIL_CODE_UNSUPPORTED, METHOD_UNSUPPORTED};
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path(), Arc::new(MemoryKeyStore::new()));
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

    // An account this app cannot sign in to: the message says why, word for word.
    for message in [EMAIL_CODE_UNSUPPORTED, METHOD_UNSUPPORTED] {
        let mut bw = FakeBw::new();
        bw.error = Some(BwError::Unsupported(message.into()));
        let error = s
            .bw_login(Box::new(bw.clone()), with_code())
            .await
            .unwrap_err();
        assert_eq!(error.0, message);
        assert!(bw.was_wiped());
    }
    assert!(s.bw.lock().await.is_none());
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
        let s = Session::with_ca_mode(
            Arc::new(MemoryKeyStore::new()),
            dir.path().to_path_buf(),
            constrained,
        );
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
        // The same certificate after a start-over, so the same fingerprint.
        let again = s.restart_proxy(None, &loopback(), no_emit()).await.unwrap();
        assert_eq!(again.cert_fingerprint, info.cert_fingerprint);
        s.cleanup().await.unwrap();
    }
}

#[tokio::test]
async fn the_proxy_never_listens_where_the_internet_can_reach_it() {
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path(), Arc::new(MemoryKeyStore::new()));
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
    assert_eq!(none.0, NO_LAN_ADDRESS);
    assert!(none.0.contains("not on a home or office Wi-Fi network"));
    let asked = s
        .start_proxy(Some("198.51.100.23"), &public_only, no_emit())
        .await
        .unwrap_err();
    assert_eq!(
        asked.0, PUBLIC_ADDRESS,
        "refused even when asked for by name"
    );
    let restart = s
        .restart_proxy(Some("198.51.100.23"), &public_only, no_emit())
        .await
        .unwrap_err();
    assert_eq!(restart.0, PUBLIC_ADDRESS);
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
    assert_eq!(not_ours.0, NOT_OUR_ADDRESS);
}

#[tokio::test]
async fn a_start_over_without_an_address_stays_on_the_one_in_use() {
    let dir = tempfile::tempdir().unwrap();
    let s = session(dir.path(), Arc::new(MemoryKeyStore::new()));
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

/// A key store that says which of its operations were used.
#[derive(Default)]
struct WatchedStore {
    inner: MemoryKeyStore,
    calls: Mutex<Vec<&'static str>>,
}

impl KeyStore for WatchedStore {
    fn load(&self) -> Result<Option<Vec<u8>>, CaError> {
        lock(&self.calls).push("load");
        self.inner.load()
    }
    fn store(&self, blob: &[u8]) -> Result<(), CaError> {
        lock(&self.calls).push("store");
        self.inner.store(blob)
    }
    fn delete(&self) -> Result<(), CaError> {
        lock(&self.calls).push("delete");
        self.inner.delete()
    }
}

#[tokio::test]
async fn a_stored_key_is_never_read_only_replaced_or_deleted() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(WatchedStore::default());
    // Something was in the store before the run began (planted, or left by a crash).
    store.inner.store(b"planted before the run").unwrap();

    // A new run: the old item is deleted and a new one made. It is not looked at.
    let s = Session::new(store.clone(), dir.path().to_path_buf());
    s.tune_proxy(0, None);
    s.start_proxy(Some("127.0.0.1"), &loopback(), no_emit())
        .await
        .unwrap();
    s.restart_proxy(None, &loopback(), no_emit()).await.unwrap();
    assert_eq!(*lock(&store.calls), ["delete", "store"]);
    assert_ne!(
        store.inner.load().unwrap().unwrap(),
        b"planted before the run"
    );
    s.on_exit();
    drop(s);

    // The next launch finds the marker. All it does with the key is delete it.
    lock(&store.calls).clear();
    let resumed = Session::new(store.clone(), dir.path().to_path_buf());
    assert!(resumed.get_state().resume_cleanup);
    resumed.cleanup().await.unwrap();
    resumed.finish().await.unwrap();
    assert_eq!(*lock(&store.calls), ["delete"]);
    assert_eq!(store.inner.load().unwrap(), None);

    // Finishing without having cleaned up deletes too, and still reads nothing.
    lock(&store.calls).clear();
    let again = Session::new(store.clone(), dir.path().to_path_buf());
    again.ensure_ca().await.unwrap();
    again.finish().await.unwrap();
    assert_eq!(*lock(&store.calls), ["delete", "store", "delete"]);
    assert_eq!(store.inner.load().unwrap(), None);
}
