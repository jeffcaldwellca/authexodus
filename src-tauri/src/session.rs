//! The one `Session` held in Tauri state, plus the resume marker file (package 2A).
//!
//! Everything here is generic over the core traits (`KeyStore`, `BwClient`) and free of Tauri,
//! so the tests run under `cargo test` with a `MemoryKeyStore` and a fake Bitwarden client.
//! Secrets (`Unlocked`, the Bitwarden client) live in memory only. Nothing in this file logs.

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use authexodus_core::backup::{self, BackupError};
use authexodus_core::bitwarden::{self, BwClient, CliClient, LoginOutcome};
use authexodus_core::ca::{Authority, KeyStore};
use authexodus_core::export::{self, ExportFile};
use authexodus_core::proxy::{self, ProxyConfig, ProxyEvent, ProxyHandle, TestUpstream};
use authexodus_core::totp;
use authexodus_core::types::{CapturedBackup, Unlocked};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::dto::*;
use crate::network::{self, Candidate};

/// Whether the certificate authority carries the name constraint (it may only issue for
/// `authy.com`). Batch 4 settles whether iOS accepts a constrained root; flip it here.
pub const CA_CONSTRAINED: bool = true;
/// Tried first; the proxy falls back to a free port by itself.
pub const PREFERRED_PORT: u16 = 8080;
/// The UI gets at most one `tlsRejected` in this window.
pub const TLS_DEBOUNCE: Duration = Duration::from_secs(2);

pub type EmitProxy = Arc<dyn Fn(ProxyEventDto) + Send + Sync>;
pub type EmitProgress = Arc<dyn Fn(String) + Send + Sync>;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

// ---------------------------------------------------------------------------------------------
// Files in the app data directory

#[derive(Debug, Clone)]
pub struct Paths {
    dir: PathBuf,
}

impl Paths {
    pub fn new(dir: PathBuf) -> Paths {
        Paths { dir }
    }
    /// `session.json`: holds only `{ "caCreated": true }`.
    pub fn marker(&self) -> PathBuf {
        self.dir.join("session.json")
    }
    /// Where the downloaded, verified `bw` binary lives. Kept between runs.
    pub fn bw_cli(&self) -> PathBuf {
        self.dir.join("bw-cli")
    }
    /// The CLI's own data (`BITWARDENCLI_APPDATA_DIR`): private, wiped at cleanup.
    pub fn bw_data(&self) -> PathBuf {
        self.dir.join("bw-data")
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Marker {
    ca_created: bool,
}

fn write_marker(paths: &Paths) -> Result<(), CmdError> {
    std::fs::create_dir_all(&paths.dir)
        .and_then(|()| {
            std::fs::write(
                paths.marker(),
                serde_json::to_vec(&Marker { ca_created: true }).unwrap_or_default(),
            )
        })
        .map_err(|e| CmdError::new(format!("could not write the session marker: {e}")))
}

fn marker_exists(paths: &Paths) -> bool {
    std::fs::read(paths.marker())
        .ok()
        .and_then(|b| serde_json::from_slice::<Marker>(&b).ok())
        .is_some_and(|m| m.ca_created)
}

fn remove_marker(paths: &Paths) -> Result<(), CmdError> {
    match std::fs::remove_file(paths.marker()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(CmdError::new(format!(
            "could not remove the session marker: {e}"
        ))),
    }
}

// ---------------------------------------------------------------------------------------------
// Proxy events: map to the UI's union, debounce `TlsRejected`

/// Maps core proxy events to the UI's and drops a `TlsRejected` that follows another within
/// [`TLS_DEBOUNCE`]. (The proxy sends one every time the device aborts a handshake.)
#[derive(Default)]
pub struct Bridge {
    last_tls_rejected: Option<Instant>,
}

impl Bridge {
    pub fn map(&mut self, event: &ProxyEvent, now: Instant) -> Option<ProxyEventDto> {
        if matches!(event, ProxyEvent::TlsRejected) {
            if let Some(last) = self.last_tls_rejected {
                if now.saturating_duration_since(last) < TLS_DEBOUNCE {
                    return None;
                }
            }
            self.last_tls_rejected = Some(now);
        }
        Some(ProxyEventDto::from(event))
    }
}

fn step_for(event: &ProxyEventDto) -> Option<Step> {
    match event {
        ProxyEventDto::DeviceConnected => Some(Step::Certificate),
        ProxyEventDto::TrustWorking => Some(Step::Authy),
        ProxyEventDto::BackupCaptured { .. } => Some(Step::Unlock),
        ProxyEventDto::TlsRejected
        | ProxyEventDto::AuthyError { .. }
        | ProxyEventDto::DeviceRefused => None,
    }
}

struct UiState {
    step: Step,
    device: Option<Device>,
}

/// Only ever moves the wizard forward: a late event cannot pull it back.
fn advance(ui: &Mutex<UiState>, to: Step) {
    let mut ui = lock(ui);
    if to > ui.step {
        ui.step = to;
    }
}

// ---------------------------------------------------------------------------------------------

struct ProxyRun {
    ip: Ipv4Addr,
    handle: ProxyHandle,
    bridge: JoinHandle<()>,
}

impl ProxyRun {
    async fn stop(self) {
        self.bridge.abort();
        self.handle.shutdown().await;
    }
}

/// Test seams for the proxy; production keeps the defaults.
struct ProxyTuning {
    port: u16,
    upstream: Option<TestUpstream>,
}

pub struct Session {
    store: Arc<dyn KeyStore>,
    paths: Paths,
    resume_cleanup: AtomicBool,
    ui: Arc<Mutex<UiState>>,
    authority: Mutex<Option<Arc<Authority>>>,
    proxy: tokio::sync::Mutex<Option<ProxyRun>>,
    tuning: Mutex<ProxyTuning>,
    unlocked: Mutex<Option<Arc<Unlocked>>>,
    bw_binary: Mutex<Option<PathBuf>>,
    bw: tokio::sync::Mutex<Option<Box<dyn BwClient>>>,
}

fn choose_ip(requested: Option<&str>, candidates: &[Candidate]) -> Result<Ipv4Addr, CmdError> {
    match requested.map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => {
            let ip: Ipv4Addr = s
                .parse()
                .map_err(|_| CmdError::new("That is not a valid network address."))?;
            if candidates.iter().any(|c| c.ip == ip) {
                Ok(ip)
            } else {
                Err(CmdError::new(
                    "That address is not one of this computer's network addresses.",
                ))
            }
        }
        None => network::default_ip(candidates).ok_or_else(|| {
            CmdError::new(
                "This computer does not seem to be on a network. Connect to the same Wi-Fi as the iPhone or iPad and try again.",
            )
        }),
    }
}

fn proxy_info(ip: Ipv4Addr, port: u16, candidates: &[Candidate]) -> ProxyInfo {
    let cert_url = format!("http://{ip}:{port}/");
    ProxyInfo {
        addresses: candidates
            .iter()
            .map(|c| AddressView {
                ip: c.ip.to_string(),
                label: c.label.clone(),
            })
            .collect(),
        ip: ip.to_string(),
        port,
        cert_qr_svg: export::qr_svg(&cert_url),
        cert_url,
        check_url: format!("https://{}/", proxy::CHECK_HOST),
    }
}

/// Seconds left in the current period and the code for every token. A token whose code cannot
/// be made is left out rather than shown wrong.
pub fn live_codes(unlocked: &Unlocked, unix_time: u64) -> Vec<LiveCode> {
    unlocked
        .tokens
        .iter()
        .filter_map(|t| {
            let code = totp::code(t.secret.expose(), t.digits, t.period, unix_time).ok()?;
            let period = u64::from(t.period.max(1));
            Some(LiveCode {
                id: t.id.clone(),
                code,
                seconds_left: (period - unix_time % period) as u32,
            })
        })
        .collect()
}

/// Write an export file readable by its owner only, even over an existing file.
pub fn write_owner_only(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    // `mode` only applies when the file is created; tighten one that already existed before
    // any secret goes in.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(bytes)?;
    file.flush()
}

impl Session {
    /// A session over `store`, keeping its files in `dir`. Reads the resume marker: a marker
    /// left by an earlier launch means the certificate may still be installed on a device.
    pub fn new(store: Arc<dyn KeyStore>, dir: PathBuf) -> Session {
        let paths = Paths::new(dir);
        let resume = marker_exists(&paths);
        Session {
            store,
            paths,
            resume_cleanup: AtomicBool::new(resume),
            ui: Arc::new(Mutex::new(UiState {
                step: if resume { Step::Cleanup } else { Step::Welcome },
                device: None,
            })),
            authority: Mutex::new(None),
            proxy: tokio::sync::Mutex::new(None),
            tuning: Mutex::new(ProxyTuning {
                port: PREFERRED_PORT,
                upstream: None,
            }),
            unlocked: Mutex::new(None),
            bw_binary: Mutex::new(None),
            bw: tokio::sync::Mutex::new(None),
        }
    }

    #[cfg(test)]
    pub(crate) fn tune_proxy(&self, port: u16, upstream: Option<TestUpstream>) {
        *lock(&self.tuning) = ProxyTuning { port, upstream };
    }

    pub fn get_state(&self) -> AppState {
        let ui = lock(&self.ui);
        AppState {
            step: ui.step,
            device: ui.device,
            resume_cleanup: self.resume_cleanup.load(Ordering::SeqCst),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    pub fn set_device(&self, device: Device) {
        lock(&self.ui).device = Some(device);
    }

    /// Create (or reuse) the certificate authority. The marker is written first, so a crash
    /// between the two can never leave a key behind that the next launch does not know about.
    fn ensure_ca(&self) -> Result<Arc<Authority>, CmdError> {
        let mut slot = lock(&self.authority);
        if let Some(ca) = slot.as_ref() {
            return Ok(Arc::clone(ca));
        }
        write_marker(&self.paths)?;
        let ca = Arc::new(
            Authority::load_or_create(&*self.store, CA_CONSTRAINED)
                .map_err(|e| CmdError::new(format!("could not create the certificate: {e}")))?,
        );
        *slot = Some(Arc::clone(&ca));
        Ok(ca)
    }

    /// Start the proxy on `requested` (or the default LAN address). Asking for the address it
    /// already listens on returns the running proxy; a different address restarts it.
    pub async fn start_proxy(
        &self,
        requested: Option<&str>,
        candidates: &[Candidate],
        emit: EmitProxy,
    ) -> Result<ProxyInfo, CmdError> {
        let ip = choose_ip(requested, candidates)?;
        let mut slot = self.proxy.lock().await;
        if let Some(run) = slot.as_ref() {
            if run.ip == ip {
                return Ok(proxy_info(ip, run.handle.port(), candidates));
            }
        }
        if let Some(old) = slot.take() {
            old.stop().await;
        }
        let ca = self.ensure_ca()?;
        let (port, upstream) = {
            let t = lock(&self.tuning);
            (t.port, t.upstream.clone())
        };
        let (tx, mut rx) = mpsc::unbounded_channel();
        let handle = proxy::start(
            ProxyConfig {
                listen_ip: IpAddr::V4(ip),
                preferred_port: port,
                upstream,
            },
            ca,
            tx,
        )
        .await
        .map_err(|e| CmdError::new(format!("could not start listening: {e}")))?;
        let ui = Arc::clone(&self.ui);
        let bridge = tokio::spawn(async move {
            let mut bridge = Bridge::default();
            while let Some(event) = rx.recv().await {
                if let Some(dto) = bridge.map(&event, Instant::now()) {
                    if let Some(step) = step_for(&dto) {
                        advance(&ui, step);
                    }
                    emit(dto);
                }
            }
        });
        advance(&self.ui, Step::Connect);
        let info = proxy_info(ip, handle.port(), candidates);
        *slot = Some(ProxyRun { ip, handle, bridge });
        Ok(info)
    }

    /// Decrypt `backup` with `password` and keep the result in memory.
    pub fn unlock_backup(
        &self,
        backup: &CapturedBackup,
        password: &str,
    ) -> Result<UnlockResult, CmdError> {
        if backup.tokens.is_empty() {
            return Err(CmdError::new("The backup has not arrived from Authy yet."));
        }
        match backup::unlock(backup, password) {
            Ok(unlocked) => {
                let summary = UnlockSummary::from(&unlocked);
                *lock(&self.unlocked) = Some(Arc::new(unlocked));
                advance(&self.ui, Step::Destination);
                Ok(UnlockResult::Summary(summary))
            }
            Err(BackupError::WrongPassword) => Ok(UnlockResult::Error {
                error: UnlockErrorKind::WrongPassword,
            }),
            Err(BackupError::Malformed(_)) => {
                Err(CmdError::new("The backup Authy sent could not be read."))
            }
        }
    }

    pub async fn unlock(&self, password: &str) -> Result<UnlockResult, CmdError> {
        let backup = match self.proxy.lock().await.as_ref() {
            Some(run) => run.handle.backup(),
            None => return Err(CmdError::new("The connection is not running.")),
        };
        self.unlock_backup(&backup, password)
    }

    fn unlocked(&self) -> Result<Arc<Unlocked>, CmdError> {
        lock(&self.unlocked)
            .clone()
            .ok_or_else(|| CmdError::new("The backup is not unlocked."))
    }

    pub fn token_qr(&self, id: &str) -> Result<String, CmdError> {
        let u = self.unlocked()?;
        let token = u
            .tokens
            .iter()
            .find(|t| t.id == id)
            .ok_or_else(|| CmdError::new("No such token."))?;
        Ok(export::qr_svg(&export::otpauth_uri(token)))
    }

    pub fn google_migration_qrs(&self) -> Result<Vec<String>, CmdError> {
        Ok(export::google_migration_qrs(&self.unlocked()?.tokens))
    }

    /// The file for `dest`, ready to be written where the person chooses.
    pub fn prepare_export(&self, dest: DestinationDto) -> Result<ExportFile, CmdError> {
        export::export(&self.unlocked()?.tokens, dest.into())
            .map_err(|e| CmdError::new(e.to_string()))
    }

    pub fn live_codes(&self) -> Result<Vec<LiveCode>, CmdError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let unlocked = self.unlocked()?;
        Ok(live_codes(&unlocked, now))
    }

    // ---- Bitwarden ----

    pub async fn bw_prepare(&self) -> Result<(), CmdError> {
        let binary = bitwarden::ensure_cli(&self.paths.bw_cli()).await?;
        *lock(&self.bw_binary) = Some(binary);
        Ok(())
    }

    pub fn new_cli_client(&self) -> Result<CliClient, CmdError> {
        let binary = lock(&self.bw_binary)
            .clone()
            .ok_or_else(|| CmdError::new("The Bitwarden tool has not been prepared yet."))?;
        Ok(CliClient::new(binary, self.paths.bw_data()))
    }

    /// Sign in with `client`. It is kept for the match and apply steps only on success; on any
    /// other outcome it is wiped so nothing is left in the Bitwarden data folder.
    pub async fn bw_login(
        &self,
        mut client: Box<dyn BwClient>,
        input: BwLoginInput,
    ) -> Result<BwLoginResult, CmdError> {
        let region = bitwarden::Region::from(input.region);
        let outcome = client
            .login(
                &input.email,
                &input.password,
                &region,
                input.two_factor_code.as_deref().filter(|c| !c.is_empty()),
            )
            .await;
        match outcome {
            Ok(LoginOutcome::Ok) => {
                *self.bw.lock().await = Some(client);
                Ok(BwLoginResult::Ok)
            }
            Ok(other) => {
                let _ = client.logout_and_wipe().await;
                Ok(match other {
                    LoginOutcome::NeedsTwoFactor => BwLoginResult::NeedsTwoFactor,
                    _ => BwLoginResult::BadCredentials,
                })
            }
            Err(e) => {
                let _ = client.logout_and_wipe().await;
                Err(e.into())
            }
        }
    }

    pub async fn bw_propose(&self) -> Result<Vec<ProposalDto>, CmdError> {
        let u = self.unlocked()?;
        let guard = self.bw.lock().await;
        let client = guard
            .as_deref()
            .ok_or_else(|| CmdError::new("You are not signed in to Bitwarden."))?;
        client.sync().await?;
        let vault = client.list_logins().await?;
        let proposals = bitwarden::propose(&u.tokens, &vault);
        Ok(join_proposals(&proposals, &vault))
    }

    pub async fn bw_apply(
        &self,
        decisions: Vec<DecisionEntry>,
        progress: EmitProgress,
    ) -> Result<ApplyReportDto, CmdError> {
        let u = self.unlocked()?;
        let guard = self.bw.lock().await;
        let client = guard
            .as_deref()
            .ok_or_else(|| CmdError::new("You are not signed in to Bitwarden."))?;
        let decisions: Vec<(String, bitwarden::Decision)> = decisions
            .into_iter()
            .map(|d| (d.token_id, d.decision.into()))
            .collect();
        let report = bitwarden::apply(client, &u.tokens, &decisions, &*progress).await;
        Ok(report.into())
    }

    // ---- end of the session ----

    /// Stop the proxy, destroy the certificate key, wipe the Bitwarden data, drop the secrets.
    ///
    /// Idempotent, and complete on a fresh launch that has nothing but the marker and a key in
    /// the store (the resume-after-quit path). Every step is tried even when an earlier one
    /// fails; the first failure is reported.
    pub async fn cleanup(&self) -> Result<(), CmdError> {
        let mut first_error: Option<CmdError> = None;
        let mut note = |e: CmdError| {
            first_error.get_or_insert(e);
        };

        if let Some(run) = self.proxy.lock().await.take() {
            run.stop().await;
        }
        lock(&self.authority).take();
        if let Err(e) = Authority::destroy(&*self.store) {
            note(CmdError::new(format!(
                "could not remove the certificate key: {e}"
            )));
        }
        if let Some(mut client) = self.bw.lock().await.take() {
            if let Err(e) = client.logout_and_wipe().await {
                note(e.into());
            }
        }
        // A previous launch may have left Bitwarden data with no client to wipe it.
        match tokio::fs::remove_dir_all(self.paths.bw_data()).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => note(CmdError::new(format!(
                "could not remove the Bitwarden data folder: {e}"
            ))),
        }
        lock(&self.unlocked).take();
        advance(&self.ui, Step::Cleanup);
        first_error.map_or(Ok(()), Err)
    }

    /// Clear the resume marker. If a key is somehow still in the store, clean up first; the
    /// marker stays when that fails, so the next launch offers cleanup again.
    pub async fn finish(&self) -> Result<(), CmdError> {
        if !matches!(self.store.load(), Ok(None)) {
            self.cleanup().await?;
        }
        remove_marker(&self.paths)?;
        self.resume_cleanup.store(false, Ordering::SeqCst);
        advance(&self.ui, Step::Done);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use authexodus_core::bitwarden::{BwError, Region, SetTotp, VaultLogin};
    use authexodus_core::ca::MemoryKeyStore;
    use authexodus_core::types::{EncryptedToken, Secret, Token};
    use std::sync::atomic::AtomicBool;

    fn session(dir: &Path, store: Arc<MemoryKeyStore>) -> Session {
        Session::new(store, dir.to_path_buf())
    }

    fn loopback() -> Vec<Candidate> {
        vec![Candidate {
            ip: Ipv4Addr::LOCALHOST,
            label: "Test".into(),
        }]
    }

    fn no_emit() -> EmitProxy {
        Arc::new(|_| {})
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

    fn unlocked_one() -> Unlocked {
        Unlocked {
            tokens: vec![Token {
                id: "1".into(),
                title: "Example".into(),
                name: "Example".into(),
                issuer: None,
                username: None,
                secret: Secret::new("JBSWY3DPEHPK3PXP".into()),
                digits: 6,
                period: 30,
            }],
            invalid: vec![],
            native: vec![],
        }
    }

    #[test]
    fn marker_makes_next_launch_resume_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(MemoryKeyStore::new());
        let first = session(dir.path(), store.clone());
        assert!(!first.get_state().resume_cleanup);
        assert_eq!(first.get_state().step, Step::Welcome);

        first.ensure_ca().unwrap();
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

    #[tokio::test]
    async fn finish_clears_the_marker_for_the_next_launch() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(MemoryKeyStore::new());
        let s = session(dir.path(), store.clone());
        s.ensure_ca().unwrap();
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
        s.ensure_ca().unwrap();
        s.finish().await.unwrap();
        assert_eq!(store.load().unwrap(), None);
    }

    struct FakeBw {
        wiped: Arc<AtomicBool>,
    }

    #[async_trait]
    impl BwClient for FakeBw {
        async fn login(
            &mut self,
            _: &str,
            _: &str,
            _: &Region,
            _: Option<&str>,
        ) -> Result<LoginOutcome, BwError> {
            Ok(LoginOutcome::Ok)
        }
        async fn sync(&self) -> Result<(), BwError> {
            Ok(())
        }
        async fn list_logins(&self) -> Result<Vec<VaultLogin>, BwError> {
            Ok(vec![VaultLogin {
                id: "item-1".into(),
                name: "Example".into(),
                username: None,
                hosts: vec!["example.com".into()],
                has_totp: false,
            }])
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
            self.wiped.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    fn login_input() -> BwLoginInput {
        serde_json::from_str(r#"{"email":"a@example.com","password":"pw","region":{"kind":"us"}}"#)
            .unwrap()
    }

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
        let wiped = Arc::new(AtomicBool::new(false));
        let result = s
            .bw_login(
                Box::new(FakeBw {
                    wiped: wiped.clone(),
                }),
                login_input(),
            )
            .await
            .unwrap();
        assert_eq!(result, BwLoginResult::Ok);
        std::fs::create_dir_all(dir.path().join("bw-data")).unwrap();

        s.cleanup().await.unwrap();

        assert_eq!(store.load().unwrap(), None, "the key is gone");
        assert!(s.proxy.lock().await.is_none(), "the proxy is stopped");
        assert!(lock(&s.unlocked).is_none(), "secrets are dropped");
        assert!(
            s.bw.lock().await.is_none(),
            "the Bitwarden client is dropped"
        );
        assert!(
            wiped.load(Ordering::SeqCst),
            "the Bitwarden session was wiped"
        );
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
            earlier.ensure_ca().unwrap();
        }
        std::fs::create_dir_all(dir.path().join("bw-data")).unwrap();
        std::fs::write(dir.path().join("bw-data").join("data.json"), b"{}").unwrap();

        let fresh = session(dir.path(), store.clone());
        assert!(fresh.get_state().resume_cleanup);
        fresh.cleanup().await.unwrap();
        fresh.finish().await.unwrap();

        assert_eq!(store.load().unwrap(), None);
        assert!(!dir.path().join("bw-data").exists());
        assert!(!dir.path().join("session.json").exists());
    }

    #[tokio::test]
    async fn start_proxy_reports_the_real_port_and_restarts_on_a_new_address() {
        let dir = tempfile::tempdir().unwrap();
        let s = session(dir.path(), Arc::new(MemoryKeyStore::new()));
        s.tune_proxy(0, None);
        let mut candidates = loopback();
        candidates.push(Candidate {
            ip: Ipv4Addr::UNSPECIFIED,
            label: "Other".into(),
        });

        let first = s
            .start_proxy(Some("127.0.0.1"), &candidates, no_emit())
            .await
            .unwrap();
        assert_ne!(first.port, 0);
        assert_eq!(first.cert_url, format!("http://127.0.0.1:{}/", first.port));
        assert_eq!(first.check_url, "https://authexodus-check.api.authy.com/");
        assert!(first.cert_qr_svg.starts_with("<?xml") || first.cert_qr_svg.contains("<svg"));
        assert_eq!(first.addresses.len(), 2);
        assert_eq!(s.get_state().step, Step::Connect);

        // Same address: the running proxy.
        let again = s
            .start_proxy(Some("127.0.0.1"), &candidates, no_emit())
            .await
            .unwrap();
        assert_eq!(again.port, first.port);

        // Different address: restarted there.
        let moved = s
            .start_proxy(Some("0.0.0.0"), &candidates, no_emit())
            .await
            .unwrap();
        assert_eq!(moved.ip, "0.0.0.0");

        // Not one of this computer's addresses.
        assert!(s
            .start_proxy(Some("8.8.8.8"), &candidates, no_emit())
            .await
            .is_err());
        assert!(s
            .start_proxy(Some("nonsense"), &candidates, no_emit())
            .await
            .is_err());
        s.cleanup().await.unwrap();
    }

    #[test]
    fn unlock_command_maps_wrong_password_to_error_variant() {
        let dir = tempfile::tempdir().unwrap();
        let s = session(dir.path(), Arc::new(MemoryKeyStore::new()));
        let result = s
            .unlock_backup(&fixture_backup(), "not the password")
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

    #[test]
    fn unlock_with_the_right_password_returns_the_summary_and_keeps_secrets_in_memory() {
        let dir = tempfile::tempdir().unwrap();
        let s = session(dir.path(), Arc::new(MemoryKeyStore::new()));
        let result = s.unlock_backup(&fixture_backup(), "hunter2").unwrap();
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["tokens"][0]["id"], "1");
        assert_eq!(json["tokens"][0]["username"], "jeff@example.com");
        assert_eq!(json["invalid"], serde_json::json!([]));
        assert_eq!(json["native"], serde_json::json!([]));
        assert!(!json.to_string().contains("JBSWY3DPEHPK3PXP"));
        assert_eq!(s.get_state().step, Step::Destination);

        let codes = s.live_codes().unwrap();
        assert_eq!(codes.len(), 1);
        assert_eq!(codes[0].code.len(), 6);
        assert!(s.token_qr("1").unwrap().contains("<svg"));
        assert!(s.token_qr("nope").is_err());
    }

    #[test]
    fn unlock_before_any_backup_is_an_error_not_a_wrong_password() {
        let dir = tempfile::tempdir().unwrap();
        let s = session(dir.path(), Arc::new(MemoryKeyStore::new()));
        assert!(s.unlock_backup(&CapturedBackup::default(), "x").is_err());
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

    #[test]
    fn export_file_is_written_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();

        let fresh = dir.path().join("fresh.csv");
        write_owner_only(&fresh, b"secret,data").unwrap();
        assert_eq!(std::fs::read(&fresh).unwrap(), b"secret,data");
        assert_eq!(
            std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o777,
            0o600
        );

        // Over a world-readable file the person chose to replace.
        let old = dir.path().join("old.csv");
        std::fs::write(&old, b"old and much longer content").unwrap();
        std::fs::set_permissions(&old, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_owner_only(&old, b"new").unwrap();
        assert_eq!(std::fs::read(&old).unwrap(), b"new");
        assert_eq!(
            std::fs::metadata(&old).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn export_prepares_the_files_and_refuses_google() {
        let dir = tempfile::tempdir().unwrap();
        let s = session(dir.path(), Arc::new(MemoryKeyStore::new()));
        assert!(
            s.prepare_export(DestinationDto::Bitwarden).is_err(),
            "locked"
        );
        s.unlock_backup(&fixture_backup(), "hunter2").unwrap();
        let f = s.prepare_export(DestinationDto::Bitwarden).unwrap();
        assert_eq!(f.suggested_name, "authy-bitwarden-import.csv");
        assert!(s
            .prepare_export(DestinationDto::GoogleAuthenticator)
            .is_err());
        assert_eq!(s.google_migration_qrs().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn propose_joins_candidates_against_the_vault() {
        let dir = tempfile::tempdir().unwrap();
        let s = session(dir.path(), Arc::new(MemoryKeyStore::new()));
        *lock(&s.unlocked) = Some(Arc::new(unlocked_one()));
        let wiped = Arc::new(AtomicBool::new(false));
        s.bw_login(Box::new(FakeBw { wiped }), login_input())
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
                vec![DecisionEntry {
                    token_id: "1".into(),
                    decision: DecisionDto::Attach {
                        item_id: "item-1".into(),
                    },
                }],
                Arc::new(move |l| lock(&sink).push(l)),
            )
            .await
            .unwrap();
        assert_eq!(report.attached, 1);
        assert!(!lock(&lines).is_empty());
        assert_eq!(report.failed, None);
    }

    #[tokio::test]
    async fn bw_login_that_needs_two_factor_keeps_no_client() {
        struct NeedsTwo(Arc<AtomicBool>);
        #[async_trait]
        impl BwClient for NeedsTwo {
            async fn login(
                &mut self,
                _: &str,
                _: &str,
                _: &Region,
                _: Option<&str>,
            ) -> Result<LoginOutcome, BwError> {
                Ok(LoginOutcome::NeedsTwoFactor)
            }
            async fn sync(&self) -> Result<(), BwError> {
                Ok(())
            }
            async fn list_logins(&self) -> Result<Vec<VaultLogin>, BwError> {
                Ok(vec![])
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
                self.0.store(true, Ordering::SeqCst);
                Ok(())
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let s = session(dir.path(), Arc::new(MemoryKeyStore::new()));
        let wiped = Arc::new(AtomicBool::new(false));
        let r = s
            .bw_login(Box::new(NeedsTwo(wiped.clone())), login_input())
            .await
            .unwrap();
        assert_eq!(
            serde_json::to_string(&r).unwrap(),
            r#"{"kind":"needsTwoFactor"}"#
        );
        assert!(s.bw.lock().await.is_none());
        assert!(wiped.load(Ordering::SeqCst));
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
        assert_eq!(l.two_factor_code.as_deref(), Some("123456"));
        let e: DecisionEntry =
            serde_json::from_str(r#"{"tokenId":"1","decision":{"kind":"skip"}}"#).unwrap();
        assert_eq!(e.decision, DecisionDto::Skip);
    }
}
