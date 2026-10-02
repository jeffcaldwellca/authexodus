//! The one `Session` held in Tauri state, plus the resume marker file (package 2A).
//!
//! Everything here is generic over the core traits (`KeyStore`, `BwClient`) and free of Tauri,
//! so the tests run under `cargo test` with a `MemoryKeyStore` and a fake Bitwarden client.
//! Secrets (`Unlocked`, the Bitwarden client) live in memory only. Nothing in this file logs.

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
use zeroize::Zeroizing;

use crate::dto::*;
use crate::network::{self, Candidate, Network};

/// Whether the certificate authority carries the name constraint (it may only issue for
/// `authy.com`). Batch 4 settles whether iOS accepts a constrained root; flip it here.
pub const CA_CONSTRAINED: bool = true;
/// Tried first; the proxy falls back to a free port by itself.
pub const PREFERRED_PORT: u16 = 8080;
/// The UI gets at most one `tlsRejected` in this window.
pub const TLS_DEBOUNCE: Duration = Duration::from_secs(2);
/// Where new versions are published. There is no auto-update: the app shows this address.
pub const RELEASES_URL: &str = "https://github.com/jeffcaldwellca/authexodus/releases";

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
/// [`TLS_DEBOUNCE`]. (The proxy sends one every time the device aborts a handshake. It limits
/// `DeviceRefused` itself, to one every two seconds.)
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

    /// Has anything of the backup arrived on this run?
    fn has_capture(&self) -> bool {
        let backup = self.handle.backup();
        !backup.tokens.is_empty() || !backup.native_apps.is_empty()
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
    /// Counts the times the session's secrets were thrown away (start-over, cleanup, exit).
    /// Slow work that began before such a moment must not put anything back afterwards: an
    /// unlock or a Bitwarden sign-in notes the count when it starts and gives up if it moved.
    discards: AtomicU64,
    unlocked: Mutex<Option<Arc<Unlocked>>>,
    bw_binary: Mutex<Option<PathBuf>>,
    /// Held for the whole of a sign-in, so two never run against the one data folder.
    bw_signing_in: tokio::sync::Mutex<()>,
    bw: tokio::sync::Mutex<Option<Box<dyn BwClient>>>,
    /// The last proposals shown to the person: what `bw_apply` may attach to.
    proposals: Mutex<Option<Vec<ProposalDto>>>,
}

/// The address asked for, if one was.
fn parse_ip(requested: Option<&str>) -> Result<Option<Ipv4Addr>, CmdError> {
    match requested.map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => s
            .parse()
            .map(Some)
            .map_err(|_| CmdError::new("That is not a valid network address.")),
        None => Ok(None),
    }
}

fn choose_ip(requested: Option<Ipv4Addr>, candidates: &[Candidate]) -> Result<Ipv4Addr, CmdError> {
    match requested {
        Some(ip) if candidates.iter().any(|c| c.ip == ip) => Ok(ip),
        Some(_) => Err(CmdError::new(
            "That address is not one of this computer's network addresses.",
        )),
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

// ---------------------------------------------------------------------------------------------
// Writing an export file

/// Write an export file readable by its owner only, all or nothing.
///
/// The bytes go to a new file beside `path`, which is flushed to disk and then renamed over
/// `path`. So `path` either keeps what it had or holds the whole export, never part of one; a
/// file the person chose to replace is not touched until the new one is complete; and if
/// `path` is a symbolic link, the link is replaced rather than followed. Whatever goes wrong,
/// no partly written file with secrets in it is left behind.
pub fn write_owner_only(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    write_owner_only_with(path, |file| std::io::Write::write_all(file, bytes))
}

/// [`write_owner_only`] with the writing itself supplied, so a test can make it fail half-way.
pub(crate) fn write_owner_only_with(
    path: &Path,
    write: impl FnOnce(&mut std::fs::File) -> std::io::Result<()>,
) -> std::io::Result<()> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let name = path
        .file_name()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a file name"))?;
    let mut write = Some(write);
    // A name nobody else is using. `create_new` refuses a name that exists, link or not, so a
    // clash only costs another try.
    for _ in 0..16 {
        let mut temp_name = std::ffi::OsString::from(".");
        temp_name.push(name);
        temp_name.push(format!(
            ".{}-{}.authexodus-tmp",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let temp = path.with_file_name(temp_name);
        match write_via(path, &temp, &mut write) {
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && write.is_some() => continue,
            done => return done,
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not make a temporary file beside the chosen one",
    ))
}

/// Create `temp` (it must not exist: a symbolic link there is refused, not followed), fill it,
/// flush it to disk and rename it over `path`. `write` is taken only once `temp` is ours.
fn write_via<W>(path: &Path, temp: &Path, write: &mut Option<W>) -> std::io::Result<()>
where
    W: FnOnce(&mut std::fs::File) -> std::io::Result<()>,
{
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(temp)?;
    let filled = (|| {
        #[cfg(unix)]
        {
            // The mode asked for above is cut down by the umask but never widened; say it
            // again so it is exactly owner read and write.
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        let write = write
            .take()
            .ok_or_else(|| std::io::Error::other("the export was already written"))?;
        write(&mut file)?;
        file.sync_all()
    })();
    drop(file);
    let done = filled.and_then(|()| std::fs::rename(temp, path));
    if done.is_err() {
        let _ = std::fs::remove_file(temp);
        return done;
    }
    // Make the new name durable too. Not being able to is not a failed export.
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        if let Ok(dir) = std::fs::File::open(dir) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------

/// Is every decision one the person could have been offered? Every token must be one of the
/// unlocked ones, and a login may only be attached to a token it was proposed for, and only
/// when it had no code of its own. One bad entry refuses the whole list: nothing is applied.
fn check_decisions(
    decisions: &[DecisionEntry],
    unlocked: &Unlocked,
    proposals: Option<&[ProposalDto]>,
) -> Result<(), CmdError> {
    for entry in decisions {
        if !unlocked.tokens.iter().any(|t| t.id == entry.token_id) {
            return Err(CmdError::new(
                "One of the accounts to move is not in the unlocked backup. Nothing was changed.",
            ));
        }
        let DecisionDto::Attach { item_id } = &entry.decision else {
            continue;
        };
        let offered = proposals
            .into_iter()
            .flatten()
            .filter(|p| p.token_id == entry.token_id)
            .flat_map(|p| &p.candidates)
            .any(|c| &c.item_id == item_id && !c.has_code);
        if !offered {
            return Err(CmdError::new(
                "One of the chosen Bitwarden logins was not among the matches offered for that account, or already has a code. Nothing was changed.",
            ));
        }
    }
    Ok(())
}

impl Session {
    /// A session over `store`, keeping its files in `dir`. Reads the resume marker: a marker
    /// left by an earlier launch means the certificate may still be installed on a device.
    ///
    /// Bitwarden data left by an earlier launch is removed here: the key to it lived in that
    /// launch's memory, so it is of no use, and a launch that crashed never wiped it.
    pub fn new(store: Arc<dyn KeyStore>, dir: PathBuf) -> Session {
        let paths = Paths::new(dir);
        let resume = marker_exists(&paths);
        let _ = std::fs::remove_dir_all(paths.bw_data());
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
            discards: AtomicU64::new(0),
            unlocked: Mutex::new(None),
            bw_binary: Mutex::new(None),
            bw_signing_in: tokio::sync::Mutex::new(()),
            bw: tokio::sync::Mutex::new(None),
            proposals: Mutex::new(None),
        }
    }

    /// For tests: the port to try first, and a stand-in for Authy. The app never calls this,
    /// and could only ever pass `None`: a `TestUpstream` cannot be built without the core's
    /// `test-upstream` feature, which only test builds switch on.
    #[doc(hidden)]
    pub fn tune_proxy(&self, port: u16, upstream: Option<TestUpstream>) {
        *lock(&self.tuning) = ProxyTuning { port, upstream };
    }

    pub fn get_state(&self) -> AppState {
        let ui = lock(&self.ui);
        AppState {
            step: ui.step,
            device: ui.device,
            resume_cleanup: self.resume_cleanup.load(Ordering::SeqCst),
            version: env!("CARGO_PKG_VERSION").to_string(),
            releases_url: RELEASES_URL.to_string(),
        }
    }

    pub fn set_device(&self, device: Device) {
        lock(&self.ui).device = Some(device);
    }

    /// Create (or reuse) the certificate authority, then write the resume marker.
    ///
    /// The marker is written only once the key is stored, so a failure to create the key
    /// leaves no marker claiming there is one. If the marker cannot be written, the key is
    /// destroyed again: a key must never be left behind that the next launch does not know
    /// about.
    fn ensure_ca(&self) -> Result<Arc<Authority>, CmdError> {
        let mut slot = lock(&self.authority);
        if let Some(ca) = slot.as_ref() {
            return Ok(Arc::clone(ca));
        }
        let ca = Arc::new(
            Authority::load_or_create(&*self.store, CA_CONSTRAINED)
                .map_err(|e| CmdError::new(format!("could not create the certificate: {e}")))?,
        );
        if let Err(e) = write_marker(&self.paths) {
            if !marker_exists(&self.paths) {
                let _ = Authority::destroy(&*self.store);
            }
            return Err(e);
        }
        *slot = Some(Arc::clone(&ca));
        Ok(ca)
    }

    /// Make sure the proxy is running, on `requested` if an address is given.
    ///
    /// * Running already and no address given, or the address it is on: nothing changes; the
    ///   running proxy is described again.
    /// * Running on another address and nothing captured yet: it moves to the new address.
    /// * Running on another address with a backup captured (or unlocked): an error. Moving
    ///   would throw the backup away, and that only happens through [`Session::restart_proxy`].
    pub async fn start_proxy(
        &self,
        requested: Option<&str>,
        net: &Network,
        emit: EmitProxy,
    ) -> Result<ProxyInfo, CmdError> {
        let requested = parse_ip(requested)?;
        let mut slot = self.proxy.lock().await;
        if let Some(run) = slot.as_ref() {
            if requested.is_none_or(|ip| ip == run.ip) {
                return Ok(proxy_info(run.ip, run.handle.port(), &net.candidates));
            }
        }
        let ip = choose_ip(requested, &net.candidates)?;
        if let Some(run) = slot.as_ref() {
            if run.has_capture() || lock(&self.unlocked).is_some() {
                return Err(CmdError::new(
                    "A backup has already been captured on the current address. Changing the address means starting over.",
                ));
            }
        }
        if let Some(old) = slot.take() {
            old.stop().await;
        }
        let run = self.launch(ip, net, emit).await?;
        advance(&self.ui, Step::Connect);
        let info = proxy_info(ip, run.handle.port(), &net.candidates);
        *slot = Some(run);
        Ok(info)
    }

    /// Start over: stop the proxy, throw away the captured backup and anything unlocked from
    /// it, and start a fresh proxy on `requested` (or the default address) with the same
    /// certificate. A fresh proxy has no accepted device, so whichever iPhone or iPad
    /// completes a trusted connection next is accepted, under whatever address it has now.
    ///
    /// An address that cannot be used is refused before anything is thrown away. If the new
    /// proxy cannot start, the error is returned with the old one already gone.
    pub async fn restart_proxy(
        &self,
        requested: Option<&str>,
        net: &Network,
        emit: EmitProxy,
    ) -> Result<ProxyInfo, CmdError> {
        let ip = choose_ip(parse_ip(requested)?, &net.candidates)?;
        let mut slot = self.proxy.lock().await;
        self.discard_secrets();
        if let Some(old) = slot.take() {
            old.stop().await;
        }
        {
            // The one place the wizard goes back: the person asked to.
            let mut ui = lock(&self.ui);
            if ui.step > Step::Connect && ui.step < Step::Cleanup {
                ui.step = Step::Connect;
            }
        }
        let run = self.launch(ip, net, emit).await?;
        advance(&self.ui, Step::Connect);
        let info = proxy_info(ip, run.handle.port(), &net.candidates);
        *slot = Some(run);
        Ok(info)
    }

    /// Drop what was unlocked and what was proposed from it, and make sure an unlock or a
    /// sign-in still under way does not put anything back.
    fn discard_secrets(&self) {
        self.discards.fetch_add(1, Ordering::SeqCst);
        lock(&self.unlocked).take();
        lock(&self.proposals).take();
    }

    async fn launch(
        &self,
        ip: Ipv4Addr,
        net: &Network,
        emit: EmitProxy,
    ) -> Result<ProxyRun, CmdError> {
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
        // Every address this computer has, so that none of them can be reached through the
        // proxy on a device's behalf.
        handle.add_local_addresses(net.own.iter().copied());
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
        Ok(ProxyRun { ip, handle, bridge })
    }

    /// Decrypt `backup` with `password` and keep the result in memory.
    ///
    /// The key derivation (100,000 rounds for every token in a real backup) runs on the
    /// blocking pool, so the rest of the app keeps answering meanwhile. The password is wiped
    /// when the work is done.
    pub async fn unlock_backup(
        &self,
        backup: CapturedBackup,
        password: Zeroizing<String>,
    ) -> Result<UnlockResult, CmdError> {
        if backup.tokens.is_empty() {
            return Err(CmdError::new("The backup has not arrived from Authy yet."));
        }
        let discards = self.discards.load(Ordering::SeqCst);
        let outcome = tokio::task::spawn_blocking(move || backup::unlock(&backup, &password))
            .await
            .map_err(|_| CmdError::new("Unlocking the backup stopped unexpectedly."))?;
        match outcome {
            Ok(unlocked) => {
                let summary = UnlockSummary::from(&unlocked);
                {
                    let mut slot = lock(&self.unlocked);
                    if self.discards.load(Ordering::SeqCst) != discards {
                        return Err(CmdError::new(
                            "The session was started over while the backup was being unlocked.",
                        ));
                    }
                    *slot = Some(Arc::new(unlocked));
                }
                lock(&self.proposals).take();
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

    pub async fn unlock(&self, password: Zeroizing<String>) -> Result<UnlockResult, CmdError> {
        let backup = match self.proxy.lock().await.as_ref() {
            Some(run) => run.handle.backup(),
            None => return Err(CmdError::new("The connection is not running.")),
        };
        self.unlock_backup(backup, password).await
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

    /// Titles of the tokens the Google Authenticator QR codes cannot carry.
    pub fn google_unsupported(&self) -> Result<Vec<String>, CmdError> {
        Ok(export::google_unsupported(&self.unlocked()?.tokens))
    }

    /// The file for `dest`, ready to be written where the person chooses.
    pub fn prepare_export(&self, dest: DestinationDto) -> Result<ExportFile, CmdError> {
        export::export(&self.unlocked()?.tokens, dest.into())
            .map_err(|e| CmdError::new(e.to_string()))
    }

    /// The codes at `unix_time`. Asking for them is what the Verify screen does, so the
    /// tracked step moves there.
    pub fn live_codes_at(&self, unix_time: u64) -> Result<Vec<LiveCode>, CmdError> {
        let unlocked = self.unlocked()?;
        advance(&self.ui, Step::Verify);
        Ok(live_codes(&unlocked, unix_time))
    }

    pub fn live_codes(&self) -> Result<Vec<LiveCode>, CmdError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        self.live_codes_at(now)
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

    async fn wipe_bw_data(&self) -> Result<(), CmdError> {
        match tokio::fs::remove_dir_all(self.paths.bw_data()).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(CmdError::new(format!(
                "could not remove the Bitwarden data folder: {e}"
            ))),
        }
    }

    /// Sign in with `client`. It is kept for the match and apply steps only on success; on any
    /// other outcome it is wiped so nothing is left in the Bitwarden data folder.
    ///
    /// One sign-in runs at a time. A client kept from an earlier sign-in is signed out and
    /// wiped first. If the session is cleaned up (or started over, or the app is closing)
    /// while this sign-in is under way, its result is thrown away and wiped as well.
    pub async fn bw_login(
        &self,
        mut client: Box<dyn BwClient>,
        input: BwLoginInput,
    ) -> Result<BwLoginResult, CmdError> {
        let _one_at_a_time = self.bw_signing_in.lock().await;
        let discards = self.discards.load(Ordering::SeqCst);
        let previous = self.bw.lock().await.take();
        if let Some(mut previous) = previous {
            let _ = previous.logout_and_wipe().await;
        }
        lock(&self.proposals).take();

        let region = bitwarden::Region::from(input.region);
        let outcome = client
            .login(
                &input.email,
                &input.password,
                &region,
                input
                    .two_factor_code
                    .as_deref()
                    .map(String::as_str)
                    .filter(|c| !c.is_empty()),
            )
            .await;
        match outcome {
            Ok(LoginOutcome::Ok) => {
                let mut slot = self.bw.lock().await;
                if self.discards.load(Ordering::SeqCst) != discards {
                    drop(slot);
                    let _ = client.logout_and_wipe().await;
                    let _ = self.wipe_bw_data().await;
                    return Err(CmdError::new(
                        "The session was cleaned up while signing in to Bitwarden.",
                    ));
                }
                *slot = Some(client);
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
        let proposals = join_proposals(&bitwarden::propose(&u.tokens, &vault), &vault);
        *lock(&self.proposals) = Some(proposals.clone());
        Ok(proposals)
    }

    /// Apply the person's decisions. They are checked against the last proposals first (see
    /// [`check_decisions`]); if any does not hold, nothing at all is applied.
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
        check_decisions(&decisions, &u, lock(&self.proposals).as_deref())?;
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

        // First, so that an unlock or a sign-in still under way gives up when it finishes.
        self.discard_secrets();
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
        if let Err(e) = self.wipe_bw_data().await {
            note(e);
        }
        advance(&self.ui, Step::Cleanup);
        first_error.map_or(Ok(()), Err)
    }

    /// The app is closing before the person reached cleanup. Stop the proxy and remove what
    /// Bitwarden left on disk; keep the certificate key and the marker, so the next launch
    /// opens on cleanup and finishes the job. Never waits: whatever is busy is skipped, and
    /// the process ending takes care of what is in memory.
    pub fn on_exit(&self) {
        self.discard_secrets();
        if let Ok(mut slot) = self.proxy.try_lock() {
            if let Some(run) = slot.take() {
                run.bridge.abort();
                drop(run.handle); // dropping the handle stops the proxy
            }
        }
        if let Ok(mut slot) = self.bw.try_lock() {
            slot.take();
        }
        let _ = std::fs::remove_dir_all(self.paths.bw_data());
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
#[path = "session_tests.rs"]
mod tests;
