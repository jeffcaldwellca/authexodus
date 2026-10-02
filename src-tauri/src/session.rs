//! The one `Session` held in Tauri state, plus the resume marker file (package 2A).
//!
//! Everything here is generic over the core traits (`KeyStore`, `BwClient`) and free of Tauri,
//! so the tests run under `cargo test` with a `MemoryKeyStore` and a fake Bitwarden client.
//! Secrets (`Unlocked`, the Bitwarden client) live in memory only.
//!
//! What this file logs (see `crate::logging` for where it goes): the stages of the session
//! and their failures, with counts and kinds only. Never a password, a key, a one-time code,
//! a token or login name, an email address, a file path, or anything about the device's
//! traffic beyond what the proxy itself logs.

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use authexodus_core::backup::{self, BackupError};
use authexodus_core::bitwarden::{self, BwClient, CliBinary, CliClient, LoginOutcome};
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
use crate::keychain::KEYCHAIN_SERVICE;
use crate::logging::{bw_error_kind, sanitised};
use crate::network::{self, Candidate, Network};

/// Whether the certificate authority carries the name constraint (it may only issue for
/// `authy.com`), unless [`UNCONSTRAINED_ENV`] says otherwise for one launch.
pub const CA_CONSTRAINED: bool = true;
/// Set to `1` in the environment the app is launched from to make the certificate authority
/// unconstrained for that launch. For the real-device test only, in case iOS refuses the
/// constrained root: an unconstrained root can vouch for any site to a device that trusts it,
/// so the app must not then say the certificate is good for Authy alone.
pub const UNCONSTRAINED_ENV: &str = "AUTHEXODUS_UNCONSTRAINED_CA";

/// The certificate-authority mode for a launch, given the value of [`UNCONSTRAINED_ENV`]:
/// constrained unless that is exactly `1`.
pub fn ca_constrained(env_value: Option<&str>) -> bool {
    CA_CONSTRAINED && env_value.map(str::trim) != Some("1")
}
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
    /// The fingerprint of the certificate this run serves.
    fingerprint: String,
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
    /// Whether the certificate authority of this launch carries the name constraint.
    constrained: bool,
    paths: Paths,
    resume_cleanup: AtomicBool,
    /// Set when a cleanup has run to the end without a failure and nothing has been created
    /// since: there is then nothing left for [`Session::finish`] to remove.
    cleaned: AtomicBool,
    ui: Arc<Mutex<UiState>>,
    authority: Mutex<Option<Arc<Authority>>>,
    proxy: tokio::sync::Mutex<Option<ProxyRun>>,
    /// The address the proxy last ran on: where a start-over goes when none is named.
    last_ip: Mutex<Option<Ipv4Addr>>,
    tuning: Mutex<ProxyTuning>,
    /// Counts the times the session's secrets were thrown away (start-over, cleanup, exit).
    /// Slow work that began before such a moment must not put anything back afterwards: an
    /// unlock or a Bitwarden sign-in notes the count when it starts and gives up if it moved.
    discards: AtomicU64,
    unlocked: Mutex<Option<Arc<Unlocked>>>,
    bw_binary: Mutex<Option<CliBinary>>,
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

/// Shown when no address was asked for and this computer has no private (home or office)
/// network address to default to.
pub const NO_LAN_ADDRESS: &str = "This computer is not on a home or office Wi-Fi network. Connect it to the same Wi-Fi as the iPhone or iPad and try again.";
/// Shown when the address asked for is a public one.
pub const PUBLIC_ADDRESS: &str = "That address is reachable from the internet, so the connection cannot be opened on it. Use this computer's address on your home or office Wi-Fi.";
/// Shown when the address asked for is not one of this computer's.
pub const NOT_OUR_ADDRESS: &str = "That address is not one of this computer's network addresses.";

/// The address to listen on. One that was asked for must be one of this computer's and must
/// not be a public address; with none asked for, only a private (RFC 1918) address is ever
/// chosen, and with none of those there is no default at all.
fn choose_ip(requested: Option<Ipv4Addr>, candidates: &[Candidate]) -> Result<Ipv4Addr, CmdError> {
    match requested {
        Some(ip) if network::is_public(ip) => Err(CmdError::new(PUBLIC_ADDRESS)),
        Some(ip) if candidates.iter().any(|c| c.ip == ip) => Ok(ip),
        Some(_) => Err(CmdError::new(NOT_OUR_ADDRESS)),
        None => network::default_ip(candidates).ok_or_else(|| CmdError::new(NO_LAN_ADDRESS)),
    }
}

fn proxy_info(run: &ProxyRun, candidates: &[Candidate]) -> ProxyInfo {
    let (ip, port) = (run.ip, run.handle.port());
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
        cert_fingerprint: run.fingerprint.clone(),
    }
}

/// The kind of a proxy event, for the log.
fn event_kind(event: &ProxyEvent) -> &'static str {
    match event {
        ProxyEvent::DeviceConnected => "deviceConnected",
        ProxyEvent::TrustWorking => "trustWorking",
        ProxyEvent::TlsRejected => "tlsRejected",
        ProxyEvent::BackupCaptured { .. } => "backupCaptured",
        ProxyEvent::AuthyError { .. } => "authyError",
        ProxyEvent::DeviceRefused => "deviceRefused",
    }
}

/// One log line for each event the proxy reports, whether or not it is passed on to the
/// screen. Counts, a status and the already-redacted path; nothing else.
fn log_event(event: &ProxyEvent, forwarded: bool) {
    let kind = event_kind(event);
    match event {
        ProxyEvent::BackupCaptured { count } => {
            tracing::info!(kind = %kind, count, forwarded, "proxy event")
        }
        ProxyEvent::AuthyError { status, path } => {
            tracing::info!(kind = %kind, status, %path, forwarded, "proxy event")
        }
        _ => tracing::info!(kind = %kind, forwarded, "proxy event"),
    }
}

/// Seconds left in the current period and the code for every token, both worked out from the
/// one instant `unix_time`, so the count is always the time left on the very code beside it:
/// `secondsLeft` runs from the period (30) down to 1 and a new code starts at the top. A
/// token whose code cannot be made is left out rather than shown wrong.
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
    ///
    /// The certificate authority is constrained unless [`UNCONSTRAINED_ENV`] is set to `1`.
    pub fn new(store: Arc<dyn KeyStore>, dir: PathBuf) -> Session {
        let constrained = ca_constrained(std::env::var(UNCONSTRAINED_ENV).ok().as_deref());
        Session::with_ca_mode(store, dir, constrained)
    }

    /// [`Session::new`] with the certificate-authority mode given rather than read from the
    /// environment.
    pub fn with_ca_mode(store: Arc<dyn KeyStore>, dir: PathBuf, constrained: bool) -> Session {
        let paths = Paths::new(dir);
        let resume = marker_exists(&paths);
        let _ = std::fs::remove_dir_all(paths.bw_data());
        if constrained {
            tracing::info!(resume_cleanup = resume, constrained, "session ready");
        } else {
            tracing::warn!(
                resume_cleanup = resume,
                constrained,
                "UNCONSTRAINED CERTIFICATE AUTHORITY: {UNCONSTRAINED_ENV}=1 is set. The \
                 certificate this launch creates can vouch for ANY site to a device that \
                 trusts it, not only Authy. Use it for the device test only, and remove the \
                 certificate from the device afterwards."
            );
        }
        Session {
            store,
            constrained,
            paths,
            resume_cleanup: AtomicBool::new(resume),
            cleaned: AtomicBool::new(false),
            ui: Arc::new(Mutex::new(UiState {
                step: if resume { Step::Cleanup } else { Step::Welcome },
                device: None,
            })),
            authority: Mutex::new(None),
            proxy: tokio::sync::Mutex::new(None),
            last_ip: Mutex::new(None),
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

    /// Whether this launch's certificate authority carries the name constraint.
    pub fn ca_is_constrained(&self) -> bool {
        self.constrained
    }

    /// The certificate authority of this launch, created the first time it is asked for.
    ///
    /// The resume marker is written first and the key created second, so that a crash at any
    /// moment leaves at worst a marker without a key (the next launch offers a cleanup that
    /// has nothing to remove), never a key the next launch does not know about. If the key
    /// cannot be created, the marker written here is taken away again.
    ///
    /// The key store is never read: whatever it holds is deleted and a new key is stored (see
    /// [`Authority::create_fresh`]). The store may block on a system prompt, so it is called
    /// on the blocking pool.
    async fn ensure_ca(&self) -> Result<Arc<Authority>, CmdError> {
        if let Some(ca) = lock(&self.authority).as_ref() {
            return Ok(Arc::clone(ca));
        }
        let had_marker = marker_exists(&self.paths);
        self.cleaned.store(false, Ordering::SeqCst);
        write_marker(&self.paths)?;
        let (store, constrained) = (Arc::clone(&self.store), self.constrained);
        let created =
            tokio::task::spawn_blocking(move || Authority::create_fresh(&*store, constrained))
                .await
                .map_err(|_| "the key store stopped unexpectedly".to_string())
                .and_then(|made| made.map_err(|e| e.to_string()));
        let ca = match created {
            Ok(ca) => Arc::new(ca),
            Err(reason) => {
                if !had_marker {
                    let _ = remove_marker(&self.paths);
                }
                tracing::error!(error = %reason, "the certificate authority could not be created");
                return Err(CmdError::new(format!(
                    "could not create the certificate: {reason}"
                )));
            }
        };
        if ca.is_constrained() {
            tracing::info!(
                constrained = true,
                fingerprint = %ca.fingerprint(),
                "certificate authority created"
            );
        } else {
            tracing::warn!(
                constrained = false,
                fingerprint = %ca.fingerprint(),
                "certificate authority created WITHOUT the name constraint"
            );
        }
        *lock(&self.authority) = Some(Arc::clone(&ca));
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
                return Ok(proxy_info(run, &net.candidates));
            }
        }
        let ip = choose_ip(requested, &net.candidates).inspect_err(
            |e| tracing::warn!(error = %e, asked = requested.is_some(), "no address to listen on"),
        )?;
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
        let info = proxy_info(&run, &net.candidates);
        *slot = Some(run);
        Ok(info)
    }

    /// Start over: stop the proxy, throw away the captured backup and anything unlocked from
    /// it, and start a fresh proxy with the same certificate on `requested`, or, when no
    /// address is given, on the address the proxy is (or last was) on, so that the iPhone or
    /// iPad only has to reconnect. Only with no earlier address is the default chosen. A fresh proxy has no accepted device, so whichever iPhone or iPad
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
        let requested = parse_ip(requested)?;
        let mut slot = self.proxy.lock().await;
        let current = slot.as_ref().map(|run| run.ip).or(*lock(&self.last_ip));
        let ip = choose_ip(requested.or(current), &net.candidates).inspect_err(
            |e| tracing::warn!(error = %e, asked = requested.is_some(), "no address to listen on"),
        )?;
        tracing::info!("starting over: the capture and anything unlocked are discarded");
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
        let info = proxy_info(&run, &net.candidates);
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
        let ca = self.ensure_ca().await?;
        let fingerprint = ca.fingerprint();
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
        .map_err(|e| {
            tracing::error!(address = %ip, error = %e, "the proxy could not start");
            CmdError::new(format!("could not start listening: {e}"))
        })?;
        // Every address this computer has, so that none of them can be reached through the
        // proxy on a device's behalf.
        handle.add_local_addresses(net.own.iter().copied());
        *lock(&self.last_ip) = Some(ip);
        tracing::info!(
            address = %ip,
            port = handle.port(),
            constrained = self.constrained,
            "proxy started"
        );
        let ui = Arc::clone(&self.ui);
        let bridge = tokio::spawn(async move {
            let mut bridge = Bridge::default();
            while let Some(event) = rx.recv().await {
                let dto = bridge.map(&event, Instant::now());
                log_event(&event, dto.is_some());
                if let Some(dto) = dto {
                    if let Some(step) = step_for(&dto) {
                        advance(&ui, step);
                    }
                    emit(dto);
                }
            }
        });
        Ok(ProxyRun {
            ip,
            handle,
            bridge,
            fingerprint,
        })
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
            tracing::info!("unlock asked for before any backup was captured");
            return Err(CmdError::new("The backup has not arrived from Authy yet."));
        }
        tracing::info!(
            tokens = backup.tokens.len(),
            native = backup.native_apps.len(),
            "unlock attempted"
        );
        let started = Instant::now();
        let discards = self.discards.load(Ordering::SeqCst);
        let outcome = tokio::task::spawn_blocking(move || backup::unlock(&backup, &password))
            .await
            .map_err(|_| {
                tracing::error!("unlock failed: the work stopped unexpectedly");
                CmdError::new("Unlocking the backup stopped unexpectedly.")
            })?;
        let took_ms = started.elapsed().as_millis() as u64;
        match outcome {
            Ok(unlocked) => {
                tracing::info!(
                    tokens = unlocked.tokens.len(),
                    invalid = unlocked.invalid.len(),
                    native = unlocked.native.len(),
                    took_ms,
                    "unlock succeeded"
                );
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
            Err(BackupError::WrongPassword) => {
                tracing::info!(took_ms, "unlock failed: wrong password");
                Ok(UnlockResult::Error {
                    error: UnlockErrorKind::WrongPassword,
                })
            }
            Err(BackupError::Malformed(_)) => {
                tracing::warn!(took_ms, "unlock failed: the backup could not be read");
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

    /// Download (or reuse) and verify the Bitwarden tool. The program is extracted afresh
    /// from the verified download every time, and its hash is kept for [`new_cli_client`].
    ///
    /// [`new_cli_client`]: Session::new_cli_client
    pub async fn bw_prepare(&self) -> Result<(), CmdError> {
        tracing::info!("bitwarden: preparing the tool");
        let binary = bitwarden::ensure_cli(&self.paths.bw_cli())
            .await
            .inspect_err(|e| log_bw_failure("prepare", e))?;
        *lock(&self.bw_binary) = Some(binary);
        tracing::info!("bitwarden: the tool is ready");
        Ok(())
    }

    /// A client for the prepared tool. It refuses to sign in if the program is no longer the
    /// file that was extracted from the verified download.
    pub fn new_cli_client(&self) -> Result<CliClient, CmdError> {
        let binary = lock(&self.bw_binary)
            .clone()
            .ok_or_else(|| CmdError::new("The Bitwarden tool has not been prepared yet."))?;
        Ok(CliClient::new(binary.path, self.paths.bw_data()).expecting_sha256(binary.sha256))
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
    ///
    /// The email and the server address are checked here before anything is done with them
    /// (see [`bitwarden::check_login_input`]); what the screen checked does not count. An
    /// account that signs in in a way this app cannot do is an error whose message says so.
    pub async fn bw_login(
        &self,
        mut client: Box<dyn BwClient>,
        input: BwLoginInput,
    ) -> Result<BwLoginResult, CmdError> {
        let region = bitwarden::Region::from(input.region);
        let email = input.email.trim();
        let code = input
            .two_factor_code
            .as_deref()
            .map(|code| code.trim())
            .filter(|code| !code.is_empty());
        let region_kind = match &region {
            bitwarden::Region::Us => "us",
            bitwarden::Region::Eu => "eu",
            bitwarden::Region::SelfHosted(_) => "selfHosted",
        };
        bitwarden::check_login_input(email, &region)
            .inspect_err(|e| log_bw_failure("sign-in", e))?;
        tracing::info!(
            region = %region_kind,
            with_code = code.is_some(),
            "bitwarden: signing in"
        );
        let _one_at_a_time = self.bw_signing_in.lock().await;
        let discards = self.discards.load(Ordering::SeqCst);
        let previous = self.bw.lock().await.take();
        if let Some(mut previous) = previous {
            let _ = previous.logout_and_wipe().await;
        }
        lock(&self.proposals).take();

        let outcome = client.login(email, &input.password, &region, code).await;
        match &outcome {
            Ok(outcome) => tracing::info!(outcome = ?outcome, "bitwarden: sign-in answered"),
            Err(e) => log_bw_failure("sign-in", e),
        }
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
                    // "Needs a code" is only ever the answer when none was sent.
                    LoginOutcome::NeedsTwoFactor if code.is_none() => BwLoginResult::NeedsTwoFactor,
                    LoginOutcome::NeedsTwoFactor | LoginOutcome::BadTwoFactorCode => {
                        BwLoginResult::BadTwoFactorCode
                    }
                    LoginOutcome::BadCredentials | LoginOutcome::Ok => {
                        BwLoginResult::BadCredentials
                    }
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
        client
            .sync()
            .await
            .inspect_err(|e| log_bw_failure("sync", e))?;
        let vault = client
            .list_logins()
            .await
            .inspect_err(|e| log_bw_failure("list", e))?;
        let proposals = join_proposals(&bitwarden::propose(&u.tokens, &vault), &vault);
        tracing::info!(
            tokens = u.tokens.len(),
            logins = vault.len(),
            attach = proposals
                .iter()
                .filter(|p| matches!(p.decision, DecisionDto::Attach { .. }))
                .count(),
            questions = proposals
                .iter()
                .filter(|p| p.confidence == ConfidenceDto::Low)
                .count(),
            "bitwarden: matches proposed"
        );
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
        check_decisions(&decisions, &u, lock(&self.proposals).as_deref())
            .inspect_err(|_| tracing::warn!("bitwarden: the decisions were refused"))?;
        let decisions: Vec<(String, bitwarden::Decision)> = decisions
            .into_iter()
            .map(|d| (d.token_id, d.decision.into()))
            .collect();
        tracing::info!(decisions = decisions.len(), "bitwarden: applying");
        let report = bitwarden::apply(client, &u.tokens, &decisions, &*progress).await;
        match &report.failed {
            None => tracing::info!(
                attached = report.attached,
                created = report.created,
                skipped = report.skipped,
                kept = report.kept.len(),
                "bitwarden: applied"
            ),
            Some(message) => tracing::warn!(
                attached = report.attached,
                created = report.created,
                skipped = report.skipped,
                kept = report.kept.len(),
                error = %sanitised(message),
                "bitwarden: apply stopped early"
            ),
        }
        Ok(report.into())
    }

    // ---- end of the session ----

    /// Stop the proxy, destroy the certificate key, wipe the Bitwarden data, drop the secrets.
    ///
    /// Idempotent, and complete on a fresh launch that has nothing but the marker and a key in
    /// the store (the resume-after-quit path). Every step is tried even when an earlier one
    /// fails; the first failure is reported. A key left by an earlier launch is deleted, and
    /// that is all that is ever done with it: it is not read.
    pub async fn cleanup(&self) -> Result<(), CmdError> {
        let mut first_error: Option<CmdError> = None;
        let mut note = |e: CmdError| {
            first_error.get_or_insert(e);
        };
        tracing::info!("cleanup: started");

        // First, so that an unlock or a sign-in still under way gives up when it finishes.
        self.discard_secrets();
        let running = self.proxy.lock().await.take();
        if let Some(run) = running {
            run.stop().await;
            tracing::info!("cleanup: proxy stopped");
        }
        lock(&self.authority).take();
        // The key store may wait on a system prompt: not on an async worker, and not while
        // the proxy lock is held (it was let go above).
        let store = Arc::clone(&self.store);
        let destroyed = tokio::task::spawn_blocking(move || Authority::destroy(&*store))
            .await
            .map_err(|_| "the key store stopped unexpectedly".to_string())
            .and_then(|done| done.map_err(|e| store_reason(&e)));
        match destroyed {
            Ok(()) => tracing::info!("cleanup: certificate key removed"),
            Err(reason) => {
                tracing::error!(error = %reason, "cleanup: the certificate key could not be removed");
                note(CmdError::new(key_not_removed(&reason)));
            }
        }
        let client = self.bw.lock().await.take();
        if let Some(mut client) = client {
            match client.logout_and_wipe().await {
                Ok(()) => tracing::info!("cleanup: signed out of Bitwarden"),
                Err(e) => {
                    log_bw_failure("sign-out", &e);
                    note(e.into());
                }
            }
        }
        // A previous launch may have left Bitwarden data with no client to wipe it.
        match self.wipe_bw_data().await {
            Ok(()) => tracing::info!("cleanup: Bitwarden data removed"),
            Err(e) => {
                tracing::error!(error = %e, "cleanup: the Bitwarden data could not be removed");
                note(e);
            }
        }
        advance(&self.ui, Step::Cleanup);
        tracing::info!(complete = first_error.is_none(), "cleanup: finished");
        if first_error.is_none() && lock(&self.authority).is_none() {
            self.cleaned.store(true, Ordering::SeqCst);
        }
        first_error.map_or(Ok(()), Err)
    }

    /// The app is closing before the person reached cleanup. Stop the proxy and remove what
    /// Bitwarden left on disk; keep the certificate key and the marker, so the next launch
    /// opens on cleanup and finishes the job. Never waits: whatever is busy is skipped, and
    /// the process ending takes care of what is in memory.
    pub fn on_exit(&self) {
        tracing::info!("the app is closing: stopping the proxy and removing Bitwarden data");
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

    /// Clear the resume marker. Unless a cleanup has already run to the end, one is run first
    /// (it deletes the key without ever reading it); the marker stays when that fails, so the
    /// next launch offers cleanup again.
    pub async fn finish(&self) -> Result<(), CmdError> {
        if !self.cleaned.load(Ordering::SeqCst) {
            self.cleanup().await?;
        }
        remove_marker(&self.paths)?;
        tracing::info!("finished: the resume marker is cleared");
        self.resume_cleanup.store(false, Ordering::SeqCst);
        advance(&self.ui, Step::Done);
        Ok(())
    }
}

/// What the person is told when the certificate key could not be removed: the reason, and
/// how to remove it by hand so that cleanup can finish.
pub fn key_not_removed(reason: &str) -> String {
    let reason = reason.trim().trim_end_matches('.');
    format!(
        "The certificate key could not be removed from this computer's keychain ({reason}). \
         To remove it by hand: open Keychain Access, search for \"{KEYCHAIN_SERVICE}\", and \
         delete the item it finds. Then try again."
    )
}

/// What the key store said, without the "key store:" in front.
fn store_reason(error: &authexodus_core::ca::CaError) -> String {
    match error {
        authexodus_core::ca::CaError::Store(message) => message.clone(),
        other => other.to_string(),
    }
}

/// One log line for a Bitwarden failure: the stage, the kind of error, and its message with
/// anything that could identify the person taken out.
fn log_bw_failure(stage: &str, error: &bitwarden::BwError) {
    tracing::warn!(
        stage = %stage,
        kind = %bw_error_kind(error),
        error = %sanitised(&error.to_string()),
        "bitwarden: failed"
    );
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
