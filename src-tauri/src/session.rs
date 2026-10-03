//! The one `Session` held in Tauri state, plus the resume marker file (package 2A).
//!
//! Everything here is generic over the core's `BwClient` and free of Tauri, so the tests run
//! under `cargo test` with a fake Bitwarden client. Secrets (`Unlocked`, the Bitwarden client,
//! the certificate authority's key) live in memory only.
//!
//! What this file logs (see `crate::logging` for where it goes): the stages of the session
//! and their failures, with counts and kinds only. Never a password, a key, a one-time code,
//! a token or login name, an email address, a file path, or anything about the device's
//! traffic beyond what the proxy itself logs.
//!
//! What a refused command tells the person is in `crate::errors`, as fixed sentences. The
//! detail of a failure (what the Bitwarden tool said, say) goes to the log only.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use authexodus_core::backup;
use authexodus_core::bitwarden::{
    self, BwClient, BwError, Cancel, CliBinary, CliClient, CodeMark, LoginOutcome, PrepareStage,
};
use authexodus_core::ca::Authority;
use authexodus_core::export::{self, ExportFile};
use authexodus_core::proxy::{self, ProxyConfig, ProxyEvent, ProxyHandle, TestUpstream};
use authexodus_core::totp;
use authexodus_core::types::{CapturedBackup, Unlocked};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use crate::awake::{KeepAwake, KeepAwakeCommand};
use crate::dto::*;
use crate::errors::{bw_reject, BwStage};
use crate::logging::{bw_error_kind, sanitised};
use crate::network::{self, Candidate, Network};
use crate::progress;

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
/// How often, while the proxy runs, this computer's addresses are read to see that the one
/// the proxy is on is still among them.
pub const ADDRESS_WATCH_EVERY: Duration = Duration::from_secs(5);
/// Where new versions are published. There is no auto-update: the app shows this address.
pub const RELEASES_URL: &str = "https://github.com/jeffcaldwellca/authexodus/releases";

pub type EmitProxy = Arc<dyn Fn(ProxyEventDto) + Send + Sync>;
pub type EmitProgress = Arc<dyn Fn(String) + Send + Sync>;
/// Every address this computer has right now.
pub type AddressSource = Arc<dyn Fn() -> Vec<IpAddr> + Send + Sync>;

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
    /// Where the downloaded, verified `bw` program lives (the zip, 42 to 44 MB, and the
    /// program unpacked from it, about 130 MB). Removed at cleanup, when the app closes and
    /// when it next starts: it is downloaded again by a run that wants it.
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
        .map_err(|e| {
            tracing::error!(kind = ?e.kind(), "the session marker could not be written");
            CmdError(Reject::MarkerNotWritten)
        })
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
        Err(e) => {
            tracing::error!(kind = ?e.kind(), "the session marker could not be removed");
            Err(CmdError(Reject::CleanupMarkerNotRemoved))
        }
    }
}

/// Remove a folder of this app's own. One that is not there is already removed.
fn remove_dir(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_dir_all(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
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

/// A task that is stopped when this is dropped, so that it cannot outlive what it serves.
struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// What has happened on one run of the proxy. A restarted proxy starts again from nothing.
#[derive(Default)]
struct RunFacts {
    device_connected: AtomicBool,
    trust_working: AtomicBool,
}

impl RunFacts {
    fn note(&self, event: &ProxyEvent) {
        match event {
            ProxyEvent::DeviceConnected => self.device_connected.store(true, Ordering::SeqCst),
            ProxyEvent::TrustWorking => self.trust_working.store(true, Ordering::SeqCst),
            _ => {}
        }
    }
}

/// Is `ip` an address this computer still has? (An unspecified address means "every
/// address", which it always has.)
fn still_ours(ip: Ipv4Addr, own: &[IpAddr]) -> bool {
    ip.is_unspecified() || own.contains(&IpAddr::V4(ip))
}

/// How many looks in a row must miss the proxy's address before the UI is told. One miss is
/// often a Wi-Fi blip or a wake from sleep, after which the same address comes back.
const ADDRESS_MISSES: u32 = 2;

/// While the proxy runs on `ip`: read this computer's addresses every `every`, and tell the
/// UI, once each time it happens, that `ip` is no longer among them: when it has been missing
/// from [`ADDRESS_MISSES`] looks in a row (so about 10 s at the usual 5 s). (A computer that
/// moves to another Wi-Fi keeps its listener, bound to an address nothing can reach any more.)
///
/// Nothing is sent when the address comes back. The UI finds out by asking for the proxy
/// again (`start_proxy` with no address), which describes it as before once the address is
/// this computer's again, and rejects with `address_changed` while it is not.
async fn watch_address(ip: Ipv4Addr, every: Duration, addresses: AddressSource, emit: EmitProxy) {
    let mut misses = 0u32;
    loop {
        tokio::time::sleep(every).await;
        if still_ours(ip, &addresses()) {
            if misses >= ADDRESS_MISSES {
                tracing::info!("this computer has the proxy's address again");
            }
            misses = 0;
            continue;
        }
        misses = misses.saturating_add(1);
        if misses == ADDRESS_MISSES {
            tracing::warn!("this computer no longer has the address the proxy is listening on");
            emit(ProxyEventDto::AddressChanged);
        }
    }
}

// ---------------------------------------------------------------------------------------------

struct ProxyRun {
    ip: Ipv4Addr,
    handle: ProxyHandle,
    facts: Arc<RunFacts>,
    /// The fingerprint of the certificate this run serves.
    fingerprint: String,
    // The three below end with the run, however it ends (stopped, or simply dropped).
    _bridge: AbortOnDrop,
    _watch: AbortOnDrop,
    _awake: Option<KeepAwake>,
}

impl ProxyRun {
    async fn stop(self) {
        let ProxyRun {
            handle,
            _bridge,
            _watch,
            _awake,
            ..
        } = self;
        drop((_bridge, _watch));
        handle.shutdown().await;
        // Last: the computer may sleep again once nothing is listening.
        drop(_awake);
    }

    /// Has anything of the backup arrived on this run?
    fn has_capture(&self) -> bool {
        let backup = self.handle.backup();
        !backup.tokens.is_empty() || !backup.native_apps.is_empty()
    }
}

/// Where a test has the Bitwarden tool downloaded from, instead of the pinned release.
#[derive(Clone)]
struct BwDownload {
    base_url: String,
    asset: String,
    sha256: String,
}

/// Test seams; production keeps the defaults.
struct Tuning {
    port: u16,
    upstream: Option<TestUpstream>,
    keep_awake: Option<KeepAwakeCommand>,
    addresses: AddressSource,
    watch_every: Duration,
    bw_download: Option<BwDownload>,
}

/// One login of the vault as it was last read: what the person may attach to.
struct VaultEntry {
    view: VaultLoginView,
    /// Which code it holds, if it holds one that could be read.
    code: Option<CodeMark>,
}

fn vault_entries(vault: &[bitwarden::VaultLogin]) -> Vec<VaultEntry> {
    vault
        .iter()
        .map(|login| VaultEntry {
            view: VaultLoginView::from(login),
            code: login.code,
        })
        .collect()
}

pub struct Session {
    /// Whether the certificate authority of this launch carries the name constraint.
    constrained: bool,
    paths: Paths,
    resume_cleanup: AtomicBool,
    /// Set when a cleanup has run to the end without a failure and nothing has been created
    /// since: there is then nothing left for [`Session::finish`] to remove.
    cleaned: AtomicBool,
    /// A cleanup has been run (whether or not all of it worked) and nothing was started since.
    cleanup_run: AtomicBool,
    /// [`Session::finish`] succeeded and nothing was started since.
    finished: AtomicBool,
    device: Mutex<Option<Device>>,
    /// This run's certificate authority, private key and all. Only ever in memory: made by
    /// the first start of the proxy, kept across restarts (the device trusts it), and dropped
    /// by cleanup and when the app closes.
    authority: Mutex<Option<Arc<Authority>>>,
    proxy: tokio::sync::Mutex<Option<ProxyRun>>,
    /// The address the proxy last ran on: where a start-over goes when none is named.
    last_ip: Mutex<Option<Ipv4Addr>>,
    tuning: Mutex<Tuning>,
    /// Counts the times the session's secrets were thrown away (start-over, cleanup, exit).
    /// Slow work that began before such a moment must not put anything back afterwards: an
    /// unlock or a Bitwarden sign-in notes the count when it starts and gives up if it moved.
    discards: AtomicU64,
    unlocked: Mutex<Option<Arc<Unlocked>>>,
    bw_binary: Mutex<Option<CliBinary>>,
    /// Held for the whole of a download or a sign-in, so that only one of them runs at a
    /// time (two would share one download folder, or one data folder).
    bw_op: tokio::sync::Mutex<()>,
    /// The way to stop the download or sign-in that is under way, if one is.
    bw_stop: Mutex<Option<Cancel>>,
    bw: tokio::sync::Mutex<Option<Box<dyn BwClient>>>,
    /// Which account the proposals and the vault below were read from: the server and the
    /// email address, nothing secret. They are kept across a new sign-in to the same account
    /// (a session that ended), and dropped when another account signs in.
    bw_account: Mutex<Option<String>>,
    /// The last proposals shown to the person.
    proposals: Mutex<Option<Vec<ProposalDto>>>,
    /// The vault's logins as last read: what `bw_apply` may attach to.
    vault: Mutex<Option<Vec<VaultEntry>>>,
}

/// The address asked for, if one was.
fn parse_ip(requested: Option<&str>) -> Result<Option<Ipv4Addr>, CmdError> {
    match requested.map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => s
            .parse()
            .map(Some)
            .map_err(|_| CmdError(Reject::AddressInvalid)),
        None => Ok(None),
    }
}

/// The address to listen on. One that was asked for must be one of this computer's and must
/// not be a public address; with none asked for, only a private (RFC 1918) address is ever
/// chosen, and with none of those there is no default at all.
fn choose_ip(requested: Option<Ipv4Addr>, candidates: &[Candidate]) -> Result<Ipv4Addr, CmdError> {
    match requested {
        Some(ip) if network::is_public(ip) => Err(CmdError(Reject::AddressPublic)),
        Some(ip) if candidates.iter().any(|c| c.ip == ip) => Ok(ip),
        Some(_) => Err(CmdError(Reject::AddressNotOurs)),
        None => network::default_ip(candidates).ok_or(CmdError(Reject::NoPrivateAddress)),
    }
}

fn proxy_info(run: &ProxyRun, candidates: &[Candidate], constrained: bool) -> ProxyInfo {
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
        cert_constrained: constrained,
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
        ProxyEvent::EmptyBackup => "emptyBackup",
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
/// `secondsLeft` runs from the period (30) down to 1 and a new code starts at the top.
/// (Unlocking only lets through tokens a code can be made for, so none is left out here.)
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

/// May these decisions be applied? Every token must be one of the unlocked ones. A login may
/// be attached to when it is in the vault as it was last read and holds no code (or holds
/// this very token's code already: an earlier run put it there, and the apply will find it
/// done), and no login may be chosen for two tokens. One bad entry refuses the whole list:
/// nothing is applied.
fn check_decisions(
    decisions: &[DecisionEntry],
    unlocked: &Unlocked,
    vault: Option<&[VaultEntry]>,
) -> Result<(), CmdError> {
    let mut chosen: HashSet<&str> = HashSet::new();
    for entry in decisions {
        let Some(token) = unlocked.tokens.iter().find(|t| t.id == entry.token_id) else {
            return Err(CmdError(Reject::DecisionUnknownAccount));
        };
        let DecisionDto::Attach { item_id } = &entry.decision else {
            continue;
        };
        let Some(login) = vault
            .into_iter()
            .flatten()
            .find(|login| &login.view.item_id == item_id)
        else {
            return Err(CmdError(Reject::DecisionUnknownLogin));
        };
        let holds_this_code =
            login.code.is_some() && login.code == CodeMark::of_secret(token.secret.expose());
        if login.view.has_code && !holds_this_code {
            return Err(CmdError(Reject::DecisionLoginHasCode));
        }
        if !chosen.insert(item_id.as_str()) {
            return Err(CmdError(Reject::DecisionLoginTwice));
        }
    }
    Ok(())
}

/// Which account a sign-in is for: the server and the email address as typed, in lower case.
fn account_key(region: &bitwarden::Region, email: &str) -> String {
    format!("{}\n{}", region.server_url(), email.to_lowercase())
}

impl Session {
    /// A session keeping its files in `dir`. Reads the resume marker: a marker left by an
    /// earlier launch means the certificate may still be installed on a device, and the proxy
    /// setting still switched on. (The certificate's key went with that launch.)
    ///
    /// What Bitwarden left from an earlier launch is removed here: its data (the key to it
    /// lived in that launch's memory, so it is of no use, and a launch that crashed never
    /// wiped it) and the downloaded tool itself.
    ///
    /// The certificate authority is constrained unless [`UNCONSTRAINED_ENV`] is set to `1`.
    pub fn new(dir: PathBuf) -> Session {
        let constrained = ca_constrained(std::env::var(UNCONSTRAINED_ENV).ok().as_deref());
        Session::with_ca_mode(dir, constrained)
    }

    /// [`Session::new`] with the certificate-authority mode given rather than read from the
    /// environment.
    pub fn with_ca_mode(dir: PathBuf, constrained: bool) -> Session {
        let paths = Paths::new(dir);
        let resume = marker_exists(&paths);
        let _ = remove_dir(&paths.bw_data());
        let _ = remove_dir(&paths.bw_cli());
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
            constrained,
            paths,
            resume_cleanup: AtomicBool::new(resume),
            cleaned: AtomicBool::new(false),
            cleanup_run: AtomicBool::new(false),
            finished: AtomicBool::new(false),
            device: Mutex::new(None),
            authority: Mutex::new(None),
            proxy: tokio::sync::Mutex::new(None),
            last_ip: Mutex::new(None),
            tuning: Mutex::new(Tuning {
                port: PREFERRED_PORT,
                upstream: None,
                keep_awake: KeepAwakeCommand::system(),
                addresses: Arc::new(|| network::own_addresses(&network::system_ifaces())),
                watch_every: ADDRESS_WATCH_EVERY,
                bw_download: None,
            }),
            discards: AtomicU64::new(0),
            unlocked: Mutex::new(None),
            bw_binary: Mutex::new(None),
            bw_op: tokio::sync::Mutex::new(()),
            bw_stop: Mutex::new(None),
            bw: tokio::sync::Mutex::new(None),
            bw_account: Mutex::new(None),
            proposals: Mutex::new(None),
            vault: Mutex::new(None),
        }
    }

    /// For tests: the port to try first, and a stand-in for Authy. The app never calls this,
    /// and could only ever pass `None`: a `TestUpstream` cannot be built without the core's
    /// `test-upstream` feature, which only test builds switch on.
    #[doc(hidden)]
    pub fn tune_proxy(&self, port: u16, upstream: Option<TestUpstream>) {
        let mut tuning = lock(&self.tuning);
        tuning.port = port;
        tuning.upstream = upstream;
    }

    /// For tests: how often this computer's addresses are read while the proxy runs, and
    /// where they are read from. The app never calls this.
    #[doc(hidden)]
    pub fn tune_address_watch(&self, every: Duration, addresses: AddressSource) {
        let mut tuning = lock(&self.tuning);
        tuning.watch_every = every;
        tuning.addresses = addresses;
    }

    /// For tests: the program run to keep the computer awake. The app never calls this.
    #[doc(hidden)]
    pub fn tune_keep_awake(&self, command: Option<KeepAwakeCommand>) {
        lock(&self.tuning).keep_awake = command;
    }

    /// For tests: where the Bitwarden tool is downloaded from, and the hash to expect. The
    /// app never calls this: it only ever downloads the pinned release.
    #[doc(hidden)]
    pub fn tune_bw_download(&self, base_url: &str, asset: &str, sha256: &str) {
        lock(&self.tuning).bw_download = Some(BwDownload {
            base_url: base_url.to_owned(),
            asset: asset.to_owned(),
            sha256: sha256.to_owned(),
        });
    }

    /// What the shell knows, for the UI to start from or to recover with after its window
    /// was reloaded.
    ///
    /// `step` is not tracked; it is read off the same facts the snapshot carries, as the
    /// furthest step they establish:
    ///
    /// | fact | step |
    /// |---|---|
    /// | `finish` succeeded | `done` |
    /// | a cleanup was run, or an earlier launch left one due | `cleanup` |
    /// | a backup is unlocked | `destination` |
    /// | the proxy holds a captured backup | `unlock` |
    /// | a device trusted the certificate on this proxy run | `authy` |
    /// | a device used this proxy run | `certificate` |
    /// | the proxy is running | `connect` |
    /// | none of these | `welcome` |
    ///
    /// It is never `verify`: whether the person is choosing a destination or checking the
    /// codes is the screen's own business, and nothing here could tell.
    ///
    /// While the proxy is being started or stopped (a moment's work), this
    /// does not wait for it: the snapshot then says there is no proxy, and `start_proxy`
    /// gives the answer when it is there.
    pub fn get_state(&self, net: &Network) -> AppState {
        let mut session = SessionSnapshot {
            proxy: None,
            device_connected: false,
            trust_working: false,
            captured: 0,
            summary: lock(&self.unlocked).as_deref().map(UnlockSummary::from),
        };
        let mut has_capture = false;
        if let Ok(slot) = self.proxy.try_lock() {
            if let Some(run) = slot.as_ref() {
                session.proxy = Some(proxy_info(run, &net.candidates, self.constrained));
                session.device_connected = run.facts.device_connected.load(Ordering::SeqCst);
                session.trust_working = run.facts.trust_working.load(Ordering::SeqCst);
                session.captured = run.handle.backup().tokens.len();
                has_capture = run.has_capture();
            }
        }
        let resume_cleanup = self.resume_cleanup.load(Ordering::SeqCst);
        let step = if self.finished.load(Ordering::SeqCst) {
            Step::Done
        } else if resume_cleanup || self.cleanup_run.load(Ordering::SeqCst) {
            Step::Cleanup
        } else if session.summary.is_some() {
            Step::Destination
        } else if has_capture {
            Step::Unlock
        } else if session.trust_working {
            Step::Authy
        } else if session.device_connected {
            Step::Certificate
        } else if session.proxy.is_some() {
            Step::Connect
        } else {
            Step::Welcome
        };
        AppState {
            step,
            device: *lock(&self.device),
            resume_cleanup,
            version: env!("CARGO_PKG_VERSION").to_string(),
            releases_url: RELEASES_URL.to_string(),
            session,
        }
    }

    pub fn set_device(&self, device: Device) {
        *lock(&self.device) = Some(device);
    }

    /// Whether this launch's certificate authority carries the name constraint.
    pub fn ca_is_constrained(&self) -> bool {
        self.constrained
    }

    /// The certificate authority of this launch, created the first time it is asked for, and
    /// kept in memory only.
    ///
    /// The resume marker is written first and the key made second, so that whatever happens
    /// to the app later, the next launch knows a certificate may be on a device (and the
    /// proxy setting switched on) and opens on cleanup. If the key cannot be made, the marker
    /// written here is taken away again.
    async fn ensure_ca(&self) -> Result<Arc<Authority>, CmdError> {
        if let Some(ca) = lock(&self.authority).as_ref() {
            return Ok(Arc::clone(ca));
        }
        let had_marker = marker_exists(&self.paths);
        self.cleaned.store(false, Ordering::SeqCst);
        write_marker(&self.paths)?;
        let ca = match Authority::create(self.constrained) {
            Ok(ca) => Arc::new(ca),
            Err(e) => {
                if !had_marker {
                    let _ = remove_marker(&self.paths);
                }
                tracing::error!(error = %e, "the certificate authority could not be created");
                return Err(CmdError(Reject::CaNotCreated));
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
    ///   running proxy is described again. Unless this computer no longer has that address
    ///   (it moved to another network): the proxy is then listening where nothing can reach
    ///   it, and describing it again would be a lie, so that is an error which says so. The
    ///   way out is [`Session::restart_proxy`].
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
                let here =
                    net.candidates.iter().any(|c| c.ip == run.ip) || still_ours(run.ip, &net.own);
                if !here {
                    tracing::warn!("asked for the proxy, whose address this computer has lost");
                    return Err(CmdError(Reject::AddressChanged));
                }
                return Ok(proxy_info(run, &net.candidates, self.constrained));
            }
        }
        let ip = choose_ip(requested, &net.candidates).inspect_err(
            |e| tracing::warn!(error = %e, asked = requested.is_some(), "no address to listen on"),
        )?;
        if let Some(run) = slot.as_ref() {
            if run.has_capture() || lock(&self.unlocked).is_some() {
                return Err(CmdError(Reject::CaptureWouldBeLost));
            }
        }
        if let Some(old) = slot.take() {
            old.stop().await;
        }
        let run = self.launch(ip, net, emit).await?;
        let info = proxy_info(&run, &net.candidates, self.constrained);
        *slot = Some(run);
        Ok(info)
    }

    /// Start over: stop the proxy, throw away the captured backup and anything unlocked from
    /// it, and start a fresh proxy with the same certificate on `requested`, or, when no
    /// address is given, on the address the proxy is (or last was) on, so that the iPhone or
    /// iPad only has to reconnect. Only with no earlier address (or one this computer no
    /// longer has) is the default chosen. A fresh proxy has no accepted device, so whichever
    /// iPhone or iPad completes a trusted connection next is accepted, under whatever address
    /// it has now.
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
        let current = slot
            .as_ref()
            .map(|run| run.ip)
            .or(*lock(&self.last_ip))
            .filter(|ip| net.candidates.iter().any(|c| c.ip == *ip));
        let ip = choose_ip(requested.or(current), &net.candidates).inspect_err(
            |e| tracing::warn!(error = %e, asked = requested.is_some(), "no address to listen on"),
        )?;
        tracing::info!("starting over: the capture and anything unlocked are discarded");
        self.discard_secrets();
        if let Some(old) = slot.take() {
            old.stop().await;
        }
        let run = self.launch(ip, net, emit).await?;
        let info = proxy_info(&run, &net.candidates, self.constrained);
        *slot = Some(run);
        Ok(info)
    }

    /// Drop what was unlocked and what was proposed from it, and make sure an unlock or a
    /// sign-in still under way does not put anything back.
    fn discard_secrets(&self) {
        self.discards.fetch_add(1, Ordering::SeqCst);
        lock(&self.unlocked).take();
        self.forget_vault();
    }

    /// Forget what was read from a Bitwarden vault and what was proposed from it.
    fn forget_vault(&self) {
        lock(&self.proposals).take();
        lock(&self.vault).take();
        lock(&self.bw_account).take();
    }

    async fn launch(
        &self,
        ip: Ipv4Addr,
        net: &Network,
        emit: EmitProxy,
    ) -> Result<ProxyRun, CmdError> {
        let ca = self.ensure_ca().await?;
        let fingerprint = ca.fingerprint();
        let (port, upstream, keep_awake, addresses, watch_every) = {
            let t = lock(&self.tuning);
            (
                t.port,
                t.upstream.clone(),
                t.keep_awake.clone(),
                Arc::clone(&t.addresses),
                t.watch_every,
            )
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
            CmdError(Reject::ListenFailed)
        })?;
        // Every address this computer has, so that none of them can be reached through the
        // proxy on a device's behalf.
        handle.add_local_addresses(net.own.iter().copied());
        *lock(&self.last_ip) = Some(ip);
        // Something is running again: whatever a cleanup or a finish said before is over.
        self.cleanup_run.store(false, Ordering::SeqCst);
        self.finished.store(false, Ordering::SeqCst);
        tracing::info!(
            address = %ip,
            port = handle.port(),
            constrained = self.constrained,
            "proxy started"
        );
        let facts = Arc::new(RunFacts::default());
        let bridge = {
            let (facts, emit) = (Arc::clone(&facts), Arc::clone(&emit));
            tokio::spawn(async move {
                let mut bridge = Bridge::default();
                while let Some(event) = rx.recv().await {
                    facts.note(&event);
                    let dto = bridge.map(&event, Instant::now());
                    log_event(&event, dto.is_some());
                    if let Some(dto) = dto {
                        emit(dto);
                    }
                }
            })
        };
        let watch = tokio::spawn(watch_address(ip, watch_every, addresses, emit));
        Ok(ProxyRun {
            ip,
            handle,
            facts,
            fingerprint,
            _bridge: AbortOnDrop(bridge),
            _watch: AbortOnDrop(watch),
            _awake: KeepAwake::start(keep_awake.as_ref()),
        })
    }

    /// Keep `unlocked` in memory, unless the session was started over or cleaned up since
    /// `discards` was read.
    fn keep_unlocked(&self, unlocked: Unlocked, discards: u64) -> Result<(), CmdError> {
        {
            let mut slot = lock(&self.unlocked);
            if self.discards.load(Ordering::SeqCst) != discards {
                return Err(CmdError(Reject::UnlockOvertaken));
            }
            *slot = Some(Arc::new(unlocked));
        }
        // Proposals were made from the tokens that were unlocked before.
        self.forget_vault();
        Ok(())
    }

    /// Decrypt `backup` with `password` and keep the result in memory.
    ///
    /// The key derivation (100,000 rounds for every token in a real backup) runs on the
    /// blocking pool, so the rest of the app keeps answering meanwhile. The password is wiped
    /// when the work is done.
    ///
    /// A backup that holds only Authy-native tokens has nothing to decrypt: whatever the
    /// password, the answer is a summary with no tokens and the native ones by name, so the
    /// person gets to the screen that says what to do about them.
    pub async fn unlock_backup(
        &self,
        backup: CapturedBackup,
        password: Zeroizing<String>,
    ) -> Result<UnlockResult, CmdError> {
        let discards = self.discards.load(Ordering::SeqCst);
        if backup.tokens.is_empty() {
            if backup.native_apps.is_empty() {
                tracing::info!("unlock asked for before any backup was captured");
                return Err(CmdError(Reject::BackupNotArrived));
            }
            tracing::info!(
                native = backup.native_apps.len(),
                "unlock: only Authy-native tokens were captured; nothing to decrypt"
            );
            let unlocked = Unlocked {
                tokens: Vec::new(),
                invalid: Vec::new(),
                native: backup.native_apps,
            };
            let summary = UnlockSummary::from(&unlocked);
            self.keep_unlocked(unlocked, discards)?;
            return Ok(UnlockResult::Summary(summary));
        }
        tracing::info!(
            tokens = backup.tokens.len(),
            native = backup.native_apps.len(),
            "unlock attempted"
        );
        let started = Instant::now();
        let outcome = tokio::task::spawn_blocking(move || backup::unlock(&backup, &password))
            .await
            .map_err(|_| {
                tracing::error!("unlock failed: the work stopped unexpectedly");
                CmdError(Reject::UnlockStopped)
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
                self.keep_unlocked(unlocked, discards)?;
                Ok(UnlockResult::Summary(summary))
            }
            Err(backup::WrongPassword) => {
                tracing::info!(took_ms, "unlock failed: wrong password");
                Ok(UnlockResult::Error {
                    error: UnlockErrorKind::WrongPassword,
                })
            }
        }
    }

    pub async fn unlock(&self, password: Zeroizing<String>) -> Result<UnlockResult, CmdError> {
        let backup = match self.proxy.lock().await.as_ref() {
            Some(run) => run.handle.backup(),
            None => return Err(CmdError(Reject::ConnectionNotRunning)),
        };
        self.unlock_backup(backup, password).await
    }

    fn unlocked(&self) -> Result<Arc<Unlocked>, CmdError> {
        lock(&self.unlocked)
            .clone()
            .ok_or(CmdError(Reject::NotUnlocked))
    }

    /// The QR code for one token. An error, never an empty picture, when none can be drawn.
    pub fn token_qr(&self, id: &str) -> Result<String, CmdError> {
        let u = self.unlocked()?;
        let token = u
            .tokens
            .iter()
            .find(|t| t.id == id)
            .ok_or(CmdError(Reject::NoSuchAccount))?;
        let svg = export::qr_svg(&export::otpauth_uri(token));
        if svg.is_empty() {
            tracing::warn!("a QR code could not be drawn for a token");
            return Err(CmdError(Reject::QrNotDrawn));
        }
        Ok(svg)
    }

    /// The Google Authenticator transfer codes. An error, never an empty list or an empty
    /// picture, when there is nothing to show: no token fits one, or one could not be drawn.
    pub fn google_migration_qrs(&self) -> Result<Vec<String>, CmdError> {
        let codes = export::google_migration_qrs(&self.unlocked()?.tokens);
        if codes.is_empty() {
            return Err(CmdError(Reject::NoGoogleCodes));
        }
        if codes.iter().any(String::is_empty) {
            tracing::warn!("a Google Authenticator transfer code could not be drawn");
            return Err(CmdError(Reject::GoogleQrNotDrawn));
        }
        Ok(codes)
    }

    /// Titles of the tokens the Google Authenticator QR codes cannot carry.
    pub fn google_unsupported(&self) -> Result<Vec<String>, CmdError> {
        Ok(export::google_unsupported(&self.unlocked()?.tokens))
    }

    /// The file for `dest`, ready to be written where the person chooses.
    pub fn prepare_export(&self, dest: DestinationDto) -> Result<ExportFile, CmdError> {
        export::export(&self.unlocked()?.tokens, dest.into()).map_err(|e| match e {
            export::ExportError::NoFileForDestination => CmdError(Reject::NoFileForDestination),
        })
    }

    pub fn live_codes_at(&self, unix_time: u64) -> Result<Vec<LiveCode>, CmdError> {
        Ok(live_codes(&*self.unlocked()?, unix_time))
    }

    pub fn live_codes(&self) -> Result<Vec<LiveCode>, CmdError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        self.live_codes_at(now)
    }

    // ---- Bitwarden ----

    /// A fresh stop signal for the download or sign-in that is about to run.
    fn begin_bw_op(&self) -> Cancel {
        let cancel = Cancel::new();
        *lock(&self.bw_stop) = Some(cancel.clone());
        cancel
    }

    /// Stop the download or the sign-in that is under way, and wait until it has stopped and
    /// taken its leavings with it: a download removes its partly written file; a sign-in has
    /// its child process killed and its data folder wiped, and no client is kept. With
    /// nothing under way this does nothing, so it may be called at any time and any number
    /// of times.
    pub async fn bw_cancel(&self) {
        let Some(cancel) = lock(&self.bw_stop).clone() else {
            return;
        };
        tracing::info!("bitwarden: asked to stop what is under way");
        cancel.cancel();
        // The work holds this for as long as it runs; having it means the work is over.
        drop(self.bw_op.lock().await);
    }

    /// Download (or reuse) and verify the Bitwarden tool, telling `progress` how far it is
    /// (see `crate::progress` for the lines). The program is extracted afresh from the
    /// verified download every time, and its hash is kept for [`new_cli_client`].
    ///
    /// [`new_cli_client`]: Session::new_cli_client
    pub async fn bw_prepare(&self, progress: EmitProgress) -> Result<(), CmdError> {
        let _one_at_a_time = self.bw_op.lock().await;
        let cancel = self.begin_bw_op();
        let discards = self.discards.load(Ordering::SeqCst);
        tracing::info!("bitwarden: preparing the tool");
        let dir = self.paths.bw_cli();
        let source = lock(&self.tuning).bw_download.clone();
        let report = |stage: PrepareStage| progress(progress::line(stage));
        let prepared = match source {
            None => bitwarden::ensure_cli_reporting(&dir, &report, &cancel).await,
            Some(from) => {
                bitwarden::download::ensure_cli_within(
                    &dir,
                    &from.base_url,
                    &from.asset,
                    &from.sha256,
                    bitwarden::download::MAX_DOWNLOAD_BYTES,
                    &report,
                    &cancel,
                )
                .await
            }
        };
        lock(&self.bw_stop).take();
        let binary = prepared.map_err(|e| {
            log_bw_failure("prepare", &e);
            CmdError(bw_reject(BwStage::Prepare, &e))
        })?;
        if self.discards.load(Ordering::SeqCst) != discards {
            // Cleaned up (or the app is closing) meanwhile: the tool is not wanted any more.
            let _ = remove_dir(&dir);
            return Err(CmdError(Reject::BwStopped));
        }
        *lock(&self.bw_binary) = Some(binary);
        tracing::info!("bitwarden: the tool is ready");
        Ok(())
    }

    /// A client for the prepared tool. It refuses to sign in if the program is no longer the
    /// file that was extracted from the verified download.
    pub fn new_cli_client(&self) -> Result<CliClient, CmdError> {
        let binary = lock(&self.bw_binary)
            .clone()
            .ok_or(CmdError(Reject::BwNotPrepared))?;
        Ok(CliClient::new(binary.path, self.paths.bw_data()).expecting_sha256(binary.sha256))
    }

    async fn wipe_bw_data(&self) -> Result<(), CmdError> {
        match tokio::fs::remove_dir_all(self.paths.bw_data()).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => {
                tracing::error!(kind = ?e.kind(), "the Bitwarden data folder could not be removed");
                Err(CmdError(Reject::CleanupBwDataNotRemoved))
            }
        }
    }

    /// Sign in with `client`. It is kept for the match and apply steps only on success; on any
    /// other outcome it is wiped so nothing is left in the Bitwarden data folder.
    ///
    /// With an API key in `input`, the sign-in is by that key and the password only unlocks
    /// the vault; otherwise it is by email and password, with the two-step code if one came.
    ///
    /// One sign-in runs at a time. A client kept from an earlier sign-in is signed out and
    /// wiped first. If the session is cleaned up (or started over, or the app is closing)
    /// while this sign-in is under way, its result is thrown away and wiped as well; so it is
    /// when the person stops it ([`Session::bw_cancel`]).
    ///
    /// What was proposed and read from the vault before is kept when this is the same
    /// account signing in again (a session that ended half-way through an apply): the person
    /// does not have to review everything again. For another account it is dropped.
    ///
    /// The email and the server address are checked here before anything is done with them
    /// (see [`bitwarden::check_login_input`]); what the screen checked does not count.
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
        let checked = match &input.api_key {
            // The email is not sent anywhere in an API-key sign-in.
            Some(_) => bitwarden::check_region(&region),
            None => bitwarden::check_login_input(email, &region),
        };
        checked.map_err(|e| {
            log_bw_failure("sign-in", &e);
            CmdError(bw_reject(BwStage::SignIn, &e))
        })?;
        tracing::info!(
            region = %region_kind,
            with_code = code.is_some(),
            by_key = input.api_key.is_some(),
            "bitwarden: signing in"
        );
        let _one_at_a_time = self.bw_op.lock().await;
        let cancel = self.begin_bw_op();
        let discards = self.discards.load(Ordering::SeqCst);
        let previous = self.bw.lock().await.take();
        if let Some(mut previous) = previous {
            let _ = previous.logout_and_wipe().await;
        }
        {
            let account = account_key(&region, email);
            let mut known = lock(&self.bw_account);
            if known.as_deref() != Some(account.as_str()) {
                lock(&self.proposals).take();
                lock(&self.vault).take();
                *known = Some(account);
            }
        }

        let outcome = {
            let attempt = async {
                match &input.api_key {
                    Some(key) => {
                        client
                            .login_with_api_key(
                                &key.client_id,
                                &key.client_secret,
                                &input.password,
                                &region,
                            )
                            .await
                    }
                    None => client.login(email, &input.password, &region, code).await,
                }
            };
            tokio::select! {
                biased;
                () = cancel.cancelled() => None,
                outcome = attempt => Some(outcome),
            }
            // Stopped: the attempt is dropped here, which kills the tool if it is running.
        };
        lock(&self.bw_stop).take();
        let Some(outcome) = outcome else {
            tracing::info!("bitwarden: the sign-in was stopped");
            let _ = client.logout_and_wipe().await;
            let _ = self.wipe_bw_data().await;
            return Err(CmdError(Reject::BwStopped));
        };
        match &outcome {
            Ok(outcome) => tracing::info!(outcome = ?outcome, "bitwarden: sign-in answered"),
            Err(e) => log_bw_failure("sign-in", e),
        }
        let answer = match outcome {
            Ok(LoginOutcome::Ok) => {
                let mut slot = self.bw.lock().await;
                if self.discards.load(Ordering::SeqCst) != discards {
                    drop(slot);
                    let _ = client.logout_and_wipe().await;
                    let _ = self.wipe_bw_data().await;
                    return Err(CmdError(Reject::BwOvertaken));
                }
                *slot = Some(client);
                return Ok(BwLoginResult::Ok);
            }
            // "Needs a code" is only ever the answer when none was sent.
            Ok(LoginOutcome::NeedsTwoFactor) if code.is_none() => BwLoginResult::NeedsTwoFactor,
            Ok(LoginOutcome::NeedsTwoFactor | LoginOutcome::BadTwoFactorCode) => {
                BwLoginResult::BadTwoFactorCode
            }
            Ok(LoginOutcome::BadCredentials) => BwLoginResult::BadCredentials,
            Ok(LoginOutcome::NeedsApiKey) => BwLoginResult::NeedsApiKey,
            Err(e) => {
                let _ = client.logout_and_wipe().await;
                return Err(CmdError(bw_reject(BwStage::SignIn, &e)));
            }
        };
        let _ = client.logout_and_wipe().await;
        Ok(answer)
    }

    /// The refusal for a failure while reading the vault, logged.
    fn read_failed(stage: &str, error: &BwError) -> CmdError {
        log_bw_failure(stage, error);
        CmdError(bw_reject(BwStage::Read, error))
    }

    pub async fn bw_propose(&self) -> Result<Vec<ProposalDto>, CmdError> {
        let u = self.unlocked()?;
        let guard = self.bw.lock().await;
        let client = guard.as_deref().ok_or(CmdError(Reject::BwNotSignedIn))?;
        client
            .sync()
            .await
            .map_err(|e| Session::read_failed("sync", &e))?;
        let vault = client
            .list_logins()
            .await
            .map_err(|e| Session::read_failed("list", &e))?;
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
        *lock(&self.vault) = Some(vault_entries(&vault));
        *lock(&self.proposals) = Some(proposals.clone());
        Ok(proposals)
    }

    /// Every login in the vault, for attaching by hand: name, username and whether it holds
    /// a code already; never a password or a code. What is read here is also what
    /// [`Session::bw_apply`] checks the person's choices against.
    pub async fn bw_logins(&self) -> Result<Vec<VaultLoginView>, CmdError> {
        let guard = self.bw.lock().await;
        let client = guard.as_deref().ok_or(CmdError(Reject::BwNotSignedIn))?;
        let vault = client
            .list_logins()
            .await
            .map_err(|e| Session::read_failed("list", &e))?;
        tracing::info!(logins = vault.len(), "bitwarden: logins listed");
        let entries = vault_entries(&vault);
        let views = entries.iter().map(|entry| entry.view.clone()).collect();
        *lock(&self.vault) = Some(entries);
        Ok(views)
    }

    /// Apply the person's decisions. They are checked first (see [`check_decisions`]); if any
    /// does not hold, nothing at all is applied.
    ///
    /// A session that has ended (before the run, or part-way through it) is an error of its
    /// own, `bw_session_expired`, so that the person can be sent to sign in again. Whatever
    /// was done stays done, the decisions' context is kept across that sign-in, and running
    /// the same decisions again finishes the rest.
    pub async fn bw_apply(
        &self,
        decisions: Vec<DecisionEntry>,
        progress: EmitProgress,
    ) -> Result<ApplyReportDto, CmdError> {
        let u = self.unlocked()?;
        let guard = self.bw.lock().await;
        let client = guard.as_deref().ok_or(CmdError(Reject::BwNotSignedIn))?;
        check_decisions(&decisions, &u, lock(&self.vault).as_deref())
            .inspect_err(|e| tracing::warn!(error = %e, "bitwarden: the decisions were refused"))?;
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
        if report.error == Some(BwError::SessionExpired) {
            return Err(CmdError(Reject::BwSessionExpired));
        }
        Ok(report.into())
    }

    // ---- end of the session ----

    /// Stop the proxy, drop the certificate authority and its key, wipe the Bitwarden data,
    /// remove the downloaded Bitwarden tool, drop the secrets.
    ///
    /// Idempotent, and complete on a fresh launch that has nothing but the marker (the
    /// resume-after-quit path): the key of an earlier launch went with it, so there is nothing
    /// of it to remove. Every step is tried even when an earlier one fails; the first failure
    /// is reported.
    pub async fn cleanup(&self) -> Result<(), CmdError> {
        let mut first_error: Option<CmdError> = None;
        let mut note = |e: CmdError| {
            first_error.get_or_insert(e);
        };
        tracing::info!("cleanup: started");

        // First, so that an unlock or a sign-in still under way gives up when it finishes.
        self.discard_secrets();
        self.cleanup_run.store(true, Ordering::SeqCst);
        // A download or a sign-in under way is stopped, not waited out.
        self.bw_cancel().await;
        let running = self.proxy.lock().await.take();
        if let Some(run) = running {
            run.stop().await;
            tracing::info!("cleanup: proxy stopped");
        }
        // The proxy holds no copy of it, so this is the last: the key is wiped as it goes.
        if lock(&self.authority).take().is_some() {
            tracing::info!("cleanup: certificate key dropped from memory");
        }
        let client = self.bw.lock().await.take();
        if let Some(mut client) = client {
            match client.logout_and_wipe().await {
                Ok(()) => tracing::info!("cleanup: signed out of Bitwarden"),
                Err(e) => {
                    log_bw_failure("sign-out", &e);
                    note(CmdError(bw_reject(BwStage::SignOut, &e)));
                }
            }
        }
        // A previous launch may have left Bitwarden data with no client to wipe it.
        match self.wipe_bw_data().await {
            Ok(()) => tracing::info!("cleanup: Bitwarden data removed"),
            Err(e) => note(e),
        }
        // The downloaded tool: of no use once this run is over, and not the person's to keep.
        lock(&self.bw_binary).take();
        let tool = self.paths.bw_cli();
        match tokio::task::spawn_blocking(move || remove_dir(&tool)).await {
            Ok(Ok(())) => tracing::info!("cleanup: Bitwarden tool removed"),
            Ok(Err(e)) => {
                tracing::error!(kind = ?e.kind(), "cleanup: the Bitwarden tool could not be removed");
                note(CmdError(Reject::CleanupBwToolNotRemoved));
            }
            Err(_) => note(CmdError(Reject::CleanupBwToolNotRemoved)),
        }
        tracing::info!(complete = first_error.is_none(), "cleanup: finished");
        if first_error.is_none() && lock(&self.authority).is_none() {
            self.cleaned.store(true, Ordering::SeqCst);
        }
        first_error.map_or(Ok(()), Err)
    }

    /// The app is closing before the person reached cleanup. Stop the proxy (and with it the
    /// helper that keeps the computer awake), drop the certificate key, and remove what
    /// Bitwarden left on disk, the downloaded tool included; keep the marker, so the next
    /// launch opens on cleanup and the person removes the certificate and the proxy setting
    /// from the device. Never waits: whatever is busy is skipped, and the process ending
    /// takes care of what is in memory.
    pub fn on_exit(&self) {
        tracing::info!("the app is closing: stopping the proxy and removing Bitwarden files");
        self.discard_secrets();
        if let Some(cancel) = lock(&self.bw_stop).as_ref() {
            cancel.cancel();
        }
        if let Ok(mut slot) = self.proxy.try_lock() {
            // Dropping the run stops the proxy, its tasks and the keep-awake helper.
            slot.take();
        }
        // The certificate authority, and with it the key, is not needed after this.
        lock(&self.authority).take();
        if let Ok(mut slot) = self.bw.try_lock() {
            slot.take();
        }
        lock(&self.bw_binary).take();
        let _ = remove_dir(&self.paths.bw_data());
        let _ = remove_dir(&self.paths.bw_cli());
    }

    /// Clear the resume marker. Unless a cleanup has already run to the end, one is run first
    /// (it drops the key, if this launch made one). When that fails, this fails with the same
    /// error and the marker stays, so the next launch offers cleanup again.
    pub async fn finish(&self) -> Result<(), CmdError> {
        if !self.cleaned.load(Ordering::SeqCst) {
            self.cleanup().await.inspect_err(
                |e| tracing::warn!(error = %e, "finish refused: the cleanup is not complete"),
            )?;
        }
        remove_marker(&self.paths)?;
        tracing::info!("finished: the resume marker is cleared");
        self.resume_cleanup.store(false, Ordering::SeqCst);
        self.finished.store(true, Ordering::SeqCst);
        Ok(())
    }
}

/// One log line for a Bitwarden failure: the stage, the kind of error, and its message with
/// anything that could identify the person taken out.
fn log_bw_failure(stage: &str, error: &BwError) {
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
