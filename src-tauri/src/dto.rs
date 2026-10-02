//! Wire types: exactly the TypeScript shapes in `ui/src/api.ts` (camelCase fields, tagged unions
//! with `kind`, `{ error: "wrongPassword" }`, `{ saved } | { cancelled: true }`).
//!
//! Nothing here derives `Debug` if it can hold a password or a secret.

use authexodus_core::bitwarden::{self, VaultLogin};
use authexodus_core::export::Destination;
use authexodus_core::proxy::ProxyEvent;
use authexodus_core::types::{InvalidReason, Unlocked};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Declared in wizard order, so `Ord` says which step is further along.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Step {
    Welcome,
    Connect,
    Certificate,
    Authy,
    Unlock,
    Destination,
    Verify,
    Cleanup,
    Done,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Device {
    Iphone,
    Ipad,
}

/// What the shell already knows about this run, so that the UI can pick up where it was
/// after its window is reloaded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionSnapshot {
    /// The running proxy, if one is.
    pub proxy: Option<ProxyInfo>,
    /// Whether a device has used this proxy run, and whether it has trusted the certificate
    /// on it. Both start again from false when the proxy is restarted.
    pub device_connected: bool,
    pub trust_working: bool,
    /// How many encrypted accounts this proxy run holds.
    pub captured: usize,
    /// What was unlocked, if anything is.
    pub summary: Option<UnlockSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppState {
    /// The furthest step the facts in `session` establish (see `Session::get_state`).
    pub step: Step,
    pub device: Option<Device>,
    pub resume_cleanup: bool,
    pub version: String,
    pub releases_url: String,
    pub session: SessionSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AddressView {
    pub ip: String,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyInfo {
    pub addresses: Vec<AddressView>,
    pub ip: String,
    pub port: u16,
    pub cert_url: String,
    pub cert_qr_svg: String,
    pub check_url: String,
    /// SHA-256 of the certificate: 32 upper-case hexadecimal pairs joined by colons, as an
    /// iPhone or iPad shows it under More Details.
    pub cert_fingerprint: String,
    /// False when the certificate is not limited to Authy's names (the device-test fallback):
    /// the UI must then not say that it is.
    pub cert_constrained: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum ProxyEventDto {
    DeviceConnected,
    TrustWorking,
    TlsRejected,
    BackupCaptured {
        count: usize,
    },
    AuthyError {
        status: u16,
        path: String,
    },
    DeviceRefused,
    /// Authy answered with no accounts: backups are probably off.
    EmptyBackup,
    /// This computer's address is no longer the one the proxy is on. Not from the proxy
    /// itself: the session notices it (see `Session::launch`).
    AddressChanged,
}

impl From<&ProxyEvent> for ProxyEventDto {
    fn from(e: &ProxyEvent) -> Self {
        match e {
            ProxyEvent::DeviceConnected => ProxyEventDto::DeviceConnected,
            ProxyEvent::TrustWorking => ProxyEventDto::TrustWorking,
            ProxyEvent::TlsRejected => ProxyEventDto::TlsRejected,
            ProxyEvent::BackupCaptured { count } => ProxyEventDto::BackupCaptured { count: *count },
            ProxyEvent::AuthyError { status, path } => ProxyEventDto::AuthyError {
                status: *status,
                path: path.clone(),
            },
            ProxyEvent::DeviceRefused => ProxyEventDto::DeviceRefused,
            ProxyEvent::EmptyBackup => ProxyEventDto::EmptyBackup,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TokenView {
    pub id: String,
    pub title: String,
    pub username: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum InvalidReasonDto {
    NotBase32,
    TooShort,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InvalidView {
    pub name: String,
    pub reason: InvalidReasonDto,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NativeView {
    pub name: String,
}

/// Titles, usernames and names only: no secret is in here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnlockSummary {
    pub tokens: Vec<TokenView>,
    pub invalid: Vec<InvalidView>,
    pub native: Vec<NativeView>,
}

impl From<&Unlocked> for UnlockSummary {
    fn from(u: &Unlocked) -> Self {
        UnlockSummary {
            tokens: u
                .tokens
                .iter()
                .map(|t| TokenView {
                    id: t.id.clone(),
                    title: t.title.clone(),
                    username: t.username.clone(),
                })
                .collect(),
            invalid: u
                .invalid
                .iter()
                .map(|i| InvalidView {
                    name: i.name.clone(),
                    reason: match i.reason {
                        InvalidReason::NotBase32 => InvalidReasonDto::NotBase32,
                        InvalidReason::TooShort => InvalidReasonDto::TooShort,
                    },
                })
                .collect(),
            native: u
                .native
                .iter()
                .map(|n| NativeView {
                    name: n.name.clone(),
                })
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum UnlockErrorKind {
    WrongPassword,
}

/// `UnlockSummary | { error: "wrongPassword" }`
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum UnlockResult {
    Summary(UnlockSummary),
    Error { error: UnlockErrorKind },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DestinationDto {
    Bitwarden,
    OnePassword,
    TwoFas,
    Aegis,
    GoogleAuthenticator,
    ProtonAuthenticator,
    PlainText,
}

impl From<DestinationDto> for Destination {
    fn from(d: DestinationDto) -> Self {
        match d {
            DestinationDto::Bitwarden => Destination::Bitwarden,
            DestinationDto::OnePassword => Destination::OnePassword,
            DestinationDto::TwoFas => Destination::TwoFas,
            DestinationDto::Aegis => Destination::Aegis,
            DestinationDto::GoogleAuthenticator => Destination::GoogleAuthenticator,
            DestinationDto::ProtonAuthenticator => Destination::ProtonAuthenticator,
            DestinationDto::PlainText => Destination::PlainText,
        }
    }
}

/// `{ saved: string } | { cancelled: true }`
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum ExportOutcome {
    Saved { saved: String },
    Cancelled { cancelled: bool },
}

/// A one-time code. This is one of the three ways a secret-derived value reaches the UI.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveCode {
    pub id: String,
    pub code: String,
    pub seconds_left: u32,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum BwRegionDto {
    Us,
    Eu,
    SelfHosted { url: String },
}

impl From<BwRegionDto> for bitwarden::Region {
    fn from(r: BwRegionDto) -> Self {
        match r {
            BwRegionDto::Us => bitwarden::Region::Us,
            BwRegionDto::Eu => bitwarden::Region::Eu,
            BwRegionDto::SelfHosted { url } => bitwarden::Region::SelfHosted(url),
        }
    }
}

/// A personal API key: deliberately no `Debug`, and wiped from memory when dropped.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BwApiKeyInput {
    pub client_id: Zeroizing<String>,
    pub client_secret: Zeroizing<String>,
}

/// Holds the Bitwarden password, the two-factor code and the API key: deliberately no
/// `Debug`. All are wiped from memory when this is dropped.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BwLoginInput {
    pub email: String,
    pub password: Zeroizing<String>,
    pub region: BwRegionDto,
    #[serde(default)]
    pub two_factor_code: Option<Zeroizing<String>>,
    /// With a key, the sign-in is by API key and the password only unlocks the vault.
    #[serde(default)]
    pub api_key: Option<BwApiKeyInput>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum BwLoginResult {
    Ok,
    /// Bitwarden wants a two-step code and none was sent.
    NeedsTwoFactor,
    BadCredentials,
    /// A two-step code was sent and Bitwarden did not accept it.
    BadTwoFactorCode,
    /// Bitwarden wants a code it sends by email, or a method this app cannot do: the way
    /// through is to sign in with an API key.
    NeedsApiKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum DecisionDto {
    Attach { item_id: String },
    CreateNew,
    Skip,
}

impl From<DecisionDto> for bitwarden::Decision {
    fn from(d: DecisionDto) -> Self {
        match d {
            DecisionDto::Attach { item_id } => bitwarden::Decision::Attach { item_id },
            DecisionDto::CreateNew => bitwarden::Decision::CreateNew,
            DecisionDto::Skip => bitwarden::Decision::Skip,
        }
    }
}

impl From<&bitwarden::Decision> for DecisionDto {
    fn from(d: &bitwarden::Decision) -> Self {
        match d {
            bitwarden::Decision::Attach { item_id } => DecisionDto::Attach {
                item_id: item_id.clone(),
            },
            bitwarden::Decision::CreateNew => DecisionDto::CreateNew,
            bitwarden::Decision::Skip => DecisionDto::Skip,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ConfidenceDto {
    High,
    Low,
}

/// One login of the vault, as the person sees it: never its password or its code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultLoginView {
    pub item_id: String,
    pub name: String,
    pub username: Option<String>,
    pub has_code: bool,
}

impl From<&VaultLogin> for VaultLoginView {
    fn from(login: &VaultLogin) -> Self {
        VaultLoginView {
            item_id: login.id.clone(),
            name: login.name.clone(),
            username: login.username.clone(),
            has_code: login.has_totp,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProposalDto {
    pub token_id: String,
    pub decision: DecisionDto,
    pub confidence: ConfidenceDto,
    pub candidates: Vec<VaultLoginView>,
}

/// Turn the matcher's proposals (candidates are item ids) into the UI's, by looking each id up
/// in the vault. An id that is no longer in the vault is dropped.
pub fn join_proposals(proposals: &[bitwarden::Proposal], vault: &[VaultLogin]) -> Vec<ProposalDto> {
    proposals
        .iter()
        .map(|p| ProposalDto {
            token_id: p.token_id.clone(),
            decision: DecisionDto::from(&p.decision),
            confidence: match p.confidence {
                bitwarden::Confidence::High => ConfidenceDto::High,
                bitwarden::Confidence::Low => ConfidenceDto::Low,
            },
            candidates: p
                .candidates
                .iter()
                .filter_map(|id| vault.iter().find(|v| &v.id == id))
                .map(VaultLoginView::from)
                .collect(),
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApplyReportDto {
    pub attached: usize,
    pub created: usize,
    /// Only what the person chose to skip, or what was refused: these stay only in Authy.
    pub skipped: usize,
    /// One sentence, shown as it is, for every account that needed nothing written because
    /// Bitwarden already holds a code there.
    pub kept: Vec<String>,
    pub failed: Option<String>,
}

impl From<bitwarden::ApplyReport> for ApplyReportDto {
    fn from(r: bitwarden::ApplyReport) -> Self {
        ApplyReportDto {
            attached: r.attached,
            created: r.created,
            skipped: r.skipped,
            kept: r.kept,
            failed: r.failed,
        }
    }
}

/// The element type of `bwApply`'s argument.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecisionEntry {
    pub token_id: String,
    pub decision: DecisionDto,
}

pub use crate::errors::{CmdError, ErrorCode, Reject};
