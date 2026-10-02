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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppState {
    pub step: Step,
    pub device: Option<Device>,
    pub resume_cleanup: bool,
    pub version: String,
    pub releases_url: String,
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
    BackupCaptured { count: usize },
    AuthyError { status: u16, path: String },
    DeviceRefused,
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

/// Holds the Bitwarden password and the two-factor code: deliberately no `Debug`. Both are
/// wiped from memory when this is dropped.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BwLoginInput {
    pub email: String,
    pub password: Zeroizing<String>,
    pub region: BwRegionDto,
    #[serde(default)]
    pub two_factor_code: Option<Zeroizing<String>>,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CandidateDto {
    pub item_id: String,
    pub name: String,
    pub username: Option<String>,
    pub has_code: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProposalDto {
    pub token_id: String,
    pub decision: DecisionDto,
    pub confidence: ConfidenceDto,
    pub candidates: Vec<CandidateDto>,
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
                .map(|v| CandidateDto {
                    item_id: v.id.clone(),
                    name: v.name.clone(),
                    username: v.username.clone(),
                    has_code: v.has_totp,
                })
                .collect(),
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApplyReportDto {
    pub attached: usize,
    pub created: usize,
    pub skipped: usize,
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

/// A failed command, as the plain-language message the UI shows. Never built from a password
/// or a secret.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct CmdError(pub String);

impl CmdError {
    pub fn new(msg: impl Into<String>) -> Self {
        CmdError(msg.into())
    }
}

impl Serialize for CmdError {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl From<bitwarden::BwError> for CmdError {
    fn from(e: bitwarden::BwError) -> Self {
        CmdError(e.to_string())
    }
}
