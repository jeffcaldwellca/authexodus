//! `BwClient` trait, `VaultLogin`, errors (package 1D).
//!
//! The Bitwarden path: download and verify the official CLI ([`download`]), drive it
//! ([`cli::CliClient`]), propose which login each token belongs to ([`matcher::propose`]) and
//! attach idempotently ([`apply::apply`]). Nothing here ever handles a vault password after it has
//! been handed to the child process, and nothing prints a password, session key or token secret.

use async_trait::async_trait;

pub mod apply;
pub mod cli;
pub mod download;
pub mod matcher;

pub use apply::{apply, ApplyReport};
pub use cli::CliClient;
pub use download::ensure_cli;
pub use matcher::{propose, Confidence, Decision, Proposal};

/// Name of the vault folder that new logins are created in.
pub const IMPORT_FOLDER: &str = "Authy import";

/// One login from the user's vault: never its password, only what matching needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultLogin {
    pub id: String,
    pub name: String,
    pub username: Option<String>,
    pub hosts: Vec<String>,
    pub has_totp: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Region {
    Us,
    Eu,
    SelfHosted(String),
}

impl Region {
    /// The server URL handed to `bw config server`.
    pub fn server_url(&self) -> String {
        match self {
            Region::Us => "https://vault.bitwarden.com".to_string(),
            Region::Eu => "https://vault.bitwarden.eu".to_string(),
            Region::SelfHosted(url) => url.trim().trim_end_matches('/').to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginOutcome {
    Ok,
    NeedsTwoFactor,
    BadCredentials,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetTotp {
    Attached,
    AlreadyHasCode,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BwError {
    /// The Bitwarden server (or the network to it) failed: worth running again.
    #[error("Bitwarden server error: {0}")]
    Server(String),
    #[error("the Bitwarden session has ended")]
    SessionExpired,
    #[error("Bitwarden CLI error: {0}")]
    Cli(String),
    #[error("could not download the Bitwarden CLI: {0}")]
    Download(String),
    #[error("the downloaded Bitwarden CLI does not match the expected checksum")]
    ChecksumMismatch,
}

#[async_trait]
pub trait BwClient: Send + Sync {
    async fn login(
        &mut self,
        email: &str,
        password: &str,
        region: &Region,
        two_factor: Option<&str>,
    ) -> Result<LoginOutcome, BwError>;
    async fn sync(&self) -> Result<(), BwError>;
    async fn list_logins(&self) -> Result<Vec<VaultLogin>, BwError>;
    /// Names already in the "Authy import" folder.
    async fn import_folder_titles(&self) -> Result<Vec<String>, BwError>;
    async fn set_totp(&self, item_id: &str, otpauth: &str) -> Result<SetTotp, BwError>;
    async fn create_in_import_folder(
        &self,
        title: &str,
        username: Option<&str>,
        otpauth: &str,
    ) -> Result<(), BwError>;
    async fn logout_and_wipe(&mut self) -> Result<(), BwError>;
}
