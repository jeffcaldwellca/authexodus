//! `BwClient` trait, `VaultLogin`, errors (package 1D).
//!
//! The Bitwarden path: download and verify the official CLI ([`download`]), drive it
//! ([`cli::CliClient`]), propose which login each token belongs to ([`matcher::propose`]) and
//! attach idempotently ([`apply::apply`]). Nothing here ever handles a vault password after it has
//! been handed to the child process, and nothing prints a password, session key or token secret.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use tokio::sync::Notify;

pub mod apply;
pub mod cli;
pub mod download;
pub mod matcher;

pub use apply::{apply, ApplyReport};
pub use cli::CliClient;
pub use download::{ensure_cli, ensure_cli_reporting, CliBinary, PrepareStage};
pub use matcher::{propose, Confidence, Decision, Proposal};

/// A signal to stop work that is under way (a download, an unpacking). Clones share the one
/// signal; once given it stays given.
#[derive(Clone, Default)]
pub struct Cancel(Arc<CancelState>);

#[derive(Default)]
struct CancelState {
    cancelled: AtomicBool,
    notify: Notify,
}

impl Cancel {
    pub fn new() -> Cancel {
        Cancel::default()
    }

    pub fn cancel(&self) {
        self.0.cancelled.store(true, Ordering::SeqCst);
        self.0.notify.notify_waiters();
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.cancelled.load(Ordering::SeqCst)
    }

    /// Resolves once [`Cancel::cancel`] has been called (at once, if it already was).
    pub async fn cancelled(&self) {
        loop {
            let notified = self.0.notify.notified();
            tokio::pin!(notified);
            // Registered before the flag is read, so a signal between the two is not missed.
            notified.as_mut().enable();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

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
    /// Which authenticator key the login holds, when it holds one that could be read. Lets a
    /// re-run recognise a code it put there itself without the key being kept.
    pub code: Option<CodeMark>,
}

/// Stands for one authenticator key without being it: a SHA-256 over the key. Two marks are
/// equal exactly when the keys are. It cannot be turned back into the key, and it prints as
/// `CodeMark(..)`, so a `VaultLogin` can still be shown in a test failure or a log.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CodeMark([u8; 32]);

impl fmt::Debug for CodeMark {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CodeMark(..)")
    }
}

impl CodeMark {
    /// The mark of a base32 key. Case, spaces, dashes and padding do not matter.
    pub fn of_secret(base32: &str) -> Option<CodeMark> {
        let mut cleaned: zeroize::Zeroizing<String> = zeroize::Zeroizing::new(
            base32
                .chars()
                .filter(|c| !c.is_whitespace() && *c != '=' && *c != '-')
                .map(|c| c.to_ascii_uppercase())
                .collect(),
        );
        let usable = !cleaned.is_empty()
            && cleaned
                .bytes()
                .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b));
        let mark = usable.then(|| {
            let mut hash = Sha256::new();
            hash.update(b"authexodus code mark\0");
            hash.update(cleaned.as_bytes());
            CodeMark(hash.finalize().into())
        });
        zeroize::Zeroize::zeroize(&mut *cleaned);
        mark
    }

    /// The mark of what a vault login's authenticator-key field holds: an `otpauth://` URI
    /// (its `secret` parameter) or a bare base32 key. `None` when the field is empty or holds
    /// something else.
    pub fn of_totp_field(value: &str) -> Option<CodeMark> {
        let value = value.trim();
        if value.to_ascii_lowercase().starts_with("otpauth://") {
            let uri = url::Url::parse(value).ok()?;
            let secret = uri
                .query_pairs()
                .find(|(name, _)| name.eq_ignore_ascii_case("secret"))?
                .1;
            return CodeMark::of_secret(&secret);
        }
        CodeMark::of_secret(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Region {
    Us,
    Eu,
    SelfHosted(String),
}

impl Region {
    /// The server URL handed to `bw config server`. For a self-hosted server it is the
    /// address as parsed, never the text as typed (check it with [`check_login_input`]
    /// first; an address that does not parse comes back trimmed and unchanged).
    pub fn server_url(&self) -> String {
        match self {
            Region::Us => "https://vault.bitwarden.com".to_string(),
            Region::Eu => "https://vault.bitwarden.eu".to_string(),
            Region::SelfHosted(url) => match url::Url::parse(url.trim()) {
                Ok(parsed) => parsed.as_str().trim_end_matches('/').to_string(),
                Err(_) => url.trim().trim_end_matches('/').to_string(),
            },
        }
    }
}

/// Refuse a sign-in whose email or server address must not reach the Bitwarden tool: the
/// email is a command-line argument, and the server is where the master password's hash is
/// sent. Checked here as well as on the screen, so that nothing depends on the screen.
///
/// * A self-hosted server address must parse as a URL, use `https`, name a host, and carry
///   no user name or password.
/// * An email must contain `@` with something on both sides, must not start with `-` (it
///   would be read as an option), and must hold no spaces or control characters.
pub fn check_login_input(email: &str, region: &Region) -> Result<(), BwError> {
    check_region(region)?;
    let usable = !email.starts_with('-')
        && email.len() <= 320
        && !email.chars().any(|c| c.is_whitespace() || c.is_control())
        && email
            .split_once('@')
            .is_some_and(|(local, domain)| !local.is_empty() && !domain.is_empty());
    if !usable {
        return Err(BwError::BadEmail);
    }
    Ok(())
}

/// The server-address half of [`check_login_input`], for a sign-in that sends no email.
pub fn check_region(region: &Region) -> Result<(), BwError> {
    if let Region::SelfHosted(url) = region {
        let usable = url::Url::parse(url.trim()).is_ok_and(|parsed| {
            parsed.scheme() == "https"
                && parsed.host_str().is_some_and(|host| !host.is_empty())
                && parsed.username().is_empty()
                && parsed.password().is_none()
        });
        if !usable {
            return Err(BwError::BadServerUrl);
        }
    }
    Ok(())
}

/// Is this shaped like a personal API key? The client id is `user.` and a UUID; the secret is
/// a run of letters and digits. Both travel in the child's environment, never in its
/// arguments, so this is only to turn a mistyped key away before the tool is run.
pub fn is_api_key(client_id: &str, client_secret: &str) -> bool {
    client_id.strip_prefix("user.").is_some_and(is_vault_id)
        && (8..=128).contains(&client_secret.len())
        && client_secret.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Is this shaped like the ids Bitwarden gives vault items and folders (a UUID:
/// 8-4-4-4-12 hexadecimal digits)? Ids come back from the server through the tool and are
/// then passed to the tool as arguments, so anything else is refused.
pub fn is_vault_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => *b == b'-',
            _ => b.is_ascii_hexdigit(),
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginOutcome {
    Ok,
    /// Bitwarden wants a two-step code and none was given.
    NeedsTwoFactor,
    BadCredentials,
    /// A two-step code was given and Bitwarden did not accept it.
    BadTwoFactorCode,
    /// A password sign-in cannot get any further: Bitwarden wants a code it sent by email (it
    /// does that for a device it has not seen), or the account's only two-step methods are
    /// ones the tool cannot do. Signing in with a personal API key gets past both.
    NeedsApiKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetTotp {
    Attached,
    /// The login already holds this very code (an earlier run put it there): done.
    AlreadySet,
    /// The login holds a different code, which is left alone.
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
    /// The email address typed cannot be handed to the tool.
    #[error("the email address is not usable")]
    BadEmail,
    /// The server address typed is not an `https` address of a server.
    #[error("the server address is not usable")]
    BadServerUrl,
    /// The work was stopped on request ([`Cancel`]).
    #[error("stopped before it finished")]
    Cancelled,
    /// This build cannot download or run the Bitwarden tool on this system (see the
    /// "Not yet portable" notes in `download.rs` and `cli.rs`).
    #[error("the Bitwarden tool is not available for this system in this version of the app")]
    UnsupportedPlatform,
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
    /// Sign in with a personal API key (which Bitwarden does not challenge with an emailed
    /// code or a two-step method), then unlock the vault with the master password.
    async fn login_with_api_key(
        &mut self,
        client_id: &str,
        client_secret: &str,
        password: &str,
        region: &Region,
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
