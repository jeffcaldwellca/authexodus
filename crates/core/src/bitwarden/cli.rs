//! Real `BwClient` driving the `bw` binary (package 1D).
//!
//! Every call is `bw <args> --nointeraction`. The master password reaches the child only through
//! an environment variable named by `--passwordenv`; it is never an argument, never logged. The
//! session key is held in memory (zeroized on drop) and handed to each child as `BW_SESSION`.
//! Item JSON (which carries the authenticator key) goes to the child on stdin, never argv.
//!
//! The child gets an environment built from nothing (see [`child_environment`]): none of the
//! parent's proxy, certificate, Node or loader variables can steer where the master password
//! goes. What is placed in argv is checked first: the email and the server address by
//! [`check_login_input`], item and folder ids by [`is_vault_id`].
//!
//! The binary: `ensure_cli` extracts it afresh from the hash-checked zip into a folder only
//! this user can open and records its SHA-256; the client checks the file against that hash at
//! the start of every sign-in (not before every one of the many runs that follow it).

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use zeroize::Zeroizing;

use super::{
    check_login_input, is_vault_id, BwClient, BwError, CodeMark, LoginOutcome, Region, SetTotp,
    VaultLogin, IMPORT_FOLDER,
};

// ---- Text of `bw` failures we react to. All matched case-insensitively as substrings of stderr.
//
// VERIFIED against the source of the real CLI 2026.9.1 (installed bundle `build/bw.js` and its
// `locales/en/messages.json`, read, not run against a vault); not observed from a live login:
/// Wrong master password or email (locale key `invalidMasterPasswordConfirmEmailAndHost`).
const BAD_CREDENTIALS: &[&str] = &[
    "invalid master password",
    // older CLIs relayed the server's wording
    "username or password is incorrect",
];
// The next four are VERIFIED the same way, in `LoginCommand.run` of CLI 2026.9.1 (read, not
// run). What each means depends on whether a code was sent: see `classify_login_failure`.
/// `badRequest("Code is required.")`. Without `--code`: the account needs a two-step code. It
/// is also what a non-interactive login ends with when Bitwarden wants the code it emails to a
/// new device, and that is the only way to get it when `--code` WAS given (with a code, the
/// two-step branch never asks for one).
const CODE_REQUIRED: &[&str] = &["code is required"];
/// `error("Login failed. No provider selected.")`: the account has several two-step methods and
/// none was chosen (no `--method`), or the one chosen with `--method 0` is not among them.
const NO_PROVIDER_SELECTED: &[&str] = &["no provider selected"];
/// `badRequest("No providers available for this client.")`: every two-step method on the
/// account is one the tool cannot do (a hardware security key, Duo).
const NO_PROVIDERS: &[&str] = &["no providers available"];
/// `error("Login failed.")`, nothing after it: the code was sent and Bitwarden asked for
/// two-step again. Matched as the whole message, since longer messages start the same way.
const LOGIN_FAILED_BARE: &str = "login failed.";
/// Vault not unlocked / session key unusable (`"Vault is locked."`, `"You are not logged in."`).
const SESSION_GONE: &[&str] = &[
    "vault is locked",
    "you are not logged in",
    "session key is invalid",
];
// ASSUMED (not in the CLI source: the wording comes from the server and the tool passes it
// through; "Two-step token is invalid. Try again." is the server's text as last read, not
// observed live): a wrong two-step code.
const WRONG_TWO_FACTOR_CODE: &[&str] = &[
    "two-step token is invalid",
    "invalid token",
    "invalid two-step",
];

/// Shown when Bitwarden wants a code it sent by email. (Our wording; the condition it reports
/// is VERIFIED against CLI 2026.9.1, see [`CODE_REQUIRED`].)
pub const EMAIL_CODE_UNSUPPORTED: &str = "Bitwarden wants a verification code that it sends by email (it does this for a new device, or when email is the account's two-step method). This app can only sign in with a code from an authenticator app. Save a Bitwarden import file instead and import it in Bitwarden yourself.";
/// Shown when the account has no authenticator-app two-step method. (Our wording; conditions
/// VERIFIED against CLI 2026.9.1, see [`NO_PROVIDER_SELECTED`] and [`NO_PROVIDERS`].)
pub const METHOD_UNSUPPORTED: &str = "This Bitwarden account uses a two-step method this app cannot do (an emailed code or a hardware security key). This app can only sign in with a code from an authenticator app. Save a Bitwarden import file instead and import it in Bitwarden yourself.";
// ASSUMED (typical Node/HTTP failure wording; the CLI passes these through): the server or the
// network to it failed. Worth running again. Phrases only: a bare "500" or "network" can appear in
// an unrelated message (an item named "Network 500"), so status codes are matched with their
// context and everything else as a whole phrase.
const SERVER_TROUBLE: &[&str] = &[
    "service unavailable",
    "bad gateway",
    "gateway timeout",
    "internal server error",
    "econnreset",
    "econnrefused",
    "enotfound",
    "etimedout",
    "fetch failed",
    "network error",
    "network request failed",
    "network is unreachable",
    "timed out",
];
/// "status code 503", "http 503", "http error 503", "error: 503"
const STATUS_CONTEXTS: &[&str] = &[
    "status code",
    "status:",
    "http",
    "http error",
    "error:",
    "error code",
];
const SERVER_STATUS_CODES: &[&str] = &["500", "502", "503", "504"];

/// The only variables of this process the child may inherit, and only when they are set. The
/// rest of the child's environment is built by [`child_environment`].
const INHERITED_ENV: &[&str] = &["HOME", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE"];
/// The child's `PATH`: the system's own folders, never the person's shell path.
const CHILD_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

const PASSWORD_ENV: &str = "AUTHEXODUS_BW_PASSWORD";
const RUN_TIMEOUT: Duration = Duration::from_secs(180);

pub struct CliClient {
    binary: PathBuf,
    /// The SHA-256 the binary must have, when it is known.
    binary_sha256: Option<String>,
    data_dir: PathBuf,
    session: Option<Zeroizing<String>>,
    folder_id: Mutex<Option<String>>,
}

/// The whole environment of a `bw` child: nothing of the parent's except [`INHERITED_ENV`], a
/// fixed `PATH`, and the tool's own settings. So `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`,
/// `NO_PROXY`, `NODE_EXTRA_CA_CERTS`, `NODE_TLS_REJECT_UNAUTHORIZED`, `NODE_OPTIONS`,
/// `SSL_CERT_FILE`, `DYLD_*`, `LD_*` and any `BW_*` or `BITWARDENCLI_*` setting of the person's
/// shell never reach it.
fn child_environment(
    parent: impl Fn(&str) -> Option<std::ffi::OsString>,
    data_dir: &std::path::Path,
    session: Option<&str>,
    password: Option<&str>,
) -> Vec<(String, std::ffi::OsString)> {
    let mut env: Vec<(String, std::ffi::OsString)> = INHERITED_ENV
        .iter()
        .filter_map(|name| Some(((*name).to_owned(), parent(name)?)))
        .collect();
    env.push(("PATH".into(), CHILD_PATH.into()));
    env.push(("BW_NOINTERACTION".into(), "true".into()));
    env.push(("BITWARDENCLI_APPDATA_DIR".into(), data_dir.into()));
    if let Some(session) = session {
        env.push(("BW_SESSION".into(), session.into()));
    }
    if let Some(password) = password {
        env.push((PASSWORD_ENV.into(), password.into()));
    }
    env
}

impl CliClient {
    /// `data_dir` is private to this app (`BITWARDENCLI_APPDATA_DIR`) and wiped on logout.
    pub fn new(binary: PathBuf, data_dir: PathBuf) -> CliClient {
        CliClient {
            binary,
            binary_sha256: None,
            data_dir,
            session: None,
            folder_id: Mutex::new(None),
        }
    }

    /// Refuse to sign in unless the binary still has this SHA-256 (hex): the hash recorded
    /// when it was extracted from the verified download.
    pub fn expecting_sha256(mut self, sha256: impl Into<String>) -> CliClient {
        self.binary_sha256 = Some(sha256.into());
        self
    }

    /// Is the binary still the file that was extracted from the verified download?
    async fn verify_binary(&self) -> Result<(), BwError> {
        let Some(expected) = &self.binary_sha256 else {
            return Ok(());
        };
        match super::download::sha256_of_file(&self.binary).await {
            Ok(actual) if actual.eq_ignore_ascii_case(expected) => Ok(()),
            _ => Err(BwError::ChecksumMismatch),
        }
    }

    /// Spawn `bw` and wait. Returns (succeeded, stdout, stderr); only failing to run at all is an `Err`.
    async fn exec(
        &self,
        args: &[&str],
        stdin: Option<&str>,
        password: Option<&str>,
    ) -> Result<(bool, String, String), BwError> {
        let mut cmd = Command::new(&self.binary);
        cmd.args(args)
            .arg("--nointeraction")
            .env_clear()
            .envs(child_environment(
                |name| std::env::var_os(name),
                &self.data_dir,
                self.session.as_ref().map(|s| s.as_str()),
                password,
            ))
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = cmd
            .spawn()
            .map_err(|e| BwError::Cli(format!("could not start the Bitwarden tool: {e}")))?;
        if let Some(input) = stdin {
            let mut pipe = child.stdin.take().expect("stdin was piped");
            let data = input.as_bytes().to_vec();
            // Write on its own task so a child that exits early cannot wedge us.
            tokio::spawn(async move {
                let _ = pipe.write_all(&data).await;
            });
        }
        let out = tokio::time::timeout(RUN_TIMEOUT, child.wait_with_output())
            .await
            .map_err(|_| BwError::Server("the Bitwarden tool timed out".into()))?
            .map_err(|e| BwError::Cli(format!("the Bitwarden tool failed: {e}")))?;
        Ok((
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        ))
    }

    /// Run `bw`. Returns stdout on success; classifies stderr on failure.
    async fn run(
        &self,
        args: &[&str],
        stdin: Option<&str>,
        password: Option<&str>,
    ) -> Result<String, BwError> {
        let (ok, stdout, stderr) = self.exec(args, stdin, password).await?;
        if ok {
            Ok(stdout)
        } else {
            Err(classify_failure(&stderr))
        }
    }

    async fn run_json(&self, args: &[&str]) -> Result<Value, BwError> {
        let out = self.run(args, None, None).await?;
        serde_json::from_str(out.trim())
            .map_err(|_| BwError::Cli(format!("unexpected output from `bw {}`", args.join(" "))))
    }

    /// Id of the import folder, creating it when `create` is set. Cached after the first lookup.
    async fn import_folder_id(&self, create: bool) -> Result<Option<String>, BwError> {
        if let Some(id) = self.folder_id.lock().unwrap().clone() {
            return Ok(Some(id));
        }
        let folders = self.run_json(&["list", "folders"]).await?;
        let found = folders
            .as_array()
            .into_iter()
            .flatten()
            .find(|f| f["name"].as_str() == Some(IMPORT_FOLDER))
            .and_then(|f| f["id"].as_str().map(str::to_owned));
        if found.as_deref().is_some_and(|id| !is_vault_id(id)) {
            return Err(BwError::Cli(
                "Bitwarden returned a folder id of an unexpected form".into(),
            ));
        }
        let id = match found {
            Some(id) => Some(id),
            None if create => {
                let encoded = self.encode(&json!({ "name": IMPORT_FOLDER })).await?;
                let made = self
                    .run(&["create", "folder"], Some(&encoded), None)
                    .await?;
                let v: Value = serde_json::from_str(made.trim())
                    .map_err(|_| BwError::Cli("unexpected output creating the folder".into()))?;
                let id = v["id"].as_str().filter(|id| is_vault_id(id));
                Some(id.map(str::to_owned).ok_or_else(|| {
                    BwError::Cli("Bitwarden returned a folder id of an unexpected form".into())
                })?)
            }
            None => None,
        };
        if let Some(id) = &id {
            *self.folder_id.lock().unwrap() = Some(id.clone());
        }
        Ok(id)
    }

    async fn encode(&self, value: &Value) -> Result<String, BwError> {
        let out = self
            .run(&["encode"], Some(&value.to_string()), None)
            .await?;
        Ok(out.trim().to_string())
    }
}

/// Turn a failed run's stderr into the right error.
pub fn classify_failure(stderr: &str) -> BwError {
    let text = stderr.trim();
    let lower = text.to_lowercase();
    let any = |needles: &[&str]| needles.iter().any(|n| lower.contains(n));
    if any(SESSION_GONE) {
        BwError::SessionExpired
    } else if any(SERVER_TROUBLE) || has_server_status(&lower) {
        BwError::Server(text.to_string())
    } else {
        BwError::Cli(if text.is_empty() {
            "no details given".into()
        } else {
            text.to_string()
        })
    }
}

/// A 5xx status code that is its own number and follows a status-ish word ("http 503").
fn has_server_status(lower: &str) -> bool {
    SERVER_STATUS_CODES.iter().any(|code| {
        lower.match_indices(code).any(|(at, _)| {
            let before = &lower[..at];
            let after = &lower[at + code.len()..];
            let standalone = !before.ends_with(|c: char| c.is_alphanumeric())
                && !after.starts_with(|c: char| c.is_alphanumeric());
            let lead = before.trim_end();
            standalone && STATUS_CONTEXTS.iter().any(|w| lead.ends_with(w))
        })
    })
}

/// Classify the stderr of a failed `bw login`. `code_sent` says whether a two-step code was
/// given, which decides what the tool's few messages mean:
///
/// | the tool says | no code was sent | a code was sent |
/// |---|---|---|
/// | wrong master password | `BadCredentials` | `BadCredentials` |
/// | the server's "token is invalid" (ASSUMED) | `BadTwoFactorCode` | `BadTwoFactorCode` |
/// | "Code is required." | `NeedsTwoFactor` | emailed code wanted: unsupported |
/// | "No provider selected." | `NeedsTwoFactor` (several methods) | no authenticator app: unsupported |
/// | "No providers available" | unsupported | unsupported |
/// | "Login failed." alone | (other error) | `BadTwoFactorCode` (asked again) |
///
/// `NeedsTwoFactor` is never returned when a code was sent.
fn classify_login_failure(stderr: &str, code_sent: bool) -> Result<LoginOutcome, BwError> {
    let lower = stderr.to_lowercase();
    let any = |needles: &[&str]| needles.iter().any(|n| lower.contains(n));
    if any(BAD_CREDENTIALS) {
        Ok(LoginOutcome::BadCredentials)
    } else if any(WRONG_TWO_FACTOR_CODE) {
        Ok(LoginOutcome::BadTwoFactorCode)
    } else if any(NO_PROVIDERS) {
        Err(BwError::Unsupported(METHOD_UNSUPPORTED.into()))
    } else if any(CODE_REQUIRED) {
        if code_sent {
            Err(BwError::Unsupported(EMAIL_CODE_UNSUPPORTED.into()))
        } else {
            Ok(LoginOutcome::NeedsTwoFactor)
        }
    } else if any(NO_PROVIDER_SELECTED) {
        if code_sent {
            Err(BwError::Unsupported(METHOD_UNSUPPORTED.into()))
        } else {
            Ok(LoginOutcome::NeedsTwoFactor)
        }
    } else if code_sent && lower.trim() == LOGIN_FAILED_BARE {
        Ok(LoginOutcome::BadTwoFactorCode)
    } else {
        Err(classify_failure(stderr))
    }
}

/// Parse `bw list items` output into logins (items of type 1). A missing or empty username is
/// `None`; a URI without a scheme still yields its host; an IP address is kept as the host.
pub fn parse_login_items(json: &str) -> Result<Vec<VaultLogin>, BwError> {
    let items: Value = serde_json::from_str(json.trim())
        .map_err(|_| BwError::Cli("unexpected output from `bw list items`".into()))?;
    let items = items
        .as_array()
        .ok_or_else(|| BwError::Cli("unexpected output from `bw list items`".into()))?;
    let mut out = Vec::new();
    for item in items {
        if item["type"].as_i64() != Some(1) {
            continue;
        }
        let (Some(id), Some(name)) = (item["id"].as_str(), item["name"].as_str()) else {
            continue;
        };
        let login = &item["login"];
        let username = login["username"]
            .as_str()
            .map(str::trim)
            .filter(|u| !u.is_empty())
            .map(str::to_owned);
        let hosts: BTreeSet<String> = login["uris"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|u| u["uri"].as_str())
            .filter_map(host_of)
            .collect();
        let totp = login["totp"].as_str().filter(|t| !t.trim().is_empty());
        out.push(VaultLogin {
            id: id.to_owned(),
            name: name.to_owned(),
            username,
            hosts: hosts.into_iter().collect(),
            has_totp: totp.is_some(),
            code: totp.and_then(CodeMark::of_totp_field),
        });
    }
    Ok(out)
}

fn host_of(uri: &str) -> Option<String> {
    let uri = uri.trim();
    if uri.is_empty() {
        return None;
    }
    let parse = |s: &str| {
        url::Url::parse(s)
            .ok()
            .and_then(|u| u.host_str().map(str::to_lowercase))
    };
    // "example.com/login" has no scheme and parses as nothing useful; retry with one. Things like
    // "androidapp://com.x" parse fine and give their own host.
    match url::Url::parse(uri) {
        Ok(u) if u.host_str().is_some() => u.host_str().map(str::to_lowercase),
        _ => parse(&format!("https://{uri}")),
    }
}

#[async_trait]
impl BwClient for CliClient {
    async fn login(
        &mut self,
        email: &str,
        password: &str,
        region: &Region,
        two_factor: Option<&str>,
    ) -> Result<LoginOutcome, BwError> {
        check_login_input(email, region)?;
        self.verify_binary().await?;
        tokio::fs::create_dir_all(&self.data_dir)
            .await
            .map_err(|e| {
                BwError::Cli(format!("could not prepare the Bitwarden data folder: {e}"))
            })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ =
                std::fs::set_permissions(&self.data_dir, std::fs::Permissions::from_mode(0o700));
        }
        self.session = None;
        // `bw config server` refuses while logged in (a repeat attempt, e.g. with a two-step
        // code); log out first and ignore "not logged in".
        let _ = self.run(&["logout"], None, None).await;
        self.run(&["config", "server", &region.server_url()], None, None)
            .await?;

        let passwordenv = format!("--passwordenv={PASSWORD_ENV}");
        let mut args = vec!["login", email, passwordenv.as_str(), "--raw"];
        // The code has to go in argv: `bw login` (2026.9.1 `--help`) offers `--code` only, with no
        // environment-variable or file form for it as it has for the password. It is a one-time,
        // 30-second code, so the exposure in `ps` is accepted.
        // Method 0 is "authenticator app", the only one this app does. The CLI needs --method
        // with --code because without it a non-interactive login cannot pick a provider when
        // the account has several.
        if let Some(code) = two_factor {
            args.extend(["--method", "0", "--code", code]);
        }
        let (ok, _stdout, stderr) = self.exec(&args, None, Some(password)).await?;
        if !ok {
            return classify_login_failure(&stderr, two_factor.is_some());
        }

        let unlock_args = ["unlock", passwordenv.as_str(), "--raw"];
        let key = self.run(&unlock_args, None, Some(password)).await?;
        let key = key.trim();
        if key.is_empty() {
            return Err(BwError::Cli(
                "Bitwarden did not return a session key".into(),
            ));
        }
        self.session = Some(Zeroizing::new(key.to_string()));
        Ok(LoginOutcome::Ok)
    }

    async fn sync(&self) -> Result<(), BwError> {
        self.run(&["sync"], None, None).await.map(|_| ())
    }

    async fn list_logins(&self) -> Result<Vec<VaultLogin>, BwError> {
        parse_login_items(&self.run(&["list", "items"], None, None).await?)
    }

    async fn import_folder_titles(&self) -> Result<Vec<String>, BwError> {
        let Some(id) = self.import_folder_id(false).await? else {
            return Ok(Vec::new());
        };
        let items = self.run_json(&["list", "items", "--folderid", &id]).await?;
        Ok(items
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|i| i["name"].as_str().map(str::to_owned))
            .collect())
    }

    async fn set_totp(&self, item_id: &str, otpauth: &str) -> Result<SetTotp, BwError> {
        if !is_vault_id(item_id) {
            return Err(BwError::Cli(
                "that vault entry has an id of an unexpected form".into(),
            ));
        }
        let mut item = self.run_json(&["get", "item", item_id]).await?;
        if item["type"].as_i64() != Some(1) {
            return Err(BwError::Cli("that vault entry is not a login".into()));
        }
        if let Some(existing) = item["login"]["totp"]
            .as_str()
            .filter(|t| !t.trim().is_empty())
        {
            // The same key as the one to set means an earlier run already did this.
            let same = CodeMark::of_totp_field(existing)
                .is_some_and(|mark| Some(mark) == CodeMark::of_totp_field(otpauth));
            return Ok(if same {
                SetTotp::AlreadySet
            } else {
                SetTotp::AlreadyHasCode
            });
        }
        item["login"]["totp"] = Value::String(otpauth.to_string());
        let encoded = self.encode(&item).await?;
        self.run(&["edit", "item", item_id], Some(&encoded), None)
            .await?;
        Ok(SetTotp::Attached)
    }

    async fn create_in_import_folder(
        &self,
        title: &str,
        username: Option<&str>,
        otpauth: &str,
    ) -> Result<(), BwError> {
        let folder = self
            .import_folder_id(true)
            .await?
            .ok_or_else(|| BwError::Cli("could not create the import folder".into()))?;
        let item = json!({
            "type": 1,
            "name": title,
            "folderId": folder,
            "notes": "Migrated from Authy",
            "login": { "username": username, "totp": otpauth },
        });
        let encoded = self.encode(&item).await?;
        self.run(&["create", "item"], Some(&encoded), None)
            .await
            .map(|_| ())
    }

    async fn logout_and_wipe(&mut self) -> Result<(), BwError> {
        let _ = self.run(&["logout"], None, None).await;
        self.session = None;
        *self.folder_id.lock().unwrap() = None;
        match tokio::fs::remove_dir_all(&self.data_dir).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(BwError::Cli(format!(
                "could not remove the Bitwarden data folder: {e}"
            ))),
        }
    }
}
