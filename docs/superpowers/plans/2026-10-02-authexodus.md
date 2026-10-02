# authexodus Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan. This plan is deliberately lean: five batches, work packages inside a batch run in parallel, one review per batch. Steps use checkbox (`- [ ]`) syntax for tracking. Each package is built test-first: write the listed tests, watch them fail, implement, watch them pass, commit.

**Goal:** A signed macOS app that guides a non-technical person through exporting their Authy tokens via an iPhone or iPad and into any authenticator, with smart matching for Bitwarden.

**Architecture:** A Tauri 2 app. All sensitive work lives in a pure Rust library crate (`authexodus-core`) with no Tauri dependency, so every module is testable from `cargo test`. A thin Tauri shell exposes the core to a React + TypeScript wizard through a typed command/event contract fixed in Batch 0, which is what lets the core, shell and UI be built in parallel.

**Tech Stack:** Rust 1.93, Tauri 2, tokio, hyper + rustls (via `hudsucker` if the spike passes), `rcgen`, RustCrypto (`pbkdf2`, `sha1`, `hmac`, `aes`, `cbc`), `zeroize`, `data-encoding`, `qrcode`, `prost`, `keyring`; React 18 + TypeScript + Vite, vitest + Testing Library; pnpm.

**Spec:** `docs/superpowers/specs/2026-10-02-authexodus-design.md`. Reference scripts from the manual run: `reference/manual-run-2026-10-02/`.

## Global Constraints

- Phone side is iPhone or iPad only. Every user-facing mention says "iPhone or iPad".
- macOS first. Nothing in `authexodus-core` may be Mac-only. Key storage sits behind the `KeyStore` trait.
- The proxy intercepts TLS for `api.authy.com` (and the app's own check host under it) only. Every other connection is tunnelled untouched and is not logged.
- The backup password and decrypted secrets are never logged and never written to disk, except in a file the user explicitly exports. Secret-holding types implement `Zeroize` and have no `Debug`/`Serialize` that prints the secret.
- Logs record request path (no query string) and status code only.
- No network calls by the app except downloading the Bitwarden CLI when the user picks that path. No analytics, no crash reporting.
- The Bitwarden apply never overwrites an existing authenticator key and is safe to re-run.
- Authy-native tokens (7 digits) are listed by name and never exported. Tokens whose secret is not valid base32 are reported by name and never exported.
- No real user data in the repository. Fixtures are synthetic, encrypted in tests with a known password.
- "Authy" is used only descriptively. The app states it is not affiliated with Twilio or Bitwarden.
- English only. All UI text lives in `ui/src/strings/en.ts`.
- Commits carry no AI co-author trailers.

## Review Focus

Inputs the spec implies but does not spell out. Each has a named test in the package that owns the code.

1. **Backup password with leading/trailing spaces or non-ASCII characters** → used exactly as typed, UTF-8 encoded (package 1A, `password_is_used_verbatim`).
2. **Account names containing commas, quotes, `+`, `:`, `&`, emoji or newlines** → every export format escapes them and round-trips (package 1B, `hostile_names_round_trip`).
3. **The backup response arrives more than once, or a later one is empty** → keep the largest non-empty capture, never replace it with a smaller one (package 1C, `later_empty_response_does_not_clobber`).
4. **The Mac has several network addresses (Wi-Fi + Ethernet + VPN), or port 8080 is taken** → the app picks a free port and lets the user choose the address; never shows a loopback or VPN-tunnel address as the default (package 2A, `picks_private_lan_address`, and 1C, `falls_back_when_port_in_use`).
5. **Bitwarden apply is interrupted (server 503, session expiry, app quit)** → re-running attaches the rest and duplicates nothing (package 1D, `apply_resumes_after_failure`).

## File Structure

```
Cargo.toml                         workspace: crates/core, src-tauri
crates/core/src/
  lib.rs                           module declarations only
  types.rs                         shared data types (Batch 0, frozen)
  backup.rs                        parse + decrypt + password check + naming
  totp.rs                          RFC 6238 code generation
  export/mod.rs                    otpauth URI, QR SVG, Destination dispatch
  export/{bitwarden,onepassword,twofas,aegis,google,plain}.rs   one writer each
  ca.rs                            certificate authority + KeyStore trait
  capture.rs                       recognise Authy responses (pure)
  proxy.rs                         proxy server, cert download, events
  bitwarden/mod.rs                 BwClient trait, VaultLogin, errors
  bitwarden/cli.rs                 real client driving the bw binary
  bitwarden/download.rs            pinned download + SHA-256 check
  bitwarden/matcher.rs             propose()
  bitwarden/apply.rs               apply()
crates/core/tests/                 integration tests (proxy, bitwarden)
src-tauri/src/
  main.rs, commands.rs, session.rs, keychain.rs, network.rs
ui/src/
  api.ts                           command/event contract (Batch 0, frozen)
  api.fake.ts                      in-memory fake of the contract for UI tests
  wizard/machine.ts                wizard state machine (pure reducer)
  screens/*.tsx                    one file per wizard screen
  device/*.tsx                     drawn iPhone/iPad Settings illustrations
  failures/*.tsx                   one plain-language help panel per failure
  strings/en.ts
.github/workflows/{ci,release}.yml
docs/manual-device-checklist.md
```

---

## Batch 0: Scaffold, contracts, proxy spike (one agent, sequential)

Everything later depends on this, so it is done first and reviewed before fan-out.

**Files:** all of the structure above as empty-but-compiling stubs; `types.rs` and `ui/src/api.ts` complete.

- [ ] **Scaffold.** `pnpm create tauri-app` (React + TypeScript + Vite) into the repo root, move the web app to `ui/`, add the Cargo workspace with `crates/core` (`authexodus-core`) and `src-tauri` depending on it. Bundle identifier `dev.somecorp.authexodus`. `cargo test`, `cargo clippy -- -D warnings`, `pnpm -C ui test`, `pnpm -C ui exec tsc --noEmit` all pass on stubs.
- [ ] **CI.** `.github/workflows/ci.yml` runs those four commands plus `cargo fmt --check` on macOS.
- [ ] **Freeze `crates/core/src/types.rs`:**

```rust
pub struct EncryptedToken {
    pub unique_id: String,              // JSON gives a number or a string; store as string
    pub name: String,
    pub issuer: Option<String>,
    pub logo: Option<String>,
    pub account_type: String,
    pub digits: u32,
    pub encrypted_seed: String,         // base64
    pub salt: String,
    pub unique_iv: Option<String>,      // hex; None means a zero IV
    pub key_derivation_iterations: u32,
}
pub struct NativeApp { pub name: String, pub digits: u32 }
#[derive(Default)]
pub struct CapturedBackup { pub tokens: Vec<EncryptedToken>, pub native_apps: Vec<NativeApp> }

pub struct Secret(String);              // base32, uppercase, unpadded; Zeroize on drop; no Debug
impl Secret { pub fn expose(&self) -> &str; }

pub struct Token {
    pub id: String,                     // = unique_id
    pub title: String,                  // display name, e.g. "Vercel (jeff@example.com)"
    pub name: String,                   // Authy's own name
    pub issuer: Option<String>,         // issuer, or derived from logo when blank
    pub username: Option<String>,
    pub secret: Secret,
    pub digits: u32,
    pub period: u32,                    // always 30 for standard tokens
}
pub enum InvalidReason { NotBase32, TooShort }
pub struct InvalidToken { pub name: String, pub reason: InvalidReason }
pub struct Unlocked { pub tokens: Vec<Token>, pub invalid: Vec<InvalidToken>, pub native: Vec<NativeApp> }
```

- [ ] **Freeze `ui/src/api.ts`** (the shell implements it in 2A; the UI builds against `api.fake.ts` in 2B):

```ts
export type Device = "iphone" | "ipad";
export type Step = "welcome" | "connect" | "certificate" | "authy" | "unlock" | "destination" | "verify" | "cleanup" | "done";
export type AppState = { step: Step; device: Device | null; resumeCleanup: boolean; version: string };
export type ProxyInfo = { addresses: { ip: string; label: string }[]; ip: string; port: number; certUrl: string; certQrSvg: string; checkUrl: string };
export type ProxyEvent =
  | { kind: "deviceConnected" } | { kind: "trustWorking" } | { kind: "tlsRejected" }
  | { kind: "backupCaptured"; count: number } | { kind: "authyError"; status: number; path: string };
export type TokenView = { id: string; title: string; username: string | null };
export type UnlockSummary = { tokens: TokenView[]; invalid: { name: string; reason: "notBase32" | "tooShort" }[]; native: { name: string }[] };
export type Destination = "bitwarden" | "onePassword" | "twoFas" | "aegis" | "googleAuthenticator" | "protonAuthenticator" | "plainText";
export type LiveCode = { id: string; code: string; secondsLeft: number };
export type BwRegion = { kind: "us" } | { kind: "eu" } | { kind: "selfHosted"; url: string };
export type BwLogin = { email: string; password: string; region: BwRegion; twoFactorCode?: string };
export type BwLoginResult = { kind: "ok" } | { kind: "needsTwoFactor" } | { kind: "badCredentials" };
export type Decision = { kind: "attach"; itemId: string } | { kind: "createNew" } | { kind: "skip" };
export type Proposal = { tokenId: string; decision: Decision; confidence: "high" | "low";
  candidates: { itemId: string; name: string; username: string | null; hasCode: boolean }[] };
export type ApplyReport = { attached: number; created: number; skipped: number; kept: string[]; failed: string | null };

export interface Api {
  getState(): Promise<AppState>;
  setDevice(device: Device): Promise<void>;
  startProxy(ip?: string): Promise<ProxyInfo>;
  onProxyEvent(cb: (e: ProxyEvent) => void): () => void;
  unlock(password: string): Promise<UnlockSummary | { error: "wrongPassword" }>;
  tokenQr(id: string): Promise<string>;                      // SVG
  googleMigrationQrs(): Promise<string[]>;                   // SVGs, 10 tokens each
  exportFile(dest: Destination): Promise<{ saved: string } | { cancelled: true }>;  // native save dialog
  liveCodes(): Promise<LiveCode[]>;
  bwPrepare(): Promise<void>;                                // download + verify the CLI
  bwLogin(login: BwLogin): Promise<BwLoginResult>;
  bwPropose(): Promise<Proposal[]>;
  bwApply(decisions: { tokenId: string; decision: Decision }[]): Promise<ApplyReport>;
  onBwProgress(cb: (line: string) => void): () => void;
  cleanup(): Promise<void>;                                  // stop proxy, destroy CA key, wipe CLI data, drop secrets
  finish(): Promise<void>;                                   // clear the resume marker
}
```

- [ ] **Proxy spike (throwaway, in `spikes/proxy/`).** With `hudsucker` and `rcgen`: start a proxy, run a local HTTPS server A (stands in for Authy) and B (stands in for any other site), and prove with a `reqwest` client that trusts only the spike CA that (a) A is intercepted and its response body is readable, (b) B is tunnelled and the client sees B's own certificate, (c) plain-HTTP requests are forwarded. Record the result at the top of `crates/core/src/proxy.rs`. If `hudsucker` cannot do (b), package 1C hand-rolls the CONNECT handler on tokio + rustls + hyper instead; the public interface in 1C does not change.
- [ ] **Commit and review Batch 0.**

---

## Batch 1: Core modules (four agents in parallel)

Each package owns its own files, so there are no collisions. Each ends with `cargo test -p authexodus-core <module>` and `cargo clippy` clean, then a commit.

### Package 1A: `backup` and `totp`

**Files:** `crates/core/src/backup.rs`, `crates/core/src/totp.rs`.
**Reference:** `reference/manual-run-2026-10-02/try_password.py`, `to_bitwarden.py`.

**Produces:**

```rust
// backup.rs
pub enum BackupError { Malformed(String), WrongPassword }
pub fn parse_tokens_response(body: &[u8]) -> Result<Vec<EncryptedToken>, BackupError>; // {"authenticator_tokens":[...]}
pub fn parse_apps_response(body: &[u8]) -> Result<Vec<NativeApp>, BackupError>;        // {"apps":[...]}; the seed is NOT read
pub fn unlock(backup: &CapturedBackup, password: &str) -> Result<Unlocked, BackupError>;
// totp.rs
pub enum TotpError { BadSecret }
pub fn code(secret_b32: &str, digits: u32, period: u32, unix_time: u64) -> Result<String, TotpError>;
```

**Behaviour:**
- Decrypt: key = PBKDF2-HMAC-SHA1(password bytes, salt bytes, `key_derivation_iterations`, 32 bytes); AES-256-CBC with IV = hex-decoded `unique_iv`, or 16 zero bytes when absent; strip PKCS7.
- A token "decrypts" when padding is valid and the plaintext is printable ASCII. `unlock` returns `WrongPassword` when fewer than half the tokens decrypt (a wrong key passes padding about 1 time in 256, so a single hit proves nothing).
- A decrypted secret is cleaned (strip spaces, `=`, `-`; uppercase). Not base32 → `InvalidToken::NotBase32`. Decodes to under 10 bytes → `TooShort`. Neither is fatal.
- Naming: `username` = text after `": "` in the name, or the whole name if it looks like an email. If `issuer` is blank and `logo` is set, does not start with `authenticator`, and is not already in the name, the issuer becomes the title-cased logo. `title` = name if it already contains the issuer, else `"{issuer} ({name})"`.

**Tests (a test helper encrypts synthetic tokens with a known password):**
- [ ] `decrypts_with_iv` and `decrypts_with_zero_iv`
- [ ] `wrong_password_is_rejected` (all 20 synthetic tokens, wrong password → `WrongPassword`)
- [ ] `password_is_used_verbatim` (passwords `" pass "` and `"pässwörd"` each decrypt only when typed exactly)
- [ ] `non_base32_secret_is_invalid_not_fatal` (a 9-character secret with `1`/`8` → in `invalid`, others still returned)
- [ ] `unique_id_accepts_number_or_string`
- [ ] `title_uses_logo_when_issuer_blank`, `title_is_not_doubled_when_name_has_issuer`, `username_from_colon_and_from_email`
- [ ] `apps_response_lists_names_only`
- [ ] `malformed_json_is_an_error_not_a_panic`
- [ ] `totp_matches_rfc6238_vectors` (SHA-1 vectors, 8 digits) and `totp_six_digit_thirty_second`

### Package 1B: `export`

**Files:** `crates/core/src/export/*.rs`, fixtures in `crates/core/tests/fixtures/export/`.

**Produces:**

```rust
pub fn otpauth_uri(t: &Token) -> String;   // otpauth://totp/{label}?secret=..&issuer=..&digits=..&period=..
pub fn qr_svg(data: &str) -> String;
pub enum Destination { Bitwarden, OnePassword, TwoFas, Aegis, GoogleAuthenticator, ProtonAuthenticator, PlainText }
pub struct ExportFile { pub suggested_name: String, pub bytes: Vec<u8> }
pub enum ExportError { NoFileForDestination }
pub fn export(tokens: &[Token], dest: Destination) -> Result<ExportFile, ExportError>;
pub fn google_migration_qrs(tokens: &[Token]) -> Vec<String>;   // SVGs of otpauth-migration:// payloads, 10 tokens each
```

**Behaviour:**
- **Bitwarden:** CSV with header `folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp`; folder `Authy import`, type `login`, `login_totp` = the otpauth URI (proven on 2026-10-02).
- **Plain text:** one otpauth URI per line.
- **Aegis, 2FAS, 1Password:** before writing each writer, read that app's current import documentation, save a minimal documented sample in `tests/fixtures/export/` with its source URL in a comment, and make the writer produce that shape.
- **Google Authenticator:** has no file import. `export` returns `NoFileForDestination`; `google_migration_qrs` builds the `otpauth-migration://offline?data=` protobuf payload with `prost`.
- **Proton Authenticator:** imports other apps' files. Check its documentation for which it accepts and emit that format under a Proton-named file.

**Tests:**
- [ ] `otpauth_uri_percent_encodes_label_and_issuer`
- [ ] `hostile_names_round_trip` (names with `,` `"` `+` `:` `&` emoji and a newline: parse every output back and get the same name and secret)
- [ ] `bitwarden_csv_matches_known_header_and_row`
- [ ] one `*_matches_documented_sample` test per file format
- [ ] `google_migration_batches_of_ten` (23 tokens → 3 QR payloads; decode the protobuf back and compare)
- [ ] `google_has_no_file`
- [ ] `empty_token_list_exports_valid_empty_file`

### Package 1C: `ca`, `capture`, `proxy`

**Files:** `crates/core/src/{ca,capture,proxy}.rs`, `crates/core/tests/proxy.rs`.
**Reference:** `reference/manual-run-2026-10-02/capture.py`.

**Produces:**

```rust
// ca.rs
pub trait KeyStore: Send + Sync {
    fn load(&self) -> Result<Option<Vec<u8>>, CaError>;
    fn store(&self, blob: &[u8]) -> Result<(), CaError>;
    fn delete(&self) -> Result<(), CaError>;
}
pub struct MemoryKeyStore;                 // for tests
pub struct Authority;                      // cert + key
impl Authority {
    pub fn load_or_create(store: &dyn KeyStore, constrained: bool) -> Result<Authority, CaError>;
    pub fn cert_der(&self) -> Vec<u8>;
    pub fn destroy(store: &dyn KeyStore) -> Result<(), CaError>;
}
// capture.rs
pub enum Captured { Tokens(Vec<EncryptedToken>), NativeApps(Vec<NativeApp>) }
pub fn inspect(body: &[u8]) -> Option<Captured>;
pub fn merge(into: &mut CapturedBackup, new: Captured) -> bool;   // true if the backup grew
// proxy.rs
pub const AUTHY_HOST: &str = "api.authy.com";
pub const CHECK_HOST: &str = "authexodus-check.api.authy.com";    // answered by the proxy itself, never forwarded
pub enum ProxyEvent { DeviceConnected, TrustWorking, TlsRejected, BackupCaptured { count: usize }, AuthyError { status: u16, path: String } }
pub struct ProxyConfig { pub listen_ip: IpAddr, pub preferred_port: u16, pub upstream: Option<TestUpstream> }
pub struct ProxyHandle;
impl ProxyHandle {
    pub fn port(&self) -> u16;
    pub fn backup(&self) -> CapturedBackup;      // clone of what has been captured
    pub async fn shutdown(self);
}
pub async fn start(cfg: ProxyConfig, ca: Arc<Authority>, events: tokio::sync::mpsc::UnboundedSender<ProxyEvent>) -> Result<ProxyHandle, ProxyError>;
```

**Behaviour:**
- **CA:** fresh P-256 root, valid 7 days, common name `authexodus (remove after use)`. When `constrained`, add an X.509 name constraint permitting only the DNS subtree `authy.com`. The stored blob is certificate + key.
- **Proxy:** CONNECT to `AUTHY_HOST` or `CHECK_HOST` is TLS-intercepted with a leaf signed by the CA; everything else is a blind tunnel; plain HTTP is forwarded. Requests addressed to the proxy's own address serve `/` (a small page with one "Download certificate" button and a "Test" link to `https://CHECK_HOST/`) and `/cert` (DER, `application/x-x509-ca-cert`). `CHECK_HOST` returns a "Certificate is trusted" page.
- **Events:** `DeviceConnected` on the first non-loopback peer. `TrustWorking` on the first completed TLS handshake for an intercepted host. `TlsRejected` when the client aborts that handshake. `BackupCaptured` when `capture::merge` grows the backup. `AuthyError` for a 4xx/5xx from Authy (path without query string).
- **Port:** bind `preferred_port`; if taken, bind port 0 and report the real port.
- **Logging:** nothing about non-intercepted hosts. For intercepted hosts: method, path without query, status.

**Tests:**
- [ ] `capture::inspect` recognises a tokens body, an apps body, and ignores anything else
- [ ] `later_empty_response_does_not_clobber` (40 tokens then `{"authenticator_tokens":[]}` → still 40) and `merge_keeps_the_larger_set`
- [ ] `ca_round_trips_through_keystore` and `destroy_removes_the_key`
- [ ] `constrained_ca_has_name_constraint` (parse the DER, assert the permitted subtree)
- [ ] integration `intercepts_authy_and_captures_backup` (fake upstream serves a synthetic tokens body; a client trusting the CA fetches it through the proxy; `BackupCaptured { count }` fires and `backup()` holds the tokens)
- [ ] integration `other_hosts_are_tunnelled_untouched` (client sees the other server's own certificate)
- [ ] integration `plain_http_is_forwarded`
- [ ] integration `untrusting_client_emits_tls_rejected`
- [ ] integration `serves_certificate_and_check_page`
- [ ] `falls_back_when_port_in_use`
- [ ] `logs_never_contain_query_strings` (capture log output during a request with `?api_key=SECRET`)

### Package 1D: `bitwarden`

**Files:** `crates/core/src/bitwarden/*.rs`, `crates/core/tests/bitwarden.rs`.
**Reference:** `reference/manual-run-2026-10-02/bw_match.py`.

**Produces:**

```rust
pub struct VaultLogin { pub id: String, pub name: String, pub username: Option<String>, pub hosts: Vec<String>, pub has_totp: bool }
pub enum Region { Us, Eu, SelfHosted(String) }
pub enum LoginOutcome { Ok, NeedsTwoFactor, BadCredentials }
pub enum SetTotp { Attached, AlreadyHasCode }
pub enum BwError { Server(String), SessionExpired, Cli(String), Download(String), ChecksumMismatch }
#[async_trait] pub trait BwClient: Send + Sync {
    async fn login(&mut self, email: &str, password: &str, region: &Region, two_factor: Option<&str>) -> Result<LoginOutcome, BwError>;
    async fn sync(&self) -> Result<(), BwError>;
    async fn list_logins(&self) -> Result<Vec<VaultLogin>, BwError>;
    async fn import_folder_titles(&self) -> Result<Vec<String>, BwError>;      // names already in "Authy import"
    async fn set_totp(&self, item_id: &str, otpauth: &str) -> Result<SetTotp, BwError>;
    async fn create_in_import_folder(&self, title: &str, username: Option<&str>, otpauth: &str) -> Result<(), BwError>;
    async fn logout_and_wipe(&mut self) -> Result<(), BwError>;
}
pub struct CliClient;  impl CliClient { pub fn new(binary: PathBuf, data_dir: PathBuf) -> CliClient; }
pub async fn ensure_cli(dir: &Path) -> Result<PathBuf, BwError>;

pub enum Decision { Attach { item_id: String }, CreateNew, Skip }
pub enum Confidence { High, Low }
pub struct Proposal { pub token_id: String, pub decision: Decision, pub confidence: Confidence, pub candidates: Vec<String> }
pub fn propose(tokens: &[Token], vault: &[VaultLogin]) -> Vec<Proposal>;
pub struct ApplyReport { pub attached: usize, pub created: usize, pub skipped: usize, pub kept: Vec<String>, pub failed: Option<String> }
pub async fn apply(client: &dyn BwClient, tokens: &[Token], decisions: &[(String, Decision)], progress: &(dyn Fn(String) + Sync)) -> ApplyReport;
```

**Behaviour:**
- **`CliClient`:** runs the `bw` binary with `BITWARDENCLI_APPDATA_DIR` set to `data_dir` (private to this app), `--nointeraction`, and the master password passed through `--passwordenv` on the child process only. The session key is held in memory. `logout_and_wipe` logs out and deletes `data_dir`.
- **`ensure_cli`:** downloads one pinned Bitwarden CLI release for the current architecture from the official GitHub release and compares its SHA-256 against a constant in the source. The implementer pins the current stable release and records both checksums (arm64, x64) in `download.rs`.
- **`propose`:** build search keys per token from issuer, logo and name, plus an alias table (`amazon web services`→`aws`,`amazon`; `microsoft`→`microsoft`,`live`,`office`; `google`/`gmail`→`google`,`gmail`). Score each login: a key appears in the login name or a host +3; username equals the token's username +2. Logins that already have a code are listed as candidates but never chosen. One clear top candidate with a service match → `Attach`, `High`. A tie, or username-only evidence → `Attach` to the best with `Low` and all tied candidates listed. No service match → `CreateNew`, `High`. A login is proposed for at most one token; a second claimant becomes `Low`.
- **`apply`:** sync first. `Attach`: `set_totp`; `AlreadyHasCode` goes to `kept`, not counted as an error. `CreateNew`: skip if the title is already in the import folder. On the first `BwError`, stop and put a plain message in `failed`; everything done so far stays done.

**Tests (against a `FakeBw` in the test file):**
- [ ] `exact_service_and_username_is_high_confidence`
- [ ] `two_logins_for_one_service_is_low_with_both_candidates` (three Shopify logins)
- [ ] `login_with_existing_code_is_never_chosen`
- [ ] `no_match_creates_new`
- [ ] `one_login_is_not_given_to_two_tokens`
- [ ] `alias_table_matches_aws_and_microsoft`
- [ ] `apply_never_overwrites_existing_code`
- [ ] `apply_resumes_after_failure` (fake fails with `Server` on the 10th write; second `apply` with the same decisions ends with every token present exactly once)
- [ ] `session_expiry_stops_with_plain_message`
- [ ] `checksum_mismatch_refuses_the_binary` (downloader pointed at a local file server)
- [ ] `cli_client_parses_real_list_output` (fixture JSON shaped like `bw list items`, synthetic values)

- [ ] **Review Batch 1** (one review across all four packages; overlap it with the start of Batch 2).

---

## Batch 2: Shell and UI (two agents in parallel)

### Package 2A: Tauri shell

**Files:** `src-tauri/src/{main,commands,session,keychain,network}.rs`.
**Consumes:** every `Produces` block in Batch 1. **Produces:** the Rust side of `ui/src/api.ts`, command for command.

**Behaviour:**
- **`session.rs`:** one `Session` in Tauri state holding the proxy handle, the `Authority`, `Option<Unlocked>`, the Bitwarden client, and the current step. A marker file `session.json` in the app data directory holds only `{ "caCreated": true }`; it is written when the CA is created and removed by `finish`. `getState` reports `resumeCleanup: true` when the marker exists at launch.
- **`keychain.rs`:** `KeyStore` on the macOS Keychain via `keyring` (service `dev.somecorp.authexodus`, account `ca`).
- **`network.rs`:** list IPv4 addresses on up, non-loopback, non-point-to-point interfaces; default to the first RFC 1918 address; label each by interface type (Wi-Fi, Ethernet).
- **`cleanup`:** shut the proxy down, `Authority::destroy`, `logout_and_wipe`, drop `Unlocked`.
- **`exportFile`:** native save dialog, default name from `ExportFile::suggested_name`, file mode 0600.
- **`liveCodes`:** `totp::code` for every token at the current time.
- Secrets cross to the UI only through `tokenQr`, `googleMigrationQrs` and `liveCodes`.

**Tests:**
- [ ] `picks_private_lan_address` (given `[127.0.0.1, 100.64.0.2 (utun), 192.168.4.109 (en0)]` → default is `192.168.4.109`)
- [ ] `marker_makes_next_launch_resume_cleanup`
- [ ] `cleanup_destroys_key_and_drops_secrets` (with `MemoryKeyStore`)
- [ ] `unlock_command_maps_wrong_password_to_error_variant`
- [ ] `export_file_is_written_owner_only`
- [ ] `commands_match_api_contract` (a test lists registered command names and compares them with the method names in `ui/src/api.ts`)

### Package 2B: Wizard UI

**Files:** `ui/src/{wizard,screens,device,failures,strings}/**`, `ui/src/api.fake.ts`.
**Consumes:** `ui/src/api.ts`. Built entirely against `api.fake.ts`; no Tauri needed to run or test it. Use the frontend-design skill for the visual direction.

**Behaviour:**
- **`wizard/machine.ts`:** a pure reducer over `Step` with events for user actions and `ProxyEvent`s. `deviceConnected` advances connect → certificate; `trustWorking` advances certificate → authy; `backupCaptured` advances authy → unlock. `resumeCleanup` starts at cleanup. The welcome step cannot advance until the device is chosen and all four checks are ticked. Cleanup cannot finish until every item is ticked.
- **`device/`:** drawn Settings screens as SVG React components, each in an iPhone frame and an iPad frame (iPad shows the Settings sidebar): Wi-Fi list, network detail with Configure Proxy, the Manual proxy form with the live IP and port highlighted, Profile Downloaded, Install Profile, Certificate Trust Settings with the toggle, VPN & Device Management (for removal), Authy's backup-password prompt, and the four Authy settings checks.
- **Screens:** the eight from the spec. Destination offers QR-by-QR, a file per app, Google Authenticator migration QRs, and the Bitwarden path (prepare → sign in with region and two-factor → match table with low-confidence rows shown as questions → apply with live progress → report, with "Run again" when `failed` is set). The verify screen refreshes `liveCodes` every second. Native and invalid tokens are listed by name with what to do about each.
- **`failures/`:** one panel each for: firewall prompt, isolated or different Wi-Fi, VPN or Private Relay, trust not switched on (shown on `tlsRejected`), Authy attestation error (shown on `authyError`), wrong password, Bitwarden server error, and "the method no longer works" (shown when the check page proved trust but Authy still rejects TLS), which links to the manual re-enrolment guide. A "Having trouble?" control on each waiting step opens the relevant panels.
- Android users: the welcome screen says the app cannot help and shows the manual route.

**Tests (vitest + Testing Library):**
- [ ] `welcome_blocks_until_device_and_all_checks`
- [ ] `proxy_events_advance_the_wizard`
- [ ] `resume_starts_at_cleanup`
- [ ] `cleanup_blocks_until_every_item_ticked`
- [ ] `proxy_form_illustration_shows_live_ip_and_port` (both device frames)
- [ ] `wrong_password_shows_inline_error_and_keeps_input`
- [ ] `low_confidence_matches_require_a_choice_before_apply`
- [ ] `failed_apply_offers_run_again`
- [ ] `tls_rejected_shows_trust_help`
- [ ] `invalid_and_native_tokens_are_listed_not_exported`
- [ ] `no_string_literals_outside_strings_file` (lint rule or test over `screens/`)

- [ ] **Review Batch 2.**

---

## Batch 3: Integration and release (one agent)

**Files:** `ui/src/api.tauri.ts`, `src-tauri/tests/e2e.rs`, `README.md`, `LICENSE`, `docs/manual-device-checklist.md`, `.github/workflows/release.yml`.

- [ ] **Wire the UI to the shell.** `api.tauri.ts` implements `Api` with `invoke`/`listen`. `pnpm tauri dev` shows the wizard driven by the real core.
- [ ] **Simulated-phone end-to-end test** (`src-tauri/tests/e2e.rs`): start a session with a fake Authy upstream; a client that trusts the CA fetches the tokens through the proxy; `unlock` with the known password; `exportFile` for Bitwarden; `liveCodes` returns codes that match `totp::code`; `cleanup` leaves no key in the store. This is the whole flow minus the real device.
- [ ] **Manual run on this Mac.** Launch the built app and walk every screen with the simulated phone, using the `run` skill. Fix what is found.
- [ ] **`docs/manual-device-checklist.md`:** the real-device script for Batch 4, one tick box per wizard step and per failure panel that can be provoked (trust off, Private Relay on, wrong password), on iPhone and on iPad.
- [ ] **README:** what it does, the iPhone-or-iPad requirement, the safety checks, the not-affiliated statement, how to build, how to verify a release.
- [ ] **Release workflow:** `tauri-action` building a universal `.dmg`, signed and notarized, on a version tag. Needs repository secrets from Jeff (below).
- [ ] **Review Batch 3.**

---

## Batch 4: Real-device verification (Jeff, with an agent on call)

- [ ] Run `docs/manual-device-checklist.md` on an iPhone and on an iPad against a real Authy account.
- [ ] **Settle the name-constraint question:** with the constrained CA, Authy must sign in and the check page must load. If iOS refuses the constrained root, flip the default to unconstrained, and add a line to the cleanup screen saying why removing the profile matters.
- [ ] Fix what the run finds, then a final whole-branch review run as parallel reviewers (core security, proxy correctness, UI copy and accessibility).
- [ ] Tag `v0.1.0`.

---

## Needed from Jeff

- **Licence:** MIT unless you say otherwise (it leaves a paid build open later).
- **Signing:** Apple Developer ID certificate, team ID and an app-specific password as GitHub secrets, before the release workflow can run.
- **GitHub:** create the repository (public or private to start) and push.
- **Batch 4:** about an hour with an iPhone or iPad and your Authy account.
