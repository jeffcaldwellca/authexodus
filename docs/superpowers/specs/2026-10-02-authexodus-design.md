# authexodus: design

Date: 2026-10-02
Status: draft for review

## Purpose

Authy has no export. authexodus is a desktop app that moves a non-technical
person's 2FA codes out of Authy into any authenticator, with smart matching for
Bitwarden. The user installs nothing else and never opens a terminal.

It automates a method proven by hand on 2026-10-02 (40 accounts moved): run an
intercepting proxy on the computer, have Authy on an iPhone or iPad sign in
through it, capture the encrypted backup Authy downloads, and decrypt it locally
with the user's backup password.

**Audience:** the public. First release is free and open source. Payment and
licensing are undecided and out of scope.

**Success:** a person who has never heard of a proxy gets every standard Authy
token into their chosen authenticator, verifies the codes match, and leaves
their phone and computer as clean as they found them.

## Constraints

- **Phone side:** iPhone or iPad only. Android needs root, so the app says so
  up front and points Android users to manual re-enrolment.
- **Computer side:** macOS first. Nothing in the core may be Mac-only except
  key storage, which sits behind an interface so Windows can follow.
- **Authy prerequisites:** backups on, backup password known, multi-device on.
  Deleting Authy without these can lock the user out for 24 hours or lose tokens.
- **Fragility:** the method works only while Authy on iOS accepts a
  user-installed root certificate. Twilio can end it with certificate pinning.
- **Stack:** Tauri. Rust core, React + TypeScript UI.

## The wizard

One linear flow. Each screen advances by itself when the app detects the step
is done, where detection is possible.

1. **Welcome and safety check.** Plain-language summary of what will happen.
   Asks which device (iPhone or iPad). Four checks the user must tick, each with
   a picture of where to find it in Authy: supported device, backups on, backup
   password known, multi-device on. Recommends a spare iPad or iPhone if one is
   available. The user cannot continue until all four are ticked.
2. **Connect the phone.** The app starts the proxy and shows drawn device
   screens (an iPhone set and an iPad set) for Settings → Wi-Fi → Configure
   Proxy, with the user's own server address and port filled in and highlighted.
   Advances when a device connects.
3. **Install the certificate.** A QR code opens a plain-HTTP download served by
   the app itself. Drawn steps for installing the profile and for turning on
   full trust under Certificate Trust Settings. Advances when an intercepted
   connection to Authy succeeds.
4. **Reinstall Authy and sign in.** Tells the user to stop at the backup
   password prompt. Shows "Captured N accounts" when the backup passes through.
5. **Unlock.** The user types the backup password. Immediate right-or-wrong
   feedback. The password is used exactly as typed.
6. **Choose a destination.** QR codes to scan one by one, an import file for a
   named app, or the Bitwarden path (below).
7. **Verify.** Live codes beside each account, to compare with Authy.
8. **Clean up.** Stops the proxy and destroys the certificate key. Walks the
   user through turning the phone proxy off and removing the profile. Not
   finished until the user ticks each item.

If the app is quit before cleanup, the next launch opens on the cleanup screen.

## Architecture

The Rust core does all sensitive work. The UI draws the wizard and holds no
secrets of its own; the core hands it a secret only for a screen that must
display one (QR codes, live codes).

### Core modules

| Module | Does | Depends on |
|---|---|---|
| `ca` | Creates a fresh certificate authority per run. Certificate is name-constrained to `authy.com`. Key lives in the OS keychain until cleanup. | `KeyStore` trait (macOS Keychain impl) |
| `proxy` | HTTP proxy. Intercepts TLS for `api.authy.com` only; tunnels everything else untouched. Serves the certificate download. Emits `DeviceConnected`, `TrustWorking`, `BackupCaptured`. | `ca`, `capture` |
| `capture` | Recognises the `authenticator_tokens` response and the Authy-native `apps` response. Holds them in memory. | none |
| `backup` | Decrypts tokens: PBKDF2-HMAC-SHA1 (salt and rounds from the token) → AES-256-CBC (per-token hex IV, zero IV if absent) → PKCS7. Validates the password against the first tokens before decrypting all. Normalises names, using the `logo` field when the issuer is blank. | none |
| `totp` | Generates codes for the verify screen. Supports 6-digit/30 s and Authy-native 7-digit/10 s. | none |
| `export` | `otpauth://` URIs, QR images, and one writer per destination app. | `backup` |
| `bitwarden` | Downloads the official CLI on demand and checks its checksum. Drives login, unlock, list, edit, create. Matching engine and idempotent apply. | `BwClient` trait (real CLI impl, fake for tests) |

### Bitwarden path

1. Download and verify the CLI (only network call the app ever makes).
2. The user signs in and unlocks inside the app. The session key stays in the
   core's memory.
3. Index the vault: name, username, website hosts, whether a code already
   exists. Never passwords.
4. Match each token to a login by service name, logo, host and username. Each
   match gets a confidence. Low-confidence and multi-candidate matches are shown
   as questions, not decided silently.
5. The user reviews a table: attach, create new, or skip, per token.
6. Apply. Never overwrites an existing code. Unmatched tokens become new logins
   in an "Authy import" folder. Safe to re-run: syncs first and skips anything
   already done, so a server error mid-run is recovered by running again.

### Export destinations at launch

QR codes, Bitwarden (file), 1Password, 2FAS, Aegis, Google Authenticator,
Proton Authenticator, and plain `otpauth://` text. Each is a small writer over
the same token list.

### Authy-native tokens

Tokens Authy issues itself (7 digits, 10 seconds) arrive in a separate `apps`
response. Observed on 2026-10-02: each entry carries a `secret_seed` (32 hex
characters, unencrypted) and `digits: 7`. The app migrates them to destinations
that accept that format, and lists any it could not move with instructions to
re-enrol by hand. That a code generated from this seed matches Authy's is still
to be confirmed by the spike below.

### Invalid tokens

A token whose decrypted secret is not valid base32 is reported by name as
"not a usable authenticator key" and is never exported.

## Failure handling

Each has its own plain-language screen with what to try:

- Mac firewall prompt blocking incoming connections.
- Wi-Fi that isolates devices (guest and hotel networks); phone on a different
  network.
- VPN or iCloud Private Relay on the phone.
- Certificate installed but full trust not switched on.
- Authy's "attestation token" error (workaround: enter the phone number with
  the proxy off, then turn it on before choosing SMS).
- Wrong backup password.
- Bitwarden server errors (retry is safe).
- The method no longer works (TLS failures from Authy with trust confirmed
  working): say so plainly and offer the manual re-enrolment guide.

## Safety rules

- The backup password and decrypted secrets are never logged and never written
  to disk, except in a file the user explicitly exports. Export screens warn to
  delete the file after importing.
- Logs record request paths and status codes only, never query strings or
  bodies.
- No analytics, no crash reporting, no network calls except the Bitwarden CLI
  download.
- The certificate key is destroyed at cleanup, and the name constraint limits
  what a leaked key could do in the meantime.
- The app states it is not affiliated with Twilio or Bitwarden and that it
  exports the user's own data. "Authy" appears only descriptively.

## Testing

- **`backup`, `export`, `totp`:** unit tests against synthetic backups
  encrypted with a known password, and RFC 6238 vectors. No real user data in
  the repository, ever.
- **`proxy`, `ca`:** integration test with a fake Authy server and a client
  that trusts the test CA: interception, pass-through of other hosts, the three
  events, the certificate download.
- **`bitwarden`:** matching and apply tested against invented vaults through
  the fake `BwClient`: duplicate names, a login that already has a code, a
  failure mid-apply then re-run, an invalid secret.
- **UI:** wizard state machine tests, including resume-at-cleanup.
- **Real device:** a written manual checklist run by a person with an iPhone or
  iPad and an Authy account. Cannot be automated.

## Spikes before the plan is final

1. **Name-constrained root on iOS:** does iOS accept and enforce a
   user-installed root limited to `authy.com`? If not, fall back to an
   unconstrained root and say so in the cleanup screen.
2. **Authy-native seeds:** the `apps` response does contain a seed. Confirm
   the derivation (seed encoding, 7 digits, 10 seconds) yields the same code
   Authy shows.
3. **Rust proxy crate:** confirm the chosen crate can intercept one host and
   blind-tunnel the rest.

## Release

- Signed and notarized `.dmg`, built by GitHub Actions, published on GitHub
  Releases. Needs an Apple Developer account.
- No auto-update. The app shows its version and links to the releases page.

## Out of scope for the first release

Payment and licensing, French, Windows, Android, auto-update, and vault
matching for password managers other than Bitwarden.
