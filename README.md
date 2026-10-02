# authexodus

authexodus moves your two-step login codes out of Authy and into another authenticator app. Authy has no export button. This desktop app, which runs on a Mac, walks you through getting your codes out using an iPhone or iPad, and puts them where you want them: any authenticator through QR codes or an import file, or Bitwarden with each code attached to the login it belongs to.

It is for people who have never heard of a proxy. You never open a terminal.

Status: **pre-release (v0.1, not yet tagged)**. It has not yet been checked on a real iPhone, iPad and Authy account. See [Status](#status).

## Requirements

- A Mac (macOS first; Windows is not supported yet).
- An **iPhone or iPad** with Authy on it. **Android cannot use this app.** Getting codes out of Authy on Android needs changes to the phone that most people should not make. If you have only Android, use the [manual guide](docs/manual-reenrolment.md), or borrow an iPhone or iPad, install Authy on it and sign in.
- The Mac and the iPhone or iPad on the same home Wi-Fi (not a guest network).
- About 20 minutes.

## Before you start: three things in Authy

You will delete Authy and install it again. Without these three, you can be locked out for 24 hours or lose codes. The app makes you confirm them before it starts.

1. **Backups are on.** In Authy: Settings > Accounts > Authenticator Backups.
2. **You know your backup password.** It is not your phone passcode. It unlocks your codes on a new device.
3. **Multi-device is on.** In Authy: Settings > Devices > Allow Multi-device.

If you have a spare iPad or iPhone, use that. Your everyday phone then keeps working the whole time.

## How it works

1. The app runs a small proxy on your Mac, and you point your iPhone or iPad's Wi-Fi settings at it.
2. You install a short-lived certificate, made by the app on your Mac, on that device so the proxy can read Authy's traffic.
3. You delete Authy and install it again, so that Authy downloads your encrypted backup through the proxy, and the app keeps a copy.
4. You type your Authy backup password on the Mac, and the app decrypts your codes there.
5. You send the codes to your new authenticator, check that the codes match, and the app helps you remove the proxy setting and the certificate.

The method was proven by hand on 2026-10-02 (40 accounts moved).

## What it never does

- It makes no network calls, except one the first time you choose Bitwarden: it downloads Bitwarden's own command-line tool from GitHub and checks it against a fixed SHA-256 checksum. The rest of the time it uses the internet for nothing.
- No analytics. No crash reporting. No accounts.
- Your backup password and codes are never written to disk, unless you choose to save an import file. That file has no lock on it, and the app tells you to delete it after use. (Bitwarden's tool keeps its own session data in the app's folder while you use that path; the app wipes it at cleanup and when it quits.)
- It reads only Authy's API address (`api.authy.com`). Every other connection from your iPhone or iPad passes through untouched and is not recorded.
- The logs hold request paths and status codes only, never passwords, query strings, codes or bodies.
- The certificate key is created on your Mac for each run, kept in the macOS Keychain, and destroyed at cleanup.

## What cannot be moved

- **Authy's own 7-digit accounts** (for example Twitch). Authy generates these itself. The app lists them by name. Set each one up again in that service's security settings and choose a standard authenticator app.
- Any account whose key is not a valid authenticator key. The app lists these by name too.

## Status

- This is a **pre-release. It has not been verified on a real device.** The code is tested against a simulated phone and a stand-in for Authy. The real-device checklist is in [docs/manual-device-checklist.md](docs/manual-device-checklist.md).
- The method depends on Authy on iOS accepting a certificate that you install yourself. Twilio can end that at any time, for example by pinning its certificate. If it stops working, the app says so and points you to the [manual guide](docs/manual-reenrolment.md). Your codes stay in Authy.
- Several import file formats (2FAS, 1Password, Proton Authenticator) and Google Authenticator's QR batches were written from documentation and have not yet been imported into the real apps.
- Not affiliated with Twilio or Bitwarden. "Authy" is used only to describe what the app works with. authexodus exports your own data.

## Building from source

You need Xcode command line tools (`xcode-select --install`), Rust 1.93 or newer, Node 24, and pnpm 11 (the version is pinned in `package.json`; `corepack enable` provides it).

```
pnpm install --frozen-lockfile
pnpm -C ui build
pnpm tauri build --bundles app
```

The app is then at `target/release/bundle/macos/authexodus.app`, unsigned (macOS will ask you to right-click and choose Open). `pnpm tauri build --no-bundle` builds just the binary. `pnpm tauri dev` runs it in development; note that launching it writes a key to your Keychain and opens a proxy on your network, so use it deliberately.

Tests:

```
cargo test --workspace
pnpm -C ui test
pnpm -C ui exec tsc --noEmit
```

The core logic (decryption, export formats, proxy, Bitwarden matching) lives in `crates/core` and has no Tauri dependency. `src-tauri` is the thin app shell, and `ui` is the React wizard. All on-screen text is in `ui/src/strings/en.ts`.

## Verifying a download

Releases are on the [releases page](https://github.com/jeffcaldwellca/authexodus/releases). Each has a `.dmg` and a `SHA256SUMS.txt`.

1. Check the checksum. In Terminal, in the folder with both files: `shasum -a 256 -c SHA256SUMS.txt`. It must say `OK`.
2. Check that Apple has notarized the app. Drag the app out of the `.dmg` to Applications, then run:

```
spctl --assess --type execute --verbose=4 /Applications/authexodus.app
xcrun stapler validate /Applications/authexodus.app
```

   You want `accepted` with `source=Notarized Developer ID`, and `The validate action worked!`.

If either check fails, do not run the app.

## For maintainers: making a release

Push a tag like `v0.1.0` (it must equal the `version` in `src-tauri/tauri.conf.json`). `.github/workflows/release.yml` runs the tests, then builds a universal, signed and notarized `.dmg` and attaches it, with a checksum file, to a **draft** release. Check it, then publish it by hand.

The workflow stops with a clear message if any of these repository secrets (Settings > Secrets and variables > Actions) is missing, so it never produces an unsigned build:

| Secret | What it is |
|---|---|
| `APPLE_CERTIFICATE` | Developer ID Application certificate, exported as `.p12`, base64-encoded |
| `APPLE_CERTIFICATE_PASSWORD` | the password set when exporting the `.p12` |
| `APPLE_SIGNING_IDENTITY` | for example `Developer ID Application: Your Name (TEAMID)` |
| `APPLE_ID` | the Apple ID email used for notarization |
| `APPLE_PASSWORD` | an app-specific password for that Apple ID |
| `APPLE_TEAM_ID` | the 10-character team ID |

Before the first tag, run the real-device checklist.

## Licence

MIT. See [LICENSE](LICENSE).

## More

- [Real-device checklist](docs/manual-device-checklist.md)
- [Moving accounts by hand](docs/manual-reenrolment.md)
