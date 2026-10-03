# authexodus

**Export your two-factor (2FA) codes out of Authy** and into Bitwarden, 1Password, 2FAS, Aegis, Google Authenticator, Proton Authenticator or any other TOTP authenticator app. A guided Mac app for people who have never used a terminal.

authexodus moves your two-step login codes out of Authy and into another authenticator app. Authy has no export button. This desktop app, which runs on a Mac, walks you through getting your codes out using an iPhone or iPad, and puts them where you want them: any authenticator through QR codes or an import file, or Bitwarden with each code attached to the login it belongs to.

It is for people who have never heard of a proxy. Using the app never needs a terminal.

Status: **pre-release (v0.1, not yet tagged)**. It has not yet been checked on a real iPhone, iPad and Authy account. See [Status](#status).

## Why this exists

Authy keeps your codes in its own app and offers no way to export them. The old workaround, reading them out of Authy's desktop app, ended when Twilio shut that app down in August 2024. What still works is the method this app automates: Authy on an iPhone or iPad downloads your encrypted backup when you sign in, and you can capture that download on your own network and decrypt it with your own backup password. Doing that by hand means running a proxy, trusting a certificate and running a script. authexodus does the same with a step-by-step window instead.

**Contents:** [Requirements](#requirements) · [Five checks](#before-you-start-five-checks) · [How it works](#how-it-works) · [What it never does](#what-it-never-does) · [Bitwarden](#bitwarden-signing-in-and-choosing-where-each-code-goes) · [What cannot be moved](#what-cannot-be-moved) · [Tested destinations](#which-destinations-have-been-tested) · [Status](#status) · [Building](#building-from-source) · [Contributing](#contributing-and-security) · [Acknowledgements](#acknowledgements) · [Licence](#licence)

## Requirements

- A Mac (macOS first; Windows is not supported yet).
- An **iPhone or iPad** with Authy on it. **Android cannot use this app.** Getting codes out of Authy on Android needs changes to the phone that most people should not make. If you have only Android, use the [manual guide](docs/manual-reenrolment.md), or borrow an iPhone or iPad, install Authy on it and sign in.
- The Mac and the iPhone or iPad on the same Wi-Fi, and it must be **a home or office network you control**. Do not do this on public or shared Wi-Fi (a café, hotel, guest network): for a few minutes your device installs a certificate that it fetches over that network, and someone else on the same network could interfere. The app shows the certificate's fingerprint so you can compare it with what your device shows before you trust it.
- A phone that can receive a text message on the number your Authy account uses. Authy sends a code by text when you sign in again.
- About 20 minutes, with the Mac **plugged in and its lid open** the whole time. The app stops the Mac from going to sleep by itself while you work, but closing the lid still puts it to sleep, and a sleeping Mac cuts your iPhone or iPad off from the internet until it wakes.

Keep the app's window open until the last screen. Only one copy of the app can be open at a time: opening it a second time does not start a second copy.

If the Mac loses its network address while you work, the app says "This Mac's network address changed" and offers to restart the connection. A short Wi-Fi drop of more than about 10 s will show the notice; it clears itself when the address returns, and then you do not need to restart anything.

## Before you start: five checks

You will delete Authy and install it again. Without these five, you can be locked out for 24 hours or lose codes. The app makes you confirm each one before it starts.

1. **Authy on the device shows your codes.** Open it and check that your accounts are listed.
2. **Backups are on.** In Authy, open Settings and look for Authenticator Backups (usually under Accounts).
3. **You know your backup password.** It is the password Authy asks for on a new device, not the passcode that unlocks the screen. If you are not sure of it, stop: once Authy is deleted, your codes cannot be opened without it.
4. **Multi-device is on.** In Authy, open Settings and look for Allow Multi-device (usually under Devices).
5. **You can get a text message on the phone number your Authy account uses.** If that number is old or the phone is not with you, stop.

If you have a spare iPad or iPhone, use that. Your everyday phone then keeps working the whole time. Install Authy on the spare and sign in there first.

## How it works

1. The app runs a small proxy on your Mac, and you point your iPhone or iPad's Wi-Fi settings at it.
2. You install a short-lived certificate, made by the app on your Mac, on that device so the proxy can read Authy's traffic.
3. You delete Authy and install it again, so that Authy downloads your encrypted backup through the proxy, and the app keeps a copy.
4. You type your Authy backup password on the Mac, and the app decrypts your codes there.
5. You send the codes to your new authenticator, check that the codes match, and the app helps you remove the proxy setting and the certificate.

The method was proven by hand on 2026-10-02 (40 accounts moved).

## What it never does

- It makes no network calls of its own, except on the Bitwarden path: it downloads Bitwarden's own command-line tool from GitHub (checked against a fixed SHA-256 checksum), and that tool then talks to Bitwarden to sign in and add your codes. While your device is connected, its internet traffic passes through the app on its way out; that traffic is relayed, not read or recorded.
- No analytics. No crash reporting. No accounts.
- Your backup password and codes are never written to disk, unless you choose to save an import file. That file has no lock on it, and the app tells you to delete it after use. (Bitwarden's tool keeps its own session data in the app's folder while you use that path; the app wipes it at cleanup and when it quits. If the app crashes or is force-quit, it is wiped the next time the app opens.)
- It reads only Authy's API address (`api.authy.com`). Every other connection from your iPhone or iPad is passed along and is not read or recorded.
- The app writes no log file. Diagnostic lines go to the terminal, and only if you launched the app from one. They hold request paths and status codes, this Mac's and the device's network addresses, and the certificate's fingerprint; never passwords, query strings, codes or bodies. See [Diagnostic output](#diagnostic-output).
- The certificate's secret key exists only in the app's memory, for one run. It is created on your Mac when the connection first starts, kept while the app is open (restarting the connection keeps the same certificate), and dropped at cleanup. It is never written to disk or to the macOS Keychain. If you quit before cleanup, the key is gone with the app, so the certificate left on your iPhone or iPad is useless: nothing can ever sign with it again, and it stops being valid after 7 days anyway. The next launch still opens on the Clean up screen, so that you remove the certificate profile and switch the proxy off on your device.
- The app uses the certificate only to read what Authy sends. By default the certificate is also limited to Authy's addresses, so that it would be of no use for anything else; whether iOS accepts and enforces that limit is one of the things the first real-device test settles.

## Bitwarden: signing in, and choosing where each code goes

The Bitwarden path signs in through Bitwarden's own command-line tool, which the app downloads and checks first (the download shows its progress and can be cancelled). How you sign in depends on your account:

- **Two-step login with an authenticator app.** Your email, master password and the 6-digit code are enough. For a code you type in, **only codes from an authenticator app work**.
- **No two-step login, or two-step login by email or a security key.** You need a Bitwarden **API key**. Bitwarden asks every new device to confirm by email, and this app is a new device every time, with no way to enter that emailed code. An API key signs in without that step. Find it in Bitwarden's web vault under Settings → Security → Keys, at "View API key": it shows a `client_id` and a `client_secret`. On the sign-in screen choose **Sign in with an API key instead** and enter both, with your master password. The key is used once, for that sign-in, and is not kept. If you sign in with your password first, Bitwarden asks for "a code" (its tool words the emailed new-device code the same way as an authenticator app's, so the app cannot tell which it wants); the app then shows **Sign in with an API key instead** beside the code box. If you type a code there anyway, Bitwarden still wants its emailed one, and the app then shows the API-key form by itself.
- If you would rather not use an API key, choose **Save a file for another app**, then **Bitwarden**, and import the file in Bitwarden yourself.

After signing in you review every match before anything changes. The app suggests a login for each account. Change any suggestion that is wrong, or use **Choose a different login…** on a row to give that code to any login in your vault, found by searching. A login can take one code only, so a login that already has a code, or that you have given to another account, is listed but cannot be chosen.

Accounts the app cannot match become new entries in an "Authy import" folder, which you can merge in Bitwarden afterwards. A code that is already in Bitwarden is never replaced, and the report lists those separately. A login that turns out to hold a different code when the codes are added (someone gave it one after the app read your vault) is left as it is, and that account is counted as skipped. If Bitwarden signs you out part-way, the app asks you to sign in again and brings you back to your choices as you left them. If you then sign in to a different account (another email or server), the suggestions are made again for that account's vault, and the app says so.

## What cannot be moved

- **Authy's own 7-digit accounts** (for example Twitch). Authy generates these itself. The app lists them by name. Set each one up again in that service's security settings and choose a standard authenticator app.
- Any account whose key is not a valid authenticator key. The app lists these by name too.

## Which destinations have been tested

"Tested" here means: the output was imported into the real app and two codes were compared with Authy. The app says the same beside each destination.

| Destination | Status |
|---|---|
| Bitwarden import file (CSV) | Tested with the real Bitwarden (web vault, Tools → Import data, format "Bitwarden (csv)"). |
| Bitwarden, matched to your logins | Not yet tested with a real vault. The code has only run against a stand-in for Bitwarden's tool. |
| QR codes, one by one | Standard authenticator QR codes. Not yet scanned with a real app. |
| Google Authenticator transfer codes | Not yet tested with the real Google Authenticator. |
| 1Password file | Not yet tested with the real 1Password. |
| 2FAS file | Not yet tested with the real 2FAS. |
| Aegis file | Written to Aegis's published format. Not yet tested with the real Aegis. |
| Proton Authenticator file | Not yet tested with the real Proton Authenticator. In Proton Authenticator you must choose Aegis as the source: the file is in Aegis's format. |
| Plain text | One standard `otpauth://` line per account. Nothing to test it against. |

Whichever you use, check two codes against Authy before you rely on it. The app's Check codes step is for exactly that. After you save a file, the app shows where that app's import option is and, for apps that run only on a phone, how to get the file there.

## What is left on your Mac afterwards

When you press Finish on the last step, nothing of the app's own is left:

- The certificate's secret key was only ever in memory, and is gone. Nothing of it is in the Keychain.
- The app's folder, `~/Library/Application Support/dev.somecorp.authexodus`, is emptied: the record of the unfinished run, Bitwarden's session data and the downloaded Bitwarden tool are all deleted.
- Your codes and passwords were only ever in memory.

What stays is not the app's doing:

- Any import file **you** chose to save, wherever you saved it. Delete it once it is imported, and empty the Trash.
- The folders macOS makes for any app with a web view (`~/Library/WebKit/dev.somecorp.authexodus` and `~/Library/Caches/dev.somecorp.authexodus`). They hold the window's cache, not your codes. You can delete them.
- The app itself, in Applications, until you delete it.
- While the app is open, a small file at `/tmp/dev_somecorp_authexodus_si.sock`, which stops a second copy from opening. The app removes it when it quits normally; after a crash or a forced quit it stays until the next launch replaces it, or until the Mac restarts. It holds nothing of yours.

On your iPhone or iPad, the proxy setting and the certificate profile stay until **you** remove them. The Clean up step walks you through both.

## Status

- This is a **pre-release. It has not been verified on a real device.** The code is tested against a simulated phone and a stand-in for Authy. The real-device checklist is in [docs/manual-device-checklist.md](docs/manual-device-checklist.md).
- The method depends on Authy on iOS accepting a certificate that you install yourself. Twilio can end that at any time, for example by pinning its certificate. If it stops working, the app says so and points you to the [manual guide](docs/manual-reenrolment.md). Your codes stay in Authy.
- Several import file formats (2FAS, 1Password, Aegis, Proton Authenticator) and Google Authenticator's QR batches were written from documentation and have not yet been imported into the real apps. See [Which destinations have been tested](#which-destinations-have-been-tested).
- Not affiliated with Twilio or Bitwarden. "Authy" is used only to describe what the app works with. authexodus exports your own data.

## Diagnostic output

For the device test, or when something goes wrong, launch the app's binary from Terminal so its diagnostic lines are visible:

```
AUTHEXODUS_LOG=debug /Applications/authexodus.app/Contents/MacOS/authexodus
```

Nothing is written to a file. Copy the lines you need from the Terminal window.

`AUTHEXODUS_UNCONSTRAINED_CA=1` makes the app create a certificate that is **not** limited to Authy's addresses. It is a testing aid for one question only: whether iOS refuses the limited certificate. Do not use it otherwise. A certificate without the limit could be used to read any of the device's traffic if its key leaked, so remove the profile from the device as soon as the test is over.

## Building from source

You need Xcode command line tools (`xcode-select --install`), Rust 1.93 or newer, Node 24, and pnpm 11 (the version is pinned in `package.json`; `corepack enable` provides it).

```
pnpm install --frozen-lockfile
pnpm -C ui build
pnpm tauri build --bundles app
```

The app is then at `target/release/bundle/macos/authexodus.app`, unsigned (macOS will ask you to right-click and choose Open). `pnpm tauri build --no-bundle` builds just the binary. `pnpm tauri dev` runs it in development; note that starting the connection in it creates a certificate and opens a proxy on your network, so use it deliberately.

Tests:

```
cargo test --workspace
pnpm -C ui test
pnpm -C ui exec tsc --noEmit
```

The core logic (decryption, export formats, proxy, Bitwarden matching) lives in `crates/core` and has no Tauri dependency. `src-tauri` is the thin app shell, and `ui` is the React wizard. All on-screen text is in `ui/src/strings/en.ts`.

## Verifying a download

There is no release yet. Releases will be published at <https://github.com/jeffcaldwellca/authexodus/releases>. Each will have a `.dmg` and a `SHA256SUMS.txt`. The app shows the same address beside its version number.

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

## Contributing and security

Bug reports and results from the [real-device checklist](docs/manual-device-checklist.md) are the most useful contributions right now: open an issue with your device, iOS version and Authy version, and never include codes, backup passwords, screenshots of codes or your Authy phone number. See [CONTRIBUTING.md](CONTRIBUTING.md).

To report a security problem, use GitHub's private vulnerability reporting rather than a public issue. See [SECURITY.md](SECURITY.md).

## Acknowledgements

authexodus stands on work by others, and thanks them:

- **[Authy-iOS-MiTM](https://github.com/AlexTech01/Authy-iOS-MiTM)** by AlexTech01, which showed that Authy on iOS still downloads its encrypted backup in a form you can capture and decrypt with your own backup password, and documented how. The capture, the decryption (PBKDF2-HMAC-SHA1 into AES-256-CBC) and the whole flow this app guides you through follow that guide. authexodus reimplements it in Rust rather than reusing its code.
- **[mitmproxy](https://mitmproxy.org)**, the interactive HTTPS proxy. The method was first proven by hand with mitmproxy before this app existed, and the guided certificate install, the `mitm.it`-style download page and the per-run certificate authority all follow its lead. authexodus does not bundle or depend on mitmproxy; it runs its own small proxy that intercepts only Authy's servers.

Neither project is affiliated with authexodus, and they are not responsible for it.

## Licence

Copyright (c) 2026 Jeff Caldwell.

authexodus is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License, version 3, as published by the Free Software Foundation. It is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See [LICENSE](LICENSE) for the full text.

## More

- [Real-device checklist](docs/manual-device-checklist.md)
- [Moving accounts by hand](docs/manual-reenrolment.md)
