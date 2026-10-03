# Contributing

Thanks for helping. authexodus is pre-release, and the most valuable help is evidence from real devices.

## Device results

Run the [real-device checklist](docs/manual-device-checklist.md) and open an issue with what you found: your Mac's macOS version, your iPhone or iPad and its iOS version, Authy's version, and which steps passed or failed. If the app was launched from Terminal with `AUTHEXODUS_LOG=debug`, include the relevant lines. They are designed to hold no secrets, but read them before you paste.

Never include codes, QR codes, screenshots of codes, backup passwords, master passwords, Authy backups or your phone number.

## Code

```
pnpm install --frozen-lockfile
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
pnpm -C ui test
pnpm -C ui exec tsc --noEmit
pnpm -C ui build
```

- The core logic lives in `crates/core` and has no Tauri dependency; the app shell is `src-tauri`; the wizard is `ui`.
- All on-screen text is in `ui/src/strings/en.ts`. A test fails on text written anywhere else.
- The UI and the shell talk only through the contract in `ui/src/api.ts`. A test fails if the two sides drift apart.
- Test fixtures must be made up. Never commit real account names, codes or backups.
- Do not launch the app as part of an automated test: starting a run opens a proxy on the local network.

By contributing you agree that your contribution is licensed under the GNU General Public License, version 3 (see [LICENSE](LICENSE)).
