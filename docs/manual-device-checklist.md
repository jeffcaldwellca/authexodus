# Manual device checklist (before v0.1.0)

This is the script for the first real run of authexodus with a real Mac, a real iPhone, a real iPad and a real Authy account. Nothing in it can be done by an automated test. Until it has been done, every claim the app makes about iOS, Authy, Keychain, the firewall and the window itself is untested.

Work through it in order. Tick a box only when you have seen the thing happen. When something differs from what is written here, do not tick it: write what you saw in the Notes lines, and carry on if you safely can.

How to read the checks: **App says** is text you should find on the screen, word for word (it comes from `ui/src/strings/en.ts`). If the words differ, that is a finding too.

## Before you start

You need:

- [ ] A Mac with the built app. Use the `.app` or `.dmg` built from the commit being tagged. Note its version and commit: ______
- [ ] An iPhone and an iPad, both with an Authy account that has real accounts in it. Use a spare device if you can: the one you run this on has Authy deleted for a while.
- [ ] The Mac and the device on the same home Wi-Fi (not a guest network).
- [ ] A second authenticator app to move codes into. For the file tests you also need the apps listed in "Export formats" below.
- [ ] A Bitwarden account with some logins, for the Bitwarden section. A throwaway vault is better than your real one.
- [ ] An Android phone or tablet, only for the Aegis test (Aegis is Android-only).
- [ ] Keychain Access open on the Mac (Applications > Utilities > Keychain Access), with the search box set to `dev.somecorp.authexodus`.
- [ ] Finder open at `~/Library/Application Support/dev.somecorp.authexodus` (Finder > Go > Go to Folder). It may not exist yet.

Safety prerequisites. Do these first, on every Authy device, before deleting anything:

- [ ] You know your Authy backup password. Prove it: it is the password Authy asks for when you add Authy to a new device. If you are not sure, stop here and reset nothing.
- [ ] In Authy: Settings > Accounts > Authenticator Backups is on.
- [ ] In Authy: Settings > Devices > Allow Multi-device is on.
- [ ] Write down, on paper, the name of three accounts and the code Authy shows for each right now. You will compare them later.
- [ ] Optional but wise: for the three most important accounts, make sure you have their recovery codes saved.

If a step here fails, the app can lock you out of Authy for 24 hours. That is why these come first.

Record the versions you are testing with (also in the table at the end): Mac macOS version ______, Authy version ______, iPhone iOS ______, iPad iPadOS ______.

## Step 0: does it launch at all

This is the first time the app has ever run in a real window. Everything else depends on this.

- [ ] Open the app. Right-click it and choose Open the first time, because it may not be notarized yet. Note what macOS says: ______
- [ ] A window titled `authexodus` opens, 960 by 720.
- [ ] The window shows the Welcome screen: the title **Move your codes out of Authy** and a list of steps on the left (Safety check, Connect, Certificate, Reinstall Authy, Unlock, Move codes, Check codes, Clean up).
- [ ] The window is NOT blank or white. If it is blank, the content-security policy (in `tauri.conf.json`) or the capability file (`src-tauri/capabilities/default.json`) is blocking the screen. Stop and record what you see (blank white or blank dark, any text at all). A developer then runs a debug build to read the error. Notes: ______
- [ ] The text is styled (not plain unstyled text). Under the steps list it says `Version 0.1.0`, then **New versions are published at** and an address.

## First-launch checks that need a real window

- [ ] Keychain. Go to the Connect step (see below). When the app first creates its certificate, macOS may ask for permission to use the Keychain. Write down the exact wording of the prompt: ______
- [ ] In Keychain Access, a new item appears with service `dev.somecorp.authexodus` (account `ca`). Note the kind and which keychain it is in: ______
- [ ] The Mac firewall. If the macOS firewall is on, a prompt asks whether authexodus can accept incoming network connections. Write down the wording: ______ Choose Allow.
- [ ] Events reach the app. When the iPhone or iPad connects (Connect step), the screen moves on by itself within a few seconds, without you clicking. If it does not, events are not arriving: note it. This is also the check for the capability file (see open question f).
- [ ] The save dialog (done later, in "Move codes"): choosing Save a file opens the normal macOS save window. After saving, open Terminal and run `ls -l` on the file. The permissions column must read `-rw-------` (owner read and write only). Write what you see: ______
- [ ] Quit in the middle of the flow. When the certificate is installed and you are at the Reinstall Authy step, quit the app (Cmd-Q). Open it again. It must open on the **Clean up** screen with the line "The app was closed before clean-up finished last time. Finish these steps now." Record: ______
- [ ] After quitting, the Keychain item is still there (that is correct: the key stays until cleanup).
- [ ] In the Finder folder, `session.json` exists once the Connect screen has appeared. (It holds only that a certificate was created.) Its permissions: the folder itself should be owner-only (`ls -ld` shows `drwx------`): ______

## The happy path on an iPhone

Use the iPhone. Each step names the exact words to look for. If the words on the iPhone differ from the app's, tick nothing and write the real words in Notes.

### Safety check (Welcome)

- [ ] Choose **iPhone** under "Which device has Authy on it?".
- [ ] The Start button is disabled and the screen says "Choose your device and tick all four to start." until you tick all four boxes.
- [ ] The four checks name these paths. Confirm each one against real Authy:
  - [ ] "In Authy: Settings > Accounts > Authenticator Backups is switched on." Is this the real menu path in the current Authy? Real path: ______
  - [ ] "In Authy: Settings > Devices > Allow Multi-device is switched on." Real path: ______
  - [ ] The "Show picture" pictures match what Authy looks like. Notes: ______
- [ ] Tick all four. The button becomes Start. Click it.

### Connect

- [ ] The screen says **Connect your iPhone to this computer** and shows a Server address and a Port. Write them: ______ : ______
- [ ] The Server address is the Mac's Wi-Fi address (compare with System Settings > Wi-Fi > Details > IP address). It is not 127.0.0.1 or a VPN address.
- [ ] "Show picture" shows drawings of the iPhone Settings screens that match what you see.
- [ ] On the iPhone: Settings > Wi-Fi.
- [ ] Tap the blue (i) beside your network.
- [ ] Scroll down. Tap Configure Proxy.
- [ ] Tap Manual. Type the Server and Port from the app. Leave Authentication off. Tap Save.
- [ ] Confirm the exact words and positions of each of those on the real iOS version. Differences: ______
- [ ] The app moves on by itself to Certificate (it detected the device).

### Certificate

- [ ] A QR code and a typed address are shown.
- [ ] On the iPhone: open Camera, point at the QR code, open the link. Safari opens a page titled authexodus with a **Download certificate** button and a **Test** link. The page loads over the proxy (the phone is proxied, so this proves the proxy serves plain HTTP to the phone).
- [ ] Tap Download certificate, then Allow. iOS says the profile was downloaded.
- [ ] Open Settings. Near the top is **Profile Downloaded**. If it is not, go to General > VPN & Device Management.
- [ ] The profile's displayed name is exactly **authexodus (remove after use)**. Write what iOS shows: ______ Does iOS show it as "Not Signed"? ______
- [ ] Tap Install, enter the passcode, tap Install again.
- [ ] Go to Settings > General > About > Certificate Trust Settings. Switch on **authexodus (remove after use)**. Tap Continue.
- [ ] Go back to the Safari page and tap **Test**. The page says **Certificate is trusted**. (If it fails, this is open question a.)
- [ ] The app moves on by itself to Reinstall Authy.

### Reinstall Authy

- [ ] On the iPhone: touch and hold the Authy icon. Choose Remove App, then Delete App. Confirm this is the real wording: ______
- [ ] Install Authy from the App Store. Open it.
- [ ] Enter your phone number and choose SMS. (If Authy shows an error about an "attestation token", stop and go to open question d.)
- [ ] Authy asks for the backup password. STOP there, and do not type it yet.
- [ ] The app moves on by itself and shows **Captured N accounts** where N is the number of accounts you have. Write N: ______ Authy shows ______ accounts. They should match, less any Authy-native ones (those arrive separately).

### Unlock

- [ ] Type a wrong password first. The app says "That password is not right." and keeps what you typed in the box.
- [ ] Type the correct backup password. The Unlock button works and the screen moves on.
- [ ] Now type the same password into Authy on the iPhone. Authy shows your accounts again.
- [ ] If your password has a space at the start or end, or a non-English character, it still works (the app uses it exactly as typed). Only test this if your real password has one.

### Move codes (Destination)

- [ ] The screen says "N accounts are ready to move" and shows the four choices.
- [ ] Any Authy-native 7-digit account (for example Twitch) appears under "can't be moved", with the line telling you to set it up again yourself. Count: ______
- [ ] Do each destination in the sections "Export formats" and "Bitwarden path" below.
- [ ] The Check the codes button is disabled until you have moved your codes with one choice.

### Check codes (Verify)

- [ ] Live codes appear beside each account name and change every 30 seconds with a countdown.
- [ ] Compare the three accounts you wrote down earlier with Authy on the phone. They are identical.
- [ ] Compare the same three with the new authenticator app. They are identical. If not, check that the date and time are set automatically.
- [ ] Click **They match. Clean up**.

### Clean up

See the Cleanup section below. On the iPhone you must do each item.

## The same on an iPad

Repeat every step above on the iPad, choosing **iPad** at the start. Only the differences are listed.

- [ ] Choosing iPad changes the wording to "Connect your iPad...".
- [ ] The Settings layout is a sidebar. The app says **Open Settings and tap Wi-Fi in the sidebar.** Confirm this is right. Notes: ______
- [ ] The drawings are iPad drawings (wide, with the sidebar). They match the real screens.
- [ ] The Camera opens the link the same way.
- [ ] In the Certificate trust step, the paths are the same as on the iPhone. If iPadOS differs, write it: ______
- [ ] Authy on iPad: reinstall works the same way. Authy for iPad may be the iPhone app in a window; write what you see: ______

## Open technical questions

Each is an experiment. Do it, and write what happened.

**(a) Does iOS accept the name-constrained certificate?** The app makes a certificate that is limited to authy.com names and excludes every IP address. Nobody has checked that iOS accepts such a certificate.
- [ ] With trust switched on, the Test page said "Certificate is trusted": yes / no
- [ ] With trust on, Authy signed in and the app captured your accounts: yes / no
- If either failed with trust on, this is the answer. Record exactly what failed: ______ The fallback is a certificate with no name limit; if you reach that conclusion, tell the developer and do not use the app until it is changed. If you do end up using an unconstrained certificate, remove the profile as soon as you are done.

**(b) Does Authy work over HTTP/1.1 through the proxy?** The app only offers HTTP/1.1.
- [ ] Authy signed in and downloaded the accounts through the proxy: yes / no
- If Authy fails while the Test page works, and the app never shows "Captured", this is likely it. Record: ______

**(c) Does iOS send a TLS alert when trust is off?** The "turn on full trust" help should appear by itself in that case.
- [ ] Install the profile but leave Certificate Trust Settings OFF. Load the Test page, then open Authy. Within about a minute the app shows **The certificate isn't trusted yet** by itself: yes / no / only after clicking "Having trouble?"
- Record how long it took: ______

**(d) Does the "attestation token" workaround still work?**
- [ ] Did Authy show an "attestation token" error on your run: yes / no
- [ ] If yes: the app shows **Authy showed an error** with four steps. Following them (proxy off, enter phone number, proxy on, choose SMS) got you through: yes / no

**(e) What happens when the phone's Wi-Fi address changes?**
- [ ] After the Certificate step, turn Wi-Fi off and on on the phone, or change the phone to a different address. The phone's new address may differ from the old one. Does the app show **A different device was turned away**? yes / no
- [ ] Open "Having trouble?", choose **Restart the connection**. The phone reconnects. Authy opens again. The backup is captured. yes / no
- Record how many "restarts" were needed and the address before and after: ______

**(f) Can the permissions be narrowed?** Today the window has `core:default`.
- [ ] A developer changes `src-tauri/capabilities/default.json` so that `permissions` is `["core:event:allow-listen", "core:event:allow-unlisten"]`, rebuilds, and repeats Step 0 and the Connect step. The window renders, and the wizard still advances by itself: yes / no
- If it does, the narrower list is what to ship. If not, restore `core:default`. Notes: ______

**(g) Also record**
- [ ] How many times Authy was refused after trust was proven before the app showed **This method no longer works with Authy**? (The app guesses 3.) Only relevant if it appeared. ______

## Failure panels to provoke on purpose

For each, make the failure happen, check the right panel appears by itself (or from "Having trouble?"), follow its steps, and check that it recovers. Put the iPhone or iPad back to working at the end of each.

- [ ] **Trust left off.** Install the profile but do not switch on trust. The panel **The certificate isn't trusted yet** appears with four steps. Following them recovers.
- [ ] **iCloud Private Relay on.** Switch Private Relay on (Settings > your name > iCloud > Private Relay). Nothing arrives. Open "Having trouble?" and find **Turn off VPN and iCloud Private Relay on the iPhone**. Its steps are correct for the real Settings. Switch it off, and the app moves on.
- [ ] **Phone on a different Wi-Fi.** Put the phone on another network. "Having trouble?" shows **Both devices must be on the same Wi-Fi**, and the Server and Port shown match.
- [ ] **Firewall prompt denied.** The prompt only appears the first time the app listens (and only if the Mac firewall is on), so do this on a run where you are happy to see it. Choose **Don't Allow** at the prompt on purpose. The phone cannot connect. Open "Having trouble?": **Your Mac may be blocking the connection**, with its three steps. Follow them: confirm the path System Settings > Network > Firewall > Options exists on your macOS and lists authexodus. Set it to Allow incoming connections (or quit and reopen the app and choose Allow). The phone then connects. If the prompt never appeared because the firewall is off or already allows the app, write that and skip this one: ______
- [ ] **Wrong backup password.** Type a wrong password at Unlock. **That password is not right.** appears, the box keeps what you typed, and no accounts are lost.
- [ ] **A second device pointed at the proxy.** After the first device has completed the Certificate step, set the iPad (or another phone) to use the same proxy and open Safari or Authy. The first device keeps working. The app shows **A different device was turned away**. After you set the second device's proxy back to Off, the panel's text is understandable.
- [ ] **Bitwarden wrong master password.** On the Bitwarden sign-in, type a wrong master password: "Bitwarden did not accept that email and master password." appears.
- [ ] **Network pulled during the Bitwarden apply.** Start Apply with many accounts. Turn the Mac's Wi-Fi off partway. The app shows **Bitwarden is partly updated** with a **Run again** button. Turn Wi-Fi on, press Run again. It finishes and nothing is added twice.

## Export formats to import for real

For each: save or scan, import into the real app, then open two imported accounts and compare their codes with Authy. Tick only when the two codes match. Do not skip: several formats were written from documentation without ever being tried.

- [ ] **QR codes, one by one** ("Scan into any app"). Scan three accounts into your new app. Codes match.
- [ ] **Google Authenticator** (QR batches). In Google Authenticator: menu > Transfer accounts > Import accounts, scan every code. (UNVERIFIED: the protocol was written from memory and never scanned. The path in the app, "Transfer accounts > Import accounts", is also unchecked.) Also check: the number of QR codes (10 accounts each), and that any account that could not be included is listed under "not in these codes". Count imported: ______
- [ ] **Bitwarden file** (CSV). Bitwarden web vault > Tools > Import data > "Bitwarden (csv)". (Proven against a real vault in the original manual run, but not through this app.) Choose the file saved as `authy-bitwarden-import.csv`. Codes match.
- [ ] **1Password** (CSV `authy-1password-import.csv`). UNVERIFIED: only the "one-time password" column name is confirmed from 1Password's documentation; the other headers are not. Does 1Password import and attach a one-time password to each item? yes / no. Record any error: ______
- [ ] **2FAS** (`authy-2fas-backup.2fas`). UNVERIFIED: no official 2FAS file layout could be found; the format is guessed from third-party samples. Import it in the 2FAS app. Does it import, and do codes match? yes / no. Record: ______
- [ ] **Aegis** (`authy-aegis-import.json`). Needs an Android device with Aegis. The format was checked against Aegis's published documentation but not imported. Import, then compare two codes. Android model: ______
- [ ] **Proton Authenticator** (`authy-proton-authenticator-import.json`). PARTLY VERIFIED: Proton publishes no file layout; the app writes Aegis-style JSON in the hope that Proton's importer accepts it. Import and compare. yes / no: ______
- [ ] **Plain text** (`authy-otpauth-uris.txt`). Open the file; it has one `otpauth://` line per account. Paste one into an app that takes otpauth links, or generate a QR from it; codes match.

For every file saved:

- [ ] The save window appears and the app then says "Saved to ..." with the real path.
- [ ] The app warns that the file has no lock on it. After importing, delete the file and empty the Trash.
- [ ] Cancelling the save window gives "Nothing was saved."
- [ ] Saving over a file that already exists works, and the file is `-rw-------`.
- [ ] Account names with odd characters (quotes, commas, accents, emoji) come across unchanged. Which names did you check? ______

## The Bitwarden path

Use a real Bitwarden vault (a throwaway one is better). Choose "Bitwarden, matched to your logins".

- [ ] The app says it will download Bitwarden's tool and that this is the only time it uses the internet. Click **Download and continue**. It says the download was checked. Time taken: ______ (The app downloads Bitwarden's own command-line tool, release `cli-v2026.9.1`, from github.com and checks it against a fixed checksum. Write down whether it said it was checked.)
- [ ] Region choice: sign in with each region that applies to you. "bitwarden.com", "bitwarden.eu" or "My own server" (a self-hosted address starting `https://`). Which did you use? ______
- [ ] If your account uses an authenticator app for two-step login: the app says "Bitwarden needs your two-step login code." Enter the six digits, sign in again. It works.
- [ ] If your account uses email codes or a hardware key (YubiKey), these are not supported yet. Record what the app shows, word for word: ______ (The expected result is a clear message, not a freeze or a wrong "bad password" message.)
- [ ] The match table lists every account on the left and an action on the right. Sanity check at least five rows: each account is attached to the login you would pick yourself, or offered as **Create a new login in the "Authy import" folder**. Write any wrong attach: ______
- [ ] An account whose name is very common (for example "Amazon" or "Apple") is not attached silently to the wrong login. It is shown as a question.
- [ ] A login that already has a code is marked "already has a code" and is not selectable as a target. Check by choosing one.
- [ ] Press **Apply to Bitwarden**. The progress shows. The report says how many codes were added, how many logins were created and how many were skipped.
- [ ] In Bitwarden, open three attached logins. Each has a code, and it matches Authy.
- [ ] A new folder **Authy import** exists with the created logins.
- [ ] Run it a second time: choose **Back to the choices**, choose Bitwarden again, sign in, and apply again. It adds nothing and creates no duplicates. (Also try **Run again** after a failed apply, in the failure section.)
- [ ] An existing code is never overwritten. Before running, add a code to one login by hand (note its secret or its current code). After Apply, that login's code is unchanged.
- [ ] After the Bitwarden step, in the app data folder, `bw-data` is gone. (`bw-cli`, the downloaded tool, stays on purpose.)

## Clean up

Do this at the end of EVERY run, including runs that failed.

- [ ] In the app, the Clean up step lists the items to tick. Its line says your device has no internet until you switch the proxy off.
- [ ] On the iPhone/iPad: Settings > Wi-Fi > (i) beside your network > Configure Proxy > Off > Save. Tick **I turned the proxy off**. Safari now loads a normal web page.
- [ ] Settings > General > VPN & Device Management > **authexodus (remove after use)** > Remove Profile. Tick **I removed the certificate profile**. Also Settings > General > About > Certificate Trust Settings no longer lists it.
- [ ] If you turned off a VPN or iCloud Private Relay, turn it back on.
- [ ] Authy on the phone is signed in and shows all your accounts and codes. Tick **Authy is signed in and shows my codes**.
- [ ] If you saved a file: delete it and empty the Trash. Tick **I deleted the file I saved**.
- [ ] The app says "This computer is clean: the connection is stopped and the certificate key is destroyed."
- [ ] In Keychain Access, the `dev.somecorp.authexodus` item is gone (press Cmd-R to refresh the search).
- [ ] Click **Finish**. The Done screen says **All done**.
- [ ] Look in `~/Library/Application Support/dev.somecorp.authexodus`. Nothing from the run is left: no `session.json`, no `bw-data` folder. (A `bw-cli` file is expected if you used the Bitwarden path.) Anything else: ______
- [ ] Search the Mac for stray temporary files: in Terminal run `find ~ -name "*.authexodus-tmp" 2>/dev/null`. Expect no output.
- [ ] Quit the app and open it again. It opens on the Welcome screen (not on Clean up).
- [ ] The Mac is no longer listening: in Terminal, `lsof -iTCP:8080 -sTCP:LISTEN` prints nothing.
- [ ] Keep Authy installed for a week. Confirm one of your accounts still works with its new code after that.

## Record

One row per device run. Copy this table into the pull request or issue for the release.

| Device | OS version | Authy version | Result (pass / fail / partly) | Notes |
|---|---|---|---|---|
| iPhone | | | | |
| iPad | | | | |
| Mac (macOS) | | n/a | | |
| Android (Aegis only) | | n/a | | |

Open questions, one line each:

| Question | Answer |
|---|---|
| (a) name-constrained certificate accepted | |
| (b) Authy works over HTTP/1.1 | |
| (c) TLS alert reaches the app when trust is off | |
| (d) attestation workaround | |
| (e) address change recovers with Restart | |
| (f) narrow permissions work | |

Tag `v0.1.0` only when every box in Step 0, Unlock, Check codes, Clean up and at least one export format is ticked, and questions (a) and (b) are answered "yes".
