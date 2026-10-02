# Manual device checklist (before v0.1.0)

This is the script for the first real run of authexodus with a real Mac, a real iPhone, a real iPad and a real Authy account. Nothing in it can be done by an automated test. Until it has been done, every claim the app makes about iOS, Authy, Keychain, the firewall and the window itself is untested.

Tick a box only when you have seen the thing happen. When something differs from what is written here, do not tick it: write what you saw in the Notes lines, and carry on if you safely can.

How to read the checks: **App says** is text you should find on the screen, word for word (it comes from `ui/src/strings/en.ts`). If the words differ, that is a finding too.

## Read first: plan the two runs

The checks cannot all be done in one pass, because some need a thing switched off that the normal path switches on. So there are two runs, and each experiment has a fixed place.

**Run 1, on the iPhone: the provoking run.** You break things on purpose at these points, in this order. Each is marked **[Provoke]** where it happens in the script below.

| When | What you do on purpose | What it tests |
|---|---|---|
| First launch, at the Mac's firewall prompt | Choose the option that does **not** allow it | Firewall panel (P1) |
| Connect, before setting the proxy | Switch iCloud Private Relay on | VPN / Private Relay panel (P2) |
| Connect, after P2 | Put the iPhone on a different Wi-Fi | Wi-Fi panel (P3) |
| Certificate, after installing the profile | Leave trust **off**, open Test, open Authy | Trust reminder, question (c) (P4) |
| After Certificate, before deleting Authy | Point the iPad at the same proxy | Second-device panel (P5) |
| After Certificate, before deleting Authy | Turn the iPhone's Wi-Fi off and on | Address change and Restart, question (e) (P6) |
| Reinstall Authy | "Having trouble?" then Stop and clean up, then cancel | Stop confirmation (P7) |
| Unlock | A wrong backup password first | Wrong-password message (P8) |

**Run 2, on the iPad: the clean run.** Start to finish with no experiments, exactly as a first-time person would do it. This is the run that says whether the app works.

**Bitwarden: use a THROWAWAY vault.** The maintainer's real vault already had its codes moved by hand, so running the match against it would create duplicates. Make a new free Bitwarden account, add six to ten logins by hand with names that match some of your Authy accounts (and one that already has an authenticator key), and use that.

**Test the built release app, not `pnpm tauri dev`.** Unlocking 40 accounts is slow in a debug build and would look like a hang.

**Launch from Terminal so the diagnostic lines are captured.** Every run in this checklist starts like this, in a Terminal window you keep open:

```
AUTHEXODUS_LOG=debug /path/to/authexodus.app/Contents/MacOS/authexodus 2>&1 | tee ~/Desktop/authexodus-run1.log
```

Use `authexodus-run2.log` for the iPad run. The app itself writes no log file; this is the only record. The lines hold request paths and status codes, never passwords or codes, but read the file before you share it.

**Whenever a secure connection fails** (the Test page does not load, Authy will not sign in, the app shows "The certificate isn't trusted yet" when trust is on), copy the ten or so log lines around that moment into Notes. This is how we learn whether iOS refuses the limited certificate.

## Before you start

You need:

- [ ] A Mac with the built release app (`.app` or `.dmg`) from the commit being tagged. Version and commit: ______
- [ ] An iPhone and an iPad. Authy is installed and signed in on both, with real accounts in it.
- [ ] The phone that receives text messages for your Authy number, with you and working.
- [ ] The Mac and both devices on the same home or office Wi-Fi that you control. Not a guest, café or hotel network.
- [ ] A second authenticator app to move codes into. For the file tests you also need the apps listed in "Export formats".
- [ ] The throwaway Bitwarden vault described above. Its email: ______
- [ ] An Android phone or tablet, only for the Aegis test (Aegis is Android-only).
- [ ] Keychain Access open on the Mac (Applications > Utilities > Keychain Access), search box set to `authexodus`.
- [ ] Finder open at `~/Library/Application Support/dev.somecorp.authexodus` (Finder > Go > Go to Folder). It may not exist yet.
- [ ] The Mac's firewall is ON for Run 1 (System Settings, search for Firewall), so the prompt appears.

Safety prerequisites. Do these first, on every Authy device, before deleting anything:

- [ ] You know your Authy backup password. Prove it: it is the password Authy asks for when you add Authy to a new device. If you are not sure, stop here and reset nothing.
- [ ] In Authy, Authenticator Backups is on. Real menu path: ______
- [ ] In Authy, Allow Multi-device is on. Real menu path: ______
- [ ] A text message sent to your Authy number arrives on the phone you have with you.
- [ ] Write down, on paper, the name of three accounts and the code Authy shows for each right now. You will compare them later.
- [ ] Optional but wise: for the three most important accounts, make sure you have their recovery codes saved.

If one of these is wrong, deleting Authy can lock you out for 24 hours. That is why they come first.

Record the versions (also in the table at the end): macOS ______, Authy ______, iPhone iOS ______, iPad iPadOS ______.

**If the Mac has more than one network address** (Wi-Fi and Ethernet, or a VPN): note them all here: ______ The app should default to the Wi-Fi or Ethernet address on your home network, never 127.0.0.1 and never a VPN address. On the Connect screen there is a menu, "This computer's address", to pick another. Use the address on the same network as the device. If you can, unplug Ethernet for Run 2 so there is only one.

---

# Run 1: the iPhone, provoking failures

## Step 0: does it launch at all

This is the first time the app has ever run in a real window. Everything else depends on this.

- [ ] Launch from Terminal as shown above. If macOS blocks it as unsigned, right-click the app, choose Open once, quit, then launch from Terminal. What macOS said: ______
- [ ] A window titled `authexodus` opens, about 960 by 720.
- [ ] The Welcome screen shows: the title **Move your codes out of Authy** and a list of steps on the left (Safety check, Connect, Certificate, Reinstall Authy, Unlock, Move codes, Check codes, Clean up).
- [ ] The window is NOT blank or white. If it is blank, the content-security policy (`tauri.conf.json`) or the capability file (`src-tauri/capabilities/default.json`) is blocking the screen. Stop and record what you see and the Terminal lines: ______
- [ ] The text is styled. Under the steps list it says `Version 0.1.0`, then **New versions are published at** and an address.
- [ ] Terminal shows diagnostic lines as the app starts. First few lines: ______

## Safety check (Welcome)

- [ ] **App says** "Only do this on a home or office network you control. Do not use public or shared Wi-Fi."
- [ ] Before choosing a device, the foot of the screen says "Choose your device and tick all five to start."
- [ ] Choose **iPhone** under "Which device has Authy on it?". The foot of the screen now says "5 checks left to tick."
- [ ] There are five checks. Confirm the wording of each against the real Authy:
  - [ ] "Authy on this iPhone shows my codes"
  - [ ] "Backups are turned on in Authy". The help line says to look for Authenticator Backups, usually under Accounts. Real path: ______
  - [ ] "I know my Authy backup password"
  - [ ] "Multi-device is turned on in Authy". The help line says to look for Allow Multi-device, usually under Devices. Real path: ______
  - [ ] "I can get a text message on the phone number my Authy account uses"
- [ ] The "Show picture" drawings look like the real Authy screens. Notes: ______
- [ ] Start stays disabled until all five are ticked. Tick them and click **Start**.

## Connect

- [ ] **[Provoke P1: firewall.]** When the Connect screen opens, macOS asks whether authexodus may accept incoming network connections. Exact wording of the prompt and of its two buttons ("Deny" or "Don't Allow"?): ______ Choose the one that does **not** allow it.
- [ ] Keychain: macOS may also ask for permission to use the Keychain. Exact wording: ______
- [ ] In Keychain Access, a new item appears for authexodus (service `dev.somecorp.authexodus`, account `ca`). Kind and keychain: ______
- [ ] In the Finder folder, `session.json` now exists. The folder is owner-only (`ls -ld` shows `drwx------`): ______
- [ ] The screen says **Connect your iPhone to this computer** and shows Server and Port. Write them down, you need them later: Server ______ Port ______
- [ ] The Server is the Mac's address on your home network (compare with System Settings > Wi-Fi > Details). It is not 127.0.0.1 or a VPN address.
- [ ] **App says** "If your Mac asks whether to allow incoming connections, choose Allow." above the steps.
- [ ] **[Provoke P2: Private Relay.]** On the iPhone switch iCloud Private Relay ON (Settings > your name > iCloud > Private Relay).
- [ ] On the iPhone: Settings > Wi-Fi. Tap the blue (i) beside your network. Scroll down, tap Configure Proxy, tap Manual. Type the Server and Port. Leave Authentication off. Tap Save.
- [ ] The exact words and positions on this iOS version match the app's five steps and drawings. Differences: ______
- [ ] The app does NOT move on (P1 and P2 are both in the way). Open **Having trouble?**:
  - [ ] **Your Mac may be blocking the connection** is listed, with three steps. Step 1 says to search System Settings for Firewall. Follow them: is authexodus listed under the Firewall's Options? Real path: ______ Set it to allow incoming connections (or quit, relaunch from Terminal, and allow at the prompt).
  - [ ] **Turn off VPN and iCloud Private Relay on the iPhone** is listed. Its paths are right for the real Settings: ______ Switch Private Relay off.
- [ ] **[Provoke P3: wrong Wi-Fi.]** Put the iPhone on a different Wi-Fi (a guest network or a hotspot). The app still waits. **Having trouble?** shows **Both devices must be on the same Wi-Fi**, and its last step quotes the same Server and Port you wrote down. Put the iPhone back on the home Wi-Fi and set the proxy again if iOS dropped it.
- [ ] The app moves on by itself to Certificate within a few seconds, without a click. (This is also the check that events reach the window: see question f.)
- [ ] **Address picker (only if the Mac has two addresses).** Before the device connects, choose the other address in "This computer's address". Server changes on screen and in the drawing. Choose the right one again.

## Certificate

- [ ] **App says** "The app uses this certificate only to read what Authy sends. You remove it at the end."
- [ ] A QR code, a typed address, and a **Certificate fingerprint (SHA-256)** in four short rows are shown.
- [ ] On the iPhone: open Camera, point at the QR code, open the link. Safari opens a page titled authexodus with a **Download certificate** button and a **Test** link.
- [ ] Tap Download certificate, then Allow. iOS says the profile was downloaded. Exact words: ______
- [ ] Open Settings. Near the top is **Profile Downloaded**. If not, General > VPN & Device Management.
- [ ] The profile's name is exactly **authexodus (remove after use)**. What iOS shows: ______ Shown as "Not Signed"? ______
- [ ] **Compare the fingerprint.** On the profile tap More Details, then the certificate. Find the SHA-256 fingerprint and compare it with the one in the app, pair by pair. Where exactly iOS shows it, and whether the format (pairs, spaces, colons) matches the app's: ______ They are identical: yes / no. If no, STOP and clean up.
- [ ] Tap Install. What the install sheet actually shows, in order (Install, passcode, a warning, Install, Done?): ______
- [ ] **[Provoke P4: trust left off. Question (c).]** Do NOT open Certificate Trust Settings yet.
  - [ ] Go back to the Safari page and tap **Test**. What Safari shows: ______
  - [ ] Open Authy on the iPhone (it is still installed and signed in).
  - [ ] Within about a minute the app shows **The certificate isn't trusted yet** by itself, under the steps, as a calm grey panel: yes / no / only under "Having trouble?". Time it took: ______
  - [ ] The QR code or whichever picture you were on did NOT jump to another picture.
  - [ ] Copy the Terminal lines from this moment into Notes (this is what a refused certificate looks like): ______
- [ ] Now go to Settings > General > About > Certificate Trust Settings. Switch on **authexodus (remove after use)**.
- [ ] iOS shows a warning about root certificates. Exact words, and the button's label (Continue?): ______ The app's step says "Your iPhone shows a warning. That is expected. Tap Continue."
- [ ] Go back to the Safari page and tap **Test**. The page says **Certificate is trusted**. If it does not, this is open question (a): copy the Terminal lines and go to "If the limited certificate is refused" below.
- [ ] The app moves on by itself to Reinstall Authy.

## Before deleting Authy: two more experiments

- [ ] **[Provoke P5: a second device.]** Set the iPad's Wi-Fi proxy to the same Server and Port and open Safari or Authy on it. The iPhone keeps working. The app shows **Authy can't connect? Another device was turned away**. Is the text understandable? ______ Set the iPad's proxy back to Off. Do NOT press Restart for this one; note whether the panel stays: ______
- [ ] **[Provoke P6: address change. Question (e).]** On the iPhone turn Wi-Fi off and on (or forget and rejoin the network so it gets a new address; set the proxy again if iOS dropped it). iPhone's address before ______ and after ______.
  - [ ] Does the app show the "another device was turned away" panel? yes / no
  - [ ] Press **Restart the connection** (in the panel, or under Having trouble?). The app goes back to Connect and shows: "You restarted the connection. You already installed the certificate on your iPhone, and you may have deleted Authy. Do not do either again: check Server and Port still match, open the Test page, then close Authy and open it again."
  - [ ] Server and Port on the Mac are the same as before the restart: yes / no. If they changed, the app says "This computer's address has changed. Update Server and Port on your iPhone to the ones shown here."
  - [ ] Open the Test page on the iPhone. The app moves forward by itself to Reinstall Authy without installing anything again: yes / no
  - [ ] Number of restarts needed: ______
- [ ] **"Restart on …" (only if the Mac has two addresses).** Note for later: after the backup is captured the address menu is gone, so this is tested at Connect in Run 2 if at all.

## Reinstall Authy

- [ ] **App says** (first time only) **You are about to delete Authy**, listing what you confirmed.
- [ ] **[Provoke P7: stop, then cancel.]** Open **Having trouble?**, choose **Stop and clean up**. A box asks **Stop and clean up?** and says what is lost, what you would redo, and to finish signing in to Authy. Choose **Keep going**. You are still on Reinstall Authy.
- [ ] On the iPhone: touch and hold the Authy icon and delete the app. Real wording of the menu items: ______
- [ ] Install Authy from the App Store. Open it.
- [ ] Enter your phone number and choose SMS. The text arrives on your phone.
  - [ ] If Authy shows any error, the app shows **Authy reported a problem**. If Authy's error mentions an "attestation token", this is open question (d): follow the four steps under "If Authy mentions an attestation token" and record whether they worked: ______
- [ ] Authy asks for the backup password. STOP there. Do not type it yet.
- [ ] The app moves on by itself and shows **Captured N accounts**. N: ______ Authy had ______ accounts. They should match, less any Authy-native 7-digit ones (those arrive separately).
- [ ] How long between Authy's password prompt appearing and the app moving on: ______

## Unlock

- [ ] **[Provoke P8.]** Type a wrong password first. **App says** "That password is not right." and keeps what you typed in the box.
- [ ] **App says** "Can't find the password? Keep trying here: nothing is lost by a wrong try. …"
- [ ] Type the correct backup password and press Unlock. Time it took to unlock: ______ (a release build should take seconds, not minutes).
- [ ] If your password has a space at the start or end, or a non-English character, it still works. Only test this if your real password has one.

## Move codes (Destination)

- [ ] **App says** **First, finish signing in to Authy**. Do it now: type the backup password into Authy on the iPhone. Authy shows your accounts again.
- [ ] The screen says "N accounts are ready to move".
- [ ] Any Authy-native 7-digit account (for example Twitch) is listed under "can't be moved", ABOVE the four choices. Count: ______
- [ ] **Check the codes** is disabled, and the screen says why: "Check the codes is switched off until something has been moved: …".
- [ ] Do the sections "Export formats" and "The Bitwarden path" below, then come back.
- [ ] After one code is scanned and ticked (or a file saved, or Bitwarden applied), Check the codes becomes available.

## Check codes (Verify)

- [ ] Live codes appear beside each account and change every 30 seconds. The code on screen changes at the same moment as the one in Authy (not a second late).
- [ ] Compare the three accounts you wrote down with Authy on the iPhone. Identical.
- [ ] Compare the same three with the new authenticator app. Identical. If not, check the date and time are set automatically.
- [ ] If there are accounts that can't move, a line under the list says how many still live only in Authy.
- [ ] Click **They match. Clean up**.

## Clean up

Do the "Clean up" section near the end of this document now, for the iPhone.

## Quit in the middle (do this on a third short run, or at the start of Run 2)

- [ ] With the certificate installed and the app at Reinstall Authy, quit the app (Cmd-Q). In Keychain Access the authexodus item is still there (correct: the key stays until cleanup).
- [ ] Open the app again. It opens on **Put everything back** with "The app was closed before clean-up finished last time. Finish these steps now."
- [ ] It asks which device you used, and lists four ticks: proxy off, profile removed, Authy signed in, and "I deleted any file I saved".
- [ ] Finish the cleanup. Then start Run 2 from the Welcome screen.

---

# Run 2: the iPad, the clean run

Launch from Terminal with `authexodus-run2.log`. Do every section of Run 1 again, in order, choosing **iPad**, and skip everything marked **[Provoke]**. At the firewall prompt choose to allow. Leave nothing switched off. Only the differences are listed here.

- [ ] Choosing iPad changes the wording to "Connect your iPad…".
- [ ] Settings on the iPad has a sidebar. **App says** "Open Settings and tap Wi-Fi in the sidebar." Correct? ______
- [ ] The drawings are iPad drawings (wide, with the sidebar) and match the real screens.
- [ ] In the Reinstall Authy drawing, the yellow "Stop here" flag sits beside the iPad, pointing at the password box, and does not look like a button.
- [ ] The Camera opens the QR link the same way.
- [ ] The fingerprint compares the same way on iPadOS. Where it is shown: ______
- [ ] The trust step paths are the same as on the iPhone. If iPadOS differs: ______
- [ ] Authy on iPad: reinstalling works the same way. (Authy for iPad may be the iPhone app in a window.) What you see: ______
- [ ] Start to finish with no help panel opened: yes / no. Total time: ______
- [ ] **A spare device with no Authy on it (if you have one).** Choose it on Welcome. Can the first check ("Authy on this iPad shows my codes") be ticked honestly after following "Install Authy on it and sign in first"? What happened when you installed Authy on the spare with multi-device on: ______

## If the limited certificate is refused (question a)

Only if, with trust switched ON, the Test page fails or Authy cannot sign in.

- [ ] Copy the Terminal lines around the failure: ______
- [ ] Stop and clean up in the app. Remove the profile from the device.
- [ ] Quit the app. Launch it again with the fallback, which makes a certificate that is NOT limited to Authy's addresses:

```
AUTHEXODUS_UNCONSTRAINED_CA=1 AUTHEXODUS_LOG=debug /path/to/authexodus.app/Contents/MacOS/authexodus 2>&1 | tee ~/Desktop/authexodus-unconstrained.log
```

- [ ] Repeat Connect and Certificate. With trust on, the Test page says **Certificate is trusted**: yes / no. Authy signs in and the backup is captured: yes / no.
- [ ] Remove the profile from the device as soon as this experiment ends, whatever the result. An unlimited certificate must not stay installed.
- [ ] Result, one line: the limited certificate was accepted / refused; the unlimited one worked / did not: ______

---

# Sections used by both runs

## Open technical questions

**(a) Does iOS accept the certificate limited to Authy's addresses?**
- [ ] With trust on, the Test page said "Certificate is trusted": yes / no
- [ ] With trust on, Authy signed in and the app captured your accounts: yes / no
- If either failed, do "If the limited certificate is refused" above.

**(b) Does Authy work over HTTP/1.1 through the proxy?** The app only offers HTTP/1.1.
- [ ] Authy signed in and downloaded the accounts through the proxy: yes / no
- If the Test page works but the app never shows "Captured", this is likely it. Terminal lines: ______

**(c) Does iOS send a TLS alert when trust is off?** Answered at P4: ______

**(d) Does the "attestation token" workaround still work?**
- [ ] Authy showed an "attestation token" error on a run: yes / no
- [ ] If yes, the four steps (proxy off, enter phone number, proxy on, choose SMS) got you through: yes / no

**(e) What happens when the phone's address changes?** Answered at P6. Also record:
- [ ] After the restart, did opening Authy again (if it was already reinstalled and waiting at the password prompt) fetch the backup again without deleting it a second time? yes / no / not tested: ______

**(f) Can the permissions be narrowed?** Today the window has `core:default`.
- [ ] A developer changes `src-tauri/capabilities/default.json` so that `permissions` is `["core:event:allow-listen", "core:event:allow-unlisten"]`, rebuilds, and repeats Step 0 and Connect. The window renders and the wizard still advances by itself: yes / no. Notes: ______

**(g) Also record**
- [ ] How many times Authy was refused after trust was proven before the app showed **This method no longer works with Authy**? (The app waits for 3.) Only if it appeared: ______
- [ ] Did the Mac's firewall prompt say "Deny" or "Don't Allow"? ______

## Other failures to provoke

- [ ] **Stop and clean up for real, mid-run.** On a short extra run, at Certificate choose Having trouble? > Stop and clean up > Stop and clean up. The app goes to **Put everything back**. Before switching the proxy off, try to load a web page on the device: it has no internet (the app says so at the top). Switch the proxy off: it loads. Finish. The last screen says **Cleaned up. Nothing was moved** and shows how to move an account by hand.
- [ ] **Bitwarden wrong master password.** "Bitwarden did not accept that email and master password. Type both again." appears and the password box is empty.
- [ ] **Bitwarden wrong two-step code.** With two-step login on the throwaway vault (authenticator app), type a wrong code: "Bitwarden did not accept that code. Wait for a new one and try again." The master password is not asked for again.
- [ ] **Bitwarden new-device email check.** On a vault with NO two-step login, Bitwarden may email a code to confirm a new device. What the app shows, word for word: ______ (Expected: a clear message that points to "Save a file for another app, then Bitwarden", not a freeze.)
- [ ] **Network pulled during the Bitwarden apply.** Start Apply with many accounts. Turn the Mac's Wi-Fi off partway. The app shows **Bitwarden is partly updated** with **Run again**. Turn Wi-Fi on, press Run again. It finishes and nothing is added twice.

## Export formats to import for real

For each: save or scan, import into the real app, then open two imported accounts and compare their codes with Authy. Tick only when the two codes match. Several formats were written from documentation without ever being tried.

- [ ] **QR codes, one by one** ("Scan into any app"). Scan three accounts, ticking "I scanned this code into my new app" for each. Codes match.
- [ ] **Google Authenticator** (QR batches). The app says to open the menu and look for Transfer accounts, then Import accounts. Real path in the current Google Authenticator: ______ (UNVERIFIED: the format was written from memory and never scanned.) Scan every code with a real camera, including a FULL code of 10 accounts: does a 10-account code scan from the screen at normal distance? ______ Number of codes shown: ______ Accounts imported: ______ Any account listed under "not in these codes": ______
- [ ] **Bitwarden file** (CSV). Bitwarden web vault > Tools > Import data > "Bitwarden (csv)". File `authy-bitwarden-import.csv`. Codes match.
- [ ] **1Password** (CSV `authy-1password-import.csv`). UNVERIFIED: only the "one-time password" column name is confirmed. Does 1Password import and attach a one-time password to each item? yes / no. Error: ______
- [ ] **2FAS** (`authy-2fas-backup.2fas`). UNVERIFIED: the format is guessed from third-party samples. Imports, and codes match? yes / no: ______
- [ ] **Aegis** (`authy-aegis-import.json`). Needs Android with Aegis. Import, compare two codes. Android model: ______
- [ ] **Proton Authenticator** (`authy-proton-authenticator-import.json`). PARTLY VERIFIED: Aegis-style JSON in the hope Proton accepts it. yes / no: ______
- [ ] **Plain text** (`authy-otpauth-uris.txt`). One `otpauth://` line per account. Make a QR from one line or paste it into an app that takes such links; codes match.

For every file saved:

- [ ] The normal macOS save window opens. Which folder did it open in? ______ The app then says "Saved to …" with the real path.
- [ ] In Terminal, `ls -l` on the file shows `-rw-------`: ______
- [ ] The app warns that the file has no lock on it.
- [ ] Cancelling the save window gives "Nothing was saved."
- [ ] Saving over a file that already exists works, and the file is still `-rw-------`.
- [ ] Account names with odd characters (quotes, commas, accents, emoji) come across unchanged. Names checked: ______

## The Bitwarden path

Use the THROWAWAY vault. Choose "Bitwarden, matched to your logins".

- [ ] **App says** that it downloads Bitwarden's own command-line tool and checks that it is genuine, and "Apart from this download, the app only uses the internet when Bitwarden's tool talks to Bitwarden."
- [ ] Click **Download and continue**. The app shows "Downloading Bitwarden's tool and checking it…" and then moves to **Sign in to Bitwarden**. Time taken: ______ (It downloads release `cli-v2026.9.1` from github.com and checks a fixed checksum; there is no separate "checked" message.)
- [ ] Before you type anything, the sign-in screen says that only authenticator-app codes work for two-step login, and to use "Save a file for another app, then Bitwarden" otherwise.
- [ ] Region: "bitwarden.com", "bitwarden.eu" or "My own server" (an address starting `https://`). Which you used: ______
- [ ] With an authenticator app as two-step login: **App says** "Bitwarden needs your two-step login code. Enter the 6-digit code from your authenticator app and sign in again." The master password box is gone while it waits. Enter the code. It signs in.
- [ ] The match table lists every account on the left and an action on the right. Check at least five rows: each is attached to the login you would pick, or offered as **Create a new login in the “Authy import” folder**. Any wrong attach: ______
- [ ] An account with a common name that could be two logins is shown as a question ("Which Bitwarden login does this code belong to?"), not decided for you.
- [ ] The login you gave an authenticator key by hand is listed as "already has a code", cannot be chosen, and its row waits for your answer.
- [ ] Press **Apply to Bitwarden**. Progress shows. The report says how many codes were added, how many logins were created and how many were skipped.
- [ ] In Bitwarden, open three attached logins. Each has a code, and it matches Authy.
- [ ] A new folder **Authy import** exists with the created logins.
- [ ] Run it a second time: **Back to the choices**, Bitwarden again, sign in, apply again. It adds nothing and creates no duplicates.
- [ ] The login that already had a code still has its old code.
- [ ] After the Bitwarden step, in the app data folder, `bw-data` is gone. (`bw-cli`, the downloaded tool, stays on purpose.)

## Clean up

Do this at the end of EVERY run, including runs that failed.

- [ ] **App says**, at the top, "Your iPhone has no internet until you switch its proxy off. Do that first." Confirm it is true: Safari on the device loads nothing right now.
- [ ] **App says** "This computer is clean: the connection is stopped and the certificate's secret key is destroyed, so the certificate on your iPhone is useless."
  - [ ] If instead it says **This computer could not finish cleaning up.**, it also gives the reason and says to delete the authexodus item in Keychain Access. Reason shown: ______
- [ ] On the device: Settings > Wi-Fi > (i) beside your network > Configure Proxy > Off > Save. Tick **I turned the proxy off**. Safari now loads a normal web page.
- [ ] Settings > General > VPN & Device Management > **authexodus (remove after use)** > Remove Profile. Tick **I removed the certificate profile**. Settings > General > About > Certificate Trust Settings no longer lists it.
- [ ] If you switched off a VPN or iCloud Private Relay, switch it back on.
- [ ] Authy on the device is signed in and shows all your accounts and codes. Tick **Authy is signed in and shows my codes**.
- [ ] If you saved a file: delete it and empty the Trash. Tick **I deleted the file I saved**.
- [ ] In Keychain Access, the authexodus item is gone (Cmd-R refreshes the search).
- [ ] Click **Finish**. The last screen says **All done** (or **Cleaned up. Nothing was moved** if nothing was moved). If some accounts could not move, it says how many still live only in Authy.
- [ ] In `~/Library/Application Support/dev.somecorp.authexodus` nothing from the run is left: no `session.json`, no `bw-data`. (`bw-cli` is expected after the Bitwarden path.) Anything else: ______
- [ ] In Terminal, `find ~ -name "*.authexodus-tmp" 2>/dev/null` prints nothing.
- [ ] Quit the app and open it again. It opens on Welcome, not on Clean up.
- [ ] The Mac is no longer listening: `lsof -iTCP:<the Port you wrote down> -sTCP:LISTEN` prints nothing.
- [ ] Save the Terminal log file for this run.
- [ ] Keep Authy installed for a week. Confirm one account still works with its new code after that.

## Accessibility and window (once, on either run)

- [ ] **Keyboard only.** From Welcome to Connect using only Tab, Space and Return. Every control is reachable and the focus ring is always visible. Problems: ______
- [ ] **VoiceOver** (Cmd-F5). On each screen change the heading is read, then the status line under it ("Your iPhone is connected."). "Captured N accounts" is announced. Problems: ______
- [ ] **Dark mode.** Switch macOS to Dark. Every screen from Welcome to Clean up is readable; the device drawings follow. Problems: ______
- [ ] **Small window.** Drag the window down to about 720 by 560. The step list disappears and a line such as "Step 3 of 8: Certificate" appears above the heading. Nothing is cut off; long screens scroll. Problems: ______

## Record

One row per run. Copy this table into the pull request or issue for the release, and attach the log files.

| Device | OS version | Authy version | Result (pass / fail / partly) | Notes |
|---|---|---|---|---|
| iPhone (Run 1) | | | | |
| iPad (Run 2) | | | | |
| Mac (macOS) | | n/a | | |
| Android (Aegis only) | | n/a | | |

Open questions, one line each:

| Question | Answer |
|---|---|
| (a) limited certificate accepted | |
| (b) Authy works over HTTP/1.1 | |
| (c) TLS alert reaches the app when trust is off | |
| (d) attestation workaround | |
| (e) address change recovers with Restart | |
| (f) narrow permissions work | |
| (g) refusals before "no longer works"; firewall button wording | |

Tag `v0.1.0` only when every box in Step 0, Run 2 (the clean run), Unlock, Check codes, Clean up and at least one export format is ticked, and questions (a) and (b) are answered "yes".
