/// <reference types="vite/client" />
// The real-device checklist quotes the app word for word, and the README repeats its
// promises. These checks fail when the wording in `en.ts` and the documents drift apart.
import checklist from "../../../docs/manual-device-checklist.md?raw";
import readme from "../../../README.md?raw";
import { en } from "./en";

const iphone = en.deviceName.iphone;

describe("documents", () => {
  it("the checklist quotes the app's current wording", () => {
    const quoted = [
      en.welcome.title,
      en.welcome.network,
      en.welcome.blocked,
      en.welcome.blockedChecks(5),
      en.welcome.checks.device.label(iphone),
      en.welcome.checks.backups.label,
      en.welcome.checks.password.label,
      en.welcome.checks.multiDevice.label,
      en.welcome.checks.sms.label,
      en.connect.title(iphone),
      en.connect.firewall,
      en.connect.addressLabel,
      en.connect.addressChanged(iphone),
      en.certificate.lede,
      en.certificate.fingerprintLabel,
      en.failures.trust.title,
      en.failures.firewall.title,
      en.failures.vpn.title(iphone),
      en.failures.wifi.title,
      en.failures.deviceRefused.title,
      en.failures.restart.noticeAfterTrust(iphone),
      en.failures.stop.title,
      en.failures.attestation.title,
      en.failures.methodBroken.title,
      en.failures.wrongPassword.title,
      en.authy.lastCheck.title,
      en.common.restart,
      en.common.keepGoing,
      en.destination.authyTitle,
      en.destination.qr.scanned,
      en.verify.confirm,
      en.bitwarden.prepare,
      en.bitwarden.preparing,
      en.bitwarden.loginTitle,
      en.bitwarden.needsTwoFactor,
      en.bitwarden.wrongTwoFactor,
      en.bitwarden.badCredentials,
      en.bitwarden.question,
      en.bitwarden.createNew,
      en.bitwarden.reportPartialTitle,
      en.cleanup.title,
      en.cleanup.resumed,
      en.cleanup.keyGone(iphone),
      en.cleanup.noInternet(iphone),
      en.cleanup.clean(iphone),
      en.cleanup.failed,
      en.cleanup.items.proxyOff.label,
      en.cleanup.items.profileRemoved.label,
      en.cleanup.items.authySignedIn.label,
      en.cleanup.items.fileDeleted.label,
      en.cleanup.items.fileDeletedMaybe.label,
      en.done.title,
      en.done.titleNothingMoved,
      en.common.stepOf(3, 8, en.rail.steps.certificate),
      en.certName,
      // Added with the completeness fixes.
      en.common.keepOpen(iphone),
      en.common.switchDevice(en.deviceName.ipad),
      en.common.reloaded(iphone),
      en.problems.byCode.address_changed.title(iphone),
      en.failures.emptyBackup.title,
      en.authy.stillWaiting.title,
      en.unlock.recapture.action,
      en.destination.backToUnlock,
      en.destination.file.guideTitle(en.destination.file.apps.bitwarden),
      en.bitwarden.introKeyTitle,
      en.bitwarden.prepareCancelled,
      en.bitwarden.useApiKey,
      en.bitwarden.apiKey.needed,
      en.bitwarden.apiKey.where,
      en.bitwarden.chooseOther,
      en.bitwarden.picker.hasCode,
      en.bitwarden.keptTitle,
      en.problems.byCode.bw_session_expired.title(iphone),
      en.bitwarden.signInAgain,
      en.cleanup.noCertificate(iphone),
      en.done.startAgain,
    ];
    const missing = quoted.filter((text) => !checklist.includes(text));
    expect(missing).toEqual([]);
  });

  it("no document still says three or four checks", () => {
    for (const doc of [checklist, readme]) {
      expect(doc).not.toMatch(/\b(three|four) (things|checks|boxes)\b/i);
      expect(doc).not.toMatch(/tick all four/i);
    }
    expect(readme).toMatch(/five checks/);
    expect(checklist).toMatch(/There are five checks/);
  });

  it("the README makes only the claims the app can back", () => {
    expect(readme).not.toMatch(/You never open a terminal/);
    expect(readme).not.toMatch(/It makes no network calls, except one/);
    expect(readme).not.toMatch(/The logs hold/);
    expect(readme).toMatch(/Using the app never needs a terminal/);
    expect(readme).toMatch(/The app writes no log file/);
    expect(readme).toMatch(/a home or office network you control/);
    // The certificate's key is never stored anywhere, and the README says so.
    expect(readme).toMatch(/The certificate's secret key exists only in the app's memory/);
    expect(readme).toMatch(/If you quit before cleanup, the key is gone with the app/);
    expect(readme).not.toMatch(/the key stays/);
    expect(readme).toMatch(/only codes from an authenticator app work/);
    expect(readme).toMatch(/AUTHEXODUS_LOG=debug/);
    expect(readme).toMatch(/AUTHEXODUS_UNCONSTRAINED_CA=1[^\n]*\n?[^\n]*testing aid/);
  });

  it("the README covers what the completeness review found missing from it", () => {
    // Sign-in by API key, and who needs it.
    expect(readme).toMatch(/API key/);
    expect(readme).toMatch(/Settings → Security → Keys/);
    expect(readme).toMatch(/no two-step login/i);
    // Attaching by hand.
    expect(readme).toMatch(/Choose a different login/);
    // Keeping the Mac awake, and one window only.
    expect(readme).toMatch(/plugged in/);
    expect(readme).toMatch(/closing the lid/i);
    expect(readme).toMatch(/only one copy/i);
    // What is left on disk.
    expect(readme).toMatch(/## What is left on your Mac afterwards/);
    expect(readme).toMatch(/Library\/Application Support\/dev\.somecorp\.authexodus/);
    // Which destinations have been tried against the real app.
    expect(readme).toMatch(/## Where your codes can go/);
    for (const app of ["1Password", "2FAS", "Aegis", "Proton Authenticator", "Google Authenticator", "Bitwarden"]) expect(readme).toContain(app);
    // The releases address does not exist yet, and the README must not say it does.
    expect(readme).toMatch(/Releases will be published at/);
    expect(readme).not.toMatch(/Releases are on the/);
  });

  it("the import steps in the app and the README agree on the two traps", () => {
    const guides = en.destination.file.guides;
    expect(guides.bitwarden.steps.join(" ")).toMatch(/Bitwarden \(csv\)/);
    expect(guides.protonAuthenticator.steps.join(" ")).toMatch(/choose Aegis/);
    expect(readme).toMatch(/Bitwarden \(csv\)/);
    expect(readme).toMatch(/choose Aegis/i);
  });

  it("the checklist covers the new experiments", () => {
    for (const needle of [
      /plugged in/, /lid open/, /API key/, /authenticator-app two-step login/, /reload/i, /Wi-Fi off and on/,
      /backups are switched off/, /Cancel/, /second copy/, /local network/i, /Dock/, /Finder/,
      /nothing is left under `~\/Library\/Application Support\/dev\.somecorp\.authexodus`/,
    ]) expect(checklist, String(needle)).toMatch(needle);
    // The old advice that could not work is gone.
    expect(checklist).not.toMatch(/`bw-cli` is expected after the Bitwarden path/);
    // The certificate key is no longer stored, so the checklist only confirms nothing was.
    expect(checklist).not.toMatch(/a new item appears for authexodus/);
    expect(checklist).not.toMatch(/the authexodus item is (still there|gone)/);
    expect(checklist).toMatch(/shows no authexodus item/);
  });

  it("no string claims the certificate can only be used for Authy", () => {
    const texts: string[] = [];
    const collect = (value: unknown) => {
      if (typeof value === "string") texts.push(value);
      else if (typeof value === "function") {
        // Wording built from values: try it with a device name. Builders that need other
        // kinds of value (lists, numbers) are not about the certificate.
        try { collect((value as (...a: unknown[]) => unknown)("iPhone", "1.2.3.4", 1)); } catch { /* not a device sentence */ }
      }
      else if (Array.isArray(value)) value.forEach(collect);
      else if (value && typeof value === "object") Object.values(value).forEach(collect);
    };
    collect(en);
    const overclaims = texts.filter((s) => /only (works|be used|used) for Authy/i.test(s) || /can only be used for/i.test(s));
    expect(overclaims).toEqual([]);
    expect(readme).not.toMatch(/can only be used for Authy/i);
  });
});
