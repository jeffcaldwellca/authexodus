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
    expect(readme).toMatch(/If you quit before cleanup, the key stays in the Keychain/);
    expect(readme).toMatch(/only codes from an authenticator app work/);
    expect(readme).toMatch(/AUTHEXODUS_LOG=debug/);
    expect(readme).toMatch(/AUTHEXODUS_UNCONSTRAINED_CA=1[^\n]*\n?[^\n]*testing aid/);
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
