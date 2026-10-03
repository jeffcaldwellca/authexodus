import type { AppState, ProxyInfo, SessionSnapshot, UnlockSummary } from "../api";
import {
  BROKEN_AFTER, CHECK_IDS, canFinish, canLeaveDestination, canStart, cantMoveCount, cleanupItems, initialState, reduce, troubleFor,
  type WizardEvent, type WizardState,
} from "./machine";

const PROXY: ProxyInfo = {
  addresses: [{ ip: "192.168.4.109", label: "Wi-Fi" }], ip: "192.168.4.109", port: 8080, certUrl: "http://192.168.4.109:8080/",
  certQrSvg: "<svg/>", checkUrl: "https://check/", certFingerprint: "AB", certConstrained: true,
};
const NO_SESSION: SessionSnapshot = { proxy: null, deviceConnected: false, trustWorking: false, captured: 0, summary: null };
function app(over: Partial<AppState> = {}, session: Partial<SessionSnapshot> = {}): AppState {
  return { step: "welcome", device: "ipad", resumeCleanup: false, version: "1.2.3", releasesUrl: "https://example.com/r",
    session: { ...NO_SESSION, ...session }, ...over };
}

const summary: UnlockSummary = { tokens: [{ id: "t1", title: "GitHub", username: "sam" }], invalid: [], native: [] };

function run(state: WizardState, ...events: WizardEvent[]): WizardState {
  return events.reduce(reduce, state);
}

function ready(device: "iphone" | "ipad" = "iphone"): WizardState {
  return run(
    initialState(),
    { type: "chooseDevice", device },
    ...CHECK_IDS.map((id): WizardEvent => ({ type: "setCheck", id, value: true })),
  );
}

function at(step: "connect" | "certificate" | "authy" | "unlock" | "destination" | "verify" | "cleanup"): WizardState {
  let s = run(ready(), { type: "start" });
  if (step === "connect") return s;
  s = reduce(s, { type: "proxy", event: { kind: "deviceConnected" } });
  if (step === "certificate") return s;
  s = reduce(s, { type: "proxy", event: { kind: "trustWorking" } });
  if (step === "authy") return s;
  s = reduce(s, { type: "proxy", event: { kind: "backupCaptured", count: 3 } });
  if (step === "unlock") return s;
  s = reduce(s, { type: "unlocked", summary });
  if (step === "destination") return s;
  s = run(s, { type: "moved" }, { type: "destinationDone" });
  if (step === "verify") return s;
  return reduce(s, { type: "verified" });
}

describe("wizard machine", () => {
  it("welcome_blocks_until_device_and_all_checks", () => {
    expect(CHECK_IDS).toHaveLength(5);
    expect(CHECK_IDS).toContain("sms");
    let s = initialState();
    expect(canStart(s)).toBe(false);
    expect(reduce(s, { type: "start" }).step).toBe("welcome");

    // Every check ticked but no device chosen: still blocked.
    s = run(s, ...CHECK_IDS.map((id): WizardEvent => ({ type: "setCheck", id, value: true })));
    expect(canStart(s)).toBe(false);
    expect(reduce(s, { type: "start" }).step).toBe("welcome");

    // Device chosen but one check missing: still blocked, whichever check it is.
    s = reduce(s, { type: "chooseDevice", device: "ipad" });
    for (const id of CHECK_IDS) {
      const missing = reduce(s, { type: "setCheck", id, value: false });
      expect(canStart(missing)).toBe(false);
      expect(reduce(missing, { type: "start" }).step).toBe("welcome");
    }

    // Android can never start, even with every check ticked.
    const android = reduce(s, { type: "chooseDevice", device: "android" });
    expect(android.device).toBeNull();
    expect(canStart(android)).toBe(false);
    expect(reduce(android, { type: "start" }).step).toBe("welcome");

    expect(canStart(s)).toBe(true);
    expect(reduce(s, { type: "start" }).step).toBe("connect");
  });

  it("proxy_events_advance_the_wizard", () => {
    let s = at("connect");
    s = reduce(s, { type: "proxy", event: { kind: "deviceConnected" } });
    expect(s.step).toBe("certificate");
    s = reduce(s, { type: "proxy", event: { kind: "trustWorking" } });
    expect(s.step).toBe("authy");
    s = reduce(s, { type: "proxy", event: { kind: "backupCaptured", count: 40 } });
    expect(s.step).toBe("unlock");
    expect(s.captured).toBe(40);
  });

  it("ignores proxy events on the welcome screen and after capture", () => {
    const welcome = reduce(ready(), { type: "proxy", event: { kind: "deviceConnected" } });
    expect(welcome.step).toBe("welcome");
    const later = reduce(at("destination"), { type: "proxy", event: { kind: "deviceConnected" } });
    expect(later.step).toBe("destination");
  });

  it("a repeated deviceConnected does not move past the certificate step", () => {
    const s = reduce(at("certificate"), { type: "proxy", event: { kind: "deviceConnected" } });
    expect(s.step).toBe("certificate");
  });

  it("keeps the largest capture, and a capture of only Authy's own accounts still goes on to Unlock", () => {
    // The shell sends a capture only when the backup grew. A count of 0 means it holds only
    // Authy's own accounts: there is still a backup to unlock, which lists them by name.
    const native = reduce(at("authy"), { type: "proxy", event: { kind: "backupCaptured", count: 0 } });
    expect(native.step).toBe("unlock");
    expect(native.captured).toBe(0);
    // An empty answer to the tokens request may come first; the capture that follows wins.
    const after = run(at("authy"),
      { type: "proxy", event: { kind: "emptyBackup" } },
      { type: "proxy", event: { kind: "backupCaptured", count: 0 } });
    expect(after.step).toBe("unlock");
    expect(after.emptyBackup).toBe(false);
    expect(troubleFor(after)).toBeNull();
    let s = reduce(at("authy"), { type: "proxy", event: { kind: "backupCaptured", count: 40 } });
    s = reduce(s, { type: "proxy", event: { kind: "backupCaptured", count: 0 } });
    s = reduce(s, { type: "proxy", event: { kind: "backupCaptured", count: 12 } });
    expect(s.captured).toBe(40);
    expect(s.step).toBe("unlock");
  });

  it("tlsRejected asks for trust on the certificate step, and never moves the wizard", () => {
    // Before the certificate step a rejection is expected and says nothing.
    expect(troubleFor(reduce(at("connect"), { type: "proxy", event: { kind: "tlsRejected" } }))).toBeNull();

    let s = reduce(at("certificate"), { type: "proxy", event: { kind: "tlsRejected" } });
    expect(s.step).toBe("certificate");
    expect(troubleFor(s)).toBe("trust");
    s = reduce(s, { type: "proxy", event: { kind: "trustWorking" } });
    expect(s.step).toBe("authy");
    expect(troubleFor(s)).toBeNull();
  });

  it("the method is called broken only after trust was proven and Authy is refused repeatedly", () => {
    const rejected: WizardEvent = { type: "proxy", event: { kind: "tlsRejected" } };
    let s = at("authy");
    for (let i = 1; i < BROKEN_AFTER; i++) {
      s = reduce(s, rejected);
      expect(troubleFor(s)).toBeNull();
    }
    s = reduce(s, rejected);
    expect(troubleFor(s)).toBe("methodBroken");

    // Trust seen working again wipes the count: it was a blip, not a change in Authy.
    s = reduce(s, { type: "proxy", event: { kind: "trustWorking" } });
    expect(troubleFor(s)).toBeNull();
    expect(troubleFor(reduce(s, rejected))).toBeNull();

    // Without trust ever proven, no number of rejections says the method is broken.
    let cert = at("certificate");
    for (let i = 0; i < BROKEN_AFTER + 2; i++) cert = reduce(cert, rejected);
    expect(troubleFor(cert)).toBe("trust");
  });

  it("a refused device is explained on every waiting step and cleared by a restart", () => {
    for (const step of ["connect", "certificate", "authy"] as const) {
      const s = reduce(at(step), { type: "proxy", event: { kind: "deviceRefused" } });
      expect(s.step).toBe(step);
      expect(troubleFor(s)).toBe("deviceRefused");
      const restarted = reduce(s, { type: "restarting" });
      expect(restarted.step).toBe("connect");
      expect(troubleFor(restarted)).toBeNull();
    }
    expect(reduce(at("destination"), { type: "proxy", event: { kind: "deviceRefused" } }).deviceRefused).toBe(false);
  });

  it("a restart goes back to connect, forgets trust and the capture, and keeps the device", () => {
    let s = reduce(at("authy"), { type: "proxy", event: { kind: "authyError", status: 400, path: "/x" } });
    s = reduce(s, { type: "restarting" });
    expect(s).toMatchObject({ step: "connect", trustProven: false, captured: null, authyError: null, device: "iphone", reachedAuthy: true });
    // The phone still has its certificate, so trust working again moves straight on.
    expect(reduce(s, { type: "proxy", event: { kind: "trustWorking" } }).step).toBe("authy");
    expect(reduce(at("verify"), { type: "restarting" }).step).toBe("verify");
  });

  it("authyError is surfaced on the Authy step", () => {
    const s = reduce(at("authy"), { type: "proxy", event: { kind: "authyError", status: 400, path: "/x" } });
    expect(troubleFor(s)).toBe("authyError");
    expect(s.step).toBe("authy");
  });

  it("walks unlock, destination and verify by user action", () => {
    let s = at("unlock");
    expect(reduce(s, { type: "destinationDone" }).step).toBe("unlock");
    s = reduce(s, { type: "unlocked", summary });
    expect(s.step).toBe("destination");
    expect(s.summary).toEqual(summary);
    // Nothing moved yet: the codes cannot be "checked" against an app that has none.
    expect(canLeaveDestination(s)).toBe(false);
    expect(reduce(s, { type: "destinationDone" }).step).toBe("destination");
    s = reduce(s, { type: "moved" });
    expect(canLeaveDestination(s)).toBe(true);
    s = reduce(s, { type: "destinationDone" });
    expect(s.step).toBe("verify");
    expect(reduce(s, { type: "backToDestination" }).step).toBe("destination");
    expect(reduce(s, { type: "verified" }).step).toBe("cleanup");
  });

  it("resume_starts_at_cleanup", () => {
    const s = reduce(initialState(), { type: "loaded", app: app({ resumeCleanup: true }) });
    expect(s.step).toBe("cleanup");
    expect(s.resumed).toBe(true);
    expect(s.device).toBe("ipad");
    expect(s.version).toBe("1.2.3");
    expect(s.releasesUrl).toBe("https://example.com/r");
    // After a resume we cannot know whether Authy was deleted, so cleanup asks about it.
    expect(cleanupItems(s)).toContain("authySignedIn");

    const fresh = reduce(initialState(), { type: "loaded", app: app({ device: null }) });
    expect(fresh.step).toBe("welcome");
    expect(fresh.resumed).toBe(false);
  });

  it("cleanup_blocks_until_every_item_ticked", () => {
    let s = at("cleanup");
    expect(cleanupItems(s)).toEqual(["proxyOff", "profileRemoved", "authySignedIn"]);
    expect(canFinish(s)).toBe(false);
    expect(reduce(s, { type: "finish" }).step).toBe("cleanup");

    for (const id of ["proxyOff", "profileRemoved"] as const) {
      s = reduce(s, { type: "setCleanup", id, value: true });
      expect(canFinish(s)).toBe(false);
      expect(reduce(s, { type: "finish" }).step).toBe("cleanup");
    }

    s = reduce(s, { type: "setCleanup", id: "authySignedIn", value: true });
    expect(canFinish(s)).toBe(true);

    // Unticking blocks again.
    const unticked = reduce(s, { type: "setCleanup", id: "proxyOff", value: false });
    expect(reduce(unticked, { type: "finish" }).step).toBe("cleanup");

    expect(reduce(s, { type: "finish" }).step).toBe("done");
  });

  it("adds a delete-the-file item to cleanup once a file was exported", () => {
    let s = reduce(at("destination"), { type: "fileExported" });
    s = run(s, { type: "destinationDone" }, { type: "verified" });
    expect(cleanupItems(s)).toEqual(["proxyOff", "profileRemoved", "authySignedIn", "fileDeleted"]);
    s = run(s,
      { type: "setCleanup", id: "proxyOff", value: true },
      { type: "setCleanup", id: "profileRemoved", value: true },
      { type: "setCleanup", id: "authySignedIn", value: true });
    expect(canFinish(s)).toBe(false);
    s = reduce(s, { type: "setCleanup", id: "fileDeleted", value: true });
    expect(reduce(s, { type: "finish" }).step).toBe("done");
  });

  it("abandoning part-way goes to cleanup, never straight to the end", () => {
    for (const step of ["connect", "certificate", "authy", "unlock"] as const) {
      expect(reduce(at(step), { type: "abandon" }).step).toBe("cleanup");
    }
    expect(reduce(ready(), { type: "abandon" }).step).toBe("welcome");
    expect(reduce(at("verify"), { type: "abandon" }).step).toBe("verify");
  });

  it("the destination step can be abandoned too, without moving anything, and keeps the names that cannot move", () => {
    const full: UnlockSummary = { tokens: summary.tokens, invalid: [{ name: "Old VPN", reason: "tooShort" }], native: [{ name: "Twitch" }] };
    const s = run(at("unlock"), { type: "unlocked", summary: full }, { type: "abandon" });
    expect(s).toMatchObject({ step: "cleanup", summary: null, moved: false, cantMove: { native: ["Twitch"], invalid: ["Old VPN"] } });
  });

  it("goes back from destination to unlock only while nothing has been moved", () => {
    const back = reduce(at("destination"), { type: "backToUnlock" });
    expect(back).toMatchObject({ step: "unlock", summary: null, captured: 3 });
    const moved = run(at("destination"), { type: "moved" }, { type: "backToUnlock" });
    expect(moved.step).toBe("destination");
    expect(reduce(at("verify"), { type: "backToUnlock" }).step).toBe("verify");
  });

  it("codes that are no longer unlocked send the person back to unlock", () => {
    expect(reduce(at("destination"), { type: "locked" })).toMatchObject({ step: "unlock", summary: null });
    expect(reduce(at("verify"), { type: "locked" })).toMatchObject({ step: "unlock", summary: null });
    expect(reduce(at("authy"), { type: "locked" }).step).toBe("authy");
  });

  it("cleanup asks about Authy only once the person was told to delete it", () => {
    // No device ever connected: no certificate can have been installed, so that tick is not asked for.
    expect(cleanupItems(reduce(at("connect"), { type: "abandon" }))).toEqual(["proxyOff"]);
    expect(cleanupItems(reduce(at("certificate"), { type: "abandon" }))).toEqual(["proxyOff", "profileRemoved"]);
    expect(cleanupItems(reduce(at("authy"), { type: "abandon" }))).toContain("authySignedIn");
    expect(cleanupItems(reduce(at("unlock"), { type: "abandon" }))).toContain("authySignedIn");
  });

  it("events that arrive after a restart was asked for are kept", () => {
    // The person clicks Restart; the new proxy's events can arrive before the shell answers.
    let s = reduce(at("authy"), { type: "restarting" });
    expect(s).toMatchObject({ step: "connect", restarts: 1, certificateInstalled: true });
    s = reduce(s, { type: "proxy", event: { kind: "deviceConnected" } });
    s = reduce(s, { type: "proxy", event: { kind: "trustWorking" } });
    expect(s.step).toBe("authy");
    s = reduce(s, { type: "proxy", event: { kind: "backupCaptured", count: 7 } });
    expect(s).toMatchObject({ step: "unlock", captured: 7 });
  });

  it("a resumed cleanup also asks about a saved file, since the app no longer knows", () => {
    const s = reduce(initialState(), { type: "loaded", app: app({ device: null, resumeCleanup: true }) });
    expect(cleanupItems(s)).toEqual(["proxyOff", "profileRemoved", "authySignedIn", "fileDeleted"]);
  });

  it("remembers how many accounts could not move after the summary is dropped", () => {
    let s = run(at("unlock"), { type: "unlocked", summary: {
      tokens: [{ id: "a", title: "A", username: null }], invalid: [{ name: "X", reason: "tooShort" }], native: [{ name: "Twitch" }],
    } });
    expect(cantMoveCount(s)).toBe(2);
    s = run(s, { type: "moved" }, { type: "destinationDone" }, { type: "verified" });
    expect(s.summary).toBeNull();
    // Names only, never keys: enough to tell the person at the end which accounts to set up again.
    expect(s.cantMove).toEqual({ native: ["Twitch"], invalid: ["X"] });
    expect(cantMoveCount(s)).toBe(2);
    expect(reduce(run(s, ...(["proxyOff", "profileRemoved", "authySignedIn"] as const).map((id): WizardEvent => ({ type: "setCleanup", id, value: true }))), { type: "finish" }).cantMove)
      .toEqual({ native: ["Twitch"], invalid: ["X"] });
  });

  it("with nothing to move, the destination step can be left", () => {
    const s = run(at("unlock"), { type: "unlocked", summary: { tokens: [], invalid: [], native: [{ name: "Twitch" }] } });
    expect(canLeaveDestination(s)).toBe(true);
    expect(reduce(s, { type: "destinationDone" }).step).toBe("verify");
  });

  it("drops the unlock summary when cleanup begins", () => {
    expect(at("verify").summary).not.toBeNull();
    expect(at("cleanup").summary).toBeNull();
  });

  describe("after a window reload, the wizard is rebuilt from what the shell knows", () => {
    const full: UnlockSummary = { tokens: summary.tokens, invalid: [{ name: "Old VPN", reason: "notBase32" }], native: [{ name: "Twitch" }] };
    const load = (session: Partial<SessionSnapshot>, over: Partial<AppState> = {}) =>
      reduce(initialState(), { type: "loaded", app: app(over, { proxy: PROXY, ...session }) });

    it("a cleanup the shell has begun wins over everything, even a proxy it is still stopping", () => {
      // Cleanup waits for a sign-in to give up before it stops the proxy: a reload then sees both.
      const during = load({ captured: 4, trustWorking: true }, { step: "cleanup" });
      expect(during).toMatchObject({ step: "cleanup", recovered: true, resumed: false, unsure: true });
      // A launch that found the last run unfinished.
      const resumed = reduce(initialState(), { type: "loaded", app: app({ step: "cleanup", resumeCleanup: true }) });
      expect(resumed).toMatchObject({ step: "cleanup", resumed: true, unsure: true });
    });

    it("the vault summary alone, with the proxy not reported, is still Move codes", () => {
      // The shell answers without the proxy when it is busy for a moment; the summary is kept apart.
      const s = reduce(initialState(), { type: "loaded", app: app({ step: "destination" }, { summary: full }) });
      expect(s).toMatchObject({ step: "destination", recovered: true, unsure: true });
      expect(s.summary).toEqual(full);
    });

    it("on the welcome screen, the device and the ticks kept from before the reload come back", () => {
      const checks = { device: true, backups: true, password: true, multiDevice: true, sms: true };
      const s = reduce(initialState(), { type: "loaded", app: app({ device: null }), kept: { device: "iphone", checks } });
      expect(s).toMatchObject({ step: "welcome", device: "iphone", checks });
      expect(canStart(s)).toBe(true);
      // What the shell says about the device wins over what the window kept.
      const shell = reduce(initialState(), { type: "loaded", app: app({ device: "ipad" }), kept: { device: "iphone", checks } });
      expect(shell.device).toBe("ipad");
    });

    it("a running proxy and nothing else is the connect step, with the device kept", () => {
      expect(load({})).toMatchObject({ step: "connect", device: "ipad", recovered: true, resumed: false, reachedCertificate: false });
    });

    it("a connected device is the certificate step", () => {
      expect(load({ deviceConnected: true })).toMatchObject({ step: "certificate", reachedCertificate: true, trustProven: false, reachedAuthy: false });
    });

    it("trust seen working is the Authy step", () => {
      expect(load({ deviceConnected: true, trustWorking: true }))
        .toMatchObject({ step: "authy", trustProven: true, certificateInstalled: true, reachedAuthy: true, reachedCertificate: true });
    });

    it("a captured backup is the unlock step, with its count", () => {
      expect(load({ deviceConnected: true, trustWorking: true, captured: 12 })).toMatchObject({ step: "unlock", captured: 12, reachedAuthy: true });
    });

    it("a capture holding only accounts that cannot move counts none, and is still the unlock step", () => {
      // The shell's count is of movable accounts; its step says a backup is waiting.
      expect(load({ deviceConnected: true, trustWorking: true, captured: 0 }, { step: "unlock" })).toMatchObject({ step: "unlock", captured: 0 });
      expect(load({ deviceConnected: true, trustWorking: true, captured: 0 }, { step: "authy" }).step).toBe("authy");
    });

    it("an unlocked backup is the destination step, with the names and the summary", () => {
      const s = load({ deviceConnected: true, trustWorking: true, captured: 3, summary: full });
      expect(s).toMatchObject({ step: "destination", summary: full, cantMove: { native: ["Twitch"], invalid: ["Old VPN"] }, moved: false });
      // The app cannot know whether a file was saved before the reload, so cleanup will ask.
      expect(cleanupItems(reduce(s, { type: "abandon" }))).toEqual(["proxyOff", "profileRemoved", "authySignedIn", "fileDeleted"]);
    });

    it("a running proxy wins over the resume flag: a reload must never start the cleanup by itself", () => {
      expect(load({ deviceConnected: true }, { resumeCleanup: true }).step).toBe("certificate");
    });

    it("a reload during cleanup stays on cleanup and asks about everything", () => {
      const s = reduce(initialState(), { type: "loaded", app: app({ step: "cleanup" }) });
      expect(s).toMatchObject({ step: "cleanup", resumed: false, recovered: true });
      expect(cleanupItems(s)).toEqual(["proxyOff", "profileRemoved", "authySignedIn", "fileDeleted"]);
    });

    it("with no proxy and nothing to resume, it is a fresh start whatever step the shell last saw", () => {
      expect(reduce(initialState(), { type: "loaded", app: app({ step: "done" }) }).step).toBe("welcome");
      expect(reduce(initialState(), { type: "loaded", app: app({ step: "connect" }) })).toMatchObject({ step: "welcome", recovered: false });
    });
  });

  it("the unlock step keeps counting: a later, larger capture updates the number", () => {
    let s = at("unlock");
    expect(s.captured).toBe(3);
    s = reduce(s, { type: "proxy", event: { kind: "backupCaptured", count: 9 } });
    expect(s).toMatchObject({ step: "unlock", captured: 9 });
    s = reduce(s, { type: "proxy", event: { kind: "backupCaptured", count: 2 } });
    expect(s.captured).toBe(9);
    // Nothing else the proxy says moves the unlock step.
    expect(reduce(s, { type: "proxy", event: { kind: "trustWorking" } })).toBe(s);
  });

  it("capture again: a restart from the unlock step goes back to connect and forgets the capture", () => {
    expect(reduce(at("unlock"), { type: "restarting" })).toMatchObject({ step: "connect", captured: null, restarts: 1, reachedAuthy: true });
  });

  it("an empty backup is remembered on the waiting steps until a real one or a restart", () => {
    let s = reduce(at("authy"), { type: "proxy", event: { kind: "emptyBackup" } });
    expect(s).toMatchObject({ step: "authy", emptyBackup: true });
    expect(troubleFor(s)).toBe("emptyBackup");
    expect(reduce(s, { type: "restarting" }).emptyBackup).toBe(false);
    s = reduce(s, { type: "proxy", event: { kind: "backupCaptured", count: 2 } });
    expect(s).toMatchObject({ step: "unlock", emptyBackup: false });
    expect(reduce(at("destination"), { type: "proxy", event: { kind: "emptyBackup" } }).emptyBackup).toBe(false);
  });

  it("a changed network address is flagged on the waiting steps and cleared by a restart", () => {
    for (const step of ["connect", "certificate", "authy"] as const) {
      const s = reduce(at(step), { type: "proxy", event: { kind: "addressChanged" } });
      expect(s).toMatchObject({ step, addressChanged: true });
      expect(reduce(s, { type: "restarting" })).toMatchObject({ step: "connect", addressChanged: false });
    }
    // Once the backup is captured the phone's connection no longer matters.
    expect(reduce(at("unlock"), { type: "proxy", event: { kind: "addressChanged" } }).addressChanged).toBe(false);
  });

  it("the device can still be changed on connect and certificate, and not once Authy is to be deleted", () => {
    expect(reduce(at("connect"), { type: "chooseDevice", device: "ipad" }).device).toBe("ipad");
    expect(reduce(at("certificate"), { type: "chooseDevice", device: "ipad" }).device).toBe("ipad");
    expect(reduce(at("certificate"), { type: "chooseDevice", device: "android" })).toMatchObject({ device: "iphone", android: false });
    expect(reduce(at("authy"), { type: "chooseDevice", device: "ipad" }).device).toBe("iphone");
    expect(reduce(at("destination"), { type: "chooseDevice", device: "ipad" }).device).toBe("iphone");
  });

  it("the certificate tick is asked for only when the certificate step was reached", () => {
    expect(cleanupItems(reduce(at("connect"), { type: "abandon" }))).not.toContain("profileRemoved");
    expect(cleanupItems(reduce(at("certificate"), { type: "abandon" }))).toContain("profileRemoved");
    // Trust seen working after a restart skips the certificate screen; the certificate is still there.
    const s = run(at("authy"), { type: "restarting" }, { type: "abandon" });
    expect(cleanupItems(s)).toContain("profileRemoved");
  });

  it("start again after Done is a fresh run that keeps only the device, the version and the address", () => {
    let s = at("cleanup");
    for (const id of cleanupItems(s)) s = reduce(s, { type: "setCleanup", id, value: true });
    s = reduce(s, { type: "finish" });
    expect(s.step).toBe("done");
    const fresh = reduce({ ...s, version: "1.2.3", releasesUrl: "https://example.com/r" }, { type: "startOver" });
    expect(fresh).toEqual({ ...initialState(), device: "iphone", version: "1.2.3", releasesUrl: "https://example.com/r" });
    expect(canStart(fresh)).toBe(false);
    // Only from Done: anywhere else it would throw away a run that still needs cleaning up.
    expect(reduce(at("authy"), { type: "startOver" }).step).toBe("authy");
  });
});
