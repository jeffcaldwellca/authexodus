import type { UnlockSummary } from "../api";
import {
  BROKEN_AFTER, CHECK_IDS, canFinish, canLeaveDestination, canStart, cleanupItems, initialState, reduce, troubleFor,
  type WizardEvent, type WizardState,
} from "./machine";

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

  it("keeps the largest capture and never advances on an empty one", () => {
    const empty = reduce(at("authy"), { type: "proxy", event: { kind: "backupCaptured", count: 0 } });
    expect(empty.step).toBe("authy");
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
      const restarted = reduce(s, { type: "restarted" });
      expect(restarted.step).toBe("connect");
      expect(troubleFor(restarted)).toBeNull();
    }
    expect(reduce(at("destination"), { type: "proxy", event: { kind: "deviceRefused" } }).deviceRefused).toBe(false);
  });

  it("a restart goes back to connect, forgets trust and the capture, and keeps the device", () => {
    let s = reduce(at("authy"), { type: "proxy", event: { kind: "authyError", status: 400, path: "/x" } });
    s = reduce(s, { type: "restarted" });
    expect(s).toMatchObject({ step: "connect", trustProven: false, captured: null, authyError: null, device: "iphone", reachedAuthy: true });
    // The phone still has its certificate, so trust working again moves straight on.
    expect(reduce(s, { type: "proxy", event: { kind: "trustWorking" } }).step).toBe("authy");
    expect(reduce(at("verify"), { type: "restarted" }).step).toBe("verify");
  });

  it("authyError is surfaced on the Authy step", () => {
    const s = reduce(at("authy"), { type: "proxy", event: { kind: "authyError", status: 400, path: "/x" } });
    expect(troubleFor(s)).toBe("attestation");
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
    const s = reduce(initialState(), {
      type: "loaded", app: { step: "welcome", device: "ipad", resumeCleanup: true, version: "1.2.3", releasesUrl: "https://example.com/r" },
    });
    expect(s.step).toBe("cleanup");
    expect(s.resumed).toBe(true);
    expect(s.device).toBe("ipad");
    expect(s.version).toBe("1.2.3");
    expect(s.releasesUrl).toBe("https://example.com/r");
    // After a resume we cannot know whether Authy was deleted, so cleanup asks about it.
    expect(cleanupItems(s)).toContain("authySignedIn");

    const fresh = reduce(initialState(), {
      type: "loaded", app: { step: "welcome", device: null, resumeCleanup: false, version: "1.2.3", releasesUrl: "https://example.com/r" },
    });
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

  it("cleanup asks about Authy only once the person was told to delete it", () => {
    expect(cleanupItems(reduce(at("connect"), { type: "abandon" }))).toEqual(["proxyOff", "profileRemoved"]);
    expect(cleanupItems(reduce(at("certificate"), { type: "abandon" }))).toEqual(["proxyOff", "profileRemoved"]);
    expect(cleanupItems(reduce(at("authy"), { type: "abandon" }))).toContain("authySignedIn");
    expect(cleanupItems(reduce(at("unlock"), { type: "abandon" }))).toContain("authySignedIn");
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
});
