// Wizard state machine: a pure reducer over `Step`.
//
// The machine holds no secrets. The only thing it keeps from an unlock is the `UnlockSummary`
// (names, never keys), and it drops that when cleanup begins.
import type { AppState, Device, ProxyEvent, Step, UnlockSummary } from "../api";

/** The five safety checks on the welcome screen. All must be ticked. */
export const CHECK_IDS = ["device", "backups", "password", "multiDevice", "sms"] as const;
export type CheckId = (typeof CHECK_IDS)[number];

/** Things the person does by hand on the phone (and Mac) during cleanup. */
export type CleanupId = "proxyOff" | "profileRemoved" | "authySignedIn" | "fileDeleted";

/** A problem the proxy has told us about, which the current screen should explain. */
export type Trouble = "trust" | "methodBroken" | "authyError" | "deviceRefused";

/** How many refused Authy connections, after trust was proven, mean the method is broken. */
export const BROKEN_AFTER = 3;

export type WizardState = {
  step: Step;
  device: Device | null;
  /** The person said their phone is an Android phone. The app cannot help. */
  android: boolean;
  checks: Record<CheckId, boolean>;
  /** A trusted connection to Authy has succeeded at least once. */
  trustProven: boolean;
  /** The phone refused our certificate before trust was ever proven. */
  tlsRejected: boolean;
  /** Authy connections refused since trust was last seen working. */
  rejectionsAfterTrust: number;
  /** A different device tried to reach Authy after one was accepted. */
  deviceRefused: boolean;
  /** The wizard got as far as telling the person to delete Authy. */
  reachedAuthy: boolean;
  /** Something has been moved: a QR code scanned and ticked, a file saved, or a Bitwarden apply done. */
  moved: boolean;
  /** How many times the connection was restarted. The waiting screens say what not to redo. */
  restarts: number;
  /** Trust was proven at some point in this run, restarts included: the certificate is installed. */
  certificateInstalled: boolean;
  /** How many accounts could not be moved. Kept after the summary is dropped, for cleanup and Done. */
  cantMove: number;
  authyError: { status: number; path: string } | null;
  /** Largest number of accounts captured so far. */
  captured: number | null;
  summary: UnlockSummary | null;
  /** A file holding the keys was saved to disk, so cleanup asks for it to be deleted. */
  exportedFile: boolean;
  cleanupTicks: Record<CleanupId, boolean>;
  /** This launch opened on cleanup because the last run was not finished. */
  resumed: boolean;
  version: string;
  releasesUrl: string;
};

export type WizardEvent =
  | { type: "loaded"; app: AppState }
  | { type: "chooseDevice"; device: Device | "android" }
  | { type: "setCheck"; id: CheckId; value: boolean }
  | { type: "start" }
  | { type: "proxy"; event: ProxyEvent }
  | { type: "unlocked"; summary: UnlockSummary }
  | { type: "restarting" }
  | { type: "fileExported" }
  | { type: "moved" }
  | { type: "destinationDone" }
  | { type: "backToDestination" }
  | { type: "verified" }
  | { type: "setCleanup"; id: CleanupId; value: boolean }
  | { type: "abandon" }
  | { type: "finish" };

export function initialState(): WizardState {
  return {
    step: "welcome",
    device: null,
    android: false,
    checks: { device: false, backups: false, password: false, multiDevice: false, sms: false },
    trustProven: false,
    tlsRejected: false,
    rejectionsAfterTrust: 0,
    deviceRefused: false,
    reachedAuthy: false,
    moved: false,
    restarts: 0,
    certificateInstalled: false,
    cantMove: 0,
    authyError: null,
    captured: null,
    summary: null,
    exportedFile: false,
    cleanupTicks: { proxyOff: false, profileRemoved: false, authySignedIn: false, fileDeleted: false },
    resumed: false,
    version: "",
    releasesUrl: "",
  };
}

export function canStart(s: WizardState): boolean {
  return s.device !== null && !s.android && CHECK_IDS.every((id) => s.checks[id]);
}

export function cleanupItems(s: WizardState): CleanupId[] {
  const items: CleanupId[] = ["proxyOff", "profileRemoved"];
  // Once the person was told to delete Authy (or we cannot know, after a resume), Authy has
  // to be signed back in before they are done, or they are left without their fallback.
  if (s.reachedAuthy || s.resumed) items.push("authySignedIn");
  // After a resume the app no longer knows whether a file was saved, so it asks either way.
  if (s.exportedFile || s.resumed) items.push("fileDeleted");
  return items;
}

/** The destination step may be left once something was moved, or when there is nothing to move. */
export function canLeaveDestination(s: WizardState): boolean {
  return s.moved || (s.summary?.tokens.length ?? 0) === 0;
}

export function canFinish(s: WizardState): boolean {
  return cleanupItems(s).every((id) => s.cleanupTicks[id]);
}

/** Which failure the current screen should explain without being asked, if any. */
export function troubleFor(s: WizardState): Trouble | null {
  if (!LISTENING.includes(s.step)) return null;
  if (s.deviceRefused) return "deviceRefused";
  if (s.step === "certificate") return s.tlsRejected && !s.trustProven ? "trust" : null;
  if (s.step !== "authy") return null;
  // One refusal proves nothing. Only trust seen working, then refused again and again, does.
  if (s.trustProven && s.rejectionsAfterTrust >= BROKEN_AFTER) return "methodBroken";
  if (s.authyError) return "authyError";
  return null;
}

const ABANDONABLE: readonly Step[] = ["connect", "certificate", "authy", "unlock"];
const LISTENING: readonly Step[] = ["connect", "certificate", "authy"];

function onProxy(s: WizardState, e: ProxyEvent): WizardState {
  if (!LISTENING.includes(s.step)) return s;
  switch (e.kind) {
    case "deviceConnected":
      return s.step === "connect" ? { ...s, step: "certificate" } : s;
    case "trustWorking":
      // A trusted connection implies the device is connected, so this also leaves `connect`.
      return {
        ...s, step: "authy", reachedAuthy: true, trustProven: true, certificateInstalled: true,
        tlsRejected: false, rejectionsAfterTrust: 0,
      };
    case "tlsRejected":
      if (s.trustProven) return { ...s, rejectionsAfterTrust: s.rejectionsAfterTrust + 1 };
      // Before the certificate step every connection to Authy is refused; that is expected.
      return s.step === "connect" ? s : { ...s, tlsRejected: true };
    case "deviceRefused":
      return { ...s, deviceRefused: true };
    case "authyError":
      return { ...s, authyError: { status: e.status, path: e.path } };
    case "backupCaptured": {
      // The backup can arrive more than once and a later one can be empty: keep the largest.
      if (e.count <= 0) return s;
      return {
        ...s, step: "unlock", reachedAuthy: true, captured: Math.max(s.captured ?? 0, e.count),
        authyError: null, tlsRejected: false, deviceRefused: false,
      };
    }
  }
}

export function reduce(s: WizardState, ev: WizardEvent): WizardState {
  switch (ev.type) {
    case "loaded": {
      const base = { ...s, device: ev.app.device, version: ev.app.version, releasesUrl: ev.app.releasesUrl };
      return ev.app.resumeCleanup ? { ...base, step: "cleanup", resumed: true } : { ...base, resumed: false };
    }
    case "chooseDevice":
      // Cleanup can open without a device (a resumed run), and its pictures need one.
      if (s.step === "cleanup") return ev.device === "android" ? s : { ...s, device: ev.device };
      if (s.step !== "welcome") return s;
      return ev.device === "android" ? { ...s, device: null, android: true } : { ...s, device: ev.device, android: false };
    case "setCheck":
      return s.step === "welcome" ? { ...s, checks: { ...s.checks, [ev.id]: ev.value } } : s;
    case "start":
      return s.step === "welcome" && canStart(s) ? { ...s, step: "connect" } : s;
    case "proxy":
      return onProxy(s, ev.event);
    case "unlocked":
      return s.step === "unlock"
        ? { ...s, step: "destination", summary: ev.summary, cantMove: ev.summary.native.length + ev.summary.invalid.length }
        : s;
    case "restarting":
      // Dispatched the moment the person asks for a restart, before the shell answers, so
      // that events from the new proxy are applied to the reset state and not wiped by it.
      // The capture is gone and the device must reconnect. The certificate on the phone is
      // unchanged, so trust will be seen again by itself.
      return LISTENING.includes(s.step) ? {
        ...s, step: "connect", trustProven: false, tlsRejected: false, rejectionsAfterTrust: 0,
        deviceRefused: false, authyError: null, captured: null, restarts: s.restarts + 1,
      } : s;
    case "fileExported":
      return { ...s, exportedFile: true, moved: true };
    case "moved":
      return s.step === "destination" ? { ...s, moved: true } : s;
    case "destinationDone":
      return s.step === "destination" && canLeaveDestination(s) ? { ...s, step: "verify" } : s;
    case "backToDestination":
      return s.step === "verify" ? { ...s, step: "destination" } : s;
    case "verified":
      return s.step === "verify" ? { ...s, step: "cleanup", summary: null } : s;
    case "abandon":
      // Giving up part-way still has to undo what was done to the phone and this computer.
      return ABANDONABLE.includes(s.step) ? { ...s, step: "cleanup", summary: null } : s;
    case "setCleanup":
      return s.step === "cleanup" ? { ...s, cleanupTicks: { ...s.cleanupTicks, [ev.id]: ev.value } } : s;
    case "finish":
      return s.step === "cleanup" && canFinish(s) ? { ...s, step: "done" } : s;
  }
}
