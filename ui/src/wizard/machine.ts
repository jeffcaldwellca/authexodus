// Wizard state machine: a pure reducer over `Step`.
//
// The machine holds no secrets. The only thing it keeps from an unlock is the `UnlockSummary`
// (names, never keys), and it drops that when cleanup begins.
import type { AppState, Device, ProxyEvent, Step, UnlockSummary } from "../api";

/** The four safety checks on the welcome screen. All must be ticked. */
export const CHECK_IDS = ["device", "backups", "password", "multiDevice"] as const;
export type CheckId = (typeof CHECK_IDS)[number];

/** Things the person does by hand on the phone (and Mac) during cleanup. */
export type CleanupId = "proxyOff" | "profileRemoved" | "fileDeleted";

/** A problem the proxy has told us about, which the current screen should explain. */
export type Trouble = "trust" | "methodBroken" | "attestation";

export type WizardState = {
  step: Step;
  device: Device | null;
  /** The person said their phone is an Android phone. The app cannot help. */
  android: boolean;
  checks: Record<CheckId, boolean>;
  /** A trusted connection to Authy has succeeded at least once. */
  trustProven: boolean;
  /** The phone refused our certificate since trust was last proven. */
  tlsRejected: boolean;
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
};

export type WizardEvent =
  | { type: "loaded"; app: AppState }
  | { type: "chooseDevice"; device: Device | "android" }
  | { type: "setCheck"; id: CheckId; value: boolean }
  | { type: "start" }
  | { type: "proxy"; event: ProxyEvent }
  | { type: "unlocked"; summary: UnlockSummary }
  | { type: "fileExported" }
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
    checks: { device: false, backups: false, password: false, multiDevice: false },
    trustProven: false,
    tlsRejected: false,
    authyError: null,
    captured: null,
    summary: null,
    exportedFile: false,
    cleanupTicks: { proxyOff: false, profileRemoved: false, fileDeleted: false },
    resumed: false,
    version: "",
  };
}

export function canStart(s: WizardState): boolean {
  return s.device !== null && !s.android && CHECK_IDS.every((id) => s.checks[id]);
}

export function cleanupItems(s: WizardState): CleanupId[] {
  return s.exportedFile ? ["proxyOff", "profileRemoved", "fileDeleted"] : ["proxyOff", "profileRemoved"];
}

export function canFinish(s: WizardState): boolean {
  return cleanupItems(s).every((id) => s.cleanupTicks[id]);
}

/** Which failure the current screen should explain without being asked, if any. */
export function troubleFor(s: WizardState): Trouble | null {
  if (s.step !== "certificate" && s.step !== "authy") return null;
  if (s.tlsRejected) return s.trustProven ? "methodBroken" : "trust";
  if (s.step === "authy" && s.authyError) return "attestation";
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
      return { ...s, step: "authy", trustProven: true, tlsRejected: false };
    case "tlsRejected":
      // Before the certificate step every connection to Authy is refused; that is expected.
      return s.step === "connect" ? s : { ...s, tlsRejected: true };
    case "authyError":
      return { ...s, authyError: { status: e.status, path: e.path } };
    case "backupCaptured": {
      // The backup can arrive more than once and a later one can be empty: keep the largest.
      if (e.count <= 0) return s;
      return { ...s, step: "unlock", captured: Math.max(s.captured ?? 0, e.count), authyError: null, tlsRejected: false };
    }
  }
}

export function reduce(s: WizardState, ev: WizardEvent): WizardState {
  switch (ev.type) {
    case "loaded": {
      const base = { ...s, device: ev.app.device, version: ev.app.version };
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
      return s.step === "unlock" ? { ...s, step: "destination", summary: ev.summary } : s;
    case "fileExported":
      return { ...s, exportedFile: true };
    case "destinationDone":
      return s.step === "destination" ? { ...s, step: "verify" } : s;
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
