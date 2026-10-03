// Wizard state machine: a pure reducer over `Step`.
//
// The machine holds no secrets. The only thing it keeps from an unlock is the `UnlockSummary`
// (names, never keys), and it drops that when cleanup begins. The names of the accounts that
// cannot be moved are kept to the end, so the person can still be told which ones they are.
import type { AppState, Device, ProxyEvent, Step, UnlockSummary } from "../api";
import type { Kept } from "./kept";

/** The five safety checks on the welcome screen. All must be ticked. */
export const CHECK_IDS = ["device", "backups", "password", "multiDevice", "sms"] as const;
export type CheckId = (typeof CHECK_IDS)[number];

/** Things the person does by hand on the phone (and Mac) during cleanup. */
export type CleanupId = "proxyOff" | "profileRemoved" | "authySignedIn" | "fileDeleted";

/** A problem the proxy has told us about, which the current screen should explain. */
export type Trouble = "trust" | "methodBroken" | "authyError" | "deviceRefused" | "emptyBackup";

/** Names of the accounts that cannot be moved. Names only: there is never a key here. */
export type CantMove = { native: string[]; invalid: string[] };

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
  /** A device connected at some point, so the person was shown how to install the certificate. */
  reachedCertificate: boolean;
  /** Authy answered with no accounts at all: backups are probably switched off. */
  emptyBackup: boolean;
  /** This computer's network address is no longer the one the device was told to use. */
  addressChanged: boolean;
  /** The wizard got as far as telling the person to delete Authy. */
  reachedAuthy: boolean;
  /** Something has been moved: a QR code scanned and ticked, a file saved, or a Bitwarden apply done. */
  moved: boolean;
  /** How many times the connection was restarted. The waiting screens say what not to redo. */
  restarts: number;
  /** Trust was proven at some point in this run, restarts included: the certificate is installed. */
  certificateInstalled: boolean;
  /** The accounts that could not be moved. Kept after the summary is dropped, for cleanup and Done. */
  cantMove: CantMove;
  authyError: { status: number; path: string } | null;
  /** Largest number of accounts captured so far. */
  captured: number | null;
  summary: UnlockSummary | null;
  /** A file holding the keys was saved to disk, so cleanup asks for it to be deleted. */
  exportedFile: boolean;
  cleanupTicks: Record<CleanupId, boolean>;
  /** This launch opened on cleanup because the last run was not finished. */
  resumed: boolean;
  /** The window was reloaded mid-run and this state was rebuilt from what the shell knows. */
  recovered: boolean;
  /** The app cannot know everything that happened before this window opened, so cleanup asks. */
  unsure: boolean;
  version: string;
  releasesUrl: string;
};

export type WizardEvent =
  /** `kept`: the device and ticks this window kept from before a reload of itself (see kept.ts). */
  | { type: "loaded"; app: AppState; kept?: Pick<Kept, "device" | "checks"> | null }
  | { type: "chooseDevice"; device: Device | "android" }
  | { type: "setCheck"; id: CheckId; value: boolean }
  | { type: "start" }
  | { type: "proxy"; event: ProxyEvent }
  | { type: "unlocked"; summary: UnlockSummary }
  | { type: "restarting" }
  | { type: "backToUnlock" }
  | { type: "locked" }
  | { type: "startOver" }
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
    reachedCertificate: false,
    emptyBackup: false,
    addressChanged: false,
    reachedAuthy: false,
    moved: false,
    restarts: 0,
    certificateInstalled: false,
    cantMove: { native: [], invalid: [] },
    authyError: null,
    captured: null,
    summary: null,
    exportedFile: false,
    cleanupTicks: { proxyOff: false, profileRemoved: false, authySignedIn: false, fileDeleted: false },
    resumed: false,
    recovered: false,
    unsure: false,
    version: "",
    releasesUrl: "",
  };
}

export function canStart(s: WizardState): boolean {
  return s.device !== null && !s.android && CHECK_IDS.every((id) => s.checks[id]);
}

export function cantMoveCount(s: WizardState): number {
  return s.cantMove.native.length + s.cantMove.invalid.length;
}

function namesThatCantMove(summary: UnlockSummary): CantMove {
  return { native: summary.native.map((n) => n.name), invalid: summary.invalid.map((n) => n.name) };
}

export function cleanupItems(s: WizardState): CleanupId[] {
  const items: CleanupId[] = ["proxyOff"];
  // A certificate can only be on the device if the device ever connected. When the app
  // cannot know (a resumed or reloaded run), it asks.
  if (s.reachedCertificate || s.unsure) items.push("profileRemoved");
  // Once the person was told to delete Authy (or we cannot know), Authy has to be signed
  // back in before they are done, or they are left without their fallback.
  if (s.reachedAuthy || s.unsure) items.push("authySignedIn");
  // When the app no longer knows whether a file was saved, it asks either way.
  if (s.exportedFile || s.unsure) items.push("fileDeleted");
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
  if (s.emptyBackup) return "emptyBackup";
  if (s.authyError) return "authyError";
  return null;
}

const ABANDONABLE: readonly Step[] = ["connect", "certificate", "authy", "unlock", "destination"];
const LISTENING: readonly Step[] = ["connect", "certificate", "authy"];
/** Steps a restart of the connection can be asked for from. */
const RESTARTABLE: readonly Step[] = [...LISTENING, "unlock"];
/** Steps where the device choice can still be put right: before Authy is deleted. */
const DEVICE_CHANGEABLE: readonly Step[] = ["connect", "certificate"];

function onProxy(s: WizardState, e: ProxyEvent): WizardState {
  // On the unlock step the capture can still grow (Authy sends its accounts in pieces), and
  // the count on screen follows it. Nothing else the proxy says matters there.
  if (s.step === "unlock") {
    return e.kind === "backupCaptured" && e.count > (s.captured ?? 0) ? { ...s, captured: e.count } : s;
  }
  if (!LISTENING.includes(s.step)) return s;
  switch (e.kind) {
    case "deviceConnected":
      return s.step === "connect" ? { ...s, step: "certificate", reachedCertificate: true } : s;
    case "trustWorking":
      // A trusted connection implies the device is connected, so this also leaves `connect`.
      return {
        ...s, step: "authy", reachedAuthy: true, reachedCertificate: true, trustProven: true, certificateInstalled: true,
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
    case "emptyBackup":
      return { ...s, emptyBackup: true };
    case "addressChanged":
      return { ...s, addressChanged: true };
    case "backupCaptured": {
      // The shell sends this only when the backup grew. The count is of accounts that can be
      // moved: 0 means Authy's own accounts only, which is still a backup to unlock (it lists
      // them by name and how to move them by hand). Keep the largest count seen.
      return {
        ...s, step: "unlock", reachedAuthy: true, reachedCertificate: true, captured: Math.max(s.captured ?? 0, e.count),
        authyError: null, tlsRejected: false, deviceRefused: false, emptyBackup: false,
      };
    }
  }
}

/**
 * The state for a freshly opened window. Normally that is the welcome screen, or cleanup when
 * the last launch was not finished. But the window can also be reloaded while a run is under
 * way: then the shell still has the proxy, the device and the capture, and the wizard is put
 * back where it was. In order:
 *
 * 1. A cleanup the shell has begun (or a launch that found the last run unfinished) wins over
 *    everything: while cleanup waits for a sign-in to give up, the proxy is still reported.
 * 2. A running proxy: the step it has reached. It wins over the resume flag, so that a reload
 *    can never start the cleanup (and throw the capture away) by itself.
 * 3. An unlocked summary with no proxy reported (the shell was busy for a moment): Move codes.
 * 4. Otherwise the welcome screen, with the device and the ticks this window kept.
 */
function onLoaded(s: WizardState, app: AppState, kept: Pick<Kept, "device" | "checks"> | null): WizardState {
  const base: WizardState = {
    ...s, device: app.device ?? kept?.device ?? null, version: app.version, releasesUrl: app.releasesUrl, resumed: false,
  };
  const snap = app.session;
  if (app.step === "cleanup") {
    return app.resumeCleanup && !snap?.proxy
      ? { ...base, step: "cleanup", resumed: true, unsure: true }
      // Reloaded after this computer's cleanup had begun: the phone's steps are still to do.
      : { ...base, step: "cleanup", recovered: true, unsure: true };
  }
  const trusted = { reachedCertificate: true, reachedAuthy: true, trustProven: true, certificateInstalled: true };
  const atDestination = (summary: UnlockSummary): WizardState => ({
    ...base, ...trusted, recovered: true, step: "destination", summary, cantMove: namesThatCantMove(summary),
    captured: snap.captured > 0 ? snap.captured : null,
    // Whether a file was saved before the reload is not known, so cleanup asks.
    unsure: true,
  });
  if (snap?.proxy) {
    const live: WizardState = { ...base, recovered: true };
    if (snap.summary) return atDestination(snap.summary);
    // The count is of accounts that can be moved. A capture holding only Authy's own
    // accounts counts none, yet is still a backup to unlock: the shell's step says so.
    if (snap.captured > 0 || app.step === "unlock") return { ...live, ...trusted, step: "unlock", captured: snap.captured };
    if (snap.trustWorking) return { ...live, ...trusted, step: "authy" };
    if (snap.deviceConnected) return { ...live, step: "certificate", reachedCertificate: true };
    return { ...live, step: "connect" };
  }
  if (snap?.summary) return atDestination(snap.summary);
  if (app.resumeCleanup) return { ...base, step: "cleanup", resumed: true, unsure: true };
  return kept ? { ...base, checks: { ...kept.checks } } : base;
}

export function reduce(s: WizardState, ev: WizardEvent): WizardState {
  switch (ev.type) {
    case "loaded":
      return onLoaded(s, ev.app, ev.kept ?? null);
    case "chooseDevice":
      // Cleanup can open without a device (a resumed run), and its pictures need one. On the
      // first two steps a wrong choice can still be put right: nothing is deleted yet.
      if (s.step === "cleanup" || DEVICE_CHANGEABLE.includes(s.step)) return ev.device === "android" ? s : { ...s, device: ev.device };
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
        ? { ...s, step: "destination", summary: ev.summary, cantMove: namesThatCantMove(ev.summary) }
        : s;
    case "restarting":
      // Dispatched the moment the person asks for a restart, before the shell answers, so
      // that events from the new proxy are applied to the reset state and not wiped by it.
      // The capture is gone and the device must reconnect. The certificate on the phone is
      // unchanged, so trust will be seen again by itself.
      return RESTARTABLE.includes(s.step) ? {
        ...s, step: "connect", trustProven: false, tlsRejected: false, rejectionsAfterTrust: 0,
        deviceRefused: false, authyError: null, captured: null, emptyBackup: false, addressChanged: false,
        restarts: s.restarts + 1,
      } : s;
    case "backToUnlock":
      // Only while nothing has been moved: after that, the way on is forward.
      return s.step === "destination" && !s.moved ? { ...s, step: "unlock", summary: null, cantMove: { native: [], invalid: [] } } : s;
    case "locked":
      // The shell says the codes are no longer unlocked; the backup password opens them again.
      return s.step === "destination" || s.step === "verify" ? { ...s, step: "unlock", summary: null } : s;
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
    case "startOver":
      // A new run from the beginning. Everything from the last one is gone: only the device
      // choice survives, and it can be changed on the welcome screen.
      return s.step === "done" ? { ...initialState(), device: s.device, version: s.version, releasesUrl: s.releasesUrl } : s;
  }
}
