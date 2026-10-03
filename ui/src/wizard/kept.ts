// What the window keeps across a reload of itself, in sessionStorage: the device chosen, the
// five safety ticks, and whether a run had been started. None of it is secret (no password,
// code, key or account name is ever put here), and sessionStorage lasts only as long as this
// window: a new launch of the app starts from nothing.
//
// The shell knows the device and the run, but a reload can come while it cannot say so: the
// first start of the connection waits behind a Keychain prompt and holds the lock the snapshot
// reads. Without this the person would be sent back to tick the checks again.
import type { Device } from "../api";
import { CHECK_IDS, type CheckId } from "./machine";

export type Kept = { device: Device | null; checks: Record<CheckId, boolean>; started: boolean };

const KEY = "authexodus.wizard";

/** What an earlier page in this window kept, or null. Storage that is off or full is no storage. */
export function readKept(): Kept | null {
  try {
    const raw = sessionStorage.getItem(KEY);
    if (raw === null) return null;
    const data = JSON.parse(raw) as Partial<Kept>;
    const device = data.device === "iphone" || data.device === "ipad" ? data.device : null;
    const checks = Object.fromEntries(CHECK_IDS.map((id) => [id, data.checks?.[id] === true])) as Record<CheckId, boolean>;
    return { device, checks, started: data.started === true };
  } catch {
    return null;
  }
}

export function writeKept(kept: Kept): void {
  try {
    sessionStorage.setItem(KEY, JSON.stringify(kept));
  } catch {
    // Nothing to do: a reload then starts on the welcome screen, as it would have anyway.
  }
}

/** Forget everything kept: a finished run must not tick the checks for the next one. */
export function clearKept(): void {
  try {
    sessionStorage.removeItem(KEY);
  } catch {
    // Storage that is off holds nothing to forget.
  }
}
