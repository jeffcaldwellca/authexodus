// The real `Api`, backed by Tauri `invoke` and `listen`.
//
// Each method calls the Rust command whose name is the method's name in snake_case, with
// arguments keyed by the parameter names in `api.ts`. A failed command rejects its promise
// with an `Error` carrying the shell's message, so callers handle it like any other failure.
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type { Api, ProxyEvent } from "./api";

export const PROXY_EVENT = "proxy-event";
export const BW_PROGRESS_EVENT = "bw-progress";

/** The shell rejects with a plain string; give callers a real `Error` either way. */
async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(command, args);
  } catch (err) {
    throw err instanceof Error ? err : new Error(String(err));
  }
}

/**
 * Subscribe to a shell event. `listen` is asynchronous, but the returned unsubscribe works at
 * any time: called before the listener is registered, it drops the listener the moment it is.
 */
function subscribe<T>(event: string, cb: (payload: T) => void): () => void {
  let stopped = false;
  let unlisten: (() => void) | null = null;
  listen<T>(event, (e) => { if (!stopped) cb(e.payload); })
    .then((off) => { if (stopped) off(); else unlisten = off; })
    // Nothing can be delivered if registration fails; the wizard's waiting steps offer help.
    .catch(() => undefined);
  return () => {
    stopped = true;
    unlisten?.();
    unlisten = null;
  };
}

export function createTauriApi(): Api {
  return {
    getState: () => call("get_state"),
    setDevice: (device) => call("set_device", { device }),
    startProxy: (ip) => call("start_proxy", { ip: ip ?? null }),
    restartProxy: (ip) => call("restart_proxy", { ip: ip ?? null }),
    onProxyEvent: (cb) => subscribe<ProxyEvent>(PROXY_EVENT, cb),
    unlock: (password) => call("unlock", { password }),
    tokenQr: (id) => call("token_qr", { id }),
    googleMigrationQrs: () => call("google_migration_qrs"),
    googleUnsupported: () => call("google_unsupported"),
    exportFile: (dest) => call("export_file", { dest }),
    liveCodes: () => call("live_codes"),
    bwPrepare: () => call("bw_prepare"),
    bwLogin: (login) => call("bw_login", { login }),
    bwPropose: () => call("bw_propose"),
    bwApply: (decisions) => call("bw_apply", { decisions }),
    onBwProgress: (cb) => subscribe<string>(BW_PROGRESS_EVENT, cb),
    cleanup: () => call("cleanup"),
    finish: () => call("finish"),
  };
}
