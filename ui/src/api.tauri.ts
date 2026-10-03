// The real `Api`, backed by Tauri `invoke` and `listen`.
//
// Each method calls the Rust command whose name is the method's name in snake_case, with
// arguments keyed by the parameter names in `api.ts`. A failed command rejects its promise
// with an `ApiError`: the shell's code, and its plain sentence as the message.
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type { Api, ProxyEvent } from "./api";
import { ApiError, isErrorCode, unexplained } from "./api.errors";
import { reportListenFailure } from "./listenFailure";

export const PROXY_EVENT = "proxy-event";
export const BW_PROGRESS_EVENT = "bw-progress";

/**
 * The one place a rejection is read. The shell rejects with "<code>: <plain sentence>". A
 * rejection with no code, or with one this UI does not know, is `internal` with no message:
 * its raw text is developer text, kept off the screen (see `unexplained`).
 */
export function toApiError(err: unknown): ApiError {
  if (err instanceof ApiError) return err;
  const raw = err instanceof Error ? err.message : typeof err === "string" ? err : String(err);
  const colon = raw.indexOf(":");
  const code = colon > 0 ? raw.slice(0, colon) : "";
  return isErrorCode(code) ? new ApiError(code, raw.slice(colon + 1).trimStart()) : unexplained(raw);
}

async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(command, args);
  } catch (err) {
    throw toApiError(err);
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
    // Nothing can be delivered if registration fails: the window says so (listenFailure.ts),
    // and a development build keeps the reason for whoever is fixing it.
    .catch((err: unknown) => {
      if (import.meta.env.DEV) console.error(`Could not listen for ${event}:`, err);
      reportListenFailure();
    });
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
    bwCancel: () => call("bw_cancel"),
    bwLogin: (login) => call("bw_login", { login }),
    bwPropose: () => call("bw_propose"),
    bwLogins: () => call("bw_logins"),
    bwApply: (decisions) => call("bw_apply", { decisions }),
    onBwProgress: (cb) => subscribe<string>(BW_PROGRESS_EVENT, cb),
    cleanup: () => call("cleanup"),
    finish: () => call("finish"),
  };
}
