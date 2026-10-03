// The window could not subscribe to the shell's events (`listen` failed to register). Nothing
// the shell reports can then arrive, and the waiting steps would wait for ever. The Tauri
// binding reports it here; the app shows a plain problem panel. Kept outside the `Api`
// contract, which has no place for it.

let failed = false;
const watchers = new Set<() => void>();

/** Called by the binding when a subscription could not be registered. */
export function reportListenFailure(): void {
  failed = true;
  for (const watcher of watchers) watcher();
}

/** Calls `cb` once a failure is reported, at once if one already was. Returns the unsubscribe. */
export function onListenFailure(cb: () => void): () => void {
  watchers.add(cb);
  if (failed) cb();
  return () => { watchers.delete(cb); };
}

/** For tests: forget a reported failure. */
export function resetListenFailure(): void {
  failed = false;
}
