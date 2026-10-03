// The window could not subscribe to one of the shell's events (`listen` failed to register).
// The Tauri binding reports which one here, and each part of the app reacts to its own:
//
// * `proxy-event`: nothing about the connection can arrive, and the waiting steps would wait
//   for ever. The app shows a plain problem panel.
// * `bw-progress`: only the progress lines are lost. The Bitwarden screen says so; the work
//   itself still finishes.
//
// Kept outside the `Api` contract, which has no place for it.

export type ShellEvent = "proxy-event" | "bw-progress";

const failed = new Set<ShellEvent>();
const watchers = new Set<{ event: ShellEvent; cb: () => void }>();

/** Called by the binding when a subscription to `event` could not be registered. */
export function reportListenFailure(event: ShellEvent): void {
  failed.add(event);
  for (const watcher of watchers) if (watcher.event === event) watcher.cb();
}

/** Calls `cb` once a failure for `event` is reported, at once if one already was. Returns the unsubscribe. */
export function onListenFailure(event: ShellEvent, cb: () => void): () => void {
  const watcher = { event, cb };
  watchers.add(watcher);
  if (failed.has(event)) cb();
  return () => { watchers.delete(watcher); };
}

/** For tests: forget the reported failures. */
export function resetListenFailure(): void {
  failed.clear();
}
