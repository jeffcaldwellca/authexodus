// The real `Api`, backed by Tauri `invoke`/`listen`. Batch 0 stub; package 2A/3 implements it
// once the shell's commands exist. UI code builds against `api.fake.ts` until then.
import type { Api } from "./api";

export function createTauriApi(): Api {
  throw new Error("createTauriApi: not implemented yet");
}
