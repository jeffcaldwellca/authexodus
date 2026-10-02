import React from "react";
import ReactDOM from "react-dom/client";
import type { Api } from "./api";
import { App } from "./App";
import "./styles.css";

/** True inside the Tauri webview, false in a plain browser (`pnpm -C ui dev`). */
function insideTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

async function boot() {
  let api: Api;
  let devTools: React.ReactNode = null;
  if (insideTauri()) {
    const { createTauriApi } = await import("./api.tauri");
    api = createTauriApi();
  } else {
    // No Tauri: run the whole wizard against the in-memory fake, with a pretend phone.
    const [{ createFakeApi }, { DevPanel }] = await Promise.all([import("./api.fake"), import("./dev/DevPanel")]);
    const fake = createFakeApi({}, { delayMs: 400 });
    api = fake;
    devTools = <DevPanel api={fake} />;
  }
  ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
    <React.StrictMode>
      <App api={api} devTools={devTools} />
    </React.StrictMode>,
  );
}

void boot();
