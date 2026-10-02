import React from "react";
import ReactDOM from "react-dom/client";
import type { Api } from "./api";
import { createTauriApi } from "./api.tauri";
import { App } from "./App";
import "./styles.css";

/** True inside the Tauri webview, false in a plain browser (`pnpm -C ui dev`). */
function insideTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

async function boot() {
  let api: Api;
  let devTools: React.ReactNode = null;
  // `import.meta.env.DEV` is a constant at build time, so in a production build this whole
  // branch, and with it the fake and the pretend phone, is removed from the bundle.
  if (import.meta.env.DEV && !insideTauri()) {
    const { createDevApi } = await import("./dev/boot");
    ({ api, devTools } = createDevApi());
  } else {
    api = createTauriApi();
  }
  ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
    <React.StrictMode>
      <App api={api} devTools={devTools} />
    </React.StrictMode>,
  );
}

void boot();
