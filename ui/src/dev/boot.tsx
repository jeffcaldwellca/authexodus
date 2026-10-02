// Dev-only: the whole wizard against the in-memory fake, with a pretend phone to fire the
// events a real device would cause. Reached only through `import.meta.env.DEV` in main.tsx.
import type { ReactNode } from "react";
import type { Api } from "../api";
import { createFakeApi } from "../api.fake";
import { DevPanel } from "./DevPanel";

export function createDevApi(): { api: Api; devTools: ReactNode } {
  const fake = createFakeApi({}, { delayMs: 400 });
  // One account Google's transfer codes cannot carry, so that list can be seen.
  fake.script.googleUnsupported = [fake.script.summary.tokens.at(-1)?.title ?? ""].filter(Boolean);
  return { api: fake, devTools: <DevPanel api={fake} /> };
}
