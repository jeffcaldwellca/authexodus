// Save an import file for a named app, through the core's native save dialog. The file holds
// unprotected keys, so the screen says to delete it and cleanup asks again.
import { useState } from "react";
import type { Destination } from "../api";
import { Callout, Screen } from "../components/ui";
import { en } from "../strings/en";
import type { ScreenProps } from "./types";

const t = en.destination.file;
const APPS = ["onePassword", "twoFas", "aegis", "protonAuthenticator", "bitwarden", "plainText"] as const satisfies readonly Destination[];
type AppId = (typeof APPS)[number];
type Outcome = { kind: "saved"; path: string } | { kind: "cancelled" } | { kind: "failed" };

export function FileExport({ api, dispatch, onDone }: ScreenProps & { onDone: (saved: boolean) => void }) {
  const [outcomes, setOutcomes] = useState<Partial<Record<AppId, Outcome>>>({});
  const [busy, setBusy] = useState<AppId | null>(null);
  const saved = Object.values(outcomes).some((o) => o.kind === "saved");

  const save = async (app: AppId) => {
    setBusy(app);
    let outcome: Outcome;
    try {
      const result = await api.exportFile(app);
      outcome = "saved" in result ? { kind: "saved", path: result.saved } : { kind: "cancelled" };
    } catch {
      outcome = { kind: "failed" };
    }
    if (outcome.kind === "saved") dispatch({ type: "fileExported" });
    setOutcomes((prev) => ({ ...prev, [app]: outcome }));
    setBusy(null);
  };

  return (
    <Screen
      title={t.title}
      lede={t.lede}
      footer={
        <>
          <button type="button" className="quiet" onClick={() => onDone(saved)}>{en.destination.backToOptions}</button>
          <button type="button" className={saved ? "primary" : "secondary"} onClick={() => onDone(saved)}>{en.common.done}</button>
        </>
      }
    >
      <Callout tone="warn"><p>{t.warning}</p></Callout>
      <ul className="file-apps">
        {APPS.map((app) => {
          const outcome = outcomes[app];
          return (
            <li key={app}>
              <button type="button" className="secondary" disabled={busy !== null} onClick={() => void save(app)}>
                {t.save(t.apps[app])}
              </button>
              <span className={outcome?.kind === "failed" ? "error-text" : "quiet-text"} role="status">
                {outcome?.kind === "saved" && t.saved(outcome.path)}
                {outcome?.kind === "cancelled" && t.cancelled}
                {outcome?.kind === "failed" && t.failed}
              </span>
            </li>
          );
        })}
      </ul>
    </Screen>
  );
}
