// Save an import file for a named app, through the core's native save dialog. The file holds
// unprotected keys, so the screen says to delete it and cleanup asks again. Once a file is
// saved, the screen shows that app's own import steps: where the option is, how to get the
// file to a phone when the app lives there, and whether the format has been tried for real.
import { useState } from "react";
import type { Destination } from "../api";
import { asApiError, type ApiError } from "../api.errors";
import { Callout, Screen } from "../components/ui";
import { Problem } from "../failures/Problem";
import { en } from "../strings/en";
import { deviceLabel, type ScreenProps } from "./types";

const t = en.destination.file;
const APPS = ["onePassword", "twoFas", "aegis", "protonAuthenticator", "bitwarden", "plainText"] as const satisfies readonly Destination[];
type AppId = (typeof APPS)[number];
type Outcome = { kind: "saved"; path: string } | { kind: "cancelled" } | { kind: "failed"; error: ApiError };

export function FileExport({ api, state, dispatch, onDone, onLocked }: ScreenProps & { onDone: (saved: boolean) => void; onLocked: () => void }) {
  const [outcomes, setOutcomes] = useState<Partial<Record<AppId, Outcome>>>({});
  const [busy, setBusy] = useState<AppId | null>(null);
  const saved = Object.values(outcomes).some((o) => o.kind === "saved");
  const d = deviceLabel(state.device);

  const save = async (app: AppId) => {
    setBusy(app);
    let outcome: Outcome;
    try {
      const result = await api.exportFile(app);
      outcome = "saved" in result ? { kind: "saved", path: result.saved } : { kind: "cancelled" };
    } catch (err) {
      outcome = { kind: "failed", error: asApiError(err) };
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
          const guide = t.guides[app];
          const name = t.apps[app];
          return (
            <li key={app}>
              <div className="file-app-row">
                <button type="button" className="secondary" disabled={busy !== null} onClick={() => void save(app)}>
                  {t.save(name)}
                </button>
                <span className="quiet-text" role="status">
                  {outcome?.kind === "saved" && t.saved(outcome.path)}
                  {outcome?.kind === "cancelled" && t.cancelled}
                </span>
              </div>
              {outcome?.kind === "failed" && (
                <Problem error={outcome.error} d={d} title={t.failed}>
                  {outcome.error.code === "not_unlocked" && (
                    <button type="button" className="secondary" onClick={onLocked}>{en.common.unlockAgain}</button>
                  )}
                </Problem>
              )}
              {outcome?.kind === "saved" && (
                <section className="import-guide" aria-label={t.guideTitle(name)}>
                  <h2>{t.guideTitle(name)}</h2>
                  <ol>{guide.steps.map((step) => <li key={step}>{step}</li>)}</ol>
                  {guide.tested !== null && <p className="quiet-text">{guide.tested ? en.common.verified(name) : en.common.untested(name)}</p>}
                </section>
              )}
            </li>
          );
        })}
      </ul>
    </Screen>
  );
}
