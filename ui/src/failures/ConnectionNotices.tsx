// What the three waiting steps (connect, certificate, Authy) show about the connection
// itself: what not to redo after a restart, a refused device with the way to recover, and a
// restart that did not work.
import { Callout } from "../components/ui";
import { en } from "../strings/en";
import type { WizardState } from "../wizard/machine";
import { DeviceRefused } from "./DeviceRefused";

export type RestartState = "idle" | "busy" | "failed";

const t = en.failures.restart;

export function ConnectionNotices({ d, state, restart, onRestart }: {
  d: string; state: WizardState; restart: RestartState; onRestart: () => void;
}) {
  return (
    <>
      {state.restarts > 0 && (
        <Callout tone="info">
          <p>{state.certificateInstalled ? t.noticeAfterTrust(d) : t.noticeBeforeTrust(d)}</p>
        </Callout>
      )}
      {restart === "failed" && (
        <Callout tone="error" title={en.common.restartFailed} alert>
          <button type="button" className="secondary" onClick={onRestart}>{en.common.tryAgain}</button>
        </Callout>
      )}
      {state.deviceRefused && (
        <DeviceRefused d={d}>
          <button type="button" className="secondary" disabled={restart === "busy"} onClick={onRestart}>
            {restart === "busy" ? en.common.restarting : en.common.restart}
          </button>
        </DeviceRefused>
      )}
    </>
  );
}
