// What the three waiting steps (connect, certificate, Authy) show about the connection
// itself: a window that was reloaded, what not to redo after a restart, this computer's
// address changing, a refused device with the way to recover, and a restart that did not work.
import type { ApiError } from "../api.errors";
import { Callout } from "../components/ui";
import { en } from "../strings/en";
import type { WizardState } from "../wizard/machine";
import { DeviceRefused } from "./DeviceRefused";
import { Problem } from "./Problem";

export type RestartState = "idle" | "busy" | "failed";

const t = en.failures.restart;
const moved = en.problems.byCode.address_changed;

export function ConnectionNotices({ d, state, restart, restartError, onRestart }: {
  d: string; state: WizardState; restart: RestartState; restartError: ApiError | null; onRestart: () => void;
}) {
  const restartButton = (
    <button type="button" className="secondary" disabled={restart === "busy"} onClick={onRestart}>
      {restart === "busy" ? en.common.restarting : en.common.restart}
    </button>
  );
  return (
    <>
      {state.recovered && state.restarts === 0 && <Callout tone="info"><p>{en.common.reloaded(d)}</p></Callout>}
      {state.restarts > 0 && (
        <Callout tone="info">
          <p>{state.certificateInstalled ? t.noticeAfterTrust(d) : t.noticeBeforeTrust(d)}</p>
        </Callout>
      )}
      {restart === "failed" && restartError && (
        <Problem error={restartError} d={d} title={en.common.restartFailed}>
          <button type="button" className="secondary" onClick={onRestart}>{en.common.tryAgain}</button>
        </Problem>
      )}
      {state.addressChanged && (
        <Callout tone="error" title={moved.title(d)} alert>
          <p>{moved.advice(d)}</p>
          {restartButton}
        </Callout>
      )}
      {state.deviceRefused && <DeviceRefused d={d}>{restartButton}</DeviceRefused>}
    </>
  );
}
