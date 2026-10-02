// What the three waiting steps (connect, certificate, Authy) show about the connection
// itself: a refused device with the way to recover, and a restart that did not work.
import { Callout } from "../components/ui";
import { en } from "../strings/en";
import { DeviceRefused } from "./DeviceRefused";

export type RestartState = "idle" | "busy" | "failed";

export function ConnectionNotices({ d, refused, restart, onRestart }: {
  d: string; refused: boolean; restart: RestartState; onRestart: () => void;
}) {
  return (
    <>
      {restart === "failed" && (
        <Callout tone="error" title={en.common.restartFailed} alert>
          <button type="button" className="secondary" onClick={onRestart}>{en.common.tryAgain}</button>
        </Callout>
      )}
      {refused && (
        <DeviceRefused d={d}>
          <button type="button" className="secondary" disabled={restart === "busy"} onClick={onRestart}>
            {restart === "busy" ? en.common.restarting : en.common.restart}
          </button>
        </DeviceRefused>
      )}
    </>
  );
}
