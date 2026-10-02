// Screen 4: delete Authy, reinstall it, sign in, and stop at the backup password prompt.
// Advances by itself when the encrypted backup passes through the proxy. If nothing arrives
// for a few minutes the screen says so, because Authy can stop working with this method
// without ever sending a refusal the app could notice.
import { useEffect, useState } from "react";
import type { Device } from "../api";
import { Callout, Guide, Screen, Waiting, type GuideStep } from "../components/ui";
import { AuthyPrompt } from "../device/scenes";
import { AuthyProblem } from "../failures/AuthyProblem";
import { ConnectionNotices } from "../failures/ConnectionNotices";
import { EmptyBackup } from "../failures/EmptyBackup";
import { MethodBroken } from "../failures/MethodBroken";
import { StopConfirm } from "../failures/StopConfirm";
import { Trouble } from "../failures/Trouble";
import { Trust } from "../failures/Trust";
import { Vpn } from "../failures/Vpn";
import { en } from "../strings/en";
import { troubleFor } from "../wizard/machine";
import { deviceLabel, type ScreenProps } from "./types";

const t = en.authy;

/** How long to wait on this step, with trust proven and nothing captured, before saying so. */
export const STILL_WAITING_MS = 3 * 60 * 1000;

export function Authy({ state, dispatch, proxy, onRestart, restart, restartError }: ScreenProps) {
  const [confirming, setConfirming] = useState(false);
  const [waitedLong, setWaitedLong] = useState(false);
  const device: Device = state.device ?? "iphone";
  const d = deviceLabel(state.device);
  const help = { d, ip: proxy?.ip, port: proxy?.port };
  const trouble = troubleFor(state);
  const abandon = () => dispatch({ type: "abandon" });

  // The clock starts when trust is proven, and starts again after a restart.
  useEffect(() => {
    setWaitedLong(false);
    if (!state.trustProven) return;
    const timer = setTimeout(() => setWaitedLong(true), STILL_WAITING_MS);
    return () => clearTimeout(timer);
  }, [state.trustProven, state.restarts]);

  const restartButton = (
    <button type="button" className="secondary" disabled={restart === "busy"} onClick={() => onRestart()}>
      {restart === "busy" ? en.common.restarting : en.common.restart}
    </button>
  );
  const steps: GuideStep[] = [
    { id: "remove", text: t.steps.remove(d) },
    { id: "install", text: t.steps.install },
    { id: "phone", text: t.steps.phone },
    { id: "stop", text: t.steps.stop, art: <AuthyPrompt device={device} stop />, important: true },
  ];

  return (
    <Screen
      title={t.title}
      lede={t.lede}
      status={<Callout tone="ok"><p>{t.trusted}</p></Callout>}
      footer={
        <>
          <Trouble d={d} mentionAuthy onAbandon={abandon} onRestart={() => onRestart()}>
            <AuthyProblem {...help} collapsible />
            <Vpn {...help} collapsible />
            <Trust {...help} collapsible />
            <EmptyBackup {...help} collapsible />
            <MethodBroken {...help} collapsible />
          </Trouble>
          <Waiting>{t.waiting}</Waiting>
        </>
      }
    >
      <ConnectionNotices d={d} state={state} restart={restart} restartError={restartError} onRestart={() => onRestart()} />
      {state.restarts === 0 && !state.recovered && <Callout tone="warn" title={t.lastCheck.title}><p>{t.lastCheck.body}</p></Callout>}
      {trouble === "authyError" && <AuthyProblem {...help} status={state.authyError?.status} />}
      {trouble === "emptyBackup" && <EmptyBackup {...help}>{restartButton}</EmptyBackup>}
      {trouble === "methodBroken" && (
        <MethodBroken {...help}>
          <button type="button" className="secondary" onClick={() => setConfirming(true)}>{en.common.stopAndCleanUp}</button>
        </MethodBroken>
      )}
      {waitedLong && trouble === null && (
        <Callout tone="warn" title={t.stillWaiting.title} alert>
          <p>{t.stillWaiting.body(d)}</p>
          {restartButton}
        </Callout>
      )}
      {confirming && <StopConfirm d={d} mentionAuthy onCancel={() => setConfirming(false)} onConfirm={abandon} />}
      <Guide steps={steps} />
    </Screen>
  );
}
