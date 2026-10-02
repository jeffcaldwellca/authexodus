// Screen 4: delete Authy, reinstall it, sign in, and stop at the backup password prompt.
// Advances by itself when the encrypted backup passes through the proxy.
import { useState } from "react";
import type { Device } from "../api";
import { Callout, Guide, Screen, Waiting, type GuideStep } from "../components/ui";
import { AuthyPrompt } from "../device/scenes";
import { Attestation } from "../failures/Attestation";
import { ConnectionNotices } from "../failures/ConnectionNotices";
import { MethodBroken } from "../failures/MethodBroken";
import { StopConfirm } from "../failures/StopConfirm";
import { Trouble } from "../failures/Trouble";
import { Trust } from "../failures/Trust";
import { Vpn } from "../failures/Vpn";
import { en } from "../strings/en";
import { troubleFor } from "../wizard/machine";
import { deviceLabel, type ScreenProps } from "./types";

const t = en.authy;

export function Authy({ state, dispatch, proxy, onRestart, restart }: ScreenProps) {
  const [confirming, setConfirming] = useState(false);
  const device: Device = state.device ?? "iphone";
  const d = deviceLabel(state.device);
  const help = { d, ip: proxy?.ip, port: proxy?.port };
  const trouble = troubleFor(state);
  const abandon = () => dispatch({ type: "abandon" });

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
            <Attestation {...help} collapsible />
            <Vpn {...help} collapsible />
            <Trust {...help} collapsible />
          </Trouble>
          <Waiting>{t.waiting}</Waiting>
        </>
      }
    >
      <ConnectionNotices d={d} refused={state.deviceRefused} restart={restart} onRestart={() => onRestart()} />
      {trouble === "attestation" && <Attestation {...help} />}
      {trouble === "methodBroken" && (
        <MethodBroken {...help}>
          <button type="button" className="secondary" onClick={() => setConfirming(true)}>{en.common.stopAndCleanUp}</button>
        </MethodBroken>
      )}
      {confirming && <StopConfirm mentionAuthy onCancel={() => setConfirming(false)} onConfirm={abandon} />}
      <Guide steps={steps} />
    </Screen>
  );
}
