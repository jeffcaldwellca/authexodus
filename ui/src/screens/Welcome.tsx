// Screen 1: what will happen, which device, and the five safety checks. The person cannot
// start until a supported device is chosen and every check is ticked.
import { useState } from "react";
import type { Device } from "../api";
import { Callout, Screen, Tick } from "../components/ui";
import { AuthyAccounts, AuthyBackups, AuthyDevices, AuthyPrompt } from "../device/scenes";
import { ManualGuide } from "../failures/ManualGuide";
import { en } from "../strings/en";
import { CHECK_IDS, canStart, type CheckId } from "../wizard/machine";
import { deviceLabel, type ScreenProps } from "./types";

const t = en.welcome;

function CheckArt({ id, device }: { id: CheckId; device: Device }) {
  switch (id) {
    case "device": return <AuthyAccounts device={device} />;
    case "backups": return <AuthyBackups device={device} />;
    case "password": return <AuthyPrompt device={device} stop={false} />;
    case "multiDevice": return <AuthyDevices device={device} />;
    // Nothing in Authy to point at: the check is about the phone number itself.
    case "sms": return null;
  }
}

export function Welcome({ api, state, dispatch }: ScreenProps) {
  const [shown, setShown] = useState<CheckId | null>(null);
  const d = deviceLabel(state.device);
  const left = CHECK_IDS.filter((id) => !state.checks[id]).length;
  const choice = state.android ? "android" : state.device;

  const choose = (device: Device | "android") => {
    dispatch({ type: "chooseDevice", device });
    if (device !== "android") void api.setDevice(device).catch(() => undefined);
  };
  const labelFor = (id: CheckId) => (id === "device" ? t.checks.device.label(d) : t.checks[id].label);

  return (
    <Screen
      title={t.title}
      lede={t.lede}
      footer={
        <>
          <p className="footer-note">{t.footer}</p>
          <p className="footer-hint" aria-live="polite">
            {state.android ? "" : state.device === null ? t.blocked : left > 0 ? t.blockedChecks(left) : ""}
          </p>
          <button type="button" className="primary" disabled={!canStart(state)} onClick={() => dispatch({ type: "start" })}>
            {t.start}
          </button>
        </>
      }
    >
      <Callout tone="info"><p>{t.network}</p></Callout>
      <div className="welcome-top">
        <div>
          <h2>{t.planTitle}</h2>
          <ol className="plan">{t.plan.map((p) => <li key={p}>{p}</li>)}</ol>
        </div>
        <div>
          <fieldset className="segmented">
            <legend>{t.deviceQuestion}</legend>
            <div className="segments">
              {(["iphone", "ipad", "android"] as const).map((option) => (
                <label key={option} className={choice === option ? "selected" : ""}>
                  <input type="radio" name="device" checked={choice === option} onChange={() => choose(option)} />
                  <span>{option === "android" ? t.android : en.deviceName[option]}</span>
                </label>
              ))}
            </div>
          </fieldset>
          <p className="quiet-text">{t.spare}</p>
        </div>
      </div>

      {state.android ? (
        <Callout tone="warn" title={t.androidTitle} alert>
          <p>{t.androidBody}</p>
          <ManualGuide />
        </Callout>
      ) : (
        <>
          <h2>{t.checksTitle}</h2>
          <Callout tone="warn"><p>{t.checksWhy}</p></Callout>
          <div className="ticks two-up">
            {CHECK_IDS.map((id) => (
              <Tick
                key={id}
                checked={state.checks[id]}
                onChange={(value) => dispatch({ type: "setCheck", id, value })}
                label={labelFor(id)}
                detail={t.checks[id].where}
                extra={id === "sms" ? undefined : (
                  <>
                    <button type="button" className="quiet small" aria-expanded={shown === id} aria-label={shown === id ? en.common.hidePictureFor(labelFor(id)) : en.common.showPictureFor(labelFor(id))} onClick={() => setShown(shown === id ? null : id)}>
                      {shown === id ? en.common.hidePicture : en.common.showPicture}
                    </button>
                    {shown === id && <div className="guide-figure"><CheckArt id={id} device={state.device ?? "iphone"} /></div>}
                  </>
                )}
              />
            ))}
          </div>
        </>
      )}
    </Screen>
  );
}
