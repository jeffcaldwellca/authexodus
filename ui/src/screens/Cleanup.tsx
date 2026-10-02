// Screen 8: the app stops the proxy and destroys the certificate key, then the person undoes
// the phone changes by hand. It is not finished until every item is ticked. A launch that
// follows an unfinished run opens here.
import { useEffect, useRef, useState } from "react";
import type { Device } from "../api";
import { Callout, Screen, Tick, Waiting } from "../components/ui";
import { AuthyAccounts, DeviceManagement, ProxyForm, TrashFile } from "../device/scenes";
import { en } from "../strings/en";
import { canFinish, cleanupItems, type CleanupId } from "../wizard/machine";
import { deviceLabel, type ScreenProps } from "./types";

const t = en.cleanup;

function ItemArt({ id, device }: { id: CleanupId; device: Device }) {
  switch (id) {
    case "proxyOff": return <ProxyForm device={device} ip="" port={0} mode="off" />;
    case "profileRemoved": return <DeviceManagement device={device} />;
    case "authySignedIn": return <AuthyAccounts device={device} />;
    case "fileDeleted": return <TrashFile />;
  }
}

export function Cleanup({ api, state, dispatch }: ScreenProps) {
  const [core, setCore] = useState<"working" | "clean" | "failed">("working");
  const [shown, setShown] = useState<CleanupId>("proxyOff");
  const [finishing, setFinishing] = useState(false);
  const started = useRef(false);
  const items = cleanupItems(state);
  const left = items.filter((id) => !state.cleanupTicks[id]).length;
  const device: Device = state.device ?? "iphone";
  const d = deviceLabel(state.device);

  const runCleanup = () => {
    setCore("working");
    api.cleanup().then(() => setCore("clean")).catch(() => setCore("failed"));
  };
  useEffect(() => {
    // The ref keeps React's development double-mount from asking the core twice.
    if (started.current) return;
    started.current = true;
    runCleanup();
  }, []);

  const finish = async () => {
    setFinishing(true);
    try {
      await api.finish();
      dispatch({ type: "finish" });
    } catch {
      setFinishing(false);
    }
  };

  return (
    <Screen
      title={t.title}
      lede={state.resumed ? t.resumed : undefined}
      footer={
        <>
          <p className="footer-hint" aria-live="polite">{left > 0 ? t.remaining(left) : ""}</p>
          <button type="button" className="primary" disabled={!canFinish(state) || core !== "clean" || finishing} onClick={() => void finish()}>
            {t.finish}
          </button>
        </>
      }
    >
      {!state.cleanupTicks.proxyOff && <Callout tone="warn" title={t.noInternet(d)} />}
      <div aria-live="polite">
        {core === "working" && <Waiting>{t.working}</Waiting>}
        {core === "clean" && <Callout tone="ok"><p>{t.clean}</p></Callout>}
      </div>
      {core === "failed" && (
        <Callout tone="error" title={t.failed} alert>
          <button type="button" className="secondary" onClick={runCleanup}>{en.common.tryAgain}</button>
        </Callout>
      )}

      {state.device === null && (
        <fieldset className="segmented">
          <legend>{t.deviceQuestion}</legend>
          <div className="segments">
            {(["iphone", "ipad"] as const).map((option) => (
              <label key={option}>
                <input type="radio" name="cleanup-device" checked={false} onChange={() => dispatch({ type: "chooseDevice", device: option })} />
                <span>{en.deviceName[option]}</span>
              </label>
            ))}
          </div>
        </fieldset>
      )}

      <div className="split">
        <div className="split-main">
          <h2>{t.todo(d)}</h2>
          <div className="ticks">
            {items.map((id) => (
              <Tick
                key={id}
                checked={state.cleanupTicks[id]}
                onChange={(value) => { setShown(id); dispatch({ type: "setCleanup", id, value }); }}
                label={t.items[id].label}
                detail={t.items[id].how}
                extra={
                  <button type="button" className="quiet small" aria-pressed={shown === id} aria-label={en.common.showPictureFor(t.items[id].label)} onClick={() => setShown(id)}>
                    {en.common.showPicture}
                  </button>
                }
              />
            ))}
          </div>
          <p className="quiet-text">{t.vpnBack}</p>
          <p className="quiet-text">{t.keepAuthy}</p>
        </div>
        <div className="split-art">
          <div className="guide-figure"><ItemArt id={shown} device={device} /></div>
        </div>
      </div>
    </Screen>
  );
}
