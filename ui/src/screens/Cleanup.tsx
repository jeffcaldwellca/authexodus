// Screen 8: the app stops the proxy and drops the certificate key from memory, then the person
// undoes the phone changes by hand. It is not finished until every item is ticked. A launch that
// follows an unfinished run opens here. Nothing fails quietly: a cleanup or a Finish that the
// shell rejects is shown with its reason and what to do about it.
import { useEffect, useRef, useState } from "react";
import type { Device } from "../api";
import { asApiError, type ApiError } from "../api.errors";
import { Callout, Screen, Tick, Waiting } from "../components/ui";
import { AuthyAccounts, DeviceManagement, ProxyForm, TrashFile } from "../device/scenes";
import { en } from "../strings/en";
import { canFinish, cantMoveCount, cleanupItems, type CleanupId } from "../wizard/machine";
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

export function Cleanup({ api, state, dispatch, certConstrained }: ScreenProps) {
  const [core, setCore] = useState<"working" | "clean" | "failed">("working");
  const [failure, setFailure] = useState<ApiError | null>(null);
  const [carryOnAnyway, setCarryOnAnyway] = useState(false);
  const [shown, setShown] = useState<CleanupId>("proxyOff");
  const [finishing, setFinishing] = useState(false);
  const [finishError, setFinishError] = useState<ApiError | null>(null);
  const started = useRef(false);
  const items = cleanupItems(state);
  const left = items.filter((id) => !state.cleanupTicks[id]).length;
  const device: Device = state.device ?? "iphone";
  const d = deviceLabel(state.device);
  const cantMove = cantMoveCount(state);

  const runCleanup = () => {
    setCore("working");
    setFinishError(null);
    api.cleanup().then(() => { setFailure(null); setCore("clean"); }).catch((err: unknown) => {
      // The shell's own words say what could not be removed; the person needs them to act.
      setFailure(asApiError(err));
      setCore("failed");
    });
  };
  useEffect(() => {
    // The ref keeps React's development double-mount from asking the core twice.
    if (started.current) return;
    started.current = true;
    runCleanup();
  }, []);

  // When this computer's own cleanup keeps failing, the person can say so and carry on.
  const computerDone = core === "clean" || (core === "failed" && carryOnAnyway);
  const text = (id: CleanupId) => (id === "fileDeleted" && !state.exportedFile ? t.items.fileDeletedMaybe : t.items[id]);

  const finish = async () => {
    setFinishing(true);
    setFinishError(null);
    try {
      await api.finish();
      dispatch({ type: "finish" });
    } catch (err) {
      // Finish runs the cleanup again in the shell. If that fails, the person is told: a
      // Finish button that does nothing is the worst outcome here.
      setFinishError(asApiError(err));
      setFinishing(false);
    }
  };

  const reasonOf = (error: ApiError) => (error.message.trim() === "" ? null : <p>{t.failedReason(error.message.trim())}</p>);

  return (
    <Screen
      title={t.title}
      lede={state.resumed ? t.resumed : state.recovered ? t.reloaded : undefined}
      footer={
        <>
          <p className="footer-hint" aria-live="polite">{left > 0 ? t.remaining(left) : ""}</p>
          <button type="button" className="primary" disabled={!canFinish(state) || !computerDone || finishing} onClick={() => void finish()}>
            {t.finish}
          </button>
        </>
      }
    >
      {!state.cleanupTicks.proxyOff && <Callout tone="warn" title={t.noInternet(d)} />}
      {state.resumed && <Callout tone="info"><p>{t.keyGone(d)}</p></Callout>}
      <div aria-live="polite">
        {core === "working" && <Waiting>{t.working}</Waiting>}
        {core === "clean" && <Callout tone="ok"><p>{t.clean(d)}</p></Callout>}
      </div>
      {core === "failed" && failure && (
        <Callout tone="error" title={t.failed} alert>
          {reasonOf(failure)}
          <p>{t.failedOther}</p>
          <button type="button" className="secondary" onClick={runCleanup}>{en.common.tryAgain}</button>
          <label className="scanned">
            <input type="checkbox" checked={carryOnAnyway} onChange={(e) => setCarryOnAnyway(e.target.checked)} />
            <span>{t.otherDone}</span>
          </label>
        </Callout>
      )}
      {finishError && (
        <Callout tone="error" title={t.finishFailed} alert>
          {reasonOf(finishError)}
          <p>{t.finishFailedOther}</p>
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
                label={text(id).label}
                detail={id === "profileRemoved" && certConstrained === false ? `${text(id).how} ${t.unconstrained}` : text(id).how}
                extra={
                  <button type="button" className="quiet small" aria-pressed={shown === id} aria-label={en.common.showPictureFor(text(id).label)} onClick={() => setShown(id)}>
                    {en.common.showPicture}
                  </button>
                }
              />
            ))}
          </div>
          {!items.includes("profileRemoved") && <p className="quiet-text">{t.noCertificate(d)}</p>}
          <p className="quiet-text">{t.vpnBack}</p>
          <p className="quiet-text">{t.keepAuthy}</p>
          {cantMove > 0 && (
            <section className="cant-move" aria-labelledby="still-in-authy">
              <h2 id="still-in-authy">{t.cantMoveTitle(cantMove)}</h2>
              <p className="quiet-text">{t.cantMoveLede}</p>
              <ul>
                {state.cantMove.native.map((name) => <li key={`native:${name}`}>{name}</li>)}
                {state.cantMove.invalid.map((name) => <li key={`invalid:${name}`}>{name}</li>)}
              </ul>
            </section>
          )}
        </div>
        <div className="split-art">
          <div className="guide-figure"><ItemArt id={shown} device={device} /></div>
        </div>
      </div>
    </Screen>
  );
}
