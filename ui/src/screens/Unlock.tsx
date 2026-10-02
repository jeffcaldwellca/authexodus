// Screen 5: the backup password. Right-or-wrong feedback is immediate and inline. The password
// lives in this component only until the unlock succeeds, and is never trimmed or changed.
// The captured count is live: it follows the proxy while this screen is open.
import { useRef, useState, type FormEvent } from "react";
import { asApiError, type ApiError } from "../api.errors";
import { Screen } from "../components/ui";
import { Problem } from "../failures/Problem";
import { StopConfirm } from "../failures/StopConfirm";
import { WrongPassword } from "../failures/WrongPassword";
import { en } from "../strings/en";
import { deviceLabel, type ScreenProps } from "./types";

const t = en.unlock;

export function Unlock({ api, state, dispatch, onRestart, restart }: ScreenProps) {
  const [password, setPassword] = useState("");
  const [visible, setVisible] = useState(false);
  const [busy, setBusy] = useState(false);
  const [wrong, setWrong] = useState(false);
  const [failure, setFailure] = useState<ApiError | null>(null);
  const [confirming, setConfirming] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  const d = deviceLabel(state.device);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (busy || password === "") return;
    setBusy(true);
    setWrong(false);
    setFailure(null);
    try {
      const result = await api.unlock(password);
      if ("error" in result) {
        setWrong(true);
        setBusy(false);
        input.current?.focus();
        return;
      }
      setPassword("");
      dispatch({ type: "unlocked", summary: result });
    } catch (err) {
      setFailure(asApiError(err));
      setBusy(false);
    }
  };

  const recapture = (
    <button type="button" className="secondary" disabled={restart === "busy"} onClick={() => onRestart()}>
      {restart === "busy" ? en.common.restarting : t.recapture.action}
    </button>
  );

  return (
    <Screen
      title={t.title}
      lede={t.lede}
      status={
        <p className="captured" role="status" aria-live="polite">
          {state.captured === null ? "" : state.captured === 0 ? t.capturedNativeOnly : t.captured(state.captured)}
        </p>
      }
      footer={
        <>
          <span />
          <button type="submit" form="unlock-form" className="primary" disabled={busy || password === ""}>
            {busy ? t.working : t.submit}
          </button>
        </>
      }
    >
      <form id="unlock-form" className="form narrow" onSubmit={submit} noValidate>
        <label htmlFor="backup-password">{t.label}</label>
        <div className="password-row">
          <input
            ref={input}
            id="backup-password"
            type={visible ? "text" : "password"}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="off"
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            aria-invalid={wrong}
            aria-describedby={wrong ? "unlock-error" : undefined}
          />
          <button type="button" className="quiet" aria-pressed={visible} onClick={() => setVisible((v) => !v)}>
            {t.show}
          </button>
        </div>
        <div id="unlock-error">
          {wrong && <WrongPassword d={d} />}
        </div>
      </form>
      {failure && (
        // With no backup held, typing the password again cannot help: only a new capture can.
        <Problem error={failure} d={d} title={t.failed}>{failure.code === "no_backup" && recapture}</Problem>
      )}
      <p className="quiet-text narrow">{t.alsoAuthy(d)}</p>
      {failure?.code !== "no_backup" && (
        <details className="panel narrow">
          <summary>{t.recapture.title}</summary>
          <div className="panel-content">
            <p>{t.recapture.body(d)}</p>
            {recapture}
          </div>
        </details>
      )}
      <p className="quiet-text narrow way-out">
        {t.forgotten}
        <button type="button" className="quiet danger small" onClick={() => setConfirming(true)}>{en.common.stopAndCleanUp}</button>
      </p>
      {confirming && (
        <StopConfirm d={d} mentionAuthy onCancel={() => setConfirming(false)} onConfirm={() => dispatch({ type: "abandon" })} />
      )}
    </Screen>
  );
}
