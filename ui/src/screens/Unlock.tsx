// Screen 5: the backup password. Right-or-wrong feedback is immediate and inline. The password
// lives in this component only until the unlock succeeds, and is never trimmed or changed.
import { useRef, useState, type FormEvent } from "react";
import { Callout, Screen } from "../components/ui";
import { StopConfirm } from "../failures/StopConfirm";
import { WrongPassword } from "../failures/WrongPassword";
import { en } from "../strings/en";
import { deviceLabel, type ScreenProps } from "./types";

const t = en.unlock;

export function Unlock({ api, state, dispatch }: ScreenProps) {
  const [password, setPassword] = useState("");
  const [visible, setVisible] = useState(false);
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<"wrong" | "failed" | null>(null);
  const [confirming, setConfirming] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  const d = deviceLabel(state.device);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (busy || password === "") return;
    setBusy(true);
    setProblem(null);
    try {
      const result = await api.unlock(password);
      if ("error" in result) {
        setProblem("wrong");
        setBusy(false);
        input.current?.focus();
        return;
      }
      setPassword("");
      dispatch({ type: "unlocked", summary: result });
    } catch {
      setProblem("failed");
      setBusy(false);
    }
  };

  return (
    <Screen
      title={t.title}
      lede={t.lede}
      status={
        <p className="captured" role="status" aria-live="polite">
          {state.captured !== null ? t.captured(state.captured) : ""}
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
            aria-invalid={problem === "wrong"}
            aria-describedby={problem === "wrong" ? "unlock-error" : undefined}
          />
          <button type="button" className="quiet" aria-pressed={visible} onClick={() => setVisible((v) => !v)}>
            {visible ? t.hide : t.show}
          </button>
        </div>
        <div id="unlock-error">
          {problem === "wrong" && <WrongPassword d={d} />}
          {problem === "failed" && <Callout tone="error" title={t.failed} alert />}
        </div>
      </form>
      <p className="quiet-text narrow">{t.alsoAuthy(d)}</p>
      <p className="quiet-text narrow way-out">
        {t.forgotten}
        <button type="button" className="quiet danger small" onClick={() => setConfirming(true)}>{en.common.stopAndCleanUp}</button>
      </p>
      {confirming && (
        <StopConfirm mentionAuthy onCancel={() => setConfirming(false)} onConfirm={() => dispatch({ type: "abandon" })} />
      )}
    </Screen>
  );
}
