// Dev-only: stands in for the phone when the wizard runs against the fake in a plain browser.
// It is never loaded inside Tauri.
import { useState } from "react";
import { ApiError } from "../api.errors";
import { FAKE_PASSWORD, type FakeApi } from "../api.fake";
import { dev as t } from "../strings/dev";
import "./dev.css";

export function DevPanel({ api }: { api: FakeApi }) {
  const [open, setOpen] = useState(true);
  if (!open) {
    return <button type="button" className="dev-toggle" onClick={() => setOpen(true)}>{t.show}</button>;
  }
  return (
    <aside className="dev-panel" aria-label={t.title}>
      <p className="dev-title">
        <strong>{t.title}</strong>
        <button type="button" onClick={() => setOpen(false)}>{t.hide}</button>
      </p>
      <p>{t.note(FAKE_PASSWORD)}</p>
      <div className="dev-buttons">
        <button type="button" onClick={() => api.emitProxyEvent({ kind: "deviceConnected" })}>{t.deviceConnected}</button>
        <button type="button" onClick={() => api.emitProxyEvent({ kind: "tlsRejected" })}>{t.tlsRejected}</button>
        <button type="button" onClick={() => api.emitProxyEvent({ kind: "trustWorking" })}>{t.trustWorking}</button>
        <button type="button" onClick={() => api.emitProxyEvent({ kind: "authyError", status: 400, path: "/json/users/new" })}>{t.authyError}</button>
        <button type="button" onClick={() => api.emitProxyEvent({ kind: "deviceRefused" })}>{t.deviceRefused}</button>
        <button type="button" onClick={() => api.emitProxyEvent({ kind: "emptyBackup" })}>{t.emptyBackup}</button>
        <button type="button" onClick={() => api.emitProxyEvent({ kind: "addressChanged" })}>{t.addressChanged}</button>
        <button type="button" onClick={() => api.emitProxyEvent({ kind: "backupCaptured", count: api.script.summary.tokens.length + 2 })}>{t.backupCaptured}</button>
        <button type="button" onClick={() => { api.script.loginResults.push({ kind: "needsApiKey" }); }}>{t.bwNeedsKey}</button>
        <button type="button" onClick={() => { (api.script.failures.bwApply ??= []).push(new ApiError("bw_session_expired", t.bwExpiredMessage)); }}>{t.bwExpire}</button>
        <button type="button" onClick={() => { api.script.applyResults.push({ attached: 2, created: 0, skipped: 0, kept: [], failed: t.bwFailMessage }); }}>{t.bwFail}</button>
      </div>
    </aside>
  );
}
