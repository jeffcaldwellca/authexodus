// QR codes on screen: one per account for any app, or Google Authenticator's transfer codes.
// A code is fetched from the core only while it is being shown and is dropped when the view
// moves on or closes. The person ticks each code they scanned; one tick is enough for the
// codes to count as moved, wherever in the walk they stop. A code that cannot be drawn says
// so and can be tried again; the screen never waits for ever.
import { useEffect, useState, type ReactNode } from "react";
import type { TokenView } from "../api";
import { ApiError, asApiError } from "../api.errors";
import { Callout, QrImage, Screen, Waiting } from "../components/ui";
import { Problem } from "../failures/Problem";
import { en } from "../strings/en";
import { deviceLabel, type ScreenProps } from "./types";

const t = en.destination;

/** `onDone(true)` means at least one code was scanned and ticked. */
function Pager({ index, total, scanned, onMove, onDone }: {
  index: number; total: number; scanned: number; onMove: (to: number) => void; onDone: (moved: boolean) => void;
}) {
  const last = index >= total - 1;
  return (
    <>
      <button type="button" className="quiet" onClick={() => onDone(scanned > 0)}>{t.backToOptions}</button>
      <span className="footer-group">
        <button type="button" className="secondary" disabled={index === 0} onClick={() => onMove(index - 1)}>{en.common.previous}</button>
        {last
          ? <button type="button" className="primary" onClick={() => onDone(scanned > 0)}>{en.common.done}</button>
          : <button type="button" className="primary" onClick={() => onMove(index + 1)}>{en.common.next}</button>}
      </span>
    </>
  );
}

function ScannedTick({ checked, onChange, count, total }: { checked: boolean; onChange: (v: boolean) => void; count: number; total: number }) {
  return (
    <>
      <label className="scanned">
        <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} />
        <span>{t.qr.scanned}</span>
      </label>
      <p className="quiet-text" aria-live="polite">{t.qr.scannedCount(count, total)}</p>
    </>
  );
}

/** Which positions in a walk have been ticked as scanned. */
function useScanned() {
  const [scanned, setScanned] = useState<ReadonlySet<number>>(new Set());
  const set = (index: number, value: boolean) => setScanned((prev) => {
    const next = new Set(prev);
    if (value) next.add(index); else next.delete(index);
    return next;
  });
  return [scanned, set] as const;
}

/** A drawing that came back blank is a failure too, not something to wait for. */
function blank(): ApiError {
  return new ApiError("export_failed", t.qr.empty);
}

/** The code could not be drawn: why, a way to try again, and the way back to unlock if that is the reason. */
function DrawFailed({ error, d, onRetry, onLocked }: { error: ApiError; d: string; onRetry: () => void; onLocked: () => void }) {
  return (
    <Problem error={error} d={d} title={t.qr.failed}>
      {error.code === "not_unlocked"
        ? <button type="button" className="secondary" onClick={onLocked}>{en.common.unlockAgain}</button>
        : <button type="button" className="secondary" onClick={onRetry}>{en.common.tryAgain}</button>}
    </Problem>
  );
}

function Tested({ app }: { app: string }): ReactNode {
  return <p className="quiet-text">{en.common.untested(app)}</p>;
}

type WalkProps = ScreenProps & { onDone: (moved: boolean) => void; onLocked: () => void };

export function QrWalk({ api, state, tokens, onDone, onLocked }: WalkProps & { tokens: TokenView[] }) {
  const [index, setIndex] = useState(0);
  const [svg, setSvg] = useState<string | null>(null);
  const [failure, setFailure] = useState<ApiError | null>(null);
  const [attempt, setAttempt] = useState(0);
  const [scanned, setScanned] = useScanned();
  const token = tokens[index];
  const d = deviceLabel(state.device);

  useEffect(() => {
    if (!token) return;
    let live = true;
    setSvg(null);
    setFailure(null);
    api.tokenQr(token.id)
      .then((s) => { if (live) { if (s.trim() === "") setFailure(blank()); else setSvg(s); } })
      .catch((err: unknown) => { if (live) setFailure(asApiError(err)); });
    return () => { live = false; setSvg(null); };
  }, [api, token, attempt]);

  if (!token) return null;
  return (
    <Screen
      title={t.qr.title}
      lede={t.qr.lede}
      footer={<Pager index={index} total={tokens.length} scanned={scanned.size} onMove={setIndex} onDone={onDone} />}
    >
      <div className="qr-walk">
        <div className="qr-block">
          {failure ? <DrawFailed error={failure} d={d} onRetry={() => setAttempt((n) => n + 1)} onLocked={onLocked} />
            : svg ? <QrImage svg={svg} alt={t.qr.alt(token.title)} size={260} /> : <Waiting>{t.qr.loading}</Waiting>}
        </div>
        <div>
          <p className="quiet-text" aria-live="polite">{t.qr.position(index + 1, tokens.length)}</p>
          <p className="account-title">{token.title}</p>
          {token.username && <p className="quiet-text">{token.username}</p>}
          {svg && <ScannedTick checked={scanned.has(index)} onChange={(v) => setScanned(index, v)} count={scanned.size} total={tokens.length} />}
          <Callout tone="warn"><p>{t.qr.warning}</p></Callout>
          <Tested app={t.qr.app} />
        </div>
      </div>
    </Screen>
  );
}

export function GoogleWalk({ api, state, onDone, onLocked }: WalkProps) {
  const [index, setIndex] = useState(0);
  const [codes, setCodes] = useState<string[] | null>(null);
  const [unsupported, setUnsupported] = useState<string[]>([]);
  const [failure, setFailure] = useState<ApiError | null>(null);
  const [attempt, setAttempt] = useState(0);
  const [scanned, setScanned] = useScanned();
  const d = deviceLabel(state.device);

  useEffect(() => {
    let live = true;
    setCodes(null);
    setFailure(null);
    Promise.all([api.googleMigrationQrs(), api.googleUnsupported()])
      .then(([qrs, titles]) => {
        if (!live) return;
        setUnsupported(titles);
        if (qrs.some((s) => s.trim() === "")) setFailure(blank()); else setCodes(qrs);
      })
      .catch((err: unknown) => { if (live) setFailure(asApiError(err)); });
    return () => { live = false; setCodes(null); };
  }, [api, attempt]);

  const svg = codes?.[index];
  const total = codes?.length ?? 1;
  // No page at all: nothing Google's codes can carry. That is an answer, not a wait.
  const nothing = codes !== null && codes.length === 0;
  return (
    <Screen
      title={t.google.title}
      lede={t.google.lede}
      footer={<Pager index={index} total={Math.max(total, 1)} scanned={scanned.size} onMove={setIndex} onDone={onDone} />}
    >
      <div className="qr-walk">
        <div className="qr-block">
          {failure ? <DrawFailed error={failure} d={d} onRetry={() => setAttempt((n) => n + 1)} onLocked={onLocked} />
            : nothing ? <Callout tone="warn" title={t.google.none} alert />
            : svg ? <QrImage svg={svg} alt={t.google.alt(index + 1)} size={260} /> : <Waiting>{t.qr.loading}</Waiting>}
        </div>
        <div>
          {codes && codes.length > 0 && <p className="account-title" aria-live="polite">{t.google.position(index + 1, codes.length)}</p>}
          {svg && <ScannedTick checked={scanned.has(index)} onChange={(v) => setScanned(index, v)} count={scanned.size} total={total} />}
          <Callout tone="warn"><p>{t.qr.warning}</p></Callout>
          {unsupported.length > 0 && (
            <Callout tone="info" title={t.google.unsupportedTitle(unsupported.length)}>
              <p>{t.google.unsupportedBody}</p>
              <ul className="plain-list">{unsupported.map((title, i) => <li key={`${i}:${title}`}>{title}</li>)}</ul>
            </Callout>
          )}
          <Tested app={t.google.app} />
        </div>
      </div>
    </Screen>
  );
}
