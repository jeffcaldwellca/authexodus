// QR codes on screen: one per account for any app, or Google Authenticator's transfer codes.
// A code is fetched from the core only while it is being shown and is dropped when the view
// moves on or closes.
import { useEffect, useState } from "react";
import type { TokenView } from "../api";
import { Callout, QrImage, Screen, Waiting } from "../components/ui";
import { en } from "../strings/en";
import type { ScreenProps } from "./types";

const t = en.destination;

function Pager({ index, total, onMove, onDone }: { index: number; total: number; onMove: (to: number) => void; onDone: () => void }) {
  const last = index >= total - 1;
  return (
    <>
      <button type="button" className="quiet" onClick={onDone}>{t.backToOptions}</button>
      <span className="footer-group">
        <button type="button" className="secondary" disabled={index === 0} onClick={() => onMove(index - 1)}>{en.common.previous}</button>
        {last
          ? <button type="button" className="primary" onClick={onDone}>{en.common.done}</button>
          : <button type="button" className="primary" onClick={() => onMove(index + 1)}>{en.common.next}</button>}
      </span>
    </>
  );
}

export function QrWalk({ api, tokens, onDone }: ScreenProps & { tokens: TokenView[]; onDone: () => void }) {
  const [index, setIndex] = useState(0);
  const [svg, setSvg] = useState<string | null>(null);
  const token = tokens[index];

  useEffect(() => {
    if (!token) return;
    let live = true;
    setSvg(null);
    api.tokenQr(token.id).then((s) => { if (live) setSvg(s); }).catch(() => undefined);
    return () => { live = false; setSvg(null); };
  }, [api, token]);

  if (!token) return null;
  return (
    <Screen title={t.qr.title} lede={t.qr.lede} footer={<Pager index={index} total={tokens.length} onMove={setIndex} onDone={onDone} />}>
      <div className="qr-walk">
        <div className="qr-block">
          {svg ? <QrImage svg={svg} alt={t.qr.alt(token.title)} size={260} /> : <Waiting>{t.qr.loading}</Waiting>}
        </div>
        <div>
          <p className="quiet-text" aria-live="polite">{t.qr.position(index + 1, tokens.length)}</p>
          <p className="account-title">{token.title}</p>
          {token.username && <p className="quiet-text">{token.username}</p>}
          <Callout tone="warn"><p>{t.qr.warning}</p></Callout>
        </div>
      </div>
    </Screen>
  );
}

export function GoogleWalk({ api, onDone }: ScreenProps & { onDone: () => void }) {
  const [index, setIndex] = useState(0);
  const [codes, setCodes] = useState<string[] | null>(null);

  useEffect(() => {
    let live = true;
    api.googleMigrationQrs().then((s) => { if (live) setCodes(s); }).catch(() => undefined);
    return () => { live = false; setCodes(null); };
  }, [api]);

  const svg = codes?.[index];
  return (
    <Screen title={t.google.title} lede={t.google.lede} footer={<Pager index={index} total={codes?.length ?? 1} onMove={setIndex} onDone={onDone} />}>
      <div className="qr-walk">
        <div className="qr-block">
          {svg ? <QrImage svg={svg} alt={t.google.alt(index + 1)} size={260} /> : <Waiting>{t.qr.loading}</Waiting>}
        </div>
        <div>
          {codes && <p className="account-title" aria-live="polite">{t.google.position(index + 1, codes.length)}</p>}
          <Callout tone="warn"><p>{t.qr.warning}</p></Callout>
        </div>
      </div>
    </Screen>
  );
}
