// Screen 7: live codes beside each account, refreshed every second, to compare with the new
// app. Codes are held only while this screen is showing.
import { useEffect, useState } from "react";
import type { LiveCode } from "../api";
import { Callout, Screen, Waiting } from "../components/ui";
import { en } from "../strings/en";
import type { ScreenProps } from "./types";

const t = en.verify;

/** "123456" → "123 456", the way authenticator apps show it. */
function grouped(code: string): string {
  const half = Math.ceil(code.length / 2);
  return `${code.slice(0, half)} ${code.slice(half)}`;
}

export function Verify({ api, state, dispatch }: ScreenProps) {
  const [codes, setCodes] = useState<Map<string, LiveCode> | null>(null);

  useEffect(() => {
    let live = true;
    const refresh = () => {
      api.liveCodes().then((list) => { if (live) setCodes(new Map(list.map((c) => [c.id, c]))); }).catch(() => undefined);
    };
    refresh();
    const timer = setInterval(refresh, 1000);
    return () => { live = false; clearInterval(timer); setCodes(null); };
  }, [api]);

  const tokens = state.summary?.tokens ?? [];
  return (
    <Screen
      title={t.title}
      lede={t.lede}
      footer={
        <>
          <button type="button" className="quiet" onClick={() => dispatch({ type: "backToDestination" })}>{t.another}</button>
          <p className="footer-hint">{t.forget}</p>
          <button type="button" className="primary" onClick={() => dispatch({ type: "verified" })}>{t.confirm}</button>
        </>
      }
    >
      {codes === null ? <Waiting>{t.loading}</Waiting> : (
        <ul className="codes" aria-label={t.listLabel}>
          {tokens.map((token) => {
            const live = codes.get(token.id);
            return (
              <li key={token.id}>
                <span className="code-account">
                  <span className="account-name">{token.title}</span>
                  {token.username && <span className="quiet-text">{token.username}</span>}
                </span>
                {live && (
                  <>
                    <span className="code">{grouped(live.code)}</span>
                    <span className={`countdown ${live.secondsLeft <= 5 ? "ending" : ""}`} aria-label={t.secondsLeftLabel(live.secondsLeft)}>
                      {t.secondsLeft(live.secondsLeft)}
                    </span>
                  </>
                )}
              </li>
            );
          })}
        </ul>
      )}
      <Callout tone="info"><p>{t.mismatch}</p></Callout>
    </Screen>
  );
}
