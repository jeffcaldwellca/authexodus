// Screen 7: live codes beside each account, to compare with the new app. The codes are
// refreshed every second, and faster as a code is about to change, so the screen turns over
// with the code rather than up to a second after it. Codes are held only while this screen
// is showing.
import { useEffect, useState } from "react";
import type { LiveCode } from "../api";
import { asApiError, type ApiError } from "../api.errors";
import { Callout, Screen, Waiting } from "../components/ui";
import { Problem } from "../failures/Problem";
import { en } from "../strings/en";
import { cantMoveCount } from "../wizard/machine";
import { deviceLabel, type ScreenProps } from "./types";

const t = en.verify;

/** The usual pause between refreshes, and the short one used around the moment codes change. */
export const REFRESH_MS = 1000;
export const REFRESH_NEAR_CHANGE_MS = 250;

/** "123456" → "123 456", the way authenticator apps show it. */
function grouped(code: string): string {
  const half = Math.ceil(code.length / 2);
  return `${code.slice(0, half)} ${code.slice(half)}`;
}

export function Verify({ api, state, dispatch }: ScreenProps) {
  const [codes, setCodes] = useState<Map<string, LiveCode> | null>(null);
  const [failure, setFailure] = useState<ApiError | null>(null);
  const failed = failure !== null;
  const cantMove = cantMoveCount(state);

  useEffect(() => {
    let live = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const refresh = () => {
      api.liveCodes()
        .then((list) => {
          if (!live) return;
          setCodes(new Map(list.map((c) => [c.id, c])));
          setFailure(null);
          // `secondsLeft` is whole seconds, so in the last second poll quickly to catch the change.
          const soonest = Math.min(...list.map((c) => c.secondsLeft), Infinity);
          timer = setTimeout(refresh, soonest <= 1 ? REFRESH_NEAR_CHANGE_MS : REFRESH_MS);
        })
        .catch((err: unknown) => {
          if (!live) return;
          setFailure(asApiError(err));
          timer = setTimeout(refresh, REFRESH_MS);
        });
    };
    refresh();
    return () => { live = false; clearTimeout(timer); setCodes(null); };
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
      {failure && (
        <Problem error={failure} d={deviceLabel(state.device)} title={t.failed}>
          {failure.code === "not_unlocked" && (
            <button type="button" className="secondary" onClick={() => dispatch({ type: "locked" })}>{en.common.unlockAgain}</button>
          )}
        </Problem>
      )}
      {codes === null && !failed && <Waiting>{t.loading}</Waiting>}
      {codes !== null && (
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
                    <span className={`countdown ${live.secondsLeft <= 5 ? "ending" : ""}`}>
                      <span aria-hidden="true">{t.secondsLeft(live.secondsLeft)}</span>
                      <span className="sr-only">{t.secondsLeftLabel(live.secondsLeft)}</span>
                    </span>
                  </>
                )}
              </li>
            );
          })}
        </ul>
      )}
      <Callout tone="info"><p>{t.mismatch}</p></Callout>
      {cantMove > 0 && <p className="quiet-text">{t.cantMove(cantMove)}</p>}
    </Screen>
  );
}
