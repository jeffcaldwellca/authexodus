// Screen 6: choose where the codes go. Four ways, each a sub-view of this screen. Tokens that
// cannot move (Authy's own 7-digit ones, and unusable keys) are listed by name, never exported.
// The step can always be left without moving anything: back to Unlock while nothing has been
// moved, or Stop and clean up at any time.
import { useState } from "react";
import { Callout, Screen } from "../components/ui";
import { ManualGuide } from "../failures/ManualGuide";
import { StopConfirm } from "../failures/StopConfirm";
import { en } from "../strings/en";
import { canLeaveDestination } from "../wizard/machine";
import { BitwardenFlow } from "./BitwardenFlow";
import { FileExport } from "./FileExport";
import { GoogleWalk, QrWalk } from "./QrWalk";
import { deviceLabel, type ScreenProps } from "./types";

const t = en.destination;
const OPTIONS = ["qr", "bitwarden", "google", "file"] as const;
type Option = (typeof OPTIONS)[number];

export function Destination(props: ScreenProps) {
  const { state, dispatch } = props;
  const [view, setView] = useState<Option | null>(null);
  const [used, setUsed] = useState<ReadonlySet<Option>>(new Set());
  const [confirming, setConfirming] = useState(false);
  const summary = state.summary ?? { tokens: [], invalid: [], native: [] };
  const cantMove = summary.native.length + summary.invalid.length;
  const nothingToMove = summary.tokens.length === 0;
  const canLeave = canLeaveDestination(state);
  const d = deviceLabel(state.device);

  const leave = (option: Option, wasUsed: boolean) => {
    if (wasUsed) {
      setUsed((prev) => new Set(prev).add(option));
      dispatch({ type: "moved" });
    }
    setView(null);
  };
  // The shell says the codes are locked again: the only way on is the backup password.
  const locked = () => dispatch({ type: "locked" });

  if (view === "qr") return <QrWalk {...props} tokens={summary.tokens} onDone={(walked) => leave("qr", walked)} onLocked={locked} />;
  if (view === "google") return <GoogleWalk {...props} tokens={summary.tokens} onDone={(walked) => leave("google", walked)} onLocked={locked} />;
  if (view === "file") return <FileExport {...props} onDone={(saved) => leave("file", saved)} onLocked={locked} />;
  if (view === "bitwarden") return <BitwardenFlow {...props} tokens={summary.tokens} onDone={(applied) => leave("bitwarden", applied)} onLocked={locked} />;

  const cantMoveList = cantMove > 0 && (
    <section className="cant-move" aria-labelledby="cant-move-title">
      <h2 id="cant-move-title">{t.cantMoveTitle(cantMove)}</h2>
      <p className="quiet-text">{t.cantMoveLede}</p>
      <ul>
        {summary.native.map((n) => <li key={`native:${n.name}`}>{t.native(n.name)}</li>)}
        {summary.invalid.map((n) => <li key={`invalid:${n.name}`}>{t.invalid(n.name)}</li>)}
      </ul>
    </section>
  );
  const authyFirst = (
    <Callout tone="warn" title={t.authyTitle}>
      <p>{t.authyBody(d)}</p>
    </Callout>
  );

  // Nothing this app can copy: say so, show what is left and how to do it by hand, and go
  // straight to cleanup. There are no codes to check, so the verify step is skipped.
  if (nothingToMove) {
    return (
      <Screen
        title={t.noneTitle}
        lede={cantMove > 0 ? t.noneCantMove : t.none}
        footer={
          <>
            <button type="button" className="quiet" onClick={() => dispatch({ type: "backToUnlock" })}>{t.backToUnlock}</button>
            <button type="button" className="primary" onClick={() => dispatch({ type: "abandon" })}>{t.toCleanup}</button>
          </>
        }
      >
        {authyFirst}
        {cantMoveList}
        <ManualGuide />
      </Screen>
    );
  }

  return (
    <Screen
      title={t.title}
      lede={t.lede(summary.tokens.length)}
      footer={
        <>
          <span className="footer-group">
            {!state.moved && (
              <button type="button" className="quiet" onClick={() => dispatch({ type: "backToUnlock" })}>{t.backToUnlock}</button>
            )}
            <button type="button" className="quiet danger" onClick={() => setConfirming(true)}>{en.common.stopAndCleanUp}</button>
          </span>
          <p className="footer-hint" aria-live="polite">{canLeave ? "" : t.continueBlocked}</p>
          <button type="button" className="primary" disabled={!canLeave} onClick={() => dispatch({ type: "destinationDone" })}>
            {t.continue}
          </button>
        </>
      }
    >
      {authyFirst}
      {cantMoveList}
      <ul className="options">
        {OPTIONS.map((option) => (
          <li key={option}>
            <button type="button" className="option" onClick={() => setView(option)}>
              <span className="option-title">
                {t.options[option].title}
                {used.has(option) && <span className="tag">{t.usedTag}</span>}
              </span>
              <span className="option-body">{t.options[option].body}</span>
            </button>
          </li>
        ))}
      </ul>
      {confirming && (
        <StopConfirm d={d} mentionAuthy onCancel={() => setConfirming(false)} onConfirm={() => dispatch({ type: "abandon" })} />
      )}
    </Screen>
  );
}
