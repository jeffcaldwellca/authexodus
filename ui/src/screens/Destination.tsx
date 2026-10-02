// Screen 6: choose where the codes go. Four ways, each a sub-view of this screen. Tokens that
// cannot move (Authy's own 7-digit ones, and unusable keys) are listed by name, never exported.
import { useState } from "react";
import { Callout, Screen } from "../components/ui";
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
  const summary = state.summary ?? { tokens: [], invalid: [], native: [] };
  const cantMove = summary.native.length + summary.invalid.length;
  const canLeave = canLeaveDestination(state);

  const leave = (option: Option, wasUsed: boolean) => {
    if (wasUsed) {
      setUsed((prev) => new Set(prev).add(option));
      dispatch({ type: "moved" });
    }
    setView(null);
  };

  if (view === "qr") return <QrWalk {...props} tokens={summary.tokens} onDone={(walked) => leave("qr", walked)} />;
  if (view === "google") return <GoogleWalk {...props} onDone={(walked) => leave("google", walked)} />;
  if (view === "file") return <FileExport {...props} onDone={(saved) => leave("file", saved)} />;
  if (view === "bitwarden") return <BitwardenFlow {...props} tokens={summary.tokens} onDone={(applied) => leave("bitwarden", applied)} />;

  return (
    <Screen
      title={t.title}
      lede={summary.tokens.length > 0 ? t.lede(summary.tokens.length) : t.none}
      footer={
        <>
          <p className="footer-hint" aria-live="polite">{canLeave ? "" : t.continueBlocked}</p>
          <button type="button" className="primary" disabled={!canLeave} onClick={() => dispatch({ type: "destinationDone" })}>
            {t.continue}
          </button>
        </>
      }
    >
      <Callout tone="warn" title={t.authyTitle}>
        <p>{t.authyBody(deviceLabel(state.device))}</p>
      </Callout>
      {summary.tokens.length > 0 && (
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
      )}
      {cantMove > 0 && (
        <section className="cant-move" aria-labelledby="cant-move-title">
          <h2 id="cant-move-title">{t.cantMoveTitle(cantMove)}</h2>
          <p className="quiet-text">{t.cantMoveLede}</p>
          <ul>
            {summary.native.map((n) => <li key={`native:${n.name}`}>{t.native(n.name)}</li>)}
            {summary.invalid.map((n) => <li key={`invalid:${n.name}`}>{t.invalid(n.name)}</li>)}
          </ul>
        </section>
      )}
    </Screen>
  );
}
