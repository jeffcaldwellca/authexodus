// The "Having trouble?" control on each waiting step. It opens a sheet holding the help
// panels that fit that step, a way to start the connection over, and a way to stop.
import { useEffect, useRef, useState, type ReactNode } from "react";
import { Dialog } from "../components/Dialog";
import { en } from "../strings/en";
import { StopConfirm } from "./StopConfirm";

const t = en.failures;

export function Trouble({ children, d, mentionAuthy, onAbandon, onRestart }: {
  children: ReactNode;
  d: string;
  /** See `StopConfirm`. */
  mentionAuthy: boolean;
  onAbandon: () => void;
  onRestart: () => void;
}) {
  const [mode, setMode] = useState<"closed" | "sheet" | "confirm">("closed");
  const opener = useRef<HTMLButtonElement>(null);
  const wasOpen = useRef(false);

  // The confirm box replaces the sheet, so the sheet's own focus-return has nowhere to go.
  useEffect(() => {
    if (mode === "closed" && wasOpen.current) opener.current?.focus();
    wasOpen.current = mode !== "closed";
  }, [mode]);

  return (
    <>
      <button ref={opener} type="button" className="quiet" aria-haspopup="dialog" onClick={() => setMode("sheet")}>
        {en.common.havingTrouble}
      </button>
      {mode === "sheet" && (
        <Dialog title={t.sheetTitle} variant="sheet" onClose={() => setMode("closed")}>
          <p className="quiet-text">{t.sheetLede}</p>
          {children}
          <section className="sheet-foot">
            <h3>{t.restart.title}</h3>
            <p>{t.restart.body(d)}</p>
            <p className="quiet-text">{t.restart.lost}</p>
            <button type="button" className="secondary" onClick={() => { setMode("closed"); onRestart(); }}>
              {en.common.restart}
            </button>
          </section>
          <p className="sheet-foot">
            <button type="button" className="quiet danger" onClick={() => setMode("confirm")}>{en.common.stopAndCleanUp}</button>
          </p>
        </Dialog>
      )}
      {mode === "confirm" && (
        <StopConfirm d={d} mentionAuthy={mentionAuthy} onCancel={() => setMode("closed")} onConfirm={() => { setMode("closed"); onAbandon(); }} />
      )}
    </>
  );
}
