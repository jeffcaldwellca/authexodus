// The "Having trouble?" control on each waiting step. It opens a sheet holding the help
// panels that fit that step.
import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { en } from "../strings/en";

export function Trouble({ children, onAbandon }: { children: ReactNode; onAbandon?: () => void }) {
  const [open, setOpen] = useState(false);
  const opener = useRef<HTMLButtonElement>(null);
  const sheet = useRef<HTMLDivElement>(null);
  const titleId = useId();

  useEffect(() => {
    if (!open) return;
    sheet.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { setOpen(false); return; }
      if (e.key !== "Tab" || !sheet.current) return;
      // Keep Tab inside the sheet while it is open.
      const items = sheet.current.querySelectorAll<HTMLElement>("button, summary, a[href], input, select");
      const first = items[0];
      const last = items[items.length - 1];
      if (!first || !last) return;
      if (e.shiftKey && (document.activeElement === first || document.activeElement === sheet.current)) {
        e.preventDefault(); last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault(); first.focus();
      }
    };
    document.addEventListener("keydown", onKey);
    const openerEl = opener.current;
    return () => { document.removeEventListener("keydown", onKey); openerEl?.focus(); };
  }, [open]);

  return (
    <>
      <button ref={opener} type="button" className="quiet" aria-haspopup="dialog" onClick={() => setOpen(true)}>
        {en.common.havingTrouble}
      </button>
      {open && (
        <div className="sheet-backdrop" onClick={(e) => { if (e.target === e.currentTarget) setOpen(false); }}>
          <div ref={sheet} className="sheet" role="dialog" aria-modal="true" aria-labelledby={titleId} tabIndex={-1}>
            <div className="sheet-head">
              <h2 id={titleId}>{en.failures.sheetTitle}</h2>
              <button type="button" className="quiet" onClick={() => setOpen(false)}>{en.common.close}</button>
            </div>
            <p className="quiet-text">{en.failures.sheetLede}</p>
            {children}
            {onAbandon && (
              <p className="sheet-foot">
                <button type="button" className="quiet danger" onClick={() => { setOpen(false); onAbandon(); }}>
                  {en.common.stopAndCleanUp}
                </button>
              </p>
            )}
          </div>
        </div>
      )}
    </>
  );
}
