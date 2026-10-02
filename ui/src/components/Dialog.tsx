// A modal dialog: takes focus when it opens, keeps Tab inside, closes on Escape, and gives
// focus back to where it was when it closes.
import { useEffect, useId, useRef, type ReactNode } from "react";
import { en } from "../strings/en";

export function Dialog({ title, onClose, children, variant, urgent }: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  /** A sheet slides in from the side for reading; a box sits in the middle for a decision. */
  variant: "sheet" | "box";
  /** An urgent dialog asks for a decision and is announced as an alert. */
  urgent?: boolean;
}) {
  const root = useRef<HTMLDivElement>(null);
  const titleId = useId();
  const close = useRef(onClose);
  close.current = onClose;

  useEffect(() => {
    const before = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    root.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { close.current(); return; }
      if (e.key !== "Tab" || !root.current) return;
      const items = root.current.querySelectorAll<HTMLElement>("button:not(:disabled), summary, a[href], input, select");
      const first = items[0];
      const last = items[items.length - 1];
      if (!first || !last) return;
      if (e.shiftKey && (document.activeElement === first || document.activeElement === root.current)) {
        e.preventDefault(); last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault(); first.focus();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      if (before?.isConnected) before.focus();
    };
  }, []);

  return (
    <div className={`backdrop backdrop-${variant}`} onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div ref={root} className={variant} role={urgent ? "alertdialog" : "dialog"} aria-modal="true" aria-labelledby={titleId} tabIndex={-1}>
        <div className="dialog-head">
          <h2 id={titleId}>{title}</h2>
          {variant === "sheet" && <button type="button" className="quiet" onClick={onClose}>{en.common.close}</button>}
        </div>
        {children}
      </div>
    </div>
  );
}
