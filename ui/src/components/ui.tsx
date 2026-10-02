// Small shared pieces of the wizard's chrome. No wording lives here: text arrives as props.
import { useEffect, useRef, useState, type ReactNode } from "react";
import { en } from "../strings/en";

/** One wizard screen: a heading that takes focus when the screen appears, a body, and a footer bar. */
export function Screen({ title, lede, children, footer, status }: {
  title: string; lede?: ReactNode; children: ReactNode; footer?: ReactNode; status?: ReactNode;
}) {
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => { heading.current?.focus(); }, []);
  return (
    <>
      <div className="screen-body">
        {status}
        <h1 ref={heading} tabIndex={-1}>{title}</h1>
        {lede && <p className="lede">{lede}</p>}
        {children}
      </div>
      {footer && <div className="screen-footer">{footer}</div>}
    </>
  );
}

export function Callout({ tone, title, children, alert }: {
  tone: "info" | "warn" | "error" | "ok"; title?: string; children?: ReactNode; alert?: boolean;
}) {
  return (
    <div className={`callout callout-${tone}`} role={alert ? "alert" : undefined}>
      {title && <p className="callout-title">{title}</p>}
      {children}
    </div>
  );
}

/** A polite live region with a spinner, for steps the app is waiting on. */
export function Waiting({ children }: { children: ReactNode }) {
  return (
    <p className="waiting" role="status">
      <span className="spinner" aria-hidden="true" />
      <span>{children}</span>
    </p>
  );
}

/**
 * A QR code handed over by the core as an SVG string. It is shown through an `<img>` data URI
 * rather than injected into the page, so nothing inside the SVG can run or reach the document.
 */
export function QrImage({ svg, alt, size = 220 }: { svg: string; alt: string; size?: number }) {
  return (
    <span className="qr" style={{ width: size, height: size }}>
      <img src={`data:image/svg+xml;utf8,${encodeURIComponent(svg)}`} alt={alt} width={size - 20} height={size - 20} />
    </span>
  );
}

export type GuideStep = { id: string; text: ReactNode; art?: ReactNode; important?: boolean };

/**
 * Numbered instructions beside a picture. Choosing a step shows its picture. The written steps
 * are always all visible, so they stand in for the pictures for anyone who cannot see them.
 */
export function Guide({ steps, initial }: { steps: GuideStep[]; initial?: string }) {
  const withArt = steps.filter((s) => s.art);
  const [activeId, setActiveId] = useState(initial ?? withArt[0]?.id);
  const index = Math.max(0, withArt.findIndex((s) => s.id === activeId));
  const active = withArt[index];
  const go = (delta: number) => {
    const next = withArt[index + delta];
    if (next) setActiveId(next.id);
  };
  return (
    <div className="guide">
      <ol className="guide-steps">
        {steps.map((s) => (
          <li key={s.id} className={`${s.important ? "important" : ""} ${active?.id === s.id ? "active" : ""}`}>
            {s.art ? (
              <button type="button" className="guide-step" aria-pressed={active?.id === s.id} onClick={() => setActiveId(s.id)}>
                {s.text}
              </button>
            ) : <div className="guide-step">{s.text}</div>}
          </li>
        ))}
      </ol>
      {active && (
        <div className="guide-art">
          <div className="guide-figure">{active.art}</div>
          {withArt.length > 1 && (
            <div className="guide-pager">
              <button type="button" className="quiet" onClick={() => go(-1)} disabled={index === 0}>{en.common.previous}</button>
              <span aria-live="polite">{en.common.pictureOf(index + 1, withArt.length)}</span>
              <button type="button" className="quiet" onClick={() => go(1)} disabled={index === withArt.length - 1}>{en.common.next}</button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/** A labelled tick box whose label can carry a second, quieter line. */
export function Tick({ checked, onChange, label, detail, extra }: {
  checked: boolean; onChange: (value: boolean) => void; label: string; detail?: string; extra?: ReactNode;
}) {
  return (
    <div className={`tick ${checked ? "ticked" : ""}`}>
      <label>
        <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} />
        <span>
          <span className="tick-label">{label}</span>
          {detail && <span className="tick-detail">{detail}</span>}
        </span>
      </label>
      {extra && <div className="tick-extra">{extra}</div>}
    </div>
  );
}
