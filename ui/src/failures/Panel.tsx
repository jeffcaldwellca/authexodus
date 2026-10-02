// The shared shape of a failure help panel: what went wrong, then what to try, in order.
import type { ReactNode } from "react";

/** What a panel may need to fill in its wording: the device's name and the live proxy values. */
export type HelpContext = { d: string; ip?: string; port?: number };

export type PanelProps = HelpContext & {
  /** Inside the "Having trouble?" sheet panels fold away; shown on their own they are open. */
  collapsible?: boolean;
};

export function Panel({ id, title, body, steps, children, collapsible }: {
  id: string; title: string; body?: string; steps?: readonly string[]; children?: ReactNode; collapsible?: boolean;
}) {
  const content = (
    <>
      {body && <p>{body}</p>}
      {steps && <ol>{steps.map((s) => <li key={s}>{s}</li>)}</ol>}
      {children}
    </>
  );
  if (collapsible) {
    return (
      <details className="panel" data-failure={id}>
        <summary>{title}</summary>
        <div className="panel-content">{content}</div>
      </details>
    );
  }
  return (
    <section className="panel panel-open" data-failure={id} role="alert">
      <h2>{title}</h2>
      {content}
    </section>
  );
}
