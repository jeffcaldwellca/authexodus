// The shared shape of a failure help panel: what went wrong, then what to try, in order.
import type { ReactNode } from "react";

/** What a panel may need to fill in its wording: the device's name and the live proxy values. */
export type HelpContext = { d: string; ip?: string; port?: number };

export type PanelProps = HelpContext & {
  /** Inside the "Having trouble?" sheet panels fold away; shown on their own they are open. */
  collapsible?: boolean;
  reminder?: boolean;
};

export function Panel({ id, title, body, steps, children, collapsible, reminder }: {
  id: string; title: string; body?: string; steps?: readonly string[]; children?: ReactNode; collapsible?: boolean;
  /** A reminder is calm and announced politely; it does not interrupt like a problem does. */
  reminder?: boolean;
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
    <section className={reminder ? "panel panel-open panel-reminder" : "panel panel-open"} data-failure={id} role={reminder ? "status" : "alert"}>
      <h2>{title}</h2>
      {content}
    </section>
  );
}
