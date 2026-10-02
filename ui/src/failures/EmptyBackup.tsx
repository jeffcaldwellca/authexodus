import type { ReactNode } from "react";
import { en } from "../strings/en";
import { Panel, type PanelProps } from "./Panel";

const t = en.failures.emptyBackup;

/**
 * Authy signed in and answered with no accounts at all, which is what an account with
 * backups switched off looks like. Says how to switch them on, with the restart as children.
 */
export function EmptyBackup({ d, collapsible, children }: PanelProps & { children?: ReactNode }) {
  return (
    <Panel id="emptyBackup" title={t.title} body={t.body} steps={t.steps(d)} collapsible={collapsible}>
      <p>{t.nowhere}</p>
      {children}
    </Panel>
  );
}
