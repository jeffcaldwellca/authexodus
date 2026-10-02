import type { ReactNode } from "react";
import { en } from "../strings/en";
import { ManualGuide } from "./ManualGuide";
import { Panel, type PanelProps } from "./Panel";

const t = en.failures.methodBroken;

/**
 * Trust was proven by the check page, yet Authy still refuses the connection: Authy has
 * changed and the method no longer works. Says so plainly and gives the manual route.
 */
export function MethodBroken({ collapsible, children }: PanelProps & { children?: ReactNode }) {
  return (
    <Panel id="methodBroken" title={t.title} body={t.body} collapsible={collapsible}>
      <p>{t.next}</p>
      <ManualGuide />
      {children}
    </Panel>
  );
}
