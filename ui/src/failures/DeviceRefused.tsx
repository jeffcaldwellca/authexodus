import type { ReactNode } from "react";
import { en } from "../strings/en";
import { Panel, type PanelProps } from "./Panel";

const t = en.failures.deviceRefused;

/**
 * Another device tried to reach Authy after one was accepted, most often the same phone
 * after its address changed. Shown on `deviceRefused`, with the restart action as children.
 */
export function DeviceRefused({ d, children }: PanelProps & { children?: ReactNode }) {
  return (
    <Panel id="deviceRefused" title={t.title} body={t.body(d)}>
      <p>{t.next(d)}</p>
      {children}
    </Panel>
  );
}
