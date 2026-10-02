import { en } from "../strings/en";
import { Panel, type PanelProps } from "./Panel";

const t = en.failures.wifi;

/** The phone is on a different network, or on one that keeps devices apart (guest, hotel). */
export function Wifi({ d, ip, port, collapsible }: PanelProps) {
  const steps = ip !== undefined && port !== undefined ? t.steps(d, ip, port) : t.stepsNoAddress(d);
  return <Panel id="wifi" title={t.title} body={t.body(d)} steps={steps} collapsible={collapsible} />;
}
