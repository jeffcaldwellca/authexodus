import { en } from "../strings/en";
import { Panel, type PanelProps } from "./Panel";

const t = en.failures.firewall;

/** The Mac's "allow incoming connections" prompt was denied, so the phone cannot reach the app. */
export function Firewall({ d, collapsible }: PanelProps) {
  return <Panel id="firewall" title={t.title} body={t.body(d)} steps={t.steps} collapsible={collapsible} />;
}
