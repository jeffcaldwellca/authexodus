import { en } from "../strings/en";
import { Panel, type PanelProps } from "./Panel";

const t = en.failures.vpn;

/** A VPN or iCloud Private Relay on the phone routes traffic around the proxy. */
export function Vpn({ d, collapsible }: PanelProps) {
  return <Panel id="vpn" title={t.title(d)} body={t.body} steps={t.steps} collapsible={collapsible} />;
}
