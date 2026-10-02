import { en } from "../strings/en";
import { Panel, type PanelProps } from "./Panel";

const t = en.failures.trust;

/** The certificate is installed but full trust is not switched on. Shown as a calm reminder on `tlsRejected`. */
export function Trust({ d, collapsible, reminder }: PanelProps) {
  return <Panel id="trust" title={t.title} body={t.body(d)} steps={t.steps} collapsible={collapsible} reminder={reminder} />;
}
