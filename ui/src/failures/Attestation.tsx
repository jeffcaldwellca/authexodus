import { en } from "../strings/en";
import { Panel, type PanelProps } from "./Panel";

const t = en.failures.attestation;

/** Authy's "attestation token" error. Shown on `authyError`. */
export function Attestation({ ip, port, collapsible }: PanelProps) {
  const steps = ip !== undefined && port !== undefined ? t.steps(ip, port) : t.stepsNoAddress;
  return <Panel id="attestation" title={t.title} body={t.body} steps={steps} collapsible={collapsible} />;
}
