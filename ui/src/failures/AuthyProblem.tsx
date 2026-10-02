import { en } from "../strings/en";
import { Panel, type PanelProps } from "./Panel";

const t = en.failures.attestation;

/**
 * Authy answered one of its own requests with an error. Shown on `authyError`, which the
 * proxy raises for any 4xx or 5xx, so the panel is titled by what the person sees and only
 * offers the "attestation token" workaround as a possibility. A server error (5xx) cannot be
 * that refusal, so there the workaround is left out. Without a status (the help sheet) the
 * workaround is shown.
 */
export function AuthyProblem({ ip, port, status, collapsible }: PanelProps & { status?: number }) {
  const mayBeAttestation = status === undefined || status < 500;
  const steps = ip !== undefined && port !== undefined ? t.steps(ip, port) : t.stepsNoAddress;
  return (
    <Panel id="authyProblem" title={t.title} body={t.body} collapsible={collapsible}>
      {mayBeAttestation && (
        <>
          <p>{t.ifAttestation}</p>
          <ol>{steps.map((s) => <li key={s}>{s}</li>)}</ol>
        </>
      )}
    </Panel>
  );
}
