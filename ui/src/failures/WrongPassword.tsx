import { en } from "../strings/en";
import { Panel, type PanelProps } from "./Panel";

const t = en.failures.wrongPassword;

/** The backup password did not unlock the codes. Always shown inline, beside the field. */
export function WrongPassword({ d }: PanelProps) {
  return (
    <Panel id="wrongPassword" title={t.title} body={t.body(d)}>
      <p>{t.kept}</p>
    </Panel>
  );
}
