import type { ReactNode } from "react";
import { en } from "../strings/en";
import { Panel } from "./Panel";

const t = en.failures.bitwardenServer;

/** Bitwarden failed part-way through an apply. Running again is safe. */
export function BitwardenServer({ message, children }: { message: string; children?: ReactNode }) {
  return (
    <Panel id="bitwardenServer" title={t.title} body={t.body}>
      <p className="quiet-text">{t.detail(message)}</p>
      {children}
    </Panel>
  );
}
