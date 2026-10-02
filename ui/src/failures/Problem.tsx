// A command the shell rejected. The title and the advice are chosen from the shell's code;
// the shell's own sentence is shown between them, as the detail. Children are the actions.
import type { ReactNode } from "react";
import type { ApiError } from "../api.errors";
import { Callout } from "../components/ui";
import { en } from "../strings/en";

export function Problem({ error, d, title, children }: {
  error: ApiError;
  /** The device's name, for sentences that mention it. */
  d: string;
  /** What failed, in the screen's own words. Used when the shell gave no code of its own. */
  title?: string;
  children?: ReactNode;
}) {
  const known = en.problems.byCode[error.code];
  const advice = known.advice(d);
  const sentence = error.message.trim();
  const unexplained = error.code === "internal";
  return (
    <Callout tone="error" title={unexplained && title ? title : known.title(d)} alert>
      {sentence !== "" && <p data-shell-sentence>{unexplained ? en.problems.reason(sentence) : sentence}</p>}
      {advice !== "" && <p>{advice}</p>}
      {children}
    </Callout>
  );
}
