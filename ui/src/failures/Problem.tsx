// A command the shell rejected. The title is chosen from the shell's code, or is the screen's
// own when the code covers too much to name. The shell's own sentence is shown under it, as
// the detail, then anything the screen can add. Children are the actions.
import type { ReactNode } from "react";
import type { ApiError } from "../api.errors";
import { Callout } from "../components/ui";
import { en } from "../strings/en";

export function Problem({ error, d, title, heading, advice: ownAdvice, children }: {
  error: ApiError;
  /** The device's name, for sentences that mention it. */
  d: string;
  /** What the screen was trying to do, in its own words. Used when the code has no title of its own. */
  title: string;
  /** Replaces the code's own title, where the same code means something else on this screen. */
  heading?: string;
  /** Replaces the code's own advice, for the same reason. Empty means none. */
  advice?: string;
  children?: ReactNode;
}) {
  const known = en.problems.byCode[error.code];
  const advice = ownAdvice ?? known.advice(d);
  // The shell's own sentence. A rejection that came without one (Tauri's own, or this UI's
  // fault) has none, and gets a fixed plain sentence: its raw text is never shown.
  const sentence = error.message.trim() || (error.code === "internal" ? en.problems.unexplained : "");
  return (
    <Callout tone="error" title={heading ?? (known.title(d) || title)} alert>
      {sentence !== "" && <p data-shell-sentence>{sentence}</p>}
      {advice !== "" && <p>{advice}</p>}
      {children}
    </Callout>
  );
}
