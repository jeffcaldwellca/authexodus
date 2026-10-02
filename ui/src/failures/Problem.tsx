// A command the shell rejected. The title is chosen from the shell's code, or is the screen's
// own when the code covers too much to name. The shell's own sentence is shown under it, as
// the detail, then anything the screen can add. Children are the actions.
import type { ReactNode } from "react";
import type { ApiError } from "../api.errors";
import { Callout } from "../components/ui";
import { en } from "../strings/en";

/** The shell could not put the certificate's key into the Keychain, or take it out again. */
export function aboutKeychain(error: ApiError): boolean {
  return error.code === "keychain_failed" || error.code === "cleanup_keychain_failed";
}

/**
 * How to remove the Keychain item by hand, for the two Keychain codes. The person must
 * always be shown this, so the screen says it itself unless the shell's sentence already has.
 */
export function keychainRoute(error: ApiError): string | null {
  return aboutKeychain(error) && !/Keychain Access/.test(error.message) ? en.problems.keychainByHand : null;
}

export function Problem({ error, d, title, children }: {
  error: ApiError;
  /** The device's name, for sentences that mention it. */
  d: string;
  /** What the screen was trying to do, in its own words. Used when the code has no title of its own. */
  title: string;
  children?: ReactNode;
}) {
  const known = en.problems.byCode[error.code];
  const advice = known.advice(d);
  const sentence = error.message.trim();
  const unexplained = error.code === "internal";
  const route = keychainRoute(error);
  return (
    <Callout tone="error" title={known.title(d) || title} alert>
      {sentence !== "" && <p data-shell-sentence>{unexplained ? en.problems.reason(sentence) : sentence}</p>}
      {advice !== "" && <p>{advice}</p>}
      {route !== null && <p>{route}</p>}
      {children}
    </Callout>
  );
}
