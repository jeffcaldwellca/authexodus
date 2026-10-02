import { en } from "../strings/en";

/** How to move one account without this app. The fallback for Android and for a broken method. */
export function ManualGuide() {
  return (
    <div className="manual-guide">
      <h3>{en.manual.title}</h3>
      <ol>{en.manual.steps.map((s) => <li key={s}>{s}</li>)}</ol>
    </div>
  );
}
