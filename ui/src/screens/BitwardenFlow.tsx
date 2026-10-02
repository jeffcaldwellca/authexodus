// The Bitwarden path: prepare (download the official CLI) → sign in → review the matches →
// apply → report. Low-confidence matches are questions the person must answer; nothing is
// decided for them. Every row can be changed to a specific login, a new login, or skip.
// The master password stays in this component only until Bitwarden accepts the sign-in.
import { useEffect, useRef, useState, type FormEvent } from "react";
import type { ApplyReport, BwRegion, Decision, Proposal, TokenView } from "../api";
import { Callout, Screen, Waiting } from "../components/ui";
import { BitwardenServer } from "../failures/BitwardenServer";
import { en } from "../strings/en";
import type { ScreenProps } from "./types";

const t = en.bitwarden;

type Stage = "intro" | "preparing" | "login" | "matching" | "review" | "applying" | "report";
type RegionKind = BwRegion["kind"];

/** A decision as a `<select>` value. The empty string means "not chosen yet". */
function encode(d: Decision): string {
  return d.kind === "attach" ? `attach:${d.itemId}` : d.kind;
}
function decode(value: string): Decision | null {
  if (value === "createNew") return { kind: "createNew" };
  if (value === "skip") return { kind: "skip" };
  if (value.startsWith("attach:")) return { kind: "attach", itemId: value.slice("attach:".length) };
  return null;
}

/** The login the proposal would attach to already holds a code, which is never replaced. */
function proposedHasCode(p: Proposal): boolean {
  const d = p.decision;
  return d.kind === "attach" && p.candidates.some((c) => c.itemId === d.itemId && c.hasCode);
}

/** Rows the person must answer themselves: uncertain matches, and matches that cannot be applied. */
function needsAnswer(p: Proposal): boolean {
  return p.confidence === "low" || proposedHasCode(p);
}

/** A self-hosted server must be a full https address before it is sent anywhere. */
export function validServerUrl(url: string): boolean {
  return /^https:\/\/[^\s/]+\S*$/.test(url.trim());
}

export function BitwardenFlow({ api, tokens, onDone }: ScreenProps & { tokens: TokenView[]; onDone: (applied: boolean) => void }) {
  const [stage, setStage] = useState<Stage>("intro");
  const [prepareFailed, setPrepareFailed] = useState(false);

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [regionKind, setRegionKind] = useState<RegionKind>("us");
  const [serverUrl, setServerUrl] = useState("");
  const [code, setCode] = useState("");
  const [needsCode, setNeedsCode] = useState(false);
  const [loginProblem, setLoginProblem] = useState<"bad" | "failed" | null>(null);
  const [busy, setBusy] = useState(false);

  const [proposals, setProposals] = useState<Proposal[]>([]);
  const [choices, setChoices] = useState<Record<string, string>>({});
  const [progress, setProgress] = useState<string[]>([]);
  const [report, setReport] = useState<ApplyReport | null>(null);
  const [applyError, setApplyError] = useState<string | null>(null);
  const applied = useRef(false);

  // Progress lines only matter while an apply is running.
  useEffect(() => {
    if (stage !== "applying") return;
    return api.onBwProgress((line) => setProgress((prev) => [...prev, line]));
  }, [api, stage]);

  const back = <button type="button" className="quiet" onClick={() => onDone(applied.current)}>{en.destination.backToOptions}</button>;
  const titleOf = (tokenId: string) => tokens.find((x) => x.id === tokenId);

  const prepare = async () => {
    setStage("preparing");
    setPrepareFailed(false);
    try {
      await api.bwPrepare();
      setStage("login");
    } catch {
      setPrepareFailed(true);
      setStage("intro");
    }
  };

  const match = async () => {
    setStage("matching");
    try {
      const found = await api.bwPropose();
      setProposals(found);
      setChoices(Object.fromEntries(found.map((p) => [p.tokenId, needsAnswer(p) ? "" : encode(p.decision)])));
      setStage("review");
    } catch {
      setLoginProblem("failed");
      setStage("login");
    }
  };

  const signIn = async (e: FormEvent) => {
    e.preventDefault();
    if (busy) return;
    setBusy(true);
    setLoginProblem(null);
    if (regionKind === "selfHosted" && !validServerUrl(serverUrl)) { setBusy(false); return; }
    const region: BwRegion = regionKind === "selfHosted" ? { kind: "selfHosted", url: serverUrl.trim() } : { kind: regionKind };
    try {
      const result = await api.bwLogin({ email, password, region, ...(needsCode && code !== "" ? { twoFactorCode: code } : {}) });
      if (result.kind === "needsTwoFactor") {
        setNeedsCode(true);
      } else if (result.kind === "badCredentials") {
        setLoginProblem("bad");
      } else {
        setPassword("");
        setCode("");
        setNeedsCode(false);
        setBusy(false);
        await match();
        return;
      }
    } catch {
      setLoginProblem("failed");
    }
    setBusy(false);
  };

  const unanswered = proposals.filter((p) => !choices[p.tokenId]).length;
  const urlProblem = regionKind === "selfHosted" && !validServerUrl(serverUrl);

  const apply = async () => {
    const decisions = proposals.flatMap((p) => {
      const decision = decode(choices[p.tokenId] ?? "");
      return decision ? [{ tokenId: p.tokenId, decision }] : [];
    });
    if (decisions.length !== proposals.length) return;
    setProgress([]);
    setApplyError(null);
    setStage("applying");
    try {
      const result = await api.bwApply(decisions);
      applied.current = true;
      setReport(result);
    } catch (err) {
      setReport(null);
      setApplyError(err instanceof Error ? err.message : String(err));
    }
    setStage("report");
  };

  if (stage === "intro" || stage === "preparing") {
    return (
      <Screen
        focusKey={stage}
        title={t.introTitle}
        lede={t.introBody}
        footer={
          <>
            {back}
            <button type="button" className="primary" disabled={stage === "preparing"} onClick={() => void prepare()}>{t.prepare}</button>
          </>
        }
      >
        <p>{t.introNext}</p>
        {stage === "preparing" && <Waiting>{t.preparing}</Waiting>}
        {prepareFailed && <Callout tone="error" title={t.prepareFailed} alert />}
      </Screen>
    );
  }

  if (stage === "login" || stage === "matching") {
    return (
      <Screen
        focusKey={stage}
        title={t.loginTitle}
        lede={t.loginLede}
        footer={
          <>
            {back}
            <button type="submit" form="bw-login" className="primary" disabled={busy || stage === "matching" || email === "" || password === "" || urlProblem}>
              {busy ? t.signingIn : t.signIn}
            </button>
          </>
        }
      >
        <form id="bw-login" className="form narrow" onSubmit={signIn} noValidate>
          <label htmlFor="bw-email">{t.email}</label>
          <input id="bw-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="off" spellCheck={false} />
          <label htmlFor="bw-password">{t.password}</label>
          <input id="bw-password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="off" />
          <fieldset className="segmented">
            <legend>{t.region}</legend>
            <div className="segments">
              {(["us", "eu", "selfHosted"] as const).map((kind) => (
                <label key={kind} className={regionKind === kind ? "selected" : ""}>
                  <input type="radio" name="bw-region" checked={regionKind === kind} onChange={() => setRegionKind(kind)} />
                  <span>{t.regions[kind]}</span>
                </label>
              ))}
            </div>
          </fieldset>
          {regionKind === "selfHosted" && (
            <>
              <label htmlFor="bw-url">{t.serverUrl}</label>
              <input id="bw-url" type="url" value={serverUrl} onChange={(e) => setServerUrl(e.target.value)} aria-describedby="bw-url-hint" aria-invalid={serverUrl !== "" && urlProblem} spellCheck={false} />
              <p id="bw-url-hint" className={serverUrl !== "" && urlProblem ? "error-text" : "quiet-text"}>
                {serverUrl !== "" && urlProblem ? t.serverUrlInvalid : t.serverUrlHint}
              </p>
            </>
          )}
          {needsCode && (
            <>
              <Callout tone="info" alert><p>{t.needsTwoFactor}</p></Callout>
              <label htmlFor="bw-code">{t.twoFactor}</label>
              <input id="bw-code" inputMode="numeric" value={code} onChange={(e) => setCode(e.target.value)} autoComplete="off" />
            </>
          )}
          {loginProblem === "bad" && <Callout tone="error" title={t.badCredentials} alert />}
          {loginProblem === "failed" && <Callout tone="error" title={t.loginFailed} alert />}
        </form>
        {stage === "matching" && <Waiting>{t.matching}</Waiting>}
      </Screen>
    );
  }

  if (stage === "review") {
    const ordered = [...proposals].sort((a, b) => Number(!needsAnswer(a)) - Number(!needsAnswer(b)));
    return (
      <Screen
        focusKey={stage}
        title={t.reviewTitle}
        lede={t.reviewLede}
        footer={
          <>
            {back}
            <p className="footer-hint" aria-live="polite">{unanswered > 0 ? t.needChoice(unanswered) : ""}</p>
            <button type="button" className="primary" disabled={unanswered > 0} onClick={() => void apply()}>{t.apply}</button>
          </>
        }
      >
        <table className="matches">
          <thead><tr><th scope="col">{t.colAccount}</th><th scope="col">{t.colAction}</th></tr></thead>
          <tbody>
            {ordered.map((p) => {
              const token = titleOf(p.tokenId);
              const title = token?.title ?? p.tokenId;
              const value = choices[p.tokenId] ?? "";
              const asking = needsAnswer(p);
              return (
                <tr key={p.tokenId} className={asking && value === "" ? "asking" : ""}>
                  <th scope="row">
                    <span className="account-name">{title}</span>
                    {token?.username && <span className="quiet-text">{token.username}</span>}
                  </th>
                  <td>
                    {asking && <span className="question">{p.confidence === "low" ? t.question : t.questionHasCode}</span>}
                    <select aria-label={t.actionFor(title)} value={value} onChange={(e) => setChoices((prev) => ({ ...prev, [p.tokenId]: e.target.value }))}>
                      {value === "" && <option value="" disabled>{t.choose}</option>}
                      {p.candidates.map((c) => (
                        <option key={c.itemId} value={`attach:${c.itemId}`} disabled={c.hasCode}>
                          {c.hasCode ? t.attachHasCode(c.name, c.username) : t.attach(c.name, c.username)}
                        </option>
                      ))}
                      <option value="createNew">{t.createNew}</option>
                      <option value="skip">{t.skip}</option>
                    </select>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </Screen>
    );
  }

  if (stage === "applying") {
    return (
      <Screen focusKey={stage} title={t.applyingTitle} footer={<><span /><Waiting>{t.applying}</Waiting></>}>
        <ProgressLog lines={progress} />
      </Screen>
    );
  }

  const failed = applyError ?? report?.failed ?? null;
  return (
    <Screen
      focusKey={stage}
      title={failed ? t.reportPartialTitle : t.reportTitle}
      footer={
        <>
          {back}
          {failed
            ? <button type="button" className="primary" onClick={() => void apply()}>{t.runAgain}</button>
            : <button type="button" className="primary" onClick={() => onDone(true)}>{en.common.done}</button>}
        </>
      }
    >
      {failed && <BitwardenServer message={failed} />}
      {report && (
        <ul className="report">
          {report.attached > 0 && <li>{t.attached(report.attached)}</li>}
          {report.created > 0 && <li>{t.created(report.created)}</li>}
          {report.skipped > 0 && <li>{t.skipped(report.skipped)}</li>}
          {report.kept.length > 0 && <li>{t.kept(report.kept)}</li>}
        </ul>
      )}
      <ProgressLog lines={progress} />
    </Screen>
  );
}

function ProgressLog({ lines }: { lines: string[] }) {
  return (
    <ol className="progress-log" role="log" aria-live="polite" aria-label={t.progressLabel}>
      {lines.map((line, i) => <li key={i}>{line}</li>)}
    </ol>
  );
}
