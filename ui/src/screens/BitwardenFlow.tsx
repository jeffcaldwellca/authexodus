// The Bitwarden path: prepare (download the official CLI) → sign in → review the matches →
// apply → report. Low-confidence matches are questions the person must answer; nothing is
// decided for them. Every row can be changed to a suggested login, any other login in the
// vault, a new login, or skip. The master password (and an API key, when one is used) stays
// in this component only until Bitwarden accepts the sign-in.
import { useEffect, useRef, useState, type FormEvent } from "react";
import type { ApplyReport, BwApiKey, BwRegion, Decision, Proposal, TokenView, VaultLoginView } from "../api";
import { asApiError, type ApiError } from "../api.errors";
import { Dialog } from "../components/Dialog";
import { Callout, Screen, Waiting } from "../components/ui";
import { BitwardenServer } from "../failures/BitwardenServer";
import { Problem } from "../failures/Problem";
import { onListenFailure } from "../listenFailure";
import { en } from "../strings/en";
import { deviceLabel, type ScreenProps } from "./types";

const t = en.bitwarden;

type Stage = "intro" | "preparing" | "login" | "matching" | "review" | "applying" | "report";
type RegionKind = BwRegion["kind"];
type LoginProblem =
  | { kind: "bad" } | { kind: "badCode" } | { kind: "cancelled" }
  | { kind: "error"; error: ApiError };

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

/** Every login the row could go to already has a code, so none of them can be chosen. */
function onlyTaken(p: Proposal): boolean {
  return proposedHasCode(p) || (p.candidates.length > 0 && p.candidates.every((c) => c.hasCode));
}

/** Rows the person must answer themselves: uncertain matches, and matches that cannot be applied. */
function needsAnswer(p: Proposal): boolean {
  return p.confidence === "low" || proposedHasCode(p);
}

/**
 * Which Bitwarden account a sign-in is to, as the shell tells them apart: the server and the
 * email in lower case. The shell keeps its matches across a new sign-in only to the same one.
 */
function accountOf(region: BwRegion, email: string): string {
  let server: string = region.kind;
  if (region.kind === "selfHosted") {
    const url = region.url.trim();
    try { server = new URL(url).href; } catch { server = url; }
    server = server.replace(/\/+$/, "");
  }
  return `${server}\n${email.toLowerCase()}`;
}

/** A self-hosted server must be a full https address before it is sent anywhere. */
export function validServerUrl(url: string): boolean {
  return /^https:\/\/[^\s/]+\S*$/.test(url.trim());
}

export function BitwardenFlow({ api, state, tokens, onDone, onLocked }: ScreenProps & {
  tokens: TokenView[]; onDone: (applied: boolean) => void; onLocked: () => void;
}) {
  const d = deviceLabel(state.device);
  const [stage, setStage] = useState<Stage>("intro");
  const [prepareError, setPrepareError] = useState<ApiError | null>(null);
  const [prepareCancelled, setPrepareCancelled] = useState(false);
  /** The person pressed Cancel: whatever the pending call answers, it is not acted on. */
  const cancelled = useRef(false);

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [regionKind, setRegionKind] = useState<RegionKind>("us");
  const [serverUrl, setServerUrl] = useState("");
  const [code, setCode] = useState("");
  const [needsCode, setNeedsCode] = useState(false);
  const [withKey, setWithKey] = useState(false);
  /** Bitwarden itself asked for the API key (rather than the person choosing it). */
  const [keyNeeded, setKeyNeeded] = useState(false);
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [loginProblem, setLoginProblem] = useState<LoginProblem | null>(null);
  /** Signed in, but reading or matching the vault failed. Not a sign-in problem. */
  const [vaultError, setVaultError] = useState<ApiError | null>(null);
  /** Bitwarden ended the session. The choices already made are kept for after the new sign-in. */
  const [expired, setExpired] = useState(false);
  const [signedInAgain, setSignedInAgain] = useState(false);
  /** Signed in again to a different account: the suggestions were made afresh for it. */
  const [refreshed, setRefreshed] = useState(false);
  /** The account of the last sign-in that Bitwarden accepted. */
  const signedInAs = useRef<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [showSecret, setShowSecret] = useState(false);
  // While Bitwarden waits for a two-step code, the master password (and the API key, if one
  // was used) has to be sent again with it. They are kept in a ref, out of React state and off
  // the screen, and only for that long: dropped on success, on rejected credentials, on any
  // failure, on cancel, and when this view closes.
  const held = useRef<{ password: string; apiKey?: BwApiKey } | null>(null);
  const [holding, setHolding] = useState(false);
  const codeInput = useRef<HTMLInputElement>(null);
  const emailInput = useRef<HTMLInputElement>(null);
  const dropSecrets = () => {
    held.current = null;
    setHolding(false);
    setPassword("");
    setClientId("");
    setClientSecret("");
  };
  /**
   * Between the password and the API key. What was held for a two-step round trip is dropped
   * with the code, and the key fields start empty: everything is typed again for the new way.
   */
  const switchMethod = () => {
    held.current = null;
    setHolding(false);
    setCode("");
    setNeedsCode(false);
    setLoginProblem(null);
    setClientId("");
    setClientSecret("");
    setWithKey((v) => !v);
    setKeyNeeded(false);
  };
  useEffect(() => () => { held.current = null; }, []);
  useEffect(() => { if (needsCode) codeInput.current?.focus(); }, [needsCode]);

  const [proposals, setProposals] = useState<Proposal[] | null>(null);
  const [choices, setChoices] = useState<Record<string, string>>({});
  /** Logins given to a row by hand, which the shell's suggestions did not include. */
  const [picked, setPicked] = useState<Record<string, VaultLoginView>>({});
  const [logins, setLogins] = useState<VaultLoginView[] | null>(null);
  const [loginsError, setLoginsError] = useState<ApiError | null>(null);
  const [picking, setPicking] = useState<string | null>(null);
  const [progress, setProgress] = useState<string[]>([]);
  /** The window could not listen for progress lines: the work goes on, unseen. */
  const [noProgress, setNoProgress] = useState(false);
  useEffect(() => onListenFailure("bw-progress", () => setNoProgress(true)), []);
  const [report, setReport] = useState<ApplyReport | null>(null);
  const [applyError, setApplyError] = useState<ApiError | null>(null);
  const applied = useRef(false);

  const back = <button type="button" className="quiet" onClick={() => onDone(applied.current)}>{en.destination.backToOptions}</button>;
  const tokenOf = (tokenId: string) => tokens.find((x) => x.id === tokenId);
  const titleOf = (tokenId: string) => tokenOf(tokenId)?.title ?? tokenId;
  /** Collects progress lines for as long as `work` runs: from before it starts until it settles. */
  const withProgress = async <T,>(work: () => Promise<T>): Promise<T> => {
    setProgress([]);
    const off = api.onBwProgress((line) => setProgress((prev) => [...prev, line]));
    try {
      return await work();
    } finally {
      off();
    }
  };
  const cancel = () => {
    cancelled.current = true;
    void api.bwCancel().catch(() => undefined);
  };

  const prepare = async () => {
    cancelled.current = false;
    setStage("preparing");
    setPrepareError(null);
    setPrepareCancelled(false);
    try {
      await withProgress(() => api.bwPrepare());
      if (cancelled.current) { setPrepareCancelled(true); setStage("intro"); } else setStage("login");
    } catch (err) {
      if (cancelled.current) setPrepareCancelled(true); else setPrepareError(asApiError(err));
      setStage("intro");
    }
  };

  /** Back to the sign-in form because the session ended. What was chosen so far is untouched. */
  const signInAgain = () => {
    setExpired(true);
    setSignedInAgain(false);
    setPicking(null);
    setLoginProblem(null);
    setVaultError(null);
    setStage("login");
  };

  const match = async () => {
    setStage("matching");
    setVaultError(null);
    try {
      const found = await api.bwPropose();
      setProposals(found);
      setChoices(Object.fromEntries(found.map((p) => [p.tokenId, needsAnswer(p) ? "" : encode(p.decision)])));
      setPicked({});
      setLogins(null);
      setStage("review");
    } catch (err) {
      const error = asApiError(err);
      if (error.code === "bw_session_expired") setExpired(true); else setVaultError(error);
      setStage("login");
    }
  };

  const signIn = async (e: FormEvent) => {
    e.preventDefault();
    if (busy) return;
    if (regionKind === "selfHosted" && !validServerUrl(serverUrl)) return;
    cancelled.current = false;
    setBusy(true);
    setLoginProblem(null);
    setVaultError(null);
    const region: BwRegion = regionKind === "selfHosted" ? { kind: "selfHosted", url: serverUrl.trim() } : { kind: regionKind };
    const secret = held.current?.password ?? password;
    const apiKey = held.current ? held.current.apiKey : withKey ? { clientId: clientId.trim(), clientSecret: clientSecret.trim() } : undefined;
    const afterTwoStep = () => { setCode(""); setNeedsCode(false); };
    try {
      const result = await api.bwLogin({
        email, password: secret, region,
        ...(needsCode && code !== "" ? { twoFactorCode: code } : {}),
        ...(apiKey ? { apiKey } : {}),
      });
      if (cancelled.current) {
        dropSecrets();
        afterTwoStep();
        setLoginProblem({ kind: "cancelled" });
      } else if (result.kind === "needsTwoFactor" || result.kind === "badTwoFactorCode") {
        held.current = { password: secret, ...(apiKey ? { apiKey } : {}) };
        setHolding(true);
        setPassword("");
        setClientId("");
        setClientSecret("");
        setCode("");
        setNeedsCode(true);
        if (result.kind === "badTwoFactorCode") setLoginProblem({ kind: "badCode" });
        codeInput.current?.focus();
      } else if (result.kind === "badCredentials") {
        dropSecrets();
        afterTwoStep();
        setLoginProblem({ kind: "bad" });
      } else if (result.kind === "needsApiKey") {
        // Bitwarden wants an emailed code or a security key. The password is not kept while
        // the person goes to find their key: all three are typed together on the next try.
        dropSecrets();
        afterTwoStep();
        setWithKey(true);
        setKeyNeeded(true);
      } else {
        dropSecrets();
        afterTwoStep();
        setKeyNeeded(false);
        setBusy(false);
        const account = accountOf(region, email);
        const sameAccount = signedInAs.current === account;
        signedInAs.current = account;
        if (expired && proposals && sameAccount) {
          // The shell kept the matches across the new sign-in, and the choices are still here.
          setExpired(false);
          setSignedInAgain(true);
          setStage("review");
        } else {
          // Another account's vault (another email or server): the shell dropped the old
          // matches, and every choice made from them would be refused. Make them again.
          setRefreshed(expired && proposals !== null);
          setExpired(false);
          await match();
        }
        return;
      }
    } catch (err) {
      dropSecrets();
      afterTwoStep();
      const error = asApiError(err);
      setLoginProblem(cancelled.current ? { kind: "cancelled" } : { kind: "error", error });
      if (!cancelled.current && error.code === "bad_email") emailInput.current?.focus();
    }
    setBusy(false);
  };

  const unanswered = (proposals ?? []).filter((p) => !choices[p.tokenId]).length;
  const urlProblem = regionKind === "selfHosted" && !validServerUrl(serverUrl);

  const apply = async () => {
    const decisions = (proposals ?? []).flatMap((p) => {
      const decision = decode(choices[p.tokenId] ?? "");
      return decision ? [{ tokenId: p.tokenId, decision }] : [];
    });
    if (!proposals || decisions.length !== proposals.length) return;
    setApplyError(null);
    setSignedInAgain(false);
    setRefreshed(false);
    setStage("applying");
    try {
      const result = await withProgress(() => api.bwApply(decisions));
      // Moved means a code is now in Bitwarden: added, created, or found there already.
      if (result.attached + result.created + result.kept.length > 0) applied.current = true;
      setReport(result);
    } catch (err) {
      setReport(null);
      setApplyError(asApiError(err));
    }
    setStage("report");
  };

  const loadLogins = () => {
    setLoginsError(null);
    api.bwLogins().then(setLogins).catch((err: unknown) => {
      const error = asApiError(err);
      if (error.code === "bw_session_expired") signInAgain(); else setLoginsError(error);
    });
  };
  const openPicker = (tokenId: string) => {
    setPicking(tokenId);
    if (logins === null) loadLogins();
  };
  /** The other account a login has already been given to, if any: a login takes one code. */
  const takenBy = (itemId: string, forToken: string): string | null => {
    const other = Object.entries(choices).find(([tokenId, value]) => tokenId !== forToken && value === `attach:${itemId}`);
    return other ? titleOf(other[0]) : null;
  };
  const choose = (tokenId: string, login: VaultLoginView) => {
    setPicked((prev) => ({ ...prev, [tokenId]: login }));
    setChoices((prev) => ({ ...prev, [tokenId]: `attach:${login.itemId}` }));
    setPicking(null);
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
            <span className="footer-group">
              {stage === "preparing" && <button type="button" className="secondary" onClick={cancel}>{en.common.cancel}</button>}
              <button type="button" className="primary" disabled={stage === "preparing"} onClick={() => void prepare()}>{t.prepare}</button>
            </span>
          </>
        }
      >
        <p>{t.introNext}</p>
        <Callout tone="info" title={t.introKeyTitle}><p>{t.introKey}</p></Callout>
        <p className="quiet-text">{en.common.untested(t.name)}</p>
        {stage === "preparing" && (
          <>
            <Waiting>{t.preparing}</Waiting>
            {/* The download reports how far it is many times over: only the latest line is shown. */}
            <p className="progress-log" role="status" aria-label={t.progressLabel}>{progress.at(-1) ?? ""}</p>
            {noProgress && <p className="quiet-text">{t.progressUnavailable}</p>}
          </>
        )}
        {prepareCancelled && <Callout tone="info"><p role="status">{t.prepareCancelled}</p></Callout>}
        {prepareError && <Problem error={prepareError} d={d} title={t.prepareFailed} />}
      </Screen>
    );
  }

  if (stage === "login" || stage === "matching") {
    const emailBad = loginProblem?.kind === "error" && loginProblem.error.code === "bad_email";
    const serverBad = loginProblem?.kind === "error" && loginProblem.error.code === "bad_server_url";
    const missing = email === "" || (!holding && password === "") || (needsCode && code === "")
      || (withKey && !holding && (clientId.trim() === "" || clientSecret.trim() === ""));
    return (
      <Screen
        focusKey={stage}
        title={t.loginTitle}
        lede={t.loginLede}
        footer={
          <>
            {back}
            <span className="footer-group">
              {busy && <button type="button" className="secondary" onClick={cancel}>{en.common.cancel}</button>}
              <button type="submit" form="bw-login" className="primary" disabled={busy || stage === "matching" || missing || urlProblem}>
                {busy ? t.signingIn : t.signIn}
              </button>
            </span>
          </>
        }
      >
        {expired && <Callout tone="warn" title={en.problems.byCode.bw_session_expired.title(d)} alert />}
        {keyNeeded
          ? <Callout tone="warn" alert><p>{t.apiKey.needed}</p></Callout>
          : <Callout tone="info"><p>{t.twoStepLimit}</p></Callout>}
        <form id="bw-login" className="form narrow" onSubmit={signIn} noValidate>
          <label htmlFor="bw-email">{t.email}</label>
          <input ref={emailInput} id="bw-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="off" spellCheck={false} aria-invalid={emailBad} />
          {withKey && !holding && (
            <fieldset className="api-key">
              <legend>{t.apiKey.title}</legend>
              <p className="quiet-text">{t.apiKey.why}</p>
              <p className="quiet-text">{t.apiKey.where}</p>
              <p className="quiet-text">{t.apiKey.once}</p>
              <label htmlFor="bw-client-id">{t.apiKey.clientId}</label>
              <input id="bw-client-id" type="text" value={clientId} onChange={(e) => setClientId(e.target.value)} autoComplete="off" autoCapitalize="none" autoCorrect="off" spellCheck={false} />
              <label htmlFor="bw-client-secret">{t.apiKey.clientSecret}</label>
              <div className="password-row">
                <input id="bw-client-secret" type={showSecret ? "text" : "password"} value={clientSecret} onChange={(e) => setClientSecret(e.target.value)} autoComplete="off" spellCheck={false} />
                <button type="button" className="quiet" aria-pressed={showSecret} onClick={() => setShowSecret((v) => !v)}>{t.apiKey.showSecret}</button>
              </div>
            </fieldset>
          )}
          {holding ? <p className="quiet-text">{t.passwordHeld}</p> : (
            <>
              <label htmlFor="bw-password">{t.password}</label>
              <div className="password-row">
                <input id="bw-password" type={showPassword ? "text" : "password"} value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="off" spellCheck={false} />
                <button type="button" className="quiet" aria-pressed={showPassword} onClick={() => setShowPassword((v) => !v)}>{t.showPassword}</button>
              </div>
            </>
          )}
          {/* Offered while a code is awaited too: Bitwarden asks a new device for an emailed
              code in the same words as for an authenticator app's, and the key is the way past it. */}
          <p>
            <button type="button" className="quiet small" disabled={busy} onClick={switchMethod}>
              {withKey ? t.usePassword : t.useApiKey}
            </button>
          </p>
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
              <input id="bw-url" type="url" value={serverUrl} onChange={(e) => setServerUrl(e.target.value)} aria-describedby="bw-url-hint" aria-invalid={(serverUrl !== "" && urlProblem) || serverBad} spellCheck={false} />
              <p id="bw-url-hint" className={serverUrl !== "" && urlProblem ? "error-text" : "quiet-text"}>
                {serverUrl !== "" && urlProblem ? t.serverUrlInvalid : t.serverUrlHint}
              </p>
            </>
          )}
          {needsCode && (
            <>
              <Callout tone="info" alert><p>{t.needsTwoFactor}</p></Callout>
              <label htmlFor="bw-code">{t.twoFactor}</label>
              <input ref={codeInput} id="bw-code" inputMode="numeric" value={code} onChange={(e) => setCode(e.target.value)} autoComplete="off" />
              {loginProblem?.kind === "badCode" && <Callout tone="error" title={t.wrongTwoFactor} alert />}
            </>
          )}
          {loginProblem?.kind === "bad" && <Callout tone="error" title={withKey ? t.badApiKey : t.badCredentials} alert />}
          {loginProblem?.kind === "cancelled" && <Callout tone="info"><p role="status">{t.loginCancelled}</p></Callout>}
          {loginProblem?.kind === "error" && (loginProblem.error.code === "bw_checksum_mismatch" ? (
            // At sign-in this code means the tool on disk changed since it was checked, not a
            // bad download: getting it again is the cure, not waiting.
            <Problem error={loginProblem.error} d={d} title={t.loginFailed} heading={t.toolChanged.title} advice="">
              <button type="button" className="secondary" onClick={() => { setLoginProblem(null); void prepare(); }}>
                {t.toolChanged.action}
              </button>
            </Problem>
          ) : (
            <Problem error={loginProblem.error} d={d} title={t.loginFailed}>
              {loginProblem.error.code === "internal" && <p>{t.loginFailedAdvice}</p>}
            </Problem>
          ))}
        </form>
        {vaultError && (
          <Problem error={vaultError} d={d} title={t.vaultFailed}>
            {vaultError.code === "not_unlocked"
              ? <button type="button" className="secondary" onClick={onLocked}>{en.common.unlockAgain}</button>
              : <button type="button" className="secondary" onClick={() => void match()}>{en.common.tryAgain}</button>}
          </Problem>
        )}
        {stage === "matching" && <Waiting>{t.matching}</Waiting>}
      </Screen>
    );
  }

  if (stage === "review" && proposals) {
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
        {signedInAgain && <Callout tone="ok"><p role="status">{t.signedInAgain}</p></Callout>}
        {refreshed && <Callout tone="warn"><p role="status">{t.refreshedForOtherAccount}</p></Callout>}
        <table className="matches">
          <thead><tr><th scope="col">{t.colAccount}</th><th scope="col">{t.colAction}</th></tr></thead>
          <tbody>
            {ordered.map((p) => {
              const token = tokenOf(p.tokenId);
              const title = token?.title ?? p.tokenId;
              const value = choices[p.tokenId] ?? "";
              const asking = needsAnswer(p);
              const extra = picked[p.tokenId];
              const options = extra && !p.candidates.some((c) => c.itemId === extra.itemId) ? [...p.candidates, extra] : p.candidates;
              return (
                <tr key={p.tokenId} className={asking && value === "" ? "asking" : ""}>
                  <th scope="row">
                    <span className="account-name">{title}</span>
                    {token?.username && <span className="quiet-text">{token.username}</span>}
                  </th>
                  <td>
                    {asking && <span className="question" id={`q-${p.tokenId}`}>{onlyTaken(p) ? t.questionHasCode : t.question}</span>}
                    <select aria-label={t.actionFor(title)} aria-describedby={asking ? `q-${p.tokenId}` : undefined} value={value} onChange={(e) => setChoices((prev) => ({ ...prev, [p.tokenId]: e.target.value }))}>
                      {value === "" && <option value="" disabled>{t.choose}</option>}
                      {options.map((c) => {
                        // A login holds one code: one that another row has is not offered twice.
                        const other = c.hasCode ? null : takenBy(c.itemId, p.tokenId);
                        return (
                          <option key={c.itemId} value={`attach:${c.itemId}`} disabled={c.hasCode || other !== null}>
                            {c.hasCode ? t.attachHasCode(c.name, c.username)
                              : other !== null ? t.attachTaken(c.name, c.username, other) : t.attach(c.name, c.username)}
                          </option>
                        );
                      })}
                      <option value="createNew">{t.createNew}</option>
                      <option value="skip">{t.skip}</option>
                    </select>
                    <button type="button" className="quiet small" aria-haspopup="dialog" aria-label={t.chooseOtherFor(title)} onClick={() => openPicker(p.tokenId)}>
                      {t.chooseOther}
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {picking !== null && (
          <LoginPicker
            title={titleOf(picking)}
            d={d}
            logins={logins}
            error={loginsError}
            whyNot={(login) => {
              if (login.hasCode) return t.picker.hasCode;
              const other = takenBy(login.itemId, picking);
              return other === null ? null : t.picker.taken(other);
            }}
            onChoose={(login) => choose(picking, login)}
            onRetry={loadLogins}
            onLocked={onLocked}
            onClose={() => setPicking(null)}
          />
        )}
      </Screen>
    );
  }

  if (stage === "applying") {
    return (
      <Screen focusKey={stage} title={t.applyingTitle} footer={<><span /><Waiting>{t.applying}</Waiting></>}>
        {noProgress && <p className="quiet-text">{t.progressUnavailable}</p>}
        <ProgressLog lines={progress} />
      </Screen>
    );
  }

  const sessionEnded = applyError?.code === "bw_session_expired";
  const locked = applyError?.code === "not_unlocked";
  // Stopped part-way: the shell answered with what it had done and why it stopped.
  const partial = report?.failed ?? null;
  return (
    <Screen
      focusKey={stage}
      title={applyError ? t.reportStoppedTitle : partial !== null ? t.reportPartialTitle : t.reportTitle}
      footer={
        <>
          {back}
          {sessionEnded ? <button type="button" className="primary" onClick={signInAgain}>{t.signInAgain}</button>
            : locked ? <button type="button" className="primary" onClick={onLocked}>{en.common.unlockAgain}</button>
            : applyError || partial !== null ? <button type="button" className="primary" onClick={() => void apply()}>{t.runAgain}</button>
            : <button type="button" className="primary" onClick={() => onDone(applied.current)}>{en.common.done}</button>}
        </>
      }
    >
      {/* Refused outright: the shell's sentence says why. The choices may be what needs changing. */}
      {applyError && (
        <Problem error={applyError} d={d} title={t.applyRejected}>
          {!sessionEnded && !locked && (
            <button type="button" className="secondary" onClick={() => setStage("review")}>{t.backToReview}</button>
          )}
        </Problem>
      )}
      {partial !== null && <BitwardenServer message={partial} />}
      {report && (
        <>
          {report.attached + report.created + report.skipped > 0 && (
            <ul className="report">
              {report.attached > 0 && <li>{t.attached(report.attached)}</li>}
              {report.created > 0 && <li>{t.created(report.created)}</li>}
              {report.skipped > 0 && <li>{t.skipped(report.skipped)}</li>}
            </ul>
          )}
          {report.kept.length > 0 && (
            <section className="kept" aria-labelledby="kept-title">
              <h2 id="kept-title">{t.keptTitle}</h2>
              <ul className="report">{report.kept.map((line, i) => <li key={`${i}:${line}`}>{line}</li>)}</ul>
            </section>
          )}
        </>
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

/**
 * Every login in the vault, to give a code to one the app did not suggest. A login that
 * already has a code, or that another row has been given, is listed but cannot be chosen.
 */
function LoginPicker({ title, d, logins, error, whyNot, onChoose, onRetry, onLocked, onClose }: {
  title: string;
  d: string;
  logins: VaultLoginView[] | null;
  error: ApiError | null;
  /** Why a login cannot be chosen, in words, or null when it can. */
  whyNot: (login: VaultLoginView) => string | null;
  onChoose: (login: VaultLoginView) => void;
  onRetry: () => void;
  onLocked: () => void;
  onClose: () => void;
}) {
  const [query, setQuery] = useState("");
  const wanted = query.trim().toLowerCase();
  const shown = logins?.filter((l) => `${l.name} ${l.username ?? ""}`.toLowerCase().includes(wanted)) ?? null;
  return (
    <Dialog title={t.picker.title(title)} variant="sheet" onClose={onClose}>
      <p className="quiet-text">{t.picker.lede}</p>
      <div className="form">
        <label htmlFor="bw-login-search">{t.picker.search}</label>
        <input id="bw-login-search" type="text" value={query} onChange={(e) => setQuery(e.target.value)} autoComplete="off" spellCheck={false} />
      </div>
      {error && (
        <Problem error={error} d={d} title={t.vaultFailed}>
          {error.code === "not_unlocked"
            ? <button type="button" className="secondary" onClick={onLocked}>{en.common.unlockAgain}</button>
            : <button type="button" className="secondary" onClick={onRetry}>{en.common.tryAgain}</button>}
        </Problem>
      )}
      {shown === null && !error && <Waiting>{t.picker.loading}</Waiting>}
      {shown !== null && (
        <>
          <p className="quiet-text" aria-live="polite">{shown.length === 0 ? t.picker.noMatch : t.picker.count(shown.length)}</p>
          <ul className="login-list" aria-label={t.picker.listLabel}>
            {shown.map((login) => {
              const why = whyNot(login);
              return (
                <li key={login.itemId}>
                  <button type="button" className="login-choice" disabled={why !== null} onClick={() => onChoose(login)}>
                    <span className="account-name">{login.name}</span>
                    {login.username && <span className="quiet-text">{login.username}</span>}
                    {why !== null && <span className="tag">{why}</span>}
                  </button>
                </li>
              );
            })}
          </ul>
        </>
      )}
    </Dialog>
  );
}
