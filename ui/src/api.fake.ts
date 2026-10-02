// In-memory fake of the `Api` contract. UI tests script it, and `pnpm -C ui dev` runs the whole
// wizard against it in a plain browser. Nothing here is real: the names are invented, the QR
// codes are patterns that scan to nothing, and the "live codes" are arithmetic on the clock.
import type {
  Api, AppState, ApplyReport, BwLogin, BwLoginResult, Decision, Destination, Device, LiveCode,
  Proposal, ProxyEvent, ProxyInfo, SessionSnapshot, Step, TokenView, UnlockSummary, VaultLoginView,
} from "./api";
import { ApiError, unexplained } from "./api.errors";

/** The commands of the contract: everything except the two subscriptions. */
export type FakeMethod = Exclude<keyof Api, "onProxyEvent" | "onBwProgress">;

/** Everything a test (or the dev build) can script. All fields have walkable defaults. */
export type FakeScript = {
  /** The one backup password `unlock` accepts, compared exactly as typed. */
  password: string;
  summary: UnlockSummary;
  addresses: { ip: string; label: string }[];
  port: number;
  /** What `ProxyInfo.certConstrained` says. */
  certConstrained: boolean;
  proposals: Proposal[];
  /** Every login in the vault, for `bwLogins`. When null, the logins the proposals mention. */
  vault: VaultLoginView[] | null;
  /** Answers for successive `bwLogin` calls. When empty, login succeeds. */
  loginResults: BwLoginResult[];
  /** Answers for successive `bwApply` calls. When empty, the report is worked out from the decisions. */
  applyResults: (ApplyReport | Error)[];
  /** Answers for successive `exportFile` calls. When empty, the file is "saved". */
  exportResults: ({ saved: string } | { cancelled: true })[];
  /** Titles the Google transfer codes cannot carry. */
  googleUnsupported: string[];
  /** What `tokenQr` and `googleMigrationQrs` hand back instead of drawings, when set. */
  qrSvg: string | null;
  googlePages: string[] | null;
  /**
   * Rejections, per command, used up one per call in order: an `ApiError` as the shell would
   * send it, or a bare string for a rejection with no code (which arrives as `internal`, with
   * the text kept off the screen, as the real binding does).
   */
  failures: Partial<Record<FakeMethod, (ApiError | string)[]>>;
  /** Makes `bwPrepare` fail with this message. */
  prepareError: string | null;
  /** Progress lines `bwPrepare` reports while it works. */
  prepareProgress: string[];
  /** Calls named here do not answer until `release` or `bwCancel`. */
  hold: Partial<Record<"bwPrepare" | "bwLogin", boolean>>;
  /** Makes the next `restartProxy` calls fail with these messages, in order. */
  restartErrors: string[];
  /** Runs inside `restartProxy` before it answers, e.g. to emit events from the "new proxy". */
  beforeRestartResolves: (() => void) | null;
  /** Makes `liveCodes` fail with this message, every time, until cleared. */
  liveCodesError: string | null;
  /** Makes `cleanup` fail with this message, once. */
  cleanupError: string | null;
  /** Artificial delay on every call, so the dev build shows its waiting states. */
  delayMs: number;
  /** Clock used for live codes. */
  now: () => number;
};

export type FakeCall = { method: keyof Api; args: unknown[] };

export type FakeApi = Api & {
  /** Test hook: push a proxy event to every subscriber. */
  emitProxyEvent(e: ProxyEvent): void;
  /** Test hook: push a Bitwarden progress line to every subscriber. */
  emitBwProgress(line: string): void;
  /** Test hook: let a held `bwPrepare` or `bwLogin` answer. */
  release(method: "bwPrepare" | "bwLogin"): void;
  /** Every call made so far, in order. */
  calls: FakeCall[];
  /** The live script. Tests may change it between calls. */
  script: FakeScript;
};

export const FAKE_PASSWORD = "correct horse";
/** Shaped like the real thing: 32 upper-case hex pairs joined by ":". */
export const FAKE_FINGERPRINT = Array.from({ length: 32 }, (_, i) => ((i * 37 + 11) % 256).toString(16).toUpperCase().padStart(2, "0")).join(":");

const TOKENS: TokenView[] = [
  { id: "t1", title: "GitHub", username: "sam.rivera" },
  { id: "t2", title: "Google", username: "sam.rivera@example.com" },
  { id: "t3", title: "Amazon", username: "sam.rivera@example.com" },
  { id: "t4", title: "Dropbox", username: null },
  { id: "t5", title: "Discord", username: "samr" },
  { id: "t6", title: "Cloudflare", username: "sam@rivera.example" },
  { id: "t7", title: "Fastmail", username: "sam@rivera.example" },
  { id: "t8", title: "Home router", username: null },
];

const PROPOSALS: Proposal[] = [
  { tokenId: "t1", confidence: "high", decision: { kind: "attach", itemId: "v1" },
    candidates: [{ itemId: "v1", name: "GitHub", username: "sam.rivera", hasCode: false }] },
  { tokenId: "t2", confidence: "low", decision: { kind: "attach", itemId: "v2" },
    candidates: [
      { itemId: "v2", name: "Google", username: "sam.rivera@example.com", hasCode: false },
      { itemId: "v3", name: "Google (work)", username: "sam@rivera.example", hasCode: false },
    ] },
  { tokenId: "t3", confidence: "high", decision: { kind: "attach", itemId: "v4" },
    candidates: [{ itemId: "v4", name: "Amazon", username: "sam.rivera@example.com", hasCode: false }] },
  // The core never proposes attaching to a login that already has a code. When the only
  // match has one, it lists the login, makes no choice, and marks the row low confidence.
  { tokenId: "t4", confidence: "low", decision: { kind: "createNew" },
    candidates: [{ itemId: "v5", name: "Dropbox", username: "sam.rivera@example.com", hasCode: true }] },
  { tokenId: "t5", confidence: "low", decision: { kind: "attach", itemId: "v6" },
    candidates: [
      { itemId: "v6", name: "Discord", username: "samr", hasCode: false },
      { itemId: "v7", name: "Discord", username: "sam-alt", hasCode: false },
    ] },
  { tokenId: "t6", confidence: "high", decision: { kind: "attach", itemId: "v8" },
    candidates: [{ itemId: "v8", name: "Cloudflare", username: "sam@rivera.example", hasCode: false }] },
  { tokenId: "t7", confidence: "high", decision: { kind: "createNew" }, candidates: [] },
  { tokenId: "t8", confidence: "high", decision: { kind: "createNew" }, candidates: [] },
];

function defaultScript(): FakeScript {
  return {
    password: FAKE_PASSWORD,
    summary: {
      tokens: TOKENS.map((t) => ({ ...t })),
      invalid: [{ name: "Old VPN", reason: "notBase32" }],
      native: [{ name: "Twitch" }],
    },
    addresses: [{ ip: "192.168.4.109", label: "Wi-Fi" }, { ip: "10.0.0.12", label: "Ethernet" }],
    port: 8080,
    certConstrained: true,
    proposals: PROPOSALS.map((p) => ({ ...p, candidates: p.candidates.map((c) => ({ ...c })) })),
    vault: null,
    loginResults: [],
    applyResults: [],
    exportResults: [],
    googleUnsupported: [],
    qrSvg: null,
    googlePages: null,
    failures: {},
    prepareError: null,
    prepareProgress: ["Downloading Bitwarden's tool…", "Checking the download…", "Unpacking…"],
    hold: {},
    restartErrors: [],
    beforeRestartResolves: null,
    liveCodesError: null,
    cleanupError: null,
    delayMs: 0,
    now: () => Date.now(),
  };
}

/** Small deterministic hash (FNV-1a), for drawing fake QR codes and inventing fake codes. */
function hash(text: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

/** A picture that looks like a QR code and encodes nothing. */
export function fakeQrSvg(seed: string): string {
  const n = 25;
  let state = hash(seed) || 1;
  const next = () => {
    state ^= state << 13; state >>>= 0;
    state ^= state >>> 17;
    state ^= state << 5; state >>>= 0;
    return state;
  };
  const inFinder = (x: number, y: number) =>
    (x < 8 && y < 8) || (x >= n - 8 && y < 8) || (x < 8 && y >= n - 8);
  let cells = "";
  for (let y = 0; y < n; y++) {
    for (let x = 0; x < n; x++) {
      if (!inFinder(x, y) && next() % 2 === 0) cells += `M${x} ${y}h1v1h-1z`;
    }
  }
  const finder = (x: number, y: number) =>
    `<path d="M${x} ${y}h7v7h-7z M${x + 1} ${y + 1}v5h5v-5z M${x + 2} ${y + 2}h3v3h-3z" fill-rule="evenodd"/>`;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="-2 -2 ${n + 4} ${n + 4}" shape-rendering="crispEdges">`
    + `<rect x="-2" y="-2" width="${n + 4}" height="${n + 4}" fill="#fff"/>`
    + `<g fill="#000">${finder(0, 0)}${finder(n - 7, 0)}${finder(0, n - 7)}<path d="${cells}"/></g></svg>`;
}

const FILE_NAMES: Record<Destination, string> = {
  bitwarden: "authy-bitwarden-import.csv",
  onePassword: "authy-1password-import.csv",
  twoFas: "authy-2fas-backup.2fas",
  aegis: "authy-aegis-import.json",
  googleAuthenticator: "authy-google.txt",
  protonAuthenticator: "authy-proton-authenticator-import.json",
  plainText: "authy-otpauth-uris.txt",
};

const ORDER: Step[] = ["welcome", "connect", "certificate", "authy", "unlock", "destination", "verify", "cleanup", "done"];
const noSession = (): SessionSnapshot => ({ proxy: null, deviceConnected: false, trustWorking: false, captured: 0, summary: null });

export function createFakeApi(initial: Partial<AppState> = {}, overrides: Partial<FakeScript> = {}): FakeApi {
  // Like the shell, `resumeCleanup` is decided once, at launch: it says a marker was found
  // then. Starting the proxy writes a marker for the next launch, and does not change this.
  const state: AppState = {
    step: "welcome", device: null, resumeCleanup: false, version: "0.0.0-fake",
    releasesUrl: "https://example.com/authexodus/releases", session: noSession(), ...initial,
  };
  const session = state.session;
  const script: FakeScript = { ...defaultScript(), ...overrides };
  const proxyListeners = new Set<(e: ProxyEvent) => void>();
  const bwListeners = new Set<(line: string) => void>();
  const calls: FakeCall[] = [];
  let chosenIp: string | null = session.proxy?.ip ?? null;
  let unlocked = session.summary !== null;
  /** Signed in to the pretend Bitwarden. */
  let signedIn = false;
  /** Vault items the fake Bitwarden has already been given a code for, so re-runs add nothing twice. */
  const applied = new Set<string>();
  /** Calls waiting on `release` or `bwCancel`. */
  const held = new Map<"bwPrepare" | "bwLogin", { resolve: () => void; reject: (e: ApiError) => void }>();
  let cancels = 0;

  const pause = () => (script.delayMs > 0 ? new Promise<void>((r) => setTimeout(r, script.delayMs)) : Promise.resolve());
  const record = (method: keyof Api, ...args: unknown[]) => { calls.push({ method, args }); return pause(); };
  const emitBw = (line: string) => bwListeners.forEach((l) => l(line));
  const titleOf = (tokenId: string) => script.summary.tokens.find((t) => t.id === tokenId)?.title ?? tokenId;
  /** The wizard only ever moves forward in the shell's eyes, except for a restart. */
  const advance = (to: Step) => { if (ORDER.indexOf(to) > ORDER.indexOf(state.step)) state.step = to; };
  /** Throws the next scripted rejection for `method`, if there is one. */
  const failIfScripted = (method: FakeMethod) => {
    const next = script.failures[method]?.shift();
    if (next !== undefined) throw typeof next === "string" ? unexplained(next) : next;
  };
  const cancelled = () => new ApiError("bw_failed", "Cancelled.");
  /** Waits for `release` when the call is held; rejects when `bwCancel` arrives first. */
  const holdIfAsked = async (method: "bwPrepare" | "bwLogin") => {
    if (!script.hold[method]) return;
    await new Promise<void>((resolve, reject) => { held.set(method, { resolve, reject }); });
  };

  function proxyInfo(): ProxyInfo {
    const ip = chosenIp ?? script.addresses[0]?.ip ?? "192.168.4.109";
    return {
      addresses: script.addresses.map((a) => ({ ...a })),
      ip,
      port: script.port,
      certUrl: `http://${ip}:${script.port}/`,
      certQrSvg: fakeQrSvg(`cert:${ip}:${script.port}`),
      checkUrl: "https://authexodus-check.api.authy.com/",
      certFingerprint: FAKE_FINGERPRINT,
      certConstrained: script.certConstrained,
    };
  }

  function vault(): VaultLoginView[] {
    if (script.vault) return script.vault.map((v) => ({ ...v }));
    const seen = new Map<string, VaultLoginView>();
    for (const p of script.proposals) for (const c of p.candidates) if (!seen.has(c.itemId)) seen.set(c.itemId, { ...c });
    return [...seen.values()];
  }

  // As the shell counts: `skipped` is only what the person skipped; a code that is already in
  // Bitwarden comes back in `kept`, one sentence each.
  function workOutReport(decisions: { tokenId: string; decision: Decision }[]): ApplyReport {
    const report: ApplyReport = { attached: 0, created: 0, skipped: 0, kept: [], failed: null };
    const logins = vault();
    for (const { tokenId, decision } of decisions) {
      const title = titleOf(tokenId);
      if (decision.kind === "skip") { report.skipped++; continue; }
      if (applied.has(tokenId)) {
        report.kept.push(`${title} is already in Bitwarden from an earlier run.`);
        continue;
      }
      if (decision.kind === "createNew") {
        report.created++;
        emitBw(`Created ${title}`);
      } else {
        const target = logins.find((c) => c.itemId === decision.itemId);
        if (target?.hasCode) {
          report.kept.push(`${target.name} already has a code, so ${title} was not added to it.`);
          emitBw(`Kept ${target.name}`);
          continue;
        }
        report.attached++;
        emitBw(`Attached ${title}`);
      }
      applied.add(tokenId);
    }
    return report;
  }

  const requireSession = () => {
    if (!signedIn) throw new ApiError("bw_session_expired", "Bitwarden's session has ended. Sign in again.");
  };

  return {
    calls,
    script,
    async getState() {
      await record("getState");
      failIfScripted("getState");
      return structuredClone(state);
    },
    async setDevice(device: Device) { await record("setDevice", device); state.device = device; },
    async startProxy(ip?: string) {
      await record("startProxy", ip);
      failIfScripted("startProxy");
      if (session.captured > 0 && ip !== undefined && ip !== proxyInfo().ip) {
        throw new ApiError("capture_would_be_lost", "A backup is already captured. Restart the connection to change the address.");
      }
      if (ip !== undefined && !script.addresses.some((a) => a.ip === ip)) {
        throw new ApiError("address_changed", "That address is no longer one of this computer's network addresses.");
      }
      if (ip !== undefined) chosenIp = ip;
      session.proxy = proxyInfo();
      advance("connect");
      return proxyInfo();
    },
    async restartProxy(ip?: string) {
      await record("restartProxy", ip);
      failIfScripted("restartProxy");
      const failure = script.restartErrors.shift();
      if (failure !== undefined) throw new ApiError("internal", failure);
      if (ip !== undefined && !script.addresses.some((a) => a.ip === ip)) {
        throw new ApiError("address_changed", "That address is no longer one of this computer's network addresses.");
      }
      chosenIp = ip ?? null;
      // A start-over: the capture and the accepted device are forgotten, and so is the unlock.
      Object.assign(session, noSession(), { proxy: proxyInfo() });
      unlocked = false;
      state.step = "connect";
      script.beforeRestartResolves?.();
      return proxyInfo();
    },
    onProxyEvent(cb) { proxyListeners.add(cb); return () => { proxyListeners.delete(cb); }; },
    async unlock(password: string) {
      await record("unlock", password);
      failIfScripted("unlock");
      if (password !== script.password) return { error: "wrongPassword" as const };
      unlocked = true;
      session.summary = structuredClone(script.summary);
      advance("destination");
      return structuredClone(script.summary);
    },
    async tokenQr(id: string) {
      await record("tokenQr", id);
      failIfScripted("tokenQr");
      return script.qrSvg ?? fakeQrSvg(`token:${id}`);
    },
    async googleMigrationQrs() {
      await record("googleMigrationQrs");
      failIfScripted("googleMigrationQrs");
      if (script.googlePages) return [...script.googlePages];
      const pages = Math.max(1, Math.ceil(script.summary.tokens.length / 10));
      return Array.from({ length: pages }, (_, i) => fakeQrSvg(`google:${i}`));
    },
    async googleUnsupported() {
      await record("googleUnsupported");
      failIfScripted("googleUnsupported");
      return [...script.googleUnsupported];
    },
    async exportFile(dest: Destination) {
      await record("exportFile", dest);
      failIfScripted("exportFile");
      return script.exportResults.shift() ?? { saved: `/Users/sam/Downloads/${FILE_NAMES[dest]}` };
    },
    async liveCodes(): Promise<LiveCode[]> {
      await record("liveCodes");
      failIfScripted("liveCodes");
      if (script.liveCodesError) throw new ApiError("internal", script.liveCodesError);
      if (!unlocked) return [];
      advance("verify");
      const seconds = Math.floor(script.now() / 1000);
      const window = Math.floor(seconds / 30);
      return script.summary.tokens.map((t) => ({
        id: t.id,
        code: String(hash(`${t.id}:${window}`) % 1_000_000).padStart(6, "0"),
        secondsLeft: 30 - (seconds % 30),
      }));
    },
    async bwPrepare() {
      const mine = cancels;
      await record("bwPrepare");
      for (const line of script.prepareProgress) {
        emitBw(line);
        await pause();
        if (cancels !== mine) throw cancelled();
      }
      await holdIfAsked("bwPrepare");
      failIfScripted("bwPrepare");
      if (script.prepareError) throw new ApiError("bw_download_failed", script.prepareError);
    },
    async bwCancel() {
      await record("bwCancel");
      cancels++;
      for (const [method, waiting] of held) { held.delete(method); waiting.reject(cancelled()); }
    },
    async bwLogin(login: BwLogin): Promise<BwLoginResult> {
      const mine = cancels;
      // The record keeps what was sent, not the object the caller may go on to change.
      await record("bwLogin", structuredClone(login));
      await holdIfAsked("bwLogin");
      if (cancels !== mine) throw cancelled();
      failIfScripted("bwLogin");
      const result = script.loginResults.shift() ?? { kind: "ok" as const };
      if (result.kind === "ok") signedIn = true;
      return result;
    },
    async bwPropose(): Promise<Proposal[]> {
      await record("bwPropose");
      failIfScripted("bwPropose");
      requireSession();
      return structuredClone(script.proposals);
    },
    async bwLogins(): Promise<VaultLoginView[]> {
      await record("bwLogins");
      failIfScripted("bwLogins");
      requireSession();
      return vault();
    },
    async bwApply(decisions) {
      await record("bwApply", decisions);
      try {
        failIfScripted("bwApply");
      } catch (err) {
        // An expired session is exactly that: the next call needs a fresh sign-in.
        if (err instanceof ApiError && err.code === "bw_session_expired") signedIn = false;
        throw err;
      }
      requireSession();
      const scripted = script.applyResults.shift();
      if (scripted instanceof Error) throw scripted;
      return scripted ?? workOutReport(decisions);
    },
    onBwProgress(cb) { bwListeners.add(cb); return () => { bwListeners.delete(cb); }; },
    async cleanup() {
      await record("cleanup");
      failIfScripted("cleanup");
      if (script.cleanupError) {
        const message = script.cleanupError;
        script.cleanupError = null;
        throw new ApiError("cleanup_keychain_failed", message);
      }
      unlocked = false;
      signedIn = false;
      Object.assign(session, noSession());
      advance("cleanup");
    },
    async finish() {
      await record("finish");
      failIfScripted("finish");
      state.resumeCleanup = false;
      advance("done");
    },
    emitProxyEvent(e) {
      // The shell's snapshot follows the same events the window is sent.
      if (e.kind === "deviceConnected") { session.deviceConnected = true; advance("certificate"); }
      if (e.kind === "trustWorking") { session.deviceConnected = true; session.trustWorking = true; advance("authy"); }
      if (e.kind === "backupCaptured") { session.captured = Math.max(session.captured, e.count); advance("unlock"); }
      proxyListeners.forEach((l) => l(e));
    },
    emitBwProgress: emitBw,
    release(method) {
      const waiting = held.get(method);
      held.delete(method);
      waiting?.resolve();
    },
  };
}
