// In-memory fake of the `Api` contract. UI tests script it, and `pnpm -C ui dev` runs the whole
// wizard against it in a plain browser. Nothing here is real: the names are invented, the QR
// codes are patterns that scan to nothing, and the "live codes" are arithmetic on the clock.
import type {
  Api, AppState, ApplyReport, BwLogin, BwLoginResult, Decision, Destination, Device, LiveCode,
  Proposal, ProxyEvent, ProxyInfo, TokenView, UnlockSummary,
} from "./api";

/** Everything a test (or the dev build) can script. All fields have walkable defaults. */
export type FakeScript = {
  /** The one backup password `unlock` accepts, compared exactly as typed. */
  password: string;
  summary: UnlockSummary;
  addresses: { ip: string; label: string }[];
  port: number;
  proposals: Proposal[];
  /** Answers for successive `bwLogin` calls. When empty, login succeeds. */
  loginResults: BwLoginResult[];
  /** Answers for successive `bwApply` calls. When empty, the report is worked out from the decisions. */
  applyResults: (ApplyReport | Error)[];
  /** Answers for successive `exportFile` calls. When empty, the file is "saved". */
  exportResults: ({ saved: string } | { cancelled: true })[];
  /** Titles the Google transfer codes cannot carry. */
  googleUnsupported: string[];
  /** Makes `bwPrepare` fail with this message. */
  prepareError: string | null;
  /** Makes the next `restartProxy` calls fail with these messages, in order. */
  restartErrors: string[];
  /** Runs inside `restartProxy` before it answers, e.g. to emit events from the "new proxy". */
  beforeRestartResolves: (() => void) | null;
  /** Makes `liveCodes` fail with this message. */
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
    proposals: PROPOSALS.map((p) => ({ ...p, candidates: p.candidates.map((c) => ({ ...c })) })),
    loginResults: [],
    applyResults: [],
    exportResults: [],
    googleUnsupported: [],
    prepareError: null,
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
  bitwarden: "authy-export-bitwarden.json",
  onePassword: "authy-export-1password.csv",
  twoFas: "authy-export.2fas",
  aegis: "authy-export-aegis.json",
  googleAuthenticator: "authy-export-google.txt",
  protonAuthenticator: "authy-export-proton.json",
  plainText: "authy-export-otpauth.txt",
};

export function createFakeApi(initial: Partial<AppState> = {}, overrides: Partial<FakeScript> = {}): FakeApi {
  const state: AppState = {
    step: "welcome", device: null, resumeCleanup: false, version: "0.0.0-fake",
    releasesUrl: "https://example.com/authexodus/releases", ...initial,
  };
  const script: FakeScript = { ...defaultScript(), ...overrides };
  const proxyListeners = new Set<(e: ProxyEvent) => void>();
  const bwListeners = new Set<(line: string) => void>();
  const calls: FakeCall[] = [];
  let chosenIp: string | null = null;
  let unlocked = false;
  /** A backup has passed through the proxy, so the address can no longer change quietly. */
  let captured = false;
  /** Vault items the fake Bitwarden has already been given a code for, so re-runs add nothing twice. */
  const applied = new Set<string>();

  const pause = () => (script.delayMs > 0 ? new Promise<void>((r) => setTimeout(r, script.delayMs)) : Promise.resolve());
  const record = (method: keyof Api, ...args: unknown[]) => { calls.push({ method, args }); return pause(); };
  const emitBw = (line: string) => bwListeners.forEach((l) => l(line));
  const titleOf = (tokenId: string) => script.summary.tokens.find((t) => t.id === tokenId)?.title ?? tokenId;

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
    };
  }

  function workOutReport(decisions: { tokenId: string; decision: Decision }[]): ApplyReport {
    const report: ApplyReport = { attached: 0, created: 0, skipped: 0, kept: [], failed: null };
    for (const { tokenId, decision } of decisions) {
      const title = titleOf(tokenId);
      if (decision.kind === "skip") { report.skipped++; continue; }
      if (applied.has(tokenId)) continue;
      if (decision.kind === "createNew") {
        report.created++;
        emitBw(`Created ${title}`);
      } else {
        const proposal = script.proposals.find((p) => p.tokenId === tokenId);
        const target = proposal?.candidates.find((c) => c.itemId === decision.itemId);
        if (target?.hasCode) { report.kept.push(target.name); emitBw(`Kept ${target.name}`); continue; }
        report.attached++;
        emitBw(`Attached ${title}`);
      }
      applied.add(tokenId);
    }
    return report;
  }

  return {
    calls,
    script,
    async getState() { await record("getState"); return { ...state }; },
    async setDevice(device: Device) { await record("setDevice", device); state.device = device; },
    async startProxy(ip?: string) {
      await record("startProxy", ip);
      if (captured && ip !== undefined && ip !== proxyInfo().ip) {
        throw new Error("a backup is already captured; restart the proxy to change address");
      }
      if (ip !== undefined) chosenIp = ip;
      // The resume marker exists from the moment the certificate is created: the first start.
      state.resumeCleanup = true;
      return proxyInfo();
    },
    async restartProxy(ip?: string) {
      await record("restartProxy", ip);
      const failure = script.restartErrors.shift();
      if (failure !== undefined) throw new Error(failure);
      if (ip !== undefined && !script.addresses.some((a) => a.ip === ip)) {
        throw new Error("That address is not one of this computer's network addresses.");
      }
      chosenIp = ip ?? null;
      script.beforeRestartResolves?.();
      captured = false;
      unlocked = false;
      state.resumeCleanup = true;
      return proxyInfo();
    },
    onProxyEvent(cb) { proxyListeners.add(cb); return () => { proxyListeners.delete(cb); }; },
    async unlock(password: string) {
      await record("unlock", password);
      if (password !== script.password) return { error: "wrongPassword" as const };
      unlocked = true;
      return structuredClone(script.summary);
    },
    async tokenQr(id: string) { await record("tokenQr", id); return fakeQrSvg(`token:${id}`); },
    async googleMigrationQrs() {
      await record("googleMigrationQrs");
      const pages = Math.max(1, Math.ceil(script.summary.tokens.length / 10));
      return Array.from({ length: pages }, (_, i) => fakeQrSvg(`google:${i}`));
    },
    async googleUnsupported() { await record("googleUnsupported"); return [...script.googleUnsupported]; },
    async exportFile(dest: Destination) {
      await record("exportFile", dest);
      return script.exportResults.shift() ?? { saved: `/Users/sam/Downloads/${FILE_NAMES[dest]}` };
    },
    async liveCodes(): Promise<LiveCode[]> {
      await record("liveCodes");
      if (script.liveCodesError) throw new Error(script.liveCodesError);
      if (!unlocked) return [];
      const seconds = Math.floor(script.now() / 1000);
      const window = Math.floor(seconds / 30);
      return script.summary.tokens.map((t) => ({
        id: t.id,
        code: String(hash(`${t.id}:${window}`) % 1_000_000).padStart(6, "0"),
        secondsLeft: 30 - (seconds % 30),
      }));
    },
    async bwPrepare() {
      await record("bwPrepare");
      if (script.prepareError) throw new Error(script.prepareError);
    },
    async bwLogin(login: BwLogin): Promise<BwLoginResult> {
      await record("bwLogin", login);
      return script.loginResults.shift() ?? { kind: "ok" };
    },
    async bwPropose(): Promise<Proposal[]> { await record("bwPropose"); return structuredClone(script.proposals); },
    async bwApply(decisions) {
      await record("bwApply", decisions);
      const scripted = script.applyResults.shift();
      if (scripted instanceof Error) throw scripted;
      return scripted ?? workOutReport(decisions);
    },
    onBwProgress(cb) { bwListeners.add(cb); return () => { bwListeners.delete(cb); }; },
    async cleanup() {
      await record("cleanup");
      if (script.cleanupError) {
        const message = script.cleanupError;
        script.cleanupError = null;
        throw new Error(message);
      }
      unlocked = false;
    },
    async finish() { await record("finish"); state.resumeCleanup = false; },
    emitProxyEvent(e) {
      if (e.kind === "backupCaptured" && e.count > 0) captured = true;
      proxyListeners.forEach((l) => l(e));
    },
    emitBwProgress: emitBw,
  };
}
