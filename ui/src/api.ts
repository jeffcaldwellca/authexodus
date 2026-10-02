export type Device = "iphone" | "ipad";
export type Step = "welcome" | "connect" | "certificate" | "authy" | "unlock" | "destination" | "verify" | "cleanup" | "done";
export type AppState = { step: Step; device: Device | null; resumeCleanup: boolean; version: string };
export type ProxyInfo = { addresses: { ip: string; label: string }[]; ip: string; port: number; certUrl: string; certQrSvg: string; checkUrl: string };
export type ProxyEvent =
  | { kind: "deviceConnected" } | { kind: "trustWorking" } | { kind: "tlsRejected" }
  | { kind: "backupCaptured"; count: number } | { kind: "authyError"; status: number; path: string };
export type TokenView = { id: string; title: string; username: string | null };
export type UnlockSummary = { tokens: TokenView[]; invalid: { name: string; reason: "notBase32" | "tooShort" }[]; native: { name: string }[] };
export type Destination = "bitwarden" | "onePassword" | "twoFas" | "aegis" | "googleAuthenticator" | "protonAuthenticator" | "plainText";
export type LiveCode = { id: string; code: string; secondsLeft: number };
export type BwRegion = { kind: "us" } | { kind: "eu" } | { kind: "selfHosted"; url: string };
export type BwLogin = { email: string; password: string; region: BwRegion; twoFactorCode?: string };
export type BwLoginResult = { kind: "ok" } | { kind: "needsTwoFactor" } | { kind: "badCredentials" };
export type Decision = { kind: "attach"; itemId: string } | { kind: "createNew" } | { kind: "skip" };
export type Proposal = { tokenId: string; decision: Decision; confidence: "high" | "low";
  candidates: { itemId: string; name: string; username: string | null; hasCode: boolean }[] };
export type ApplyReport = { attached: number; created: number; skipped: number; kept: string[]; failed: string | null };

export interface Api {
  getState(): Promise<AppState>;
  setDevice(device: Device): Promise<void>;
  startProxy(ip?: string): Promise<ProxyInfo>;
  onProxyEvent(cb: (e: ProxyEvent) => void): () => void;
  unlock(password: string): Promise<UnlockSummary | { error: "wrongPassword" }>;
  tokenQr(id: string): Promise<string>;                      // SVG
  googleMigrationQrs(): Promise<string[]>;                   // SVGs, 10 tokens each
  exportFile(dest: Destination): Promise<{ saved: string } | { cancelled: true }>;  // native save dialog
  liveCodes(): Promise<LiveCode[]>;
  bwPrepare(): Promise<void>;                                // download + verify the CLI
  bwLogin(login: BwLogin): Promise<BwLoginResult>;
  bwPropose(): Promise<Proposal[]>;
  bwApply(decisions: { tokenId: string; decision: Decision }[]): Promise<ApplyReport>;
  onBwProgress(cb: (line: string) => void): () => void;
  cleanup(): Promise<void>;                                  // stop proxy, destroy CA key, wipe CLI data, drop secrets
  finish(): Promise<void>;                                   // clear the resume marker
}
