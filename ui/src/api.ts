export type Device = "iphone" | "ipad";
export type Step = "welcome" | "connect" | "certificate" | "authy" | "unlock" | "destination" | "verify" | "cleanup" | "done";
// What the shell already knows about this run, so the UI can pick up where it was after a window reload.
export type SessionSnapshot = { proxy: ProxyInfo | null; deviceConnected: boolean; trustWorking: boolean; captured: number;
  summary: UnlockSummary | null };
export type AppState = { step: Step; device: Device | null; resumeCleanup: boolean; version: string; releasesUrl: string;
  session: SessionSnapshot };
export type ProxyInfo = { addresses: { ip: string; label: string }[]; ip: string; port: number; certUrl: string; certQrSvg: string; checkUrl: string;
  certFingerprint: string;                                   // SHA-256 of the certificate, upper-case hex pairs joined by ":"
  certConstrained: boolean };                                // false when the certificate is not limited to Authy's names
export type ProxyEvent =
  | { kind: "deviceConnected" } | { kind: "trustWorking" } | { kind: "tlsRejected" }
  | { kind: "backupCaptured"; count: number } | { kind: "authyError"; status: number; path: string }
  | { kind: "deviceRefused" }                                // another device tried to reach Authy after one was accepted
  | { kind: "emptyBackup" }                                  // Authy answered with no accounts (backups are probably off)
  | { kind: "addressChanged" };                              // this computer's network address is no longer the one the proxy is on
export type TokenView = { id: string; title: string; username: string | null };
export type UnlockSummary = { tokens: TokenView[]; invalid: { name: string; reason: "notBase32" | "tooShort" }[]; native: { name: string }[] };
export type Destination = "bitwarden" | "onePassword" | "twoFas" | "aegis" | "googleAuthenticator" | "protonAuthenticator" | "plainText";
export type LiveCode = { id: string; code: string; secondsLeft: number };
export type BwRegion = { kind: "us" } | { kind: "eu" } | { kind: "selfHosted"; url: string };
export type BwApiKey = { clientId: string; clientSecret: string };   // a personal API key, for accounts Bitwarden asks to verify by email
export type BwLogin = { email: string; password: string; region: BwRegion; twoFactorCode?: string; apiKey?: BwApiKey };
export type BwLoginResult = { kind: "ok" } | { kind: "needsTwoFactor" } | { kind: "badCredentials" }
  | { kind: "badTwoFactorCode" }                              // a code was sent and Bitwarden did not accept it
  | { kind: "needsApiKey" };                                  // Bitwarden wants an emailed code or a security key; sign in with an API key instead
export type VaultLoginView = { itemId: string; name: string; username: string | null; hasCode: boolean };
export type Decision = { kind: "attach"; itemId: string } | { kind: "createNew" } | { kind: "skip" };
export type Proposal = { tokenId: string; decision: Decision; confidence: "high" | "low";
  candidates: VaultLoginView[] };
export type ApplyReport = { attached: number; created: number; skipped: number; kept: string[]; failed: string | null };

export interface Api {
  getState(): Promise<AppState>;
  setDevice(device: Device): Promise<void>;
  startProxy(ip?: string): Promise<ProxyInfo>;             // idempotent; rejects a different address once a backup is captured
  restartProxy(ip?: string): Promise<ProxyInfo>;           // explicit start-over: discards the capture, forgets the accepted device
  onProxyEvent(cb: (e: ProxyEvent) => void): () => void;
  unlock(password: string): Promise<UnlockSummary | { error: "wrongPassword" }>;
  tokenQr(id: string): Promise<string>;                      // SVG
  googleMigrationQrs(): Promise<string[]>;                   // SVGs, at most 10 tokens each
  googleUnsupported(): Promise<string[]>;                    // titles the Google QR cannot carry
  exportFile(dest: Destination): Promise<{ saved: string } | { cancelled: true }>;  // native save dialog
  liveCodes(): Promise<LiveCode[]>;
  bwPrepare(): Promise<void>;                                // download + verify the CLI; progress lines arrive on onBwProgress
  bwCancel(): Promise<void>;                                 // abandon an in-flight download or sign-in
  bwLogin(login: BwLogin): Promise<BwLoginResult>;
  bwPropose(): Promise<Proposal[]>;
  bwLogins(): Promise<VaultLoginView[]>;                     // every login in the vault, for attaching by hand
  bwApply(decisions: { tokenId: string; decision: Decision }[]): Promise<ApplyReport>;
  onBwProgress(cb: (line: string) => void): () => void;
  cleanup(): Promise<void>;                                  // stop proxy, destroy CA key, wipe CLI data, drop secrets
  finish(): Promise<void>;                                   // clear the resume marker
}
