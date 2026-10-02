// In-memory fake of the `Api` contract, for UI tests and for running the UI without Tauri.
// Batch 0: just enough to type-check and answer; package 2B fleshes it out (scripted proxy
// events, a fake unlock, a fake Bitwarden vault, ...).
import type {
  Api, AppState, ApplyReport, BwLoginResult, Device, LiveCode, Proposal, ProxyEvent, ProxyInfo,
  UnlockSummary,
} from "./api";

export type FakeApi = Api & {
  /** Test hook: push a proxy event to every subscriber. */
  emitProxyEvent(e: ProxyEvent): void;
  /** Test hook: push a Bitwarden progress line to every subscriber. */
  emitBwProgress(line: string): void;
};

export function createFakeApi(initial: Partial<AppState> = {}): FakeApi {
  const state: AppState = { step: "welcome", device: null, resumeCleanup: false, version: "0.0.0-fake", ...initial };
  const proxyListeners = new Set<(e: ProxyEvent) => void>();
  const bwListeners = new Set<(line: string) => void>();
  const proxyInfo: ProxyInfo = {
    addresses: [{ ip: "192.168.4.109", label: "Wi-Fi" }],
    ip: "192.168.4.109",
    port: 8080,
    certUrl: "http://192.168.4.109:8080/",
    certQrSvg: "<svg xmlns=\"http://www.w3.org/2000/svg\"/>",
    checkUrl: "https://authexodus-check.api.authy.com/",
  };
  const emptySummary: UnlockSummary = { tokens: [], invalid: [], native: [] };
  const emptyReport: ApplyReport = { attached: 0, created: 0, skipped: 0, kept: [], failed: null };

  return {
    async getState() { return { ...state }; },
    async setDevice(device: Device) { state.device = device; },
    async startProxy() { return proxyInfo; },
    onProxyEvent(cb) { proxyListeners.add(cb); return () => { proxyListeners.delete(cb); }; },
    async unlock() { return emptySummary; },
    async tokenQr() { return "<svg xmlns=\"http://www.w3.org/2000/svg\"/>"; },
    async googleMigrationQrs() { return []; },
    async exportFile() { return { cancelled: true }; },
    async liveCodes(): Promise<LiveCode[]> { return []; },
    async bwPrepare() {},
    async bwLogin(): Promise<BwLoginResult> { return { kind: "ok" }; },
    async bwPropose(): Promise<Proposal[]> { return []; },
    async bwApply() { return emptyReport; },
    onBwProgress(cb) { bwListeners.add(cb); return () => { bwListeners.delete(cb); }; },
    async cleanup() {},
    async finish() {},
    emitProxyEvent(e) { proxyListeners.forEach((l) => l(e)); },
    emitBwProgress(line) { bwListeners.forEach((l) => l(line)); },
  };
}
