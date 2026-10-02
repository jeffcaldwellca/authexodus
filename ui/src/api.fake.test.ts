import { createFakeApi } from "./api.fake";
import type { Api, ProxyEvent } from "./api";

describe("api.fake", () => {
  it("satisfies the Api contract and reports initial state", async () => {
    const api: Api = createFakeApi({ resumeCleanup: true });
    expect(await api.getState()).toMatchObject({ step: "welcome", device: null, resumeCleanup: true });
  });

  it("remembers the chosen device", async () => {
    const api = createFakeApi();
    await api.setDevice("ipad");
    expect((await api.getState()).device).toBe("ipad");
  });

  it("delivers proxy events until unsubscribed", () => {
    const api = createFakeApi();
    const seen: ProxyEvent[] = [];
    const off = api.onProxyEvent((e) => seen.push(e));
    api.emitProxyEvent({ kind: "deviceConnected" });
    off();
    api.emitProxyEvent({ kind: "trustWorking" });
    expect(seen).toEqual([{ kind: "deviceConnected" }]);
  });

  it("unlocks only with the exact scripted password", async () => {
    const api = createFakeApi({}, { password: " pass word " });
    expect(await api.unlock("pass word")).toEqual({ error: "wrongPassword" });
    expect(await api.liveCodes()).toEqual([]);
    const summary = await api.unlock(" pass word ");
    expect("tokens" in summary && summary.tokens.length).toBeGreaterThan(0);
    expect((await api.liveCodes()).every((c) => /^\d{6}$/.test(c.code))).toBe(true);
  });

  it("a second apply adds nothing twice and never attaches to a login that has a code", async () => {
    const api = createFakeApi();
    const decisions = (await api.bwPropose()).map((p) => ({ tokenId: p.tokenId, decision: p.decision }));
    const first = await api.bwApply(decisions);
    expect(first).toMatchObject({ attached: 5, created: 2, kept: ["Dropbox"], failed: null });
    expect(await api.bwApply(decisions)).toMatchObject({ attached: 0, created: 0 });
  });

  it("starting the proxy leaves a run to clean up until finish", async () => {
    const api = createFakeApi();
    const info = await api.startProxy("10.0.0.12");
    expect(info).toMatchObject({ ip: "10.0.0.12", certUrl: "http://10.0.0.12:8080/" });
    expect((await api.getState()).resumeCleanup).toBe(true);
    await api.finish();
    expect((await api.getState()).resumeCleanup).toBe(false);
  });
});
