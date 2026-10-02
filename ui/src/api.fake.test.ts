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
    expect(first).toMatchObject({ attached: 5, created: 3, kept: [], failed: null });
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

  it("refuses a different address once a backup is captured, until the proxy is restarted", async () => {
    const api = createFakeApi();
    await api.startProxy();
    api.emitProxyEvent({ kind: "backupCaptured", count: 3 });
    // The same address is fine: starting is idempotent.
    expect((await api.startProxy("192.168.4.109")).ip).toBe("192.168.4.109");
    expect((await api.startProxy()).ip).toBe("192.168.4.109");
    await expect(api.startProxy("10.0.0.12")).rejects.toThrow();
    expect((await api.restartProxy("10.0.0.12")).ip).toBe("10.0.0.12");
    expect((await api.startProxy("192.168.4.109")).ip).toBe("192.168.4.109");
  });

  it("never proposes attaching to a login that already has a code, as the core never does", async () => {
    const proposals = await createFakeApi().bwPropose();
    for (const p of proposals) {
      const d = p.decision;
      if (d.kind === "attach") expect(p.candidates.find((c) => c.itemId === d.itemId)?.hasCode).toBe(false);
    }
    // The real has-code case: the login is listed, nothing is chosen, and it is a question.
    const taken = proposals.find((p) => p.candidates.some((c) => c.hasCode))!;
    expect(taken).toMatchObject({ confidence: "low", decision: { kind: "createNew" } });
  });

  it("gives a certificate fingerprint in the contract's shape", async () => {
    const info = await createFakeApi().startProxy();
    expect(info.certFingerprint).toMatch(/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
  });

  it("reports the release page and the titles Google's codes cannot carry", async () => {
    const api = createFakeApi({}, { googleUnsupported: ["Steam"] });
    expect((await api.getState()).releasesUrl).toMatch(/^https:\/\//);
    expect(await api.googleUnsupported()).toEqual(["Steam"]);
  });
});
