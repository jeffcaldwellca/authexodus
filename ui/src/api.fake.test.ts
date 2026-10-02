import { createFakeApi } from "./api.fake";
import type { Api, ProxyEvent } from "./api";
import { ApiError, ERROR_CODES } from "./api.errors";

const signIn = (api: Api) => api.bwLogin({ email: "sam@example.com", password: "pw", region: { kind: "us" } });

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
    await signIn(api);
    const decisions = (await api.bwPropose()).map((p) => ({ tokenId: p.tokenId, decision: p.decision }));
    const first = await api.bwApply(decisions);
    expect(first).toMatchObject({ attached: 5, created: 3, skipped: 0, kept: [], failed: null });
    // As the shell reports it: what is already there is "kept", a sentence each, and never "skipped".
    const second = await api.bwApply(decisions);
    expect(second).toMatchObject({ attached: 0, created: 0, skipped: 0 });
    expect(second.kept).toHaveLength(8);
    expect(second.kept.every((line) => /\.$/.test(line))).toBe(true);
  });

  it("counts as skipped only what the person skipped", async () => {
    const api = createFakeApi();
    await signIn(api);
    const report = await api.bwApply([
      { tokenId: "t1", decision: { kind: "skip" } },
      { tokenId: "t4", decision: { kind: "attach", itemId: "v5" } },
    ]);
    expect(report).toMatchObject({ attached: 0, created: 0, skipped: 1 });
    expect(report.kept).toEqual(["Dropbox already has a code, so Dropbox was not added to it."]);
  });

  it("like the shell, reports resumeCleanup as it was at launch: starting the proxy does not change it", async () => {
    const api = createFakeApi();
    const info = await api.startProxy("10.0.0.12");
    expect(info).toMatchObject({ ip: "10.0.0.12", certUrl: "http://10.0.0.12:8080/", certConstrained: true });
    expect((await api.getState()).resumeCleanup).toBe(false);
    // A launch that found the marker says so until Finish clears it.
    const resumed = createFakeApi({ resumeCleanup: true });
    expect((await resumed.getState()).resumeCleanup).toBe(true);
    await resumed.finish();
    expect((await resumed.getState()).resumeCleanup).toBe(false);
  });

  it("keeps a snapshot of the run, as the shell does, for a window that is reloaded", async () => {
    const api = createFakeApi();
    expect((await api.getState()).session).toEqual({ proxy: null, deviceConnected: false, trustWorking: false, captured: 0, summary: null });
    const info = await api.startProxy();
    expect((await api.getState()).session.proxy).toEqual(info);
    api.emitProxyEvent({ kind: "deviceConnected" });
    api.emitProxyEvent({ kind: "trustWorking" });
    api.emitProxyEvent({ kind: "backupCaptured", count: 4 });
    api.emitProxyEvent({ kind: "backupCaptured", count: 9 });
    api.emitProxyEvent({ kind: "backupCaptured", count: 0 });
    expect(await api.getState()).toMatchObject({ step: "unlock", session: { deviceConnected: true, trustWorking: true, captured: 9, summary: null } });
    await api.unlock(api.script.password);
    expect((await api.getState()).session.summary?.tokens).toHaveLength(8);
    expect((await api.getState()).step).toBe("destination");

    // A restart forgets the device and the capture; cleanup forgets the proxy too.
    await api.restartProxy();
    expect(await api.getState()).toMatchObject({ step: "connect", session: { deviceConnected: false, trustWorking: false, captured: 0, summary: null } });
    expect((await api.getState()).session.proxy).not.toBeNull();
    await api.cleanup();
    expect(await api.getState()).toMatchObject({ step: "cleanup", session: { proxy: null } });
  });

  it("can be scripted to reject any command with any of the shell's codes, once each", async () => {
    for (const code of ERROR_CODES) {
      const api = createFakeApi({}, { failures: { tokenQr: [new ApiError(code, "A sentence.")] } });
      await expect(api.tokenQr("t1")).rejects.toMatchObject({ code, message: "A sentence." });
      expect(await api.tokenQr("t1")).toMatch(/^<svg/);
    }
    // A bare string is a rejection with no code: internal, its text kept off the screen.
    const api = createFakeApi({}, { failures: { finish: ["marker is stuck"], getState: ["no state"] } });
    await expect(api.finish()).rejects.toMatchObject({ code: "internal", message: "" });
    await expect(api.getState()).rejects.toBeInstanceOf(ApiError);
  });

  it("the vault read needs a live session, and an expired one ends it", async () => {
    const api = createFakeApi({}, { failures: { bwApply: [new ApiError("bw_session_expired", "Signed out.")] } });
    await expect(api.bwLogins()).rejects.toMatchObject({ code: "bw_session_expired" });
    await signIn(api);
    expect((await api.bwLogins()).map((l) => l.itemId)).toEqual(["v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8"]);
    await expect(api.bwApply([])).rejects.toMatchObject({ code: "bw_session_expired" });
    await expect(api.bwPropose()).rejects.toMatchObject({ code: "bw_session_expired" });
    await signIn(api);
    expect(await api.bwPropose()).toHaveLength(8);
  });

  it("reports download progress, and a held download or sign-in is ended by bwCancel", async () => {
    const api = createFakeApi({}, { hold: { bwPrepare: true, bwLogin: true }, prepareProgress: ["one", "two"] });
    const lines: string[] = [];
    api.onBwProgress((line) => lines.push(line));
    const download = api.bwPrepare().then(() => "done", (e: ApiError) => e.code);
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
    expect(lines).toEqual(["one", "two"]);
    await api.bwCancel();
    expect(await download).toBe("bw_failed");

    const held = signIn(api).then((r) => r.kind);
    await Promise.resolve();
    await Promise.resolve();
    api.release("bwLogin");
    expect(await held).toBe("ok");
  });

  it("refuses a different address once a backup is captured, until the proxy is restarted", async () => {
    const api = createFakeApi();
    await api.startProxy();
    api.emitProxyEvent({ kind: "backupCaptured", count: 3 });
    // The same address is fine: starting is idempotent.
    expect((await api.startProxy("192.168.4.109")).ip).toBe("192.168.4.109");
    expect((await api.startProxy()).ip).toBe("192.168.4.109");
    await expect(api.startProxy("10.0.0.12")).rejects.toMatchObject({ code: "capture_would_be_lost" });
    expect((await api.restartProxy("10.0.0.12")).ip).toBe("10.0.0.12");
    expect((await api.startProxy("192.168.4.109")).ip).toBe("192.168.4.109");
  });

  it("never proposes attaching to a login that already has a code, as the core never does", async () => {
    const api = createFakeApi();
    await signIn(api);
    const proposals = await api.bwPropose();
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
