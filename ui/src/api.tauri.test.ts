/// <reference types="vite/client" />
import ts from "typescript";
import { beforeEach, vi } from "vitest";
import type { Api } from "./api";
import apiSource from "./api.ts?raw";
import { createFakeApi } from "./api.fake";
import { ApiError, ERROR_CODES } from "./api.errors";
import { createTauriApi, toApiError } from "./api.tauri";
import { onListenFailure, resetListenFailure } from "./listenFailure";

const invoke = vi.hoisted(() => vi.fn());
const listen = vi.hoisted(() => vi.fn());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/api/event", () => ({ listen }));

/** The method names of the `Api` interface, read from `api.ts` itself. */
function apiMethods(): string[] {
  const file = ts.createSourceFile("api.ts", apiSource, ts.ScriptTarget.Latest, true);
  const names: string[] = [];
  file.forEachChild((node) => {
    if (ts.isInterfaceDeclaration(node) && node.name.text === "Api") {
      for (const member of node.members) if (ts.isMethodSignature(member)) names.push(member.name.getText(file));
    }
  });
  return names;
}

const snake = (name: string) => name.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`);

beforeEach(() => {
  resetListenFailure();
  invoke.mockReset();
  listen.mockReset();
  invoke.mockResolvedValue(undefined);
});

describe("api.tauri", () => {
  it("every command method invokes the snake_case command with the contract's argument keys", async () => {
    const api = createTauriApi();
    const login = { email: "a@b.c", password: "pw", region: { kind: "eu" as const }, twoFactorCode: "1" };
    const decisions = [{ tokenId: "t", decision: { kind: "skip" as const } }];
    const expected: Record<string, [() => Promise<unknown>, Record<string, unknown> | undefined]> = {
      getState: [() => api.getState(), undefined],
      setDevice: [() => api.setDevice("ipad"), { device: "ipad" }],
      startProxy: [() => api.startProxy("10.0.0.2"), { ip: "10.0.0.2" }],
      restartProxy: [() => api.restartProxy("10.0.0.3"), { ip: "10.0.0.3" }],
      unlock: [() => api.unlock(" pw "), { password: " pw " }],
      tokenQr: [() => api.tokenQr("t1"), { id: "t1" }],
      googleMigrationQrs: [() => api.googleMigrationQrs(), undefined],
      googleUnsupported: [() => api.googleUnsupported(), undefined],
      exportFile: [() => api.exportFile("aegis"), { dest: "aegis" }],
      liveCodes: [() => api.liveCodes(), undefined],
      bwPrepare: [() => api.bwPrepare(), undefined],
      bwCancel: [() => api.bwCancel(), undefined],
      bwLogins: [() => api.bwLogins(), undefined],
      bwLogin: [() => api.bwLogin(login), { login }],
      bwPropose: [() => api.bwPropose(), undefined],
      bwApply: [() => api.bwApply(decisions), { decisions }],
      cleanup: [() => api.cleanup(), undefined],
      finish: [() => api.finish(), undefined],
    };
    // Nothing in the contract is left out of this table except the two subscriptions.
    expect(Object.keys(expected).sort()).toEqual(apiMethods().filter((m) => !m.startsWith("on")).sort());

    for (const [method, [run, args]] of Object.entries(expected)) {
      invoke.mockClear();
      await run();
      expect(invoke, method).toHaveBeenCalledTimes(1);
      expect(invoke, method).toHaveBeenCalledWith(snake(method), args);
    }
  });

  it("passes the command's result through and an omitted address as null", async () => {
    const api = createTauriApi();
    invoke.mockResolvedValueOnce({ ip: "192.168.4.109", port: 8080 });
    expect(await api.startProxy()).toEqual({ ip: "192.168.4.109", port: 8080 });
    expect(invoke).toHaveBeenLastCalledWith("start_proxy", { ip: null });
    await api.restartProxy();
    expect(invoke).toHaveBeenLastCalledWith("restart_proxy", { ip: null });
  });

  it("hands back the newer contract fields untouched: the fingerprint and a refused two-step code", async () => {
    const api = createTauriApi();
    const fingerprint = Array.from({ length: 32 }, () => "AB").join(":");
    invoke.mockResolvedValueOnce({ ip: "192.168.4.109", port: 8080, certFingerprint: fingerprint });
    expect((await api.startProxy()).certFingerprint).toBe(fingerprint);
    invoke.mockResolvedValueOnce({ kind: "badTwoFactorCode" });
    expect(await api.bwLogin({ email: "a@b.c", password: "pw", region: { kind: "us" }, twoFactorCode: "000000" })).toEqual({ kind: "badTwoFactorCode" });
  });

  it("a failed command rejects with a typed error: the shell's code, and its sentence as the message", async () => {
    const api = createTauriApi();
    invoke.mockRejectedValueOnce("capture_would_be_lost: A backup is already captured. Restart the connection to change address.");
    const err = await api.startProxy("10.0.0.9").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err).toMatchObject({ code: "capture_would_be_lost", message: "A backup is already captured. Restart the connection to change address." });
  });

  it("every code the shell uses is recognised, on every command", async () => {
    const api = createTauriApi();
    for (const code of ERROR_CODES) {
      invoke.mockRejectedValueOnce(`${code}: A plain sentence: with a colon in it.`);
      await expect(api.finish()).rejects.toMatchObject({ code, message: "A plain sentence: with a colon in it." });
    }
  });

  it("a rejection with no code, or one the UI does not know, is internal; its raw text goes only to the console", async () => {
    const api = createTauriApi();
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const developerText = "invalid args `login` for command `bw_login`: missing field `region`";
    for (const raw of [developerText, "a backup is already captured", "made_up_code: something else", "Not A Code: text", ": nothing before the colon", "bad_email"]) {
      invoke.mockRejectedValueOnce(raw);
      // The screen gets no message to show: Tauri's own words are not for the person.
      await expect(api.cleanup(), raw).rejects.toMatchObject({ code: "internal", message: "" });
      // A development build keeps them for whoever is fixing it.
      expect(consoleError).toHaveBeenLastCalledWith(expect.any(String), raw);
    }
    invoke.mockRejectedValueOnce(new Error("boom"));
    await expect(api.cleanup()).rejects.toMatchObject({ code: "internal", message: "" });
    consoleError.mockRestore();
    invoke.mockRejectedValueOnce({ unexpected: true });
    await expect(api.cleanup()).rejects.toBeInstanceOf(ApiError);
    invoke.mockRejectedValueOnce(undefined);
    await expect(api.cleanup()).rejects.toMatchObject({ code: "internal" });
  });

  it("the parser keeps a sentence that spans lines and trims nothing inside it", () => {
    expect(toApiError("bw_failed: line one\nline two")).toMatchObject({ code: "bw_failed", message: "line one\nline two" });
    // A missing space after the colon is forgiven; an empty sentence is still that code.
    expect(toApiError("export_failed:no space")).toMatchObject({ code: "export_failed", message: "no space" });
    expect(toApiError("no_backup: ")).toMatchObject({ code: "no_backup", message: "" });
    const already = new ApiError("no_backup", "x");
    expect(toApiError(already)).toBe(already);
  });

  it("hands back the newest contract fields untouched: the session snapshot, the certificate mode, the vault list and needsApiKey", async () => {
    const api = createTauriApi();
    const session = { proxy: null, deviceConnected: true, trustWorking: false, captured: 3, summary: null };
    invoke.mockResolvedValueOnce({ step: "authy", device: "ipad", resumeCleanup: false, version: "1", releasesUrl: "u", session });
    expect((await api.getState()).session).toEqual(session);
    invoke.mockResolvedValueOnce({ ip: "192.168.4.109", port: 8080, certConstrained: false });
    expect((await api.startProxy()).certConstrained).toBe(false);
    invoke.mockResolvedValueOnce({ kind: "needsApiKey" });
    const login = { email: "a@b.c", password: "pw", region: { kind: "us" as const }, apiKey: { clientId: "user.1", clientSecret: "s" } };
    expect(await api.bwLogin(login)).toEqual({ kind: "needsApiKey" });
    expect(invoke).toHaveBeenLastCalledWith("bw_login", { login });
    const vault = [{ itemId: "v1", name: "GitHub", username: null, hasCode: true }];
    invoke.mockResolvedValueOnce(vault);
    expect(await api.bwLogins()).toEqual(vault);
  });

  it.each([
    ["onProxyEvent", "proxy-event", { kind: "deviceRefused" }],
    ["onProxyEvent", "proxy-event", { kind: "emptyBackup" }],
    ["onProxyEvent", "proxy-event", { kind: "addressChanged" }],
    ["onBwProgress", "bw-progress", "Attached GitHub"],
  ] as const)("%s listens to %s, delivers payloads, and unsubscribes", async (method, event, payload) => {
    const unlisten = vi.fn();
    let handler: ((e: { payload: unknown }) => void) | undefined;
    listen.mockImplementation(async (_name: string, h: (e: { payload: unknown }) => void) => { handler = h; return unlisten; });

    const seen: unknown[] = [];
    const api = createTauriApi();
    const off = (api[method] as (cb: (p: unknown) => void) => () => void)((p) => seen.push(p));
    expect(listen).toHaveBeenCalledWith(event, expect.any(Function));
    await Promise.resolve();
    await Promise.resolve();

    handler!({ payload });
    expect(seen).toEqual([payload]);

    off();
    expect(unlisten).toHaveBeenCalledTimes(1);
    handler!({ payload });
    expect(seen).toHaveLength(1);
  });

  it("unsubscribing before listen resolves still removes the listener and delivers nothing", async () => {
    const unlisten = vi.fn();
    let resolve!: (off: () => void) => void;
    let handler: ((e: { payload: unknown }) => void) | undefined;
    listen.mockImplementation((_name: string, h: (e: { payload: unknown }) => void) => {
      handler = h;
      return new Promise<() => void>((r) => { resolve = r; });
    });

    const seen: unknown[] = [];
    const off = createTauriApi().onProxyEvent((e) => seen.push(e));
    off();
    expect(unlisten).not.toHaveBeenCalled();

    resolve(unlisten);
    await Promise.resolve();
    await Promise.resolve();
    expect(unlisten).toHaveBeenCalledTimes(1);
    handler!({ payload: { kind: "deviceConnected" } });
    expect(seen).toEqual([]);
  });

  it("a listen that fails to register is not an unhandled rejection, and is reported for the screen", async () => {
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const heard = vi.fn();
    const stop = onListenFailure(heard);
    listen.mockRejectedValue(new Error("no event system"));
    const off = createTauriApi().onBwProgress(() => undefined);
    await vi.waitFor(() => expect(heard).toHaveBeenCalledTimes(1));
    expect(() => off()).not.toThrow();
    stop();
    consoleError.mockRestore();
  });
});

describe("api implementations", () => {
  it("api.tauri and api.fake both implement every Api method", () => {
    const methods = apiMethods();
    expect(methods.length).toBeGreaterThanOrEqual(20);
    const implementations: Record<string, Api> = { tauri: createTauriApi(), fake: createFakeApi() };
    for (const [name, api] of Object.entries(implementations)) {
      const missing = methods.filter((m) => typeof (api as unknown as Record<string, unknown>)[m] !== "function");
      expect(missing, `${name} is missing`).toEqual([]);
    }
  });
});
