/// <reference types="vite/client" />
import ts from "typescript";
import { beforeEach, vi } from "vitest";
import type { Api } from "./api";
import apiSource from "./api.ts?raw";
import { createFakeApi } from "./api.fake";
import { createTauriApi } from "./api.tauri";

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

  it("a failed command rejects with an Error carrying the shell's message", async () => {
    const api = createTauriApi();
    invoke.mockRejectedValueOnce("a backup is already captured");
    await expect(api.startProxy("10.0.0.9")).rejects.toThrow("a backup is already captured");
    invoke.mockRejectedValueOnce(new Error("boom"));
    await expect(api.cleanup()).rejects.toThrow("boom");
  });

  it.each([
    ["onProxyEvent", "proxy-event", { kind: "deviceRefused" }],
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

  it("a listen that fails to register is not an unhandled rejection", async () => {
    listen.mockRejectedValue(new Error("no event system"));
    const off = createTauriApi().onBwProgress(() => undefined);
    await Promise.resolve();
    await Promise.resolve();
    expect(() => off()).not.toThrow();
  });
});

describe("api implementations", () => {
  it("api.tauri and api.fake both implement every Api method", () => {
    const methods = apiMethods();
    expect(methods.length).toBeGreaterThanOrEqual(18);
    const implementations: Record<string, Api> = { tauri: createTauriApi(), fake: createFakeApi() };
    for (const [name, api] of Object.entries(implementations)) {
      const missing = methods.filter((m) => typeof (api as unknown as Record<string, unknown>)[m] !== "function");
      expect(missing, `${name} is missing`).toEqual([]);
    }
  });
});
