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
});
