// A reload of the window mid-run: the shell still holds the proxy, the device and the capture,
// and the wizard must come back where it was, without starting anything over.
import { act, cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { App } from "./App";
import { en } from "./strings/en";
import { mountApp, reload, tickAllChecks, walkTo } from "./test-utils";

const ipad = en.deviceName.ipad;
const count = (api: { calls: { method: string }[] }, method: string) => api.calls.filter((c) => c.method === method).length;

describe("reload recovery", () => {
  it("at Connect: the same Server and Port are shown, the device choice is kept, and nothing is restarted", async () => {
    const { api } = await walkTo("connect", {}, "ipad");
    await reload(api);
    expect(screen.getByRole("heading", { level: 1, name: en.connect.title(ipad) })).toBeInTheDocument();
    const values = screen.getByRole("group", { name: en.connect.valuesLabel(ipad) });
    expect(within(values).getByText("192.168.4.109")).toBeInTheDocument();
    expect(screen.getByText(en.common.reloaded(ipad))).toBeInTheDocument();
    // The proxy was started once, by the first window. The second only read the state.
    expect(count(api, "startProxy")).toBe(1);
    expect(count(api, "restartProxy")).toBe(0);
    expect(count(api, "cleanup")).toBe(0);
    // And it still listens: the device connecting moves it on.
    act(() => api.emitProxyEvent({ kind: "deviceConnected" }));
    await screen.findByRole("heading", { level: 1, name: en.certificate.title });
  });

  it("at Certificate: back on Certificate with the QR code and the fingerprint", async () => {
    const { api } = await walkTo("certificate", {}, "ipad");
    await reload(api);
    expect(screen.getByRole("heading", { level: 1, name: en.certificate.title })).toBeInTheDocument();
    expect(screen.getByAltText(en.certificate.qrAlt)).toBeInTheDocument();
    expect(screen.getByTestId("fingerprint")).toBeInTheDocument();
    expect(screen.getByText(en.certificate.connected(ipad))).toBeInTheDocument();
    expect(count(api, "startProxy")).toBe(1);
    act(() => api.emitProxyEvent({ kind: "trustWorking" }));
    await screen.findByRole("heading", { level: 1, name: en.authy.title });
  });

  it("at Reinstall Authy: back there, and not told a second time that Authy is about to be deleted", async () => {
    const { api } = await walkTo("authy");
    await reload(api);
    expect(screen.getByRole("heading", { level: 1, name: en.authy.title })).toBeInTheDocument();
    expect(screen.queryByText(en.authy.lastCheck.title)).not.toBeInTheDocument();
    expect(screen.getByText(en.common.reloaded(en.deviceName.iphone))).toBeInTheDocument();
    expect(count(api, "startProxy")).toBe(1);
    act(() => api.emitProxyEvent({ kind: "backupCaptured", count: 6 }));
    await screen.findByRole("heading", { level: 1, name: en.unlock.title });
  });

  it("at Unlock: the captured count comes from the shell, and unlocking works without capturing again", async () => {
    const { api } = await walkTo("unlock");
    await reload(api);
    const user = userEvent.setup();
    expect(screen.getByRole("heading", { level: 1, name: en.unlock.title })).toBeInTheDocument();
    expect(screen.getByText(en.unlock.captured(10))).toBeInTheDocument();
    expect(count(api, "restartProxy")).toBe(0);
    await user.type(screen.getByLabelText(en.unlock.label), api.script.password);
    await user.click(screen.getByRole("button", { name: en.unlock.submit }));
    await screen.findByRole("heading", { level: 1, name: en.destination.title });
  });

  it("at Move codes: the accounts are still listed, and cleanup later asks about a file it cannot know of", async () => {
    const { api } = await walkTo("destination");
    await reload(api);
    const user = userEvent.setup();
    expect(screen.getByRole("heading", { level: 1, name: en.destination.title })).toBeInTheDocument();
    expect(screen.getByText(en.destination.lede(8))).toBeInTheDocument();
    expect(screen.getByText(en.destination.native("Twitch"))).toBeInTheDocument();
    expect(count(api, "unlock")).toBe(1);
    expect(count(api, "cleanup")).toBe(0);

    await user.click(screen.getByRole("button", { name: en.common.stopAndCleanUp }));
    await user.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: en.common.stopAndCleanUp }));
    await screen.findByRole("heading", { level: 1, name: en.cleanup.title });
    expect(screen.getByRole("checkbox", { name: new RegExp(en.cleanup.items.fileDeletedMaybe.label) })).toBeInTheDocument();
  });

  it("at Clean up: stays on Clean up, says the window was reloaded, and asks about everything", async () => {
    const { api } = await walkTo("cleanup");
    await screen.findByText(en.cleanup.clean(en.deviceName.iphone));
    await reload(api);
    expect(screen.getByRole("heading", { level: 1, name: en.cleanup.title })).toBeInTheDocument();
    expect(screen.getByText(en.cleanup.reloaded)).toBeInTheDocument();
    expect(screen.queryByText(en.cleanup.resumed)).not.toBeInTheDocument();
    expect(screen.getAllByRole("checkbox")).toHaveLength(4);
    expect(count(api, "startProxy")).toBe(1);
  });

  it("a reload never begins the cleanup by itself, even if the shell also reports an unfinished run", async () => {
    const { api } = await walkTo("unlock");
    // What a shell that reports the marker live would say: resume, and a proxy still running.
    const real = api.getState.bind(api);
    api.getState = async () => ({ ...(await real()), resumeCleanup: true });
    await reload(api);
    expect(screen.getByRole("heading", { level: 1, name: en.unlock.title })).toBeInTheDocument();
    expect(count(api, "cleanup")).toBe(0);
  });

  it("a reload during a cleanup the shell is still doing stays on Clean up, even with the proxy still reported", async () => {
    const { api } = await walkTo("unlock");
    const real = api.getState.bind(api);
    api.getState = async () => ({ ...(await real()), step: "cleanup" });
    await reload(api);
    expect(screen.getByRole("heading", { level: 1, name: en.cleanup.title })).toBeInTheDocument();
    expect(screen.getByText(en.cleanup.reloaded)).toBeInTheDocument();
  });

  it("a snapshot that missed the proxy for a moment is asked for again before deciding", async () => {
    const { api } = await walkTo("unlock");
    const real = api.getState.bind(api);
    let asked = 0;
    // The first answer after the reload is what the shell says while its lock is held: no
    // proxy, and nothing else that points at a run.
    api.getState = async () => {
      const state = await real();
      asked += 1;
      return asked === 1
        ? { ...state, step: "welcome", session: { proxy: null, deviceConnected: false, trustWorking: false, captured: 0, summary: null } }
        : state;
    };
    cleanup();
    render(<App api={api} />);
    await screen.findByRole("heading", { level: 1, name: en.unlock.title }, { timeout: 2000 });
    expect(asked).toBe(2);
    expect(count(api, "restartProxy")).toBe(0);
  });

  it("a reload while the first start has not answered yet keeps the device and the ticks", async () => {
    const h = await mountApp();
    await h.user.click(screen.getByRole("radio", { name: en.deviceName.ipad }));
    await tickAllChecks(h.user);
    // The shell's start has not answered yet, and the snapshot has no proxy.
    let release = () => undefined as void;
    const start = h.api.startProxy.bind(h.api);
    h.api.startProxy = (ip?: string) => new Promise((resolve, reject) => { release = () => { start(ip).then(resolve, reject); }; });
    await h.user.click(screen.getByRole("button", { name: en.welcome.start }));
    await screen.findByRole("heading", { level: 1, name: en.connect.title(ipad) });

    await reload(h.api);
    await screen.findByRole("heading", { level: 1, name: en.welcome.title }, { timeout: 2000 });
    expect(screen.getByRole("radio", { name: en.deviceName.ipad })).toBeChecked();
    for (const box of screen.getAllByRole("checkbox")) expect(box).toBeChecked();
    const startButton = screen.getByRole("button", { name: en.welcome.start });
    expect(startButton).toBeEnabled();
    // Start again joins the start that is still waiting.
    await h.user.click(startButton);
    act(() => release());
    await screen.findByText(en.connect.waiting(ipad));
  });

  it("a reload after the run is finished does not tick the safety checks for a new run", async () => {
    const { api, user } = await walkTo("cleanup");
    await screen.findByText(en.cleanup.clean(en.deviceName.iphone));
    for (const box of screen.getAllByRole("checkbox")) await user.click(box);
    await user.click(screen.getByRole("button", { name: en.cleanup.finish }));
    await screen.findByRole("heading", { level: 1, name: en.done.title });
    expect(sessionStorage.length).toBe(0);

    await reload(api);
    await screen.findByRole("heading", { level: 1, name: en.welcome.title });
    for (const box of screen.getAllByRole("checkbox")) expect(box).not.toBeChecked();
    expect(screen.getByRole("button", { name: en.welcome.start })).toBeDisabled();
  });

  it("the fake reports a fresh run as the shell does: a first start does not mark it for resume", async () => {
    const { api } = await walkTo("connect");
    expect((await api.getState()).resumeCleanup).toBe(false);
  });
});
