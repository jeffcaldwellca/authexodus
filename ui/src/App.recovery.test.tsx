// A reload of the window mid-run: the shell still holds the proxy, the device and the capture,
// and the wizard must come back where it was, without starting anything over.
import { act, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { en } from "./strings/en";
import { reload, walkTo } from "./test-utils";

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

  it("the fake reports a fresh run as the shell does: a first start does not mark it for resume", async () => {
    const { api } = await walkTo("connect");
    expect((await api.getState()).resumeCleanup).toBe(false);
  });
});
