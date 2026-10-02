// Ways through, back and out of the wizard that a person needs and the first build lacked.
import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { vi } from "vitest";
import { createFakeApi } from "./api.fake";
import { en } from "./strings/en";
import { Authy, STILL_WAITING_MS } from "./screens/Authy";
import { mountApp, moveByQr, walkTo } from "./test-utils";
import { initialState, type WizardState } from "./wizard/machine";

const iphone = en.deviceName.iphone;
const ipad = en.deviceName.ipad;

async function stopFromDestination(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole("button", { name: en.common.stopAndCleanUp }));
  await user.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: en.common.stopAndCleanUp }));
  await screen.findByRole("heading", { level: 1, name: en.cleanup.title });
}

async function finishCleanup(user: ReturnType<typeof userEvent.setup>, d: string) {
  await screen.findByText(en.cleanup.clean(d));
  for (const box of screen.getAllByRole("checkbox")) await user.click(box);
  await user.click(screen.getByRole("button", { name: en.cleanup.finish }));
}

describe("ways out and back", () => {
  it("the Authy step's help sheet says by hand that the method may no longer work, with the manual route", async () => {
    const { user } = await walkTo("authy");
    // No refusal has been seen: this is the case where Authy just drops the connection.
    expect(screen.queryByText(en.failures.methodBroken.title)).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: en.common.havingTrouble }));
    const sheet = screen.getByRole("dialog", { name: en.failures.sheetTitle });
    const panel = within(sheet).getByText(en.failures.methodBroken.title).closest("details")!;
    expect(panel).not.toHaveAttribute("open");
    await user.click(within(sheet).getByText(en.failures.methodBroken.title));
    expect(panel).toHaveAttribute("open");
    expect(within(panel).getByText(en.failures.methodBroken.next)).toBeInTheDocument();
    expect(within(panel).getByText(en.manual.steps[0])).toBeInTheDocument();
    // And the empty-backup advice is there to open too.
    expect(within(sheet).getByText(en.failures.emptyBackup.title)).toBeInTheDocument();
  });

  it("Destination can be left without moving anything: Stop and clean up, with the confirmation", async () => {
    const { api, user } = await walkTo("destination");
    const stop = screen.getByRole("button", { name: en.common.stopAndCleanUp });
    await user.click(stop);
    const confirm = screen.getByRole("alertdialog", { name: en.failures.stop.title });
    expect(within(confirm).getByText(en.common.authyFinish)).toBeInTheDocument();
    await user.click(within(confirm).getByRole("button", { name: en.common.keepGoing }));
    expect(screen.getByRole("heading", { level: 1, name: en.destination.title })).toBeInTheDocument();
    expect(api.calls.some((c) => c.method === "cleanup")).toBe(false);

    await stopFromDestination(user);
    expect(api.calls.filter((c) => c.method === "cleanup")).toHaveLength(1);
    await finishCleanup(user, iphone);
    await screen.findByRole("heading", { level: 1, name: en.done.titleNothingMoved });
    expect(en.destination.continueBlocked).toMatch(/To leave without moving anything, choose Stop and clean up/);
  });

  it("Destination goes back to Unlock while nothing has been moved, and not after", async () => {
    const { api, user } = await walkTo("destination");
    await user.click(screen.getByRole("button", { name: en.destination.backToUnlock }));
    await screen.findByRole("heading", { level: 1, name: en.unlock.title });
    expect(screen.getByText(en.unlock.captured(10))).toBeInTheDocument();
    await user.type(screen.getByLabelText(en.unlock.label), api.script.password);
    await user.click(screen.getByRole("button", { name: en.unlock.submit }));
    await screen.findByRole("heading", { level: 1, name: en.destination.title });

    await moveByQr(user);
    expect(screen.queryByRole("button", { name: en.destination.backToUnlock })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: en.common.stopAndCleanUp })).toBeInTheDocument();
  });

  it("Check the codes leads back to Move codes for a second app, through the screen", async () => {
    const { user } = await walkTo("verify");
    await user.click(screen.getByRole("button", { name: en.verify.another }));
    await screen.findByRole("heading", { level: 1, name: en.destination.title });
    // Something was moved already, so the way forward is open at once.
    const go = screen.getByRole("button", { name: en.destination.continue });
    expect(go).toBeEnabled();
    await user.click(go);
    await screen.findByRole("heading", { level: 1, name: en.verify.title });
  });

  it("the way a destination was used is marked when the person comes back to the choices", async () => {
    const { user } = await walkTo("destination");
    expect(screen.queryByText(en.destination.usedTag)).not.toBeInTheDocument();
    await moveByQr(user);
    const qr = screen.getByRole("button", { name: new RegExp(en.destination.options.qr.title) });
    expect(within(qr).getByText(en.destination.usedTag)).toBeInTheDocument();
    expect(within(screen.getByRole("button", { name: new RegExp(en.destination.options.file.title) })).queryByText(en.destination.usedTag)).not.toBeInTheDocument();
  });

  it("Unlock shows a count that keeps up with the capture, and offers to capture again", async () => {
    const { api, user } = await walkTo("unlock");
    expect(screen.getByText(en.unlock.captured(10))).toBeInTheDocument();
    act(() => api.emitProxyEvent({ kind: "backupCaptured", count: 14 }));
    expect(await screen.findByText(en.unlock.captured(14))).toBeInTheDocument();

    await user.click(screen.getByText(en.unlock.recapture.title));
    expect(screen.getByText(en.unlock.recapture.body(iphone))).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: en.unlock.recapture.action }));
    await screen.findByRole("heading", { level: 1, name: en.connect.title(iphone) });
    expect(api.calls.find((c) => c.method === "restartProxy")?.args).toEqual(["192.168.4.109"]);
    expect(screen.getByText(en.failures.restart.noticeAfterTrust(iphone))).toBeInTheDocument();
  });

  it("the device choice can be put right on Connect and Certificate, and the screens follow", async () => {
    const { api, user } = await walkTo("connect");
    await user.click(screen.getByRole("button", { name: en.common.switchDevice(ipad) }));
    await screen.findByRole("heading", { level: 1, name: en.connect.title(ipad) });
    expect(screen.getByText(en.connect.steps.wifi.ipad)).toBeInTheDocument();
    expect(api.calls.filter((c) => c.method === "setDevice").map((c) => c.args[0])).toEqual(["iphone", "ipad"]);
    expect(en.common.switchDevice(ipad)).toBe("Using an iPad instead?");

    act(() => api.emitProxyEvent({ kind: "deviceConnected" }));
    await screen.findByRole("heading", { level: 1, name: en.certificate.title });
    expect(screen.getByText(en.certificate.connected(ipad))).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: en.common.switchDevice(iphone) }));
    expect(await screen.findByText(en.certificate.connected(iphone))).toBeInTheDocument();

    // Once Authy is to be deleted, the choice is settled.
    act(() => api.emitProxyEvent({ kind: "trustWorking" }));
    await screen.findByRole("heading", { level: 1, name: en.authy.title });
    expect(screen.queryByRole("button", { name: en.common.switchDevice(ipad) })).not.toBeInTheDocument();
  });

  it("Done offers a fresh run, says what that involves, and a fresh run starts a new connection", async () => {
    const { api, user } = await walkTo("cleanup");
    await finishCleanup(user, iphone);
    await screen.findByRole("heading", { level: 1, name: en.done.title });
    expect(screen.getByText(en.done.again(iphone))).toBeInTheDocument();
    expect(en.done.again(iphone)).toMatch(/has forgotten your codes/);
    expect(en.done.again(iphone)).toMatch(/delete and reinstall Authy once more/);
    // The codes are gone from the app, so it must not offer to move them anywhere.
    expect(screen.queryByRole("button", { name: en.verify.another })).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: en.done.startAgain }));
    await screen.findByRole("heading", { level: 1, name: en.welcome.title });
    // Every check has to be made again; the device is remembered.
    expect(screen.getByRole("radio", { name: iphone })).toBeChecked();
    for (const box of screen.getAllByRole("checkbox")) expect(box).not.toBeChecked();
    expect(screen.getByRole("button", { name: en.welcome.start })).toBeDisabled();

    for (const box of screen.getAllByRole("checkbox")) await user.click(box);
    await user.click(screen.getByRole("button", { name: en.welcome.start }));
    await screen.findByText(en.connect.waiting(iphone));
    expect(api.calls.filter((c) => c.method === "startProxy")).toHaveLength(2);
    expect(screen.queryByText(en.failures.restart.noticeAfterTrust(iphone))).not.toBeInTheDocument();
  });

  it("Done after giving up offers the fresh run too", async () => {
    const { user } = await walkTo("destination");
    await stopFromDestination(user);
    await finishCleanup(user, iphone);
    await screen.findByRole("heading", { level: 1, name: en.done.titleNothingMoved });
    expect(screen.getByRole("button", { name: en.done.startAgain })).toBeInTheDocument();
  });

  it("the names of the accounts that could not move are kept through Clean up and Done", async () => {
    const { user } = await walkTo("verify");
    await user.click(screen.getByRole("button", { name: en.verify.confirm }));
    const section = await screen.findByRole("region", { name: en.cleanup.cantMoveTitle(2) });
    expect(within(section).getByText("Twitch")).toBeInTheDocument();
    expect(within(section).getByText("Old VPN")).toBeInTheDocument();
    expect(within(section).getByText(en.cleanup.cantMoveLede)).toBeInTheDocument();

    await finishCleanup(user, iphone);
    await screen.findByRole("heading", { level: 1, name: en.done.title });
    const list = screen.getByRole("list", { name: en.done.notMovedLabel });
    expect(within(list).getAllByRole("listitem").map((li) => li.textContent)).toEqual(["Twitch", "Old VPN"]);
  });

  it("an empty backup is explained, with how to turn backups on and the restart", async () => {
    const { api, user } = await walkTo("authy");
    act(() => api.emitProxyEvent({ kind: "emptyBackup" }));
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByRole("heading", { name: en.failures.emptyBackup.title })).toBeInTheDocument();
    expect(within(alert).getByText(en.failures.emptyBackup.body)).toBeInTheDocument();
    expect(en.failures.emptyBackup.body).toMatch(/Backups are probably turned off/);
    for (const step of en.failures.emptyBackup.steps(iphone)) expect(within(alert).getByText(step)).toBeInTheDocument();
    expect(en.failures.emptyBackup.steps(iphone).join(" ")).toMatch(/Authenticator Backups/);

    await user.click(within(alert).getByRole("button", { name: en.common.restart }));
    await screen.findByRole("heading", { level: 1, name: en.connect.title(iphone) });
    expect(api.calls.filter((c) => c.method === "restartProxy")).toHaveLength(1);
    // The explanation does not follow the person back to the Authy step.
    act(() => api.emitProxyEvent({ kind: "trustWorking" }));
    await screen.findByRole("heading", { level: 1, name: en.authy.title });
    expect(screen.queryByRole("heading", { name: en.failures.emptyBackup.title })).not.toBeInTheDocument();
  });

  it("when every account is one that cannot be copied, the screen says so and goes straight to clean up", async () => {
    const { api, user } = await walkTo("unlock", {
      summary: { tokens: [], native: [{ name: "Twitch" }, { name: "Authy Demo" }], invalid: [] },
    });
    await user.type(screen.getByLabelText(en.unlock.label), api.script.password);
    await user.click(screen.getByRole("button", { name: en.unlock.submit }));

    await screen.findByRole("heading", { level: 1, name: en.destination.noneTitle });
    expect(screen.getByText(en.destination.noneCantMove)).toBeInTheDocument();
    expect(screen.getByText(en.destination.native("Twitch"))).toBeInTheDocument();
    expect(screen.getByText(en.destination.native("Authy Demo"))).toBeInTheDocument();
    expect(screen.getByText(en.manual.steps[0])).toBeInTheDocument();
    expect(screen.getByText(en.destination.authyTitle)).toBeInTheDocument();
    // None of the four ways is offered, and there are no codes to check.
    expect(screen.queryByRole("button", { name: new RegExp(en.destination.options.qr.title) })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: en.destination.continue })).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: en.destination.toCleanup }));
    await screen.findByRole("heading", { level: 1, name: en.cleanup.title });
    expect(api.calls.some((c) => c.method === "liveCodes")).toBe(false);
    expect(within(screen.getByRole("region", { name: en.cleanup.cantMoveTitle(2) })).getByText("Authy Demo")).toBeInTheDocument();
    await finishCleanup(user, iphone);
    await screen.findByRole("heading", { level: 1, name: en.done.titleNothingMoved });
    expect(within(screen.getByRole("list", { name: en.done.notMovedLabel })).getByText("Twitch")).toBeInTheDocument();
  });

  it("keeps the person told to leave the window open and the Mac awake, from Connect to Check codes only", async () => {
    const banner = () => screen.queryByRole("note");
    const { api, user } = await mountApp();
    expect(banner()).not.toBeInTheDocument();
    await user.click(screen.getByRole("radio", { name: iphone }));
    for (const box of screen.getAllByRole("checkbox")) await user.click(box);
    await user.click(screen.getByRole("button", { name: en.welcome.start }));
    await screen.findByText(en.connect.waiting(iphone));
    expect(banner()).toHaveTextContent(en.common.keepOpen(iphone));
    expect(en.common.keepOpen(iphone)).toMatch(/^Keep this window open and this Mac awake and plugged in until you finish\./);
    expect(en.common.keepOpen(iphone)).toMatch(/Do not close the lid/);

    act(() => api.emitProxyEvent({ kind: "deviceConnected" }));
    await screen.findByRole("heading", { level: 1, name: en.certificate.title });
    expect(banner()).toBeInTheDocument();
    act(() => api.emitProxyEvent({ kind: "trustWorking" }));
    await screen.findByRole("heading", { level: 1, name: en.authy.title });
    expect(banner()).toBeInTheDocument();
    act(() => api.emitProxyEvent({ kind: "backupCaptured", count: 3 }));
    await screen.findByRole("heading", { level: 1, name: en.unlock.title });
    expect(banner()).toBeInTheDocument();
    await user.type(screen.getByLabelText(en.unlock.label), api.script.password);
    await user.click(screen.getByRole("button", { name: en.unlock.submit }));
    await screen.findByRole("heading", { level: 1, name: en.destination.title });
    expect(banner()).toBeInTheDocument();
    await moveByQr(user);
    await user.click(screen.getByRole("button", { name: en.destination.continue }));
    await screen.findByRole("heading", { level: 1, name: en.verify.title });
    expect(banner()).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: en.verify.confirm }));
    await screen.findByRole("heading", { level: 1, name: en.cleanup.title });
    expect(banner()).not.toBeInTheDocument();
  });

  it("the version and the releases address are outside the step list, so a narrow window still shows them", async () => {
    await mountApp({ version: "1.4.2", releasesUrl: "https://example.com/authexodus/releases" });
    const version = screen.getByText(en.rail.version("1.4.2"));
    const rail = screen.getByRole("navigation", { name: en.rail.label });
    expect(rail).not.toContainElement(version);
    expect(rail).not.toContainElement(screen.getByText("https://example.com/authexodus/releases"));
    expect(version.closest(".version")).not.toBeNull();
  });

  it("cleanup asks for the profile to be removed once the certificate step was reached", async () => {
    const { user } = await walkTo("certificate");
    await user.click(screen.getByRole("button", { name: en.common.havingTrouble }));
    await user.click(screen.getByRole("button", { name: en.common.stopAndCleanUp }));
    await user.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: en.common.stopAndCleanUp }));
    await screen.findByRole("heading", { level: 1, name: en.cleanup.title });
    expect(screen.getByRole("checkbox", { name: new RegExp(en.cleanup.items.profileRemoved.label) })).toBeInTheDocument();
    expect(screen.queryByText(en.cleanup.noCertificate(iphone))).not.toBeInTheDocument();
    // A limited certificate: nothing extra is said.
    expect(screen.queryByText(new RegExp(en.cleanup.unconstrained))).not.toBeInTheDocument();
  });

  it("a certificate that was not limited to Authy gets a stronger line on the cleanup item", async () => {
    const { user } = await walkTo("cleanup", { certConstrained: false });
    await screen.findByText(en.cleanup.clean(iphone));
    const item = screen.getByRole("checkbox", { name: new RegExp(en.cleanup.items.profileRemoved.label) });
    expect(item).toHaveAccessibleName(new RegExp(en.cleanup.unconstrained));
    expect(en.cleanup.unconstrained).toBe("This certificate was not limited to Authy, so removing it matters even more.");
    void user;
  });

  it("a resumed cleanup asks which device was used, and then speaks of that device", async () => {
    const { user } = await mountApp({ resumeCleanup: true });
    await screen.findByText(en.cleanup.clean(en.deviceName.either));
    const group = screen.getByRole("group", { name: en.cleanup.deviceQuestion });
    expect(screen.getByText(en.cleanup.todo(en.deviceName.either))).toBeInTheDocument();
    await user.click(within(group).getByRole("radio", { name: ipad }));
    expect(await screen.findByText(en.cleanup.todo(ipad))).toBeInTheDocument();
    expect(screen.getByText(en.cleanup.clean(ipad))).toBeInTheDocument();
    expect(screen.getByRole("img", { name: en.device.alt.proxyOff(ipad) })).toBeInTheDocument();
    // Asked once: the question goes away when it is answered.
    expect(screen.queryByRole("group", { name: en.cleanup.deviceQuestion })).not.toBeInTheDocument();
  });

  it("a dialog keeps Tab inside itself, in both directions", async () => {
    const { user } = await walkTo("connect");
    await user.click(screen.getByRole("button", { name: en.common.havingTrouble }));
    const sheet = screen.getByRole("dialog", { name: en.failures.sheetTitle });
    expect(sheet).toHaveFocus();
    const close = within(sheet).getByRole("button", { name: en.common.close });
    const stop = within(sheet).getByRole("button", { name: en.common.stopAndCleanUp });

    // Backwards from the dialog itself wraps to its last control, not out to the page behind.
    await user.tab({ shift: true });
    expect(stop).toHaveFocus();
    // Forwards from the last control wraps to the first.
    await user.tab();
    expect(close).toHaveFocus();
    // And backwards from the first goes to the last again.
    await user.tab({ shift: true });
    expect(stop).toHaveFocus();
    // Tabbing through every control never leaves the dialog.
    for (let i = 0; i < 12; i++) {
      await user.tab();
      expect(sheet).toContainElement(document.activeElement as HTMLElement);
    }
  });

  it("one whole run in the iPad frame: every sentence and every drawing is the iPad's", async () => {
    const { api, user } = await walkTo("connect", {}, "ipad");
    const drawing = (name: string) => screen.getByRole("img", { name });
    expect(screen.getByText(en.connect.steps.wifi.ipad)).toBeInTheDocument();
    expect(drawing(en.device.alt.wifiOpen(ipad))).toHaveAttribute("data-device", "ipad");
    expect(screen.getByText(en.common.keepOpen(ipad))).toBeInTheDocument();

    act(() => api.emitProxyEvent({ kind: "deviceConnected" }));
    await screen.findByRole("heading", { level: 1, name: en.certificate.title });
    expect(screen.getByText(en.certificate.connected(ipad))).toBeInTheDocument();
    expect(screen.getByText(en.certificate.steps.trust(ipad))).toBeInTheDocument();
    expect(screen.getByText(en.certificate.fingerprintHow(ipad))).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: en.certificate.steps.trust(ipad) }));
    expect(drawing(en.device.alt.trustSettings(ipad))).toHaveAttribute("data-device", "ipad");

    act(() => api.emitProxyEvent({ kind: "trustWorking" }));
    await screen.findByRole("heading", { level: 1, name: en.authy.title });
    expect(screen.getByText(en.authy.steps.remove(ipad))).toBeInTheDocument();
    expect(drawing(en.device.alt.authyPrompt(ipad))).toHaveAttribute("data-device", "ipad");

    act(() => api.emitProxyEvent({ kind: "backupCaptured", count: 10 }));
    await screen.findByRole("heading", { level: 1, name: en.unlock.title });
    expect(screen.getByText(en.unlock.alsoAuthy(ipad))).toBeInTheDocument();
    await user.type(screen.getByLabelText(en.unlock.label), api.script.password);
    await user.click(screen.getByRole("button", { name: en.unlock.submit }));

    await screen.findByRole("heading", { level: 1, name: en.destination.title });
    expect(screen.getByText(en.destination.authyBody(ipad))).toBeInTheDocument();
    await moveByQr(user);
    await user.click(screen.getByRole("button", { name: en.destination.continue }));
    await user.click(await screen.findByRole("button", { name: en.verify.confirm }));

    await screen.findByText(en.cleanup.clean(ipad));
    expect(screen.getByText(en.cleanup.noInternet(ipad))).toBeInTheDocument();
    expect(screen.getByText(en.cleanup.todo(ipad))).toBeInTheDocument();
    expect(drawing(en.device.alt.proxyOff(ipad))).toHaveAttribute("data-device", "ipad");
    await user.click(screen.getByRole("button", { name: en.common.showPictureFor(en.cleanup.items.profileRemoved.label) }));
    expect(drawing(en.device.alt.deviceManagement(ipad))).toHaveAttribute("data-device", "ipad");
    for (const box of screen.getAllByRole("checkbox")) await user.click(box);
    await user.click(screen.getByRole("button", { name: en.cleanup.finish }));
    await screen.findByRole("heading", { level: 1, name: en.done.title });
    expect(screen.getByText(en.done.body(ipad))).toBeInTheDocument();
    // Nowhere did the run fall back to the other device's name.
    expect(document.body.textContent).not.toMatch(/iPhone/);
  });
});

describe("the Authy step when nothing arrives", () => {
  afterEach(() => { vi.useRealTimers(); });

  function mountAuthy(over: Partial<WizardState> = {}) {
    const api = createFakeApi();
    const onRestart = vi.fn();
    const state: WizardState = { ...initialState(), step: "authy", device: "iphone", trustProven: true, reachedAuthy: true, ...over };
    render(<Authy api={api} state={state} dispatch={() => undefined} proxy={null} onRestart={onRestart} restart="idle" restartError={null} certConstrained={true} />);
    return { onRestart };
  }

  it("says nothing for three minutes, then points at the help sheet and the restart", async () => {
    vi.useFakeTimers();
    const { onRestart } = mountAuthy();
    expect(STILL_WAITING_MS).toBe(180_000);
    await act(async () => { await vi.advanceTimersByTimeAsync(STILL_WAITING_MS - 1000); });
    expect(screen.queryByText(en.authy.stillWaiting.title)).not.toBeInTheDocument();

    await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
    const hint = screen.getByText(en.authy.stillWaiting.title).closest("[role=alert]") as HTMLElement;
    expect(within(hint).getByText(en.authy.stillWaiting.body(iphone))).toBeInTheDocument();
    expect(en.authy.stillWaiting.body(iphone)).toMatch(/Open Having trouble\?/);
    expect(en.authy.stillWaiting.body(iphone)).toMatch(/if this method no longer works with Authy/);
    expect(en.authy.stillWaiting.body(iphone)).toMatch(/restart the connection/);
    vi.useRealTimers();
    await userEvent.setup().click(within(hint).getByRole("button", { name: en.common.restart }));
    expect(onRestart).toHaveBeenCalledTimes(1);
  });

  it("does not start counting until trust has been proven", async () => {
    vi.useFakeTimers();
    mountAuthy({ trustProven: false });
    await act(async () => { await vi.advanceTimersByTimeAsync(STILL_WAITING_MS * 2); });
    expect(screen.queryByText(en.authy.stillWaiting.title)).not.toBeInTheDocument();
  });

  it("gives way to a more specific explanation when there is one", async () => {
    vi.useFakeTimers();
    mountAuthy({ emptyBackup: true });
    await act(async () => { await vi.advanceTimersByTimeAsync(STILL_WAITING_MS); });
    expect(screen.queryByText(en.authy.stillWaiting.title)).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { name: en.failures.emptyBackup.title })).toBeInTheDocument();
  });
});
