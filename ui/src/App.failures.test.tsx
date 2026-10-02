// Every rejection the shell can send is shown by its code: a fitting title, the shell's own
// sentence as the detail, and something to do. No catch-all messages.
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ApiError } from "./api.errors";
import { createFakeApi } from "./api.fake";
import { App } from "./App";
import { Problem } from "./failures/Problem";
import { en } from "./strings/en";
import { mountApp, tickAllChecks, walkTo } from "./test-utils";

const iphone = en.deviceName.iphone;
const by = en.problems.byCode;

async function startFailing(error: ApiError | string) {
  const h = await mountApp({}, { failures: { startProxy: [error] } });
  await h.user.click(screen.getByRole("radio", { name: iphone }));
  await tickAllChecks(h.user);
  await h.user.click(screen.getByRole("button", { name: en.welcome.start }));
  return { ...h, alert: await screen.findByRole("alert") };
}

describe("failures, by the shell's code", () => {
  it("the app failing to start says why, and offers Try again and how to quit", async () => {
    const api = createFakeApi({}, { failures: { getState: ["the app data folder could not be created"] } });
    const user = userEvent.setup();
    render(<App api={api} />);
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByText(en.common.loadFailed)).toBeInTheDocument();
    expect(within(alert).getByText(en.problems.unexplained)).toBeInTheDocument();
    expect(alert.textContent).not.toContain("the app data folder could not be created");
    expect(within(alert).getByText(en.common.loadFailedHelp)).toBeInTheDocument();
    expect(en.common.loadFailedHelp).toMatch(/quit authexodus \(press Command-Q\)/);

    await user.click(within(alert).getByRole("button", { name: en.common.tryAgain }));
    await screen.findByRole("heading", { level: 1, name: en.welcome.title });
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  // The sentences are the shell's own, word for word (src-tauri/src/errors.rs).
  it.each([
    ["no_private_address", "This computer is not on a home or office Wi-Fi network. Connect it to the same Wi-Fi as the iPhone or iPad and try again."],
    ["keychain_failed", "The certificate could not be created, because this computer's keychain did not take its key. Open Keychain Access, search for \"dev.somecorp.authexodus\", delete the item it finds, and try again."],
    ["listen_failed", "This computer could not open the connection for your iPhone or iPad. Check that Wi-Fi is switched on and that no other copy of this app is running, then try again."],
    ["address_not_private", "That address is reachable from the internet, so the connection cannot be opened on it. Use this computer's address on your home or office Wi-Fi."],
  ] as const)("a proxy that cannot start (%s) shows its own title, the shell's sentence and Try again", async (code, sentence) => {
    const { api, user, alert } = await startFailing(new ApiError(code, sentence));
    expect(by[code].title(iphone)).not.toBe("");
    expect(within(alert).getByText(by[code].title(iphone))).toBeInTheDocument();
    expect(within(alert).getByText(sentence)).toBeInTheDocument();
    const advice = by[code].advice(iphone);
    if (advice !== "") expect(within(alert).getByText(advice)).toBeInTheDocument();
    // Title, the shell's sentence, and at most one line of the screen's own: nothing is said twice.
    expect(alert.querySelectorAll("p")).toHaveLength(advice === "" ? 2 : 3);
    // Never the old catch-all for a reason the shell named.
    if (code !== "listen_failed") expect(within(alert).queryByText(en.connect.startFailed(iphone))).not.toBeInTheDocument();

    await user.click(within(alert).getByRole("button", { name: en.common.tryAgain }));
    await screen.findByText(en.connect.waiting(iphone));
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(api.calls.filter((c) => c.method === "startProxy")).toHaveLength(2);
  });

  it("the home-network and Keychain cases say what the person needs to hear", () => {
    expect(by.no_private_address.title(iphone)).toMatch(/not on a home or office network/);
    expect(by.no_private_address.advice(iphone)).toMatch(/home or office router.*nobody outside your network/);
    expect(by.address_not_private.advice(iphone)).toMatch(/home or office router.*nobody outside your network/);
    expect(en.problems.keychainByHand).toMatch(/Keychain Access.*authexodus.*delete the item/);
  });

  it.each(["keychain_failed", "cleanup_keychain_failed"] as const)("%s always shows the Keychain route, once: the screen adds it only when the shell's sentence lacks it", (code) => {
    const mount = (message: string) => render(<Problem error={new ApiError(code, message)} d={iphone} title={en.connect.startFailed(iphone)} />);
    const said = () => screen.getByRole("alert").textContent!.match(/Keychain Access/g) ?? [];

    const bare = mount("The key could not be stored.");
    expect(screen.getByText(en.problems.keychainByHand)).toBeInTheDocument();
    expect(said()).toHaveLength(1);
    bare.unmount();

    mount("The key could not be removed. To remove it by hand: open Keychain Access, search for \"dev.somecorp.authexodus\", and delete the item it finds.");
    expect(screen.queryByText(en.problems.keychainByHand)).not.toBeInTheDocument();
    expect(said()).toHaveLength(1);
  });

  it("no other code is given the Keychain route", () => {
    render(<Problem error={new ApiError("cleanup_failed", "The Bitwarden data folder could not be removed.")} d={iphone} title={en.cleanup.failed} />);
    expect(screen.getByRole("alert").textContent).not.toMatch(/Keychain/);
  });

  it("a start that fails with no code keeps the screen's own title and a plain sentence, never the raw text", async () => {
    const { alert } = await startFailing("os error 48");
    expect(within(alert).getByText(en.connect.startFailed(iphone))).toBeInTheDocument();
    expect(within(alert).getByText(en.problems.unexplained)).toBeInTheDocument();
    expect(alert.textContent).not.toContain("os error 48");
  });

  it("the person can still stop and clean up when the proxy never started", async () => {
    const { user } = await startFailing(new ApiError("no_private_address", "No home network."));
    await user.click(screen.getByRole("button", { name: en.common.havingTrouble }));
    await user.click(screen.getByRole("button", { name: en.common.stopAndCleanUp }));
    await user.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: en.common.stopAndCleanUp }));
    await screen.findByRole("heading", { level: 1, name: en.cleanup.title });
  });

  it("a start refused because the address is gone offers the restart, not a retry that cannot work", async () => {
    const sentence = "This computer's network address has changed, so the iPhone or iPad can no longer reach the connection it was using. Restart the connection to carry on.";
    const { api, user, alert } = await startFailing(new ApiError("address_changed", sentence));
    expect(within(alert).getByText(sentence)).toBeInTheDocument();
    expect(within(alert).queryByRole("button", { name: en.common.tryAgain })).not.toBeInTheDocument();
    await user.click(within(alert).getByRole("button", { name: en.common.restart }));
    await screen.findByText(en.connect.waiting(iphone));
    expect(api.calls.filter((c) => c.method === "restartProxy")).toHaveLength(1);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("an address the shell will not listen on is explained, and is not mistaken for a captured backup", async () => {
    const { api, user } = await walkTo("connect");
    api.script.failures.startProxy = [new ApiError("address_not_private", "10.0.0.12 is not a home or office address.")];
    await user.selectOptions(screen.getByLabelText(new RegExp(en.connect.addressLabel)), "10.0.0.12");
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByText(by.address_not_private.title(iphone))).toBeInTheDocument();
    expect(within(alert).getByText("10.0.0.12 is not a home or office address.")).toBeInTheDocument();
    expect(screen.queryByText(en.connect.addressRejected("10.0.0.12"))).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: en.connect.restartOn("10.0.0.12") })).not.toBeInTheDocument();
    // The values on screen are still the ones the shell is really using.
    expect(within(screen.getByRole("group", { name: en.connect.valuesLabel(iphone) })).getByText("192.168.4.109")).toBeInTheDocument();
  });

  it("a restart in progress is announced, and the address cannot be changed under it", async () => {
    const { api, user } = await walkTo("connect", { delayMs: 30 });
    await user.click(screen.getByRole("button", { name: en.common.havingTrouble }));
    await user.click(screen.getByRole("button", { name: en.common.restart }));
    const busy = await screen.findByText(en.common.restarting);
    expect(busy.closest("[role=status]")).not.toBeNull();
    expect(screen.getByLabelText(new RegExp(en.connect.addressLabel))).toBeDisabled();
    await waitFor(() => expect(screen.queryByText(en.common.restarting)).not.toBeInTheDocument());
    expect(screen.getByLabelText(new RegExp(en.connect.addressLabel))).toBeEnabled();
    expect(api.calls.filter((c) => c.method === "restartProxy")).toHaveLength(1);
  });

  it("a restart that fails shows the shell's reason by code", async () => {
    const { api, user } = await walkTo("certificate");
    api.script.failures.restartProxy = [new ApiError("listen_failed", "Port 8080 is in use by another program.")];
    await user.click(screen.getByRole("button", { name: en.common.havingTrouble }));
    await user.click(screen.getByRole("button", { name: en.common.restart }));
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByText(by.listen_failed.title(iphone))).toBeInTheDocument();
    expect(within(alert).getByText("Port 8080 is in use by another program.")).toBeInTheDocument();
    // One attempt only: a busy port is not a reason to try another address.
    expect(api.calls.filter((c) => c.method === "restartProxy")).toHaveLength(1);
    await user.click(within(alert).getByRole("button", { name: en.common.tryAgain }));
    await waitFor(() => expect(screen.queryByRole("alert")).not.toBeInTheDocument());
  });

  it("an unlock that fails for a reason other than the password says so, with the reason", async () => {
    const { api, user } = await walkTo("unlock", { failures: { unlock: ["the decryption worker stopped"] } });
    await user.type(screen.getByLabelText(en.unlock.label), api.script.password);
    await user.click(screen.getByRole("button", { name: en.unlock.submit }));
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByText(en.unlock.failed)).toBeInTheDocument();
    expect(within(alert).getByText(en.problems.unexplained)).toBeInTheDocument();
    expect(alert.textContent).not.toContain("the decryption worker stopped");
    // Not presented as a wrong password, and what was typed is kept for another try.
    expect(screen.queryByText(en.failures.wrongPassword.title)).not.toBeInTheDocument();
    expect(screen.getByLabelText(en.unlock.label)).toHaveValue(api.script.password);
    await user.click(screen.getByRole("button", { name: en.unlock.submit }));
    await screen.findByRole("heading", { level: 1, name: en.destination.title });
  });

  it("an unlock with no backup held offers to capture again, not to retype the password", async () => {
    const { api, user } = await walkTo("unlock", { failures: { unlock: [new ApiError("no_backup", "Nothing has been captured from Authy yet.")] } });
    await user.type(screen.getByLabelText(en.unlock.label), api.script.password);
    await user.click(screen.getByRole("button", { name: en.unlock.submit }));
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByText(by.no_backup.title(iphone))).toBeInTheDocument();
    expect(within(alert).getByText("Nothing has been captured from Authy yet.")).toBeInTheDocument();
    await user.click(within(alert).getByRole("button", { name: en.unlock.recapture.action }));
    await screen.findByRole("heading", { level: 1, name: en.connect.title(iphone) });
    expect(api.calls.filter((c) => c.method === "restartProxy")).toHaveLength(1);
  });

  it("a Finish the shell rejects is never silent: the Keychain route is shown and Finish can be pressed again", async () => {
    const { api, user } = await walkTo("cleanup", {
      failures: { finish: [new ApiError("cleanup_keychain_failed", "The certificate key is still in the Keychain.")] },
    });
    await screen.findByText(en.cleanup.clean(iphone));
    for (const box of screen.getAllByRole("checkbox")) await user.click(box);
    const finish = screen.getByRole("button", { name: en.cleanup.finish });
    await user.click(finish);

    const alert = await screen.findByRole("alert");
    expect(within(alert).getByText(en.cleanup.finishFailed)).toBeInTheDocument();
    expect(within(alert).getByText(en.cleanup.failedReason("The certificate key is still in the Keychain."))).toBeInTheDocument();
    expect(within(alert).getByText(en.cleanup.finishFailedKeychain)).toBeInTheDocument();
    expect(within(alert).getByText(en.problems.keychainByHand)).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 1, name: en.cleanup.title })).toBeInTheDocument();
    expect(finish).toBeEnabled();

    await user.click(finish);
    await screen.findByRole("heading", { level: 1, name: en.done.title });
    expect(api.calls.filter((c) => c.method === "finish")).toHaveLength(2);
  });

  it("a Finish that fails for another reason gives no Keychain advice", async () => {
    const { user } = await walkTo("cleanup", { failures: { finish: [new ApiError("cleanup_failed", "The Bitwarden data folder could not be removed.")] } });
    await screen.findByText(en.cleanup.clean(iphone));
    for (const box of screen.getAllByRole("checkbox")) await user.click(box);
    await user.click(screen.getByRole("button", { name: en.cleanup.finish }));
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByText(en.cleanup.finishFailedOther)).toBeInTheDocument();
    expect(alert.textContent).not.toMatch(/Keychain/);
  });

  it("a cleanup that fails over something other than the key gives no Keychain advice either", async () => {
    await walkTo("cleanup", { failures: { cleanup: [new ApiError("cleanup_failed", "The Bitwarden data folder could not be removed.")] } });
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByText(en.cleanup.failedReason("The Bitwarden data folder could not be removed."))).toBeInTheDocument();
    expect(within(alert).getByText(en.cleanup.failedOther)).toBeInTheDocument();
    expect(alert.textContent).not.toMatch(/Keychain/);
    expect(within(alert).getByRole("checkbox", { name: en.cleanup.otherDone })).toBeInTheDocument();
  });

  it("this computer's address changing is announced, and the restart shows the new Server and Port", async () => {
    const { api, user } = await walkTo("authy");
    // The Mac moved to another network: its old address is gone.
    api.script.addresses = [{ ip: "192.168.7.20", label: "Wi-Fi" }];
    act(() => api.emitProxyEvent({ kind: "addressChanged" }));
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByText(en.failures.addressChanged.title(iphone))).toBeInTheDocument();
    expect(en.failures.addressChanged.title(iphone)).toBe("This Mac's network address changed. Your iPhone can no longer reach it.");
    expect(within(alert).getByText(en.failures.addressChanged.body(iphone))).toBeInTheDocument();

    await user.click(within(alert).getByRole("button", { name: en.common.restart }));
    await screen.findByRole("heading", { level: 1, name: en.connect.title(iphone) });
    // The shell is asked to choose: the old address is not offered back to it.
    expect(api.calls.filter((c) => c.method === "restartProxy").map((c) => c.args[0])).toEqual([undefined]);
    const values = await screen.findByRole("group", { name: en.connect.valuesLabel(iphone) });
    expect(await within(values).findByText("192.168.7.20")).toBeInTheDocument();
    expect(values).toHaveClass("values-changed");
    expect(screen.getByText(en.connect.addressChanged(iphone))).toBeInTheDocument();
    expect(screen.queryByText(en.failures.addressChanged.title(iphone))).not.toBeInTheDocument();
  });
});
