import { act, screen, waitFor, within } from "@testing-library/react";
import { en } from "./strings/en";
import { mountApp, tickAllChecks, walkTo } from "./test-utils";

const iphone = en.deviceName.iphone;

describe("wizard", () => {
  it("welcome_blocks_until_device_and_all_checks", async () => {
    const { user, api } = await mountApp();
    const start = screen.getByRole("button", { name: en.welcome.start });
    expect(start).toBeDisabled();

    // All four ticked, no device: still blocked.
    await tickAllChecks(user);
    expect(screen.getAllByRole("checkbox")).toHaveLength(4);
    expect(start).toBeDisabled();

    // Device chosen, one check unticked: still blocked.
    await user.click(screen.getByRole("radio", { name: en.deviceName.ipad }));
    await user.click(screen.getByRole("checkbox", { name: new RegExp(en.welcome.checks.backups.label) }));
    expect(start).toBeDisabled();
    expect(screen.getByText(en.welcome.blockedChecks(1))).toBeInTheDocument();

    await user.click(screen.getByRole("checkbox", { name: new RegExp(en.welcome.checks.backups.label) }));
    expect(start).toBeEnabled();
    await user.click(start);
    await screen.findByRole("heading", { level: 1, name: en.connect.title(en.deviceName.ipad) });
    expect(api.calls.some((c) => c.method === "setDevice" && c.args[0] === "ipad")).toBe(true);
  });

  it("an Android phone gets the manual route and cannot start", async () => {
    const { user } = await mountApp();
    await user.click(screen.getByRole("radio", { name: en.welcome.android }));
    expect(screen.getByText(en.welcome.androidTitle)).toBeInTheDocument();
    expect(screen.getByText(en.manual.steps[0])).toBeInTheDocument();
    expect(screen.queryAllByRole("checkbox")).toHaveLength(0);
    expect(screen.getByRole("button", { name: en.welcome.start })).toBeDisabled();
  });

  it("states once, on the welcome screen, that it is not affiliated", async () => {
    await mountApp();
    expect(screen.getByText(en.welcome.footer)).toBeInTheDocument();
    expect(en.welcome.footer).toMatch(/not affiliated with Twilio or Bitwarden/);
  });

  it("proxy_events_advance_the_wizard (through the app)", async () => {
    const { api } = await walkTo("connect");
    // The live values are on screen for the person to type.
    const values = screen.getByRole("group", { name: en.connect.valuesLabel(iphone) });
    expect(within(values).getByText("192.168.4.109")).toBeInTheDocument();
    expect(within(values).getByText("8080")).toBeInTheDocument();

    act(() => api.emitProxyEvent({ kind: "deviceConnected" }));
    await screen.findByRole("heading", { level: 1, name: en.certificate.title });
    expect(screen.getByAltText(en.certificate.qrAlt)).toBeInTheDocument();

    act(() => api.emitProxyEvent({ kind: "trustWorking" }));
    await screen.findByRole("heading", { level: 1, name: en.authy.title });

    act(() => api.emitProxyEvent({ kind: "backupCaptured", count: 40 }));
    await screen.findByRole("heading", { level: 1, name: en.unlock.title });
    const status = screen.getByText(en.unlock.captured(40));
    expect(status).toHaveAttribute("aria-live", "polite");
  });

  it("choosing another address restarts the proxy on it", async () => {
    const { api, user } = await walkTo("connect");
    await user.selectOptions(screen.getByLabelText(new RegExp(en.connect.addressLabel)), "10.0.0.12");
    const values = screen.getByRole("group", { name: en.connect.valuesLabel(iphone) });
    await within(values).findByText("10.0.0.12");
    expect(api.calls.filter((c) => c.method === "startProxy").map((c) => c.args[0])).toEqual([undefined, "10.0.0.12"]);
  });

  it("tls_rejected_shows_trust_help", async () => {
    const { api } = await walkTo("certificate");
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();

    act(() => api.emitProxyEvent({ kind: "tlsRejected" }));
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByRole("heading", { name: en.failures.trust.title })).toBeInTheDocument();
    expect(within(alert).getByText(en.failures.trust.steps[1])).toBeInTheDocument();
    // The trust picture is brought into view too.
    expect(screen.getByRole("img", { name: en.device.alt.trustSettings(iphone) })).toBeInTheDocument();

    // Once trust works the help goes away and the wizard moves on.
    act(() => api.emitProxyEvent({ kind: "trustWorking" }));
    await screen.findByRole("heading", { level: 1, name: en.authy.title });
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("a rejection after trust was proven says the method no longer works and offers the manual guide", async () => {
    const { api, user } = await walkTo("authy");
    act(() => api.emitProxyEvent({ kind: "tlsRejected" }));
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByRole("heading", { name: en.failures.methodBroken.title })).toBeInTheDocument();
    expect(within(alert).getByText(en.manual.steps[0])).toBeInTheDocument();
    await user.click(within(alert).getByRole("button", { name: en.common.stopAndCleanUp }));
    await screen.findByRole("heading", { level: 1, name: en.cleanup.title });
  });

  it("an Authy error shows the attestation workaround with the live address", async () => {
    const { api } = await walkTo("authy");
    act(() => api.emitProxyEvent({ kind: "authyError", status: 400, path: "/x" }));
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByRole("heading", { name: en.failures.attestation.title })).toBeInTheDocument();
    expect(within(alert).getByText(en.failures.attestation.steps("192.168.4.109", 8080)[2]!)).toBeInTheDocument();
  });

  it("Having trouble? opens the panels for the step and closes with Escape", async () => {
    const { user } = await walkTo("connect");
    const opener = screen.getByRole("button", { name: en.common.havingTrouble });
    await user.click(opener);
    const sheet = screen.getByRole("dialog", { name: en.failures.sheetTitle });
    for (const title of [en.failures.firewall.title, en.failures.wifi.title, en.failures.vpn.title(iphone)]) {
      expect(within(sheet).getByText(title)).toBeInTheDocument();
    }
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(opener).toHaveFocus();
  });

  it("wrong_password_shows_inline_error_and_keeps_input", async () => {
    const { api, user } = await walkTo("unlock");
    const field = screen.getByLabelText(en.unlock.label);
    await user.type(field, " not it ");
    await user.click(screen.getByRole("button", { name: en.unlock.submit }));

    const alert = await screen.findByRole("alert");
    expect(within(alert).getByRole("heading", { name: en.failures.wrongPassword.title })).toBeInTheDocument();
    expect(within(alert).getByText(en.failures.wrongPassword.body(iphone))).toBeInTheDocument();
    // Inline: the error sits in the form beside the field and is tied to it.
    expect(field.closest("form")).toContainElement(alert);
    expect(field).toHaveAttribute("aria-invalid", "true");
    expect(field).toHaveAccessibleDescription(new RegExp(en.failures.wrongPassword.title));
    // What was typed is kept, spaces and all, and was sent exactly as typed.
    expect(field).toHaveValue(" not it ");
    expect(field).toHaveFocus();
    expect(api.calls.find((c) => c.method === "unlock")?.args).toEqual([" not it "]);
    expect(screen.getByRole("heading", { level: 1, name: en.unlock.title })).toBeInTheDocument();

    // The right password clears the error and moves on.
    await user.clear(field);
    await user.type(field, api.script.password);
    await user.click(screen.getByRole("button", { name: en.unlock.submit }));
    await screen.findByRole("heading", { level: 1, name: en.destination.title });
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("resume_starts_at_cleanup", async () => {
    const { api } = await mountApp({ resumeCleanup: true });
    expect(screen.getByRole("heading", { level: 1, name: en.cleanup.title })).toBeInTheDocument();
    expect(screen.getByText(en.cleanup.resumed)).toBeInTheDocument();
    await screen.findByText(en.cleanup.clean);
    expect(api.calls.filter((c) => c.method === "cleanup")).toHaveLength(1);
    expect(api.calls.some((c) => c.method === "startProxy")).toBe(false);
  });

  it("cleanup_blocks_until_every_item_ticked", async () => {
    const { api, user } = await walkTo("cleanup");
    await screen.findByText(en.cleanup.clean);
    const finish = screen.getByRole("button", { name: en.cleanup.finish });
    const boxes = screen.getAllByRole("checkbox");
    expect(boxes).toHaveLength(2);
    expect(finish).toBeDisabled();

    await user.click(boxes[0]!);
    expect(finish).toBeDisabled();
    expect(screen.getByText(en.cleanup.remaining(1))).toBeInTheDocument();
    expect(api.calls.some((c) => c.method === "finish")).toBe(false);

    await user.click(boxes[1]!);
    expect(finish).toBeEnabled();
    await user.click(finish);
    await screen.findByRole("heading", { level: 1, name: en.done.title });
    expect(api.calls.filter((c) => c.method === "finish")).toHaveLength(1);
  });

  it("cleanup cannot finish while the computer's own cleanup has failed, and retries", async () => {
    const { user } = await walkTo("cleanup", { cleanupError: "keychain busy" });
    const alert = await screen.findByRole("alert");
    for (const box of screen.getAllByRole("checkbox")) await user.click(box);
    expect(screen.getByRole("button", { name: en.cleanup.finish })).toBeDisabled();
    await user.click(within(alert).getByRole("button", { name: en.common.tryAgain }));
    await screen.findByText(en.cleanup.clean);
    await waitFor(() => expect(screen.getByRole("button", { name: en.cleanup.finish })).toBeEnabled());
  });
});
