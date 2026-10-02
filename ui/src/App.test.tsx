import { act, cleanup, screen, waitFor, within } from "@testing-library/react";
import { en } from "./strings/en";
import { mountApp, tickAllChecks, walkTo } from "./test-utils";

const iphone = en.deviceName.iphone;

describe("wizard", () => {
  it("welcome_blocks_until_device_and_all_checks", async () => {
    const { user, api } = await mountApp();
    const start = screen.getByRole("button", { name: en.welcome.start });
    expect(start).toBeDisabled();

    // All five ticked, no device: still blocked.
    await tickAllChecks(user);
    expect(screen.getAllByRole("checkbox")).toHaveLength(5);
    expect(screen.getByRole("checkbox", { name: new RegExp(en.welcome.checks.sms.label) })).toBeChecked();
    expect(en.welcome.checksTitle).toMatch(/five/);
    expect(en.welcome.blocked).toMatch(/five/);
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
    const { api, user } = await walkTo("certificate");
    const trustTitle = en.failures.trust.title;
    expect(screen.queryByRole("heading", { name: trustTitle })).not.toBeInTheDocument();

    // The person has moved on to the second picture when the phone refuses the certificate.
    await user.click(screen.getByRole("button", { name: en.certificate.steps.download }));
    const picture = () => screen.getByRole("img", { name: en.device.alt.downloadPage(iphone) });
    expect(picture()).toBeInTheDocument();

    act(() => api.emitProxyEvent({ kind: "tlsRejected" }));
    const help = (await screen.findByRole("heading", { name: trustTitle })).closest("section")!;
    expect(within(help).getByText(en.failures.trust.steps[1])).toBeInTheDocument();
    // A calm reminder, not an alarm: it is a status, and nothing on screen is an alert.
    expect(help).toHaveAttribute("role", "status");
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    // The picture the person was looking at has not moved.
    expect(picture()).toBeInTheDocument();
    expect(screen.getByRole("button", { name: en.certificate.steps.download })).toHaveAttribute("aria-pressed", "true");
    expect(screen.queryByRole("img", { name: en.device.alt.trustSettings(iphone) })).not.toBeInTheDocument();

    // Once trust works the reminder goes away and the wizard moves on.
    act(() => api.emitProxyEvent({ kind: "trustWorking" }));
    await screen.findByRole("heading", { level: 1, name: en.authy.title });
    expect(screen.queryByRole("heading", { name: trustTitle })).not.toBeInTheDocument();
  });

  it("the QR code stays put when the certificate is refused on the first step", async () => {
    const { api } = await walkTo("certificate");
    expect(screen.getByAltText(en.certificate.qrAlt)).toBeInTheDocument();
    act(() => api.emitProxyEvent({ kind: "tlsRejected" }));
    await screen.findByRole("heading", { name: en.failures.trust.title });
    expect(screen.getByAltText(en.certificate.qrAlt)).toBeInTheDocument();
  });

  it("one rejection after trust says nothing; repeated ones say the method no longer works", async () => {
    const { api, user } = await walkTo("authy");
    const title = en.failures.methodBroken.title;
    act(() => api.emitProxyEvent({ kind: "tlsRejected" }));
    act(() => api.emitProxyEvent({ kind: "tlsRejected" }));
    expect(screen.queryByRole("heading", { name: title })).not.toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();

    act(() => api.emitProxyEvent({ kind: "tlsRejected" }));
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByRole("heading", { name: title })).toBeInTheDocument();
    expect(within(alert).getByText(en.manual.steps[0])).toBeInTheDocument();
    expect(en.failures.methodBroken.body).not.toMatch(/not something you did/i);

    // Stopping asks first, then goes to cleanup.
    await user.click(within(alert).getByRole("button", { name: en.common.stopAndCleanUp }));
    const confirm = screen.getByRole("alertdialog", { name: en.failures.stop.title });
    await user.click(within(confirm).getByRole("button", { name: en.common.stopAndCleanUp }));
    await screen.findByRole("heading", { level: 1, name: en.cleanup.title });
  });

  it("an Authy error is titled by what the person sees, with the attestation workaround only as a possibility", async () => {
    const { api } = await walkTo("authy");
    act(() => api.emitProxyEvent({ kind: "authyError", status: 400, path: "/x" }));
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByRole("heading", { name: en.failures.attestation.title })).toBeInTheDocument();
    expect(en.failures.attestation.title).not.toMatch(/attestation/i);
    expect(within(alert).getByText(en.failures.attestation.body)).toBeInTheDocument();
    expect(within(alert).getByText(en.failures.attestation.ifAttestation)).toBeInTheDocument();
    expect(en.failures.attestation.ifAttestation).toMatch(/^If Authy mentions/);
    expect(within(alert).getByText(en.failures.attestation.steps("192.168.4.109", 8080)[2]!)).toBeInTheDocument();
  });

  it("a server error from Authy gets the generic advice and no attestation workaround", async () => {
    const { api } = await walkTo("authy");
    act(() => api.emitProxyEvent({ kind: "authyError", status: 503, path: "/x" }));
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByText(en.failures.attestation.body)).toBeInTheDocument();
    expect(within(alert).queryByText(en.failures.attestation.ifAttestation)).not.toBeInTheDocument();
    expect(within(alert).queryByRole("list")).not.toBeInTheDocument();
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

  it("Stop and clean up asks first, says what is lost, and can be backed out of", async () => {
    const { api, user } = await walkTo("connect");
    await user.click(screen.getByRole("button", { name: en.common.havingTrouble }));
    await user.click(screen.getByRole("button", { name: en.common.stopAndCleanUp }));

    const confirm = screen.getByRole("alertdialog", { name: en.failures.stop.title });
    expect(within(confirm).getByText(en.failures.stop.lost(iphone))).toBeInTheDocument();
    expect(within(confirm).getByText(en.failures.stop.redo)).toBeInTheDocument();
    // Authy has not been deleted yet at this step, so nothing is said about signing in to it.
    expect(within(confirm).queryByText(en.common.authyFinish)).not.toBeInTheDocument();

    await user.click(within(confirm).getByRole("button", { name: en.common.keepGoing }));
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 1, name: en.connect.title(iphone) })).toBeInTheDocument();
    expect(api.calls.some((c) => c.method === "cleanup")).toBe(false);

    await user.click(screen.getByRole("button", { name: en.common.havingTrouble }));
    await user.click(screen.getByRole("button", { name: en.common.stopAndCleanUp }));
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 1, name: en.connect.title(iphone) })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: en.common.havingTrouble }));
    await user.click(screen.getByRole("button", { name: en.common.stopAndCleanUp }));
    await user.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: en.common.stopAndCleanUp }));
    await screen.findByRole("heading", { level: 1, name: en.cleanup.title });
    // Authy was never deleted, so cleanup does not ask about it. No device ever connected, so
    // no certificate can be on it either: that is said, not asked.
    expect(screen.getAllByRole("checkbox")).toHaveLength(1);
    expect(screen.getByText(en.cleanup.noCertificate(iphone))).toBeInTheDocument();
    expect(screen.queryByRole("checkbox", { name: new RegExp(en.cleanup.items.profileRemoved.label) })).not.toBeInTheDocument();
  });

  it("stopping from the unlock step says to finish signing in to Authy, and cleanup asks for it", async () => {
    const { user } = await walkTo("unlock");
    // The way out is not in the footer where a Back button would be.
    const stop = screen.getByRole("button", { name: en.common.stopAndCleanUp });
    expect(stop.closest(".screen-footer")).toBeNull();
    await user.click(stop);
    const confirm = screen.getByRole("alertdialog", { name: en.failures.stop.title });
    expect(within(confirm).getByText(en.common.authyFinish)).toBeInTheDocument();
    await user.click(within(confirm).getByRole("button", { name: en.common.stopAndCleanUp }));
    await screen.findByRole("heading", { level: 1, name: en.cleanup.title });
    expect(screen.getByRole("checkbox", { name: new RegExp(en.cleanup.items.authySignedIn.label) })).toBeInTheDocument();
  });

  it("the trouble sheet says the same when stopping from the Authy step", async () => {
    const { user } = await walkTo("authy");
    await user.click(screen.getByRole("button", { name: en.common.havingTrouble }));
    await user.click(screen.getByRole("button", { name: en.common.stopAndCleanUp }));
    expect(within(screen.getByRole("alertdialog")).getByText(en.common.authyFinish)).toBeInTheDocument();
  });

  it("finishing sign-in to Authy is called out once the codes are unlocked", async () => {
    await walkTo("destination");
    expect(screen.getByText(en.destination.authyTitle)).toBeInTheDocument();
    expect(screen.getByText(en.destination.authyBody(iphone))).toBeInTheDocument();
  });

  it("Restart the connection is offered on every waiting step and starts over at connect", async () => {
    for (const step of ["connect", "certificate", "authy"] as const) {
      const { api, user } = await walkTo(step);
      await user.click(screen.getByRole("button", { name: en.common.havingTrouble }));
      const sheet = screen.getByRole("dialog", { name: en.failures.sheetTitle });
      expect(within(sheet).getByText(en.failures.restart.body(iphone))).toBeInTheDocument();
      await user.click(within(sheet).getByRole("button", { name: en.common.restart }));
      await waitFor(() => expect(api.calls.filter((c) => c.method === "restartProxy")).toHaveLength(1));
      expect(api.calls.find((c) => c.method === "restartProxy")?.args).toEqual(["192.168.4.109"]);
      await screen.findByRole("heading", { level: 1, name: en.connect.title(iphone) });
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
      // The phone still has its certificate: trust seen again moves straight on.
      act(() => api.emitProxyEvent({ kind: "trustWorking" }));
      await screen.findByRole("heading", { level: 1, name: en.authy.title });
      cleanup();
    }
  });

  it("a refused device is explained and offers the restart", async () => {
    const { api, user } = await walkTo("authy");
    act(() => api.emitProxyEvent({ kind: "deviceRefused" }));
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByRole("heading", { name: en.failures.deviceRefused.title })).toBeInTheDocument();
    expect(within(alert).getByText(en.failures.deviceRefused.next(iphone))).toBeInTheDocument();
    await user.click(within(alert).getByRole("button", { name: en.common.restart }));
    await screen.findByRole("heading", { level: 1, name: en.connect.title(iphone) });
    expect(api.calls.filter((c) => c.method === "restartProxy")).toHaveLength(1);
    expect(screen.queryByRole("heading", { name: en.failures.deviceRefused.title })).not.toBeInTheDocument();
  });

  it("a restart that fails says so and can be tried again", async () => {
    // Both the restart on the current address and the fallback with no address fail.
    const { api, user } = await walkTo("certificate", { restartErrors: ["port busy", "port busy"] });
    act(() => api.emitProxyEvent({ kind: "deviceRefused" }));
    await user.click(await screen.findByRole("button", { name: en.common.restart }));
    await screen.findByText(en.common.restartFailed);
    await user.click(screen.getByRole("button", { name: en.common.tryAgain }));
    await waitFor(() => expect(screen.queryByText(en.common.restartFailed)).not.toBeInTheDocument());
    expect(screen.getByRole("heading", { level: 1, name: en.connect.title(iphone) })).toBeInTheDocument();
  });

  it("a restart stays on the address the device is set to", async () => {
    // The person had switched to the second address; a restart must not fall back to the first.
    const { api, user } = await walkTo("connect");
    await user.selectOptions(screen.getByLabelText(new RegExp(en.connect.addressLabel)), "10.0.0.12");
    const values = screen.getByRole("group", { name: en.connect.valuesLabel(iphone) });
    await within(values).findByText("10.0.0.12");

    await user.click(screen.getByRole("button", { name: en.common.havingTrouble }));
    await user.click(screen.getByRole("button", { name: en.common.restart }));
    await waitFor(() => expect(api.calls.filter((c) => c.method === "restartProxy")).toHaveLength(1));
    expect(api.calls.find((c) => c.method === "restartProxy")?.args).toEqual(["10.0.0.12"]);
    expect(within(screen.getByRole("group", { name: en.connect.valuesLabel(iphone) })).getByText("10.0.0.12")).toBeInTheDocument();
    expect(screen.queryByText(en.connect.addressChanged(iphone))).not.toBeInTheDocument();
  });

  it("when this computer's address is gone, a restart falls back and says to update the device", async () => {
    const { api, user } = await walkTo("connect");
    await user.selectOptions(screen.getByLabelText(new RegExp(en.connect.addressLabel)), "10.0.0.12");
    await within(screen.getByRole("group", { name: en.connect.valuesLabel(iphone) })).findByText("10.0.0.12");
    // The Mac loses that address (cable pulled, Wi-Fi changed).
    api.script.addresses = [{ ip: "192.168.4.109", label: "Wi-Fi" }];

    await user.click(screen.getByRole("button", { name: en.common.havingTrouble }));
    await user.click(screen.getByRole("button", { name: en.common.restart }));
    const notice = await screen.findByText(en.connect.addressChanged(iphone));
    expect(notice.closest("[role=alert]")).not.toBeNull();
    // First on the old address, then once with none.
    expect(api.calls.filter((c) => c.method === "restartProxy").map((c) => c.args[0])).toEqual(["10.0.0.12", undefined]);
    const values = screen.getByRole("group", { name: en.connect.valuesLabel(iphone) });
    expect(within(values).getByText("192.168.4.109")).toBeInTheDocument();
    expect(within(values).getByText("8080")).toBeInTheDocument();
  });

  it("events from the new proxy that arrive before the restart answers are not lost", async () => {
    const { api, user } = await walkTo("authy");
    // The phone reconnects and Authy's handshake succeeds while restartProxy is still pending.
    api.script.beforeRestartResolves = () => {
      api.emitProxyEvent({ kind: "deviceConnected" });
      api.emitProxyEvent({ kind: "trustWorking" });
    };
    await user.click(screen.getByRole("button", { name: en.common.havingTrouble }));
    await user.click(screen.getByRole("button", { name: en.common.restart }));
    // Without the early reset the wizard would be stranded on Connect, waiting for events
    // that have already been and gone.
    await screen.findByRole("heading", { level: 1, name: en.authy.title });
    await waitFor(() => expect(api.calls.filter((c) => c.method === "restartProxy")).toHaveLength(1));
    await new Promise((r) => setTimeout(r, 20));
    expect(screen.getByRole("heading", { level: 1, name: en.authy.title })).toBeInTheDocument();
  });

  it("after a restart the waiting screens say what not to do again", async () => {
    const { api, user } = await walkTo("authy");
    expect(screen.getByText(en.authy.lastCheck.title)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: en.common.havingTrouble }));
    await user.click(screen.getByRole("button", { name: en.common.restart }));
    await screen.findByRole("heading", { level: 1, name: en.connect.title(iphone) });
    const notice = en.failures.restart.noticeAfterTrust(iphone);
    expect(notice).toMatch(/Do not do either again/);
    expect(screen.getByText(notice)).toBeInTheDocument();

    act(() => api.emitProxyEvent({ kind: "deviceConnected" }));
    await screen.findByRole("heading", { level: 1, name: en.certificate.title });
    expect(screen.getByText(notice)).toBeInTheDocument();

    act(() => api.emitProxyEvent({ kind: "trustWorking" }));
    await screen.findByRole("heading", { level: 1, name: en.authy.title });
    expect(screen.getByText(notice)).toBeInTheDocument();
    // "You are about to delete Authy" is not repeated to someone who already did.
    expect(screen.queryByText(en.authy.lastCheck.title)).not.toBeInTheDocument();
  });

  it("a restart before the certificate was ever trusted does not claim it is installed", async () => {
    const { user } = await walkTo("connect");
    await user.click(screen.getByRole("button", { name: en.common.havingTrouble }));
    await user.click(screen.getByRole("button", { name: en.common.restart }));
    await screen.findByText(en.failures.restart.noticeBeforeTrust(iphone));
    expect(screen.queryByText(en.failures.restart.noticeAfterTrust(iphone))).not.toBeInTheDocument();
  });

  it("the restart action has one name everywhere", () => {
    expect(en.failures.restart.title).toBe(en.common.restart);
    expect(en.connect.addressRejected("1.2.3.4")).toMatch(/restarting the connection/);
  });

  it("an address change the shell refuses after a capture offers a restart on that address", async () => {
    const { api, user } = await mountApp();
    // A backup captured before the person reaches the connect screen (a resumed phone).
    act(() => api.emitProxyEvent({ kind: "backupCaptured", count: 5 }));
    await user.click(screen.getByRole("radio", { name: iphone }));
    await tickAllChecks(user);
    await user.click(screen.getByRole("button", { name: en.welcome.start }));
    await screen.findByText(en.connect.waiting(iphone));

    await user.selectOptions(screen.getByLabelText(new RegExp(en.connect.addressLabel)), "10.0.0.12");
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByText(en.connect.addressRejected("10.0.0.12"))).toBeInTheDocument();
    const values = screen.getByRole("group", { name: en.connect.valuesLabel(iphone) });
    expect(within(values).getByText("192.168.4.109")).toBeInTheDocument();

    await user.click(within(alert).getByRole("button", { name: en.connect.restartOn("10.0.0.12") }));
    await within(values).findByText("10.0.0.12");
    expect(api.calls.find((c) => c.method === "restartProxy")?.args).toEqual(["10.0.0.12"]);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("shows the version and the releases address as text that can be selected", async () => {
    await mountApp({ version: "1.4.2", releasesUrl: "https://example.com/authexodus/releases" });
    expect(screen.getByText(en.rail.version("1.4.2"))).toBeInTheDocument();
    const url = screen.getByText("https://example.com/authexodus/releases");
    expect(url).toHaveClass("selectable");
    expect(url.closest("a")).toBeNull();
  });

  it("Check the codes is blocked until something has been moved, and says why", async () => {
    const { user } = await walkTo("destination");
    const go = () => screen.getByRole("button", { name: en.destination.continue });
    expect(go()).toBeDisabled();
    expect(screen.getByText(en.destination.continueBlocked)).toBeInTheDocument();
    expect(en.destination.continueBlocked).toMatch(/scan a QR code and tick it/);

    // Looking at the QR codes, even all of them, moves nothing until one is ticked as scanned.
    await user.click(screen.getByRole("button", { name: new RegExp(en.destination.options.qr.title) }));
    await screen.findByRole("checkbox", { name: en.destination.qr.scanned });
    await user.click(screen.getByRole("button", { name: en.common.next }));
    await user.click(screen.getByRole("button", { name: en.destination.backToOptions }));
    expect(go()).toBeDisabled();

    // One code scanned and ticked is enough, wherever in the walk the person stops.
    await user.click(screen.getByRole("button", { name: new RegExp(en.destination.options.qr.title) }));
    await user.click(await screen.findByRole("checkbox", { name: en.destination.qr.scanned }));
    expect(screen.getByText(en.destination.qr.scannedCount(1, 8))).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: en.destination.backToOptions }));
    expect(go()).toBeEnabled();
    expect(screen.queryByText(en.destination.continueBlocked)).not.toBeInTheDocument();
  });

  it("Done after giving up says nothing was moved and shows the manual route", async () => {
    const { user } = await walkTo("unlock");
    await user.click(screen.getByRole("button", { name: en.common.stopAndCleanUp }));
    await user.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: en.common.stopAndCleanUp }));
    await screen.findByText(en.cleanup.clean(iphone));
    for (const box of screen.getAllByRole("checkbox")) await user.click(box);
    await user.click(screen.getByRole("button", { name: en.cleanup.finish }));
    await screen.findByRole("heading", { level: 1, name: en.done.titleNothingMoved });
    expect(screen.getByText(en.done.bodyNothingMoved)).toBeInTheDocument();
    expect(screen.getByText(en.manual.steps[0])).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: en.done.title })).not.toBeInTheDocument();
    expect(en.done.bodyNothingMoved).not.toMatch(/run authexodus again/);
  });

  it("accounts that can't move are still named as a count on Verify and on Done", async () => {
    const { user } = await walkTo("verify");
    expect(screen.getByText(en.verify.cantMove(2))).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: en.verify.confirm }));
    await screen.findByText(en.cleanup.clean(iphone));
    expect(screen.getByText(en.cleanup.keepAuthy)).toBeInTheDocument();
    expect(en.cleanup.keepAuthy).toMatch(/Do not delete Authy until/);
    for (const box of screen.getAllByRole("checkbox")) await user.click(box);
    await user.click(screen.getByRole("button", { name: en.cleanup.finish }));
    await screen.findByRole("heading", { level: 1, name: en.done.title });
    expect(screen.getByText(en.done.notMoved(2))).toBeInTheDocument();
  });

  it("the Welcome screen asks about the text message, the network and a spare device", async () => {
    await mountApp();
    expect(screen.getByText(en.welcome.network)).toBeInTheDocument();
    expect(en.welcome.network).toMatch(/home or office network you control/);
    expect(screen.getByText(en.welcome.spare)).toBeInTheDocument();
    expect(en.welcome.spare).toMatch(/Install Authy on it and sign in first/);
    expect(screen.getByText(en.welcome.checks.sms.where)).toBeInTheDocument();
    expect(screen.getByText(en.welcome.checks.password.where)).toBeInTheDocument();
    expect(en.welcome.checks.password.where).toMatch(/cannot be opened without it/);
    // The warning about the checks is a callout, not quiet text.
    expect(screen.getByText(en.welcome.checksWhy).closest(".callout-warn")).not.toBeNull();
  });

  it("the picture button's name follows what it will do", async () => {
    const { user } = await mountApp();
    const label = en.welcome.checks.backups.label;
    const show = screen.getByRole("button", { name: en.common.showPictureFor(label) });
    await user.click(show);
    expect(screen.getByRole("button", { name: en.common.hidePictureFor(label) })).toHaveTextContent(en.common.hidePicture);
  });

  it("the Certificate screen shows the fingerprint to compare, and claims no more than the app does", async () => {
    const { api } = await walkTo("certificate");
    const info = await api.startProxy();
    const shown = screen.getByTestId("fingerprint");
    expect(shown.textContent!.replace(/[^0-9A-F]/g, "")).toBe(info.certFingerprint.replace(/:/g, ""));
    expect(shown.querySelectorAll("span")).toHaveLength(4);
    expect(screen.getByText(en.certificate.fingerprintHow(iphone))).toBeInTheDocument();
    expect(en.certificate.fingerprintHow(iphone)).toMatch(/More Details/);
    expect(screen.getByText(en.certificate.lede)).toBeInTheDocument();
    expect(en.certificate.lede).toBe("The app uses this certificate only to read what Authy sends. You remove it at the end.");
    // The trust step warns about the iOS warning and says to tap Continue.
    expect(screen.getByText(en.certificate.steps.trust(iphone))).toBeInTheDocument();
    expect(en.certificate.steps.trust(iphone)).toMatch(/Your iPhone shows a warning. That is expected. Tap Continue\./);
  });

  it("the status line comes after the heading, so it is read when the heading takes focus", async () => {
    await walkTo("certificate");
    const heading = screen.getByRole("heading", { level: 1 });
    const status = screen.getByText(en.certificate.connected(iphone));
    expect(heading.compareDocumentPosition(status) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("says which step this is in words, for when the step list is hidden", async () => {
    await walkTo("certificate");
    expect(screen.getByText(en.common.stepOf(3, 8, en.rail.steps.certificate))).toBeInTheDocument();
  });

  it("the unlock screen's forgot-password line says to keep trying and never to type it elsewhere", async () => {
    await walkTo("unlock");
    expect(screen.getByText(en.unlock.forgotten)).toBeInTheDocument();
    expect(en.unlock.forgotten).toMatch(/nothing is lost by a wrong try/);
    const toggle = screen.getByRole("button", { name: en.unlock.show });
    expect(toggle).toHaveAttribute("aria-pressed", "false");
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
    await screen.findByText(en.cleanup.clean(en.deviceName.either));
    // The app no longer knows what happened before it was closed, so it asks about Authy
    // and about a saved file as well.
    expect(screen.getAllByRole("checkbox")).toHaveLength(4);
    expect(screen.getByRole("checkbox", { name: new RegExp(en.cleanup.items.fileDeletedMaybe.label) })).toBeInTheDocument();
    expect(api.calls.filter((c) => c.method === "cleanup")).toHaveLength(1);
    expect(api.calls.some((c) => c.method === "startProxy")).toBe(false);
  });

  it("cleanup_blocks_until_every_item_ticked", async () => {
    const { api, user } = await walkTo("cleanup");
    await screen.findByText(en.cleanup.clean(iphone));
    const finish = screen.getByRole("button", { name: en.cleanup.finish });
    const boxes = screen.getAllByRole("checkbox");
    expect(boxes).toHaveLength(3);
    expect(screen.getByRole("checkbox", { name: new RegExp(en.cleanup.items.authySignedIn.label) })).toBeInTheDocument();
    expect(finish).toBeDisabled();
    // The phone is offline until its proxy is off, and that is said first and plainly.
    expect(screen.getByText(en.cleanup.noInternet(iphone))).toBeInTheDocument();
    expect(screen.getByText(en.cleanup.vpnBack)).toBeInTheDocument();

    await user.click(boxes[0]!);
    await user.click(boxes[1]!);
    expect(finish).toBeDisabled();
    expect(screen.getByText(en.cleanup.remaining(1))).toBeInTheDocument();
    expect(api.calls.some((c) => c.method === "finish")).toBe(false);

    await user.click(boxes[2]!);
    expect(finish).toBeEnabled();
    await user.click(finish);
    await screen.findByRole("heading", { level: 1, name: en.done.title });
    expect(api.calls.filter((c) => c.method === "finish")).toHaveLength(1);
    expect(screen.getByText(en.done.again(iphone))).toBeInTheDocument();
  });

  it("a failed cleanup shows the shell's reason and a manual route, and can still be finished", async () => {
    const { api, user } = await walkTo("cleanup", { cleanupError: "could not remove the certificate key: keychain is locked" });
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByText(en.cleanup.failed)).toBeInTheDocument();
    expect(within(alert).getByText(en.cleanup.failedReason("could not remove the certificate key: keychain is locked"))).toBeInTheDocument();
    // The shell's words here do not say how to remove the item, so the screen does.
    expect(within(alert).getByText(en.problems.keychainByHand)).toBeInTheDocument();
    expect(en.problems.keychainByHand).toMatch(/Keychain Access.*authexodus/);
    expect(within(alert).getByText(en.cleanup.carryOn)).toBeInTheDocument();

    // The phone-side ticks can be made regardless, but they alone do not finish.
    const finish = screen.getByRole("button", { name: en.cleanup.finish });
    for (const id of ["proxyOff", "profileRemoved", "authySignedIn"] as const) {
      await user.click(screen.getByRole("checkbox", { name: new RegExp(en.cleanup.items[id].label) }));
    }
    expect(finish).toBeDisabled();

    // Saying the key was removed by hand is the way out when Try again keeps failing.
    await user.click(within(alert).getByRole("checkbox", { name: en.cleanup.manualDone }));
    expect(finish).toBeEnabled();
    await user.click(finish);
    await screen.findByRole("heading", { level: 1 });
    expect(api.calls.filter((c) => c.method === "finish")).toHaveLength(1);
  });

  it("Try again after a failed cleanup can succeed", async () => {
    const { user } = await walkTo("cleanup", { cleanupError: "keychain busy" });
    const alert = await screen.findByRole("alert");
    await user.click(within(alert).getByRole("button", { name: en.common.tryAgain }));
    await screen.findByText(en.cleanup.clean(iphone));
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
});
