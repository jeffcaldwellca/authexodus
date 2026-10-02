// Helpers for driving the whole wizard in tests, the way a person and their phone would.
import { act, cleanup, render, screen } from "@testing-library/react";
import userEvent, { type UserEvent } from "@testing-library/user-event";
import type { AppState, Device, Step } from "./api";
import { createFakeApi, FAKE_PASSWORD, type FakeApi, type FakeScript } from "./api.fake";
import { App } from "./App";
import { en } from "./strings/en";

export type Harness = { api: FakeApi; user: UserEvent };

export async function mountApp(initial: Partial<AppState> = {}, script: Partial<FakeScript> = {}): Promise<Harness> {
  const api = createFakeApi(initial, script);
  const user = userEvent.setup();
  render(<App api={api} />);
  await screen.findByRole("heading", { level: 1 });
  return { api, user };
}

export async function tickAllChecks(user: UserEvent) {
  for (const box of screen.getAllByRole("checkbox")) await user.click(box);
}

/** Scans (ticks) the first QR code and goes back, which is one way of having "moved" codes. */
export async function moveByQr(user: UserEvent) {
  await user.click(screen.getByRole("button", { name: new RegExp(en.destination.options.qr.title) }));
  await screen.findByRole("heading", { level: 1, name: en.destination.qr.title });
  await user.click(await screen.findByRole("checkbox", { name: en.destination.qr.scanned }));
  await user.click(screen.getByRole("button", { name: en.destination.backToOptions }));
  await screen.findByRole("heading", { level: 1, name: en.destination.title });
}

const ORDER: Step[] = ["welcome", "connect", "certificate", "authy", "unlock", "destination", "verify", "cleanup"];

/** Opens the same app again in a new window, as a reload of the webview would. */
export async function reload(api: FakeApi): Promise<void> {
  cleanup();
  render(<App api={api} />);
  await screen.findByRole("heading", { level: 1 });
}

/** Walks a fresh wizard forward to `step` using only what a person could do. */
export async function walkTo(step: Step, script: Partial<FakeScript> = {}, device: Device = "iphone"): Promise<Harness> {
  const h = await mountApp({}, script);
  const { api, user } = h;
  const reach = ORDER.indexOf(step);
  if (reach >= 1) {
    await user.click(screen.getByRole("radio", { name: en.deviceName[device] }));
    await tickAllChecks(user);
    await user.click(screen.getByRole("button", { name: en.welcome.start }));
    await screen.findByRole("heading", { level: 1, name: en.connect.title(en.deviceName[device]) });
    await screen.findByText(en.connect.waiting(en.deviceName[device]));
  }
  if (reach >= 2) {
    act(() => api.emitProxyEvent({ kind: "deviceConnected" }));
    await screen.findByRole("heading", { level: 1, name: en.certificate.title });
  }
  if (reach >= 3) {
    act(() => api.emitProxyEvent({ kind: "trustWorking" }));
    await screen.findByRole("heading", { level: 1, name: en.authy.title });
  }
  if (reach >= 4) {
    act(() => api.emitProxyEvent({ kind: "backupCaptured", count: 10 }));
    await screen.findByRole("heading", { level: 1, name: en.unlock.title });
  }
  if (reach >= 5) {
    await user.type(screen.getByLabelText(en.unlock.label), script.password ?? FAKE_PASSWORD);
    await user.click(screen.getByRole("button", { name: en.unlock.submit }));
    await screen.findByRole("heading", { level: 1, name: en.destination.title });
  }
  if (reach >= 6) {
    await moveByQr(user);
    await user.click(screen.getByRole("button", { name: en.destination.continue }));
    await screen.findByRole("heading", { level: 1, name: en.verify.title });
  }
  if (reach >= 7) {
    await user.click(screen.getByRole("button", { name: en.verify.confirm }));
    await screen.findByRole("heading", { level: 1, name: en.cleanup.title });
  }
  return h;
}
