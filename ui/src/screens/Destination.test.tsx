import { act, render, screen, within } from "@testing-library/react";
import { vi } from "vitest";
import { createFakeApi } from "../api.fake";
import { en } from "../strings/en";
import { moveByQr, walkTo } from "../test-utils";
import { initialState } from "../wizard/machine";
import { REFRESH_MS, REFRESH_NEAR_CHANGE_MS, Verify } from "./Verify";

describe("destination", () => {
  it("invalid_and_native_tokens_are_listed_not_exported", async () => {
    const { api, user } = await walkTo("destination", {
      summary: {
        tokens: [{ id: "a", title: "GitHub", username: "sam" }, { id: "b", title: "Dropbox", username: null }],
        native: [{ name: "Twitch" }],
        invalid: [{ name: "Old VPN", reason: "notBase32" }, { name: "Stub", reason: "tooShort" }],
      },
    });

    // Listed by name, each with what to do about it.
    const section = screen.getByRole("region", { name: en.destination.cantMoveTitle(3) });
    expect(within(section).getByText(en.destination.native("Twitch"))).toBeInTheDocument();
    expect(within(section).getByText(en.destination.invalid("Old VPN"))).toBeInTheDocument();
    expect(within(section).getByText(en.destination.invalid("Stub"))).toBeInTheDocument();
    expect(screen.getByText(en.destination.lede(2))).toBeInTheDocument();
    // It comes before the choices, so it is seen before anything is moved.
    const firstOption = screen.getByRole("button", { name: new RegExp(en.destination.options.qr.title) });
    expect(section.compareDocumentPosition(firstOption) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();

    // Not exported: the QR walk covers the two usable accounts and nothing else.
    await user.click(screen.getByRole("button", { name: new RegExp(en.destination.options.qr.title) }));
    await screen.findByAltText(en.destination.qr.alt("GitHub"));
    expect(screen.getByText(en.destination.qr.position(1, 2))).toBeInTheDocument();
    await user.click(screen.getByRole("checkbox", { name: en.destination.qr.scanned }));
    await user.click(screen.getByRole("button", { name: en.common.next }));
    await screen.findByAltText(en.destination.qr.alt("Dropbox"));
    await user.click(screen.getByRole("button", { name: en.common.done }));
    expect(api.calls.filter((c) => c.method === "tokenQr").map((c) => c.args[0])).toEqual(["a", "b"]);

    // Nor do they appear among the codes to verify.
    await user.click(screen.getByRole("button", { name: en.destination.continue }));
    const codes = await screen.findByRole("list", { name: en.verify.listLabel });
    expect(within(codes).getAllByRole("listitem")).toHaveLength(2);
    expect(within(codes).queryByText(/Twitch|Old VPN|Stub/)).not.toBeInTheDocument();
  });

  it("saving a file warns to delete it and adds a cleanup item", async () => {
    const { api, user } = await walkTo("destination");
    await user.click(screen.getByRole("button", { name: new RegExp(en.destination.options.file.title) }));
    expect(screen.getByText(en.destination.file.warning)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: en.destination.file.save(en.destination.file.apps.aegis) }));
    await screen.findByText(en.destination.file.saved("/Users/sam/Downloads/authy-aegis-import.json"));
    expect(api.calls.find((c) => c.method === "exportFile")?.args).toEqual(["aegis"]);

    await user.click(screen.getByRole("button", { name: en.common.done }));
    await user.click(screen.getByRole("button", { name: en.destination.continue }));
    await user.click(await screen.findByRole("button", { name: en.verify.confirm }));
    await screen.findByRole("heading", { level: 1, name: en.cleanup.title });
    expect(screen.getByRole("checkbox", { name: new RegExp(en.cleanup.items.fileDeleted.label) })).toBeInTheDocument();
    expect(screen.getAllByRole("checkbox")).toHaveLength(4);
  });

  it("a cancelled save dialog adds nothing to cleanup", async () => {
    const { user } = await walkTo("destination", { exportResults: [{ cancelled: true }] });
    await user.click(screen.getByRole("button", { name: new RegExp(en.destination.options.file.title) }));
    await user.click(screen.getByRole("button", { name: en.destination.file.save(en.destination.file.apps.twoFas) }));
    await screen.findByText(en.destination.file.cancelled);
    await user.click(screen.getByRole("button", { name: en.common.done }));
    // Nothing was saved, so nothing has been moved yet either.
    expect(screen.getByRole("button", { name: en.destination.continue })).toBeDisabled();
    await moveByQr(user);
    await user.click(screen.getByRole("button", { name: en.destination.continue }));
    await user.click(await screen.findByRole("button", { name: en.verify.confirm }));
    await screen.findByRole("heading", { level: 1, name: en.cleanup.title });
    expect(screen.queryByRole("checkbox", { name: new RegExp(en.cleanup.items.fileDeleted.label) })).not.toBeInTheDocument();
    expect(screen.getAllByRole("checkbox")).toHaveLength(3);
  });

  it("the Google screen lists the accounts its codes cannot carry, with what to do", async () => {
    const { api, user } = await walkTo("destination", { googleUnsupported: ["Steam", "Old bank"] });
    await user.click(screen.getByRole("button", { name: new RegExp(en.destination.options.google.title) }));
    await screen.findByAltText(en.destination.google.alt(1));
    expect(screen.getByText(en.destination.google.unsupportedTitle(2))).toBeInTheDocument();
    expect(screen.getByText(en.destination.google.unsupportedBody)).toBeInTheDocument();
    expect(screen.getByText("Steam")).toBeInTheDocument();
    expect(screen.getByText("Old bank")).toBeInTheDocument();
    expect(api.calls.filter((c) => c.method === "googleUnsupported")).toHaveLength(1);
  });

  it("the Google screen says nothing extra when every account fits", async () => {
    const { user } = await walkTo("destination");
    await user.click(screen.getByRole("button", { name: new RegExp(en.destination.options.google.title) }));
    await screen.findByAltText(en.destination.google.alt(1));
    expect(screen.queryByText(en.destination.google.unsupportedBody)).not.toBeInTheDocument();
  });
});

describe("verify", () => {
  afterEach(() => { vi.useRealTimers(); });

  async function mountVerify(now: { ms: number }, script: Parameters<typeof createFakeApi>[1] = {}) {
    const api = createFakeApi({}, { now: () => now.ms, ...script });
    const summary = await api.unlock(api.script.password);
    if ("error" in summary) throw new Error("fake rejected its own password");
    api.calls.length = 0;
    const state = { ...initialState(), step: "verify" as const, summary };
    render(<Verify api={api} state={state} dispatch={() => undefined} proxy={null} onRestart={() => undefined} restart="idle" restartError={null} certConstrained={null} />);
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    return api;
  }
  const polls = (api: ReturnType<typeof createFakeApi>) => api.calls.filter((c) => c.method === "liveCodes").length;

  it("refreshes the live codes every second", async () => {
    vi.useFakeTimers();
    // 20 seconds into a 30-second period: nowhere near a change.
    const now = { ms: 1_700_000_000_000 - (1_700_000_000_000 % 30_000) + 10_000 };
    const api = await mountVerify(now);
    const first = (await api.liveCodes())[0]!;
    expect(first.secondsLeft).toBe(20);
    expect(screen.getByText(`${first.code.slice(0, 3)} ${first.code.slice(3)}`)).toBeInTheDocument();
    expect(screen.getAllByText(en.verify.secondsLeft(20)).length).toBeGreaterThan(0);
    // The countdown is also said in words for a screen reader.
    expect(screen.getAllByText(en.verify.secondsLeftLabel(20)).length).toBeGreaterThan(0);

    const before = polls(api);
    for (let i = 0; i < 3; i++) {
      now.ms += REFRESH_MS;
      await act(async () => { await vi.advanceTimersByTimeAsync(REFRESH_MS); });
    }
    expect(polls(api)).toBe(before + 3);
    expect(screen.getAllByText(en.verify.secondsLeft(17)).length).toBeGreaterThan(0);
  });

  it("polls faster in the last second, so the new code appears as the old one expires", async () => {
    vi.useFakeTimers();
    // One second before the period ends.
    const boundary = 1_700_000_000_000 - (1_700_000_000_000 % 30_000) + 30_000;
    const now = { ms: boundary - 1000 };
    const api = await mountVerify(now);
    const old = (await api.liveCodes())[0]!;
    expect(old.secondsLeft).toBe(1);
    const shown = (code: string) => screen.queryByText(`${code.slice(0, 3)} ${code.slice(3)}`);
    expect(shown(old.code)).toBeInTheDocument();

    // Cross the boundary by a quarter of a second: a once-a-second poll would still show the old code.
    const before = polls(api);
    for (let i = 0; i < 5; i++) {
      now.ms += REFRESH_NEAR_CHANGE_MS;
      await act(async () => { await vi.advanceTimersByTimeAsync(REFRESH_NEAR_CHANGE_MS); });
    }
    expect(now.ms).toBe(boundary + 250);
    // Four quick polls reach the boundary; from there the pace drops back to once a second.
    expect(polls(api) - before).toBe(4);
    const fresh = (await api.liveCodes())[0]!;
    expect(fresh.code).not.toBe(old.code);
    expect(shown(fresh.code)).toBeInTheDocument();
    expect(shown(old.code)).not.toBeInTheDocument();
  });

  it("says so when the codes cannot be worked out, instead of loading for ever, and recovers", async () => {
    vi.useFakeTimers();
    const now = { ms: 1_700_000_010_000 };
    const api = await mountVerify(now, { liveCodesError: "The backup is not unlocked." });
    expect(screen.getByRole("alert")).toHaveTextContent(en.verify.failed);
    expect(screen.queryByText(en.verify.loading)).not.toBeInTheDocument();

    api.script.liveCodesError = null;
    await act(async () => { await vi.advanceTimersByTimeAsync(REFRESH_MS); });
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.getByRole("list", { name: en.verify.listLabel })).toBeInTheDocument();
  });

  it("tells the person what to do when a code still differs", () => {
    expect(en.verify.mismatch).toMatch(/Still different\? Go back and move that account again\. Do not clean up yet\./);
  });
});
