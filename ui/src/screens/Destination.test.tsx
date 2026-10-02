import { act, render, screen, within } from "@testing-library/react";
import { vi } from "vitest";
import { createFakeApi } from "../api.fake";
import { en } from "../strings/en";
import { moveByQr, walkTo } from "../test-utils";
import { initialState } from "../wizard/machine";
import { Verify } from "./Verify";

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

    // Not exported: the QR walk covers the two usable accounts and nothing else.
    await user.click(screen.getByRole("button", { name: new RegExp(en.destination.options.qr.title) }));
    await screen.findByAltText(en.destination.qr.alt("GitHub"));
    expect(screen.getByText(en.destination.qr.position(1, 2))).toBeInTheDocument();
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
    await screen.findByText(en.destination.file.saved("/Users/sam/Downloads/authy-export-aegis.json"));
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

  it("refreshes the live codes every second", async () => {
    vi.useFakeTimers();
    let now = 1_700_000_000_000;
    const api = createFakeApi({}, { now: () => now });
    const summary = await api.unlock(api.script.password);
    if ("error" in summary) throw new Error("fake rejected its own password");
    api.calls.length = 0;
    const state = { ...initialState(), step: "verify" as const, summary };

    render(<Verify api={api} state={state} dispatch={() => undefined} proxy={null} onRestart={() => undefined} restart="idle" />);
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    const first = (await api.liveCodes())[0]!;
    expect(screen.getByText(`${first.code.slice(0, 3)} ${first.code.slice(3)}`)).toBeInTheDocument();
    expect(screen.getAllByText(en.verify.secondsLeft(first.secondsLeft)).length).toBeGreaterThan(0);

    const before = api.calls.filter((c) => c.method === "liveCodes").length;
    now += 3000;
    await act(async () => { await vi.advanceTimersByTimeAsync(3000); });
    expect(api.calls.filter((c) => c.method === "liveCodes").length).toBe(before + 3);
    expect(screen.getAllByText(en.verify.secondsLeft(first.secondsLeft - 3)).length).toBeGreaterThan(0);
  });
});
