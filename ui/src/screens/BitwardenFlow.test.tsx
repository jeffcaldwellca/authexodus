import { screen, within } from "@testing-library/react";
import type { Proposal } from "../api";
import type { FakeScript } from "../api.fake";
import { en } from "../strings/en";
import { walkTo, type Harness } from "../test-utils";

const t = en.bitwarden;

const summary: FakeScript["summary"] = {
  tokens: [
    { id: "gh", title: "GitHub", username: "sam" },
    { id: "go", title: "Google", username: "sam@example.com" },
    { id: "fm", title: "Fastmail", username: null },
  ],
  invalid: [],
  native: [],
};

const proposals: Proposal[] = [
  { tokenId: "gh", confidence: "high", decision: { kind: "attach", itemId: "v-gh" },
    candidates: [{ itemId: "v-gh", name: "GitHub", username: "sam", hasCode: false }] },
  { tokenId: "go", confidence: "low", decision: { kind: "attach", itemId: "v-go1" },
    candidates: [
      { itemId: "v-go1", name: "Google", username: "sam@example.com", hasCode: false },
      { itemId: "v-go2", name: "Google (work)", username: "sam@work.example", hasCode: false },
    ] },
  { tokenId: "fm", confidence: "high", decision: { kind: "createNew" }, candidates: [] },
];

async function toReview(script: Partial<FakeScript> = {}): Promise<Harness> {
  const h = await walkTo("destination", { summary, proposals, ...script });
  const { user } = h;
  await user.click(screen.getByRole("button", { name: new RegExp(en.destination.options.bitwarden.title) }));
  await user.click(screen.getByRole("button", { name: t.prepare }));
  await screen.findByRole("heading", { level: 1, name: t.loginTitle });
  await user.type(screen.getByLabelText(t.email), "sam@example.com");
  await user.type(screen.getByLabelText(t.password), "master pw");
  await user.click(screen.getByRole("button", { name: t.signIn }));
  await screen.findByRole("heading", { level: 1, name: t.reviewTitle });
  return h;
}

describe("bitwarden path", () => {
  it("low_confidence_matches_require_a_choice_before_apply", async () => {
    const { api, user } = await toReview();
    const apply = screen.getByRole("button", { name: t.apply });
    expect(apply).toBeDisabled();
    expect(screen.getByText(t.needChoice(1))).toBeInTheDocument();

    // The uncertain row is a question with nothing chosen for the person, and it comes first.
    const google = screen.getByRole("combobox", { name: t.actionFor("Google") });
    expect(google).toHaveValue("");
    const rows = screen.getAllByRole("row");
    expect(within(rows[1]!).getByText(t.question)).toBeInTheDocument();
    expect(within(rows[1]!).getByRole("combobox")).toBe(google);
    // Confident rows arrive decided, but stay changeable.
    expect(screen.getByRole("combobox", { name: t.actionFor("GitHub") })).toHaveValue("attach:v-gh");
    expect(screen.getByRole("combobox", { name: t.actionFor("Fastmail") })).toHaveValue("createNew");
    expect(api.calls.some((c) => c.method === "bwApply")).toBe(false);

    await user.selectOptions(google, t.attach("Google (work)", "sam@work.example"));
    expect(apply).toBeEnabled();
    expect(screen.queryByText(t.needChoice(1))).not.toBeInTheDocument();

    // Every row offers a specific login, a new login, or skip.
    await user.selectOptions(screen.getByRole("combobox", { name: t.actionFor("GitHub") }), t.skip);

    await user.click(apply);
    await screen.findByRole("heading", { level: 1, name: t.reportTitle });
    expect(api.calls.find((c) => c.method === "bwApply")?.args[0]).toEqual([
      { tokenId: "gh", decision: { kind: "skip" } },
      { tokenId: "go", decision: { kind: "attach", itemId: "v-go2" } },
      { tokenId: "fm", decision: { kind: "createNew" } },
    ]);
    expect(screen.getByText(t.attached(1))).toBeInTheDocument();
    expect(screen.getByText(t.created(1))).toBeInTheDocument();
    expect(screen.getByText(t.skipped(1))).toBeInTheDocument();
  });

  it("failed_apply_offers_run_again", async () => {
    const { api, user } = await toReview({
      applyResults: [{ attached: 1, created: 0, skipped: 0, kept: [], failed: "503 Service Unavailable" }],
    });
    await user.selectOptions(screen.getByRole("combobox", { name: t.actionFor("Google") }), t.createNew);
    await user.click(screen.getByRole("button", { name: t.apply }));

    await screen.findByRole("heading", { level: 1, name: t.reportPartialTitle });
    const alert = screen.getByRole("alert");
    expect(within(alert).getByRole("heading", { name: en.failures.bitwardenServer.title })).toBeInTheDocument();
    expect(within(alert).getByText(en.failures.bitwardenServer.detail("503 Service Unavailable"))).toBeInTheDocument();
    expect(screen.getByText(t.attached(1))).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: en.common.done })).not.toBeInTheDocument();

    // Running again sends the same decisions, and this time it completes.
    await user.click(screen.getByRole("button", { name: t.runAgain }));
    await screen.findByRole("heading", { level: 1, name: t.reportTitle });
    const applies = api.calls.filter((c) => c.method === "bwApply");
    expect(applies).toHaveLength(2);
    expect(applies[1]!.args).toEqual(applies[0]!.args);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: t.runAgain })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: en.common.done })).toBeInTheDocument();
  });

  it("an apply that throws also offers Run again", async () => {
    const { user } = await toReview({ applyResults: [new Error("session expired")] });
    await user.selectOptions(screen.getByRole("combobox", { name: t.actionFor("Google") }), t.skip);
    await user.click(screen.getByRole("button", { name: t.apply }));
    await screen.findByText(en.failures.bitwardenServer.detail("session expired"));
    expect(screen.getByRole("button", { name: t.runAgain })).toBeInTheDocument();
  });

  it("asks for the two-step code, then signs in with it and forgets the master password", async () => {
    const { api, user } = await walkTo("destination", { summary, proposals, loginResults: [{ kind: "badCredentials" }, { kind: "needsTwoFactor" }] });
    await user.click(screen.getByRole("button", { name: new RegExp(en.destination.options.bitwarden.title) }));
    await user.click(screen.getByRole("button", { name: t.prepare }));
    await screen.findByRole("heading", { level: 1, name: t.loginTitle });
    await user.type(screen.getByLabelText(t.email), "sam@example.com");
    await user.type(screen.getByLabelText(t.password), "master pw");
    await user.click(screen.getByRole("radio", { name: t.regions.eu }));

    await user.click(screen.getByRole("button", { name: t.signIn }));
    await screen.findByText(t.badCredentials);
    expect(screen.getByLabelText(t.password)).toHaveValue("master pw");

    await user.click(screen.getByRole("button", { name: t.signIn }));
    await user.type(await screen.findByLabelText(t.twoFactor), "123456");
    await user.click(screen.getByRole("button", { name: t.signIn }));
    await screen.findByRole("heading", { level: 1, name: t.reviewTitle });

    const logins = api.calls.filter((c) => c.method === "bwLogin").map((c) => c.args[0]);
    expect(logins).toHaveLength(3);
    expect(logins[2]).toEqual({ email: "sam@example.com", password: "master pw", region: { kind: "eu" }, twoFactorCode: "123456" });
    expect(screen.queryByLabelText(t.password)).not.toBeInTheDocument();
  });

  it("a login that already has a code is offered as left alone, and is reported as kept", async () => {
    const withCode: Proposal[] = [
      { tokenId: "gh", confidence: "high", decision: { kind: "attach", itemId: "v-gh" },
        candidates: [{ itemId: "v-gh", name: "GitHub", username: "sam", hasCode: true }] },
    ];
    const { user } = await toReview({ summary: { ...summary, tokens: [summary.tokens[0]!] }, proposals: withCode });
    expect(screen.getByRole("option", { name: t.attachHasCode("GitHub", "sam") })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: t.apply }));
    await screen.findByText(t.kept(["GitHub"]));
  });
});
