import { screen, waitFor, within } from "@testing-library/react";
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
    // Refused outright, with no code: a plain sentence (never the raw text), not a claim that it stopped part-way.
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByText(t.applyRejected)).toBeInTheDocument();
    expect(within(alert).getByText(en.problems.unexplained)).toBeInTheDocument();
    expect(alert.textContent).not.toContain("session expired");
    expect(screen.getByRole("heading", { level: 1, name: t.reportStoppedTitle })).toBeInTheDocument();
    expect(screen.queryByText(en.failures.bitwardenServer.title)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: t.runAgain })).toBeInTheDocument();
  });

  async function toLogin(script: Partial<FakeScript>): Promise<Harness> {
    const h = await walkTo("destination", { summary, proposals, ...script });
    await h.user.click(screen.getByRole("button", { name: new RegExp(en.destination.options.bitwarden.title) }));
    await h.user.click(screen.getByRole("button", { name: t.prepare }));
    await screen.findByRole("heading", { level: 1, name: t.loginTitle });
    await h.user.type(screen.getByLabelText(t.email), "sam@example.com");
    await h.user.type(screen.getByLabelText(t.password), "master pw");
    return h;
  }
  /** True when the master password is anywhere in the page: a field's value or its text. */
  const passwordOnPage = () =>
    [...document.querySelectorAll("input")].some((i) => i.value === "master pw") || document.body.textContent!.includes("master pw");
  const logins = (api: Harness["api"]) => api.calls.filter((c) => c.method === "bwLogin").map((c) => c.args[0]);

  it("says before sign-in which two-step methods work, and the way out for the others", async () => {
    await toLogin({});
    expect(screen.getByText(t.twoStepLimit)).toBeInTheDocument();
    expect(t.twoStepLimit).toMatch(/only codes from an authenticator app work here/);
    expect(t.twoStepLimit).toMatch(/Save a file for another app, then Bitwarden/);
    expect(t.twoStepLimit).toMatch(/sign in with an API key instead/);
    expect(screen.getByText(t.loginLede)).toBeInTheDocument();
    expect(t.loginLede).toMatch(/does not keep it/);
  });

  it("rejected credentials clear the master password from the form", async () => {
    const { user } = await toLogin({ loginResults: [{ kind: "badCredentials" }] });
    await user.click(screen.getByRole("button", { name: t.signIn }));
    await screen.findByText(t.badCredentials);
    expect(screen.getByLabelText(t.password)).toHaveValue("");
    expect(passwordOnPage()).toBe(false);
    expect(screen.getByRole("button", { name: t.signIn })).toBeDisabled();
  });

  it("the master password leaves the form during the two-step round trip and is still sent with the code", async () => {
    const { api, user } = await toLogin({ loginResults: [{ kind: "needsTwoFactor" }] });
    await user.click(screen.getByRole("radio", { name: t.regions.eu }));
    await user.click(screen.getByRole("button", { name: t.signIn }));

    // Asked for a code: the code field appears focused, and the password is no longer in a field.
    const code = await screen.findByLabelText(t.twoFactor);
    expect(code).toHaveFocus();
    expect(screen.getByText(t.needsTwoFactor)).toBeInTheDocument();
    expect(t.needsTwoFactor).toMatch(/authenticator app for Bitwarden, type its 6-digit code/);
    expect(screen.queryByLabelText(t.password)).not.toBeInTheDocument();
    expect(screen.getByText(t.passwordHeld)).toBeInTheDocument();
    expect(passwordOnPage()).toBe(false);
    // No code typed yet: nothing to send.
    expect(screen.getByRole("button", { name: t.signIn })).toBeDisabled();

    await user.type(code, "123456");
    await user.click(screen.getByRole("button", { name: t.signIn }));
    await screen.findByRole("heading", { level: 1, name: t.reviewTitle });
    expect(logins(api)).toHaveLength(2);
    expect(logins(api)[1]).toEqual({ email: "sam@example.com", password: "master pw", region: { kind: "eu" }, twoFactorCode: "123456" });
    expect(passwordOnPage()).toBe(false);
  });

  it("a wrong two-step code gets its own message and another try, without retyping the password", async () => {
    const { api, user } = await toLogin({ loginResults: [{ kind: "needsTwoFactor" }, { kind: "badTwoFactorCode" }] });
    await user.click(screen.getByRole("button", { name: t.signIn }));
    await user.type(await screen.findByLabelText(t.twoFactor), "111111");
    await user.click(screen.getByRole("button", { name: t.signIn }));

    await screen.findByText(t.wrongTwoFactor);
    expect(screen.queryByText(t.badCredentials)).not.toBeInTheDocument();
    expect(screen.queryByText(t.loginFailed)).not.toBeInTheDocument();
    const code = screen.getByLabelText(t.twoFactor);
    expect(code).toHaveValue("");
    expect(code).toHaveFocus();
    expect(passwordOnPage()).toBe(false);

    await user.type(code, "222222");
    await user.click(screen.getByRole("button", { name: t.signIn }));
    await screen.findByRole("heading", { level: 1, name: t.reviewTitle });
    expect(logins(api)[2]).toMatchObject({ password: "master pw", twoFactorCode: "222222" });
  });

  it("the held master password is dropped when the credentials are refused after all", async () => {
    const { api, user } = await toLogin({ loginResults: [{ kind: "needsTwoFactor" }, { kind: "badCredentials" }] });
    await user.click(screen.getByRole("button", { name: t.signIn }));
    await user.type(await screen.findByLabelText(t.twoFactor), "111111");
    await user.click(screen.getByRole("button", { name: t.signIn }));
    await screen.findByText(t.badCredentials);

    // The password must be typed again: nothing was kept to send.
    expect(screen.getByLabelText(t.password)).toHaveValue("");
    expect(screen.queryByText(t.passwordHeld)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(t.twoFactor)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: t.signIn })).toBeDisabled();
    await user.type(screen.getByLabelText(t.password), "second try");
    await user.click(screen.getByRole("button", { name: t.signIn }));
    await screen.findByRole("heading", { level: 1, name: t.reviewTitle });
    expect(logins(api)[2]).toMatchObject({ password: "second try" });
    expect(logins(api)[2]).not.toHaveProperty("twoFactorCode");
  });

  it("a sign-in that fails outright clears the password and points to the file route", async () => {
    const { api, user } = await toLogin({});
    api.bwLogin = async () => { throw new Error("bw: unexpected output"); };
    await user.click(screen.getByRole("button", { name: t.signIn }));
    await screen.findByText(t.loginFailed);
    // A rejection with no code: a plain sentence is shown; the raw text is developer text.
    expect(screen.getByText(en.problems.unexplained)).toBeInTheDocument();
    expect(document.body.textContent).not.toContain("bw: unexpected output");
    expect(screen.getByText(t.loginFailedAdvice)).toBeInTheDocument();
    expect(t.loginFailedAdvice).toMatch(/Save a file for another app, then Bitwarden/);
    expect(screen.getByLabelText(t.password)).toHaveValue("");
    expect(passwordOnPage()).toBe(false);
  });

  it("leaving the sign-in screen mid two-step drops the held password: coming back asks for it again", async () => {
    const { api, user } = await toLogin({ loginResults: [{ kind: "needsTwoFactor" }] });
    await user.click(screen.getByRole("button", { name: t.signIn }));
    await screen.findByLabelText(t.twoFactor);
    await user.click(screen.getByRole("button", { name: en.destination.backToOptions }));

    await user.click(screen.getByRole("button", { name: new RegExp(en.destination.options.bitwarden.title) }));
    await user.click(screen.getByRole("button", { name: t.prepare }));
    await screen.findByRole("heading", { level: 1, name: t.loginTitle });
    expect(screen.getByLabelText(t.password)).toHaveValue("");
    expect(screen.queryByLabelText(t.twoFactor)).not.toBeInTheDocument();
    expect(logins(api)).toHaveLength(1);
  });

  it("the master password can be shown while typing", async () => {
    const { user } = await toLogin({});
    const field = screen.getByLabelText(t.password);
    expect(field).toHaveAttribute("type", "password");
    await user.click(screen.getByRole("button", { name: t.showPassword }));
    expect(field).toHaveAttribute("type", "text");
  });

  it("a login that already has a code is listed but cannot be chosen, and the row waits for an answer", async () => {
    // What the core really sends when the only match already holds a code: the login is
    // listed, nothing is chosen for the person, and the row is low confidence.
    const taken: Proposal[] = [
      { tokenId: "gh", confidence: "low", decision: { kind: "createNew" },
        candidates: [{ itemId: "v-gh", name: "GitHub", username: "sam", hasCode: true }] },
    ];
    const { api, user } = await toReview({ summary: { ...summary, tokens: [summary.tokens[0]!] }, proposals: taken });
    const select = screen.getByRole("combobox", { name: t.actionFor("GitHub") });
    expect(select).toHaveValue("");
    expect(select).toHaveAccessibleDescription(t.questionHasCode);
    expect(screen.getByRole("button", { name: t.apply })).toBeDisabled();

    const option = screen.getByRole("option", { name: t.attachHasCode("GitHub", "sam") });
    expect(option).toBeDisabled();
    expect(option.textContent).toMatch(/already has a code/);

    await user.selectOptions(select, t.createNew);
    await user.click(screen.getByRole("button", { name: t.apply }));
    await screen.findByRole("heading", { level: 1, name: t.reportTitle });
    expect(api.calls.find((c) => c.method === "bwApply")?.args[0]).toEqual([{ tokenId: "gh", decision: { kind: "createNew" } }]);
  });

  it("a row with several free logins asks which one, and the question is tied to its menu", async () => {
    await toReview();
    expect(screen.getByRole("combobox", { name: t.actionFor("Google") })).toHaveAccessibleDescription(t.question);
    expect(t.question).toBe("Which Bitwarden login does this code belong to?");
    expect(screen.getByRole("combobox", { name: t.actionFor("GitHub") })).not.toHaveAccessibleDescription();
  });

  it("the review says what was pre-filled, what happens to unmatched accounts, and what skip means", async () => {
    await toReview();
    expect(screen.getByText(t.reviewLede)).toBeInTheDocument();
    expect(t.reviewLede).toMatch(/could not match become new entries in the “Authy import” folder, which you can merge in Bitwarden afterwards/);
    expect(t.reviewLede).toMatch(/Skipped accounts stay only in Authy/);
  });

  it("focus moves to the heading on every stage of the Bitwarden path", async () => {
    const { user } = await walkTo("destination", { summary, proposals });
    const heading = () => screen.getByRole("heading", { level: 1 });
    await user.click(screen.getByRole("button", { name: new RegExp(en.destination.options.bitwarden.title) }));
    expect(heading()).toHaveTextContent(t.introTitle);
    expect(heading()).toHaveFocus();

    await user.click(screen.getByRole("button", { name: t.prepare }));
    await screen.findByRole("heading", { level: 1, name: t.loginTitle });
    await waitFor(() => expect(heading()).toHaveFocus());

    await user.type(screen.getByLabelText(t.email), "sam@example.com");
    await user.type(screen.getByLabelText(t.password), "master pw");
    await user.click(screen.getByRole("button", { name: t.signIn }));
    await screen.findByRole("heading", { level: 1, name: t.reviewTitle });
    await waitFor(() => expect(heading()).toHaveFocus());

    await user.selectOptions(screen.getByRole("combobox", { name: t.actionFor("Google") }), t.skip);
    await user.click(screen.getByRole("button", { name: t.apply }));
    await screen.findByRole("heading", { level: 1, name: t.reportTitle });
    await waitFor(() => expect(heading()).toHaveFocus());
    expect(document.activeElement).not.toBe(document.body);
  });

  it("a self-hosted server needs a full https address before sign-in is possible", async () => {
    const { api, user } = await walkTo("destination", { summary, proposals });
    await user.click(screen.getByRole("button", { name: new RegExp(en.destination.options.bitwarden.title) }));
    await user.click(screen.getByRole("button", { name: t.prepare }));
    await screen.findByRole("heading", { level: 1, name: t.loginTitle });
    await user.type(screen.getByLabelText(t.email), "sam@example.com");
    await user.type(screen.getByLabelText(t.password), "master pw");
    const signIn = screen.getByRole("button", { name: t.signIn });
    expect(signIn).toBeEnabled();

    await user.click(screen.getByRole("radio", { name: t.regions.selfHosted }));
    const url = screen.getByLabelText(t.serverUrl);
    expect(signIn).toBeDisabled();
    expect(screen.getByText(t.serverUrlHint)).toBeInTheDocument();

    for (const bad of ["vault.example.com", "http://vault.example.com", "https://", "https:// vault"]) {
      await user.clear(url);
      await user.type(url, bad);
      expect(signIn, bad).toBeDisabled();
      expect(screen.getByText(t.serverUrlInvalid)).toBeInTheDocument();
      expect(url).toHaveAttribute("aria-invalid", "true");
    }
    // Pressing Enter in the form does not get around it.
    await user.type(url, "{Enter}");
    expect(api.calls.some((c) => c.method === "bwLogin")).toBe(false);

    await user.clear(url);
    await user.type(url, "https://vault.example.com");
    expect(signIn).toBeEnabled();
    await user.click(signIn);
    await screen.findByRole("heading", { level: 1, name: t.reviewTitle });
    expect(api.calls.find((c) => c.method === "bwLogin")?.args[0]).toMatchObject({
      region: { kind: "selfHosted", url: "https://vault.example.com" },
    });
  });
});
