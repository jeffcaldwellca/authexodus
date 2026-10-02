// The Bitwarden path beyond the straight walk: download progress and cancel, sign-in by API
// key, rejections by code, a session that ends part-way, attaching by hand, and the report.
import { act, screen, waitFor, within } from "@testing-library/react";
import type { Proposal, VaultLoginView } from "../api";
import { ApiError } from "../api.errors";
import type { FakeScript } from "../api.fake";
import { en } from "../strings/en";
import { walkTo, type Harness } from "../test-utils";

const t = en.bitwarden;
const by = en.problems.byCode;
const iphone = en.deviceName.iphone;

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
const vault: VaultLoginView[] = [
  { itemId: "v-gh", name: "GitHub", username: "sam", hasCode: false },
  { itemId: "v-go1", name: "Google", username: "sam@example.com", hasCode: false },
  { itemId: "v-go2", name: "Google (work)", username: "sam@work.example", hasCode: false },
  { itemId: "v-fm", name: "Fastmail", username: "sam@fastmail.example", hasCode: false },
  { itemId: "v-bank", name: "Bank", username: null, hasCode: true },
];
const base = { summary, proposals, vault };

async function toIntro(script: Partial<FakeScript> = {}): Promise<Harness> {
  const h = await walkTo("destination", { ...base, ...script });
  await h.user.click(screen.getByRole("button", { name: new RegExp(en.destination.options.bitwarden.title) }));
  return h;
}
async function toLogin(script: Partial<FakeScript> = {}): Promise<Harness> {
  const h = await toIntro(script);
  await h.user.click(screen.getByRole("button", { name: t.prepare }));
  await screen.findByRole("heading", { level: 1, name: t.loginTitle });
  return h;
}
async function typeLogin({ user }: Harness, email = "sam@example.com") {
  await user.type(screen.getByLabelText(t.email), email);
  await user.type(screen.getByLabelText(t.password), "master pw");
}
async function toReview(script: Partial<FakeScript> = {}): Promise<Harness> {
  const h = await toLogin(script);
  await typeLogin(h);
  await h.user.click(screen.getByRole("button", { name: t.signIn }));
  await screen.findByRole("heading", { level: 1, name: t.reviewTitle });
  return h;
}
const secretsOnPage = (...secrets: string[]) => secrets.some((secret) =>
  [...document.querySelectorAll("input")].some((i) => i.value === secret) || document.body.textContent!.includes(secret));
const logins = (api: Harness["api"]) => api.calls.filter((c) => c.method === "bwLogin").map((c) => c.args[0]);

describe("the download", () => {
  it("tells the person up front which accounts need an API key", async () => {
    await toIntro();
    expect(screen.getByText(t.introKeyTitle)).toBeInTheDocument();
    expect(screen.getByText(t.introKey)).toBeInTheDocument();
    expect(t.introKey).toMatch(/no two-step login, or uses email or a security key, you need a Bitwarden API key/);
    expect(t.introKey).toMatch(/authenticator app, your master password and a code are enough/);
    expect(screen.getByText(en.common.untested(t.name))).toBeInTheDocument();
  });

  it("shows the progress lines as they arrive, from the first one", async () => {
    const { api, user } = await toIntro({ hold: { bwPrepare: true }, prepareProgress: ["Fetching the tool", "Checking it", "Unpacking it"] });
    await user.click(screen.getByRole("button", { name: t.prepare }));
    const log = await screen.findByRole("log", { name: t.progressLabel });
    await waitFor(() => expect(within(log).getAllByRole("listitem").map((li) => li.textContent)).toEqual(["Fetching the tool", "Checking it", "Unpacking it"]));
    expect(screen.getByText(t.preparing)).toBeInTheDocument();
    act(() => api.release("bwPrepare"));
    await screen.findByRole("heading", { level: 1, name: t.loginTitle });
  });

  it("can be cancelled, and then says so instead of reporting a failure", async () => {
    const { api, user } = await toIntro({ hold: { bwPrepare: true } });
    expect(screen.queryByRole("button", { name: en.common.cancel })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: t.prepare }));
    await user.click(await screen.findByRole("button", { name: en.common.cancel }));
    expect(await screen.findByText(t.prepareCancelled)).toBeInTheDocument();
    expect(api.calls.filter((c) => c.method === "bwCancel")).toHaveLength(1);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 1, name: t.introTitle })).toBeInTheDocument();

    // It can be started again.
    api.script.hold = {};
    await user.click(screen.getByRole("button", { name: t.prepare }));
    await screen.findByRole("heading", { level: 1, name: t.loginTitle });
  });

  it("a download that does not match gets its own serious message, not advice about the internet", async () => {
    const { user } = await toIntro({ failures: { bwPrepare: [new ApiError("bw_checksum_mismatch", "The file's checksum was not the one expected.")] } });
    await user.click(screen.getByRole("button", { name: t.prepare }));
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByText("The download did not match what Bitwarden published.")).toBeInTheDocument();
    expect(within(alert).getByText("Nothing was run. Try again later; if it keeps happening, use Save a file instead.")).toBeInTheDocument();
    expect(within(alert).getByText("The file's checksum was not the one expected.")).toBeInTheDocument();
    expect(alert.textContent).not.toMatch(/internet connection/);
    expect(screen.getByRole("heading", { level: 1, name: t.introTitle })).toBeInTheDocument();
  });

  it("a download that fails says to check the connection, with the shell's reason", async () => {
    const { user } = await toIntro({ failures: { bwPrepare: [new ApiError("bw_download_failed", "github.com could not be reached.")] } });
    await user.click(screen.getByRole("button", { name: t.prepare }));
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByText(by.bw_download_failed.title(iphone))).toBeInTheDocument();
    expect(within(alert).getByText("github.com could not be reached.")).toBeInTheDocument();
    expect(within(alert).getByText(by.bw_download_failed.advice(iphone))).toBeInTheDocument();
    // Trying again works.
    await user.click(screen.getByRole("button", { name: t.prepare }));
    await screen.findByRole("heading", { level: 1, name: t.loginTitle });
  });
});

describe("sign-in rejections", () => {
  it("a bad email is called a bad email, with the shell's sentence, and the email field takes focus", async () => {
    const h = await toLogin({ failures: { bwLogin: [new ApiError("bad_email", "That does not look like an email address.")] } });
    await typeLogin(h, "sam");
    await h.user.click(screen.getByRole("button", { name: t.signIn }));
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByText(by.bad_email.title(iphone))).toBeInTheDocument();
    expect(within(alert).getByText("That does not look like an email address.")).toBeInTheDocument();
    expect(alert.textContent).not.toMatch(/internet/);
    expect(screen.queryByText(t.loginFailed)).not.toBeInTheDocument();
    expect(screen.getByLabelText(t.email)).toHaveAttribute("aria-invalid", "true");
    expect(screen.getByLabelText(t.email)).toHaveFocus();
    expect(secretsOnPage("master pw")).toBe(false);
  });

  it("a server address the shell refuses is marked on its field", async () => {
    const h = await toLogin({ failures: { bwLogin: [new ApiError("bad_server_url", "The server address must not contain a user name or password.")] } });
    await typeLogin(h);
    await h.user.click(screen.getByRole("radio", { name: t.regions.selfHosted }));
    await h.user.type(screen.getByLabelText(t.serverUrl), "https://user:pass@vault.example.com");
    await h.user.click(screen.getByRole("button", { name: t.signIn }));
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByText(by.bad_server_url.title(iphone))).toBeInTheDocument();
    expect(within(alert).getByText("The server address must not contain a user name or password.")).toBeInTheDocument();
    expect(screen.getByLabelText(t.serverUrl)).toHaveAttribute("aria-invalid", "true");
  });

  it("Bitwarden being out of reach is the one case that mentions the internet connection", async () => {
    const h = await toLogin({ failures: { bwLogin: [new ApiError("bw_unreachable", "Bitwarden's server did not answer.")] } });
    await typeLogin(h);
    await h.user.click(screen.getByRole("button", { name: t.signIn }));
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByText(by.bw_unreachable.title(iphone))).toBeInTheDocument();
    expect(within(alert).getByText("Bitwarden's server did not answer.")).toBeInTheDocument();
    expect(by.bw_unreachable.advice(iphone)).toMatch(/internet connection/);
  });

  it("a sign-in in progress can be cancelled, and the password is dropped", async () => {
    const h = await toLogin({ hold: { bwLogin: true } });
    await typeLogin(h);
    await h.user.click(screen.getByRole("button", { name: t.signIn }));
    await h.user.click(await screen.findByRole("button", { name: en.common.cancel }));
    expect(await screen.findByText(t.loginCancelled)).toBeInTheDocument();
    expect(h.api.calls.filter((c) => c.method === "bwCancel")).toHaveLength(1);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.getByLabelText(t.password)).toHaveValue("");
    expect(secretsOnPage("master pw")).toBe(false);
    expect(h.api.calls.some((c) => c.method === "bwPropose")).toBe(false);
  });

  it("signed in but the vault cannot be read is its own message, and trying again does not ask for the password", async () => {
    const h = await toLogin({ failures: { bwPropose: [new ApiError("bw_vault_read_failed", "Bitwarden's sync did not finish.")] } });
    await typeLogin(h);
    await h.user.click(screen.getByRole("button", { name: t.signIn }));
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByText(by.bw_vault_read_failed.title(iphone))).toBeInTheDocument();
    expect(within(alert).getByText("Bitwarden's sync did not finish.")).toBeInTheDocument();
    // Not a sign-in failure.
    expect(screen.queryByText(t.loginFailed)).not.toBeInTheDocument();
    expect(screen.queryByText(t.badCredentials)).not.toBeInTheDocument();

    await h.user.click(within(alert).getByRole("button", { name: en.common.tryAgain }));
    await screen.findByRole("heading", { level: 1, name: t.reviewTitle });
    expect(logins(h.api)).toHaveLength(1);
    expect(h.api.calls.filter((c) => c.method === "bwPropose")).toHaveLength(2);
  });
});

describe("sign-in with an API key", () => {
  const clientId = "user.4f2c0a1e";
  const clientSecret = "s3cr3tK3yValue";

  it("when Bitwarden wants an emailed code, the API-key form appears with where to find the key and why", async () => {
    const h = await toLogin({ loginResults: [{ kind: "needsApiKey" }] });
    await typeLogin(h);
    await h.user.click(screen.getByRole("button", { name: t.signIn }));

    const needed = await screen.findByText(t.apiKey.needed);
    expect(needed.closest("[role=alert]")).not.toBeNull();
    const form = screen.getByRole("group", { name: t.apiKey.title });
    expect(within(form).getByText(t.apiKey.where)).toBeInTheDocument();
    expect(t.apiKey.where).toMatch(/Settings → Security → Keys for “View API key”/);
    expect(within(form).getByText(t.apiKey.why)).toBeInTheDocument();
    expect(t.apiKey.why).toMatch(/confirm by email, which this app cannot do/);
    expect(within(form).getByText(t.apiKey.once)).toBeInTheDocument();
    expect(t.apiKey.once).toMatch(/used once.*not kept/);
    // The password typed for the first try was not kept while the person finds their key.
    expect(screen.getByLabelText(t.password)).toHaveValue("");
    expect(secretsOnPage("master pw")).toBe(false);
    expect(screen.getByRole("button", { name: t.signIn })).toBeDisabled();

    await h.user.type(screen.getByLabelText(t.apiKey.clientId), ` ${clientId} `);
    await h.user.type(screen.getByLabelText(t.apiKey.clientSecret), clientSecret);
    expect(screen.getByRole("button", { name: t.signIn })).toBeDisabled();
    await h.user.type(screen.getByLabelText(t.password), "master pw");
    await h.user.click(screen.getByRole("button", { name: t.signIn }));
    await screen.findByRole("heading", { level: 1, name: t.reviewTitle });

    expect(logins(h.api)[0]).not.toHaveProperty("apiKey");
    expect(logins(h.api)[1]).toEqual({
      email: "sam@example.com", password: "master pw", region: { kind: "us" }, apiKey: { clientId, clientSecret },
    });
    expect(secretsOnPage("master pw", clientId, clientSecret)).toBe(false);
  });

  it("can be chosen from the start, and switched back", async () => {
    const h = await toLogin();
    expect(screen.queryByRole("group", { name: t.apiKey.title })).not.toBeInTheDocument();
    await h.user.click(screen.getByRole("button", { name: t.useApiKey }));
    expect(screen.getByRole("group", { name: t.apiKey.title })).toBeInTheDocument();
    // Chosen, not demanded: the calm note stays, the "Bitwarden wants" one is not shown.
    expect(screen.queryByText(t.apiKey.needed)).not.toBeInTheDocument();
    expect(screen.getByLabelText(t.apiKey.clientSecret)).toHaveAttribute("type", "password");

    await h.user.type(screen.getByLabelText(t.apiKey.clientId), clientId);
    await h.user.click(screen.getByRole("button", { name: t.usePassword }));
    expect(screen.queryByRole("group", { name: t.apiKey.title })).not.toBeInTheDocument();
    // What was typed into the key fields is not kept behind the scenes.
    await h.user.click(screen.getByRole("button", { name: t.useApiKey }));
    expect(screen.getByLabelText(t.apiKey.clientId)).toHaveValue("");
  });

  it("all three fields are cleared together when the key is refused", async () => {
    const h = await toLogin({ loginResults: [{ kind: "badCredentials" }] });
    await h.user.click(screen.getByRole("button", { name: t.useApiKey }));
    await h.user.type(screen.getByLabelText(t.email), "sam@example.com");
    await h.user.type(screen.getByLabelText(t.apiKey.clientId), clientId);
    await h.user.type(screen.getByLabelText(t.apiKey.clientSecret), clientSecret);
    await h.user.type(screen.getByLabelText(t.password), "master pw");
    await h.user.click(screen.getByRole("button", { name: t.signIn }));

    await screen.findByText(t.badApiKey);
    expect(screen.queryByText(t.badCredentials)).not.toBeInTheDocument();
    expect(screen.getByLabelText(t.apiKey.clientId)).toHaveValue("");
    expect(screen.getByLabelText(t.apiKey.clientSecret)).toHaveValue("");
    expect(screen.getByLabelText(t.password)).toHaveValue("");
    expect(secretsOnPage("master pw", clientId, clientSecret)).toBe(false);
  });

  it("all three are cleared when the sign-in fails outright or is cancelled", async () => {
    const h = await toLogin({ failures: { bwLogin: [new ApiError("bw_failed", "Bitwarden's tool stopped unexpectedly.")] } });
    await h.user.click(screen.getByRole("button", { name: t.useApiKey }));
    await h.user.type(screen.getByLabelText(t.email), "sam@example.com");
    await h.user.type(screen.getByLabelText(t.apiKey.clientId), clientId);
    await h.user.type(screen.getByLabelText(t.apiKey.clientSecret), clientSecret);
    await h.user.type(screen.getByLabelText(t.password), "master pw");
    await h.user.click(screen.getByRole("button", { name: t.signIn }));
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByText(by.bw_failed.title(iphone))).toBeInTheDocument();
    expect(within(alert).getByText("Bitwarden's tool stopped unexpectedly.")).toBeInTheDocument();
    expect(secretsOnPage("master pw", clientId, clientSecret)).toBe(false);
  });
});

describe("a session that ends part-way", () => {
  it("on Apply: sign in again, and come straight back to the review with every choice intact", async () => {
    const h = await toReview({ failures: { bwApply: [new ApiError("bw_session_expired", "Bitwarden's session has ended.")] } });
    const { api, user } = h;
    await user.selectOptions(screen.getByRole("combobox", { name: t.actionFor("Google") }), t.attach("Google (work)", "sam@work.example"));
    await user.selectOptions(screen.getByRole("combobox", { name: t.actionFor("GitHub") }), t.skip);
    await user.click(screen.getByRole("button", { name: t.apply }));

    const alert = await screen.findByRole("alert");
    expect(within(alert).getByText("Bitwarden signed you out. Sign in again and your choices will still be here.")).toBeInTheDocument();
    // Running again without signing in cannot work, so it is not what is offered.
    expect(screen.queryByRole("button", { name: t.runAgain })).not.toBeInTheDocument();
    expect(screen.queryByText(en.failures.bitwardenServer.title)).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: t.signInAgain }));
    await screen.findByRole("heading", { level: 1, name: t.loginTitle });
    // The email is still there; the password is asked for again.
    expect(screen.getByLabelText(t.email)).toHaveValue("sam@example.com");
    await user.type(screen.getByLabelText(t.password), "master pw");
    await user.click(screen.getByRole("button", { name: t.signIn }));

    await screen.findByRole("heading", { level: 1, name: t.reviewTitle });
    expect(screen.getByText(t.signedInAgain)).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: t.actionFor("Google") })).toHaveValue("attach:v-go2");
    expect(screen.getByRole("combobox", { name: t.actionFor("GitHub") })).toHaveValue("skip");
    // The shell kept the matches: they were not worked out a second time.
    expect(api.calls.filter((c) => c.method === "bwPropose")).toHaveLength(1);

    await user.click(screen.getByRole("button", { name: t.apply }));
    await screen.findByRole("heading", { level: 1, name: t.reportTitle });
    const applies = api.calls.filter((c) => c.method === "bwApply");
    expect(applies).toHaveLength(2);
    expect(applies[1]!.args).toEqual(applies[0]!.args);
  });

  it("while choosing a login by hand: the same way back, and the picker closes", async () => {
    const h = await toReview({ failures: { bwLogins: [new ApiError("bw_session_expired", "Bitwarden's session has ended.")] } });
    const { user } = h;
    await user.selectOptions(screen.getByRole("combobox", { name: t.actionFor("Google") }), t.createNew);
    await user.click(screen.getByRole("button", { name: t.chooseOtherFor("Fastmail") }));
    await screen.findByRole("heading", { level: 1, name: t.loginTitle });
    expect(screen.getByText(by.bw_session_expired.title(iphone))).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    await user.type(screen.getByLabelText(t.password), "master pw");
    await user.click(screen.getByRole("button", { name: t.signIn }));
    await screen.findByRole("heading", { level: 1, name: t.reviewTitle });
    expect(screen.getByRole("combobox", { name: t.actionFor("Google") })).toHaveValue("createNew");
  });
});

describe("attaching a code to a login by hand", () => {
  const picker = (title: string) => screen.findByRole("dialog", { name: t.picker.title(title) });

  it("every row can be given any login in the vault, found by searching", async () => {
    const { api, user } = await toReview();
    for (const title of ["GitHub", "Google", "Fastmail"]) expect(screen.getByRole("button", { name: t.chooseOtherFor(title) })).toBeInTheDocument();
    expect(t.reviewLede).toMatch(/use Choose a different login to give the code to any login in your vault/);

    const opener = screen.getByRole("button", { name: t.chooseOtherFor("Fastmail") });
    await user.click(opener);
    const dialog = await picker("Fastmail");
    const list = await within(dialog).findByRole("list", { name: t.picker.listLabel });
    expect(within(list).getAllByRole("listitem")).toHaveLength(5);
    expect(within(dialog).getByText(t.picker.count(5))).toBeInTheDocument();

    // Searching is by name or by user name.
    const search = within(dialog).getByLabelText(t.picker.search);
    await user.type(search, "FASTMAIL.example");
    expect(within(list).getAllByRole("listitem")).toHaveLength(1);
    await user.clear(search);
    await user.type(search, "zzz");
    expect(within(dialog).getByText(t.picker.noMatch)).toBeInTheDocument();
    await user.clear(search);
    await user.type(search, "fast");

    await user.click(within(list).getByRole("button", { name: /Fastmail/ }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    // Focus goes back to the row it came from, and the row shows the choice.
    expect(opener).toHaveFocus();
    const select = screen.getByRole("combobox", { name: t.actionFor("Fastmail") });
    expect(select).toHaveValue("attach:v-fm");
    expect(within(select).getByRole("option", { name: t.attach("Fastmail", "sam@fastmail.example") })).toBeInTheDocument();

    await user.selectOptions(screen.getByRole("combobox", { name: t.actionFor("Google") }), t.skip);
    await user.click(screen.getByRole("button", { name: t.apply }));
    await screen.findByRole("heading", { level: 1, name: t.reportTitle });
    expect(api.calls.find((c) => c.method === "bwApply")?.args[0]).toContainEqual({ tokenId: "fm", decision: { kind: "attach", itemId: "v-fm" } });
    // The vault was read once, however many times the picker opens.
    expect(api.calls.filter((c) => c.method === "bwLogins")).toHaveLength(1);
  });

  it("a login that already has a code, or that another row has, is shown and cannot be chosen", async () => {
    const { user } = await toReview();
    await user.click(screen.getByRole("button", { name: t.chooseOtherFor("Fastmail") }));
    const dialog = await picker("Fastmail");
    const list = await within(dialog).findByRole("list", { name: t.picker.listLabel });

    const bank = within(list).getByRole("button", { name: /Bank/ });
    expect(bank).toBeDisabled();
    expect(bank).toHaveTextContent(t.picker.hasCode);
    expect(t.picker.hasCode).toBe("already has a code");
    // GitHub's login is already chosen in GitHub's own row.
    const github = within(list).getByRole("button", { name: /GitHub/ });
    expect(github).toBeDisabled();
    expect(github).toHaveTextContent(t.picker.taken("GitHub"));
    // Google's row is still unanswered, so both Google logins are free.
    expect(within(list).getByRole("button", { name: /Google \(work\)/ })).toBeEnabled();

    await user.click(within(list).getByRole("button", { name: /Google \(work\)/ }));
    // Now that login is taken for anyone else.
    await user.click(screen.getByRole("button", { name: t.chooseOtherFor("GitHub") }));
    const second = await picker("GitHub");
    const work = within(second).getByRole("button", { name: /Google \(work\)/ });
    expect(work).toBeDisabled();
    expect(work).toHaveTextContent(t.picker.taken("Fastmail"));
    // A row's own choice is not held against it.
    expect(within(second).getByRole("button", { name: /^GitHub/ })).toBeEnabled();
  });

  it("works from the keyboard alone, and Escape closes it without changing the row", async () => {
    const { user } = await toReview();
    const opener = screen.getByRole("button", { name: t.chooseOtherFor("Fastmail") });
    opener.focus();
    await user.keyboard("{Enter}");
    const dialog = await picker("Fastmail");
    await within(dialog).findByRole("list", { name: t.picker.listLabel });
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(opener).toHaveFocus();
    expect(screen.getByRole("combobox", { name: t.actionFor("Fastmail") })).toHaveValue("createNew");

    await user.keyboard("{Enter}");
    const again = await picker("Fastmail");
    await user.tab();   // Close
    await user.tab();   // the search box
    expect(within(again).getByLabelText(t.picker.search)).toHaveFocus();
    await user.keyboard("fastmail");
    await user.tab();
    expect(within(again).getByRole("button", { name: /Fastmail/ })).toHaveFocus();
    await user.keyboard("{Enter}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: t.actionFor("Fastmail") })).toHaveValue("attach:v-fm");
    expect(opener).toHaveFocus();
  });

  it("a vault list that cannot be read says so in the picker and can be tried again", async () => {
    const { user } = await toReview({ failures: { bwLogins: [new ApiError("bw_vault_read_failed", "The list of logins could not be read.")] } });
    await user.click(screen.getByRole("button", { name: t.chooseOtherFor("GitHub") }));
    const dialog = await picker("GitHub");
    const alert = await within(dialog).findByRole("alert");
    expect(within(alert).getByText(by.bw_vault_read_failed.title(iphone))).toBeInTheDocument();
    expect(within(alert).getByText("The list of logins could not be read.")).toBeInTheDocument();
    await user.click(within(alert).getByRole("button", { name: en.common.tryAgain }));
    expect(await within(dialog).findByRole("list", { name: t.picker.listLabel })).toBeInTheDocument();
    expect(within(dialog).queryByRole("alert")).not.toBeInTheDocument();
  });
});

describe("apply and its report", () => {
  it("every progress line appears, the first and the last included", async () => {
    const { user } = await toReview();
    await user.selectOptions(screen.getByRole("combobox", { name: t.actionFor("Google") }), t.attach("Google", "sam@example.com"));
    await user.click(screen.getByRole("button", { name: t.apply }));
    await screen.findByRole("heading", { level: 1, name: t.reportTitle });
    const lines = within(screen.getByRole("log", { name: t.progressLabel })).getAllByRole("listitem").map((li) => li.textContent);
    expect(lines).toEqual(["Attached GitHub", "Attached Google", "Created Fastmail"]);
  });

  it("says what was added, created and skipped, and lists apart what was already in Bitwarden", async () => {
    const kept = ["GitHub already has this code in Bitwarden.", "Fastmail is already in the “Authy import” folder."];
    const { user } = await toReview({ applyResults: [{ attached: 2, created: 1, skipped: 3, kept, failed: null }] });
    await user.selectOptions(screen.getByRole("combobox", { name: t.actionFor("Google") }), t.skip);
    await user.click(screen.getByRole("button", { name: t.apply }));
    await screen.findByRole("heading", { level: 1, name: t.reportTitle });

    expect(screen.getByText("Added a code to 2 logins.")).toBeInTheDocument();
    expect(screen.getByText("Created 1 new entry in the “Authy import” folder.")).toBeInTheDocument();
    expect(screen.getByText("Skipped 3 accounts (these stay only in Authy).")).toBeInTheDocument();
    const already = screen.getByRole("region", { name: "Already in Bitwarden" });
    expect(within(already).getAllByRole("listitem").map((li) => li.textContent)).toEqual(kept);
    // What was already there is not counted among the skipped.
    expect(screen.queryByText(/Skipped 5/)).not.toBeInTheDocument();
  });

  it("with nothing already there, no such list is shown", async () => {
    const { user } = await toReview();
    await user.selectOptions(screen.getByRole("combobox", { name: t.actionFor("Google") }), t.skip);
    await user.click(screen.getByRole("button", { name: t.apply }));
    await screen.findByRole("heading", { level: 1, name: t.reportTitle });
    expect(screen.getByText(t.skipped(1))).toBeInTheDocument();
    expect(t.skipped(1)).toBe("Skipped 1 account (this stays only in Authy).");
    expect(screen.queryByText(t.keptTitle)).not.toBeInTheDocument();
  });
});
