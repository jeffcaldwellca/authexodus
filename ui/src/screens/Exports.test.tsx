// The QR walks and the saved files: drawing failures, paging, rejected saves, and the import
// steps each app needs once its file is on disk.
import { screen, within } from "@testing-library/react";
import { ApiError } from "../api.errors";
import { fakeQrSvg, type FakeScript } from "../api.fake";
import { en } from "../strings/en";
import { walkTo } from "../test-utils";

const t = en.destination;
const iphone = en.deviceName.iphone;
const two: FakeScript["summary"] = {
  tokens: [{ id: "a", title: "GitHub", username: "sam" }, { id: "b", title: "Dropbox", username: null }],
  native: [], invalid: [],
};

async function open(option: keyof typeof t.options, script: Partial<FakeScript> = {}) {
  const h = await walkTo("destination", script);
  await h.user.click(screen.getByRole("button", { name: new RegExp(t.options[option].title) }));
  return h;
}

describe("QR codes, one by one", () => {
  it("a code the shell cannot draw shows its reason and a way to try again, never an endless wait", async () => {
    const { api, user } = await open("qr", { summary: two, failures: { tokenQr: [new ApiError("export_failed", "This account's key is too long for a QR code.")] } });
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByText(en.problems.byCode.export_failed.title(iphone))).toBeInTheDocument();
    expect(within(alert).getByText("This account's key is too long for a QR code.")).toBeInTheDocument();
    expect(screen.queryByText(t.qr.loading)).not.toBeInTheDocument();
    // Nothing to tick while there is nothing to scan.
    expect(screen.queryByRole("checkbox", { name: t.qr.scanned })).not.toBeInTheDocument();

    await user.click(within(alert).getByRole("button", { name: en.common.tryAgain }));
    await screen.findByAltText(t.qr.alt("GitHub"));
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(api.calls.filter((c) => c.method === "tokenQr").map((c) => c.args[0])).toEqual(["a", "a"]);
  });

  it("a blank drawing is treated as a failure, with the same retry", async () => {
    const { api, user } = await open("qr", { summary: two, qrSvg: "" });
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByText(t.qr.empty)).toBeInTheDocument();
    expect(screen.queryByText(t.qr.loading)).not.toBeInTheDocument();
    api.script.qrSvg = null;
    await user.click(within(alert).getByRole("button", { name: en.common.tryAgain }));
    await screen.findByAltText(t.qr.alt("GitHub"));
  });

  it("a failure with no code keeps the screen's own title and a plain sentence, never the raw text", async () => {
    await open("qr", { summary: two, failures: { tokenQr: ["encoder panicked"] } });
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByText(t.qr.failed)).toBeInTheDocument();
    expect(within(alert).getByText(en.problems.unexplained)).toBeInTheDocument();
    expect(alert.textContent).not.toContain("encoder panicked");
  });

  it("codes that are locked again lead back to the backup password", async () => {
    const { user } = await open("qr", { summary: two, failures: { tokenQr: [new ApiError("not_unlocked", "The backup is not unlocked.")] } });
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByText(en.problems.byCode.not_unlocked.title(iphone))).toBeInTheDocument();
    await user.click(within(alert).getByRole("button", { name: en.common.unlockAgain }));
    await screen.findByRole("heading", { level: 1, name: en.unlock.title });
  });

  it("Previous goes back a code, and Done on the last code returns to the choices as moved", async () => {
    const { user } = await open("qr", { summary: two });
    await screen.findByAltText(t.qr.alt("GitHub"));
    const previous = () => screen.getByRole("button", { name: en.common.previous });
    expect(previous()).toBeDisabled();
    expect(screen.queryByRole("button", { name: en.common.done })).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: en.common.next }));
    await screen.findByAltText(t.qr.alt("Dropbox"));
    expect(screen.getByText(t.qr.position(2, 2))).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: en.common.next })).not.toBeInTheDocument();
    await user.click(screen.getByRole("checkbox", { name: t.qr.scanned }));

    await user.click(previous());
    await screen.findByAltText(t.qr.alt("GitHub"));
    // The tick belongs to the code it was made on.
    expect(screen.getByRole("checkbox", { name: t.qr.scanned })).not.toBeChecked();
    expect(screen.getByText(t.qr.scannedCount(1, 2))).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: en.common.next }));
    expect(await screen.findByRole("checkbox", { name: t.qr.scanned })).toBeChecked();
    await user.click(screen.getByRole("button", { name: en.common.done }));
    await screen.findByRole("heading", { level: 1, name: t.title });
    expect(screen.getByRole("button", { name: t.continue })).toBeEnabled();
  });

  it("says the codes are not yet tried with a real app", async () => {
    await open("qr", { summary: two });
    expect(await screen.findByText(en.common.untested(t.qr.app))).toBeInTheDocument();
    expect(en.common.untested(t.qr.app)).toBe("Not yet tested with a real authenticator app. Check two codes before relying on it.");
  });
});

describe("Google Authenticator transfer codes", () => {
  const pages = [fakeQrSvg("one"), fakeQrSvg("two"), fakeQrSvg("three")];

  it("walks several codes with Next, Previous and Done", async () => {
    const { api, user } = await open("google", { googlePages: pages });
    await screen.findByAltText(t.google.alt(1));
    expect(screen.getByText(t.google.position(1, 3))).toBeInTheDocument();
    await user.click(screen.getByRole("checkbox", { name: t.qr.scanned }));
    expect(screen.getByText(t.qr.scannedCount(1, 3))).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: en.common.next }));
    await screen.findByAltText(t.google.alt(2));
    await user.click(screen.getByRole("button", { name: en.common.next }));
    await screen.findByAltText(t.google.alt(3));
    expect(screen.getByText(t.google.position(3, 3))).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: en.common.previous }));
    await screen.findByAltText(t.google.alt(2));
    await user.click(screen.getByRole("button", { name: en.common.next }));
    await user.click(screen.getByRole("button", { name: en.common.done }));
    await screen.findByRole("heading", { level: 1, name: t.title });
    expect(screen.getByRole("button", { name: t.continue })).toBeEnabled();
    // The pages were fetched once, not once per page.
    expect(api.calls.filter((c) => c.method === "googleMigrationQrs")).toHaveLength(1);
    expect(en.common.untested(t.google.app)).toMatch(/real Google Authenticator/);
  });

  it("a walk the shell cannot make shows why and can be tried again", async () => {
    const { user } = await open("google", { failures: { googleMigrationQrs: [new ApiError("export_failed", "The transfer codes could not be built.")] } });
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByText("The transfer codes could not be built.")).toBeInTheDocument();
    expect(screen.queryByText(t.qr.loading)).not.toBeInTheDocument();
    await user.click(within(alert).getByRole("button", { name: en.common.tryAgain }));
    await screen.findByAltText(t.google.alt(1));
  });

  it("the list of what the codes cannot carry failing is a failure of the walk too", async () => {
    await open("google", { failures: { googleUnsupported: ["list unavailable"] } });
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByText(en.problems.unexplained)).toBeInTheDocument();
    expect(alert.textContent).not.toContain("list unavailable");
  });

  it("no codes at all is an answer, not a wait: nothing fits, use the other way", async () => {
    const { user } = await open("google", { googlePages: [], googleUnsupported: ["Steam"] });
    expect(await screen.findByText(t.google.none)).toBeInTheDocument();
    expect(screen.queryByText(t.qr.loading)).not.toBeInTheDocument();
    expect(screen.getByText("Steam")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: en.common.done }));
    await screen.findByRole("heading", { level: 1, name: t.title });
    expect(screen.getByRole("button", { name: t.continue })).toBeDisabled();
  });
});

describe("saved files", () => {
  const f = t.file;
  const saveFor = (app: keyof typeof f.apps) => screen.getByRole("button", { name: f.save(f.apps[app]) });
  const guideFor = (app: keyof typeof f.apps) => screen.findByRole("region", { name: f.guideTitle(f.apps[app]) });

  it("a save the shell rejects shows the shell's reason beside that app, and other apps still work", async () => {
    const { user } = await open("file", { failures: { exportFile: [new ApiError("export_failed", "The folder is read-only.")] } });
    await user.click(saveFor("twoFas"));
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByText(en.problems.byCode.export_failed.title(iphone))).toBeInTheDocument();
    expect(within(alert).getByText("The folder is read-only.")).toBeInTheDocument();
    expect(saveFor("twoFas").closest("li")).toContainElement(alert);
    // Nothing was saved: no import steps, and nothing to delete at cleanup.
    expect(screen.queryByRole("region", { name: f.guideTitle(f.apps.twoFas) })).not.toBeInTheDocument();

    await user.click(saveFor("twoFas"));
    await guideFor("twoFas");
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("a rejection with no code says the file could not be saved, in plain words, never the raw text", async () => {
    const { user } = await open("file", { failures: { exportFile: ["dialog closed unexpectedly"] } });
    await user.click(saveFor("aegis"));
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByText(f.failed)).toBeInTheDocument();
    expect(within(alert).getByText(en.problems.unexplained)).toBeInTheDocument();
    expect(alert.textContent).not.toContain("dialog closed unexpectedly");
  });

  it("no steps are shown before a file is saved, or after a cancelled save", async () => {
    const { user } = await open("file", { exportResults: [{ cancelled: true }] });
    expect(screen.queryByRole("region")).not.toBeInTheDocument();
    expect(screen.getByText(f.lede)).toBeInTheDocument();
    await user.click(saveFor("bitwarden"));
    await screen.findByText(f.cancelled);
    expect(screen.queryByRole("region")).not.toBeInTheDocument();
  });

  it("the Bitwarden file's steps name the web vault's import and the one format that reads it", async () => {
    const { user } = await open("file");
    await user.click(saveFor("bitwarden"));
    const guide = await guideFor("bitwarden");
    expect(guide.textContent).toMatch(/Tools → Import data/);
    expect(guide.textContent).toMatch(/“Bitwarden \(csv\)”/);
    expect(within(guide).getByText(en.common.verified(f.apps.bitwarden))).toBeInTheDocument();
    expect(screen.getByText(f.saved("/Users/sam/Downloads/authy-bitwarden-import.csv"))).toBeInTheDocument();
  });

  it("the Proton Authenticator file's steps say to choose Aegis as the source", async () => {
    const { user } = await open("file");
    await user.click(saveFor("protonAuthenticator"));
    const guide = await guideFor("protonAuthenticator");
    expect(guide.textContent).toMatch(/choose Aegis\. That is not a mistake/);
    expect(guide.textContent).toMatch(/look for Import/);
    expect(within(guide).getByText(en.common.untested(f.apps.protonAuthenticator))).toBeInTheDocument();
  });

  it("apps that live on a phone say how the file gets there", async () => {
    const { user } = await open("file");
    await user.click(saveFor("twoFas"));
    const twoFas = await guideFor("twoFas");
    expect(twoFas.textContent).toMatch(/AirDrop/);
    expect(twoFas.textContent).toMatch(/Save to Files/);
    expect(twoFas.textContent).toMatch(/look for 2FAS Backup/);
    expect(within(twoFas).getByText(en.common.untested(f.apps.twoFas))).toBeInTheDocument();

    await user.click(saveFor("aegis"));
    const aegis = await guideFor("aegis");
    expect(aegis.textContent).toMatch(/Android/);
    expect(aegis.textContent).toMatch(/AirDrop does not reach Android/);
    expect(aegis.textContent).toMatch(/look for Import & Export/);
    expect(within(aegis).getByText(en.common.untested(f.apps.aegis))).toBeInTheDocument();
  });

  it("1Password's steps are worded as places to look, and say it is untried", async () => {
    const { user } = await open("file");
    await user.click(saveFor("onePassword"));
    const guide = await guideFor("onePassword");
    expect(guide.textContent).toMatch(/look for Import/);
    expect(within(guide).getByText("Not yet tested with a real 1Password. Check two codes before relying on it.")).toBeInTheDocument();
  });

  it("every app has steps, and only the formats that were really tried say so", () => {
    for (const app of Object.keys(f.apps) as (keyof typeof f.apps)[]) expect(f.guides[app].steps.length).toBeGreaterThanOrEqual(3);
    const tried = (Object.keys(f.guides) as (keyof typeof f.guides)[]).filter((app) => f.guides[app].tested === true);
    expect(tried).toEqual(["bitwarden"]);
    // Unchecked menu paths are worded as somewhere to look.
    for (const app of ["onePassword", "twoFas", "aegis", "protonAuthenticator"] as const) {
      expect(f.guides[app].steps.join(" ")).toMatch(/look for/);
    }
  });

  it("the plain-text file makes no claim about an app", async () => {
    const { user } = await open("file");
    await user.click(saveFor("plainText"));
    const guide = await guideFor("plainText");
    expect(guide.textContent).toMatch(/otpauth:\/\//);
    expect(guide.textContent).not.toMatch(/Tested with|Not yet tested/);
  });
});
