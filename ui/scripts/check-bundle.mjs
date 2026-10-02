// Build check: the production bundle must not contain the in-memory fake or the dev-only
// pretend phone, and its stylesheet must not carry the pretend phone's styles. Run by `pnpm -C ui build` after `vite build`; exits non-zero on a leak.
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const dist = new URL("../dist/", import.meta.url).pathname;
// One marker from each dev-only module: strings/dev.ts, api.fake.ts, dev/DevPanel.tsx.
const MARKERS = ["Pretend phone", "correct horse", "0.0.0-fake", "dev-panel\"", ".dev-panel", ".dev-toggle"];

function files(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? files(join(dir, e.name)) : /\.(js|html|css)$/.test(e.name) ? [join(dir, e.name)] : []);
}

const leaks = [];
for (const file of files(dist)) {
  const text = readFileSync(file, "utf8");
  for (const marker of MARKERS) if (text.includes(marker)) leaks.push(`${file}: contains ${JSON.stringify(marker)}`);
}
if (leaks.length > 0) {
  console.error("Dev-only code leaked into the production bundle:\n" + leaks.join("\n"));
  process.exit(1);
}
console.log(`bundle check: no dev-only code in ${files(dist).length} files`);
