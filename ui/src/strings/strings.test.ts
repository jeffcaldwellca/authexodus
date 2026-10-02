// Guards the rule that every piece of user-facing text lives in `strings/en.ts`.
// It parses each component with the TypeScript compiler and looks for wording written in
// place: text between JSX tags, wording in user-facing attributes, and any other string
// literal that reads like a phrase.
/// <reference types="vite/client" />
import ts from "typescript";
import { en } from "./en";

/**
 * Every source file in the app, components and plain modules alike, read as text:
 * path (relative to src/) → contents. Tests and the strings files themselves are left out.
 */
const SOURCES = Object.fromEntries(
  Object.entries(import.meta.glob<string>("../**/*.{ts,tsx}", { query: "?raw", import: "default", eager: true }))
    .map(([path, text]) => [path.replace(/^\.\.\//, "").replace(/^\.\//, "strings/"), text] as const)
    .filter(([path]) => !path.includes(".test.") && !path.endsWith(".d.ts") && !path.startsWith("strings/")
      && path !== "test-utils.tsx" && path !== "test-setup.ts"),
);

/**
 * The explicit exceptions. Each is wording that is deliberately not in `strings/en.ts`,
 * with the reason. Anything not listed here fails the test.
 */
const ALLOWED: { file: string; text: string | RegExp; why: string }[] = [
  { file: "api.fake.ts", text: /.*/, why: "invented account names and stand-ins for the core's own messages; never shipped" },
];

function allowed(file: string, text: string): boolean {
  return ALLOWED.some((a) => a.file === file && (typeof a.text === "string" ? a.text === text.trim() : a.text.test(text)));
}
/**
 * Props whose value a person reads or hears: the HTML ones, and the ones this app's own
 * components put on screen. A single word in any of these is wording.
 */
const SPOKEN = new Set([
  "aria-label", "aria-description", "aria-roledescription", "title", "alt", "placeholder", "label",
  "lede", "detail", "body", "text", "message", "steps", "status", "footer", "caption",
]);
/** Attributes whose value is never wording, however it looks. */
const SILENT = new Set(["className", "d", "transform", "viewBox", "points"]);

const WORD = /[A-Za-z]{2,}/;
const PHRASE = /[A-Za-z]{2,}\s+[A-Za-z]{2,}/;

export function findLiterals(fileName: string, source: string): string[] {
  const kind = fileName.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS;
  const file = ts.createSourceFile(fileName, source, ts.ScriptTarget.Latest, true, kind);
  const found: string[] = [];
  const report = (node: ts.Node, text: string) => {
    if (allowed(fileName, text)) return;
    const { line } = file.getLineAndCharacterOfPosition(node.getStart());
    found.push(`${fileName}:${line + 1} ${JSON.stringify(text.trim())}`);
  };
  const attributeOf = (node: ts.Node): string | null => {
    for (let n: ts.Node | undefined = node.parent; n; n = n.parent) {
      if (ts.isJsxAttribute(n)) return n.name.getText();
      if (ts.isJsxElement(n) || ts.isJsxSelfClosingElement(n)) return null;
    }
    return null;
  };
  const visit = (node: ts.Node) => {
    if (ts.isImportDeclaration(node)) return;
    if (ts.isJsxText(node)) {
      if (WORD.test(node.text)) report(node, node.text);
    } else if (ts.isStringLiteralLike(node) || ts.isTemplateHead(node) || ts.isTemplateMiddle(node) || ts.isTemplateTail(node)) {
      // Type positions ("a" | "b") are not wording, and neither is a value being compared with.
      const compared = ts.isBinaryExpression(node.parent)
        && [ts.SyntaxKind.EqualsEqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsEqualsToken].includes(node.parent.operatorToken.kind);
      if (!ts.isLiteralTypeNode(node.parent) && !compared) {
        const attribute = attributeOf(node);
        const jsxChild = ts.isJsxExpression(node.parent) && !ts.isJsxAttribute(node.parent.parent);
        if (attribute !== null && SILENT.has(attribute)) {
          // never wording
        } else if (attribute !== null && SPOKEN.has(attribute) && WORD.test(node.text)) {
          report(node, node.text);
        } else if (jsxChild && WORD.test(node.text)) {
          report(node, node.text);
        } else if (PHRASE.test(node.text)) {
          report(node, node.text);
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(file);
  return found;
}

describe("strings", () => {
  it("no_string_literals_outside_strings_file", () => {
    // The screens are the heart of it; make sure the scan really reached them, and the rest.
    const names = Object.keys(SOURCES);
    for (const screen of ["Welcome", "Connect", "Certificate", "Authy", "Unlock", "Destination", "Verify", "Cleanup"]) {
      expect(names).toContain(`screens/${screen}.tsx`);
    }
    for (const dir of ["device", "failures", "components"]) expect(names.some((n) => n.startsWith(`${dir}/`))).toBe(true);
    for (const file of ["App.tsx", "main.tsx", "api.tauri.ts", "wizard/machine.ts", "screens/types.ts", "dev/boot.tsx"]) {
      expect(names).toContain(file);
    }
    const found = Object.entries(SOURCES).flatMap(([name, text]) => findLiterals(name, text));
    expect(found).toEqual([]);
  });

  it("the check itself catches wording written in a component", () => {
    const bad = [
      "export const A = () => <p>Tap Save.</p>;",
      "export const B = () => <img alt=\"Code\" />;",
      "export const C = () => <p>{\"Start\"}</p>;",
      "export const D = () => <p>{cond ? `Waiting for ${d}` : null}</p>;",
      "export const E = () => { const msg = 'Try again later'; return <p>{msg}</p>; };",
    ];
    for (const source of bad) expect(findLiterals("x.tsx", source)).toHaveLength(1);
    // Single words in props that are shown or spoken, on HTML elements and on our own components.
    const badProps = [
      "export const A = () => <Screen title=\"Unlock\">{x}</Screen>;",
      "export const B = () => <Tick label={\"Done\"} checked onChange={f} />;",
      "export const C = () => <Callout tone=\"info\" title={ok ? \"Saved\" : en.x} />;",
      "export const D = () => <button aria-label=\"Close\" />;",
    ];
    for (const source of badProps) expect(findLiterals("x.tsx", source), source).toHaveLength(1);
    // Plain modules are covered too.
    expect(findLiterals("x.ts", "export const message = (n: number) => `Captured ${n} accounts so far`;")).toHaveLength(1);
    expect(findLiterals("x.ts", "export function f() { throw new Error('could not start the proxy'); }")).toHaveLength(1);
    expect(findLiterals("x.ts", "export const KIND: 'two words' | 'x' = 'x'; export const cmd = 'restart_proxy';")).toEqual([]);
    // The allow-list is by file, and only that file.
    expect(findLiterals("api.fake.ts", "export const name = 'Home router';")).toEqual([]);
    expect(findLiterals("api.other.ts", "export const name = 'Home router';")).toHaveLength(1);
    const fine = [
      "export const A = () => <p className=\"quiet text\" role=\"status\">{en.a}</p>;",
      "export const B = (k: \"left side\" | \"right side\") => <svg viewBox=\"0 0 1 1\"><path d=\"M0 0h1\" /></svg>;",
      "export const C = () => <span className={`a ${b ? \"on now\" : \"\"}`}>✓ 1</span>;",
    ];
    for (const source of fine) expect(findLiterals("x.tsx", source)).toEqual([]);
  });

  it("says iPhone or iPad wherever the device is named generically", () => {
    const texts: string[] = [];
    const collect = (value: unknown) => {
      if (typeof value === "string") texts.push(value);
      else if (Array.isArray(value)) value.forEach(collect);
      else if (value && typeof value === "object") Object.values(value).forEach(collect);
    };
    collect(en);
    // Only fixed strings are checked here; wording built by a function takes the device's
    // name as an argument, which is how it gets "iPhone or iPad" before a device is chosen.
    // These are other things that happen to contain the word: a phone number, an Android
    // phone, Authy's "new device" and "Multi-device", the drawn "This device" row, the
    // questions that ask which device, and the dev-only pretend phone.
    const other = /phone number|Android phone|new device|Multi-device|^This device$|^Which device|^Choose your device|^Pretend phone$|^A different device|Device Management/;
    const generic = texts.filter((s) => /\b(phone|device)\b/i.test(s.replace(/iPhone/g, "")) && !/iPhone or iPad|iPad or iPhone/.test(s) && !other.test(s));
    expect(generic).toEqual([]);
  });

  it("has no strings that nothing uses", () => {
    const code = Object.values(SOURCES).join("\n");
    const unused: string[] = [];
    const walk = (value: unknown, path: string[]) => {
      if (value && typeof value === "object" && !Array.isArray(value)) {
        for (const [key, child] of Object.entries(value)) walk(child, [...path, key]);
        return;
      }
      // Used directly (`.key`), or looked up through its parent (`.parent[id]`), at any depth.
      const used = path.some((key, i) => new RegExp(`\\.${key}\\b`).test(code) && (i === path.length - 1 || new RegExp(`\\.${key}\\[`).test(code)));
      if (!used) unused.push(path.join("."));
    };
    walk(en, []);
    expect(unused).toEqual([]);
  });
});
