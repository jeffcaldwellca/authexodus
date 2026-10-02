// Guards the rule that every piece of user-facing text lives in `strings/en.ts`.
// It parses each component with the TypeScript compiler and looks for wording written in
// place: text between JSX tags, wording in user-facing attributes, and any other string
// literal that reads like a phrase.
/// <reference types="vite/client" />
import ts from "typescript";
import { en } from "./en";

/** Every component source in the app, read as text: path (relative to src/) → contents. */
const SOURCES = Object.fromEntries(
  Object.entries(import.meta.glob<string>("../**/*.tsx", { query: "?raw", import: "default", eager: true }))
    .map(([path, text]) => [path.replace(/^\.\.\//, ""), text] as const)
    .filter(([path]) => !path.includes(".test.") && path !== "test-utils.tsx"),
);
/** Attributes whose value a person reads or hears. */
const SPOKEN = new Set(["aria-label", "aria-description", "title", "alt", "placeholder", "label"]);
/** Attributes whose value is never wording, however it looks. */
const SILENT = new Set(["className", "d", "transform", "viewBox", "points"]);

const WORD = /[A-Za-z]{2,}/;
const PHRASE = /[A-Za-z]{2,}\s+[A-Za-z]{2,}/;

export function findLiterals(fileName: string, source: string): string[] {
  const file = ts.createSourceFile(fileName, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  const found: string[] = [];
  const report = (node: ts.Node, text: string) => {
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
      // Type positions ("a" | "b") are not wording.
      if (!ts.isLiteralTypeNode(node.parent)) {
        const attribute = attributeOf(node);
        const direct = ts.isJsxAttribute(node.parent) || (ts.isJsxExpression(node.parent) && ts.isJsxAttribute(node.parent.parent));
        const jsxChild = ts.isJsxExpression(node.parent) && !ts.isJsxAttribute(node.parent.parent);
        if (attribute !== null && SILENT.has(attribute)) {
          // never wording
        } else if (attribute !== null && SPOKEN.has(attribute) && direct && WORD.test(node.text)) {
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
    expect(names).toContain("App.tsx");
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
    const other = /phone number|Android phone|new device|Multi-device|^This device$|^Which device|^Choose your device|^Pretend phone$|^Device connects$|Device Management/;
    const generic = texts.filter((s) => /\b(phone|device)\b/i.test(s.replace(/iPhone/g, "")) && !/iPhone or iPad|iPad or iPhone/.test(s) && !other.test(s));
    expect(generic).toEqual([]);
  });
});
