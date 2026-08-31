// Every interface module loads, and every import it names exists.
//
// The interface is fifteen small modules with no build step and no type
// checker, so a rename that misses one import site produces a page that looks
// finished until someone opens the panel that broke. ES modules resolve their
// named imports at link time, which means simply importing every module is a
// real check: a missing export fails here rather than in front of a user.
//
// The stubs below are the smallest thing that lets a module reach top level.
// They are deliberately not a DOM implementation — anything that needs a real
// browser is tested in a real browser, and anything worth testing without one
// should not be touching the DOM in the first place.
//
//   node --test viewer/modules.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));

function stubElement() {
  const node = {
    style: {},
    dataset: {},
    classList: { add() {}, remove() {}, toggle() {} },
    children: [],
    hidden: true,
    textContent: "",
    value: "",
    append() {},
    remove() {},
    setAttribute() {},
    getAttribute: () => null,
    addEventListener() {},
    getBoundingClientRect: () => ({ width: 0, height: 0 }),
    querySelector: () => null,
    querySelectorAll: () => [],
    scrollIntoView() {},
    focus() {},
    matches: () => false,
  };
  return node;
}

function installStubs() {
  const store = new Map();
  globalThis.localStorage = {
    getItem: (k) => (store.has(k) ? store.get(k) : null),
    setItem: (k, v) => store.set(k, String(v)),
    removeItem: (k) => store.delete(k),
  };
  globalThis.document = {
    documentElement: stubElement(),
    body: stubElement(),
    createElement: () => stubElement(),
    createDocumentFragment: () => stubElement(),
    getElementById: () => stubElement(),
    querySelector: () => stubElement(),
    querySelectorAll: () => [],
    addEventListener() {},
    activeElement: null,
  };
  globalThis.window = { addEventListener() {}, __TAURI__: undefined };
  globalThis.Notification = undefined;
}

installStubs();

const modules = [
  ...readdirSync(join(here, "ui"))
    .filter((f) => f.endsWith(".mjs"))
    .map((f) => `./ui/${f}`),
  ...readdirSync(join(here, "ui", "panels"))
    .filter((f) => f.endsWith(".mjs"))
    .map((f) => `./ui/panels/${f}`),
];

test("the interface is more than one file", () => {
  // A guard against the split quietly collapsing back into a monolith, and
  // against this test silently passing because it found nothing to load.
  assert.ok(modules.length >= 15, `expected the interface to be split; found ${modules.length}`);
});

test("app.mjs imports only names the other modules export", async () => {
  // The entry point cannot simply be imported: doing so starts the poll loop.
  // Its import list is checked against what each module actually exports, so a
  // rename that misses the entry point fails here and not on someone's screen.
  const source = readFileSync(join(here, "ui", "app.mjs"), "utf8");
  for (const [, names, from] of source.matchAll(/import \{([^}]*)\} from "([^"]+)";/g)) {
    const module = await import(from.replace(/^\.\//, "./ui/"));
    for (const name of names.split(",").map((n) => n.trim()).filter(Boolean)) {
      assert.ok(name in module, `app.mjs imports ${name} from ${from}, which does not export it`);
    }
  }
});

// app.mjs is the entry point: importing it starts the poll loop, so it is
// checked for parse and link errors rather than run.
for (const path of modules.filter((m) => m !== "./ui/app.mjs")) {
  test(`${path} loads and every import it names resolves`, async () => {
    const module = await import(path);
    assert.ok(Object.keys(module).length > 0, `${path} exports nothing`);
  });
}

test("every panel exports the render function the application calls", async () => {
  const panels = modules.filter((m) => m.startsWith("./ui/panels/"));
  for (const path of panels) {
    const module = await import(path);
    const renders = Object.keys(module).filter((n) => n.startsWith("render"));
    assert.ok(renders.length > 0, `${path} exports no render function`);
  }
});

test("the alert rules stay free of the DOM", async () => {
  // These are the decisions worth testing without a browser. If one of them
  // starts touching the page, alerts.test.mjs stops proving anything.
  delete globalThis.document;
  const alerts = await import("./ui/alerts.mjs?nodom");
  assert.equal(typeof alerts.isAlarming, "function");
  assert.equal(alerts.isAlarming({ kind: "recon", run: "1@1" }), true);
  installStubs();
});
