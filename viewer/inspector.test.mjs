// The inspector wiring: the module exports its API, the page declares its
// mount points, and the behaviour view uses it. DOM behaviour (open, close,
// content) is verified in a real browser, per this project's testing note.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const read = (p) => readFileSync(join(here, p), "utf8");

test("the inspector module exports its open/close/init API", async () => {
  const ins = await import("./ui/inspector.mjs");
  for (const fn of ["openInspector", "closeInspector", "initInspector"]) {
    assert.equal(typeof ins[fn], "function", `missing ${fn}`);
  }
});

test("the page declares the inspector and its scrim", () => {
  const html = read("ui/index.html");
  assert.match(html, /id="inspector"/);
  assert.match(html, /id="inspectorScrim"/);
});

test("the behaviour view opens the inspector and offers severity chips", () => {
  const src = read("ui/panels/behaviour.mjs");
  assert.match(src, /openInspector/);
  assert.match(src, /fchip/);
  assert.match(src, /clickable/);
});

test("the app initialises the inspector once at start-up", () => {
  const app = read("ui/app.mjs");
  assert.match(app, /initInspector\(\)/);
});

test("per-agent evidence tables open the inspector", () => {
  for (const panel of ["actions", "processes", "network", "events", "activity", "access", "response", "assets", "context", "health"]) {
    const src = read(`ui/panels/${panel}.mjs`);
    assert.match(src, /openInspector/, `${panel} should open the inspector`);
    assert.match(src, /clickable/, `${panel} rows should be clickable`);
  }
});
