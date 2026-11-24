// The maintenance check for provider prefixes, offline: no network, a fixed
// list of OpenRouter-shaped ids against the shipped data file.
//
//   node --test viewer/model-providers.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { gaps, providerOf, stem } from "../scripts/model-providers.mjs";

const { providers } = JSON.parse(readFileSync(new URL("../crates/topgent-collect/data/model-signatures.json", import.meta.url), "utf8"));

test("names the data file already maps are not reported", () => {
  assert.equal(providerOf(providers, "glm-5.1"), "zhipu");
  assert.equal(providerOf(providers, "claude-opus-5-5"), "anthropic");
  assert.equal(providerOf(providers, "unsloth/Llama-3.2-3B-Instruct"), "meta");
  assert.deepEqual(gaps(providers, ["z-ai/glm-5.1", "anthropic/claude-opus-5-5", "qwen/qwen3-max"]), []);
});

test("an unmapped vendor is reported with a suggested prefix", () => {
  const found = gaps(providers, ["acme/quillon-2", "acme/quillon-2-mini", "openrouter/auto", "z-ai/glm-5.1"]);
  assert.equal(found.length, 1);
  assert.equal(found[0].vendor, "acme");
  assert.deepEqual(found[0].models, ["quillon-2", "quillon-2-mini"]);
  assert.deepEqual(found[0].suggest, [{ match: "prefix", value: "quillon", provider: "acme" }]);
});

test("the stem is the leading word", () => {
  assert.equal(stem("glm-5.1"), "glm");
  assert.equal(stem("inkling-2-mini:free"), "inkling");
  assert.equal(stem("4o-mini"), null);
});
