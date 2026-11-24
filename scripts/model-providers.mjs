#!/usr/bin/env node
// Which models in OpenRouter's public list our provider prefixes do not name.
//
// Topgent reads a model's name from the agent's own files and never fetches
// anything at run time. The only thing that goes stale is the short list of
// prefixes in crates/topgent-collect/data/model-signatures.json that turn a
// model name into a provider (`glm-5.1` → zhipu). This script is for
// maintainers: it compares those prefixes with OpenRouter's model list and
// prints the vendors whose models no prefix catches, with a suggested line.
//
//   node scripts/model-providers.mjs            # report, exit 1 on gaps
//   node scripts/model-providers.mjs --json     # the same, as JSON
//
// Nothing is written. Adding a prefix stays a reviewed edit to the data file.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const SIGNATURES = new URL("../crates/topgent-collect/data/model-signatures.json", import.meta.url);
const SOURCE = "https://openrouter.ai/api/v1/models";

// OpenRouter vendor slugs that are routers or resellers, not model makers.
const NOT_MAKERS = new Set(["openrouter", "switchpoint"]);

/** The provider the data file would derive, mirroring model.rs `provider_of`. */
export function providerOf(providers, model) {
  for (const candidate of model.toLowerCase().split("/")) {
    for (const rule of providers) if (candidate.startsWith(rule.value)) return rule.provider;
  }
  return null;
}

/** The leading word of a model name: `glm-5.1` → `glm`, `inkling-2-mini` → `inkling`. */
export function stem(name) {
  const word = name.toLowerCase().split(":")[0].match(/^[a-z]+/);
  return word ? word[0] : null;
}

/**
 * Vendors with models no prefix names. `ids` are OpenRouter ids such as
 * `z-ai/glm-5.1`; only the part after the vendor is tested, which is the part
 * an agent writes in its own files.
 */
export function gaps(providers, ids) {
  const byVendor = new Map();
  for (const id of ids) {
    const [vendor, ...rest] = id.split("/");
    const name = rest.join("/");
    if (!name || NOT_MAKERS.has(vendor)) continue;
    if (providerOf(providers, name)) continue;
    const entry = byVendor.get(vendor) ?? { vendor, models: [], stems: new Set() };
    entry.models.push(name);
    const s = stem(name);
    if (s && s.length >= 2) entry.stems.add(s);
    byVendor.set(vendor, entry);
  }
  return [...byVendor.values()]
    .map(e => ({ vendor: e.vendor, models: e.models.sort(), suggest: [...e.stems].sort().map(value => ({ match: "prefix", value, provider: e.vendor })) }))
    .sort((a, b) => b.models.length - a.models.length || a.vendor.localeCompare(b.vendor));
}

async function main() {
  const { providers } = JSON.parse(readFileSync(SIGNATURES, "utf8"));
  const response = await fetch(SOURCE, { headers: { "user-agent": "topgent-maintenance" } });
  if (!response.ok) throw new Error(`${SOURCE}: HTTP ${response.status}`);
  const { data } = await response.json();
  const ids = (data ?? []).map(m => m.id).filter(id => typeof id === "string");
  const found = gaps(providers, ids);
  if (process.argv.includes("--json")) {
    console.log(JSON.stringify({ checked: ids.length, gaps: found }, null, 2));
  } else if (!found.length) {
    console.log(`All ${ids.length} models map to a provider.`);
  } else {
    console.log(`${ids.length} models checked. Vendors with unmapped models:\n`);
    for (const g of found) {
      console.log(`${g.vendor} (${g.models.length}): ${g.models.slice(0, 5).join(", ")}${g.models.length > 5 ? ", …" : ""}`);
      for (const rule of g.suggest) console.log(`  suggest: ${JSON.stringify(rule)}`);
    }
  }
  process.exitCode = found.length ? 1 : 0;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch(error => { console.error(error.message); process.exitCode = 2; });
}
