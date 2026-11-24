// The simple view's own arithmetic: company names, grouping, and the one-word
// activity. The sentences themselves come from the report and are tested in
// crates/topgent-report/src/plain.rs.
//
//   node --test viewer/simple.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";

const store = new Map();
globalThis.localStorage = { getItem: k => store.get(k) ?? null, setItem: (k, v) => store.set(k, String(v)), removeItem: k => store.delete(k) };
const stub = () => ({ style: {}, dataset: {}, classList: { add() {}, remove() {}, toggle() {} }, append() {}, replaceChildren() {}, setAttribute() {}, addEventListener() {} });
globalThis.document = { documentElement: stub(), body: stub(), createElement: stub, getElementById: stub, querySelector: stub, querySelectorAll: () => [], addEventListener() {}, dispatchEvent() {} };
globalThis.window = { addEventListener() {}, scrollTo() {} };

const { ownerName, agentName, companies, activity, modelLine, eventLabel, foldServers, modelsOf, programGroups, shortPath, incidentText, incidentTools } = await import("./ui/simple.mjs");
const { session } = await import("./ui/state.mjs");

test("registry owner names read as company names", () => {
  assert.equal(ownerName("ANTHROPIC · AS399358"), "Anthropic");
  assert.equal(ownerName("AMAZON-02 · AS16509"), "Amazon Web Services");
  assert.equal(ownerName("TELETECH · AS208398"), "Teletech");
  assert.equal(ownerName("FASTLY (GitHub Pages)"), "Fastly");
  assert.equal(ownerName(null), "Unknown");
});

test("agent families read as product names", () => {
  assert.equal(agentName({ family: "claude-code" }), "Claude Code");
  assert.equal(agentName({ family: "some-new-agent" }), "Some New Agent");
  assert.equal(agentName({}), "Unknown agent");
});

test("connections group by company, skip this machine and listeners", () => {
  const network = [
    { direction: "outbound", agent_pid: 1, network_owner: "ANTHROPIC · AS399358", country: "US", last_seen: 5 },
    { direction: "outbound", agent_pid: 1, network_owner: "ANTHROPIC · AS399358", country: "US", last_seen: 9 },
    { direction: "outbound", agent_pid: 2, network_owner: "GITHUB · AS36459", country: "US", last_seen: 3 },
    { direction: "outbound", agent_pid: 1, network_owner: "Loopback", country: "unknown" },
    { direction: "listening", agent_pid: 1, network_owner: "CLOUDFLARENET · AS13335", country: "US" },
  ];
  const all = companies(network);
  assert.deepEqual(all.map(c => [c.name, c.connections]), [["Anthropic", 2], ["GitHub", 1]]);
  assert.equal(all[0].last, 9);
  assert.equal(all[0].sentKnown, false);
  assert.deepEqual(companies(network, 2).map(c => c.name), ["GitHub"]);
});

test("activity says incident before unusual before normal", () => {
  session.data = { incidents: [{ agent: { pid: 7 } }] };
  assert.deepEqual(activity({ pid: 7, summary: { did_something: false } }), ["Incident", "bad"]);
  assert.deepEqual(activity({ pid: 8, summary: { did_something: true } }), ["Suspicious", "warn"]);
  assert.deepEqual(activity({ pid: 9, summary: { did_something: false } }), ["Normal", "calm"]);
  assert.deepEqual(activity({ pid: 7, live: false }), ["Stopped", "quiet"]);
});

test("the model line names the model, or says why there is none", () => {
  assert.equal(modelLine({ model: "anthropic/claude-opus-5-5" }), "claude-opus-5-5");
  assert.equal(modelLine({ kind: "model_runtime" }), "Model runtime");
  assert.equal(modelLine({ kind: "agent_editor" }), "Desktop app");
  assert.equal(modelLine({ kind: "agent" }), "Unknown model");
});

test("timeline events read as short labels", () => {
  assert.deepEqual(eventLabel({ kind: "started" }), ["Started", "calm"]);
  assert.deepEqual(eventLabel({ kind: "recon" }), ["Network scanning", "bad"]);
  assert.deepEqual(eventLabel({ kind: "grade_changed", detail: "HIGH to CRITICAL" }), ["Risk raised", "warn"]);
  assert.deepEqual(eventLabel({ kind: "grade_changed", detail: "CRITICAL to HIGH" }), ["Risk lowered", "calm"]);
  assert.deepEqual(eventLabel({ kind: "new_thing" }), ["New thing", "quiet"]);
});

test("a model server folds into the app that started it, an agent does not", () => {
  const agents = [
    { pid: 1, family: "unsloth", kind: "model_runtime", children: [{ pid: 2, depth: 1 }, { pid: 3, depth: 2 }] },
    { pid: 3, family: "llama-cpp", kind: "model_runtime", model: "unsloth/Qwen3.8-27B-GGUF", children: [] },
    { pid: 10, family: "claude-desktop", kind: "agent_editor", children: [{ pid: 11, depth: 1 }] },
    { pid: 11, family: "claude-code", kind: "agent", children: [] },
    { pid: 20, family: "ollama", kind: "model_runtime", children: [{ pid: 21, depth: 1 }] },
  ];
  const top = foldServers(agents);
  assert.deepEqual(top.map(a => a.pid), [1, 10, 11, 20]);
  assert.deepEqual(top[0].servers.map(s => s.pid), [3]);
  assert.equal(modelLine(top[0]), "Qwen3.8-27B-GGUF via llama.cpp");
  assert.equal(top[3].servers, undefined);
});

test("every recent model is listed, current first, without routes", () => {
  const agent = { model: "openai/gpt-6.1-terra", models_seen: ["openai/gpt-6-astra", "openai/gpt-6-luna", "openai/gpt-6.1-terra"] };
  assert.deepEqual(modelsOf(agent), ["gpt-6.1-terra", "gpt-6-astra", "gpt-6-luna"]);
  assert.deepEqual(modelsOf({}), []);
});

test("programs group by name with every run kept for the detail panel", () => {
  const groups = programGroups([
    { name: "zsh", pid: 1, agent_pid: 10, last_seen: 5 },
    { name: "lsof", pid: 2, agent_pid: 20, last_seen: 6 },
    { name: "zsh", pid: 3, agent_pid: 20, last_seen: 7 },
  ]);
  assert.deepEqual(groups.map(g => [g.name, g.runs.length]), [["zsh", 2], ["lsof", 1]]);
  assert.deepEqual(groups[0].runs.map(r => r.pid), [1, 3]);
});

test("paths hide the account name", () => {
  assert.equal(shortPath("/Users/someone/.bun/bin/bun"), "~/.bun/bin/bun");
  assert.equal(shortPath("/home/someone/x"), "~/x");
  assert.equal(shortPath("/usr/bin/zsh"), "/usr/bin/zsh");
});

test("incident actions read as text, never as raw JSON", () => {
  assert.equal(incidentText({ label: "Stop the agent." }), "Stop the agent.");
  assert.equal(incidentText("Rotate keys."), "Rotate keys.");
  assert.equal(incidentText({ text: "Check it." }), "Check it.");
  assert.equal(incidentText({}), "");
});

test("an incident names its tools from its own field or its evidence", () => {
  assert.deepEqual(incidentTools({ tools: ["nmap"] }), ["nmap"]);
  assert.deepEqual(incidentTools({ evidence: { findings: [{ summary: "nikto" }, { summary: "nikto" }, { summary: "nmap" }] } }), ["nikto", "nmap"]);
  assert.deepEqual(incidentTools({}), []);
});
