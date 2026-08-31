// What an agent's own harness reported about itself.
//
// A claim by the thing being watched. Shown because it is useful, and never
// allowed to outrank what the host observed directly.

import { $, clock, el } from "../dom.mjs";
import { session } from "../state.mjs";
import { makeTable } from "../table.mjs";

export function renderContext() {
  const context = session.data.context ?? { enabled:false, records:[] };
  const records = (context.records ?? []).filter(record => session.selected == null || record.pid === session.selected);
  $("contextCount").textContent = context.enabled ? `${records.length} selected-agent record${records.length===1?"":"s"}` : "disabled";
  $("contextToggle").textContent = context.enabled ? "Disable context" : "Enable context";
  $("contextClear").disabled = !(context.records ?? []).length;
  const host = $("context"); host.replaceChildren();
  host.append(el("div", { className:"context-note" }, [
    el("strong", { textContent:"Agent-supplied, sanitized context only. " }),
    document.createTextNode("Raw prompts and tool payloads are not accepted. Deterministic host evidence remains authoritative when context disagrees.")
  ]));
  const integrations = context.integrations?.adapters ?? [];
  if (integrations.length) {
    const strip = el("div", { className:"integration-strip" });
    for (const adapter of integrations) {
      const ready = adapter.configured && adapter.detected;
      const state = !adapter.detected ? "not running" : adapter.configured ? "connected" : "hook not installed";
      strip.append(el("span", { className:`integration ${ready?"ready":"wait"}`, textContent:`${adapter.family} · ${state}`, title:adapter.mode.replaceAll("_", " ") }));
    }
    host.append(strip);
  }
  if (!context.enabled) {
    host.append(el("div", { className:"empty", textContent:"Context is opt-in and currently disabled. Host monitoring and detection continue normally." }));
    return;
  }
  if (!records.length) {
    host.append(el("div", { className:"empty", textContent:"Context is ready, but this session.selected agent has not emitted a correlated lifecycle event yet. Start a new task or turn after its adapter is connected." }));
    return;
  }
  const rows = records.map(record => el("tr", {}, [
    el("td", { textContent:clock(record.observed_at) }),
    el("td", {}, el("span", { className:"mono", textContent:record.session_id })),
    el("td", { textContent:record.summary }),
    el("td", { textContent:record.objective }),
    el("td", { textContent:record.tool }),
    el("td", { textContent:record.outcome }),
    el("td", {}, el("span", { className:record.matched?"mono":"mono context-unmatched", textContent:`${record.source}${record.matched?"":" · unmatched"}` }))
  ]));
  host.append(makeTable("context", [
    {key:"observed_at",label:"When"}, {key:"session_id",label:"Session"},
    {key:"summary",label:"Sanitized summary"}, {key:"objective",label:"Objective"},
    {key:"tool",label:"Tool"}, {key:"outcome",label:"Outcome"}, {key:"source",label:"Source"}
  ], rows));
}
