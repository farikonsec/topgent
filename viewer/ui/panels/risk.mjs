// Why an agent scored what it scored.
//
// Every factor with its points and the observation behind it. A score with no
// breakdown is an assertion; this panel is the argument.

import { $, CONF, GRADE, el, marks } from "../dom.mjs";
import { session } from "../state.mjs";

export function renderRisk() {
  const a = session.data.agents.find(x => x.pid === session.selected);
  $("riskTitle").textContent = a ? `Risk — ${a.family ?? "agent"}` : "Risk";
  $("riskSub").textContent = a ? `pid ${a.pid} · score ${a.score}` : "";
  const out = document.createDocumentFragment();
  if (!a) { out.append(el("div", { className: "empty", textContent: "Select an agent to see how its score is built." })); $("risk").replaceChildren(out); return; }
  if (!a.factors.length) out.append(el("div", { className: "empty", textContent: "No capability worth a factor. This agent scores zero." }));
  for (const f of a.factors) {
    const b = el("b", { className: "mono", textContent: "+" + f.points }); b.style.color = GRADE[a.grade]?.[0] ?? "var(--tx)";
    const titleRow = el("div", { style: "display:flex;align-items:center;gap:8px;flex-wrap:wrap" }, el("span", { textContent: f.title, style: "font-weight:500" }));
    if (f.atlas_id) titleRow.append(el("span", { className: "mono", style: "font-size:10px;padding:1px 5px;border:1px solid var(--bd2);border-radius:4px;color:var(--tx3)", textContent: f.atlas_id, title: f.atlas_desc }));
    const body = el("div", { style: "flex:1 1 auto; min-width:0" }, [ titleRow, el("div", { className: "mono faint", textContent: f.source }) ]);
    const c = el("div", { className: "faint", style: "flex:0 0 auto" }); c.append(marks("dots",3,CONF[f.confidence]??1), " " + f.confidence);
    out.append(el("div", { className: "factor" }, [b, body, c]));
  }
  $("risk").replaceChildren(out);
}
