// Declared, observed, and reachable, side by side.
//
// The gap between what an agent says it needs and what it can actually touch
// is usually the finding.

import { $, el } from "../dom.mjs";
import { session, view } from "../state.mjs";
import { changeSort, makeTable, sortedBy } from "../table.mjs";

export function renderAccess() {
  const a = session.data.agents.find(x => x.pid === session.selected);
  const out = document.createDocumentFragment();
  if (!a) { out.append(el("div", { className: "empty", textContent: "Select an agent." })); $("access").replaceChildren(out); return; }
  const interesting = a.resources.filter(r => r.drift || r.latent_secret);
  const candidates = interesting.length ? interesting : a.resources.slice(0, 14);
  const shown = sortedBy(candidates, view.accessSort, (resource, col) =>
    col === "evidence" ? (resource.evidence||[]).join(" · ") : resource[col]);
  if (!shown.length) { out.append(el("div", { className: "empty", textContent: "No resources observed for this agent." })); $("access").replaceChildren(out); return; }
  const rows = shown.map(r => {
    const first = el("td", {}, el("code", { textContent: r.path }));
    if (r.drift) { const f = el("span", { className: "flag", textContent: "OUT OF POLICY" }); f.style.color="var(--high)"; f.style.background="var(--highbg)"; first.append(" ", f); }
    if (r.latent_secret) { const f = el("span", { className: "flag", textContent: "CREDENTIAL" }); f.style.color="var(--crit)"; f.style.background="var(--critbg)"; first.append(" ", f); }
    const reach = el("td", { textContent: r.latent_secret ? "YES" : r.reachable });
    if (r.latent_secret) { reach.style.color="var(--crit)"; reach.style.fontWeight="600"; } else reach.className = "muted";
    return el("tr", {}, [ first, el("td",{className:"muted",textContent:r.declared}), el("td",{className:"muted",textContent:r.observed}), reach, el("td",{className:"mono faint",textContent:(r.evidence||[]).join(" · ")}) ]);
  });
  out.append(makeTable("access", [
    { key:"path", label:"Resource", sortable:true }, { key:"declared", label:"Declared", sortable:true },
    { key:"observed", label:"Observed", sortable:true }, { key:"reachable", label:"Reachable", sortable:true }, { key:"evidence", label:"Evidence", sortable:true },
  ], rows, { sort:view.accessSort, onSort:(col)=>changeSort("accessSort", col, renderAccess) }));
  $("access").replaceChildren(out);
}
