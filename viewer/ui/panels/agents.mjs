// The agent table: what is running, and how bad it is.
//
// The first thing anyone looks at, so it is the one panel that is always open.
// A row names the exact run, not just the pid, because the pid is what a stale
// row would act on.

import { identityName } from "../alerts.mjs";
import { app } from "../app-hooks.mjs";
import { $, CONF, ROGUE_CODES, el, gradePill, marks, rel } from "../dom.mjs";
import { save, session, view } from "../state.mjs";
import { makeTable } from "../table.mjs";
import { blastPanel } from "./blast.mjs";

const AGENT_COLS = [
  { key:"family", label:"Agent", sortable:true },
  { key:"score", label:"Risk", sortable:true },
  { key:"identity", label:"Identity", sortable:true },
  { key:"model", label:"Model", sortable:true },
  { key:"discovery_confidence", label:"Detection", sortable:true },
  { key:"exposure", label:"Exposure" },
  { key:"started_at", label:"Uptime", sortable:true },
  { key:"pid", label:"PID", sortable:true, align:"right" },
  { key:"action", label:"", align:"right" },
];

function agentMatches(a, q) {
  if (!q) return true;
  q = q.toLowerCase();
  return [a.family, a.exe, a.model, a.identity, String(a.pid), a.grade].some(v => (v||"").toLowerCase().includes(q));
}

function sortedAgents() {
  let list = session.data.agents.filter(a =>
    (view.riskFilter === "all" || a.grade === view.riskFilter) && agentMatches(a, view.agentQuery));
  const { col, dir } = view.agentSort;
  list.sort((a, b) => {
    let x = a[col], y = b[col];
    if (col === "started_at" || col === "pid" || col === "score") { x = a[col]||0; y = b[col]||0; return (x - y) * dir; }
    return String(x ?? "").localeCompare(String(y ?? "")) * dir || (b.score - a.score);
  });
  return list;
}

function agentRow(a) {
  const tr = el("tr", { className: "agent" });
  tr.dataset.pid = a.pid;
  tr.setAttribute("aria-selected", String(a.pid === session.selected));
  tr.onclick = () => { session.selected = a.pid; app.render(); };

  const name = el("td", {}, [
    el("div", { textContent: identityName(a), style: "font-weight:500" }),
    el("div", { className: "mono faint", textContent: (a.exe ?? "").split("/").pop() }),
  ]);
  const limits = a.identity_evidence?.limits ?? [];
  if (limits.length) {
    // An unrecognised process is not automatically a safe one. Say which
    // sensor could not see it rather than drawing an empty card.
    name.append(el("div", { className: "faint", textContent: limits.join(" "), style: "margin-top:2px" }));
    name.title = limits.join("\n");
  }
  const risk = el("td", {}, gradePill(a.grade, a.score));
  const ident = el("td", { className: "muted", textContent: a.identity });
  const model = el("td", { className: "mono muted", textContent: a.model ?? "—" });

  const det = el("td", { className: "muted" });
  const sources = [...new Set((a.resources||[]).flatMap(r=>r.evidence||[]).map(s=>s.split(" ")[0]))].filter(Boolean).slice(0,4);
  det.title = "Identified from: process table" + (sources.length ? ", " + sources.join(", ") : "");
  det.append(marks("dots",3,CONF[a.discovery_confidence]??1), " " + a.discovery_confidence);

  const secrets = a.resources.filter(r=>r.latent_secret);
  const drift = a.resources.filter(r=>r.drift);
  const exposure = el("td");
  const chips = [];
  if (a.outbound) chips.push([`${a.outbound} outbound`, "net"]);
  if (secrets.length) chips.push([`${secrets.length} credential${secrets.length>1?"s":""}`, "cred"]);
  if (drift.length) chips.push([`${drift.length} out of policy`, "drift"]);
  const rogue = a.factors.filter(f=>ROGUE_CODES.has(f.code));
  if (rogue.length) chips.push([`${rogue.length} rogue signal${rogue.length>1?"s":""}`, "cred"]);
  if ((a.children||[]).length) chips.push([`${a.children.length} child proc.`, "net"]);
  if (!chips.length) exposure.append(el("span", { className: "faint", textContent: "None" }));
  else for (const [label, cls] of chips) {
    const c = el("button", { className: `chip ${cls}`, textContent: label, type: "button", title: "Click to expand" });
    c.onclick = (ev) => { ev.stopPropagation(); session.expanded = session.expanded === a.pid ? null : a.pid; session.selected = a.pid; app.render(); };
    exposure.append(c);
  }

  const up = el("td", { className: "mono muted", textContent: rel(a.started_at) });
  const pid = el("td", { className: "mono muted", textContent: String(a.pid), style: "text-align:right" });
  const act = el("td", { style: "text-align:right" });
  const stop = el("button", { className: "btn quiet", textContent: "Stop" });
  stop.onclick = (ev) => { ev.stopPropagation(); app.askStop(a); };
  act.append(stop);

  tr.append(name, risk, ident, model, det, exposure, up, pid, act);
  return tr;
}

function expansionRow(a) {
  const tr = el("tr");
  const td = el("td", { colSpan: AGENT_COLS.length, style: "background:var(--surf2); padding:0" });
  td.append(blastPanel(a, true));
  tr.append(td);
  return tr;
}

export function renderAgents() {
  const host = $("agentsBody");
  const list = sortedAgents();
  const rows = [];
  for (const a of list) {
    rows.push(agentRow(a));
    if (session.expanded === a.pid) rows.push(expansionRow(a));
  }
  const frag = document.createDocumentFragment();
  if (!rows.length) {
    frag.append(el("div", { className: "empty", textContent:
      session.data.agents.length ? "No agents match this filter." : "No AI agents are running on this machine right now." }));
  } else {
    frag.append(makeTable("agents", AGENT_COLS, rows, {
      sort: view.agentSort,
      onSort: (col) => { view.agentSort = { col, dir: view.agentSort.col === col ? -view.agentSort.dir : (col==="family"||col==="identity"||col==="model"?1:-1) }; save(); app.render(); },
    }));
  }
  host.replaceChildren(frag);

  $("agentCount").textContent = `${list.length} of ${session.data.agents.length}`;
  const by = (g) => session.data.agents.filter(a => a.grade === g).length;
  $("nCrit").textContent = by("CRITICAL"); $("nHigh").textContent = by("HIGH");
  $("nMed").textContent = by("MEDIUM"); $("nLow").textContent = by("LOW");
}
