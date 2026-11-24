// The event log.
//
// One timeline covering both what Topgent observed and what it did, so an
// incident does not have to be reconstructed from two formats.

import { eventLabel } from "../alerts.mjs";
import { $, clock, el, rel } from "../dom.mjs";
import { session, view, runName } from "../state.mjs";
import { changeSort, makeTable, sortedBy } from "../table.mjs";
import { openInspector } from "../inspector.mjs";

export function renderEvents() {
  const filtered = (session.data.events ?? []).filter(e =>
    (view.eventKind === "all" || e.kind === view.eventKind) &&
    (!view.eventQuery || [e.agent, e.detail, eventLabel(e), String(e.pid)].some(v => (v||"").toLowerCase().includes(view.eventQuery.toLowerCase()))));
  const events = sortedBy(filtered, view.eventSort, (event, col) => col === "kind" ? eventLabel(event) : event[col]);
  $("eventCount").textContent = `${events.length} event${events.length===1?"":"s"}`;
  const out = document.createDocumentFragment();
  if (!events.length) {
    out.append(el("div", { className: "empty", textContent:
      (session.data.events||[]).length ? "No events match." : "No events yet. Topgent records agents starting and stopping, risk changing, credentials coming into reach, and every action it takes." }));
    $("events").replaceChildren(out); return;
  }
  const sevClass = s => s === "critical" ? "crit" : s === "high" ? "high" : ["warning","medium"].includes(s) ? "med" : "low";
  const rows = [];
  for (const e of events.slice(0, 500)) {
    const severity = e.severity ?? (["behaviour","recon","credential_exposed","policy_breach"].includes(e.kind) ? "critical" : "info");
    const row = el("tr", { className:`event-row event-${severity} clickable`, tabIndex:0, title:"Open event details" }, [
      el("td", { className: "mono", title: new Date(e.at).toString() }, [ el("div", { textContent: clock(e.at) }), el("div", { className: "faint", textContent: rel(e.at) + " ago" }) ]),
      el("td", {}, [el("span", { className: "kchip k-" + e.kind + (e.direction ? " k-" + e.direction : ""), textContent: eventLabel(e) })]),
      el("td", { textContent: runName(e.pid, e.started_at, e.agent) }),
      el("td", { className: "mono muted", textContent: String(e.pid) }),
      el("td", { className: "muted", textContent: e.detail }),
    ]);
    const open = () => openInspector({
      title: eventLabel(e), sevLabel: severity.toUpperCase(), sevClass: sevClass(severity),
      plain: e.detail,
      rows: [
        ["event code", e.kind, true],
        ["agent instance", `${runName(e.pid, e.started_at, e.agent)} · pid ${e.pid}`],
        ["recorded", new Date(e.at).toISOString()],
        ["evidence", e.evidence ?? "persistent local event journal"],
      ],
    });
    row.onclick = open;
    row.onkeydown = event => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); open(); } };
    rows.push(row);
  }
  out.append(makeTable("events", [
    { key:"at", label:"When", sortable:true }, { key:"kind", label:"Event", sortable:true }, { key:"agent", label:"Agent", sortable:true }, { key:"pid", label:"PID", align:"right", sortable:true }, { key:"detail", label:"Detail", sortable:true },
  ], rows, { sort:view.eventSort, onSort:(col)=>changeSort("eventSort", col, renderEvents) }));
  $("events").replaceChildren(out);
}
