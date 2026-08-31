// The event log.
//
// One timeline covering both what Topgent observed and what it did, so an
// incident does not have to be reconstructed from two formats.

import { eventLabel } from "../alerts.mjs";
import { $, clock, el, rel } from "../dom.mjs";
import { session, view } from "../state.mjs";
import { changeSort, makeTable, sortedBy } from "../table.mjs";

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
  const rows = [];
  for (const e of events.slice(0, 500)) {
    const eventId = e.id ?? `${e.at}:${e.kind}:${e.pid}`;
    const isOpen = session.expandedEvents.has(eventId);
    const severity = e.severity ?? (["behaviour","recon","credential_exposed","policy_breach"].includes(e.kind) ? "critical" : "info");
    const row = el("tr", { className:`event-row event-${severity}`, tabIndex:0, ariaExpanded:String(isOpen), title:"Open event details" }, [
      el("td", { className: "mono", title: new Date(e.at).toString() }, [ el("div", { textContent: clock(e.at) }), el("div", { className: "faint", textContent: rel(e.at) + " ago" }) ]),
      el("td", {}, [el("span", { className:"event-disclosure", textContent:isOpen?"▾":"▸" }), el("span", { className: "kchip k-" + e.kind + (e.direction ? " k-" + e.direction : ""), textContent: eventLabel(e) })]),
      el("td", { textContent: e.agent }),
      el("td", { className: "mono muted", textContent: String(e.pid) }),
      el("td", { className: "muted", textContent: e.detail }),
    ]);
    const toggle = () => { if (isOpen) session.expandedEvents.delete(eventId); else session.expandedEvents.add(eventId); renderEvents(); };
    row.onclick = toggle;
    row.onkeydown = event => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); toggle(); } };
    rows.push(row);
    if (isOpen) {
      const detail = el("div", { className:"event-detail-grid" });
      const items = [
        ["Severity", severity.toUpperCase()], ["Recorded", new Date(e.at).toISOString()],
        ["Event code", e.kind], ["Agent instance", `${e.agent} · pid ${e.pid}`],
        ["Evidence", e.evidence ?? "persistent local event journal"], ["Detail", e.detail],
      ];
      for (const [label,value] of items) detail.append(el("div", { className:"event-detail-item" }, [el("b", { textContent:label }), el("span", { className:label==="Event code"?"mono":"", textContent:value })]));
      rows.push(el("tr", { className:"event-detail-row" }, el("td", { colSpan:5 }, detail)));
    }
  }
  out.append(makeTable("events", [
    { key:"at", label:"When", sortable:true }, { key:"kind", label:"Event", sortable:true }, { key:"agent", label:"Agent", sortable:true }, { key:"pid", label:"PID", align:"right", sortable:true }, { key:"detail", label:"Detail", sortable:true },
  ], rows, { sort:view.eventSort, onSort:(col)=>changeSort("eventSort", col, renderEvents) }));
  $("events").replaceChildren(out);
}
