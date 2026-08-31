// The activity path.
//
// Metadata only, and bounded. Direct relationships are labelled direct;
// sequences joined by identity and time are labelled correlated, so temporal
// proximity never reads as causality.

import { $, clock, el, rel } from "../dom.mjs";
import { session, view } from "../state.mjs";
import { changeSort, makeTable, sortedBy } from "../table.mjs";

export function renderActivity() {
  const host = $("activity");
  const agent = session.data.agents.find(item => item.pid === session.selected);
  const allEvents = session.data.activity?.events ?? [];
  const events = sortedBy(
    allEvents.filter(event => !agent || (event.agent_pid === agent.pid && event.agent_started_at === agent.started_at)),
    view.activitySort,
    (event, col) => event[col],
  );
  const paths = (session.data.activity?.paths ?? []).filter(path => !agent || (path.agent_pid === agent.pid && path.agent_started_at === agent.started_at));
  const linkByTarget = new Map((session.data.activity?.links ?? []).map(link => [link.to, link]));
  $("activityCount").textContent = `${events.length} observation${events.length===1?"":"s"} · ${paths.length} correlated path${paths.length===1?"":"s"}${agent ? ` · pid ${agent.pid}` : ""}`;

  if (!events.length) {
    host.replaceChildren(el("div", { className:"empty", textContent:agent ? "No retained activity evidence for this agent run." : "No retained agent activity observed." }));
    return;
  }

  const out = document.createDocumentFragment();
  out.append(el("div", { className:"activity-note", textContent:"Metadata-only host evidence is retained locally for up to 7 days (maximum 4,096 observations) and kept separate by process start time. ‘Correlated’ does not prove intent, causation, or data transfer." }));
  if (paths.length) {
    const cards = el("div", { className:"path-list" });
    for (const path of paths) cards.append(el("div", { className:"path-card" }, [
      el("div", { className:"path-head" }, [el("span", { textContent:path.title }), el("span", { className:"certainty", textContent:path.certainty })]),
      el("p", { textContent:path.explanation }),
    ]));
    out.append(cards);
  }
  const rows = events.map(event => {
    const link = linkByTarget.get(event.id);
    return el("tr", {}, [
    el("td", { className:"mono", title:new Date(event.at).toString() }, [el("div", { textContent:clock(event.at) }), el("div", { className:"faint", textContent:rel(event.at)+" ago" })]),
    el("td", {}, [el("div", { textContent:event.title, style:"font-weight:500" }), el("div", { className:"mono faint", textContent:event.detail })]),
    el("td", { className:"mono muted", textContent:String(event.actor_pid) }),
    el("td", {}, link ? [el("div", { textContent:link.relation }), el("div", { className:"certainty", textContent:link.certainty })] : el("span", { className:"faint", textContent:"root" })),
    el("td", {}, [el("div", { textContent:event.confidence }), el("div", { className:"mono faint", textContent:`${event.collector} · ${event.probe}` })]),
  ]);
  });
  out.append(makeTable("activity", [
    {key:"at",label:"When",sortable:true}, {key:"title",label:"Observed activity",sortable:true},
    {key:"actor_pid",label:"Actor PID",sortable:true,align:"right"}, {key:"relation",label:"Relationship",sortable:false},
    {key:"confidence",label:"Evidence",sortable:true},
  ], rows, {sort:view.activitySort,onSort:(col)=>changeSort("activitySort",col,renderActivity)}));
  host.replaceChildren(out);
}
