// The four figures across the top, as the desktop draws them (shell.rs,
// `metrics`): the counts an operator checks before deciding where to look.
// Each is a button that opens where the evidence behind it is.

import { $ } from "../dom.mjs";
import { go, session } from "../state.mjs";
import { incidentTime } from "./incidents.mjs";

/** Credential files an agent was observed reading, as the desktop counts. */
export function credentialReads(agents) {
  return agents.flatMap(a => a.resources ?? []).filter(r => r.sensitive && r.observed === "yes").length;
}

export function renderOverview() {
  const agents = session.data.agents ?? [];
  const critical = agents.filter(a => String(a.grade).toUpperCase() === "CRITICAL").length;
  const endpoints = (session.data.network ?? []).length;
  const reads = credentialReads(agents);
  const set = (id, value, tone) => {
    $(id).textContent = String(value);
    $(id).style.color = tone;
  };
  set("metricAgents", agents.length, "var(--tx)");
  set("metricCritical", critical, critical ? "var(--crit)" : "var(--tx2)");
  set("metricEndpoints", endpoints, endpoints ? "var(--tx)" : "var(--tx2)");
  set("metricReads", reads, reads ? "var(--crit)" : "var(--tx2)");
  // Incidents, with the most recent one's time as the note.
  const incidents = session.data.incidents ?? [];
  const anyCrit = incidents.some(i => String(i.severity).toLowerCase() === "critical");
  const newest = incidents.reduce((best, i) => Math.max(best, i.first_seen ?? i.first_at ?? 0), 0);
  set("metricIncidents", incidents.length, incidents.length ? (anyCrit ? "var(--crit)" : "var(--high)") : "var(--tx2)");
  const note = $("metricIncidentsNote");
  if (note) note.textContent = newest ? `latest ${incidentTime({ first_seen: newest })}` : "Open";
  for (const button of document.querySelectorAll(".threat-rail [data-go]")) {
    button.onclick = () => go(button.dataset.go);
  }
}
