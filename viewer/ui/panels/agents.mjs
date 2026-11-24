// Stable, worst-first agent picker. The desktop shell is the wording and
// information-architecture source of truth for this list.

import { identityName } from "../alerts.mjs";
import { app } from "../app-hooks.mjs";
import { $, el, gradePill } from "../dom.mjs";
import { findAgent, session, stamp, view } from "../state.mjs";

export function agentMatchesFilter(agent, filter) {
  if (filter === "at_risk") return agent.grade === "CRITICAL" || agent.grade === "HIGH";
  if (filter === "unscored") return !["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(agent.grade);
  return true;
}

function matchesQuery(agent, query) {
  const needle = query.trim().toLowerCase();
  if (!needle) return true;
  return [agent.family, agent.exe, agent.model, agent.identity, agent.pid, agent.grade]
    .some(value => String(value ?? "").toLowerCase().includes(needle));
}

// Current reports give {id, image}; the first build with the field, the id.
function containerText(container) {
  if (!container) return null;
  if (typeof container === "string") return ` · container ${container}`;
  return ` · container ${container.id}${container.image ? ` (${container.image})` : ""}`;
}

function card(agent) {
  const button = el("button", { className:"agent-card", type:"button" });
  button.dataset.pid = String(agent.pid);
  button.setAttribute("aria-pressed", String(agent.pid === session.selected));
  button.onclick = () => { session.selected = agent.pid; app.render(); };
  const cls = agent.identity_evidence?.class;
  const idChip = cls ? el("span", { className:`id-chip id-${cls}`, textContent:cls, title:"How firmly this agent's identity is established" }) : null;
  button.append(
    el("span", { className:"agent-card-top" }, [
      el("strong", { textContent:identityName(agent) }),
      gradePill(agent.grade, agent.score),
    ]),
    el("span", { className:"agent-card-program mono", textContent:agent.exe || "Executable not reported" }),
    el("span", { className:"agent-card-meta" }, [
      idChip, idChip ? " " : null,
      `PID ${agent.pid} · ${agent.model || "model unknown"}`,
      containerText(agent.container),
    ]),
    el("span", { className:`agent-card-state${ended(agent) ? " ended" : ""}`, textContent:stateLine(agent) }),
  );
  if (ended(agent)) button.classList.add("ended");
  return button;
}

const ended = agent => agent.live === false;

/** Running since when, or ended and last seen when (report.rs, state_line). */
export function stateLine(agent) {
  const started = stamp(agent.started_at);
  if (!ended(agent)) return `Running since ${started}`;
  return agent.last_seen ? `Ended · ran ${started} to ${stamp(agent.last_seen)}` : `Ended · started ${started}`;
}

export function renderAgents() {
  // Running first, then those that ended this session; each worst first.
  const all = [...(session.data.agents ?? []), ...(session.data.ended_agents ?? [])].sort((left, right) =>
    Number(ended(left)) - Number(ended(right)) || (right.score ?? -1) - (left.score ?? -1) || left.pid - right.pid);
  const list = all.filter(agent => agentMatchesFilter(agent, view.riskFilter) && matchesQuery(agent, view.agentQuery));
  const host = $("agentsBody");
  if (!list.length) {
    host.replaceChildren(el("div", { className:"empty", textContent:all.length ? "No agent matches this filter." : "No AI agents are running on this machine." }));
  } else {
    const cards = [];
    let heading = false;
    for (const agent of list) {
      if (ended(agent) && !heading) {
        heading = true;
        cards.push(el("div", { className:"list-heading", textContent:"Ended this session" }));
      }
      cards.push(card(agent));
    }
    host.replaceChildren(...cards);
  }
  $("agentCount").textContent = `${list.length} of ${all.length}`;

  const agent = findAgent(session.selected);
  $("selectedAgentName").textContent = agent ? identityName(agent) : "Select an agent";
  $("selectedAgentMeta").textContent = agent
    ? `${agent.exe || "Executable not reported"} · PID ${agent.pid} · ${stateLine(agent)}`
    : "";
  const stop = $("selectedAgentStop");
  // Nothing to stop once it has ended.
  stop.hidden = !agent || ended(agent);
  stop.onclick = agent ? () => app.askStop(agent) : null;
}
