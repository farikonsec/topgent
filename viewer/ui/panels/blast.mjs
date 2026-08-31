// What the selected agent can reach.
//
// Not what it did — what it could. The distinction matters when deciding
// whether to stop something: reach is the cost of being wrong about it.

import { connectionAge, connectionTraffic } from "../alerts.mjs";
import { $, el } from "../dom.mjs";
import { session } from "../state.mjs";
import { invoke } from "../transport.mjs";

export function blastPanel(a, compact) {
  const wrap = el("div", { className: "blast" });
  const files = a.resources.filter(r => r.reachable === "yes" || r.latent_secret);
  const creds = a.resources.filter(r => r.latent_secret);
  const nets = a.endpoints.filter(e => e.direction === "outbound");
  const drift = a.resources.filter(r => r.drift);
  const agents = a.invokes || [];

  const total = agents.length + creds.length + nets.length;
  wrap.append(el("div", { className: "lead" }, [
    "If ", el("b", { textContent: a.family ?? "this agent" }),
    ` (pid ${a.pid}) were compromised, an attacker would immediately reach `,
    el("b", { textContent: `${total} sensitive target${total===1?"":"s"}` }), ".",
  ]));

  if (agents.length) {
    const note = el("div", { className: "brnote" });
    const icon = el("span", { style: "display:flex;color:var(--crit)" });
    icon.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9"><path d="M7 17L17 7M9 7h8v8"/></svg>';
    note.append(icon, el("span", {}, [ el("b", { textContent: `${agents.length} other agent${agents.length>1?"s":""}` }),
      " can be invoked from here, so their reach becomes its reach at the second hop." ]));
    wrap.append(note);
  }

  const grid = el("div", { className: "brgrid" });
  grid.append(
    brCard(agents.length, "agents it can invoke", agents.map(e => [`pid ${e.target_pid}`, e.via]), true),
    brCard(creds.length, "credentials in reach", creds.map(r => [r.path, "reachable now, not yet accessed"]), creds.length > 0),
    brCard(nets.length, "outbound destinations", nets.map(e => [`${e.host}:${e.port}`, `${connectionAge(e)}${connectionTraffic(e)}`]), false),
    brCard(drift.length, "resources out of policy", drift.map(r => [r.path, "touched, not granted"]), drift.length > 0),
  );
  wrap.append(grid);
  return wrap;
}

function brCard(n, label, items, hot) {
  const card = el("div", { className: "brcard" + (hot && n ? " hot" : "") });
  card.append(el("div", { className: "t" }, [ el("span", { className: "n", textContent: String(n) }), el("span", { className: "l", textContent: label }) ]));
  if (items.length) {
    const ul = el("ul");
    for (const [main, why] of items) ul.append(el("li", {}, [ el("code", { textContent: main }), why ? el("span", { className: "why", textContent: why }) : null ]));
    card.append(ul);
  }
  return card;
}

export function renderBlast() {
  const a = session.data.agents.find(x => x.pid === session.selected);
  $("blastSub").textContent = a ? `pid ${a.pid}` : "";
  if (!a) { $("blast").replaceChildren(el("div", { className: "empty", textContent: "Select an agent to see what a compromise would reach." })); return; }
  $("blast").replaceChildren(blastPanel(a, false));
}
