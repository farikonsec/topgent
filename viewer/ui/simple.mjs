// The simple view: the default face of Topgent, for people who are not
// security engineers.
//
// It answers one question first: is any AI agent running here, and does any of
// them need a decision? Everything technical stays one click away in the
// technical view, which is the original interface, unchanged. The words come
// from the report's per-agent `summary` (crates/topgent-report/src/plain.rs and
// data/plain-risks.json), so this file arranges sentences and never writes its
// own translation of a risk.
//
// Layout follows the product page mock: a sidebar of five pages, four figures,
// and one table of agents with Risk, Talking to and Activity.

import { $, el } from "./dom.mjs";
import { bytes } from "./format.mjs";
import { app } from "./app-hooks.mjs";
import { logo } from "./brands.mjs";
import { agentName } from "./names.mjs";

export { agentName };
import { applyPanelLayout, save, session, stamp, view } from "./state.mjs";

export const PAGES = [
  ["agents", "Agents"],
  ["risks", "Risks"],
  ["connections", "Connections"],
  ["incidents", "Incidents"],
  ["reports", "Reports"],
];

const LEVEL_TONE = { act: "bad", watch: "warn", info: "calm", none: "calm" };

// Network owners as the address registry spells them, and as a person would.
const OWNER_NAMES = {
  ANTHROPIC: "Anthropic", OPENAI: "OpenAI", "GOOGLE": "Google", "GOOGLE-CLOUD-PLATFORM": "Google Cloud",
  CLOUDFLARENET: "Cloudflare", "AMAZON-02": "Amazon Web Services", "AMAZON-AES": "Amazon Web Services",
  "MICROSOFT-CORP-MSN-AS-BLOCK": "Microsoft", FASTLY: "Fastly", GITHUB: "GitHub", AKAMAI: "Akamai",
  "AKAMAI-ASN1": "Akamai", "DIGITALOCEAN-ASN": "DigitalOcean", VERCEL: "Vercel", CONTABO: "Contabo",
};
const LOCAL_OWNERS = new Set(["Loopback", "Private use", "Link-local", "Unique local", "Multicast", "This network", "Carrier-grade NAT"]);

/** A network owner's name as a person reads it: `ANTHROPIC · AS399358` → Anthropic. */
export function ownerName(raw) {
  if (!raw) return "Unknown";
  const base = String(raw).split(" · ")[0].split(" (")[0].trim();
  if (OWNER_NAMES[base]) return OWNER_NAMES[base];
  if (base !== base.toUpperCase()) return base;
  const word = base.split(/[-_ ]/)[0].toLowerCase();
  return word.charAt(0).toUpperCase() + word.slice(1);
}

/** The model without its route: `anthropic/claude-opus-4-8` → claude-opus-4-8. */
const modelName = (agent) => agent.model ? String(agent.model).split("/").pop() : null;

/** Every model an agent used recently, current first, without routes. */
export function modelsOf(agent) {
  const all = [agent.model, ...(agent.models_seen ?? [])].filter(Boolean).map(m => String(m).split("/").pop());
  return all.filter((m, i) => all.indexOf(m) === i);
}

/** The model line: the model, or what kind of thing has none of its own. */
export function modelLine(agent) {
  const model = modelName(agent);
  if (model) return model;
  const served = (agent.servers ?? []).find(s => s.model);
  if (served) return `${modelName(served)} via ${agentName(served)}`;
  if (agent.kind === "model_runtime") return "Model runtime";
  if (agent.kind === "agent_editor") return "Desktop app";
  return "Unknown model";
}

/** Outbound connections to the internet, grouped by the company at the other end. */
export function companies(network, pid) {
  const groups = new Map();
  const pids = pid == null ? null : new Set([].concat(pid));
  for (const row of network ?? []) {
    if (row.direction === "listening") continue;
    if (pids && !pids.has(row.agent_pid)) continue;
    if (LOCAL_OWNERS.has(row.network_owner)) continue;
    const name = ownerName(row.network_owner);
    const group = groups.get(name) ?? { name, country: row.country, agents: new Set(), connections: 0, sent: 0, sentKnown: false, last: 0 };
    group.connections += 1;
    if (row.agent_pid != null) group.agents.add(row.agent_pid);
    const sent = row.bytes?.sent ?? row.bytes_sent;
    if (sent != null) { group.sent += sent; group.sentKnown = true; }
    group.last = Math.max(group.last, row.last_seen ?? 0);
    if (group.country === "unknown" && row.country !== "unknown") group.country = row.country;
    groups.set(name, group);
  }
  return [...groups.values()].sort((a, b) => b.connections - a.connections || a.name.localeCompare(b.name));
}

const incidentsFor = (pid) => (session.data.incidents ?? []).filter(i => (i.agent?.pid ?? i.agent_pid) === pid);

/** What an agent is doing, in one word, for the Activity column. */
export function activity(agent) {
  if (agent.live === false) return ["Stopped", "quiet"];
  if (incidentsFor(agent.pid).length) return ["Incident", "bad"];
  if (agent.summary?.did_something) return ["Suspicious", "warn"];
  return ["Normal", "calm"];
}

/**
 * Model servers folded into the app that started them.
 *
 * Unsloth Studio runs its model in a llama.cpp server two levels below it, and
 * the catalogue recognises that server on its own, so the overview listed one
 * product as two agents. A model runtime found among another agent's children
 * moves under that agent as `servers`. Only model runtimes fold: a Claude Code
 * session started from Claude Desktop is an agent in its own right.
 */
export function foldServers(agents) {
  const parentOf = new Map();
  for (const a of agents) for (const c of a.children ?? []) if (c.pid !== a.pid) parentOf.set(c.pid, a.pid);
  const byPid = new Map(agents.map(a => [a.pid, a]));
  const servers = new Map();
  const top = [];
  for (const a of agents) {
    const parent = byPid.get(parentOf.get(a.pid));
    if (a.kind === "model_runtime" && parent && parentOf.get(parent.pid) !== a.pid) {
      servers.set(parent.pid, [...(servers.get(parent.pid) ?? []), a]);
    } else top.push(a);
  }
  return top.map(a => servers.has(a.pid) ? { ...a, servers: servers.get(a.pid) } : a);
}

/** The pids an overview row speaks for: the agent and any model server it runs. */
const rowPids = (agent) => [agent.pid, ...(agent.servers ?? []).map(s => s.pid)];

/** The more urgent of an agent's summary and its servers'. */
function rowSummary(agent) {
  const all = [agent, ...(agent.servers ?? [])].map(a => a.summary).filter(Boolean);
  return all.sort((a, b) => (({ act: 0, watch: 1, info: 2 })[a.level] ?? 3) - (({ act: 0, watch: 1, info: 2 })[b.level] ?? 3))[0];
}

const TONE_RANK = { bad: 0, warn: 1, calm: 2, quiet: 3 };

/** A time to the minute: a seconds clock changed the page on every refresh. */
const minute = (ms) => stamp(ms).replace(/(\d{2}:\d{2}):\d{2}$/, "$1");

const pill = (text, tone) => el("span", { className: `s-pill s-${tone}`, textContent: text });
const runningAgents = () => foldServers((session.data?.agents ?? []).filter(a => a.live !== false));

// ---- pages ----

function figures(running) {
  const needDecision = running.filter(a => a.summary?.level === "act").length;
  const incidents = (session.data.incidents ?? []).length;
  const contacted = companies(session.data.network).length;
  const tile = (value, label, tone, page) => {
    const b = el("button", { className: `s-tile${value && tone ? ` s-tile-${tone}` : ""}`, type: "button" }, [
      el("strong", { textContent: String(value) }), el("span", { textContent: label }),
    ]);
    b.onclick = () => goSimple(page);
    return b;
  };
  return el("div", { className: "s-tiles" }, [
    tile(running.length, "Running", null, "agents"),
    tile(needDecision, "Critical", "bad", "risks"),
    tile(contacted, "Destinations", null, "connections"),
    tile(incidents, "Incidents", "bad", "incidents"),
  ]);
}

function agentRow(agent) {
  const summary = rowSummary(agent) ?? { level: "none", label: "OK", headline: "OK" };
  const talking = companies(session.data.network, rowPids(agent)).map(c => c.name);
  const [act, actTone] = [agent, ...(agent.servers ?? [])].map(activity).sort((a, b) => TONE_RANK[a[1]] - TONE_RANK[b[1]])[0];
  const row = el("tr", { className: "s-row", tabIndex: 0 });
  const open = () => { session.simpleAgent = agent.pid; app.render(); window.scrollTo(0, 0); };
  row.onclick = open;
  row.onkeydown = (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(); } };
  const name = agentName(agent);
  row.append(
    el("td", {}, el("div", { className: "s-agent" }, [
      logo({ family: agent.family, name }),
      el("div", {}, [el("strong", { textContent: name }), el("small", { textContent: [modelLine(agent) + (modelsOf(agent).length > 1 ? ` +${modelsOf(agent).length - 1}` : ""), agent.live === false ? null : `started ${stamp(agent.started_at)}`].filter(Boolean).join(" · ") })]),
    ])),
    el("td", {}, [pill(summary.label, LEVEL_TONE[summary.level] ?? "calm"), el("small", { className: "s-why", textContent: summary.level === "info" || summary.level === "none" ? "" : summary.headline })]),
    el("td", {}, talking.length
      ? el("div", { className: "s-dest" }, [
        ...talking.slice(0, 4).map(c => el("span", { className: "s-dest-item" }, [logo({ company: c }, "sm"), c])),
        talking.length > 4 ? el("span", { className: "s-muted", textContent: `+${talking.length - 4}` }) : null,
      ])
      : el("span", { className: "s-muted", textContent: "—" })),
    el("td", {}, pill(act, actTone)),
  );
  return row;
}

function agentTable(agents) {
  return el("table", { className: "s-table" }, [
    el("colgroup", {}, ["34%", "20%", "34%", "12%"].map(width => el("col", { style: `width:${width}` }))),
    el("thead", {}, el("tr", {}, ["Agent", "Risk", "Destinations", "Status"].map(h => el("th", { textContent: h })))),
    el("tbody", {}, agents.map(agentRow)),
  ]);
}

function agentsPage() {
  const running = runningAgents()
    .sort((a, b) => rankOf(a) - rankOf(b) || (b.score ?? 0) - (a.score ?? 0) || a.pid - b.pid);
  const ended = session.data.ended_agents ?? [];
  const kids = [];
  if (!running.length) {
    kids.push(el("div", { className: "s-empty" }, [
      el("div", { className: "s-empty-mark", textContent: "✓" }),
      el("h2", { textContent: "No agents running" }),
      el("p", { textContent: "Monitoring is active." }),
    ]));
  } else {
    kids.push(figures(running), el("div", { className: "s-split" }, [
      el("div", { className: "s-split-main" }, [
        el("div", { className: "s-card s-flush" }, agentTable(running)),
        programsCard(),
      ]),
      el("aside", { className: "s-split-side" }, [destinationsCard(), findingsCard(running), activityCard()]),
    ]));
  }
  if (ended.length) {
    const details = keyed("stopped", el("details", { className: "s-ended" }, [
      el("summary", { textContent: `Stopped (${ended.length})` }),
      el("div", { className: "s-card s-flush" }, agentTable(ended)),
    ]));
    kids.push(details);
  }
  return kids;
}

function sideCard(title, page, rows, link = true) {
  const more = link ? el("button", { className: "s-link", type: "button", textContent: "View all" }) : null;
  if (more) more.onclick = () => goSimple(page);
  return el("div", { className: "s-card s-side-card" }, [
    el("div", { className: "s-side-head" }, [el("h3", { textContent: title }), more]),
    ...rows,
  ]);
}

const GRADE_RANK = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };

/** One timeline event in short words, with its tone. */
export function eventLabel(event) {
  switch (event.kind) {
    case "started": return ["Started", "calm"];
    case "stopped": return ["Stopped", "quiet"];
    case "recon": return ["Network scanning", "bad"];
    case "grade_changed": {
      const [from, to] = String(event.detail ?? "").split(" to ").map(g => GRADE_RANK[g.trim()]);
      const up = event.direction ? event.direction === "escalated" : to > from;
      return up ? ["Risk raised", "warn"] : ["Risk lowered", "calm"];
    }
    default: return [String(event.kind ?? "Event").replace(/_/g, " ").replace(/^\w/, c => c.toUpperCase()), "quiet"];
  }
}

const agentByPid = (pid) => [...(session.data.agents ?? []), ...(session.data.ended_agents ?? [])].find(a => a.pid === pid);

function openAgent(pid) {
  if (!agentByPid(pid)) return;
  session.simpleAgent = pid; app.render(); window.scrollTo(0, 0);
}

function activityCard() {
  const events = [...(session.data.events ?? [])].sort((a, b) => (b.at ?? 0) - (a.at ?? 0)).slice(0, 8);
  const rows = events.map(e => {
    const [label, tone] = eventLabel(e);
    const agent = agentByPid(e.pid);
    const name = agent ? agentName(agent) : agentName({ family: e.agent });
    const row = el("div", { className: "s-side-row s-click" }, [
      logo({ family: agent?.family ?? e.agent, name }, "sm"),
      el("div", { className: "s-grow" }, [el("strong", { textContent: name }), el("small", { className: "s-muted", textContent: stamp(e.at) })]),
      pill(label, tone),
    ]);
    row.onclick = () => openAgent(e.pid);
    return row;
  });
  return sideCard("Recent activity", "agents", rows.length ? rows : [el("p", { className: "s-muted s-side-empty", textContent: "No activity yet." })], false);
}

/** Child processes grouped by program name, most runs first. */
export function programGroups(history) {
  const byName = new Map();
  for (const p of history ?? []) {
    const name = p.name || "unknown";
    const entry = byName.get(name) ?? { name, runs: [], agents: new Set(), last: 0 };
    entry.runs.push(p);
    if (p.agent_pid != null) entry.agents.add(p.agent_pid);
    entry.last = Math.max(entry.last, p.last_seen ?? p.first_seen ?? 0);
    byName.set(name, entry);
  }
  return [...byName.values()].sort((a, b) => b.runs.length - a.runs.length || b.last - a.last);
}

function programsCard() {
  const groups = programGroups(session.data.process_history);
  const shown = groups.slice(0, 12);
  if (session.simpleProgram && !groups.some(g => g.name === session.simpleProgram)) session.simpleProgram = null;
  const rows = shown.map(g => {
    const owners = [...new Set([...g.agents].map(pid => { const a = agentByPid(pid); return a ? agentName(a) : null; }).filter(Boolean))];
    const open = session.simpleProgram === g.name;
    const row = el("button", { className: `s-side-row s-click s-prog-tile${open ? " s-on" : ""}`, type: "button", ariaExpanded: String(open) }, [
      el("span", { className: "s-prog", textContent: ">_" }),
      el("div", { className: "s-grow" }, [el("strong", { className: "s-mono", textContent: g.name }), el("small", { className: "s-muted", textContent: owners.join(", ") || "—" })]),
      el("span", { className: "s-count", textContent: `${g.runs.length}×` }),
    ]);
    row.onclick = () => { session.simpleProgram = open ? null : g.name; app.render(); };
    return row;
  });
  const picked = groups.find(g => g.name === session.simpleProgram);
  return sideCard("Programs run", "agents", [
    rows.length ? el("div", { className: "s-grid-rows" }, rows) : el("p", { className: "s-muted s-side-empty", textContent: "No child processes seen." }),
    picked ? programRuns(picked) : null,
  ], false);
}

/** Every run of one program: which agent, when, and whether it is still running. */
function programRuns(group) {
  const runs = [...group.runs].sort((a, b) => (b.started_at ?? 0) - (a.started_at ?? 0)).slice(0, 25);
  const close = el("button", { className: "s-link", type: "button", textContent: "Close" });
  close.onclick = () => { session.simpleProgram = null; app.render(); };
  return el("div", { className: "s-runs" }, [
    el("div", { className: "s-side-head" }, [el("h3", { textContent: `${group.name} · ${group.runs.length} runs` }), close]),
    el("table", { className: "s-table" }, [
      el("thead", {}, el("tr", {}, ["Agent", "PID", "Started", "Status", "Path"].map(h => el("th", { textContent: h })))),
      el("tbody", {}, runs.map(p => {
        const agent = agentByPid(p.agent_pid);
        const name = agent ? agentName(agent) : "—";
        const running = p.state === "running";
        const tr = el("tr", { className: agent ? "s-row" : "" }, [
          el("td", {}, el("div", { className: "s-agent" }, [agent ? logo({ family: agent.family, name }, "sm") : null, el("span", { textContent: name })])),
          el("td", { className: "s-mono", textContent: String(p.pid) }),
          el("td", { className: "s-muted", textContent: minute(p.started_at ?? p.first_seen) }),
          el("td", {}, pill(running ? "Running" : p.exit_code != null ? `Ended · code ${p.exit_code}` : "Ended", running ? "calm" : "quiet")),
          el("td", { className: "s-mono s-muted s-path", textContent: shortPath(p.exe || p.program || p.name) }),
        ]);
        if (agent) tr.onclick = () => openAgent(agent.pid);
        return tr;
      })),
    ]),
  ]);
}

/** A path with the home folder as `~`, so the account name stays off the screen. */
export function shortPath(path) {
  return String(path ?? "").replace(/^\/(Users|home)\/[^/]+/, "~");
}

function destinationsCard() {
  const groups = companies(session.data.network);
  const rows = groups.slice(0, 6).map(g => el("div", { className: "s-side-row" }, [
    logo({ company: g.name }),
    el("div", { className: "s-grow" }, [el("strong", { textContent: g.name }), el("small", { className: "s-muted", textContent: `${g.agents.size} agent${g.agents.size === 1 ? "" : "s"}` })]),
    el("span", { className: "s-count", textContent: String(g.connections) }),
  ]));
  return sideCard("Destinations", "connections", rows.length ? rows : [el("p", { className: "s-muted s-side-empty", textContent: "No outbound connections." })]);
}

function findingsCard(running) {
  const counts = new Map();
  for (const agent of running) for (const r of agent.summary?.risks ?? []) {
    if (r.level === "info") continue;
    const c = counts.get(r.id) ?? { risk: r, n: 0 };
    c.n += 1; counts.set(r.id, c);
  }
  const rows = [...counts.values()]
    .sort((a, b) => (({ act: 0, watch: 1 })[a.risk.level] ?? 2) - (({ act: 0, watch: 1 })[b.risk.level] ?? 2) || b.n - a.n)
    .map(({ risk, n }) => el("div", { className: "s-side-row" }, [
      el("span", { className: `s-dot s-dot-${LEVEL_TONE[risk.level] ?? "calm"}` }),
      el("div", { className: "s-grow" }, [el("strong", { textContent: risk.headline }), el("small", { className: "s-muted", textContent: risk.label })]),
      el("span", { className: "s-count", textContent: String(n) }),
    ]));
  return sideCard("Findings", "risks", rows.length ? rows : [el("p", { className: "s-muted s-side-empty", textContent: "No findings." })]);
}

const rankOf = (agent) => ({ act: 0, watch: 1, info: 2, none: 3 })[agent.summary?.level] ?? 3;

function riskCard(risk, extra) {
  const card = el("div", { className: `s-risk s-risk-${LEVEL_TONE[risk.level] ?? "calm"}` }, [
    el("div", { className: "s-risk-head" }, [el("strong", { textContent: risk.headline }), pill(risk.label, LEVEL_TONE[risk.level] ?? "calm")]),
    risk.why ? el("p", { textContent: risk.why }) : null,
    risk.decision ? el("p", { className: "s-decision" }, [el("b", { textContent: "Action: " }), risk.decision]) : null,
    extra ?? null,
  ]);
  if (risk.details?.length) {
    card.append(keyed(`evidence:${risk.id}`, el("details", { className: "s-details" }, [
      el("summary", { textContent: "Evidence" }),
      el("ul", {}, risk.details.map(d => el("li", { className: "s-mono", textContent: d }))),
    ])));
  }
  return card;
}

function agentDetail(found) {
  const agent = runningAgents().find(a => a.pid === found.pid) ?? found;
  const name = agentName(agent);
  const summary = agent.summary ?? { risks: [] };
  const back = el("button", { className: "s-back", type: "button", textContent: "← Agents" });
  back.onclick = () => { session.simpleAgent = null; app.render(); };
  const stop = el("button", { className: "s-btn s-btn-bad", type: "button", textContent: "Stop agent", hidden: agent.live === false });
  stop.onclick = () => app.askStop(agent);
  const tech = el("button", { className: "s-btn", type: "button", textContent: "Advanced" });
  tech.onclick = () => { session.selected = agent.pid; setMode("technical"); view.workspace = "agents"; save(); document.dispatchEvent(new CustomEvent("topgent-view-change")); };
  const started = agent.live === false ? `Stopped · last seen ${stamp(agent.last_seen)}` : `Started ${stamp(agent.started_at)}`;
  const incidents = incidentsFor(agent.pid);
  const talking = companies(session.data.network, agent.pid);
  const attention = (summary.risks ?? []).filter(r => r.level !== "info");
  const normal = (summary.risks ?? []).filter(r => r.level === "info");

  return [
    back,
    el("div", { className: "s-detail-head" }, [
      logo({ family: agent.family, name }, "lg"),
      el("div", { className: "s-grow" }, [
        el("h2", { textContent: name }),
        el("p", { className: "s-muted", textContent: [modelsOf(agent).length > 1 ? modelsOf(agent).join(", ") : modelLine(agent), started].filter(Boolean).join(" · ") }),
      ]),
      tech, stop,
    ]),
    incidents.length ? section("Incidents", incidents.map(incidentCard)) : null,
    section("Findings", attention.length
      ? attention.map(r => riskCard(r))
      : [el("p", { className: "s-muted", textContent: "No findings." })]),
    section("Connections", talking.length
      ? [el("div", { className: "s-card s-flush" }, companyTable(talking, false))]
      : [el("p", { className: "s-muted", textContent: "No external connections." })]),
    agent.servers?.length ? section("Model server", [el("div", { className: "s-card s-flush" }, agent.servers.map(serverRow))]) : null,
    normal.length ? section("Expected access", normal.map(r => riskCard(r))) : null,
  ];
}

function serverRow(server) {
  const row = el("div", { className: "s-side-row s-click" }, [
    logo({ family: server.family, name: agentName(server) }),
    el("div", { className: "s-grow" }, [
      el("strong", { textContent: agentName(server) }),
      el("small", { className: "s-muted", textContent: [modelLine(server), `PID ${server.pid}`, `started ${stamp(server.started_at)}`].join(" · ") }),
    ]),
    pill((server.summary?.label) ?? "OK", LEVEL_TONE[server.summary?.level] ?? "calm"),
  ]);
  row.onclick = () => { session.simpleAgent = server.pid; app.render(); window.scrollTo(0, 0); };
  return row;
}

function section(title, kids) {
  return el("section", { className: "s-section" }, [el("h3", { textContent: title }), ...kids]);
}

function risksPage() {
  const byRisk = new Map();
  for (const agent of runningAgents()) {
    for (const risk of agent.summary?.risks ?? []) {
      const entry = byRisk.get(risk.id) ?? { risk, agents: [] };
      entry.agents.push(agent);
      byRisk.set(risk.id, entry);
    }
  }
  const entries = [...byRisk.values()].sort((a, b) => (({ act: 0, watch: 1, info: 2 })[a.risk.level] ?? 3) - (({ act: 0, watch: 1, info: 2 })[b.risk.level] ?? 3));
  if (!entries.length) return [el("div", { className: "s-empty" }, [el("div", { className: "s-empty-mark", textContent: "✓" }), el("h2", { textContent: "No risks" }), el("p", { textContent: "No running agent has findings." })])];
  return entries.map(({ risk, agents }) => {
    const who = el("div", { className: "s-chips" }, agents.map(a => {
      const chip = el("button", { className: "s-chip", type: "button", textContent: `${agentName(a)} · ${a.pid}` });
      chip.onclick = () => { session.simpleAgent = a.pid; goSimple("agents"); };
      return chip;
    }));
    const shown = { ...risk, details: [] };
    return riskCard(shown, who);
  });
}

function companyTable(groups, withAgents = true) {
  // Sent is shown only where the platform measured it; a column of "not
  // measured" says nothing a person can act on.
  const measured = groups.some(g => g.sentKnown);
  const head = ["Owner", "Country", ...(withAgents ? ["Agents"] : []), "Connections", ...(measured ? ["Sent"] : []), "Last seen"];
  return el("table", { className: "s-table" }, [
    el("thead", {}, el("tr", {}, head.map(h => el("th", { textContent: h })))),
    el("tbody", {}, groups.map(g => el("tr", {}, [
      el("td", {}, el("div", { className: "s-agent" }, [logo({ company: g.name }), el("strong", { textContent: g.name })])),
      el("td", { className: "s-muted", textContent: g.country && g.country !== "unknown" ? g.country : "—" }),
      ...(withAgents ? [el("td", { className: "s-muted", textContent: [...g.agents].map(pid => agentName((session.data.agents ?? []).find(a => a.pid === pid) ?? (session.data.ended_agents ?? []).find(a => a.pid === pid))).filter((v, i, all) => all.indexOf(v) === i).join(", ") || "—" })] : []),
      el("td", { textContent: String(g.connections) }),
      measured ? el("td", { className: "s-muted", textContent: g.sentKnown ? bytes(g.sent) : "not measured" }) : null,
      el("td", { className: "s-muted", textContent: g.last ? minute(g.last) : "—" }),
    ]))),
  ]);
}

function connectionsPage() {
  const groups = companies(session.data.network);
  if (!groups.length) return [el("div", { className: "s-empty" }, [el("div", { className: "s-empty-mark", textContent: "✓" }), el("h2", { textContent: "No external connections" }), el("p", { textContent: "Outbound agent traffic appears here." })])];
  return [
    el("div", { className: "s-card s-flush" }, companyTable(groups)),
  ];
}

/** One line of an incident's impact or action list, whatever shape it came in. */
export function incidentText(item) {
  if (typeof item === "string") return item;
  return item?.label ?? item?.text ?? item?.title ?? "";
}

/** The tools an incident names, from its own field or its evidence. */
export function incidentTools(inc) {
  const named = inc.tools ?? (inc.evidence?.findings ?? []).map(f => f.summary).filter(Boolean);
  return [...new Set(named)];
}

/** Open the advanced view on an agent, and on one of its processes when given. */
function openAdvanced(agentPid, processPid) {
  session.selected = agentPid;
  session.focusProcess = processPid ?? null;
  view.workspace = "agents";
  view.agentTab = processPid != null ? "processes" : "overview";
  setMode("technical");
  save();
  applyPanelLayout();
  document.dispatchEvent(new CustomEvent("topgent-view-change"));
}

function incidentCard(inc) {
  const severity = String(inc.severity ?? "high").toLowerCase();
  const tone = severity === "critical" ? "bad" : "warn";
  const pid = inc.agent?.pid ?? inc.agent_pid;
  const agent = pid != null ? agentByPid(pid) : null;
  const who = agent ? agentName(agent) : (inc.agent?.name ?? "An agent");
  const tools = incidentTools(inc);
  const verb = inc.kind === "offensive_tool" ? "ran" : null;
  const list = (items) => el("ul", {}, items.map(t => el("li", { textContent: incidentText(t) })));
  const meta = [
    inc.first_seen ? stamp(inc.first_seen) : null,
    inc.numbers?.duration ? `lasted ${inc.numbers.duration}` : null,
    inc.process_pid != null ? `PID ${inc.process_pid}` : null,
  ].filter(Boolean).join(" · ");
  const buttons = [];
  if (pid != null) {
    const open = el("button", { className: "s-btn", type: "button", textContent: "Open agent" });
    open.onclick = () => { session.simpleAgent = pid; goSimple("agents"); };
    const advanced = el("button", { className: "s-btn", type: "button", textContent: inc.process_pid != null ? "Show process" : "Advanced" });
    advanced.onclick = () => openAdvanced(pid, inc.process_pid);
    buttons.push(open, advanced);
  }
  return el("article", { className: `s-inc s-inc-${tone}` }, [
    el("header", { className: "s-inc-head" }, [
      el("span", { className: `s-inc-kind s-inc-kind-${tone}`, textContent: inc.name || "Incident" }),
      el("span", { className: "s-muted s-inc-meta", textContent: meta }),
      pill(severity === "critical" ? "Critical" : "High", tone),
    ]),
    el("div", { className: "s-inc-what" }, [
      agent ? logo({ family: agent.family, name: who }) : null,
      el("div", { className: "s-inc-line" }, verb && tools.length
        ? [el("strong", { textContent: who }), ` ${verb} `, ...tools.flatMap((t, i) => [i ? " " : "", el("code", { className: "s-tool", textContent: t })])]
        : [el("span", { textContent: inc.headline ?? inc.summary ?? inc.what ?? "" })]),
    ]),
    el("div", { className: "s-inc-cols" }, [
      inc.why?.length ? el("div", {}, [el("h4", { textContent: "Impact" }), list([].concat(inc.why))]) : null,
      inc.actions?.length ? el("div", {}, [el("h4", { textContent: "Action" }), list([].concat(inc.actions))]) : null,
    ]),
    buttons.length ? el("footer", { className: "s-actions s-inc-foot" }, buttons) : null,
  ]);
}

function incidentsPage() {
  const incidents = session.data.incidents ?? [];
  if (!incidents.length) return [el("div", { className: "s-empty" }, [el("div", { className: "s-empty-mark", textContent: "✓" }), el("h2", { textContent: "No incidents" }), el("p", { textContent: "Monitoring is active." })])];
  return incidents.map(incidentCard);
}

function reportsPage() {
  const summary = session.data.aibom ?? {};
  const html = el("button", { className: "s-btn s-btn-primary", type: "button", textContent: "Export HTML" });
  html.onclick = () => $("exportAibomHtml")?.click();
  const json = el("button", { className: "s-btn", type: "button", textContent: "Export JSON (CycloneDX)" });
  json.onclick = () => $("exportAibomJson")?.click();
  return [
    el("div", { className: "s-card s-pad" }, [
      el("h3", { textContent: "AI-BOM" }),
      el("p", { className: "s-muted", textContent: `Inventory of agents, models, connectors and services. ${summary.component_count ?? 0} components, ${summary.service_count ?? 0} services.` }),
      el("div", { className: "s-actions" }, [html, json]),
    ]),
  ];
}

// ---- shell ----

export function setMode(mode) {
  view.mode = mode;
  save();
  applyMode();
}

export function applyMode() {
  const simple = view.mode !== "technical";
  $("simple").hidden = !simple;
  $("technical").hidden = simple;
}

function goSimple(page) {
  view.simplePage = page;
  if (page !== "agents") session.simpleAgent = null;
  save();
  app.render();
  window.scrollTo(0, 0);
}

function nav() {
  const incidents = (session.data?.incidents ?? []).length;
  const host = $("simpleNav");
  host.replaceChildren(...PAGES.map(([id, label]) => {
    const b = el("button", { className: "s-nav-item", type: "button" }, [el("i"), el("span", { textContent: label })]);
    b.setAttribute("aria-current", String(view.simplePage === id));
    if (id === "incidents" && incidents) b.append(el("b", { className: "s-badge", textContent: String(incidents) }));
    b.onclick = () => { session.simpleAgent = null; goSimple(id); };
    return b;
  }));
}

const TITLES = {
  agents: "Agents",
  risks: "Risks",
  connections: "Connections",
  incidents: "Incidents",
  reports: "Reports",
};

/** Tag a collapsible section so its open state survives a refresh. */
function keyed(key, node) { node.dataset.key = key; return node; }

// The page is rebuilt on every refresh, which closed any section a person had
// opened a moment earlier. Open sections are remembered per page and reopened.
const openSections = new Set();

/** Reopen remembered sections under `root` and remember new toggles. */
export function keepOpen(root, scope) {
  for (const details of root.querySelectorAll("details[data-key]")) {
    const key = `${scope}|${details.dataset.key}`;
    if (openSections.has(key)) details.open = true;
    details.addEventListener("toggle", () => {
      if (details.open) openSections.add(key); else openSections.delete(key);
    });
  }
}

export function renderSimple() {
  if (!PAGES.some(([id]) => id === view.simplePage)) view.simplePage = "agents";
  applyMode();
  if (!session.data) return;
  nav();
  const live = !session.paused;
  $("simpleLive").replaceChildren(el("i"), live ? "Live" : "Paused");
  $("simpleLive").classList.toggle("paused", !live);
  const agent = session.simpleAgent != null
    ? [...(session.data.agents ?? []), ...(session.data.ended_agents ?? [])].find(a => a.pid === session.simpleAgent)
    : null;
  if (session.simpleAgent != null && !agent) session.simpleAgent = null;
  $("simpleTitle").textContent = agent ? "Agent" : TITLES[view.simplePage];
  $("simpleTitle").hidden = Boolean(agent);
  const page = agent ? agentDetail(agent)
    : view.simplePage === "risks" ? risksPage()
    : view.simplePage === "connections" ? connectionsPage()
    : view.simplePage === "incidents" ? incidentsPage()
    : view.simplePage === "reports" ? reportsPage()
    : agentsPage();
  const nodes = page.filter(Boolean);
  const scope = agent ? `agent:${agent.pid}` : `page:${view.simplePage}`;
  const body = $("simpleBody");
  // Rebuild only when the page would look different. A refresh arrives every
  // second or two, and replacing identical content closed open sections, lost
  // a click that landed mid-rebuild, and wiped any text being selected.
  const print = scope + "\n" + nodes.map(n => n.outerHTML ?? String(n.textContent)).join("");
  if (print === lastPrint) return;
  if (selecting(body)) return;
  lastPrint = print;
  body.replaceChildren(...nodes);
  keepOpen(body, scope);
}

let lastPrint = null;

/** Whether the person is selecting text in `root`; a rebuild would drop it. */
function selecting(root) {
  const sel = typeof window.getSelection === "function" ? window.getSelection() : null;
  return Boolean(sel && !sel.isCollapsed && sel.anchorNode && root.contains(sel.anchorNode));
}

export function wireSimple() {
  document.addEventListener("topgent-open-agent", (e) => {
    session.simpleAgent = e.detail;
    setMode("simple");
    view.simplePage = "agents";
    app.render();
    window.scrollTo(0, 0);
  });
  $("simpleTechnical").onclick = () => { setMode("technical"); app.render(); };
  $("simpleBack").onclick = () => { setMode("simple"); app.render(); };
}
