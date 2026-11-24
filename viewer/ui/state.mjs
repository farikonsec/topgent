// What the operator has chosen, and what the interface currently knows.
//
// Two kinds of state, kept apart on purpose. The view is preference — sort
// order, filters, which panels are open — and is persisted per browser so a
// reload does not undo someone's layout. The session is the current scan and
// what has been clicked, and is deliberately not persisted: a stale row in a
// security tool is a wrong answer, so the interface starts from nothing and
// renders whatever the next report says.

import { $, el } from "./dom.mjs";
import { agentName } from "./names.mjs";
import {
  eventLabel,
  isAlarming,
  recordNotified,
  shouldAnnounce,
  withinCooldown,
} from "./alerts.mjs";

// ---- the operator's preferences ----

export const DEFAULTS = {
  agentSort:{col:"score",dir:-1}, accessSort:{col:"path",dir:1}, eventSort:{col:"at",dir:-1}, activitySort:{col:"at",dir:1}, networkSort:{col:"last_seen",dir:-1}, coverageSort:{col:"state",dir:1}, assetSort:{col:"kind",dir:1},
  riskFilter:"all", agentQuery:"", eventKind:"all", eventQuery:"", networkDirection:"all", networkQuery:"", assetKind:"all", assetQuery:"", workspace:"incidents", agentTab:"overview", density:"normal", theme:"light", refreshMs:1500, widths:{}, mode:"simple", simplePage:"agents"
};
export const WORKSPACES = [
  ["incidents", "Incidents", "Open incidents.", "observe"],
  ["agents", "Agents", "Running and stopped agents.", "observe"],
  ["network", "Network", "Connections and listeners.", "observe"],
  ["events", "Event log", "Security events, newest first.", "observe"],
  ["behaviour", "Behaviour", "Runtime rule matches.", "observe"],
  ["assets", "Assets", "AI assets and approval status.", "manage"],
  ["response", "Rules & response", "Detection rules and response actions.", "manage"],
  ["context", "Session context", "Agent-reported session data. Unverified.", "manage"],
  ["health", "Coverage", "Sensor status and coverage.", "manage"],
  ["settings", "Settings", "Theme, density, refresh, alerts.", "manage"],
];
export const AGENT_TABS = [
  ["overview", "Overview"], ["access", "Access"], ["blast", "Blast radius"],
  ["activity", "Activity"], ["network", "Network"], ["processes", "Processes"],
  ["actions", "Actions"], ["files", "Files"], ["behaviour", "Behaviour"],
];
export const view = load();
function load() {
  try {
    const saved = JSON.parse(localStorage.getItem("topgent.view") || "{}");
    return {
      ...DEFAULTS, ...saved,
      agentSort:saved.agentSort ?? DEFAULTS.agentSort,
      accessSort:saved.accessSort ?? DEFAULTS.accessSort,
      eventSort:saved.eventSort ?? DEFAULTS.eventSort,
      activitySort:saved.activitySort ?? DEFAULTS.activitySort,
      networkSort:saved.networkSort ?? DEFAULTS.networkSort,
      coverageSort:saved.coverageSort ?? DEFAULTS.coverageSort,
      assetSort:saved.assetSort ?? DEFAULTS.assetSort,
      theme:["dark","light","high-contrast"].includes(saved.theme) ? saved.theme : DEFAULTS.theme,
      workspace:WORKSPACES.some(([id]) => id === saved.workspace) ? saved.workspace : DEFAULTS.workspace,
      agentTab:AGENT_TABS.some(([id]) => id === saved.agentTab) ? saved.agentTab : DEFAULTS.agentTab,
    };
  } catch { return { ...DEFAULTS }; }
}
/** Put every preference back to its default, in place.
 *
 * In place because `view` is imported by every panel, and replacing the object
 * would leave each of them holding the old one.
 */
export function resetView() {
  for (const key of Object.keys(view)) delete view[key];
  Object.assign(view, structuredClone(DEFAULTS), { widths: {} });
  save();
}

export function save() { try { localStorage.setItem("topgent.view", JSON.stringify(view)); } catch {} }

export function applyPanelLayout() {
  document.querySelectorAll("[data-workspace-page]").forEach(page => page.hidden = page.dataset.workspacePage !== view.workspace);
  document.querySelectorAll("[data-agent-tab]").forEach(panel => panel.hidden = panel.dataset.agentTab !== view.agentTab);
  const current = WORKSPACES.find(([id]) => id === view.workspace) ?? WORKSPACES[0];
  $("workspaceTitle").textContent = current[1];
  $("workspaceDescription").textContent = current[2];
  renderViewNav();
}

/** Open a workspace, as a sidebar link or a metric does. */
export function go(workspace) { choose("workspace", workspace); }

function choose(kind, id) {
  view[kind] = id;
  save();
  applyPanelLayout();
  document.dispatchEvent(new CustomEvent("topgent-view-change"));
}

export function renderViewNav() {
  for (const section of ["observe", "manage"]) {
    const host = $(section+"Nav"); host.replaceChildren();
    for (const [id, label, description, group] of WORKSPACES.filter(item => item[3] === section)) {
      const active = id === view.workspace;
      const button = el("button", { className:"view-link", ariaPressed:String(active), title:description }, [
        el("span", { textContent:label }), el("span", { className:"view-state", textContent:workspaceTally(id) })
      ]);
      button.onclick = () => choose("workspace", id);
      host.append(button);
    }
  }
  const mobile = $("mobileWorkspace");
  mobile.replaceChildren(...WORKSPACES.map(([id, label]) => el("option", {
    value:id, textContent:label, selected:id === view.workspace,
  })));
  mobile.onchange = () => choose("workspace", mobile.value);
  const tabs = $("agentTabs"); tabs.replaceChildren();
  for (const [id, label] of AGENT_TABS) {
    const button = el("button", { className:"agent-tab", ariaPressed:String(id === view.agentTab), textContent:label });
    button.onclick = () => choose("agentTab", id);
    tabs.append(button);
  }
}

function workspaceTally(id) {
  const report = session.data;
  if (!report) return "";
  if (id === "incidents") return String(report.incidents?.length ?? 0);
  if (id === "agents") return String(report.agents?.length ?? 0);
  if (id === "network") return String(report.network?.length ?? 0);
  if (id === "events") return String(report.events?.length ?? 0);
  if (id === "behaviour") return String(report.behaviour?.findings?.length ?? 0);
  if (id === "assets") return String(report.assets?.length ?? 0);
  if (id === "response") return String(report.watchlist?.length ?? 0);
  if (id === "context") return report.context?.enabled ? String(report.context?.records?.length ?? 0) : "Off";
  if (id === "health") return `${(report.coverage ?? []).filter(row => row.state === "available").length}/${report.coverage?.length ?? 0}`;
  return "";
}

// ---- what the interface knows right now ----

/** Everything the interface knows right now.
 *
 * One object rather than a set of module-level bindings, because a binding
 * exported from a module is read-only to whoever imports it, and half of this
 * state is written by one panel and read by another. Nothing here survives a
 * reload: it is the current scan and what the operator has clicked, not
 * evidence. Evidence lives in the journal.
 */
export const session = {
  /** The most recent report, or null before the first one arrives. */
  data: null,
  /** Pid of the expanded agent row, if any. */
  selected: null,
  /** Pid whose detail block is open, if any. */
  expanded: null,
  /** Whether polling is suspended. */
  paused: false,
  /** The stop awaiting confirmation, if any. */
  pending: null,
  /** True while a sweep is in flight. Guards against overlapping sweeps.
   *
   * Not the same as `pending`, which is the open confirmation dialog. Until
   * the desktop command became async, Tauri ran it on the main thread and
   * serialised sweeps by blocking; nothing needed a guard. Moving the sweep
   * off that thread removed the accidental serialisation, and on Windows,
   * where a sweep takes seconds, PowerShell processes then accumulated: four
   * after four seconds, eight after twenty. */
  sweeping: false,
  /** Event ids the operator has expanded. */
  /** Event ids already seen, so an alarm fires once. */
  seenEvents: new Set(),
  /** False until the first scan lands; the first load never alarms. */
  primed: false,
  /** Whether outbound alerts are delivered at all. */
  alertsOn: (localStorage.getItem("topgent.sound") ?? "1") === "1",
};

// One switch over every outbound alert: sound, in-app toast and OS
// notification. It deliberately does not touch the event log, the row
// highlight or the response queue, which are retained evidence.
export function beep() {
  if (!session.alertsOn) return;
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const o = ctx.createOscillator(), g = ctx.createGain();
    o.connect(g); g.connect(ctx.destination); o.type = "square"; o.frequency.value = 880;
    g.gain.setValueAtTime(0.0001, ctx.currentTime);
    g.gain.exponentialRampToValueAtTime(0.2, ctx.currentTime + 0.01);
    g.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.5);
    o.start(); o.stop(ctx.currentTime + 0.5);
    setTimeout(() => { const o2=ctx.createOscillator(),g2=ctx.createGain(); o2.connect(g2); g2.connect(ctx.destination); o2.type="square"; o2.frequency.value=1180; g2.gain.setValueAtTime(0.0001,ctx.currentTime); g2.gain.exponentialRampToValueAtTime(0.2,ctx.currentTime+0.01); g2.gain.exponentialRampToValueAtTime(0.0001,ctx.currentTime+0.5); o2.start(); o2.stop(ctx.currentTime+0.5); }, 260);
  } catch {}
}
export function notify(title, body) {
  try {
    if (window.__TAURI__?.notification) { window.__TAURI__.notification.sendNotification({ title, body }); return; }
    if ("Notification" in window && Notification.permission === "granted") new Notification(title, { body });
  } catch {}
}

export function checkAlarms(now = Date.now()) {
  const events = session.data.events ?? [];
  const fresh = [];
  for (const e of events) {
    const key = e.id ?? `${e.at}:${e.kind}:${e.pid}`;
    if (!session.seenEvents.has(key)) { session.seenEvents.add(key); fresh.push(e); }
  }
  if (!session.primed) { session.primed = true; return []; } // do not alarm on the first load
  const alarms = fresh.filter(isAlarming);
  const announce = alarms.filter(e => !withinCooldown(e, now));
  for (const e of announce) recordNotified(e, now);
  if (shouldAnnounce(announce, session.alertsOn)) {
    beep();
    const top = announce[0];
    const title = eventLabel(top);
    const name = agentName({ family: top.agent });
    const more = announce.length > 1 ? ` +${announce.length - 1}` : "";
    toast(`${title} · ${name}${more}`, { tone: "bad", action: "Review", onAction: () => document.dispatchEvent(new CustomEvent("topgent-open-agent", { detail: top.pid })) });
    notify(`Topgent: ${title}`, `${name}, PID ${top.pid}.`);
  }
  // Rows still highlight while alerts are off: suppressing delivery must not
  // suppress the finding.
  return alarms.map(a => a.pid);
}

export function toast(msg, { tone, action, onAction } = {}) {
  document.querySelectorAll(".toast").forEach(n => n.remove());
  const n = el("div", { className: tone ? `toast toast-${tone}` : "toast", role: "status" }, [el("span", { textContent: msg })]);
  if (action && onAction) {
    const b = el("button", { className: "toast-action", type: "button", textContent: action });
    b.onclick = () => { n.remove(); onAction(); };
    n.append(b);
  }
  document.body.append(n);
  setTimeout(() => n.remove(), action ? 8000 : 4500);
}

/** An agent by pid: a running one, else one that ended this session (the
 *  report's `ended_agents`), as the desktop's `Report::find_agent`. */
export function findAgent(pid) {
  if (pid == null || !session.data) return undefined;
  return (session.data.agents ?? []).find(a => a.pid === pid)
    ?? (session.data.ended_agents ?? []).find(a => a.pid === pid);
}

/** Local time as the desktop's clock::stamp shows it: HH:MM:SS today, the
 *  day and minute otherwise, so an old row cannot pass as recent. */
export function stamp(ms) {
  if (!ms) return "—";
  const d = new Date(ms), now = new Date();
  const two = n => String(n).padStart(2, "0");
  return d.toDateString() === now.toDateString()
    ? `${two(d.getHours())}:${two(d.getMinutes())}:${two(d.getSeconds())}`
    : `${two(d.getDate())}/${two(d.getMonth()+1)} ${two(d.getHours())}:${two(d.getMinutes())}`;
}

/** A model's name without its route, as the desktop's `short_model`:
 *  `openrouter/z-ai/glm-4.7-flash` is `glm-4.7-flash`. */
export function shortModel(model) {
  return String(model ?? "").split("/").pop().trim();
}

/** An agent and the model it runs on, as a column names it: `opencode ·
 *  glm-4.7-flash`, or the family alone when no model was read. */
export function agentWithModel(agent) {
  const name = agent.family || "unrecognised";
  const model = shortModel(agent.model);
  return model ? `${name} · ${model}` : name;
}

/** What a row that names an agent by family calls it: the run (its pid,
 *  and its start when the row knows it) with its model when this report has
 *  it, else the family the row gave. As the desktop's `Report::run_name`. */
export function runName(pid, startedAt, family) {
  const run = [...(session.data?.agents ?? []), ...(session.data?.ended_agents ?? [])]
    .find(a => a.pid === pid && (startedAt == null || a.started_at === startedAt));
  return run ? agentWithModel(run) : (family || "agent");
}
