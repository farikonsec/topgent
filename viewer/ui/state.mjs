// What the operator has chosen, and what the interface currently knows.
//
// Two kinds of state, kept apart on purpose. The view is preference — sort
// order, filters, which panels are open — and is persisted per browser so a
// reload does not undo someone's layout. The session is the current scan and
// what has been clicked, and is deliberately not persisted: a stale row in a
// security tool is a wrong answer, so the interface starts from nothing and
// renders whatever the next report says.

import { $, el } from "./dom.mjs";
import {
  isAlarming,
  recordNotified,
  shouldAnnounce,
  withinCooldown,
} from "./alerts.mjs";

// ---- the operator's preferences ----

export const DEFAULTS = {
  agentSort:{col:"score",dir:-1}, accessSort:{col:"path",dir:1}, eventSort:{col:"at",dir:-1}, activitySort:{col:"at",dir:1}, networkSort:{col:"last_seen",dir:-1}, coverageSort:{col:"state",dir:1}, assetSort:{col:"kind",dir:1},
  riskFilter:"all", agentQuery:"", eventKind:"all", eventQuery:"", networkDirection:"all", networkQuery:"", assetKind:"all", assetQuery:"", openPanels:[], widths:{}
};
export const PANEL_VIEWS = [
  ["risk","Risk explanation"], ["blast","Blast radius"], ["access","Access"],
  ["events","Event log"], ["activity","Activity path"], ["network","Network activity"],
  ["health","Sensor health"], ["response","Response & governance"],
  ["context","Session context"], ["assets","Agents & assets"],
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
      openPanels:Array.isArray(saved.openPanels) ? saved.openPanels.filter(id => PANEL_VIEWS.some(([known]) => known === id)) : [],
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
  Object.assign(view, structuredClone(DEFAULTS), { openPanels: [], widths: {} });
  save();
}

export function save() { try { localStorage.setItem("topgent.view", JSON.stringify(view)); } catch {} }

export function applyPanelLayout(scrollTo) {
  const open = new Set(view.openPanels ?? []);
  for (const [id] of PANEL_VIEWS) $("panel-"+id).hidden = !open.has(id);
  document.querySelectorAll("[data-panel-group]").forEach(group => {
    const count = [...group.querySelectorAll(":scope > .panel")].filter(panel => !panel.hidden).length;
    group.hidden = count === 0;
    group.dataset.openCount = String(count);
  });
  renderViewNav();
  if (scrollTo && open.has(scrollTo)) requestAnimationFrame(() => $("panel-"+scrollTo)?.scrollIntoView({behavior:"smooth",block:"start"}));
}

export function setPanelOpen(id, shouldOpen, scroll = false) {
  const open = new Set(view.openPanels ?? []);
  if (shouldOpen) open.add(id); else open.delete(id);
  view.openPanels = PANEL_VIEWS.map(([known]) => known).filter(known => open.has(known));
  save(); applyPanelLayout(scroll ? id : null);
}

export function renderViewNav() {
  const host = $("viewNav"); host.replaceChildren();
  host.append(el("button", { className:"view-link", disabled:true, ariaPressed:"true", title:"The primary Agents table is always visible" }, [
    el("span", { className:"view-index", textContent:"00" }), el("span", { textContent:"Agents" }), el("span", { className:"view-state", textContent:"always" })
  ]));
  const open = new Set(view.openPanels ?? []);
  PANEL_VIEWS.forEach(([id,label], index) => {
    const active = open.has(id);
    const button = el("button", { className:"view-link", ariaPressed:String(active), title:`${active?"Close":"Open"} ${label}` }, [
      el("span", { className:"view-index", textContent:String(index+1).padStart(2,"0") }),
      el("span", { textContent:label }), el("span", { className:"view-state", textContent:active?"open":"" })
    ]);
    button.onclick = () => setPanelOpen(id, !active, !active);
    host.append(button);
  });
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
  expandedEvents: new Set(),
  /** Event ids already seen, so an alarm fires once. */
  seenEvents: new Set(),
  /** False until the first scan lands; the first load never alarms. */
  primed: false,
  /** Whether outbound alerts are delivered at all. */
  alertsOn: (localStorage.getItem("topgent.sound") ?? "1") === "1",
  /** The chosen colour scheme. */
  theme: localStorage.getItem("topgent.theme") === "light" ? "light" : "dark",
};

// One switch over every outbound alert: sound, in-app toast and OS
// notification. It deliberately does not touch the event log, the row
// highlight or the response queue, which are retained evidence.
export function applyTheme() {
  document.documentElement.dataset.theme = session.theme;
  const light = session.theme === "light";
  $("themeBtn").setAttribute("aria-pressed", String(light));
  $("themeBtn").textContent = light ? "☾ Dark mode" : "☀ Bright mode";
}
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
    const label = top.kind === "recon" ? "Scanning detected" : top.kind === "credential_exposed" ? "Credential exposed" : top.kind === "behaviour" ? "Rogue behaviour" : top.kind === "model_drift" ? "Model drift" : "Risk escalated";
    toast(`⚠ ${label}: ${top.agent} (pid ${top.pid})`);
    notify(`Topgent — ${label}`, `${top.agent} (pid ${top.pid}) — ${top.detail}`);
  }
  // Rows still highlight while alerts are off: suppressing delivery must not
  // suppress the finding.
  return alarms.map(a => a.pid);
}

export function toast(msg) { document.querySelectorAll(".toast").forEach(n=>n.remove()); const n=el("div",{className:"toast",textContent:msg}); document.body.append(n); setTimeout(()=>n.remove(),4500); }
