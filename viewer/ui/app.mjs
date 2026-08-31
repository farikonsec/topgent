// The application: wiring, the poll loop, and startup.
//
// Everything that makes the page a running program rather than a set of
// drawing functions. The panels know nothing about polling and the poll loop
// knows nothing about panels; they meet here and in `app-hooks.mjs`.
//
// Nothing worth testing lives in this file. The alert rules are in
// `alerts.mjs`, where they run without a browser.

import { $, el } from "./dom.mjs";
import { app } from "./app-hooks.mjs";
import { invoke, inDesktopApp } from "./transport.mjs";
import {
  resetView,
  PANEL_VIEWS,
  applyPanelLayout,
  applyTheme,
  checkAlarms,
  renderViewNav,
  save,
  session,
  setPanelOpen,
  toast,
  view,
} from "./state.mjs";
import { render } from "./render.mjs";
import { renderAgents } from "./panels/agents.mjs";
import { renderAssets } from "./panels/assets.mjs";
import { renderEvents } from "./panels/events.mjs";
import { renderNetwork } from "./panels/network.mjs";
import { askStop, wireResponse } from "./respond.mjs";
import { wireOverlays } from "./overlays.mjs";

function downloadExport(contents, type, suffix) {
  const blob = new Blob([contents], { type });
  const url = URL.createObjectURL(blob);
  const link = el("a", { href:url, download:`topgent-aibom-${Date.now()}.${suffix}` });
  document.body.append(link); link.click(); link.remove(); URL.revokeObjectURL(url);
}

function syncControls() {
  $("agentSearch").value = view.agentQuery; $("eventSearch").value = view.eventQuery; $("eventKind").value = view.eventKind;
  $("networkSearch").value = view.networkQuery; $("networkDirection").value = view.networkDirection;
  $("assetSearch").value = view.assetQuery; $("assetKind").value = view.assetKind;
  document.querySelectorAll(".fchip[data-risk]").forEach(c => c.setAttribute("aria-pressed", String(c.dataset.risk === view.riskFilter)));
}

async function poll(force = false) {
  const selectOpen = document.activeElement?.matches?.("select");
  const overlayOpen = !$("legendScrim").hidden || !$("ciScrim").hidden;
  if (!force && (session.paused || session.pending || selectOpen || overlayOpen)) return;
  // A sweep already running is never joined by a second one. A slow host would
  // otherwise stack them until it ran out of memory.
  if (session.sweeping) return;
  if (!inDesktopApp && !location.protocol.startsWith("http")) { $("beat").classList.add("stale"); $("host").textContent = "open Topgent.app to run this"; return; }
  session.sweeping = true;
  try {
    session.data = await invoke("scan");
    if (!session.data.agents.some(a => a.pid === session.selected)) session.selected = [...session.data.agents].sort((x,y)=>y.score-x.score)[0]?.pid ?? null;
    if (session.expanded != null && !session.data.agents.some(a => a.pid === session.expanded)) session.expanded = null;
    $("meta").textContent = `${session.data.agents.length} agents detected · ${session.data.fact_count} evidence points · topgent ${session.data.version}`;
    $("beat").classList.remove("stale"); if (!session.paused) $("host").textContent = "Live";
    const alarmed = checkAlarms();
    render();
    for (const pid of alarmed) { const tr = document.querySelector(`#agentsBody tbody tr.agent[data-pid="${pid}"]`); if (tr) tr.classList.add("alarm"); }
  } catch (e) { $("beat").classList.add("stale"); $("host").textContent = "collector unreachable"; console.error(e); }
  finally { session.sweeping = false; }
}

/** Attach the header and panel controls. Called once at startup. */
function wireControls() {
  $("pause").onclick = () => { session.paused = !session.paused; $("pause").textContent = session.paused ? "Resume" : "Pause"; $("beat").classList.toggle("stale", session.paused); $("host").textContent = session.paused ? "Paused" : "Live"; if (!session.paused) poll(); };
  $("reset").onclick = () => { resetView(); document.querySelectorAll(".resizable").forEach(n => n.style.height = ""); syncControls(); applyPanelLayout(); render(); };
  $("openAllViews").onclick = () => { view.openPanels = PANEL_VIEWS.map(([id]) => id); save(); applyPanelLayout(); };
  $("closeAllViews").onclick = () => { view.openPanels = []; save(); applyPanelLayout(); $("panel-agents").scrollIntoView({behavior:"smooth",block:"start"}); };
  $("agentSearch").oninput = (e) => { view.agentQuery = e.target.value; save(); renderAgents(); };
  $("eventSearch").oninput = (e) => { view.eventQuery = e.target.value; save(); renderEvents(); };
  $("eventKind").onchange = (e) => { view.eventKind = e.target.value; save(); renderEvents(); };
  $("networkSearch").oninput = (e) => { view.networkQuery = e.target.value; save(); renderNetwork(); };
  $("networkDirection").onchange = (e) => { view.networkDirection = e.target.value; save(); renderNetwork(); };
  $("assetSearch").oninput = (e) => { view.assetQuery = e.target.value; save(); renderAssets(); };
  $("assetKind").onchange = (e) => { view.assetKind = e.target.value; save(); renderAssets(); };
  $("exportAibomJson").onclick = async () => {
    try {
      const bom = await invoke("export_cyclonedx", {});
      if (bom.error) throw new Error(bom.error);
      downloadExport(JSON.stringify(bom, null, 2) + "\n", "application/vnd.cyclonedx+json", "cdx.json");
      const summary = session.data.aibom ?? {};
      toast(`Exported machine-readable JSON · ${summary.component_count ?? 0} components · ${summary.service_count ?? 0} services`);
    } catch (error) { toast(`Export failed: ${error}`); }
  };
  $("exportAibomHtml").onclick = async () => {
    try {
      const html = await invoke("export_aibom_html", {});
      downloadExport(html, "text/html;charset=utf-8", "html");
      const summary = session.data.aibom ?? {};
      toast(`Exported human-readable AI-BOM · ${summary.component_count ?? 0} components · ${summary.service_count ?? 0} services`);
    } catch (error) { toast(`Export failed: ${error}`); }
  };
  $("contextToggle").onclick = async () => { const enabled = !(session.data.context?.enabled); const result = await invoke("set_semantic_enabled", { enabled }); toast(result.message ?? (enabled ? "Optional context enabled" : "Optional context disabled")); await poll(); };
  $("contextClear").onclick = async () => { if (!confirm("Delete every locally retained semantic context record?")) return; const result = await invoke("clear_semantic_context", {}); toast(result.message ?? "Retained context deleted"); await poll(); };
  $("networkBaselineReset").onclick = async () => {
    const agent = session.data.agents.find(item => item.pid === session.selected);
    if (!agent) return;
    if (!confirm(`Reset the network baseline for ${agent.family ?? "this agent"} (pid ${agent.pid})?\n\nOnly history for this exact PID and start time will be removed. Current endpoints will become the first sample of a fresh collecting baseline.`)) return;
    const result = await invoke("reset_network_baseline", { pid:agent.pid, startedAt:agent.started_at });
    toast(result.message ?? (result.ok ? "Baseline reset" : "Baseline reset refused"));
    await poll(true);
  };
  document.querySelectorAll(".fchip[data-risk]").forEach(chip => chip.onclick = () => {
    view.riskFilter = chip.dataset.risk; save();
    document.querySelectorAll(".fchip[data-risk]").forEach(c => c.setAttribute("aria-pressed", String(c === chip)));
    renderAgents();
  });
}

// ---- startup ----

app.render = render;
app.poll = poll;
app.askStop = askStop;

wireOverlays();
wireResponse();
wireControls();

syncControls();
applyPanelLayout();
applyTheme();
$("soundBtn").textContent = session.alertsOn ? "🔔 On" : "🔕 Off";
if (session.alertsOn && "Notification" in window && Notification.permission === "default") Notification.requestPermission();
poll();
setInterval(poll, 1500);
