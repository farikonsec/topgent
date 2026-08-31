// The two things that sit on top of the page: the legend and the watchlist.
//
// Both are read-mostly. The watchlist is the one place the operator states
// something about their own estate, and a rule they wrote is reported as a
// match rather than softened into a probability.

import { $, el } from "./dom.mjs";
import { invoke } from "./transport.mjs";
import { app } from "./app-hooks.mjs";
import { applyTheme, session, toast } from "./state.mjs";

export function renderLegend() {
  const host = $("legendList"); host.textContent = "";
  for (const item of (session.data.legend ?? [])) {
    const row = el("div", { className: "legend-row" });
    row.append(el("b", { textContent: item.code === "SANDBOX_ESCAPE" || item.code === "WATCHLIST" ? "max" : "+" + item.points }));
    const d = el("div", { className: "d" });
    d.append(el("div", { textContent: item.description }));
    const meta = el("small", { textContent: item.code });
    if (item.atlas_id) meta.append(` · ${item.atlas_id}`);
    d.append(meta);
    row.append(d);
    host.append(row);
  }
  renderWatch();
}
export function renderWatch() {
  const host = $("watchList"); host.textContent = "";
  const rules = session.data.watchlist ?? [];
  if (!rules.length) { host.append(el("div", { className: "faint", style: "font-size:12px", textContent: "No watchlist rules yet." })); return; }
  for (const r of rules) {
    const row = el("div", { style: "display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--bd)" });
    row.append(el("span", { style: "flex:1 1 auto;font-size:12px" }, [ "If an agent ", el("b", { textContent: r.condition }), " ", el("code", { textContent: r.path }), " → ", el("b", { textContent: r.severity, style: "color:var(--crit)" }) ]));
    const response = el("select", { className:"btn quiet", title:"Approval and Block require an interception sensor. Kill always asks for local confirmation." });
    for (const mode of ["observe","alert","approval","block","kill"]) response.append(el("option", { value:mode, textContent:mode[0].toUpperCase()+mode.slice(1) }));
    response.value = r.response ?? "alert";
    response.onchange = async () => {
      response.disabled = true;
      const result = await invoke("set_rule_response", { index:r.index, response:response.value });
      if (!result?.ok) toast(result?.message || "Response mode could not be saved");
      await app.poll(); renderLegend();
    };
    const rm = el("button", { className: "btn quiet", textContent: "Remove" });
    rm.onclick = async () => {
      rm.disabled = true;
      rm.textContent = "Removing…";
      try {
        const result = await invoke("remove_rule", { index: r.index });
        if (!result?.ok) throw new Error(result?.message || "Rule could not be removed");
        await app.poll();
        renderLegend();
        toast("Rule removed");
      } catch (error) {
        rm.disabled = false;
        rm.textContent = "Remove";
        toast(`Rule removal failed: ${error}`);
      }
    };
    row.append(response, rm);
    host.append(row);
  }
}
export function setOverlay(id, open, focusId) {
  $(id).hidden = !open;
  document.body.style.overflow = open ? "hidden" : "";
  if (open && focusId) requestAnimationFrame(() => $(focusId)?.focus());
}
export function openLegend() { if (session.data) renderLegend(); setOverlay("legendScrim", true, "legendClose"); }

/** Attach the overlay controls. Called once at startup. */
export function wireOverlays() {
  $("legendBtn").onclick = openLegend;
  $("legendClose").onclick = () => setOverlay("legendScrim", false);
  $("legendScrim").onclick = (e) => { if (e.target === $("legendScrim")) setOverlay("legendScrim", false); };
  $("ciBtn").onclick = () => setOverlay("ciScrim", true, "ciClose");
  $("ciClose").onclick = () => setOverlay("ciScrim", false);
  $("ciScrim").onclick = (e) => { if (e.target === $("ciScrim")) setOverlay("ciScrim", false); };
  $("themeBtn").onclick = () => {
  session.theme = session.theme === "light" ? "dark" : "light";
  localStorage.setItem("topgent.theme", session.theme);
  applyTheme();
};
  $("wAdd").onclick = async () => {
  const path = $("wPath").value.trim(); if (!path) return;
  await invoke("add_rule", { path, condition: $("wCond").value, severity: $("wSev").value });
  $("wPath").value = ""; await app.poll(); renderLegend();
};
  $("soundBtn").onclick = () => { session.alertsOn = !session.alertsOn; localStorage.setItem("topgent.sound", session.alertsOn ? "1" : "0"); $("soundBtn").textContent = session.alertsOn ? "🔔 On" : "🔕 Off"; if (session.alertsOn && "Notification" in window && Notification.permission === "default") Notification.requestPermission(); };

// ---- stop flow ----
}
