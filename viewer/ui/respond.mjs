// Stopping an agent: the only thing this interface can make happen.
//
// Nothing is sent until someone confirms against a named run, and the exact
// identity travels with the request so the core can refuse a pid that has been
// reused since the row was drawn. The confirmation names what will be stopped
// rather than asking whether to proceed.

import { $, clock, el, rel } from "./dom.mjs";
import { invoke } from "./transport.mjs";
import { app } from "./app-hooks.mjs";
import { identityName } from "./alerts.mjs";
import { session, toast } from "./state.mjs";
import { setOverlay } from "./overlays.mjs";

export function askStop(a, approval = null) {
  session.pending = { agent:a, approval };
  $("mTitle").textContent = approval ? "Approve and stop this agent?" : "Stop this agent?";
  $("mGo").textContent = approval ? "Approve & stop" : "Stop";
  $("mSub").textContent = `${identityName(a)} · pid ${a.pid} · running as ${a.user ?? "unreadable"} · up ${rel(a.started_at)}${approval ? ` · request expires ${clock(approval.expires_at)}` : ""}`;
  $("scrim").hidden = false; $("mGo").focus();
}
export function closeModal() { session.pending = null; $("scrim").hidden = true; }

/** Attach the confirmation controls. Called once at startup. */
export function wireResponse() {
  $("mCancel").onclick = closeModal;
  $("scrim").onclick = (e) => { if (e.target === $("scrim")) closeModal(); };
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") { closeModal(); setOverlay("legendScrim", false); setOverlay("ciScrim", false); } });
  $("mGo").onclick = async () => {
    if (!session.pending) return;
    const { agent, approval } = session.pending; closeModal();
    try {
      const b = approval
        ? await invoke("resolve_termination_approval", { requestId:approval.id, pid:agent.pid, startedAt:agent.started_at, approve:true })
        : await invoke("stop", { pid:agent.pid });
      toast(b.message || (b.ok ? "stopped" : "refused"));
    } catch (e) { toast(String(e)); }
    app.poll();
  };
  
  // ---- controls ----
}
