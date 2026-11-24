// What Topgent is allowed to do here, and what it has done.
//
// The ladder this installation has honestly earned, the approvals outstanding,
// and every action already taken.

import { app } from "../app-hooks.mjs";
import { $, clock, el } from "../dom.mjs";
import { session, toast, runName } from "../state.mjs";
import { makeTable } from "../table.mjs";
import { openInspector, closeInspector } from "../inspector.mjs";
import { invoke } from "../transport.mjs";

export function renderResponse() {
  const host = $("response");
  const capability = session.data.response?.capability ?? {};
  const decisions = session.data.response?.decisions ?? [];
  $("responseCount").textContent = `${decisions.length} matched response${decisions.length===1?"":"s"}`;
  const out = document.createDocumentFragment();
  const ladder = el("div", { className:"response-cap" });
  for (const [label, available] of [["Observe",capability.observe],["Alert",capability.alert],["Approval",capability.intercept],["Block",capability.intercept],["Kill",capability.terminate]]) {
    ladder.append(el("span", { className:`response-step ${available?"on":"off"}`, textContent:`${label} · ${available?"available":"unavailable"}` }));
  }
  out.append(ladder);
  if (!decisions.length) {
    out.append(el("div", { className:"empty", textContent:"No watchlist rule currently matches a running agent. Response modes remain configured on each rule." }));
    host.replaceChildren(out); return;
  }
  const sevOf = o => o === "awaiting_approval" ? "high" : o === "capability_mismatch" ? "med" : "low";
  const pending = d => d.outcome === "awaiting_approval" && d.requested === "kill" && d.approval?.state === "pending";
  const inspect = decision => {
    const agent = session.data.agents.find(item => item.pid === decision.agent_pid && item.started_at === decision.agent_started_at);
    const actions = [];
    if (pending(decision)) {
      actions.push({ label:"Deny", kind:"quiet", on: async () => {
        if (!agent) return;
        const result = await invoke("resolve_termination_approval", { requestId:decision.approval.id, pid:agent.pid, startedAt:agent.started_at, approve:false });
        toast(result.message ?? (result.ok ? "Termination denied" : "Decision refused"));
        closeInspector(); await app.poll(true);
      }});
      actions.push({ label:"Approve & stop", kind:"danger", on: () => { if (agent) { closeInspector(); app.askStop(agent, decision.approval); } }});
    }
    openInspector({
      title: `${runName(decision.agent_pid, decision.agent_started_at, decision.agent_family)} · ${decision.path}`,
      sevLabel: decision.outcome.replaceAll("_", " "), sevClass: sevOf(decision.outcome),
      plain: `Rule: if an agent ${decision.condition} ${decision.path} → ${decision.requested}.`,
      context: decision.detail,
      rows: [
        ["agent", `${runName(decision.agent_pid, decision.agent_started_at, decision.agent_family)} · pid ${decision.agent_pid}`],
        ["matched rule", decision.path, true],
        ["condition", decision.condition],
        ["requested", decision.requested],
        ["actual outcome", decision.outcome.replaceAll("_", " ")],
        decision.approval ? ["approval", `${decision.approval.state} · expires ${clock(decision.approval.expires_at)}`] : null,
      ].filter(Boolean),
      actions,
    });
  };
  const rows = decisions.map(decision => {
    const hot = decision.outcome === "capability_mismatch" ? "warn" : decision.outcome === "awaiting_approval" ? "hot" : "";
    const tr = el("tr", { className:"clickable" }, [
      el("td", {}, [el("div", { textContent:runName(decision.agent_pid, decision.agent_started_at, decision.agent_family) }), el("div", { className:"mono faint", textContent:`pid ${decision.agent_pid}` })]),
      el("td", {}, [el("code", { textContent:decision.path }), el("div", { className:"faint", textContent:decision.condition })]),
      el("td", { textContent:decision.requested }),
      el("td", {}, [el("span", { className:`net-verdict ${hot}`, textContent:decision.outcome.replaceAll("_", " ") }), el("div", { className:"faint", style:"margin-top:5px", textContent:decision.detail })]),
      el("td", { style:"text-align:right" }, el("span", { className:"faint", textContent:pending(decision) ? "Review →" : "—" })),
    ]);
    tr.onclick = () => inspect(decision);
    return tr;
  });
  out.append(makeTable("response", [
    {key:"agent_family",label:"Agent"}, {key:"path",label:"Matched rule"}, {key:"requested",label:"Requested"},
    {key:"outcome",label:"Actual outcome"}, {key:"action",label:"Action",align:"right"},
  ], rows));
  host.replaceChildren(out);
}
