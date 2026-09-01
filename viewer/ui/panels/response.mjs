// What Topgent is allowed to do here, and what it has done.
//
// The ladder this installation has honestly earned, the approvals outstanding,
// and every action already taken.

import { app } from "../app-hooks.mjs";
import { $, clock, el } from "../dom.mjs";
import { session, toast } from "../state.mjs";
import { makeTable } from "../table.mjs";
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
  const rows = decisions.map(decision => {
    const action = el("td", { style:"text-align:right" });
    if (decision.outcome === "awaiting_approval" && decision.requested === "kill" && decision.approval?.state === "pending") {
      const agent = session.data.agents.find(item => item.pid === decision.agent_pid && item.started_at === decision.agent_started_at);
      const deny = el("button", { className:"btn quiet", textContent:"Deny", disabled:!agent, style:"margin-right:6px" });
      deny.onclick = async () => {
        if (!agent) return;
        const result = await invoke("resolve_termination_approval", { requestId:decision.approval.id, pid:agent.pid, startedAt:agent.started_at, approve:false });
        toast(result.message ?? (result.ok ? "Termination denied" : "Decision refused"));
        await app.poll(true);
      };
      const button = el("button", { className:"btn danger", textContent:"Approve & stop", disabled:!agent });
      button.onclick = () => { if (agent) app.askStop(agent, decision.approval); };
      action.append(deny, button);
    } else action.append(el("span", { className:"faint", textContent:"—" }));
    const hot = decision.outcome === "capability_mismatch" ? "warn" : decision.outcome === "awaiting_approval" ? "hot" : "";
    return el("tr", {}, [
      el("td", {}, [el("div", { textContent:decision.agent_family }), el("div", { className:"mono faint", textContent:`pid ${decision.agent_pid}` })]),
      el("td", {}, [el("code", { textContent:decision.path }), el("div", { className:"faint", textContent:decision.condition })]),
      el("td", { textContent:decision.requested }),
      el("td", {}, [el("span", { className:`net-verdict ${hot}`, textContent:decision.outcome.replaceAll("_", " ") }), el("div", { className:"faint", style:"margin-top:5px", textContent:decision.detail }), decision.approval ? el("div", { className:"mono faint", style:"margin-top:5px", textContent:`${decision.approval.state} · expires ${clock(decision.approval.expires_at)}`, title:`Persistent one-shot request ${decision.approval.id}` }) : null]),
      action,
    ]);
  });
  out.append(makeTable("response", [
    {key:"agent_family",label:"Agent"}, {key:"path",label:"Matched rule"}, {key:"requested",label:"Requested"},
    {key:"outcome",label:"Actual outcome"}, {key:"action",label:"Action",align:"right"},
  ], rows));
  host.replaceChildren(out);
}
