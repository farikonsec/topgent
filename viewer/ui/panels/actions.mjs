// Linux Audit actions attributed to the selected, exact agent run.
import { $, clock, el } from "../dom.mjs";
import { session, findAgent } from "../state.mjs";
import { makeTable } from "../table.mjs";
import { openInspector } from "../inspector.mjs";

export function actionLabel(action) { return ({read:"open/read",write:"open/write",read_write:"open/read-write"})[action] ?? action; }
export function actionMeaning(action) {
  if (["read","write","read_write"].includes(action)) return "A successful open or related syscall; transferred bytes and contents were not observed.";
  if (["connect","send"].includes(action)) return "The recorded syscall result, not proof of an open socket, protocol, delivered bytes or a completed nonblocking connection.";
  return "The kernel's Audit rule recorded this action; coverage is limited to configured rules.";
}
function chain(row) { return row.agent_pid == null ? "Unattributed: event-time ancestry was not established" : [`agent ${row.agent_pid}`, ...(row.chain ?? []).map(String)].join(" → "); }
export function renderActions() {
  const host = $("actions");
  const agent = findAgent(session.selected);
  const rows = (session.data.observed_actions ?? []).filter(row => row.action !== "execute" && agent && row.agent_pid === agent.pid && row.agent_started_at === agent.started_at);
  const coverage = session.data.action_coverage ?? {};
  $("actionCount").textContent = `${rows.length} action${rows.length === 1 ? "" : "s"}`;
  const note = el("div", {className:"evidence-note"}, [el("strong",{textContent:"Observed actions"}), el("span",{textContent:`${coverage.detail ?? ""} Retention evictions: ${coverage.evicted ?? 0}; measured queue losses this sweep: ${coverage.queue_losses ?? 0}.`})]);
  if (!rows.length) {
    // This tab lists Linux Audit records only. Where the eBPF sensor is the
    // source there is no Audit stream, so point to the tabs that do carry what
    // eBPF saw for this agent rather than imply nothing happened.
    const hasFlow = agent && (session.data.agent_flows ?? []).some(f => f.agent?.pid === agent.pid && f.agent?.started_at === agent.started_at);
    const empty = hasFlow
      ? "No Linux Audit records for this agent. This host's file and network activity comes from the eBPF sensor, not Audit — see the Files tab for what it read and where its data went, and Network for its endpoints."
      : "No Audit actions attributed to this agent. Check Audit rules and sensor coverage.";
    host.replaceChildren(note, el("div", {className:"empty",textContent:empty}));
    return;
  }
  const table = makeTable("actions", [
    {key:"at",label:"TIME"},{key:"action",label:"ACTION"},{key:"target",label:"TARGET"},{key:"result",label:"RESULT"},{key:"actor",label:"DIRECT ACTOR"},{key:"state",label:"STATE"},
  ], rows.map(row => {
    const tr = el("tr", {className:"clickable", title:`meaning: ${actionMeaning(row.action)}`}, [
      el("td",{textContent:clock(row.at)}),el("td",{textContent:actionLabel(row.action)}),el("td",{className:"mono",textContent:row.target}),el("td",{textContent:row.result}),el("td",{textContent:`${row.actor_name || "unknown"} (${row.actor_pid})`}),el("td",{textContent:row.actor_state || "unresolved"}),
    ]);
    tr.onclick = () => openInspector({
      title: `${actionLabel(row.action)} — ${(row.target || "").split("/").pop() || row.target}`,
      plain: actionMeaning(row.action),
      rows: [
        ["target", row.target, true],
        ["result", row.result],
        ["direct actor", `${row.actor_name || "unknown"} (${row.actor_pid})`],
        ["actor run", row.actor_started_at == null ? "which run of it was not established" : clock(row.actor_started_at)],
        ["record", `Linux Audit ${row.record}`, true],
        ["attribution", chain(row)],
        ["state", row.actor_state || "unresolved"],
      ],
      actions: [{label:"Copy record", kind:"quiet", on:() => navigator.clipboard?.writeText(row.record || "")}],
    });
    return tr;
  }));
  host.replaceChildren(note, table);
}

