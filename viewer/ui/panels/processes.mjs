// Process history for the selected, exact agent run.
import { $, clock, el } from "../dom.mjs";
import { session, findAgent, stamp } from "../state.mjs";
import { makeTable } from "../table.mjs";
import { openInspector } from "../inspector.mjs";

export function processLineage(row) {
  return [`agent ${row.agent_pid}`, ...(row.chain ?? []).slice().reverse().map(String), String(row.pid)].join(" → ");
}
export function processName(row) {
  const name = row.name || "?";
  return row.program_unread ? `${name} → ?` : name;
}
export function processStateMeaning(row) {
  if (row.state === "exited" && row.exited_at != null) {
    const code = row.exit_code == null ? "" : `, status ${row.exit_code}`;
    return `exited at ${clock(row.exited_at)}${code}; lived about ${Math.max(0, row.exited_at - row.started_at)} ms`;
  }
  if (row.state === "gone" && row.gone_after != null) return `gone: last seen ${clock(row.last_seen)}, not found at ${clock(row.gone_after)}; the exit itself was not observed`;
  if (row.state === "running") return "running at the latest sweep";
  return row.state;
}
function seenBy(row) {
  return row.observed_by === "kernel_event" ? "the kernel, as it happened (process connector)"
    : row.observed_by === "sweep" ? "a sweep only; its start and end are known to a sweep's resolution"
    : "not recorded by this report's build";
}
function programOf(row) {
  const current = row.exe ?? row.program ?? (row.program_unread ? "exec'd, then gone before the new program could be read" : "not readable");
  return (row.previous_programs ?? []).length ? `${current}, after exec from ${row.previous_programs.join(", ")} (${row.exec_generation} exec)` : current;
}
function details(row) {
  return [`identity: pid ${row.pid} started ${clock(row.started_at)}`, `lineage: ${processLineage(row)}`, `state: ${processStateMeaning(row)}`, `program: ${programOf(row)}`, `seen by: ${seenBy(row)}`].join("\n");
}
/** Each process after its parent, earliest first at each level, as the
 *  desktop's `tree_order`; anything a gap left out goes at the end. */
export function treeOrder(rows) {
  const key = r => `${r.pid}:${r.started_at}`;
  const placed = new Set(), ordered = [];
  const roots = rows.filter(r => r.parent_pid == null || !rows.some(o => o.pid === r.parent_pid))
    .sort((a, b) => a.started_at - b.started_at || a.pid - b.pid);
  const stack = [...roots].reverse();
  while (stack.length) {
    const row = stack.pop();
    if (placed.has(key(row))) continue;
    placed.add(key(row)); ordered.push(row);
    const children = rows.filter(c => c.parent_pid === row.pid && !placed.has(key(c)))
      .sort((a, b) => b.started_at - a.started_at || b.pid - a.pid);
    stack.push(...children);
  }
  return ordered.concat(rows.filter(r => !placed.has(key(r))));
}
/** How long it ran: to its exit, or at least until last seen. */
export function ranFor(row) {
  const ms = Math.max(0, (row.exited_at ?? row.last_seen) - row.started_at);
  const prefix = row.state === "running" ? "≥ " : "";
  return ms < 1000 ? `${prefix}${ms} ms` : ms < 60000 ? `${prefix}${Math.floor(ms/1000)} s` : `${prefix}${Math.floor(ms/60000)} min`;
}
/** The rules that held on exactly this process. */
function findingsOf(row) {
  return [...new Set((session.data.behaviour?.findings ?? [])
    .filter(f => f.actor_pid === row.pid && (f.actor_started_at == null || f.actor_started_at === row.started_at))
    .map(f => f.rule))].sort();
}
function parentLabel(rows, parent) {
  const p = rows.find(r => r.pid === parent);
  return p?.name ? `${p.name} (${parent})` : String(parent);
}
function stateWord(row) {
  return row.state === "exited" && row.exit_code != null ? `exited ${row.exit_code}` : row.state;
}
export function renderProcesses() {
  const host = $("processes");
  const agent = findAgent(session.selected);
  const mine = (session.data.process_history ?? []).filter(row => agent && row.agent_pid === agent.pid && (row.agent_started_at == null || row.agent_started_at === agent.started_at));
  $("processCount").textContent = `${mine.length} process${mine.length === 1 ? "" : "es"}`;
  if (!mine.length) { host.replaceChildren(el("div", { className:"empty", textContent:"No process history recorded for this agent yet." })); return; }
  host.replaceChildren(makeTable("processes", [
    {key:"name",label:"PROCESS"}, {key:"pid",label:"PID"}, {key:"parent",label:"PARENT"}, {key:"state",label:"STATE"}, {key:"started",label:"STARTED"}, {key:"ran",label:"RAN FOR"}, {key:"findings",label:"FINDINGS"},
  ], treeOrder(mine).map(row => {
    const findings = findingsOf(row);
    const indent = "\u00a0\u00a0".repeat(Math.max(0, (row.depth ?? 0) - 1)) + ((row.depth ?? 0) > 0 ? "└ " : "");
    const tr = el("tr", { className:"clickable", title:details(row) }, [
      el("td", {textContent:indent + processName(row)}),
      el("td", {className:"mono",textContent:String(row.pid)}),
      el("td", {textContent:row.parent_pid == null ? "-" : parentLabel(mine, row.parent_pid)}),
      el("td", {className:row.state === "running" ? "" : "muted", textContent:stateWord(row)}),
      el("td", {className:"mono",textContent:stamp(row.started_at)}),
      el("td", {className:"mono",textContent:ranFor(row)}),
      el("td", {className:findings.length ? "hot" : "faint", textContent:findings.length ? String(findings.length) : "-"}),
    ]);
    if (session.focusProcess === row.pid) {
      session.focusProcess = null;
      tr.classList.add("focus");
      queueMicrotask(() => { tr.scrollIntoView({ block: "center" }); tr.onclick(); });
    }
    tr.onclick = () => openInspector({
      title: `${processName(row)} · pid ${row.pid}`,
      plain: processStateMeaning(row),
      rows: [
        ["program", programOf(row)],
        ["pid", String(row.pid)],
        ["parent", row.parent_pid == null ? "-" : parentLabel(mine, row.parent_pid)],
        ["started", clock(row.started_at)],
        ["ran for", ranFor(row)],
        ["lineage", processLineage(row)],
        ["behaviour", findings.length ? findings.join("; ") : "no behaviour rule held on this process"],
        ["seen by", seenBy(row)],
      ],
    });
    return tr;
  })));
}
