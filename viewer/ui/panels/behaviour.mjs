// Runtime-rule findings. Capability and missing-field detail lives in Coverage.
import { $, clock, el } from "../dom.mjs";
import { session, findAgent, runName } from "../state.mjs";
import { makeTable } from "../table.mjs";
import { openInspector } from "../inspector.mjs";

const RANK = {EMERGENCY:0,ALERT:1,CRITICAL:2,ERROR:3,WARNING:4,NOTICE:5,INFORMATIONAL:6,INFO:6};
const BUCKETS = [["crit","Critical"],["high","High"],["med","Medium"],["low","Low"]];
// Severity bucket a rule priority falls in, for the chip colour and the filter.
function bucket(priority) { const r = RANK[priority] ?? 7; return r <= 2 ? "crit" : r === 3 ? "high" : r === 4 ? "med" : "low"; }
function sevChip(priority) { return el("span", { className: `sev ${bucket(priority)}`, textContent: priority || "" }); }
const activeSev = new Set(); // severity filter, session-local

export function ruleState(rule) {
  if (rule.live) return rule.enabled ? "Live" : "Live, off as shipped";
  if (!(rule.needs ?? []).length) return "Cannot fire here";
  return rule.needs.length === 1 ? `Needs ${rule.needs[0]}` : `Needs ${rule.needs[0]} +${rule.needs.length - 1}`;
}
export function behaviourSummary(report) {
  const count = report.behaviour?.findings?.length ?? 0;
  return `${count} behaviour finding${count === 1 ? "" : "s"} on this host`;
}
function limits(report) {
  const b = report.behaviour ?? {}; const c = b.catalogue ?? {};
  return `${c.enabled ?? 0} rules enabled. ${b.syscall_events ?? 0} syscall events read this sweep; measured queue losses: ${b.syscall_queue_losses ?? 0}; findings evicted: ${b.evicted ?? 0}. A finding means the rule's condition held on one event. Arguments are read in memory and never stored.`;
}
function plainOf(finding, rule) { return finding.summary || rule?.summary || finding.explanation || rule?.desc || "Not in this build's catalogue."; }
function whereOf(finding) { return finding.container === "host" ? "host" : finding.container ? `container ${finding.container}` : "not established"; }
// Which agent a host-wide finding belongs to, in plain terms.
function agentLabel(finding) {
  if (finding.agent_pid == null) return { text: "host", host: true };
  // A finding keeps its agent after the agent exits; named with its model
  // while the session has the run, else as history knew it.
  return { text: runName(finding.agent_pid, finding.agent_started_at, finding.agent_name || `agent ${finding.agent_pid}`), host: false };
}

// Open the inspector on a finding: the plain meaning first, then evidence.
function eventOf(finding) {
  if (finding.source === "audit") return `Linux Audit ${finding.record}`;
  if (finding.source === "ebpf") return `A syscall Topgent's eBPF probe saw, ${finding.record}`;
  return "An exec the process sensor saw";
}
function inspectFinding(finding, rule) {
  const plain = plainOf(finding, rule);
  const attribution = finding.agent_pid == null ? "Host finding: no agent in the actor's ancestry" : [`${agentLabel(finding).text} ${finding.agent_pid}`, ...(finding.chain ?? []).map(String)].join(" → ");
  openInspector({
    title: finding.rule, sevLabel: finding.priority, sevClass: bucket(finding.priority),
    plain, context: finding.explanation && finding.explanation !== plain ? finding.explanation : "",
    rows: [
      ["target", finding.target, true],
      ["direct actor", `${finding.actor_name || "unknown"} (${finding.actor_pid})`],
      ["where", whereOf(finding)],
      ["event", eventOf(finding), true],
      ["first seen", clock(finding.at)],
      ["count", String(Math.max(finding.count ?? 1, 1))],
      ["tags", (finding.tags ?? []).join(", ")],
      ["attribution", attribution],
    ],
    actions: [{ label: "Copy record", kind: "quiet", on: () => navigator.clipboard?.writeText(finding.record || "") }],
  });
}
function inspectRule(rule) {
  openInspector({
    title: rule.rule, sevLabel: rule.priority, sevClass: bucket(rule.priority),
    plain: rule.summary || rule.desc, context: rule.summary ? rule.desc : "",
    rows: [
      ["maturity", rule.maturity],
      ["state", ruleState(rule)],
      ["fields this host lacks", (rule.needs ?? []).join(", ") || "None"],
    ],
  });
}

function findingRows(findings, catalogue, showAgent) {
  return findings.map(finding => {
    const rule = catalogue.find(item => item.rule === finding.rule);
    const plain = plainOf(finding, rule);
    const ruleCell = el("td", {}, [el("div", { className: "rn", textContent: finding.rule }), el("div", { className: "rp", textContent: plain })]);
    const cells = [
      el("td", { textContent: clock(Math.max(finding.last_at ?? 0, finding.at ?? 0)) }), ruleCell,
      el("td", {}, [sevChip(finding.priority)]), el("td", { className: "mono", textContent: finding.target }),
    ];
    if (showAgent) {
      const owner = agentLabel(finding);
      cells.push(el("td", {}, el("span", { className: owner.host ? "faint" : "agent-owner", textContent: owner.text })));
    }
    cells.push(
      el("td", { textContent: `${finding.actor_name || "unknown"} (${finding.actor_pid})` }),
      el("td", { className: "mono", textContent: String(Math.max(finding.count ?? 1, 1)) }),
    );
    const tr = el("tr", { className: "clickable", title: `what it means: ${plain}` }, cells);
    tr.onclick = () => inspectFinding(finding, rule);
    return tr;
  });
}
function note(title, detail) { return el("div", { className: "evidence-note" }, [el("strong", { textContent: title }), el("span", { textContent: detail })]); }
function sevChips(findings, rerender) {
  const present = new Set(findings.map(f => bucket(f.priority)));
  const box = el("div", { className: "fchips" });
  for (const [cls, label] of BUCKETS) {
    if (!present.has(cls)) continue;
    const chip = el("button", { className: `fchip ${cls}${activeSev.has(cls) ? " on" : ""}`, textContent: label });
    chip.onclick = () => { activeSev.has(cls) ? activeSev.delete(cls) : activeSev.add(cls); rerender(); };
    box.append(chip);
  }
  return box.children.length ? box : null;
}
function renderInto(hostId, countId, agent) {
  const report = session.data, behaviour = report.behaviour ?? {}, catalogue = behaviour.catalogue?.coverage ?? [];
  let findings = (behaviour.findings ?? []).filter(f => !agent || (f.agent_pid === agent.pid && f.agent_started_at === agent.started_at));
  if (activeSev.size) findings = findings.filter(f => activeSev.has(bucket(f.priority)));
  $(countId).textContent = `${findings.length} finding${findings.length === 1 ? "" : "s"}`;
  const children = [note(behaviourSummary(report), limits(report))];
  const chips = sevChips((behaviour.findings ?? []).filter(f => !agent || (f.agent_pid === agent.pid && f.agent_started_at === agent.started_at)), renderBehaviour);
  if (chips) children.push(chips);
  const showAgent = !agent;
  const cols = [{ key: "last", label: "LAST SEEN" }, { key: "rule", label: "RULE" }, { key: "priority", label: "SEVERITY" }, { key: "target", label: "TARGET" }];
  if (showAgent) cols.push({ key: "agent", label: "AGENT" });
  cols.push({ key: "actor", label: "DIRECT ACTOR" }, { key: "count", label: "COUNT" });
  const noSyscalls = (behaviour.syscall_events ?? 0) === 0 && !(behaviour.findings ?? []).length;
  const emptyMsg = noSyscalls
    ? "No syscalls are reaching Topgent — the Linux Audit stream is not configured on this host, so there is nothing to match. Enable auditd with rules to turn detection on."
    : agent ? "No behaviour rule has held on this agent or its descendants." : "No behaviour rule has held on this host.";
  children.push(findings.length ? makeTable(`behaviour-${hostId}`, cols, findingRows(findings, catalogue, showAgent)) : el("div", { className: "empty", textContent: emptyMsg }));
  $(hostId).replaceChildren(...children);
}
export function renderBehaviour() { const agent = findAgent(session.selected); renderInto("behaviour-agent", "behaviourAgentCount", agent); renderInto("behaviour-host", "behaviourHostCount", null); }
