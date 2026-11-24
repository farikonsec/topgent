// Incidents: the human-first surface. What an agent did that a person has to
// decide on, in plain words, before any of the technical detail elsewhere.
//
// Each incident is one agent run. It reads top to bottom the way a person
// reads it: one sentence of what happened, why it matters, what to do, then
// the evidence, then what the evidence does not establish. No table, no
// jargon. The rich per-event detail still lives in the other workspaces; this
// is the layer that was missing.
import { $, el, clock } from "../dom.mjs";
import { session } from "../state.mjs";

// When the incident happened, human-readable, or "" if not known.
export const incidentTime = (inc) => {
  const ms = inc?.first_seen ?? inc?.first_at ?? 0;
  return ms ? clock(ms) : "";
};

const SEV = { critical: ["crit", "Critical"], high: ["high", "High"] };
// Older reports carry only the exfiltration incident, which had no name field.
const kindName = (inc) => inc.name || "Workspace exfiltration";

function bytes(n) {
  const units = ["bytes", "KB", "MB", "GB", "TB"];
  let v = Number(n) || 0, u = 0;
  while (v >= 1000 && u < units.length - 1) { v /= 1000; u += 1; }
  if (u === 0) return `${v} bytes`;
  return `${v >= 100 ? Math.round(v) : v.toFixed(1)} ${units[u]}`;
}
const count = (n) => (Number(n) || 0).toLocaleString("en-US");

export function incidentsSummary(report) {
  const n = report?.incidents?.length ?? 0;
  return n === 0 ? "No incidents" : `${n} incident${n === 1 ? "" : "s"}`;
}

// What this host watches for, shown on the Coverage page (not here): the
// workspace-exfiltration state and every named incident with how many of its
// rules can fire. This is detection capability, not something to decide on, so
// it belongs with the other coverage, not above the incidents themselves.
export function incidentCoverage(report) {
  const c = report?.incident_coverage;
  if (!c && !(report?.incident_kinds || []).length) return null;
  const named = (report.incident_kinds || []).map((k) => ({
    name: k.name,
    live: (k.rules || []).filter((r) => r.live).length,
    total: (k.rules || []).length,
  }));
  const rows = [{ name: "Workspace exfiltration", state: c?.state ?? "" }, ...named];
  const listEl = el("div", { className: "cov-incidents" }, rows.map((k) => el("div", { className: "cov-incident-row" }, [
    el("span", { className: "cov-incident-name", textContent: k.name }),
    el("span", {
      className: `cov-incident-rules${k.total != null && k.live < k.total ? " partial" : ""}`,
      textContent: k.total == null ? (k.state || "available") : `${k.live}/${k.total} rules`,
    }),
  ])));
  return el("div", {}, [
    c?.detail ? el("div", { className: "context-note", textContent: c.detail }) : null,
    listEl,
  ]);
}

function section(title, kids) {
  return el("div", { className: "incident-section" }, [
    el("h4", { className: "incident-section-title", textContent: title }),
    ...[].concat(kids),
  ]);
}

function whatToDo(actions) {
  return el("ol", { className: "incident-actions" }, (actions || []).map((a) => {
    const li = el("li", {}, el("span", { textContent: a.label || "" }));
    if (a.command) li.append(el("code", { className: "incident-cmd", textContent: a.command }));
    return li;
  }));
}

function evidence(inc) {
  const ev = inc.evidence || {}, ws = ev.workspace || {}, n = inc.numbers || {};
  const rows = [];
  const add = (k, v) => rows.push(el("div", { className: "incident-erow" }, [
    el("span", { className: "incident-ekey", textContent: k }),
    el("span", { className: "incident-eval", textContent: v }),
  ]));
  // A behaviour incident: the rules that matched, on what, by which process.
  for (const f of ev.findings || []) {
    const times = f.count > 1 ? `, ${count(f.count)} times` : "";
    add(f.rule || "rule", `${f.target || "?"} by ${f.actor_name || "?"} (${f.actor_pid ?? "?"})${times}`);
  }
  // A secret incident: which secret files were read, and where data went after.
  for (const sec of ev.secrets || []) {
    const size = sec.bytes ? ` (${bytes(sec.bytes)})` : "";
    add(sec.class_name || "secret", `${sec.path || sec.name || "?"}${size}`);
  }
  for (const d of ev.sent_to || []) {
    const name = d.name ? ` (${d.name})` : d.owner ? ` (${d.owner})` : "";
    const own = d.own_service ? "  · its own service" : "";
    add("then sent to", `${d.address || "?"}:${d.port}${name}${own}, ${bytes(d.bytes)}`);
  }
  if (ev.workspace) {
    const inRoot = n.files_in_root ? ` of ${count(n.files_in_root)}` : "";
    add("read", `${count(ws.files)}${inRoot} files under ${ws.root || "?"}`);
  }
  if (ws.history_files) add("git history", `${count(ws.history_files)} objects read`);
  const tops = (ws.top_directories || []).map((t) => `${t.directory} (${count(t.files)})`).join(", ");
  if (tops) add("most from", tops);
  for (const d of ev.destinations || []) {
    const name = d.name ? ` (${d.name})` : "";
    const store = d.object_storage ? "  · object storage" : "";
    add("sent to", `${d.address || "?"}:${d.port}${name}${store}`);
    add("", `${count(d.attempts)} attempts, ${count(d.failed)} failed, ${bytes(d.bytes)}`);
  }
  if (n.encrypted) add("encrypted", `yes — ran ${(ev.encryption_tools || []).join(", ")}`);
  add("duration", n.duration || "?");
  const rec = inc.agent?.recognised ? "recognised agent" : "not a recognised agent";
  add("by", `${inc.agent?.name || "?"} pid ${inc.agent?.pid} (${rec})`);
  return el("div", { className: "incident-evidence" }, rows);
}

function card(inc) {
  const [cls, word] = SEV[inc.severity] || ["high", inc.severity || ""];
  // The summary is always visible; the rest folds away. Critical ones open by
  // default, so the worst is read first without a click.
  const when = incidentTime(inc);
  const summary = el("summary", { className: "incident-summary" }, [
    el("span", { className: `sev ${cls}`, textContent: word }),
    el("span", { className: "incident-kind", textContent: kindName(inc) }),
    el("span", { className: "incident-headline", textContent: inc.headline || "" }),
    when ? el("span", { className: "incident-when", textContent: when, title: "When Topgent first saw this" }) : null,
    el("span", { className: "incident-chevron" }),
  ]);
  const why = section("Why it matters", el("ul", { className: "incident-why" },
    (inc.why || []).map((w) => el("li", { textContent: w }))));
  const limits = section("What this does not establish", el("ul", { className: "incident-limits" },
    (inc.limits || []).map((l) => el("li", { textContent: l }))));
  const inner = el("div", { className: "incident-body" }, [
    why,
    section("What to do", whatToDo(inc.actions)),
    section("Evidence", evidence(inc)),
    limits,
  ]);
  // The page redraws on every poll, which would reset a native <details>.
  // Remember each card's open state by its id so a card a person opened stays
  // open; a card not yet touched follows the default (critical open).
  const id = inc.id || inc.headline || "";
  const open = openState.has(id) ? openState.get(id) : inc.severity === "critical";
  const details = el("details", { className: `incident-card ${cls}`, open }, [summary, inner]);
  details.addEventListener("toggle", () => openState.set(id, details.open));
  return details;
}

// Open/closed state per incident id, kept across the poll's redraws.
const openState = new Map();


export function renderIncidents() {
  const body = $("incidents");
  if (!body) return;
  const report = session.data || {};
  const list = (report.incidents || [])
    .slice()
    .sort((a, b) => (b.first_seen ?? b.first_at ?? 0) - (a.first_seen ?? a.first_at ?? 0));
  const count = $("incidentCount");
  if (count) count.textContent = list.length ? `${list.length}` : "";
  const kids = [];
  if (list.length === 0) {
    kids.push(el("div", { className: "incident-empty" }, [
      el("p", { textContent: "No incidents." }),
      el("p", {
        className: "incident-empty-note",
        textContent: report.incident_coverage?.state === "available"
          ? "No matches this session. See Coverage."
          : "Full detection needs eBPF (Linux). See Coverage.",
      }),
    ]));
  } else {
    kids.push(...list.map(card));
  }
  body.replaceChildren(...kids);
}
