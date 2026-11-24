// Files: what the selected agent read, and — for each place it sent data —
// the files it had just opened. Built from the same OS-level counts as the
// incidents rule: file names and sizes come from stat at read time, never
// from the bytes sent, which are encrypted. This tab answers "what did it
// touch, and what was it reading when it uploaded", in plain terms.
import { $, el } from "../dom.mjs";
import { session, findAgent } from "../state.mjs";

function bytes(n) {
  const units = ["bytes", "KB", "MB", "GB", "TB"];
  let v = Number(n) || 0, u = 0;
  while (v >= 1000 && u < units.length - 1) { v /= 1000; u += 1; }
  if (u === 0) return `${v} bytes`;
  return `${v >= 100 ? Math.round(v) : v.toFixed(1)} ${units[u]}`;
}
const count = (n) => (Number(n) || 0).toLocaleString("en-US");
const tail = (path) => String(path ?? "").split("/").filter(Boolean).slice(-2).join("/") || path;

// The flow record for exactly this agent run (pid + start), if there is one.
function flowFor(agent) {
  return (session.data.agent_flows ?? []).find(
    (f) => f.agent?.pid === agent.pid && f.agent?.started_at === agent.started_at,
  );
}

function section(title, kids) {
  return el("div", { className: "files-section" }, [
    el("h4", { className: "files-section-title", textContent: title }),
    ...[].concat(kids),
  ]);
}

function summary(flow) {
  const read = flow.bytes_read ? `${count(flow.files_read)} files (${bytes(flow.bytes_read)})` : `${count(flow.files_read)} files`;
  const hist = flow.history_files ? `, ${count(flow.history_files)} from git history` : "";
  const line = `Read ${read} under ${flow.workspace || "?"}${hist}.`;
  const note = flow.large_read
    ? "A large read: the burst sizes below are shown as a share of it."
    : "Not a large read: bursts are shown as totals only, not as a share.";
  return section("What it read", [
    el("p", { className: "files-summary", textContent: line }),
    el("p", { className: "files-note", textContent: note }),
  ]);
}

function folders(flow) {
  const rows = (flow.folders || []).filter((d) => d.directory);
  if (!rows.length) return null;
  return section("Folders read most", el("table", { className: "files-table" }, [
    el("thead", {}, el("tr", {}, ["Folder", "Files"].map((h) => el("th", { textContent: h })))),
    el("tbody", {}, rows.map((d) => el("tr", {}, [
      el("td", { className: "mono", textContent: d.directory }),
      el("td", { className: "num", textContent: count(d.files) }),
    ]))),
  ]));
}

function sensitive(flow) {
  const list = flow.sensitive || [];
  if (!list.length) return null;
  return section("Files that look like secrets", [
    el("p", { className: "files-note", textContent: "Matched by name — credentials, keys, tokens. Topgent sees that these were opened, never their contents." }),
    el("ul", { className: "files-secrets" }, list.map((p) => el("li", {}, [
      el("span", { className: "files-flag", textContent: "⚠" }),
      el("span", { className: "mono", textContent: p }),
    ]))),
  ]);
}

function destinations(flow) {
  const rows = (flow.destinations || []).filter((d) => d.bytes > 0);
  if (!rows.length) return null;
  const blocks = rows.map((d) => {
    const label = d.name || d.owner || (d.address ? `${d.address}:${d.port}` : "unknown");
    const tag = d.own_service ? "its own service" : (d.address ? `${d.address}:${d.port}` : "");
    const pct = d.burst_percent_of_workspace;
    const head = el("div", { className: "files-dest-head" }, [
      el("strong", { textContent: label }),
      tag ? el("span", { className: "files-dest-tag", textContent: ` · ${tag}` }) : null,
    ]);
    const stats = el("p", { className: "files-note", textContent:
      `${bytes(d.bytes)} in total, biggest ${flow.burst_window_minutes}-min burst ${bytes(d.burst_bytes)}`
      + (pct == null ? "" : ` (about ${pct}% of the ${flow.compared_with})`) });
    const before = d.files_before_burst || [];
    const kids = [head, stats];
    if (before.length) {
      kids.push(el("p", { className: "files-note", textContent: "Files it had just read when that burst was sent (contents not seen):" }));
      kids.push(el("ul", { className: "files-before" }, before.map((p) =>
        el("li", { className: "mono", textContent: tail(p), title: p }))));
    }
    return el("div", { className: `files-dest${d.over_threshold ? " hot" : ""}` }, kids);
  });
  return section("Where its data went", blocks);
}

export function renderFiles() {
  const host = $("files");
  if (!host) return;
  const agent = findAgent(session.selected);
  const countEl = $("filesCount");
  if (!agent) {
    if (countEl) countEl.textContent = "";
    host.replaceChildren(el("div", { className: "empty", textContent: "Select an agent to see what it read and where its data went." }));
    return;
  }
  const flow = flowFor(agent);
  if (!flow) {
    if (countEl) countEl.textContent = "";
    host.replaceChildren(el("div", { className: "empty", textContent: "No file reads or data transfers recorded for this agent yet. This needs the eBPF sensor on Linux." }));
    return;
  }
  if (countEl) countEl.textContent = `${count(flow.files_read)} files read`;
  const kids = [summary(flow)];
  for (const block of [folders(flow), sensitive(flow), destinations(flow)]) {
    if (block) kids.push(block);
  }
  host.replaceChildren(...kids);
}
