// Where an agent has been talking.
//
// Retained per endpoint, with what the kernel counted where it counts. Absent
// values are shown as unavailable rather than as zero.

import { $, clock, el } from "../dom.mjs";
import { session, view, findAgent, runName } from "../state.mjs";
import { changeSort, makeTable, sortedBy } from "../table.mjs";
import { openInspector } from "../inspector.mjs";
import { bytes } from "../format.mjs";

const count = (n) => (Number(n) || 0).toLocaleString("en-US");

// Where each agent sent data, host wide, whether or not anything fired. A
// coding agent sends parts of files to its model on every turn; what matters is
// how much, to whom, and whether it arrived as a burst about the size of what
// it read. The per-agent view of this lives in the agent's Files tab; this is
// the roll-up across every agent, so it belongs with the host's traffic.
function flows(report) {
  const list = report.agent_flows || [];
  if (!list.length) return null;
  const wrap = el("section", { className: "flows" }, [
    el("h3", { className: "flows-title", textContent: "Where agents sent data" }),
    el("p", { className: "flows-note", textContent: "Totals since each agent started, and the most it sent to one place within five minutes, compared with what it read once it has read a large part of a workspace. Encrypted traffic: this is how much, never what." }),
  ]);
  for (const f of list) {
    const ws = f.bytes_read ? `${bytes(f.bytes_read)} read` : f.workspace_bytes ? `${bytes(f.workspace_bytes)} workspace` : "size unknown";
    wrap.append(el("div", { className: "flow-head" }, [
      el("strong", { textContent: f.agent?.name || "?" }),
      el("span", { className: "flow-sub", textContent: ` · pid ${f.agent?.pid} · read ${count(f.files_read)} files in ${f.workspace || "?"} (${ws})` }),
    ]));
    const rows = (f.destinations || []).map((d) => {
      const label = d.name || d.owner || d.address || "unknown";
      const pct = d.burst_percent_of_workspace;
      const basis = f.compared_with === "bytes read" ? "what it read" : "the workspace";
      const flag = pct == null ? "" : d.over_threshold
        ? `▲ about ${pct}% of ${basis} within ${f.burst_window_minutes} min`
        : d.own_service ? "ok: within normal prompt sizes" : "";
      return el("tr", { className: flag.startsWith("▲") ? "flow-hot" : "" }, [
        el("td", { textContent: label }),
        el("td", { className: "flow-tag", textContent: d.own_service ? "its own service" : (d.address ? `${d.address}:${d.port}` : "") }),
        el("td", { className: "num", textContent: bytes(d.bytes) }),
        el("td", { className: "num", textContent: bytes(d.burst_bytes) }),
        el("td", { className: "num", textContent: pct == null ? "" : `${pct}%` }),
        el("td", { textContent: flag }),
      ]);
    });
    wrap.append(el("table", { className: "flow-table" }, [
      el("thead", {}, el("tr", {}, ["Destination", "", "Total", "Biggest 5-min burst", "Share of read", ""].map((h) => el("th", { textContent: h })))),
      el("tbody", {}, rows),
    ]));
  }
  return wrap;
}

export function renderNetwork() {
  const agent = findAgent(session.selected);
  const retainedBaseline = agent && (session.data.network_baselines ?? []).some(item => item.agent_pid === agent.pid && item.agent_started_at === agent.started_at && item.retained_samples > 0);
  $("networkBaselineReset").disabled = !retainedBaseline;
  $("networkBaselineReset").title = retainedBaseline
    ? `Remove retained endpoint history only for ${agent.family ?? "this agent"} pid ${agent.pid}, start ${agent.started_at}`
    : "Select an agent with retained network history";
  renderNetworkInto("network", "networkCount", agent, "network-agent");
  renderNetworkInto("network-host", "networkHostCount", null, "network-host");
  // Host-wide egress roll-up, below the endpoint tables.
  const where = flows(session.data);
  if (where) $("network-host").append(where);
}

function renderNetworkInto(hostId, countId, agent, tableKey) {
  const host = $(hostId);
  let records = (session.data.network ?? []).filter(record =>
    (!agent || (record.agent_pid === agent.pid && record.agent_started_at === agent.started_at)) &&
    (view.networkDirection === "all" || record.direction === view.networkDirection) &&
    (!view.networkQuery || [record.host, record.port, record.verdict, record.agent_family].some(value => String(value ?? "").toLowerCase().includes(view.networkQuery.toLowerCase())))
  );
  records = sortedBy(records, view.networkSort, (record, col) => record[col]);
  $(countId).textContent = `${records.length} endpoint${records.length===1?"":"s"}${agent ? ` · pid ${agent.pid}` : " · bounded history"}`;
  if (!records.length) {
    host.replaceChildren(el("div", { className:"empty", textContent:agent ? "No matching network metadata for this agent instance." : "No network metadata observed yet." }));
    return;
  }
  const rows = records.map(record => {
    const alertLevel = record.alert_level ?? (record.verdict === "private_peer" ? "high" : record.verdict === "observed" ? "none" : "critical");
    const severity = alertLevel === "critical" ? "hot" : alertLevel === "high" ? "warn" : "";
    const owner = [...(session.data.agents ?? []), ...(session.data.ended_agents ?? [])].find(item => item.pid === record.agent_pid && item.started_at === record.agent_started_at);
    // Which agent's process held the socket, as the desktop's AGENT column.
    const agentText = `${runName(record.agent_pid, record.agent_started_at, record.agent_family)} (${record.agent_pid})${owner?.live === false ? " · ended" : ""}`;
    const series = record.time_series ?? {patterns:[],retained_samples:0,warmup:"collecting",evidence:"socket_snapshot_visibility"};
    const baseline = record.baseline ?? {state:"collecting",warmup_samples:5,outside_baseline:false};
    const patternLabel = pattern => ({new_destination:"new destination",raw_ip_endpoint:"raw IP",nonstandard_port:"nonstandard port",repeated_snapshot_visibility:"repeated visibility",outside_baseline:"outside baseline"}[pattern] ?? pattern.replaceAll("_", " "));
    const sevClass = alertLevel === "critical" ? "crit" : alertLevel === "high" ? "high" : "low";
    const tr = el("tr", { className:`network-${alertLevel} clickable` }, [
      el("td", { textContent:agentText }),
      el("td", {}, [el("div", { className:"mono" }, [`${record.host}:${record.port}`, record.first_seen_this_sweep ? el("span", { className:"flag", style:"margin-left:7px;color:var(--ac);background:var(--acbg)", textContent:"FIRST SEEN" }) : null]), el("div", { className:"faint", textContent:record.dns_name ? "DNS name observed" : "Raw IP · no DNS name in socket metadata" })]),
      el("td", { textContent:record.direction }),
      el("td", {}, el("span", { className:`net-verdict ${severity}`, textContent:record.verdict.replaceAll("_", " ") })),
      el("td", {}, [el("span", { className:"net-verdict", textContent:record.currently_observed === false ? "not in latest sweep" : "visible now" }), el("div", { className:"faint", style:"margin-top:5px", textContent:`${record.visibility_changes ?? 1} snapshot edge${(record.visibility_changes ?? 1)===1?"":"s"}` })]),
      el("td", { className:record.owner_known ? "" : "faint", textContent:record.country ?? "unknown" }),
      el("td", { className:record.owner_known ? "" : "faint", textContent:record.network_owner ?? "unknown" }),
      el("td", { className:"mono", textContent:String(record.observations), title:"Number of sweeps where this endpoint was visible; not a connection or request count" }),
      el("td", { className:"mono muted", textContent:record.packets == null ? "Unavailable" : String(record.packets), title:"Packets counted by capture; unavailable is not zero" }),
      el("td", { className:"muted", textContent:record.bytes == null ? "Unavailable" : String(record.bytes), title:"Traffic volume for a retained endpoint; the kernel counts per connection, and this row spans a history of them" }),
    ]);
    tr.onclick = () => openInspector({
      title: `${record.host}:${record.port}`,
      sevLabel: record.verdict.replaceAll("_", " "), sevClass,
      plain: `${record.direction} endpoint. Topgent sees the connection metadata, not the payload.`,
      rows: [
        ["agent", agentText],
        ["direction", record.direction],
        ["verdict", record.verdict.replaceAll("_", " ")],
        ["name", record.dns_name || "raw IP (no DNS name in socket metadata)"],
        ["country", record.country ?? "unknown"],
        ["network", record.network_owner ?? "unknown"],
        ["snapshot state", record.currently_observed === false ? "not in latest sweep" : "visible now"],
        ["patterns", series.patterns.length ? series.patterns.map(patternLabel).join(", ") : "None"],
        ["baseline", `${series.retained_samples} / ${series.max_samples ?? 64} samples · ${baseline.state}`],
        ["risk impact", record.risk_points ? `+${record.risk_points}` : "None"],
        ["observations", String(record.observations)],
        ["first seen", clock(record.first_seen)],
        ["last seen", clock(record.last_seen)],
        ["packets", record.packets == null ? "Unavailable" : String(record.packets)],
        ["bytes", record.bytes == null ? "Unavailable" : String(record.bytes)],
      ],
    });
    return tr;
  });
  host.replaceChildren(makeTable(tableKey, [
    {key:"agent_pid",label:"Agent",sortable:true}, {key:"host",label:"Endpoint",sortable:true}, {key:"direction",label:"Direction",sortable:true},
    {key:"verdict",label:"Verdict",sortable:true}, {key:"currently_observed",label:"State",sortable:true},
    {key:"country",label:"Country",sortable:true}, {key:"network_owner",label:"Network",sortable:true},
    {key:"observations",label:"Obs",sortable:true,align:"right"}, {key:"packets",label:"Packets",sortable:true,align:"right"},
    {key:"bytes",label:"Bytes",sortable:true,align:"right"},
  ], rows, {sort:view.networkSort,onSort:(col)=>changeSort("networkSort",col,renderNetwork)}));
}
