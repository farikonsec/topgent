// Where an agent has been talking.
//
// Retained per endpoint, with what the kernel counted where it counts. Absent
// values are shown as unavailable rather than as zero.

import { $, clock, el } from "../dom.mjs";
import { session, view } from "../state.mjs";
import { changeSort, makeTable, sortedBy } from "../table.mjs";

export function renderNetwork() {
  const host = $("network");
  const agent = session.data.agents.find(item => item.pid === session.selected);
  const retainedBaseline = agent && (session.data.network_baselines ?? []).some(item => item.agent_pid === agent.pid && item.agent_started_at === agent.started_at && item.retained_samples > 0);
  $("networkBaselineReset").disabled = !retainedBaseline;
  $("networkBaselineReset").title = retainedBaseline
    ? `Remove retained endpoint history only for ${agent.family ?? "this agent"} pid ${agent.pid}, start ${agent.started_at}`
    : "Select an agent with retained network history";
  let records = (session.data.network ?? []).filter(record =>
    (!agent || (record.agent_pid === agent.pid && record.agent_started_at === agent.started_at)) &&
    (view.networkDirection === "all" || record.direction === view.networkDirection) &&
    (!view.networkQuery || [record.host, record.port, record.verdict, record.agent_family].some(value => String(value ?? "").toLowerCase().includes(view.networkQuery.toLowerCase())))
  );
  records = sortedBy(records, view.networkSort, (record, col) => record[col]);
  $("networkCount").textContent = `${records.length} endpoint${records.length===1?"":"s"}${agent ? ` · pid ${agent.pid}` : " · bounded history"}`;
  if (!records.length) {
    host.replaceChildren(el("div", { className:"empty", textContent:agent ? "No matching network metadata for this agent instance." : "No network metadata observed yet." }));
    return;
  }
  const rows = records.map(record => {
    const alertLevel = record.alert_level ?? (record.verdict === "private_peer" ? "high" : record.verdict === "observed" ? "none" : "critical");
    const severity = alertLevel === "critical" ? "hot" : alertLevel === "high" ? "warn" : "";
    const owner = session.data.agents.find(item => item.pid === record.agent_pid && item.started_at === record.agent_started_at);
    const series = record.time_series ?? {patterns:[],retained_samples:0,warmup:"collecting",evidence:"socket_snapshot_visibility"};
    const baseline = record.baseline ?? {state:"collecting",warmup_samples:5,outside_baseline:false};
    const patternLabel = pattern => ({new_destination:"new destination",raw_ip_endpoint:"raw IP",nonstandard_port:"nonstandard port",repeated_snapshot_visibility:"repeated visibility",outside_baseline:"outside baseline"}[pattern] ?? pattern.replaceAll("_", " "));
    return el("tr", { className:`network-${alertLevel}` }, [
      el("td", {}, [el("div", { className:"mono" }, [`${record.host}:${record.port}`, record.first_seen_this_sweep ? el("span", { className:"flag", style:"margin-left:7px;color:var(--ac);background:var(--acbg)", textContent:"FIRST SEEN" }) : null]), el("div", { className:"faint", textContent:record.dns_name ? "DNS name observed" : "Raw IP · no DNS name in socket metadata" })]),
      el("td", { textContent:record.direction }),
      el("td", {}, el("span", { className:`net-verdict ${severity}`, textContent:record.verdict.replaceAll("_", " ") })),
      el("td", {}, [el("span", { className:"net-verdict", textContent:record.currently_observed === false ? "not in latest sweep" : "visible now" }), el("div", { className:"faint", style:"margin-top:5px", textContent:`${record.visibility_changes ?? 1} snapshot edge${(record.visibility_changes ?? 1)===1?"":"s"}` })]),
      el("td", {}, [series.patterns.length ? el("div", {}, series.patterns.map(pattern => el("span", { className:"flag", style:"margin:0 4px 4px 0", textContent:patternLabel(pattern) }))) : el("span", { className:"faint", textContent:"None" }), el("div", { className:"faint", style:"margin-top:5px", textContent:`${series.retained_samples} / ${series.max_samples ?? 64} samples · baseline ${baseline.state}`, title:`Detector ${series.detector_version ?? 1} · ${series.evidence} · seven-day endpoint retention · warm-up ${baseline.warmup_samples} samples · PID/start-time reset · patterns are metadata, not proof of intent` })]),
      el("td", {}, record.risk_points ? [el("span", { className:`net-verdict ${severity}`, textContent:`+${record.risk_points} risk` }), owner ? el("div", { className:"faint", style:"margin-top:5px", textContent:`agent ${owner.grade}` }) : null] : el("span", { className:"faint", textContent:"None" })),
      el("td", { className:"mono", textContent:String(record.observations), title:"Number of sweeps where this endpoint was visible; not a connection or request count" }),
      el("td", { className:"mono muted", textContent:clock(record.first_seen), title:new Date(record.first_seen).toString() }),
      el("td", { className:"mono muted", textContent:clock(record.last_seen), title:new Date(record.last_seen).toString() }),
      el("td", { className:"muted", textContent:record.bytes == null ? "Unavailable" : String(record.bytes), title:"Traffic volume for a retained endpoint; the kernel counts per connection, and this row spans a history of them" }),
    ]);
  });
  host.replaceChildren(makeTable("network", [
    {key:"host",label:"Endpoint",sortable:true}, {key:"direction",label:"Direction",sortable:true},
    {key:"verdict",label:"Rule verdict",sortable:true}, {key:"currently_observed",label:"Snapshot state",sortable:true}, {key:"patterns",label:"Time-series patterns",sortable:false}, {key:"risk_points",label:"Risk impact",sortable:true}, {key:"observations",label:"Observations",sortable:true,align:"right"},
    {key:"first_seen",label:"First seen",sortable:true}, {key:"last_seen",label:"Last seen",sortable:true},
    {key:"bytes",label:"Bytes",sortable:false},
  ], rows, {sort:view.networkSort,onSort:(col)=>changeSort("networkSort",col,renderNetwork)}));
}
