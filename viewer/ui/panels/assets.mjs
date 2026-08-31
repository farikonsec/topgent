// The typed inventory: agents, models, tools and endpoints.
//
// The same identities that appear in the exported bill of materials, so what
// is on screen and what goes to CI cannot disagree.

import { app } from "../app-hooks.mjs";
import { $, el } from "../dom.mjs";
import { session, toast, view } from "../state.mjs";
import { changeSort, makeTable, sortedBy } from "../table.mjs";
import { invoke } from "../transport.mjs";

export function renderAssets() {
  const host = $("assets");
  const selectedAgent = session.data.agents.find(agent => agent.pid === session.selected);
  const relationships = (session.data.relationships ?? []).filter(link => !selectedAgent || link.agent_pid === selectedAgent.pid);
  const relationshipByTarget = new Map(relationships.map(link => [link.to, link]));
  if (selectedAgent) relationshipByTarget.set(selectedAgent.asset_id, {
    to:selectedAgent.asset_id, kind:"running_as", agent_pid:selectedAgent.pid,
    agent_family:selectedAgent.family ?? "unclassified",
    disposition:selectedAgent.asset_disposition ?? "unreviewed",
  });
  let assets = (session.data.assets ?? []).filter(asset => !selectedAgent || relationshipByTarget.has(asset.id));
  assets = assets.filter(asset =>
    (view.assetKind === "all" || asset.kind === view.assetKind) &&
    (!view.assetQuery || [asset.name, asset.kind, asset.id, asset.source].some(value => String(value ?? "").toLowerCase().includes(view.assetQuery.toLowerCase()))));
  assets = sortedBy(assets, view.assetSort, (asset, col) => {
    if (col === "relationship") return relationshipByTarget.get(asset.id)?.kind ?? "";
    if (col === "disposition") return relationshipByTarget.get(asset.id)?.disposition ?? asset.disposition;
    return asset[col];
  });
  $("assetCount").textContent = `${assets.length} asset${assets.length===1?"":"s"}${selectedAgent ? ` · ${selectedAgent.family ?? "agent"}` : ""}`;
  if (!assets.length) {
    host.replaceChildren(el("div", { className:"empty", textContent:selectedAgent ? "No matching assets are connected to this agent." : "No AI assets discovered yet." }));
    return;
  }
  const rows = assets.map(asset => {
    const link = relationshipByTarget.get(asset.id);
    const effective = link?.disposition ?? asset.disposition ?? "unreviewed";
    const state = el("select", { className:"btn quiet asset-state", title:"Set the expected state for this asset" });
    for (const value of ["unreviewed","approved","restricted","disallowed"]) state.append(el("option", { value, textContent:value[0].toUpperCase()+value.slice(1) }));
    state.value = effective;
    state.dataset.state = effective;
    state.onchange = async () => {
      state.disabled = true;
      const result = await invoke("set_asset_disposition", {
        asset_id:asset.id,
        agent_family:selectedAgent?.family ?? null,
        disposition:state.value,
      });
      if (!result?.ok) { toast(result?.message || "Asset policy could not be saved"); state.value = effective; }
      state.blur();
      await app.poll(true);
    };
    return el("tr", {}, [
      el("td", {}, [el("div", { textContent:asset.name, style:"font-weight:500" }), el("div", { className:"mono faint", textContent:asset.id })]),
      el("td", { textContent:asset.kind }),
      el("td", { className:"muted", textContent:(link?.kind ?? (asset.kind === "agent" ? "discovered" : "—")).replaceAll("_", " ") }),
      el("td", { className:"muted", textContent:asset.confidence }),
      el("td", {}, state),
    ]);
  });
  host.replaceChildren(makeTable("assets", [
    {key:"name",label:"Asset",sortable:true}, {key:"kind",label:"Type",sortable:true},
    {key:"relationship",label:"Relationship",sortable:true}, {key:"confidence",label:"Evidence",sortable:true},
    {key:"disposition",label:"Policy state",sortable:true},
  ], rows, {sort:view.assetSort,onSort:(col)=>changeSort("assetSort",col,renderAssets)}));
}
