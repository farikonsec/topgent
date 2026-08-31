// What each sensor can see on this machine, and what it cannot.
//
// The most important panel in the product and the least exciting. Everything
// else is only as true as this: a sensor that is unavailable makes an empty
// panel mean nothing, and saying so is the difference between a monitor and a
// reassuring picture.

import { $, clock, el } from "../dom.mjs";
import { session, view } from "../state.mjs";
import { changeSort, makeTable, sortedBy } from "../table.mjs";

export function renderHealth() {
  const host = $("health");
  const sensors = session.data.sensors ?? [];
  const coverage = sortedBy(session.data.coverage ?? [], view.coverageSort, (entry, col) => entry[col]);
  const available = sensors.filter(sensor => sensor.state === "available").length;
  const covered = coverage.filter(entry => entry.state === "available").length;
  $("healthCount").textContent = `${available}/${sensors.length} sensors available · ${covered}/${coverage.length} rules live-capable · ${session.data.platform?.os ?? "unknown"}/${session.data.platform?.arch ?? "unknown"}`;
  if (!sensors.length) {
    host.replaceChildren(el("div", { className:"empty", textContent:"Sensor health was not reported by this build." }));
    return;
  }
  const out = document.createDocumentFragment();
  const grid = el("div", { className:"sensor-grid" });
  for (const sensor of sensors) grid.append(el("div", { className:"sensor-card" }, [
    el("div", { className:"sensor-head" }, [el("b", { className:"mono", textContent:sensor.id.replaceAll("_", " ") }), el("span", { className:`sensor-state ${sensor.state}`, textContent:sensor.state.replaceAll("_", " ") })]),
    el("div", { className:"muted", style:"margin-top:8px;font-size:11px", textContent:sensor.detail || `${sensor.fact_count} observations · ${sensor.duration_ms} ms` }),
    el("div", { className:"faint", style:"margin-top:7px;font-size:10px", textContent:`Permission: ${sensor.permission} · Last success: ${sensor.last_successful_sweep ? clock(sensor.last_successful_sweep) : "never"} · Dropped: ${sensor.dropped_events ?? "unknown"}` }),
    // A working sensor the platform only lets see part of the picture says so,
    // or a green row reads as coverage of something never provided.
    sensor.boundary ? el("div", { className:"faint", style:"margin-top:7px;font-size:10px;border-top:1px solid var(--bd);padding-top:6px", textContent:`Does not cover: ${sensor.boundary}` }) : null,
  ]));
  out.append(grid);

  // The binaries the sensors actually run. Resolving these through PATH would
  // let anything running as the user choose what Topgent reads, so each one is
  // bound to a location the operating system owns and what was found is shown.
  const tools = session.data.tools ?? [];
  if (tools.length) {
    const toolGrid = el("div", { className:"sensor-grid", style:"margin-top:10px" });
    for (const tool of tools) toolGrid.append(el("div", { className:"sensor-card" }, [
      el("div", { className:"sensor-head" }, [
        el("b", { className:"mono", textContent:tool.name }),
        el("span", { className:`sensor-state ${tool.state === "trusted" ? "available" : "permission_required"}`, textContent:tool.state }),
      ]),
      el("div", { className:"muted", style:"margin-top:8px;font-size:11px", textContent:tool.path ?? "not present at any accepted operating-system location; a copy elsewhere on PATH is deliberately not used" }),
      tool.changed_at ? el("div", { className:"faint", style:"margin-top:7px;font-size:10px", textContent:`Changed from ${tool.previous_state} at ${clock(tool.changed_at)}` }) : null,
    ]));
    out.append(el("div", { className:"faint", style:"margin-top:14px;font-size:10px", textContent:"SENSOR BINARIES" }), toolGrid);
  }

  // Whether an action can be stopped before it happens. A ladder offering Block
  // and Approval owes the operator the reason it cannot, rather than one flat
  // refusal that reads as "this product does not do that".
  const intercept = session.data.interception;
  if (intercept) {
    out.append(
      el("div", { className:"faint", style:"margin-top:14px;font-size:10px", textContent:"PRE-ACTION INTERCEPTION" }),
      el("div", { className:"sensor-grid", style:"margin-top:10px" }, el("div", { className:"sensor-card" }, [
        el("div", { className:"sensor-head" }, [
          el("b", { className:"mono", textContent:"interception" }),
          el("span", { className:`sensor-state ${intercept.state === "available" ? "available" : intercept.state === "privilege_required" ? "permission_required" : "unsupported"}`, textContent:intercept.state.replaceAll("_", " ") }),
        ]),
        el("div", { className:"muted", style:"margin-top:8px;font-size:11px", textContent:intercept.detail }),
      ]))
    );
  }

  const legend = new Map((session.data.legend ?? []).map(item => [item.code, item.description]));
  const rows = coverage.map(entry => el("tr", {}, [
    el("td", {}, [el("div", { className:"mono", textContent:entry.rule }), el("div", { className:"faint", textContent:legend.get(entry.rule) ?? "" })]),
    el("td", { className:"mono muted", textContent:entry.sensor.replaceAll("_", " ") }),
    el("td", {}, el("span", { className:`sensor-state ${entry.state}`, textContent:entry.state.replaceAll("_", " ") })),
    el("td", { textContent:entry.verification.replaceAll("_", " ") }),
    el("td", { className:"mono faint", textContent:entry.last_verified_at ? clock(entry.last_verified_at) : "Not live-canary verified" }),
  ]));
  out.append(makeTable("coverage", [
    {key:"rule",label:"Rule",sortable:true}, {key:"sensor",label:"Required sensor",sortable:true},
    {key:"state",label:"Current state",sortable:true}, {key:"verification",label:"Test level",sortable:true},
    {key:"last_verified_at",label:"Last live canary",sortable:true},
  ], rows, {sort:view.coverageSort,onSort:(col)=>changeSort("coverageSort",col,renderHealth)}));
  host.replaceChildren(out);
}
