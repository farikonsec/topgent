// Coverage: can I trust this monitor on this host, and what am I blind to?
//
// Read relative to the host OS. A detection this platform cannot do by design
// is "not applicable", not "broken" — so macOS is not punished for lacking
// Linux Audit. The score counts only what applies here; the gaps that CAN be
// fixed say how.

import { $, clock, el } from "../dom.mjs";
import { session } from "../state.mjs";
import { openInspector } from "../inspector.mjs";
import { incidentCoverage } from "./incidents.mjs";
import { ruleState } from "./behaviour.mjs";
import { makeTable } from "../table.mjs";

const LIVE = new Set(["available"]);
const NA = new Set(["unsupported", "not_applicable", "unavailable"]);
const cls = state => (LIVE.has(state) ? "live" : NA.has(state) ? "na" : "needs");
const STATE_LABEL = { live: "Live", needs: "Needs a fix", na: "Not applicable here" };

// A short step for the gaps a host can actually close.
const FIX = {
  permission_required: "Grant this sensor permission, then re-run.",
  privilege_required: "Run Topgent with the privilege this sensor needs.",
  degraded: "Sensor is degraded on this host; some activity may be missed.",
  loss_observed: "Sensor reported drops; give it more buffer or reduce load.",
  snapshot_only: "Only sweep snapshots here; short-lived activity can be missed.",
};
const fixFor = state => FIX[state] ?? "Needs attention on this host.";

function tile(label, value, tone) {
  return el("div", { className: `cov-tile${tone ? " " + tone : ""}` }, [
    el("div", { className: "cov-tile-v", textContent: value }),
    el("div", { className: "cov-tile-l", textContent: label }),
  ]);
}

function gauge(live, applicable) {
  const pct = applicable ? Math.round((live / applicable) * 100) : 0;
  const tone = pct >= 90 ? "live" : pct >= 60 ? "warn" : "bad";
  return el("div", { className: "cov-gauge" }, [
    el("div", { className: "cov-gauge-head" }, [
      el("span", { className: "cov-gauge-n", textContent: `${live} / ${applicable}` }),
      el("span", { className: "cov-gauge-l", textContent: "applicable detections live" }),
      el("span", { className: `cov-gauge-p ${tone}`, textContent: `${pct}%` }),
    ]),
    el("div", { className: "cov-bar" }, el("div", { className: `cov-bar-fill ${tone}`, style: `width:${pct}%` })),
  ]);
}

export function renderHealth() {
  const host = $("health");
  const d = session.data;
  const os = d.platform?.os ?? "unknown";
  const arch = d.platform?.arch ?? "unknown";
  const kernel = d.deployment?.kernel;
  const sensors = d.sensors ?? [];
  const coverage = d.coverage ?? [];
  const intercept = d.interception ?? {};
  const policy = d.policy_health ?? {};

  const tally = { live: 0, needs: 0, na: 0 };
  for (const c of coverage) tally[cls(c.state)]++;
  const applicable = tally.live + tally.needs;
  const sensorsUp = sensors.filter(s => LIVE.has(s.state)).length;
  const policyOk = !["malformed", "recovered"].includes(policy.state);

  $("healthCount").textContent = `${os} ${arch} · ${tally.live}/${applicable} live · ${sensorsUp}/${sensors.length} sensors`;

  const out = document.createDocumentFragment();

  // Host + trust tiles.
  out.append(el("div", { className: "cov-host" }, [
    el("span", { className: "cov-oschip", textContent: `${os} · ${arch}` }),
    kernel ? el("span", { className: "faint", textContent: `kernel ${kernel}` }) : null,
  ]));
  out.append(gauge(tally.live, applicable));
  out.append(el("div", { className: "cov-tiles" }, [
    tile("Sensors up", `${sensorsUp}/${sensors.length}`, sensorsUp === sensors.length ? "live" : "warn"),
    tile("Prevention", (intercept.state || "unknown").replaceAll("_", " "), LIVE.has(intercept.state) ? "live" : "warn"),
    tile("Policy", policyOk ? "in force" : "not in force", policyOk ? "live" : "bad"),
    tile("Not applicable here", String(tally.na), ""),
  ]));

  // Gaps first: the fixable ones, worst signal at the top.
  const gaps = sensors.filter(s => cls(s.state) === "needs");
  if (gaps.length) {
    out.append(el("div", { className: "cov-section", textContent: "Needs a fix" }));
    for (const s of gaps) out.append(gapRow(s, coverage));
  }

  // Capabilities: one row per sensor, drill to its rules and limits.
  out.append(el("div", { className: "cov-section", textContent: "Capabilities" }));
  for (const s of sensors) out.append(capabilityRow(s, coverage));

  // What the Incidents page watches for: workspace exfiltration and the named
  // behaviour incidents, each with how many of its rules can fire here. This is
  // detection capability, so it lives here, not above the incidents themselves.
  const incCov = incidentCoverage(session.data);
  if (incCov) {
    out.append(el("div", { className: "cov-section", textContent: "Incident coverage" }));
    out.append(el("div", { className: "context-note", textContent: "What the Incidents page can raise on this host. An incident whose rules cannot fire here is not being watched for." }));
    out.append(incCov);
  }

  // The complete runtime catalogue belongs here, beside sensor and product
  // coverage, rather than under findings in Behaviour.
  const catalogue = d.behaviour?.catalogue ?? {};
  const rules = [...(catalogue.coverage ?? [])].sort((a, b) =>
    Number(!a.live) - Number(!b.live) ||
    String(a.needs?.[0] ?? "").localeCompare(String(b.needs?.[0] ?? "")) ||
    a.rule.localeCompare(b.rule));
  out.append(el("div", { className: "cov-section", textContent: `Runtime rules · ${Math.min(catalogue.live ?? 0, catalogue.rules ?? 0)} / ${catalogue.rules ?? 0} can fire here` }));
  out.append(el("div", { className: "context-note", textContent: "The 95-rule runtime catalogue is separate from the 20 product risk factors above. Unavailable rules are grouped by their first missing field; open a row to see every missing field." }));
  if (rules.length) out.append(makeTable("coverage-rules", [
    {key:"rule",label:"RULE"}, {key:"priority",label:"SEVERITY"},
    {key:"state",label:"STATE"}, {key:"missing",label:"MISSING FIELD GROUP"},
  ], rules.map(rule => {
    const tr = el("tr", {className:"clickable"}, [
      el("td", {}, [el("div", {className:"rn", textContent:rule.rule}), el("div", {className:"rp", textContent:rule.summary || rule.desc})]),
      el("td", {textContent:rule.priority}), el("td", {textContent:ruleState(rule)}),
      el("td", {className:"mono", textContent:rule.needs?.[0] ?? "None"}),
    ]);
    tr.onclick = () => openInspector({title:rule.rule, sevLabel:rule.priority, plain:rule.summary || rule.desc, rows:[["state",ruleState(rule)],["fields this host lacks",(rule.needs ?? []).join(", ") || "None"]]});
    return tr;
  })));

  if (!sensors.length) out.append(el("div", { className: "empty", textContent: "No sensors reported." }));
  host.replaceChildren(out);
}

function rulesFor(sensor, coverage) {
  return coverage.filter(c => c.sensor === sensor.id);
}

function gapRow(sensor, coverage) {
  const row = el("div", { className: "cov-row cov-gap clickable" }, [
    el("span", { className: "cov-dot needs" }),
    el("div", { className: "cov-row-main" }, [
      el("div", { className: "cov-row-name", textContent: sensor.id.replaceAll("_", " ") }),
      el("div", { className: "cov-row-sub", textContent: fixFor(sensor.state) }),
    ]),
    el("span", { className: "cov-count", textContent: `${rulesFor(sensor, coverage).length} rules` }),
  ]);
  row.onclick = () => inspectSensor(sensor, coverage);
  return row;
}

function capabilityRow(sensor, coverage) {
  const state = cls(sensor.state);
  const row = el("div", { className: "cov-row clickable" }, [
    el("span", { className: `cov-dot ${state}` }),
    el("div", { className: "cov-row-main" }, [
      el("div", { className: "cov-row-name", textContent: sensor.id.replaceAll("_", " ") }),
      el("div", { className: "cov-row-sub", textContent: STATE_LABEL[state] + (sensor.boundary ? ` · ${sensor.boundary}` : "") }),
    ]),
    el("span", { className: "cov-count", textContent: `${rulesFor(sensor, coverage).length} rules` }),
  ]);
  row.onclick = () => inspectSensor(sensor, coverage);
  return row;
}

function inspectSensor(sensor, coverage) {
  const state = cls(sensor.state);
  const rules = rulesFor(sensor, coverage);
  const liveRules = rules.filter(r => cls(r.state) === "live").length;
  openInspector({
    title: sensor.id.replaceAll("_", " "),
    sevLabel: STATE_LABEL[state],
    sevClass: state === "live" ? "low" : state === "needs" ? "high" : "",
    plain: state === "needs" ? fixFor(sensor.state)
      : state === "na" ? "This platform cannot run this sensor; its rules are not counted against coverage."
      : "Running and feeding detections on this host.",
    context: sensor.boundary ? `Does not cover: ${sensor.boundary}` : "",
    rows: [
      ["state", sensor.state.replaceAll("_", " ")],
      ["permission", sensor.permission],
      ["rules backed", `${liveRules} live of ${rules.length}`],
      ["observations", sensor.fact_count == null ? undefined : String(sensor.fact_count)],
      ["last success", sensor.last_successful_sweep ? clock(sensor.last_successful_sweep) : "never"],
      ["dropped", sensor.dropped_events == null ? "unknown" : String(sensor.dropped_events)],
      ["detail", sensor.detail],
    ],
  });
}
