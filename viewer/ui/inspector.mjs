// The inspector: one slide-in panel that shows the detail of a selected row.
//
// The table stays terse — a row is a glance. Everything else (the plain-English
// meaning, the honest context, the evidence grid, the actions) lives here and
// opens only when a row is chosen. One panel, reused by every view, so detail
// is presented the same way everywhere.

import { $, el } from "./dom.mjs";

let onClose = null;

/**
 * Open the inspector.
 * @param {object} d
 *  title: string            technical name (the reference)
 *  sevLabel, sevClass       severity chip text + class (e.g. "WARNING","med")
 *  plain: string            short plain-English line, shown first
 *  context?: string         longer honest context, optional
 *  rows: [label, value, mono?][]   the evidence grid
 *  actions?: {label, kind, on}[]   buttons
 */
export function openInspector(d) {
  const host = $("inspector");
  host.textContent = "";
  const head = el("div", { className: "ins-head" }, [
    el("div", { className: "ins-title" }, [
      d.sevLabel ? el("span", { className: `sev ${d.sevClass || ""}`, textContent: d.sevLabel }) : "",
      el("span", { textContent: d.title || "" }),
    ]),
    el("button", { className: "ins-x", textContent: "×", title: "Close", onclick: closeInspector }),
  ]);
  host.append(head);
  if (d.plain) host.append(el("div", { className: "ins-plain", textContent: d.plain }));
  if (d.context && d.context !== d.plain) host.append(el("div", { className: "ins-ctx", textContent: d.context }));
  const body = el("div", { className: "ins-body" });
  for (const [label, value, mono] of (d.rows || [])) {
    if (value === undefined || value === null || value === "") continue;
    body.append(el("div", { className: "ins-row" }, [
      el("div", { className: "ins-l", textContent: label }),
      el("div", { className: "ins-v" + (mono ? " mono" : ""), textContent: String(value) }),
    ]));
  }
  host.append(body);
  if ((d.actions || []).length) {
    const actions = el("div", { className: "ins-actions" });
    for (const a of d.actions) {
      actions.append(el("button", { className: "btn " + (a.kind || ""), textContent: a.label, onclick: a.on || (() => {}) }));
    }
    host.append(actions);
  }
  host.classList.add("open");
  host.setAttribute("aria-hidden", "false");
  $("inspectorScrim").classList.add("on");
  onClose = d.onClose || null;
}

export function closeInspector() {
  const host = $("inspector");
  host.classList.remove("open");
  host.setAttribute("aria-hidden", "true");
  $("inspectorScrim").classList.remove("on");
  const cb = onClose; onClose = null;
  if (cb) cb();
}

/** Wire the scrim and Escape once, from app start-up. */
export function initInspector() {
  const scrim = $("inspectorScrim");
  if (scrim && !scrim.dataset.wired) {
    scrim.dataset.wired = "1";
    scrim.addEventListener("click", closeInspector);
    document.addEventListener("keydown", e => { if (e.key === "Escape") closeInspector(); });
  }
}
