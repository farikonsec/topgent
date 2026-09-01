// One table builder for every panel.
//
// Sortable and resizable, with both stored in the view so a layout survives a
// reload. Rows are built from values, never from markup, so a hostile process
// name is text in a cell and nothing more.

import { $, el } from "./dom.mjs";
import { save, view } from "./state.mjs";

export function makeTable(key, columns, rows, opts = {}) {
  const table = el("table");
  const thead = el("thead"); const htr = el("tr");
  const sort = opts.sort;
  for (const c of columns) {
    const th = el("th", { textContent: c.label });
    if (c.align === "right") th.style.textAlign = "right";
    if (c.sortable) {
      th.classList.add("sortable");
      if (sort && sort.col === c.key) {
        th.setAttribute("aria-sort", sort.dir < 0 ? "descending" : "ascending");
        th.append(" ", el("span", { className: "arrow", textContent: sort.dir < 0 ? "▼" : "▲" }));
      }
      th.onclick = (e) => { if (e.target.classList.contains("grip")) return; opts.onSort?.(c.key); };
    }
    const w = view.widths[`${key}.${c.key}`];
    if (w) th.style.width = w + "px";
    const grip = el("span", { className: "grip" });
    grip.onmousedown = (e) => startResize(e, key, c.key, th);
    th.append(grip);
    htr.append(th);
  }
  thead.append(htr); table.append(thead);
  const tb = el("tbody");
  for (const r of rows) {
    if (!(r instanceof HTMLTableRowElement)) throw new TypeError(`${key} table row must be a <tr>`);
    tb.append(r);
  }
  table.append(tb);
  return table;
}

export function sortedBy(items, sort, value) {
  return [...items].sort((a, b) => {
    const left = value(a, sort.col), right = value(b, sort.col);
    if (typeof left === "number" && typeof right === "number") return (left - right) * sort.dir;
    return String(left ?? "").localeCompare(String(right ?? ""), undefined, { numeric:true, sensitivity:"base" }) * sort.dir;
  });
}

export function changeSort(name, col, renderFn) {
  const current = view[name];
  view[name] = { col, dir:current.col === col ? -current.dir : 1 };
  save(); renderFn();
}

let resizing = null;
export function startResize(e, key, col, th) {
  e.preventDefault(); e.stopPropagation();
  resizing = { key, col, startX: e.clientX, startW: th.getBoundingClientRect().width, th };
  document.body.style.cursor = "col-resize";
}
window.addEventListener("mousemove", (e) => {
  if (!resizing) return;
  const w = Math.max(60, Math.round(resizing.startW + (e.clientX - resizing.startX)));
  resizing.th.style.width = w + "px";
  view.widths[`${resizing.key}.${resizing.col}`] = w;
});
window.addEventListener("mouseup", () => { if (resizing) { save(); resizing = null; document.body.style.cursor = ""; } });

// ---- agents ----
