// Talking to Topgent, from either side of the same interface.
//
// In the desktop app the core is in-process and reached over Tauri's IPC. In
// the development viewer it is a local HTTP server holding a token this page
// was handed at load. Neither path opens a network port: the app has none, and
// the dev server binds loopback only.

const TOKEN = document.querySelector('meta[name="topgent-token"]')?.content || "";
const tauri = window.__TAURI__?.core?.invoke;

/** True in the desktop app, false in the development viewer. */
export const inDesktopApp = Boolean(tauri);
export async function invoke(cmd, args) {
  if (tauri) return tauri(cmd, args);
  if (cmd === "scan") return (await fetch("/api/state", { cache: "no-store" })).json();
  if (cmd === "stop") {
    return (await fetch(`/api/stop/${args.pid}`, { method: "POST", headers: { "x-topgent-token": TOKEN } })).json();
  }
  if (cmd === "add_rule" || cmd === "remove_rule" || cmd === "set_rule_response") {
    const body = cmd === "remove_rule" ? { remove: args.index } : cmd === "set_rule_response" ? { index:args.index, response:args.response } : args;
    return (await fetch("/api/rule", { method: "POST", headers: { "x-topgent-token": TOKEN, "content-type": "application/json" }, body: JSON.stringify(body) })).json();
  }
  if (cmd === "set_asset_disposition") {
    return (await fetch("/api/asset", { method: "POST", headers: { "x-topgent-token": TOKEN, "content-type": "application/json" }, body: JSON.stringify(args) })).json();
  }
  if (cmd === "set_semantic_enabled" || cmd === "clear_semantic_context") {
    return (await fetch("/api/context", { method:"POST", headers:{ "x-topgent-token":TOKEN, "content-type":"application/json" }, body:JSON.stringify(cmd === "set_semantic_enabled" ? { enabled:args.enabled } : { clear:true }) })).json();
  }
  if (cmd === "reset_network_baseline") {
    const response = await fetch("/api/network/baseline/reset", { method:"POST", headers:{ "x-topgent-token":TOKEN, "content-type":"application/json" }, body:JSON.stringify({ pid:args.pid, started_at:args.startedAt }) });
    const result = await response.json();
    if (!response.ok && !result.message) throw new Error(`HTTP ${response.status}`);
    return result;
  }
  if (cmd === "resolve_termination_approval") {
    const response = await fetch("/api/approval/resolve", { method:"POST", headers:{ "x-topgent-token":TOKEN, "content-type":"application/json" }, body:JSON.stringify({ request_id:args.requestId, pid:args.pid, started_at:args.startedAt, approve:args.approve }) });
    const result = await response.json();
    if (!response.ok && !result.message) throw new Error(`HTTP ${response.status}`);
    return result;
  }
  if (cmd === "export_cyclonedx") return (await fetch("/api/export/cyclonedx", { cache:"no-store" })).json();
  if (cmd === "export_aibom_html") {
    const response = await fetch("/api/export/aibom.html", { cache:"no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return response.text();
  }
}
