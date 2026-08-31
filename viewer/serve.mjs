// Development server for the Topgent viewer.
//
// NOT part of the product. The shipping desktop app opens no listening socket
// at all — its UI talks to the core in-process — and that is deliberate: a port
// is a thing an attacker can reach, and a port that can stop processes is worth
// reaching. This exists so the same data can be looked at in a browser while
// the desktop shell is being built.
//
// What it does to stay honest about that:
//   - binds 127.0.0.1 only, never 0.0.0.0
//   - checks the Host header, so a hostile page cannot reach it by rebinding DNS
//   - requires a per-run token on anything that changes something
//   - shells out to the `topgent` binary rather than reimplementing any of it,
//     so every guard in topgent-enforce still applies
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { extname, join, normalize } from "node:path";
import { promisify } from "node:util";

const run = promisify(execFile);
// The dev server serves exactly what the desktop app bundles, so a page that
// works here is the page that ships. Fixtures and this server live one level
// up and are never reachable from it.
const UI = new URL("ui/", import.meta.url).pathname;
const REPO = join(UI, "..", "..");
const PORT = Number(process.env.PORT ?? 4173);
const TOKEN = randomBytes(16).toString("hex");
const ALLOWED_HOSTS = new Set([`127.0.0.1:${PORT}`, `localhost:${PORT}`]);
const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".json": "application/json",
  ".js": "text/javascript",
  ".mjs": "text/javascript",
  ".css": "text/css",
};

const BIN = join(REPO, "target", "debug", "topgent");

async function topgent(args) {
  const { stdout } = await run(BIN, args, { maxBuffer: 32 * 1024 * 1024 });
  return stdout;
}

function send(res, code, type, body) {
  res.writeHead(code, {
    "content-type": type,
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "content-security-policy":
      "default-src 'none'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
      "font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; connect-src 'self'",
  });
  res.end(body);
}

const server = createServer(async (req, res) => {
  if (!ALLOWED_HOSTS.has(req.headers.host ?? "")) {
    return send(res, 403, "text/plain", "bad host");
  }
  const url = new URL(req.url ?? "/", `http://${req.headers.host}`);

  if (url.pathname === "/api/state") {
    try {
      const body = await topgent(["--json"]);
      return send(res, 200, "application/json", body);
    } catch (e) {
      return send(res, 500, "application/json", JSON.stringify({ error: String(e) }));
    }
  }

  if (url.pathname === "/api/export/cyclonedx") {
    try {
      const body = await topgent(["export", "cyclonedx"]);
      return send(res, 200, "application/json", body);
    } catch (e) {
      return send(res, 500, "application/json", JSON.stringify({ error: String(e) }));
    }
  }

  if (url.pathname === "/api/export/aibom.html") {
    try {
      const body = await topgent(["export", "cyclonedx", "--format", "html"]);
      return send(res, 200, "text/html; charset=utf-8", body);
    } catch (e) {
      return send(res, 500, "application/json", JSON.stringify({ error: String(e) }));
    }
  }

  if (url.pathname === "/api/rule" && req.method === "POST") {
    if (req.headers["x-topgent-token"] !== TOKEN) return send(res, 403, "application/json", JSON.stringify({ error: "bad token" }));
    let body = ""; for await (const c of req) body += c;
    let j; try { j = JSON.parse(body || "{}"); } catch { return send(res, 400, "application/json", JSON.stringify({ error: "bad json" })); }
    try {
      if (j.response != null && j.index != null) { await topgent(["rule", "response", String(j.index), String(j.response)]); }
      else if (j.remove != null) { await topgent(["rule", "remove", String(j.remove)]); }
      else { await topgent(["rule", "add", String(j.path), String(j.condition), String(j.severity)]); }
      return send(res, 200, "application/json", JSON.stringify({ ok: true }));
    } catch (e) { return send(res, 500, "application/json", JSON.stringify({ ok: false, message: String(e) })); }
  }

  if (url.pathname === "/api/asset" && req.method === "POST") {
    if (req.headers["x-topgent-token"] !== TOKEN) return send(res, 403, "application/json", JSON.stringify({ error: "bad token" }));
    let body = ""; for await (const c of req) body += c;
    let j; try { j = JSON.parse(body || "{}"); } catch { return send(res, 400, "application/json", JSON.stringify({ error: "bad json" })); }
    try {
      const args = ["asset", "set", String(j.asset_id), String(j.disposition)];
      if (j.agent_family) args.push("--agent", String(j.agent_family));
      const output = JSON.parse(await topgent(args));
      return send(res, output.ok ? 200 : 400, "application/json", JSON.stringify(output));
    } catch (e) { return send(res, 500, "application/json", JSON.stringify({ ok: false, message: String(e) })); }
  }

  if (url.pathname === "/api/context" && req.method === "POST") {
    if (req.headers["x-topgent-token"] !== TOKEN) return send(res, 403, "application/json", JSON.stringify({ error:"bad token" }));
    let body = ""; for await (const c of req) body += c;
    let j; try { j = JSON.parse(body || "{}"); } catch { return send(res, 400, "application/json", JSON.stringify({ error:"bad json" })); }
    try {
      const args = j.clear ? ["context", "clear"] : ["context", j.enabled ? "enable" : "disable"];
      const output = JSON.parse(await topgent(args));
      return send(res, output.ok ? 200 : 400, "application/json", JSON.stringify(output));
    } catch (e) { return send(res, 500, "application/json", JSON.stringify({ ok:false, message:String(e) })); }
  }

  if (url.pathname === "/api/network/baseline/reset" && req.method === "POST") {
    if (req.headers["x-topgent-token"] !== TOKEN) return send(res, 403, "application/json", JSON.stringify({ error:"bad token" }));
    let body = ""; for await (const c of req) body += c;
    let j; try { j = JSON.parse(body || "{}"); } catch { return send(res, 400, "application/json", JSON.stringify({ error:"bad json" })); }
    if (!Number.isSafeInteger(j.pid) || j.pid < 1 || !Number.isSafeInteger(j.started_at) || j.started_at < 1) {
      return send(res, 400, "application/json", JSON.stringify({ ok:false, message:"pid and started_at must be positive integers" }));
    }
    try {
      const output = JSON.parse(await topgent(["network", "baseline", "reset", String(j.pid), String(j.started_at), "--yes"]));
      return send(res, output.ok ? 200 : 409, "application/json", JSON.stringify(output));
    } catch (e) {
      const message = (e.stdout || e.stderr || e.message || "").trim();
      try { return send(res, 409, "application/json", JSON.stringify(JSON.parse(message))); }
      catch { return send(res, 500, "application/json", JSON.stringify({ ok:false, message })); }
    }
  }

  if (url.pathname === "/api/approval/resolve" && req.method === "POST") {
    if (req.headers["x-topgent-token"] !== TOKEN) return send(res, 403, "application/json", JSON.stringify({ error:"bad token" }));
    let body = ""; for await (const c of req) body += c;
    let j; try { j = JSON.parse(body || "{}"); } catch { return send(res, 400, "application/json", JSON.stringify({ error:"bad json" })); }
    if (typeof j.request_id !== "string" || !j.request_id.startsWith("approval-") || !Number.isSafeInteger(j.pid) || j.pid < 1 || !Number.isSafeInteger(j.started_at) || j.started_at < 1 || typeof j.approve !== "boolean") {
      return send(res, 400, "application/json", JSON.stringify({ ok:false, message:"request_id, pid, started_at and approve are required" }));
    }
    const args = ["approval", "resolve", j.request_id, String(j.pid), String(j.started_at), j.approve ? "approve" : "deny"];
    if (j.approve) args.push("--yes");
    try {
      const output = JSON.parse(await topgent(args));
      return send(res, output.ok ? 200 : 409, "application/json", JSON.stringify(output));
    } catch (e) {
      const message = (e.stdout || e.stderr || e.message || "").trim();
      try { return send(res, 409, "application/json", JSON.stringify(JSON.parse(message))); }
      catch { return send(res, 500, "application/json", JSON.stringify({ ok:false, message })); }
    }
  }

  if (url.pathname.startsWith("/api/stop/")) {
    if (req.method !== "POST") return send(res, 405, "text/plain", "post only");
    if (req.headers["x-topgent-token"] !== TOKEN) {
      return send(res, 403, "application/json", JSON.stringify({ error: "bad token" }));
    }
    const pid = url.pathname.slice("/api/stop/".length);
    if (!/^\d+$/.test(pid)) {
      return send(res, 400, "application/json", JSON.stringify({ error: "pid must be a number" }));
    }
    try {
      const out = await topgent(["stop", pid, "--yes"]);
      return send(res, 200, "application/json", JSON.stringify({ ok: true, message: out.trim() }));
    } catch (e) {
      const msg = (e.stderr || e.message || "").trim();
      return send(res, 409, "application/json", JSON.stringify({ ok: false, message: msg }));
    }
  }

  const rel = normalize(decodeURIComponent(url.pathname));
  if (rel.includes("..")) return send(res, 400, "text/plain", "no");
  const file = join(UI, rel === "/" ? "index.html" : rel);
  try {
    let body = await readFile(file);
    if (extname(file) === ".html") {
      body = body.toString().replace("__TOPGENT_TOKEN__", TOKEN);
    }
    return send(res, 200, TYPES[extname(file)] ?? "application/octet-stream", body);
  } catch {
    return send(res, 404, "text/plain", "not found");
  }
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`topgent viewer: http://127.0.0.1:${PORT}`);
  console.log(`binary: ${BIN}`);
  console.log("local testing surface: loopback only; press Ctrl-C to stop");
});
