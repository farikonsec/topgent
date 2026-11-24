import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer, request } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

async function freePort() {
  const socket = createServer();
  await new Promise((resolve, reject) => {
    socket.once("error", reject);
    socket.listen(0, "127.0.0.1", resolve);
  });
  const { port } = socket.address();
  await new Promise((resolve, reject) => socket.close(error => error ? reject(error) : resolve()));
  return port;
}

function requestWithHost(port, host) {
  return new Promise((resolve, reject) => {
    const req = request({ hostname:"127.0.0.1", port, path:"/", headers:{ host } }, response => {
      let body = "";
      response.setEncoding("utf8");
      response.on("data", chunk => body += chunk);
      response.on("end", () => resolve({ status:response.statusCode, body }));
    });
    req.once("error", reject);
    req.end();
  });
}

test("development server uses the configured binary and rejects foreign Host headers", async t => {
  const directory = await mkdtemp(join(tmpdir(), "topgent-viewer-"));
  const binary = join(directory, "fake-topgent");
  await writeFile(binary, "#!/bin/sh\nprintf '{\"version\":\"isolated-test\",\"agents\":[]}\\n'\n");
  await chmod(binary, 0o700);
  t.after(() => rm(directory, { recursive:true, force:true }));

  const port = await freePort();
  const child = spawn(process.execPath, [new URL("serve.mjs", import.meta.url).pathname], {
    env:{ ...process.env, PORT:String(port), TOPGENT_BIN:binary },
    stdio:["ignore", "pipe", "pipe"],
  });
  t.after(() => child.kill("SIGTERM"));

  await new Promise((resolve, reject) => {
    let output = "";
    const timer = setTimeout(() => reject(new Error(`server did not start: ${output}`)), 5_000);
    child.once("error", reject);
    child.stderr.on("data", chunk => output += chunk);
    child.stdout.on("data", chunk => {
      output += chunk;
      if (output.includes("topgent viewer:")) { clearTimeout(timer); resolve(); }
    });
  });

  const state = await fetch(`http://127.0.0.1:${port}/api/state`).then(response => response.json());
  assert.deepEqual(state, { version:"isolated-test", agents:[] });

  const page = await fetch(`http://127.0.0.1:${port}/`).then(async response => ({ status:response.status, csp:response.headers.get("content-security-policy"), body:await response.text() }));
  assert.equal(page.status, 200);
  assert.match(page.body, /<title>Topgent<\/title>/);
  assert.doesNotMatch(page.body, /__TOPGENT_TOKEN__/);
  assert.match(page.csp, /img-src 'self'/);

  const icon = await fetch(`http://127.0.0.1:${port}/icon.svg`).then(async response => ({ status:response.status, type:response.headers.get("content-type"), body:await response.text() }));
  assert.equal(icon.status, 200);
  assert.equal(icon.type, "image/svg+xml");
  assert.match(icon.body, /aria-label="Topgent"/);

  const rejected = await requestWithHost(port, "attacker.example");
  assert.equal(rejected.status, 403);
  assert.equal(rejected.body, "bad host");

  const forwarded = await requestWithHost(port, `127.0.0.1:${port + 1}`);
  assert.equal(forwarded.status, 200);
  assert.match(forwarded.body, /<title>Topgent<\/title>/);
});
