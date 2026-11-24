import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

globalThis.localStorage = { getItem:()=>null, setItem(){} };
globalThis.document = { getElementById:()=>({}), querySelectorAll:()=>[] };
globalThis.window = { addEventListener(){} };

const root = new URL("..", import.meta.url).pathname;
const viewer = dirname(fileURLToPath(import.meta.url));
const { WORKSPACES, AGENT_TABS } = await import("./ui/state.mjs");
const { ruleState, behaviourSummary } = await import("./ui/panels/behaviour.mjs");
const { actionLabel, actionMeaning } = await import("./ui/panels/actions.mjs");
const { processName, processStateMeaning } = await import("./ui/panels/processes.mjs");
const { DENSITIES, REFRESHES } = await import("./ui/panels/settings.mjs");

test("web navigation uses the desktop workspace and tab wording one for one", () => {
  assert.deepEqual(WORKSPACES.map(row=>row[1]), ["Incidents","Agents","Network","Event log","Behaviour","Assets","Rules & response","Session context","Coverage","Settings"]);
  assert.deepEqual(AGENT_TABS.map(row=>row[1]), ["Overview","Access","Blast radius","Activity","Network","Processes","Actions","Files","Behaviour"]);
  const shell=join(root,"crates/topgent-ui/src/shell.rs"), agents=join(root,"crates/topgent-ui/src/agents.rs");
  if (existsSync(shell) && existsSync(agents)) {
    const desktop = readFileSync(shell,"utf8") + readFileSync(agents,"utf8");
    const normalized = desktop.replace(/\\\s*\n\s*/g, "").replace(/\s+/g, " ");
    for (const [,label,description] of WORKSPACES) { assert.ok(desktop.includes(label)); assert.ok(normalized.includes(description)); }
    for (const [,label] of AGENT_TABS) assert.ok(desktop.includes(label), `desktop is missing ${label}`);
  }
});

test("web brand uses the exact desktop product mark and wordmark", () => {
  const webIcon = readFileSync(join(viewer,"ui/icon.svg"),"utf8");
  const html = readFileSync(join(viewer,"ui/index.html"),"utf8");
  assert.match(webIcon,/aria-label="Topgent"/);
  assert.match(html,/rel="icon" href="icon\.svg"/);
  assert.match(html,/<strong><span>top<\/span><span>gent<\/span><\/strong>/);
  assert.match(readFileSync(join(viewer,"ui/styles.css"),"utf8"),/\.brand-lockup strong span \{ display:inline; margin:0; font-size:inherit; \}/);
  const desktopIcon=join(root,"assets/icon.svg");
  if (existsSync(desktopIcon)) assert.equal(webIcon,readFileSync(desktopIcon,"utf8"));
});

test("narrow screens keep every workspace reachable and long evidence bounded", () => {
  const html = readFileSync(join(viewer,"ui/index.html"),"utf8");
  const css = readFileSync(join(viewer,"ui/styles.css"),"utf8");
  const state = readFileSync(join(viewer,"ui/state.mjs"),"utf8");
  assert.match(html,/id="mobileWorkspace" aria-label="Workspace"/);
  assert.match(state,/mobile\.onchange = \(\) => choose\("workspace", mobile\.value\)/);
  assert.match(css,/\[data-workspace-page\]:not\(\.agent-workspace\) > \.panel > \.body \{ max-height:calc\(100vh - 210px\); \}/);
});

test("web settings expose the desktop density and refresh choices", () => {
  assert.deepEqual(DENSITIES.map(([,label])=>label),["Compact","Normal","Comfortable"]);
  assert.deepEqual(REFRESHES,[[1500,"1.5s"],[5000,"5s"],[15000,"15s"],[30000,"30s"],[0,"Paused"]]);
  const app = readFileSync(join(viewer,"ui/app.mjs"),"utf8");
  assert.doesNotMatch(app,/setInterval\(poll/);
  assert.match(app,/view\.refreshMs > 0/);
});

test("rule coverage is honest and behaviour counts findings only", () => {
  assert.equal(ruleState({live:true,enabled:true,needs:[]}),"Live");
  assert.equal(ruleState({live:true,enabled:false,needs:[]}),"Live, off as shipped");
  assert.equal(ruleState({live:false,enabled:true,needs:["container.id"]}),"Needs container.id");
  assert.equal(ruleState({live:false,enabled:true,needs:["proc.vpid","fd.l4proto"]}),"Needs proc.vpid +1");
  assert.equal(behaviourSummary({behaviour:{catalogue:{rules:95,live:120},findings:[]}}),"0 behaviour findings on this host");
  assert.equal(behaviourSummary({behaviour:{findings:[{},{}]}}),"2 behaviour findings on this host");
});

test("action labels and caveats preserve the desktop evidence boundary", () => {
  assert.equal(actionLabel("read"),"open/read");
  assert.match(actionMeaning("read"),/bytes and contents were not observed/);
  assert.match(actionMeaning("connect"),/not proof of an open socket/);
});

test("process history distinguishes an unread exec and an unobserved exit", () => {
  assert.equal(processName({name:"sh",program_unread:true}),"sh → ?");
  const text=processStateMeaning({state:"gone",last_seen:1,gone_after:2});
  assert.match(text,/the exit itself was not observed/);
});
