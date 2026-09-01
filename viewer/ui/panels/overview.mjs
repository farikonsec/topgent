// The four numbers across the top.
//
// A summary for someone deciding where to look first, never the evidence.

import { identityName } from "../alerts.mjs";
import { $, ROGUE_CODES } from "../dom.mjs";
import { session } from "../state.mjs";

export function renderOverview() {
  const critical = session.data.agents.filter(a=>a.grade==="CRITICAL").length;
  const signals = session.data.agents.reduce((n,a)=>n+a.factors.filter(f=>ROGUE_CODES.has(f.code)).length,0);
  const top = [...session.data.agents].sort((a,b)=>b.score-a.score)[0];
  $("railCritical").textContent = critical; $("railSignals").textContent = signals;
  $("railEstate").textContent = session.data.agents.length; $("railEstateNote").textContent = `${session.data.fact_count} evidence points`;
  $("posture").textContent = critical ? `${critical} critical agent${critical>1?"s":""}` : signals ? `${signals} active signal${signals>1?"s":""}` : "No active rogue signal";
  $("posture").style.color = critical ? "var(--crit)" : signals ? "var(--high)" : "var(--low)";
  $("postureNote").textContent = top ? `Highest: ${identityName(top)} · ${top.score}/100` : "Metadata only · no traffic decryption";
}
