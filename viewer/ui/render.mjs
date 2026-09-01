// One render pass over every panel.
//
// Each panel rewrites its own part of the page from the report it is handed.
// There is no diffing and no cached model of the estate: the most recent report
// is the only truth, and redrawing everything from it makes a stale row
// impossible by construction. In a security tool a stale row is a wrong answer,
// which costs more than a redraw.

import { renderOverview } from "./panels/overview.mjs";
import { renderAgents } from "./panels/agents.mjs";
import { renderRisk } from "./panels/risk.mjs";
import { renderBlast } from "./panels/blast.mjs";
import { renderAccess } from "./panels/access.mjs";
import { renderEvents } from "./panels/events.mjs";
import { renderActivity } from "./panels/activity.mjs";
import { renderNetwork } from "./panels/network.mjs";
import { renderHealth } from "./panels/health.mjs";
import { renderResponse } from "./panels/response.mjs";
import { renderContext } from "./panels/context.mjs";
import { renderAssets } from "./panels/assets.mjs";

export function render() {
  renderOverview();
  renderAgents();
  renderRisk();
  renderBlast();
  renderAccess();
  renderEvents();
  renderActivity();
  renderNetwork();
  renderHealth();
  renderResponse();
  renderContext();
  renderAssets();
}
