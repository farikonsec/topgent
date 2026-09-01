// Tests for the interface's alert decisions.
//
// These import the module the desktop app and the dev server both load, so a
// test can never pass against a copy of a rule the user does not actually run.
// The file sits outside `ui/` because that directory is what gets bundled, and
// a test has no business shipping inside the application.
//
//   node --test viewer/alerts.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import * as ui from "./ui/alerts.mjs";
import { bytes, duration } from "./ui/format.mjs";

const escalation = { kind: "grade_changed", direction: "escalated", detail: "HIGH to CRITICAL", run: "18246@1000", pid: 18246 };
const downgrade = { kind: "grade_changed", direction: "downgraded", detail: "CRITICAL to HIGH", run: "18246@1000", pid: 18246 };
const unknownMove = { kind: "grade_changed", detail: "CRITICAL to HIGH", run: "18246@1000", pid: 18246 };

test("a rise in risk is alarming", () => {
  assert.equal(ui.isAlarming(escalation), true);
  assert.equal(ui.isAlarming({ kind: "recon", run: "1@1" }), true);
  assert.equal(ui.isAlarming({ kind: "credential_exposed", run: "1@1" }), true);
  assert.equal(ui.isAlarming({ kind: "behaviour", run: "1@1" }), true);
});

test("a downgrade never alarms, whatever the sentence contains", () => {
  // The PID 18246 defect exactly: the detail contains the word CRITICAL, and
  // a substring test on it reported the recovery as an escalation.
  assert.match(downgrade.detail, /CRITICAL/);
  assert.equal(ui.isAlarming(downgrade), false);
  // A record with no direction cannot be shown to be a rise, so it is quiet.
  assert.equal(ui.isAlarming(unknownMove), false);
});

test("lifecycle and action events are never alarms", () => {
  for (const kind of ["started", "stopped", "action", "policy_breach"]) {
    assert.equal(ui.isAlarming({ kind, run: "1@1" }), false, `${kind} must not alarm`);
  }
});

test("turning alerts off suppresses delivery and nothing else", () => {
  // The switch was wired to the sound only, so a user who turned alerts off
  // still received a system notification for every sweep.
  assert.equal(ui.shouldAnnounce([escalation], true), true);
  assert.equal(ui.shouldAnnounce([escalation], false), false);
  // With nothing to announce it stays quiet whatever the switch says.
  assert.equal(ui.shouldAnnounce([], true), false);
  // The finding itself is unaffected by the switch: it is still an alarm, so
  // it still highlights the row and still reaches the event log.
  assert.equal(ui.isAlarming(escalation), true);
});

test("a downgrade is worded as a reduction, not an escalation", () => {
  assert.equal(ui.eventLabel(escalation), "Risk escalated");
  assert.equal(ui.eventLabel(downgrade), "Risk reduced");
  assert.equal(ui.eventLabel(unknownMove), "Risk changed");
  assert.equal(ui.eventLabel({ kind: "recon" }), "Scanning detected");
  assert.equal(ui.eventLabel({ kind: "not a kind" }), "not a kind");
});

test("the same transition on the same run is one finding for the cooldown window", () => {
  ui.forgetNotified();
  const start = 1_000_000;
  assert.equal(ui.withinCooldown(escalation, start), false);
  ui.recordNotified(escalation, start);
  assert.equal(ui.withinCooldown(escalation, start), true);
  assert.equal(ui.withinCooldown(escalation, start + ui.NOTIFY_COOLDOWN_MS - 1), true);
  assert.equal(ui.withinCooldown(escalation, start + ui.NOTIFY_COOLDOWN_MS), false);
});

test("the cooldown separates direction, kind and exact run", () => {
  ui.forgetNotified();
  const now = 1_000_000;
  ui.recordNotified(escalation, now);
  // The opposite transition is a different finding.
  assert.equal(ui.withinCooldown(downgrade, now), false);
  // A different kind on the same run is a different finding.
  assert.equal(ui.withinCooldown({ kind: "recon", run: escalation.run }, now), false);
  // A reused pid is a different run and must not inherit the suppression.
  assert.equal(ui.withinCooldown({ ...escalation, run: "18246@9999" }, now), false);
});

test("the cooldown table stays bounded", () => {
  ui.forgetNotified();
  for (let i = 0; i < ui.MAX_NOTIFY_KEYS + 50; i += 1) {
    ui.recordNotified({ kind: "recon", run: `${i}@1` }, i);
  }
  assert.ok(ui.notifiedCount() <= ui.MAX_NOTIFY_KEYS);
});

test("an unrecognised process says whether Topgent actually got to look", () => {
  // The evidence-free `unclassified` card: a process whose executable path was
  // refused had never been compared against anything, and the interface
  // presented that as a verdict.
  assert.equal(ui.identityName({ family: "codex-cli" }), "codex-cli");
  assert.equal(ui.identityName({ identity_evidence: { state: "unexamined" } }), "not examined");
  assert.equal(ui.identityName({ identity_evidence: { state: "unrecognised" } }), "unrecognised");
  // A report with no evidence block at all must not claim examination happened.
  assert.equal(ui.identityName({}), "unrecognised");
});

test("a connection's age comes from the system record or is said to be absent", () => {
  // A socket snapshot proves a connection exists now. It does not prove how
  // long it has existed, and the gap between two sweeps is how long Topgent
  // has been watching, which is a different fact.
  assert.equal(
    ui.connectionAge({ opened_at: 1000, open_for_ms: 6000 }),
    "open 6s · system-recorded"
  );
  assert.equal(
    ui.connectionAge({ opened_at: null, open_for_ms: null }),
    "open now · age not recorded by this platform"
  );
  // A timestamp the report could not turn into an age is still not an age.
  assert.equal(ui.connectionAge({ opened_at: 9_999, open_for_ms: null }), "open now");
  // Zero is a real age, not a missing one.
  assert.equal(ui.connectionAge({ opened_at: 1000, open_for_ms: 0 }), "open 0s · system-recorded");
});

test("durations read in human units and never go negative", () => {
  assert.equal(duration(0), "0s");
  assert.equal(duration(59_000), "59s");
  assert.equal(duration(60_000), "1m");
  assert.equal(duration(3_600_000), "1h 0m");
  assert.equal(duration(90 * 60_000), "1h 30m");
  assert.equal(duration(86_400_000), "1d");
  assert.equal(duration(-5_000), "0s");
});

test("traffic is shown only where the kernel actually counted it", () => {
  // A snapshot collector counts sweeps, not traffic. Absent counters must read
  // as absent rather than as a quiet zero.
  assert.equal(ui.connectionTraffic({ bytes_sent: 4213, bytes_received: 4410 }), " · 4.1 KB sent, 4.3 KB received");
  assert.equal(ui.connectionTraffic({ bytes_sent: null, bytes_received: null }), "");
  assert.equal(ui.connectionTraffic({}), "");
  // Half a reading is not a smaller reading.
  assert.equal(ui.connectionTraffic({ bytes_sent: 10, bytes_received: null }), "");
  // Zero is a real count, and is shown.
  assert.equal(ui.connectionTraffic({ bytes_sent: 0, bytes_received: 0 }), " · 0 B sent, 0 B received");
});

test("byte sizes read in human units", () => {
  assert.equal(bytes(0), "0 B");
  assert.equal(bytes(1023), "1023 B");
  assert.equal(bytes(1024), "1.0 KB");
  assert.equal(bytes(1048576), "1.0 MB");
  assert.equal(bytes(1073741824), "1.0 GB");
});
