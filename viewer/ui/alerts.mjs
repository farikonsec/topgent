// What the interface says about an event, and whether it interrupts anyone.
//
// Everything here is pure — no DOM, no browser globals, no timers — so
// `alerts.test.mjs` runs the code that actually ships rather than a restatement
// of it. Keep it that way: a rule about when to wake someone up is exactly the
// kind of thing that should be provable without a browser.

import { bytes, duration } from "./format.mjs";

// ---- wording ----

export const KIND_LABEL = {
  started: "Started",
  stopped: "Stopped",
  grade_changed: "Risk changed",
  credential_exposed: "Credential exposed",
  policy_breach: "Out of policy",
  recon: "Scanning detected",
  behaviour: "Rogue behaviour",
  model_drift: "Model drift",
  action: "Action",
};

// A grade change is not one thing. Reading the direction out of the sentence
// is how "CRITICAL to HIGH" was labelled an escalation and notified about.
export function eventLabel(e) {
  if (e.kind !== "grade_changed") return KIND_LABEL[e.kind] ?? e.kind;
  if (e.direction === "escalated") return "Risk escalated";
  if (e.direction === "downgraded") return "Risk reduced";
  return KIND_LABEL.grade_changed;
}

// What to call an agent whose family is not known. "unclassified" alone reads
// as a verdict; it is only a verdict when Topgent actually got to look.
export function identityName(a) {
  if (a.family) return a.family;
  return a.identity_evidence?.state === "unexamined" ? "not examined" : "unrecognised";
}

// How long a connection has been open, from the timestamp the operating system
// recorded when it made the connection. Platforms that keep no such record say
// so: the gap between two sweeps measures how long Topgent has been watching,
// which is a different thing, and presenting it as the connection's age would
// be an invented fact.
export function connectionAge(endpoint) {
  if (endpoint.open_for_ms == null) {
    return endpoint.opened_at == null ? "open now · age not recorded by this platform" : "open now";
  }
  return `open ${duration(endpoint.open_for_ms)} · system-recorded`;
}

// What the kernel has counted on this connection. Absent where it counts
// nothing: never zero, and never a tally of how often a sweep saw the endpoint.
export function connectionTraffic(endpoint) {
  if (endpoint.bytes_sent == null || endpoint.bytes_received == null) return "";
  return ` · ${bytes(endpoint.bytes_sent)} sent, ${bytes(endpoint.bytes_received)} received`;
}

// ---- decisions ----

const ALARM_KINDS = new Set(["recon", "credential_exposed", "grade_changed", "behaviour", "model_drift"]);

/** How long the same finding stays quiet after it has been announced once. */
export const NOTIFY_COOLDOWN_MS = 5 * 60 * 1000;

/** Ceiling on remembered findings, so a long session cannot grow without bound. */
export const MAX_NOTIFY_KEYS = 512;

const notifiedAt = new Map();

// Only a genuine rise is worth interrupting someone for. A downgrade stays in
// the event log with its own wording and never raises an alarm.
export function isAlarming(e) {
  if (!ALARM_KINDS.has(e.kind)) return false;
  if (e.kind === "grade_changed") return e.direction === "escalated";
  return true;
}

// The same transition on the same exact run, over and over, is one finding.
// Keyed on the run rather than the pid so a reused pid is never folded into
// the history of a process that has exited.
export function alarmKey(e) {
  return `${e.run ?? e.pid}:${e.kind}:${e.direction ?? ""}`;
}

export function withinCooldown(e, now) {
  const last = notifiedAt.get(alarmKey(e));
  return last !== undefined && now - last < NOTIFY_COOLDOWN_MS;
}

export function recordNotified(e, now) {
  if (notifiedAt.size >= MAX_NOTIFY_KEYS) notifiedAt.delete(notifiedAt.keys().next().value);
  notifiedAt.set(alarmKey(e), now);
}

/** How many findings are currently being kept quiet. */
export function notifiedCount() {
  return notifiedAt.size;
}

/** Forget every announced finding. Used by tests to start from a known state. */
export function forgetNotified() {
  notifiedAt.clear();
}

// Delivery is a separate state from the finding. Alerts off silences the
// sound, the toast and the system notification and changes nothing about the
// event log, the row highlight or the response queue.
export function shouldAnnounce(announce, alertsEnabled) {
  return announce.length > 0 && alertsEnabled;
}
