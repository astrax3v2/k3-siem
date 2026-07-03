'use strict';
// SOC SLA targets by severity, in minutes.
//   Time-to-acknowledge: from creation to the first status change away from the initial
//     "unworked" state (New for alerts, Open for incidents).
//   Time-to-resolve: from creation to reaching a closed/terminal state.
// Breach is a permanent fact once crossed — an alert acknowledged late stays "breached" even
// though its acknowledged_at is now fixed; an alert still open past its target is breached and
// stays so until acknowledged/resolved. Both cases fall out of the same elapsed-time formula.
const SLA_TARGETS = {
  Critical: { ackMinutes: 15, resolveMinutes: 240 },
  High: { ackMinutes: 30, resolveMinutes: 480 },
  Medium: { ackMinutes: 120, resolveMinutes: 1440 },
  Low: { ackMinutes: 480, resolveMinutes: 4320 },
  Info: { ackMinutes: 480, resolveMinutes: 4320 },
};

function minutesBetween(a, b) {
  return (b.getTime() - a.getTime()) / 60000;
}

// SQLite's datetime('now') (used for created_at/acknowledged_at/closed_at in dev/sqlite mode)
// returns UTC as "YYYY-MM-DD HH:MM:SS" with no zone marker. `new Date(...)` on a string in that
// exact shape is parsed as *local* time by V8, not UTC — on any host whose local timezone isn't
// UTC that silently shifts every timestamp by the zone offset. Two such mis-parsed values still
// diff correctly against each other (the offset cancels out), but diffing one against a
// correctly-built `new Date()` (a real "now") does not — it introduces a spurious multi-hour
// gap. Postgres returns TIMESTAMPTZ columns as real Date objects already, so this only matters
// for the sqlite string case.
function toUtcDate(value) {
  if (!value) return null;
  if (value instanceof Date) return value;
  const s = String(value);
  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(\.\d+)?$/.test(s)) return new Date(s.replace(' ', 'T') + 'Z');
  return new Date(s);
}

/**
 * Compute SLA status for a row with created_at, acknowledged_at, closed_at, severity.
 * Returns null if the row has no created_at to measure from.
 */
function computeSla(row) {
  if (!row || !row.created_at) return null;
  const targets = SLA_TARGETS[row.severity] || SLA_TARGETS.Medium;
  const created = toUtcDate(row.created_at);
  const now = new Date();
  const ackAt = toUtcDate(row.acknowledged_at);
  const closedAt = toUtcDate(row.closed_at);

  const ackElapsedMinutes = minutesBetween(created, ackAt || now);
  const resolveElapsedMinutes = minutesBetween(created, closedAt || now);

  return {
    ack_target_minutes: targets.ackMinutes,
    ack_elapsed_minutes: Math.round(ackElapsedMinutes),
    ack_done: !!ackAt,
    ack_breached: ackElapsedMinutes > targets.ackMinutes,
    resolve_target_minutes: targets.resolveMinutes,
    resolve_elapsed_minutes: Math.round(resolveElapsedMinutes),
    resolve_done: !!closedAt,
    resolve_breached: resolveElapsedMinutes > targets.resolveMinutes,
  };
}

module.exports = { SLA_TARGETS, computeSla };
