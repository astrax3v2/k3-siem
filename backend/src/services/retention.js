'use strict';
// Purges old events/closed-alert data past a configurable retention window. Previously
// there was no retention policy at all — events accumulated forever, which is both a
// compliance gap and, eventually, a disk-exhaustion risk.
const cron = require('node-cron');
const { db, sqlNowMinus } = require('../models/db');

let task = null;
const EVENTS_RETENTION_DAYS = parseInt(process.env.EVENTS_RETENTION_DAYS || '90', 10);
const CLOSED_ALERTS_RETENTION_DAYS = parseInt(process.env.CLOSED_ALERTS_RETENTION_DAYS || '180', 10);

async function runOnce() {
  const d = db();
  try {
    const cutoff = sqlNowMinus(EVENTS_RETENTION_DAYS, 'day');
    await d.exec(`DELETE FROM events WHERE timestamp < ${cutoff}`);
  } catch (e) { console.error('[Retention] Event purge failed:', e.message); }
  try {
    const cutoff = sqlNowMinus(CLOSED_ALERTS_RETENTION_DAYS, 'day');
    await d.exec(`DELETE FROM alerts WHERE status = 'Closed' AND closed_at < ${cutoff}`);
  } catch (e) { console.error('[Retention] Alert purge failed:', e.message); }
}

function startRetention() {
  if (task) return;
  console.log(`[Retention] Purging events older than ${EVENTS_RETENTION_DAYS}d, closed alerts older than ${CLOSED_ALERTS_RETENTION_DAYS}d, daily at 03:00`);
  task = cron.schedule('0 3 * * *', () => runOnce().catch(() => {}));
}

function stopRetention() {
  if (task) { task.stop(); task = null; }
}

module.exports = { startRetention, stopRetention, runOnce };
