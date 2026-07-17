'use strict';
// Purges old closed-alert data past a configurable retention window. Event retention is
// handled by ClickHouse's table TTL (see models/clickhouse.js initClickHouse) instead of
// a manual DELETE — ClickHouse drops expired partitions in the background.
const cron = require('node-cron');
const { db, sqlNowMinus } = require('../models/db');

let task = null;
const CLOSED_ALERTS_RETENTION_DAYS = parseInt(process.env.CLOSED_ALERTS_RETENTION_DAYS || '180', 10);

async function runOnce() {
  const d = db();
  try {
    const cutoff = sqlNowMinus(CLOSED_ALERTS_RETENTION_DAYS, 'day');
    await d.exec(`DELETE FROM alerts WHERE status = 'Closed' AND closed_at < ${cutoff}`);
  } catch (e) { console.error('[Retention] Alert purge failed:', e.message); }
}

function startRetention() {
  if (task) return;
  console.log(`[Retention] Purging closed alerts older than ${CLOSED_ALERTS_RETENTION_DAYS}d, daily at 03:00 (events retention handled by ClickHouse TTL)`);
  task = cron.schedule('0 3 * * *', () => runOnce().catch(() => {}));
}

function stopRetention() {
  if (task) { task.stop(); task = null; }
}

module.exports = { startRetention, stopRetention, runOnce };
