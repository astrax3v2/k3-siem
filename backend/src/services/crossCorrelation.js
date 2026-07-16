'use strict';
// Correlates ACROSS alerts/rules, not within a single rule like correlationEngine.js does.
// When one entity (user/IP/asset) accumulates alerts from multiple distinct sources within a
// short window, that's a stronger signal than any one alert alone — group them into an incident
// automatically instead of waiting for an analyst to notice the pattern and do it by hand via
// POST /incidents/from-alert/:alertId (the only way this happened before).
//
// Deliberate scope cut: the window/threshold below are fixed constants, not a rule-builder UI —
// keeps this shippable without inventing a second rules schema on top of correlation_rules.
const cron = require('node-cron');
const { v4: uuidv4 } = require('uuid');
const { db, getDialect, sqlNow, sqlNowMinus } = require('../models/db');

const WINDOW_MINUTES = 15;
const MIN_DISTINCT_SOURCES = 2;
const SEVERITY_RANK = { Critical: 4, High: 3, Medium: 2, Low: 1 };
const CROSS_CORRELATION_TAG = 'cross-correlation';

let task = null;

function maxSeverity(severities) {
  return severities.reduce((best, s) => (SEVERITY_RANK[s] || 0) > (SEVERITY_RANK[best] || 0) ? s : best, 'Low');
}

async function runOnce() {
  const d = db();
  const windowExpr = sqlNowMinus(WINDOW_MINUTES, 'minute');

  // Entities with alerts from >= MIN_DISTINCT_SOURCES distinct rules/tactics in the window,
  // excluding alerts already grouped into any incident (so re-running this every tick doesn't
  // recreate incidents for the same alerts).
  const candidates = await d.prepare(`
    SELECT COALESCE(a.username, a.ip_address, a.asset) as entity,
           COUNT(DISTINCT COALESCE(a.rule_id, a.mitre_tactic)) as distinct_sources
    FROM alerts a
    WHERE a.created_at >= ${windowExpr}
      AND a.status != 'Closed'
      AND (a.username IS NOT NULL OR a.ip_address IS NOT NULL OR a.asset IS NOT NULL)
      AND a.id NOT IN (SELECT alert_id FROM incident_alerts)
    GROUP BY entity
    HAVING COUNT(DISTINCT COALESCE(a.rule_id, a.mitre_tactic)) >= ?
  `).all(MIN_DISTINCT_SOURCES);

  for (const { entity } of candidates) {
    const alerts = await d.prepare(`
      SELECT * FROM alerts
      WHERE created_at >= ${windowExpr} AND status != 'Closed'
        AND id NOT IN (SELECT alert_id FROM incident_alerts)
        AND COALESCE(username, ip_address, asset) = ?
    `).all(entity);
    if (alerts.length < 2) continue;

    const distinctSources = new Set(alerts.map(a => a.rule_id || a.mitre_tactic).filter(Boolean));
    if (distinctSources.size < MIN_DISTINCT_SOURCES) continue;

    const incidentId = uuidv4();
    const severity = maxSeverity(alerts.map(a => a.severity));
    const title = `Correlated Activity: ${alerts.length} alerts across ${distinctSources.size} sources for ${entity}`;
    await d.prepare(
      'INSERT INTO incidents(id,title,description,severity,status,priority,owner,tags) VALUES(?,?,?,?,?,?,?,?)'
    ).run(
      incidentId, title,
      `Auto-correlated by the cross-correlation engine: ${alerts.length} alerts from ${distinctSources.size} distinct rules/tactics for ${entity} within ${WINDOW_MINUTES}m.`,
      severity, 'Open', severity === 'Critical' ? 1 : 2, 'Cross-Correlation Engine', JSON.stringify([CROSS_CORRELATION_TAG])
    );

    const linkSql = getDialect() === 'postgres'
      ? 'INSERT INTO incident_alerts(incident_id,alert_id) VALUES(?,?) ON CONFLICT DO NOTHING'
      : 'INSERT OR IGNORE INTO incident_alerts(incident_id,alert_id) VALUES(?,?)';
    const link = d.prepare(linkSql);
    for (const alert of alerts) await link.run(incidentId, alert.id);
  }
}

async function countRecent() {
  const d = db();
  const windowExpr = sqlNowMinus(24, 'hour');
  const row = await d.prepare(
    `SELECT COUNT(*) as cnt FROM incidents WHERE created_at >= ${windowExpr} AND tags LIKE ?`
  ).get(`%${CROSS_CORRELATION_TAG}%`);
  return row?.cnt || 0;
}

function startCrossCorrelation() {
  if (task) return;
  console.log('[CrossCorrelation] Cross-alert evaluation every 60s');
  task = cron.schedule('0 * * * * *', () => { runOnce().catch(e => console.error('[CrossCorrelation] failed:', e.message)); });
}

function stopCrossCorrelation() {
  if (task) { task.stop(); task = null; }
}

module.exports = { startCrossCorrelation, stopCrossCorrelation, runOnce, countRecent, WINDOW_MINUTES, MIN_DISTINCT_SOURCES };
