'use strict';
// Evaluates correlation_rules against real ingested events on a schedule and creates
// real alerts when a rule's threshold is crossed — replacing the previous behavior where
// rules were stored in the DB (and toggleable in the UI) but never actually evaluated;
// alerting was instead hardcoded per-event-type in ingestion.js.
const cron = require('node-cron');
const { v4: uuidv4 } = require('uuid');
const { db, sqlNow, sqlNowMinus } = require('../models/db');
const { chQuery, chNowMinus } = require('../models/clickhouse');

let task = null;

// Best-effort extraction of the primary trigger condition from a rule's free-text `logic`
// description (e.g. "EventID==4625 count>=10 within window -> EventID==4672 same account").
// Rules created via the API can instead supply a structured `conditions` JSON field with
// {field, value} or {field, like} to skip this parsing entirely.
function extractCondition(rule) {
  if (rule.conditions) {
    try {
      const parsed = JSON.parse(rule.conditions);
      if (parsed && parsed.field) return parsed;
    } catch { /* fall through to text parsing */ }
  }
  const text = rule.logic || '';
  const eid = text.match(/event[_]?id\s*==\s*"?(\d+)"?/i);
  if (eid) return { field: 'event_id', value: eid[1] };
  const enc = text.match(/EncryptionType\s*==\s*(0x[0-9a-fA-F]+)/);
  if (enc) return { field: 'event_id', value: '4769' }; // Kerberoasting: TGS requests
  const cmd = text.match(/CmdLine has (\w+)/i);
  if (cmd) return { field: 'action', like: cmd[1] };
  const logon = text.match(/LogonType\s*==\s*10/);
  if (logon) return { field: 'event_id', value: '4624' };
  return null;
}

async function evaluateRule(rule) {
  const cond = extractCondition(rule);
  if (!cond) return; // rule logic isn't in a recognizable shape yet — skip rather than guess

  const d = db();
  let indices = [];
  try { indices = JSON.parse(rule.indices || '[]'); } catch { /* none */ }
  const windowExpr = sqlNowMinus(rule.window_minutes || 5, 'minute');
  const chWindowExpr = chNowMinus(rule.window_minutes || 5, 'minute');

  const where = [`timestamp >= ${chWindowExpr}`];
  const params = { threshold: rule.threshold || 1 };
  if (cond.field === 'event_id') { where.push('event_id = {event_id:String}'); params.event_id = cond.value; }
  else if (cond.field === 'action') { where.push('action ILIKE {action:String}'); params.action = `%${cond.like}%`; }
  else return;

  if (indices.length) {
    where.push(`index_name IN (${indices.map((_, i) => `{index_${i}:String}`).join(',')})`);
    indices.forEach((idx, i) => { params[`index_${i}`] = idx; });
  }

  const rows = await chQuery(
    `SELECT username, ip_address, computer, source, COUNT(*) as cnt
     FROM events WHERE ${where.join(' AND ')}
     GROUP BY username, ip_address, computer, source
     HAVING COUNT(*) >= {threshold:UInt32}`,
    params
  );

  for (const row of rows) {
    // Throttle: don't re-fire for the same rule + entity within the same window.
    const dupe = await d.prepare(
      `SELECT 1 as ok FROM alerts WHERE rule_id = ? AND (username = ? OR (username IS NULL AND ip_address = ?)) AND created_at >= ${windowExpr} LIMIT 1`
    ).get(rule.id, row.username, row.ip_address);
    if (dupe) continue;

    const alertId = uuidv4();
    const entity = row.username || row.ip_address || row.computer || 'unknown';
    await d.prepare(
      `INSERT INTO alerts(id,title,description,severity,status,source,asset,username,ip_address,mitre_tactic,risk_score,rule_id)
       VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`
    ).run(
      alertId, rule.name,
      `${rule.description || rule.name} — ${row.cnt} matching events for ${entity} in the last ${rule.window_minutes || 5}m (correlation rule)`,
      rule.severity || 'High', 'New', row.source, row.computer, row.username, row.ip_address,
      null, rule.risk_score || 80, rule.id
    );
    await d.prepare(`UPDATE correlation_rules SET hit_count = hit_count + 1, last_triggered = ${sqlNow()} WHERE id = ?`).run(rule.id);
  }
}

async function runOnce() {
  const d = db();
  const rules = await d.prepare('SELECT * FROM correlation_rules WHERE enabled = 1').all();
  for (const rule of rules) {
    try { await evaluateRule(rule); }
    catch (e) { console.error(`[Correlation] Rule "${rule.name}" failed:`, e.message); }
  }
}

function startCorrelationEngine() {
  if (task) return;
  console.log('[Correlation] Rule evaluation every 30s');
  task = cron.schedule('*/30 * * * * *', () => { runOnce().catch(() => {}); });
}

function stopCorrelationEngine() {
  if (task) { task.stop(); task = null; }
}

module.exports = { startCorrelationEngine, stopCorrelationEngine, runOnce, evaluateRule, extractCondition };
