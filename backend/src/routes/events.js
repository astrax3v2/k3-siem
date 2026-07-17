'use strict';
const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { db } = require('../models/db');
const { chQuery, chInsert, chNowMinus } = require('../models/clickhouse');
const { authenticate } = require('../middleware/auth');
const { parseToOCSF } = require('../services/ocsfParser');
const { matchIOCs } = require('../services/iocMatcher');
const { buildRealtimeAlerts, persistRealtimeAlerts } = require('../services/realtimeAlerts');
const { INGEST_API_KEY } = require('../config');
const router = express.Router();

router.get('/', authenticate, async (req, res) => {
  const { page=1, limit=50, severity, source, search, index, agent_id } = req.query;
  const offset = (parseInt(page)-1)*parseInt(limit);
  let where=[], params={};
  if (severity) { where.push('severity = {severity:String}'); params.severity = severity; }
  if (source)   { where.push('source = {source:String}');   params.source = source; }
  if (index)    { where.push('index_name = {index:String}'); params.index = index; }
  if (agent_id) { where.push('agent_id = {agent_id:String}'); params.agent_id = agent_id; }
  if (search)   { where.push('(username ILIKE {search:String} OR computer ILIKE {search:String} OR ip_address ILIKE {search:String} OR action ILIKE {search:String})'); params.search = `%${search}%`; }
  const wc = where.length ? 'WHERE '+where.join(' AND ') : '';
  const total = (await chQuery(`SELECT COUNT(*) as cnt FROM events ${wc}`, params))[0]?.cnt || 0;
  const events = await chQuery(`SELECT * FROM events ${wc} ORDER BY timestamp DESC LIMIT {limit:UInt32} OFFSET {offset:UInt32}`, { ...params, limit: parseInt(limit), offset });
  res.json({ events, total, page:parseInt(page), limit:parseInt(limit), pages:Math.ceil(total/parseInt(limit)) });
});

router.get('/stats', authenticate, async (req, res) => {
  const last24hExpr = chNowMinus(1, 'day');
  res.json({
    total:        (await chQuery('SELECT COUNT(*) as cnt FROM events'))[0].cnt,
    last24h:      (await chQuery(`SELECT COUNT(*) as cnt FROM events WHERE timestamp >= ${last24hExpr}`))[0].cnt,
    severityCounts: await chQuery('SELECT severity, COUNT(*) as cnt FROM events GROUP BY severity'),
    sourceCounts:   await chQuery('SELECT source, COUNT(*) as cnt FROM events GROUP BY source ORDER BY cnt DESC LIMIT 10'),
    indexCounts:    await chQuery('SELECT index_name, COUNT(*) as cnt FROM events GROUP BY index_name'),
  });
});

router.post('/ingest', async (req, res) => {
  const key = req.headers['x-api-key'];
  if (key !== INGEST_API_KEY)
    return res.status(401).json({ error: 'Invalid API key' });
  const logs = Array.isArray(req.body) ? req.body : [req.body];
  const agentId = req.headers['x-agent-id'] || null;
  const rows = logs.map(l => {
    let ocsf = null;
    try { ocsf = parseToOCSF(l); } catch { /* best-effort normalization */ }
    return {
      id: uuidv4(),
      timestamp: l.timestamp || new Date().toISOString(),
      source: l.source || 'Unknown',
      event_id: l.event_id != null ? String(l.event_id) : null,
      computer: l.computer || null,
      username: l.username || null,
      ip_address: l.ip_address || null,
      action: l.action || null,
      severity: l.severity || 'Info',
      raw_log: typeof l.raw === 'string' ? l.raw : JSON.stringify(l),
      index_name: l.index || 'default',
      agent_id: l.agent_id || agentId,
      ocsf_log: ocsf ? JSON.stringify(ocsf) : null,
      ocsf_class_uid: ocsf ? ocsf.class_uid : null,
      ocsf_class_name: ocsf ? ocsf.class_name : null,
      ocsf_category_name: ocsf ? ocsf.category_name : null,
    };
  });
  try {
    await chInsert('events', rows);
  } catch (e) {
    console.error('[Ingest] ClickHouse insert failed:', e.message);
    return res.status(503).json({ error: 'Event storage temporarily unavailable' });
  }

  if (agentId) {
    try {
      await db().prepare('UPDATE agents SET events_sent = events_sent + ?, last_heartbeat = ? WHERE id = ?')
        .run(rows.length, new Date().toISOString(), agentId);
    } catch {}
  }

  const normalized = logs.map((l) => ({
    source: l.source || 'Unknown',
    event_id: String(l.event_id || ''),
    computer: l.computer || null,
    username: l.username || null,
    ip_address: l.ip_address || null,
    action: l.action || '',
    severity: l.severity || 'Info',
  }));

  Promise.all(normalized.map((event) => buildRealtimeAlerts(event)))
    .then((groups) => persistRealtimeAlerts(groups.flat()))
    .catch(() => {});

  // IOC matching runs after the response is queued so ingestion latency isn't gated on it.
  Promise.all(logs.map((l) => matchIOCs({
    source: l.source, computer: l.computer, username: l.username,
    ip_address: l.ip_address, raw_log: typeof l.raw === 'string' ? l.raw : JSON.stringify(l),
  }).catch(() => []))).catch(() => {});

  res.json({ ingested: rows.length, status: 'ok' });
});

router.post('/kql', authenticate, async (req, res) => {
  const { query } = req.body;
  if (!query) return res.status(400).json({ error: 'Query required' });
  const start = Date.now();
  try {
    const sql = kqlToSql(query);
    const results = await chQuery(sql.query, sql.params);
    res.json({ results, total: results.length, execution_ms: Date.now()-start, query_parsed: sql.query });
  } catch(e) { res.status(400).json({ error: e.message }); }
});

function kqlToSql(kql) {
  let sql = 'SELECT * FROM events';
  const params = {}, conditions = [];
  const lines = kql.split('\n').map(l=>l.trim()).filter(Boolean);
  let limitN = 100, n = 0;
  const nextParam = (value, type='String') => { const name = `p${n++}`; params[name] = value; return `{${name}:${type}}`; };

  for (let i=1; i<lines.length; i++) {
    const line = lines[i];
    if (line.startsWith('| where ')) {
      const cond = line.slice(8);
      const eid = cond.match(/event_id\s*==\s*"([^"]+)"/);
      if (eid) { conditions.push(`event_id = ${nextParam(eid[1])}`); }
      const sev = cond.match(/severity\s*==\s*"([^"]+)"/);
      if (sev) { conditions.push(`severity = ${nextParam(sev[1])}`); }
      const ago = cond.match(/timestamp\s*>\s*datetime_ago\("(\d+)([mhd])"\)/);
      if (ago) { const u={m:'minutes',h:'hours',d:'days'}[ago[2]]; conditions.push(`timestamp >= ${chNowMinus(parseInt(ago[1], 10), u)}`); }
      const hasAny = cond.match(/action\s+has_any\s*\(([^)]+)\)/);
      if (hasAny) { const terms=hasAny[1].split(',').map(t=>t.trim().replace(/"/g,'')); conditions.push(`(${terms.map((t)=>`action ILIKE ${nextParam(`%${t}%`)}`).join(' OR ')})`); }
      const src = cond.match(/source\s*==\s*"([^"]+)"/);
      if (src) { conditions.push(`source = ${nextParam(src[1])}`); }
      const user = cond.match(/username\s*!=\s*"([^"]+)"/);
      if (user) { conditions.push(`username != ${nextParam(user[1])}`); }
      const agentMatch = cond.match(/agent_id\s*==\s*"([^"]+)"/);
      if (agentMatch) { conditions.push(`agent_id = ${nextParam(agentMatch[1])}`); }
    }
    if (line.startsWith('| top ')) { limitN = parseInt(line.split(' ')[2]) || 10; }
    if (line.startsWith('| project ')) { /* ignore for now */ }
  }

  if (conditions.length) sql += ' WHERE '+conditions.join(' AND ');
  sql += ` ORDER BY timestamp DESC LIMIT ${limitN}`;
  return { query: sql, params };
}

module.exports = router;
