'use strict';
const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { db, sqlNowMinus } = require('../models/db');
const { authenticate } = require('../middleware/auth');
const { parseToOCSF } = require('../services/ocsfParser');
const { matchIOCs } = require('../services/iocMatcher');
const { buildRealtimeAlerts, persistRealtimeAlerts } = require('../services/realtimeAlerts');
const { INGEST_API_KEY } = require('../config');
const router = express.Router();

router.get('/', authenticate, async (req, res) => {
  const { page=1, limit=50, severity, source, search, index, agent_id } = req.query;
  const offset = (parseInt(page)-1)*parseInt(limit);
  let where=[], params=[];
  if (severity) { where.push('severity = ?'); params.push(severity); }
  if (source)   { where.push('source = ?');   params.push(source); }
  if (index)    { where.push('index_name = ?'); params.push(index); }
  if (agent_id) { where.push('agent_id = ?'); params.push(agent_id); }
  if (search)   { where.push('(username LIKE ? OR computer LIKE ? OR ip_address LIKE ? OR action LIKE ?)'); params.push(`%${search}%`,`%${search}%`,`%${search}%`,`%${search}%`); }
  const wc = where.length ? 'WHERE '+where.join(' AND ') : '';
  const d = db();
  const total = (await d.prepare(`SELECT COUNT(*) as cnt FROM events ${wc}`).get(...params))?.cnt || 0;
  const events = await d.prepare(`SELECT * FROM events ${wc} ORDER BY timestamp DESC LIMIT ? OFFSET ?`).all(...params, parseInt(limit), offset);
  res.json({ events, total, page:parseInt(page), limit:parseInt(limit), pages:Math.ceil(total/parseInt(limit)) });
});

router.get('/stats', authenticate, async (req, res) => {
  const d = db();
  const last24hExpr = sqlNowMinus(1, 'day');
  res.json({
    total:        (await d.prepare('SELECT COUNT(*) as cnt FROM events').get()).cnt,
    last24h:      (await d.prepare(`SELECT COUNT(*) as cnt FROM events WHERE timestamp >= ${last24hExpr}`).get()).cnt,
    severityCounts: await d.prepare('SELECT severity, COUNT(*) as cnt FROM events GROUP BY severity').all(),
    sourceCounts:   await d.prepare('SELECT source, COUNT(*) as cnt FROM events GROUP BY source ORDER BY cnt DESC LIMIT 10').all(),
    indexCounts:    await d.prepare('SELECT index_name, COUNT(*) as cnt FROM events GROUP BY index_name').all(),
  });
});

router.post('/ingest', async (req, res) => {
  const key = req.headers['x-api-key'];
  if (key !== INGEST_API_KEY)
    return res.status(401).json({ error: 'Invalid API key' });
  const logs = Array.isArray(req.body) ? req.body : [req.body];
  const agentId = req.headers['x-agent-id'] || null;
  const d = db();
  const ins = d.prepare(`INSERT INTO events(id,timestamp,source,event_id,computer,username,ip_address,action,severity,raw_log,index_name,agent_id,ocsf_log,ocsf_class_uid,ocsf_class_name,ocsf_category_name) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);
  const insertAll = d.transaction(async (rows) => {
    for (const r of rows) await ins.run(...r);
  });
  const rows = logs.map(l => {
    let ocsf = null;
    try { ocsf = parseToOCSF(l); } catch { /* best-effort normalization */ }
    return [
      uuidv4(),
      l.timestamp || new Date().toISOString(),
      l.source || 'Unknown',
      l.event_id || null,
      l.computer || null,
      l.username || null,
      l.ip_address || null,
      l.action || null,
      l.severity || 'Info',
      typeof l.raw === 'string' ? l.raw : JSON.stringify(l),
      l.index || 'default',
      l.agent_id || agentId,
      ocsf ? JSON.stringify(ocsf) : null,
      ocsf ? ocsf.class_uid : null,
      ocsf ? ocsf.class_name : null,
      ocsf ? ocsf.category_name : null,
    ];
  });
  await insertAll(rows);

  if (agentId) {
    try {
      await d.prepare('UPDATE agents SET events_sent = events_sent + ?, last_heartbeat = ? WHERE id = ?')
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
    const results = await db().prepare(sql.query).all(...sql.params);
    res.json({ results, total: results.length, execution_ms: Date.now()-start, query_parsed: sql.query });
  } catch(e) { res.status(400).json({ error: e.message }); }
});

function kqlToSql(kql) {
  let sql = 'SELECT * FROM events';
  const params = [], conditions = [];
  const lines = kql.split('\n').map(l=>l.trim()).filter(Boolean);
  let limitN = 100;

  for (let i=1; i<lines.length; i++) {
    const line = lines[i];
    if (line.startsWith('| where ')) {
      const cond = line.slice(8);
      const eid = cond.match(/event_id\s*==\s*"([^"]+)"/);
      if (eid) { conditions.push('event_id = ?'); params.push(eid[1]); }
      const sev = cond.match(/severity\s*==\s*"([^"]+)"/);
      if (sev) { conditions.push('severity = ?'); params.push(sev[1]); }
      const ago = cond.match(/timestamp\s*>\s*datetime_ago\("(\d+)([mhd])"\)/);
      if (ago) { const u={m:'minutes',h:'hours',d:'days'}[ago[2]]; conditions.push(`timestamp >= ${sqlNowMinus(parseInt(ago[1], 10), u)}`); }
      const hasAny = cond.match(/action\s+has_any\s*\(([^)]+)\)/);
      if (hasAny) { const terms=hasAny[1].split(',').map(t=>t.trim().replace(/"/g,'')); conditions.push(`(${terms.map(()=>'action LIKE ?').join(' OR ')})`); terms.forEach(t=>params.push(`%${t}%`)); }
      const src = cond.match(/source\s*==\s*"([^"]+)"/);
      if (src) { conditions.push('source = ?'); params.push(src[1]); }
      const user = cond.match(/username\s*!=\s*"([^"]+)"/);
      if (user) { conditions.push('username != ?'); params.push(user[1]); }
      const agentMatch = cond.match(/agent_id\s*==\s*"([^"]+)"/);
      if (agentMatch) { conditions.push('agent_id = ?'); params.push(agentMatch[1]); }
    }
    if (line.startsWith('| top ')) { limitN = parseInt(line.split(' ')[2]) || 10; }
    if (line.startsWith('| project ')) { /* ignore for now */ }
  }

  if (conditions.length) sql += ' WHERE '+conditions.join(' AND ');
  sql += ` ORDER BY timestamp DESC LIMIT ${limitN}`;
  return { query: sql, params };
}

module.exports = router;
