'use strict';
const fs = require('fs/promises');
const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { db } = require('../models/db');
const { chQuery, chInsert, chNowMinus } = require('../models/clickhouse');
const { authenticate } = require('../middleware/auth');
const { parseLogRecord, toOCSF } = require('../services/ocsfParser');
const { broadcast } = require('../services/ingestion');
const { matchIOCs } = require('../services/iocMatcher');
const { buildRealtimeAlerts, persistRealtimeAlerts } = require('../services/realtimeAlerts');
const { INGEST_API_KEY } = require('../config');
const router = express.Router();
const MAX_IMPORT_BYTES = parseInt(process.env.LOG_IMPORT_MAX_BYTES || `${5 * 1024 * 1024}`, 10);
const MAX_IMPORT_RECORDS = parseInt(process.env.LOG_IMPORT_MAX_RECORDS || '5000', 10);

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

function buildParsedLogs(logs, agentId = null) {
  return logs.map((log) => {
    let parsed = null;
    let ocsf = null;
    try {
      parsed = parseLogRecord(log);
      ocsf = toOCSF(parsed);
    } catch {
      parsed = null;
      ocsf = null;
    }
    return { original: log, parsed, ocsf, agentId: log?.agent_id || agentId };
  });
}

function buildRows(parsedLogs) {
  return parsedLogs.map(({ original, parsed, ocsf, agentId }) => {
    const normalized = parsed || {};
    return {
      id: uuidv4(),
      timestamp: normalized.timestamp || original.timestamp || new Date().toISOString(),
      source: normalized.source || original.source || 'Unknown',
      event_id: normalized.event_id != null ? String(normalized.event_id) : (original.event_id != null ? String(original.event_id) : null),
      computer: normalized.computer || original.computer || null,
      username: normalized.username || original.username || null,
      ip_address: normalized.ip_address || original.ip_address || null,
      action: normalized.action || original.action || null,
      severity: normalized.severity || original.severity || 'Info',
      raw_log: normalized.raw || (typeof original.raw === 'string' ? original.raw : JSON.stringify(original)),
      index_name: normalized.index_name || original.index || original.index_name || 'default',
      agent_id: agentId,
      parser_profile: normalized.parser?.profile_id || null,
      parser_vendor: normalized.parser?.vendor || null,
      parser_product: normalized.parser?.product || null,
      parser_family: normalized.parser?.family || null,
      parser_device_type: normalized.parser?.device_type || null,
      parser_format: normalized.parser?.format || null,
      ocsf_log: ocsf ? JSON.stringify(ocsf) : null,
      ocsf_class_uid: ocsf ? ocsf.class_uid : null,
      ocsf_class_name: ocsf ? ocsf.class_name : null,
      ocsf_category_name: ocsf ? ocsf.category_name : null,
    };
  });
}

function buildRealtimeEvents(parsedLogs) {
  return parsedLogs.map(({ original, parsed }) => ({
    source: parsed?.source || original.source || 'Unknown',
    event_id: String(parsed?.event_id || original.event_id || ''),
    computer: parsed?.computer || original.computer || null,
    username: parsed?.username || original.username || null,
    ip_address: parsed?.ip_address || original.ip_address || null,
    action: parsed?.action || original.action || '',
    severity: parsed?.severity || original.severity || 'Info',
  }));
}

function summarizeBy(rows, key) {
  const counts = new Map();
  for (const row of rows) {
    const value = row[key] || 'unknown';
    counts.set(value, (counts.get(value) || 0) + 1);
  }
  return Array.from(counts.entries())
    .map(([value, count]) => ({ value, count }))
    .sort((a, b) => b.count - a.count);
}

function parseInlineImportContent(content) {
  if (content === undefined || content === null) return [];
  if (Array.isArray(content)) return content;
  if (typeof content === 'object') return [content];
  const text = String(content).trim();
  if (!text) return [];
  try {
    const parsed = JSON.parse(text);
    if (Array.isArray(parsed)) return parsed;
    if (parsed && typeof parsed === 'object') return [parsed];
  } catch {}
  return text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
}

async function resolveImportLogs({ content, file_path: filePath }) {
  if (content !== undefined && content !== null && String(content).trim() !== '') {
    return { logs: parseInlineImportContent(content), source: 'inline' };
  }
  if (!filePath || !String(filePath).trim()) {
    throw new Error('Provide log content or a file path');
  }

  const resolvedPath = String(filePath).trim();
  const stat = await fs.stat(resolvedPath);
  if (!stat.isFile()) throw new Error('Provided path is not a file');
  if (stat.size > MAX_IMPORT_BYTES) {
    throw new Error(`File is too large (${stat.size} bytes). Max allowed is ${MAX_IMPORT_BYTES} bytes`);
  }

  const raw = await fs.readFile(resolvedPath, 'utf8');
  return { logs: parseInlineImportContent(raw), source: resolvedPath };
}

async function ingestLogs(logs, { agentId = null } = {}) {
  const parsedLogs = buildParsedLogs(logs, agentId);
  const rows = buildRows(parsedLogs);
  try {
    await chInsert('events', rows);
  } catch (e) {
    console.error('[Ingest] ClickHouse insert failed:', e.message);
    throw e;
  }

  if (agentId) {
    try {
      await db().prepare('UPDATE agents SET events_sent = events_sent + ?, last_heartbeat = ? WHERE id = ?')
        .run(rows.length, new Date().toISOString(), agentId);
    } catch {}
  }

  const normalized = buildRealtimeEvents(parsedLogs);

  const alertGroups = await Promise.all(normalized.map((event) => buildRealtimeAlerts(event).catch(() => [])));
  const alerts = alertGroups.flat();
  if (alerts.length) {
    await persistRealtimeAlerts(alerts);
  }
  if (rows.length) {
    broadcast('events', rows.slice(0, 200));
  }
  if (alerts.length) {
    broadcast('alerts', alerts.slice(0, 50));
  }

  // IOC matching runs after the response is queued so ingestion latency isn't gated on it.
  Promise.all(parsedLogs.map(({ original, parsed }) => matchIOCs({
    source: parsed?.source || original.source,
    computer: parsed?.computer || original.computer,
    username: parsed?.username || original.username,
    ip_address: parsed?.ip_address || original.ip_address,
    raw_log: parsed?.raw || (typeof original.raw === 'string' ? original.raw : JSON.stringify(original)),
  }).catch(() => []))).catch(() => {});

  return { rows, parsedLogs, alerts };
}

router.post('/ingest', async (req, res) => {
  const key = req.headers['x-api-key'];
  if (key !== INGEST_API_KEY)
    return res.status(401).json({ error: 'Invalid API key' });
  const logs = Array.isArray(req.body) ? req.body : [req.body];
  const agentId = req.headers['x-agent-id'] || null;
  try {
    const { rows } = await ingestLogs(logs, { agentId });
    res.json({ ingested: rows.length, status: 'ok' });
  } catch (e) {
    return res.status(503).json({ error: 'Event storage temporarily unavailable' });
  }
});

router.post('/import', authenticate, async (req, res) => {
  const { content, file_path: filePath } = req.body || {};
  try {
    const { logs, source } = await resolveImportLogs({ content, file_path: filePath });
    if (!logs.length) return res.status(400).json({ error: 'No log entries found to import' });
    if (logs.length > MAX_IMPORT_RECORDS) {
      return res.status(400).json({ error: `Too many log entries (${logs.length}). Max allowed is ${MAX_IMPORT_RECORDS}` });
    }

    const { rows, alerts } = await ingestLogs(logs);
    res.json({
      imported: rows.length,
      alerts_created: alerts.length,
      source,
      profiles: summarizeBy(rows, 'parser_profile'),
      indices: summarizeBy(rows, 'index_name'),
      classes: summarizeBy(rows, 'ocsf_class_name'),
      status: 'ok',
    });
  } catch (e) {
    const status = /No log entries|Provide log content|too large|Too many log entries|not a file|ENOENT|EACCES|EPERM/i.test(e.message) ? 400 : 500;
    res.status(status).json({ error: e.message || 'Failed to import logs' });
  }
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
