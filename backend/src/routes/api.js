'use strict';
const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { db, getDialect, sqlNow, sqlNowMinus, sqlDate } = require('../models/db');
const { chQuery, chNowMinus } = require('../models/clickhouse');
const { authenticate, authorize, ROLE_ADMIN, ROLE_T1, ROLE_T2 } = require('../middleware/auth');
const { runStep } = require('../services/connectors');
const { runOnce: runFeedSync, ensureFeedCatalog, getFeedDefinitions } = require('../services/connectors/feedSync');
const { logAction } = require('../services/audit');
const { computeSla } = require('../services/slaPolicy');
const { isAdmin, alertTeamJoin, scopeClause, guardTeamAccess } = require('../services/teamScope');
const { countRecent: countRecentCrossCorrelation } = require('../services/crossCorrelation');
const router = express.Router();

const withSla = (row) => (row ? { ...row, sla: computeSla(row) } : row);
const ALERT_TEAM_SELECT = `a.*, ag.team_id as team_id, t.name as team_name FROM alerts a ${alertTeamJoin()} LEFT JOIN teams t ON t.id = ag.team_id`;

// ── DASHBOARD ──────────────────────────────────────────────────────────────
router.get('/dashboard/stats', authenticate, async (req, res) => {
  const d = db();
  const last24hAlertsExpr = sqlNowMinus(1, 'day');
  const alerts = await d.prepare(`SELECT COUNT(*) as total, SUM(CASE WHEN severity='Critical' THEN 1 ELSE 0 END) as critical, SUM(CASE WHEN status NOT IN ('Closed') THEN 1 ELSE 0 END) as open FROM alerts WHERE created_at >= ${last24hAlertsExpr}`).get();
  const eventCount = (await chQuery(`SELECT COUNT(*) as cnt FROM events WHERE timestamp >= ${chNowMinus(1, 'day')}`))[0].cnt;
  const uebaHigh  = (await d.prepare('SELECT COUNT(*) as cnt FROM ueba_scores WHERE risk_score > 70').get()).cnt;
  const soarRuns  = (await d.prepare('SELECT COALESCE(SUM(execution_count),0) as cnt FROM playbooks').get()).cnt;
  const iocHits   = (await d.prepare('SELECT COALESCE(SUM(hits),0) as cnt FROM iocs').get()).cnt;
  const trend = await Promise.all(Array.from({length:14}, async (_, i) => {
    const date = new Date(Date.now()-(13-i)*86400000).toISOString().slice(0,10);
    const cnt = (await d.prepare(`SELECT COUNT(*) as cnt FROM alerts WHERE ${sqlDate('created_at')} = ?`).get(date))?.cnt || 0;
    return { date, count: cnt };
  }));

  const allAgents = await d.prepare('SELECT last_heartbeat FROM agents').all();
  const now = Date.now();
  let agOnline = 0, agOffline = 0;
  for (const a of allAgents) {
    const diff = now - new Date(a.last_heartbeat).getTime();
    if (diff < 300000) agOnline++; else agOffline++;
  }
  const agentStats = { total: allAgents.length, online: agOnline, offline: agOffline };

  const assetTotal = (await d.prepare('SELECT COUNT(*) as cnt FROM assets').get())?.cnt || 0;
  const assetByOs = await d.prepare('SELECT os_name, COUNT(*) as cnt FROM assets GROUP BY os_name ORDER BY cnt DESC').all();
  const assetCompliant = (await d.prepare("SELECT COUNT(*) as cnt FROM assets WHERE firewall_enabled = 1 AND antivirus_status != 'None' AND antivirus_status != 'Unknown'").get())?.cnt || 0;
  const assetStats = { total: assetTotal, byOs: assetByOs, compliant: assetCompliant, compliancePercent: assetTotal > 0 ? Math.round((assetCompliant / assetTotal) * 100) : 0 };

  res.json({ alerts, eventCount, uebaHigh, soarRuns, iocHits, trend, agentStats, assetStats });
});

// ── ALERTS ─────────────────────────────────────────────────────────────────
router.get('/alerts', authenticate, async (req, res) => {
  const { page=1, limit=25, severity, status, search, mitre_tactic } = req.query;
  const offset = (parseInt(page)-1)*parseInt(limit);
  const d = db(); let where=[], params=[];
  if (severity) { where.push('a.severity = ?'); params.push(severity); }
  if (status)   { where.push('a.status = ?');   params.push(status); }
  if (mitre_tactic) { where.push('a.mitre_tactic = ?'); params.push(mitre_tactic); }
  if (search)   { where.push('(a.title LIKE ? OR a.asset LIKE ? OR a.username LIKE ?)'); params.push(`%${search}%`,`%${search}%`,`%${search}%`); }
  const scope = scopeClause(req.user, 'ag.team_id');
  if (scope.clause) { where.push(scope.clause); params.push(...scope.params); }
  const wc = where.length ? 'WHERE '+where.join(' AND ') : '';
  const total = (await d.prepare(`SELECT COUNT(*) as cnt FROM alerts a ${alertTeamJoin()} ${wc}`).get(...params))?.cnt || 0;
  const alerts = await d.prepare(`SELECT ${ALERT_TEAM_SELECT} ${wc} ORDER BY a.created_at DESC LIMIT ? OFFSET ?`).all(...params, parseInt(limit), offset);
  res.json({ alerts: alerts.map(withSla), total, page:parseInt(page), pages:Math.ceil(total/parseInt(limit)) });
});

router.get('/alerts/stats', authenticate, async (req, res) => {
  const d = db();
  const last24hExpr = sqlNowMinus(1, 'day');
  res.json({
    bySeverity: await d.prepare('SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity').all(),
    byStatus:   await d.prepare('SELECT status, COUNT(*) as cnt FROM alerts GROUP BY status').all(),
    byTactic:   await d.prepare('SELECT mitre_tactic, COUNT(*) as cnt FROM alerts GROUP BY mitre_tactic ORDER BY cnt DESC LIMIT 5').all(),
    last24h:    (await d.prepare(`SELECT COUNT(*) as cnt FROM alerts WHERE created_at >= ${last24hExpr}`).get()).cnt,
    open:       (await d.prepare("SELECT COUNT(*) as cnt FROM alerts WHERE status NOT IN ('Closed')").get()).cnt,
  });
});

router.get('/alerts/:id', authenticate, async (req, res) => {
  const alert = await db().prepare(`SELECT ${ALERT_TEAM_SELECT} WHERE a.id = ?`).get(req.params.id);
  if (!alert) return res.status(404).json({ error: 'Not found' });
  if (!guardTeamAccess(res, req.user, alert.team_id)) return;
  res.json(withSla(alert));
});

router.patch('/alerts/:id', authenticate, authorize(ROLE_T1, ROLE_T2, ROLE_ADMIN), async (req, res) => {
  const d = db();
  const existing = await d.prepare(`SELECT a.id, ag.team_id as team_id FROM alerts a ${alertTeamJoin()} WHERE a.id = ?`).get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'Not found' });
  if (!guardTeamAccess(res, req.user, existing.team_id)) return;

  const { status, analyst_id, risk_score } = req.body;
  const fields=[], params=[];
  if (status) {
    fields.push('status = ?'); params.push(status);
    // Set once, the first time status moves off "New" — later status changes don't touch it.
    fields.push(`acknowledged_at = COALESCE(acknowledged_at, CASE WHEN ? <> 'New' THEN ${sqlNow()} ELSE NULL END)`);
    params.push(status);
  }
  if (analyst_id) { fields.push('analyst_id = ?'); params.push(analyst_id); }
  if (risk_score !== undefined) { fields.push('risk_score = ?'); params.push(risk_score); }
  fields.push(`updated_at = ${sqlNow()}`);
  if (status === 'Closed') fields.push(`closed_at = ${sqlNow()}`);
  params.push(req.params.id);
  await d.prepare(`UPDATE alerts SET ${fields.join(', ')} WHERE id = ?`).run(...params);
  if (status) await logAction(req.user.username, 'alert_status_changed', 'alert', req.params.id, status, req.ip);
  res.json(withSla(await d.prepare(`SELECT ${ALERT_TEAM_SELECT} WHERE a.id = ?`).get(req.params.id)));
});

// ── IOCs ───────────────────────────────────────────────────────────────────
router.get('/intel/iocs', authenticate, async (req, res) => {
  const { type, severity, search, page=1, limit=50 } = req.query;
  const offset = (parseInt(page)-1)*parseInt(limit);
  const d = db(); let where=[], params=[];
  if (type)     { where.push('type = ?');     params.push(type); }
  if (severity) { where.push('severity = ?'); params.push(severity); }
  if (search)   { where.push('(value LIKE ? OR description LIKE ?)'); params.push(`%${search}%`,`%${search}%`); }
  const wc = where.length ? 'WHERE '+where.join(' AND ') : '';
  const total = (await d.prepare(`SELECT COUNT(*) as cnt FROM iocs ${wc}`).get(...params))?.cnt || 0;
  const iocs  = await d.prepare(`SELECT * FROM iocs ${wc} ORDER BY confidence DESC LIMIT ? OFFSET ?`).all(...params, parseInt(limit), offset);
  res.json({ iocs, total, pages: Math.ceil(total/parseInt(limit)) });
});

router.post('/intel/iocs', authenticate, authorize(ROLE_T2, ROLE_ADMIN), async (req, res) => {
  const { type, value, confidence=50, severity='Medium', source, description, tags } = req.body;
  if (!type || !value) return res.status(400).json({ error: 'type and value required' });
  const id = uuidv4();
  await db().prepare('INSERT INTO iocs(id,type,value,confidence,severity,source,description,tags) VALUES(?,?,?,?,?,?,?,?)').run(id,type,value,confidence,severity,source,description,JSON.stringify(tags||[]));
  res.status(201).json(await db().prepare('SELECT * FROM iocs WHERE id = ?').get(id));
});

router.get('/intel/feeds', authenticate, async (req, res) => {
  const d = db();
  await ensureFeedCatalog(d);
  const supported = getFeedDefinitions().map((feed) => feed.name);
  const placeholders = supported.map(() => '?').join(',');
  const feeds = await d.prepare(`SELECT * FROM intel_feeds WHERE name IN (${placeholders}) ORDER BY name`).all(...supported);
  res.json({ feeds });
});

async function handleFeedSync(req, res) {
  const result = await runFeedSync();
  await logAction(req.user.username, 'threat_feed_sync', 'intel_feed', 'builtin', `added:${result.totals.added}`, req.ip);
  res.json(result);
}

router.post('/intel/feeds/sync', authenticate, authorize(ROLE_T2, ROLE_ADMIN), handleFeedSync);
router.get('/intel/feeds/sync', authenticate, authorize(ROLE_T2, ROLE_ADMIN), handleFeedSync);

// ── CORRELATION ────────────────────────────────────────────────────────────
router.get('/correlation/rules', authenticate, async (req, res) => {
  res.json({ rules: await db().prepare('SELECT * FROM correlation_rules ORDER BY risk_score DESC').all() });
});

router.get('/correlation/cross-hits', authenticate, async (req, res) => {
  res.json({ count: await countRecentCrossCorrelation() });
});

router.patch('/correlation/rules/:id', authenticate, authorize(ROLE_T2, ROLE_ADMIN), async (req, res) => {
  const d = db();
  const existing = await d.prepare('SELECT * FROM correlation_rules WHERE id = ?').get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'Not found' });

  const {
    enabled,
    name,
    description,
    logic,
    severity,
    risk_score,
    window_minutes,
    indices,
    threshold,
    conditions,
  } = req.body || {};

  const fields = [];
  const params = [];
  let onlyEnabledChanged = enabled !== undefined;

  if (enabled !== undefined) {
    fields.push('enabled = ?');
    params.push(enabled ? 1 : 0);
  }
  if (name !== undefined) {
    const normalizedName = String(name).trim();
    if (!normalizedName) return res.status(400).json({ error: 'name required' });
    fields.push('name = ?');
    params.push(normalizedName);
    onlyEnabledChanged = false;
  }
  if (description !== undefined) {
    fields.push('description = ?');
    params.push(description ? String(description).trim() : '');
    onlyEnabledChanged = false;
  }
  if (logic !== undefined) {
    const normalizedLogic = String(logic).trim();
    if (!normalizedLogic) return res.status(400).json({ error: 'logic required' });
    fields.push('logic = ?');
    params.push(normalizedLogic);
    onlyEnabledChanged = false;
  }
  if (severity !== undefined) {
    fields.push('severity = ?');
    params.push(severity);
    onlyEnabledChanged = false;
  }
  if (risk_score !== undefined) {
    fields.push('risk_score = ?');
    params.push(parseInt(risk_score, 10) || 0);
    onlyEnabledChanged = false;
  }
  if (window_minutes !== undefined) {
    fields.push('window_minutes = ?');
    params.push(parseInt(window_minutes, 10) || 1);
    onlyEnabledChanged = false;
  }
  if (indices !== undefined) {
    const normalizedIndices = Array.isArray(indices)
      ? indices.map((item) => String(item).trim()).filter(Boolean)
      : String(indices || '')
        .split(',')
        .map((item) => item.trim())
        .filter(Boolean);
    fields.push('indices = ?');
    params.push(JSON.stringify(normalizedIndices));
    onlyEnabledChanged = false;
  }
  if (threshold !== undefined) {
    fields.push('threshold = ?');
    params.push(parseInt(threshold, 10) || 1);
    onlyEnabledChanged = false;
  }
  if (conditions !== undefined) {
    fields.push('conditions = ?');
    params.push(conditions == null ? null : JSON.stringify(conditions));
    onlyEnabledChanged = false;
  }

  if (!fields.length) return res.json(existing);

  params.push(req.params.id);
  await d.prepare(`UPDATE correlation_rules SET ${fields.join(', ')} WHERE id = ?`).run(...params);

  const updated = await d.prepare('SELECT * FROM correlation_rules WHERE id = ?').get(req.params.id);
  const action = onlyEnabledChanged
    ? (updated.enabled ? 'rule_enabled' : 'rule_disabled')
    : 'rule_updated';
  await logAction(req.user.username, action, 'correlation_rule', req.params.id, updated.name, req.ip);
  res.json(updated);
});

router.post('/correlation/rules', authenticate, authorize(ROLE_T2, ROLE_ADMIN), async (req, res) => {
  const { name, description, logic, severity='High', risk_score=80, window_minutes=5, indices, threshold=1, conditions } = req.body;
  if (!name || !logic) return res.status(400).json({ error: 'name and logic required' });
  const id = uuidv4();
  await db().prepare('INSERT INTO correlation_rules(id,name,description,logic,severity,risk_score,window_minutes,indices,threshold,conditions) VALUES(?,?,?,?,?,?,?,?,?,?)').run(id,name,description,logic,severity,risk_score,window_minutes,JSON.stringify(indices||[]),threshold,conditions?JSON.stringify(conditions):null);
  await logAction(req.user.username, 'rule_created', 'correlation_rule', id, name, req.ip);
  res.status(201).json(await db().prepare('SELECT * FROM correlation_rules WHERE id = ?').get(id));
});

// ── PLAYBOOKS ──────────────────────────────────────────────────────────────
router.get('/soar/playbooks', authenticate, async (req, res) => {
  const d = db();
  res.json({ playbooks: await d.prepare('SELECT * FROM playbooks ORDER BY execution_count DESC').all(), executions: await d.prepare('SELECT * FROM playbook_executions ORDER BY started_at DESC LIMIT 20').all() });
});

router.patch('/soar/playbooks/:id', authenticate, authorize(ROLE_T2, ROLE_ADMIN), async (req, res) => {
  const d = db();
  const existing = await d.prepare('SELECT * FROM playbooks WHERE id = ?').get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'Not found' });

  const { name, description, trigger_condition, status, steps } = req.body;
  if (!name || !String(name).trim()) return res.status(400).json({ error: 'name required' });
  if (!trigger_condition || !String(trigger_condition).trim()) return res.status(400).json({ error: 'trigger_condition required' });

  const normalizedStatus = status === 'Paused' ? 'Paused' : 'Active';
  const normalizedSteps = Array.isArray(steps)
    ? steps.map((step) => String(step).trim()).filter(Boolean)
    : String(steps || '')
      .split(/\r?\n/)
      .map((step) => step.trim())
      .filter(Boolean);

  await d.prepare('UPDATE playbooks SET name=?, description=?, trigger_condition=?, status=?, steps=? WHERE id=?')
    .run(String(name).trim(), description || '', String(trigger_condition).trim(), normalizedStatus, JSON.stringify(normalizedSteps), req.params.id);
  await logAction(req.user.username, 'playbook_updated', 'playbook', req.params.id, String(name).trim(), req.ip);

  res.json(await d.prepare('SELECT * FROM playbooks WHERE id = ?').get(req.params.id));
});

router.post('/soar/playbooks/:id/execute', authenticate, authorize(ROLE_T2, ROLE_ADMIN), async (req, res) => {
  const { alert_id } = req.body;
  const d = db();
  const pb = await d.prepare('SELECT * FROM playbooks WHERE id = ?').get(req.params.id);
  if (!pb) return res.status(404).json({ error: 'Not found' });
  if (pb.status !== 'Active') return res.status(400).json({ error: 'Playbook is not active' });
  const steps = JSON.parse(pb.steps || '[]');
  const execId = uuidv4();
  await d.prepare('INSERT INTO playbook_executions(id,playbook_id,alert_id,triggered_by,status,steps_completed) VALUES(?,?,?,?,?,?)').run(execId,pb.id,alert_id||null,req.user.username,'running',0);
  await d.prepare(`UPDATE playbooks SET execution_count=execution_count+1, last_executed=${sqlNow()} WHERE id=?`).run(pb.id);

  const alert = alert_id ? await d.prepare('SELECT * FROM alerts WHERE id = ?').get(alert_id) : null;
  const context = alert ? {
    summary: alert.title, ip: alert.ip_address, asset: alert.asset,
    hash: (alert.raw_evidence || '').match(/\b[a-fA-F0-9]{32,64}\b/)?.[0] || null,
  } : { summary: pb.name };

  (async () => {
    const d2 = db();
    const results = [];
    for (let i = 0; i < steps.length; i++) {
      let r;
      try { r = await runStep(steps[i], context); }
      catch (e) { r = { ok: false, detail: `Step failed: ${e.message}`, connector: 'unknown' }; }
      results.push({ step: steps[i], ...r });
      await d2.prepare('UPDATE playbook_executions SET steps_completed = ? WHERE id = ?').run(i + 1, execId);
    }
    const okCount = results.filter((r) => r.ok).length;
    const notConfigured = results.filter((r) => !r.ok && /not configured/i.test(r.detail || ''));
    const uniqueConnectors = [...new Set(notConfigured.map((r) => r.connector))];
    const summary = notConfigured.length
      ? `${okCount}/${results.length} steps completed — ${notConfigured.length} skipped (connector not configured: ${uniqueConnectors.join(', ')})`
      : `${okCount}/${results.length} steps completed successfully`;
    await d2.prepare(`UPDATE playbook_executions SET status='completed', completed_at=${sqlNow()}, result=? WHERE id=?`)
      .run(summary, execId);
  })().catch((e) => console.error('[SOAR] Execution failed:', e.message));

  res.json({ execution_id: execId, playbook: pb.name, steps_total: steps.length, status: 'running' });
});

router.get('/soar/executions/:id', authenticate, async (req, res) => {
  const exec = await db().prepare('SELECT * FROM playbook_executions WHERE id = ?').get(req.params.id);
  if (!exec) return res.status(404).json({ error: 'Not found' });
  res.json(exec);
});

// ── UEBA ───────────────────────────────────────────────────────────────────
router.get('/ueba/scores', authenticate, async (req, res) => {
  const scores = await db().prepare('SELECT * FROM ueba_scores ORDER BY risk_score DESC').all();
  res.json({ scores, highRisk: scores.filter(s=>s.risk_score>70).length, totalAnomalies: scores.reduce((s,u)=>s+u.anomaly_count,0), totalUsers: scores.length });
});

// ── KQL QUERIES ────────────────────────────────────────────────────────────
router.get('/kql/queries', authenticate, async (req, res) => {
  res.json({ queries: await db().prepare('SELECT * FROM kql_saved_queries ORDER BY created_at DESC').all() });
});

router.post('/kql/queries', authenticate, async (req, res) => {
  const { name, query, description, category, is_rule=0 } = req.body;
  if (!name||!query) return res.status(400).json({ error: 'name and query required' });
  const id = uuidv4();
  await db().prepare('INSERT INTO kql_saved_queries(id,name,query,description,category,created_by,is_rule) VALUES(?,?,?,?,?,?,?)').run(id,name,query,description,category,req.user.username,is_rule?1:0);
  res.status(201).json(await db().prepare('SELECT * FROM kql_saved_queries WHERE id = ?').get(id));
});

// ── INCIDENT RESPONSE ───────────────────────────────────────────────────────
router.get('/incidents', authenticate, async (req, res) => {
  const { page = 1, limit = 25, status, severity, search } = req.query;
  const offset = (parseInt(page) - 1) * parseInt(limit);
  const d = db();
  const where = [];
  const params = [];
  if (status) { where.push('i.status = ?'); params.push(status); }
  if (severity) { where.push('i.severity = ?'); params.push(severity); }
  if (search) { where.push('(i.title LIKE ? OR i.description LIKE ?)'); params.push(`%${search}%`, `%${search}%`); }
  const scope = scopeClause(req.user, 'i.team_id');
  if (scope.clause) { where.push(scope.clause); params.push(...scope.params); }
  const wc = where.length ? 'WHERE ' + where.join(' AND ') : '';
  const total = (await d.prepare(`SELECT COUNT(*) as cnt FROM incidents i ${wc}`).get(...params))?.cnt || 0;
  const incidents = await d.prepare(`
    SELECT
      i.*, t.name as team_name,
      (SELECT COUNT(*) FROM incident_alerts ia WHERE ia.incident_id = i.id) as alerts_count,
      (SELECT COUNT(*) FROM incident_notes n WHERE n.incident_id = i.id) as notes_count
    FROM incidents i
    LEFT JOIN teams t ON t.id = i.team_id
    ${wc}
    ORDER BY i.created_at DESC
    LIMIT ? OFFSET ?
  `).all(...params, parseInt(limit), offset);
  res.json({ incidents: incidents.map(withSla), total, page: parseInt(page), pages: Math.ceil(total / parseInt(limit)) });
});

router.post('/incidents', authenticate, authorize(ROLE_T1, ROLE_T2, ROLE_ADMIN), async (req, res) => {
  const { title, description, severity = 'Medium', priority = 3, owner, tags, alert_ids, team_id } = req.body || {};
  if (!title) return res.status(400).json({ error: 'title required' });
  const id = uuidv4();
  const d = db();
  await d.prepare('INSERT INTO incidents(id,title,description,severity,status,priority,owner,tags,team_id) VALUES(?,?,?,?,?,?,?,?,?)')
    .run(id, title, description || null, severity, 'Open', priority, owner || req.user.username, JSON.stringify(tags || []), team_id !== undefined ? team_id : (req.user.team_id || null));
  const ids = Array.isArray(alert_ids) ? alert_ids : [];
  if (ids.length) {
    const linkSql = getDialect() === 'postgres'
      ? 'INSERT INTO incident_alerts(incident_id,alert_id) VALUES(?,?) ON CONFLICT DO NOTHING'
      : 'INSERT OR IGNORE INTO incident_alerts(incident_id,alert_id) VALUES(?,?)';
    const link = d.prepare(linkSql);
    await d.transaction(async (rows) => { for (const aid of rows) await link.run(id, aid); })(ids);
  }
  res.status(201).json(withSla(await d.prepare('SELECT i.*, t.name as team_name FROM incidents i LEFT JOIN teams t ON t.id = i.team_id WHERE i.id = ?').get(id)));
});

router.post('/incidents/from-alert/:alertId', authenticate, authorize(ROLE_T1, ROLE_T2, ROLE_ADMIN), async (req, res) => {
  const d = db();
  const alert = await d.prepare(`SELECT a.*, ag.team_id as team_id FROM alerts a ${alertTeamJoin()} WHERE a.id = ?`).get(req.params.alertId);
  if (!alert) return res.status(404).json({ error: 'Alert not found' });
  if (!guardTeamAccess(res, req.user, alert.team_id)) return;
  const id = uuidv4();
  const title = `Incident: ${alert.title}`;
  await d.prepare('INSERT INTO incidents(id,title,description,severity,status,priority,owner,tags,team_id) VALUES(?,?,?,?,?,?,?,?,?)')
    .run(id, title, alert.description || null, alert.severity || 'Medium', 'Open', 2, req.user.username, JSON.stringify(['from-alert']), alert.team_id || req.user.team_id || null);
  const linkSql = getDialect() === 'postgres'
    ? 'INSERT INTO incident_alerts(incident_id,alert_id) VALUES(?,?) ON CONFLICT DO NOTHING'
    : 'INSERT OR IGNORE INTO incident_alerts(incident_id,alert_id) VALUES(?,?)';
  await d.prepare(linkSql).run(id, alert.id);
  await d.prepare('INSERT INTO incident_notes(id,incident_id,author,note) VALUES(?,?,?,?)')
    .run(uuidv4(), id, req.user.username, `Created from alert ${alert.id.slice(0, 8)} (${alert.severity})`);
  res.status(201).json(withSla(await d.prepare('SELECT i.*, t.name as team_name FROM incidents i LEFT JOIN teams t ON t.id = i.team_id WHERE i.id = ?').get(id)));
});

router.get('/incidents/:id', authenticate, async (req, res) => {
  const d = db();
  const incident = await d.prepare('SELECT i.*, t.name as team_name FROM incidents i LEFT JOIN teams t ON t.id = i.team_id WHERE i.id = ?').get(req.params.id);
  if (!incident) return res.status(404).json({ error: 'Not found' });
  if (!guardTeamAccess(res, req.user, incident.team_id)) return;
  const alerts = await d.prepare(`
    SELECT a.*
    FROM incident_alerts ia
    JOIN alerts a ON a.id = ia.alert_id
    WHERE ia.incident_id = ?
    ORDER BY a.created_at DESC
  `).all(req.params.id);
  const notes = await d.prepare('SELECT * FROM incident_notes WHERE incident_id = ? ORDER BY created_at DESC').all(req.params.id);
  const processTree = await chQuery('SELECT * FROM process_nodes WHERE incident_id = {incident_id:String} ORDER BY sequence', { incident_id: req.params.id });
  res.json({ incident: withSla(incident), alerts, notes, process_tree: processTree });
});

router.patch('/incidents/:id', authenticate, authorize(ROLE_T1, ROLE_T2, ROLE_ADMIN), async (req, res) => {
  const d = db();
  const existing = await d.prepare('SELECT id, team_id FROM incidents WHERE id = ?').get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'Not found' });
  if (!guardTeamAccess(res, req.user, existing.team_id)) return;

  const { title, description, severity, status, priority, owner, tags, team_id } = req.body || {};
  const fields = [];
  const params = [];
  if (title !== undefined) { fields.push('title = ?'); params.push(title); }
  if (description !== undefined) { fields.push('description = ?'); params.push(description); }
  if (severity !== undefined) { fields.push('severity = ?'); params.push(severity); }
  if (status !== undefined) {
    fields.push('status = ?'); params.push(status);
    // Set once, the first time status moves off "Open" — later status changes don't touch it.
    fields.push(`acknowledged_at = COALESCE(acknowledged_at, CASE WHEN ? <> 'Open' THEN ${sqlNow()} ELSE NULL END)`);
    params.push(status);
  }
  if (priority !== undefined) { fields.push('priority = ?'); params.push(priority); }
  if (owner !== undefined) { fields.push('owner = ?'); params.push(owner); }
  if (tags !== undefined) { fields.push('tags = ?'); params.push(JSON.stringify(tags || [])); }
  // Reassigning an item to a different team's queue is an admin-only action; non-admins'
  // attempts to change it are silently ignored rather than hard-failing the whole request.
  if (team_id !== undefined && isAdmin(req.user)) { fields.push('team_id = ?'); params.push(team_id); }
  fields.push(`updated_at = ${sqlNow()}`);
  if (status === 'Closed') fields.push(`closed_at = ${sqlNow()}`);
  if (status && status !== 'Closed') fields.push('closed_at = NULL');
  params.push(req.params.id);
  await d.prepare(`UPDATE incidents SET ${fields.join(', ')} WHERE id = ?`).run(...params);
  if (status) await logAction(req.user.username, 'incident_status_changed', 'incident', req.params.id, status, req.ip);
  res.json(withSla(await d.prepare('SELECT i.*, t.name as team_name FROM incidents i LEFT JOIN teams t ON t.id = i.team_id WHERE i.id = ?').get(req.params.id)));
});

router.post('/incidents/:id/notes', authenticate, authorize(ROLE_T1, ROLE_T2, ROLE_ADMIN), async (req, res) => {
  const { note } = req.body || {};
  if (!note) return res.status(400).json({ error: 'note required' });
  const d = db();
  const exists = await d.prepare('SELECT 1 as ok FROM incidents WHERE id = ?').get(req.params.id);
  if (!exists) return res.status(404).json({ error: 'Not found' });
  const id = uuidv4();
  await d.prepare('INSERT INTO incident_notes(id,incident_id,author,note) VALUES(?,?,?,?)').run(id, req.params.id, req.user.username, note);
  await d.prepare(`UPDATE incidents SET updated_at=${sqlNow()} WHERE id=?`).run(req.params.id);
  res.status(201).json(await d.prepare('SELECT * FROM incident_notes WHERE id = ?').get(id));
});

router.post('/incidents/:id/alerts', authenticate, authorize(ROLE_T1, ROLE_T2, ROLE_ADMIN), async (req, res) => {
  const { alert_id } = req.body || {};
  if (!alert_id) return res.status(400).json({ error: 'alert_id required' });
  const d = db();
  const inc = await d.prepare('SELECT 1 as ok FROM incidents WHERE id = ?').get(req.params.id);
  if (!inc) return res.status(404).json({ error: 'Not found' });
  const alert = await d.prepare('SELECT 1 as ok FROM alerts WHERE id = ?').get(alert_id);
  if (!alert) return res.status(404).json({ error: 'Alert not found' });
  const linkSql = getDialect() === 'postgres'
    ? 'INSERT INTO incident_alerts(incident_id,alert_id) VALUES(?,?) ON CONFLICT DO NOTHING'
    : 'INSERT OR IGNORE INTO incident_alerts(incident_id,alert_id) VALUES(?,?)';
  await d.prepare(linkSql).run(req.params.id, alert_id);
  await d.prepare(`UPDATE incidents SET updated_at=${sqlNow()} WHERE id=?`).run(req.params.id);
  res.json({ ok: true });
});

// ── AUDIT LOG ──────────────────────────────────────────────────────────────
router.get('/audit', authenticate, authorize(ROLE_ADMIN), async (req, res) => {
  const { page = 1, limit = 50 } = req.query;
  const offset = (parseInt(page) - 1) * parseInt(limit);
  const total = (await chQuery('SELECT COUNT(*) as cnt FROM audit_log'))[0]?.cnt || 0;
  const entries = await chQuery('SELECT * FROM audit_log ORDER BY created_at DESC LIMIT {limit:UInt32} OFFSET {offset:UInt32}', { limit: parseInt(limit), offset });
  res.json({ entries, total, page: parseInt(page), pages: Math.ceil(total / parseInt(limit)) });
});

// ── HEALTH ─────────────────────────────────────────────────────────────────
router.get('/health', (req, res) => res.json({ status:'ok', version:'2.4.1', platform:'K3 SIEM', time:new Date().toISOString() }));

module.exports = router;
