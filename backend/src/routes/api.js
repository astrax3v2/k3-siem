'use strict';
const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { db, getDialect, sqlNow, sqlNowMinus, sqlDate } = require('../models/db');
const { authenticate, authorize, ROLE_ADMIN, ROLE_T1, ROLE_T2 } = require('../middleware/auth');
const router = express.Router();

// ── DASHBOARD ──────────────────────────────────────────────────────────────
router.get('/dashboard/stats', authenticate, async (req, res) => {
  const d = db();
  const last24hAlertsExpr = sqlNowMinus(1, 'day');
  const last24hEventsExpr = sqlNowMinus(1, 'day');
  const alerts = await d.prepare(`SELECT COUNT(*) as total, SUM(CASE WHEN severity='Critical' THEN 1 ELSE 0 END) as critical, SUM(CASE WHEN status NOT IN ('Closed') THEN 1 ELSE 0 END) as open FROM alerts WHERE created_at >= ${last24hAlertsExpr}`).get();
  const eventCount = (await d.prepare(`SELECT COUNT(*) as cnt FROM events WHERE timestamp >= ${last24hEventsExpr}`).get()).cnt;
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
  const { page=1, limit=25, severity, status, search } = req.query;
  const offset = (parseInt(page)-1)*parseInt(limit);
  const d = db(); let where=[], params=[];
  if (severity) { where.push('severity = ?'); params.push(severity); }
  if (status)   { where.push('status = ?');   params.push(status); }
  if (search)   { where.push('(title LIKE ? OR asset LIKE ? OR username LIKE ?)'); params.push(`%${search}%`,`%${search}%`,`%${search}%`); }
  const wc = where.length ? 'WHERE '+where.join(' AND ') : '';
  const total = (await d.prepare(`SELECT COUNT(*) as cnt FROM alerts ${wc}`).get(...params))?.cnt || 0;
  const alerts = await d.prepare(`SELECT * FROM alerts ${wc} ORDER BY created_at DESC LIMIT ? OFFSET ?`).all(...params, parseInt(limit), offset);
  res.json({ alerts, total, page:parseInt(page), pages:Math.ceil(total/parseInt(limit)) });
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
  const alert = await db().prepare('SELECT * FROM alerts WHERE id = ?').get(req.params.id);
  if (!alert) return res.status(404).json({ error: 'Not found' });
  res.json(alert);
});

router.patch('/alerts/:id', authenticate, authorize(ROLE_T1, ROLE_T2, ROLE_ADMIN), async (req, res) => {
  const { status, analyst_id, risk_score } = req.body;
  const d = db(); const fields=[], params=[];
  if (status)     { fields.push('status = ?');     params.push(status); }
  if (analyst_id) { fields.push('analyst_id = ?'); params.push(analyst_id); }
  if (risk_score !== undefined) { fields.push('risk_score = ?'); params.push(risk_score); }
  fields.push(`updated_at = ${sqlNow()}`);
  if (status === 'Closed') fields.push(`closed_at = ${sqlNow()}`);
  params.push(req.params.id);
  await d.prepare(`UPDATE alerts SET ${fields.join(', ')} WHERE id = ?`).run(...params);
  res.json(await d.prepare('SELECT * FROM alerts WHERE id = ?').get(req.params.id));
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
  res.json({ feeds: await db().prepare('SELECT * FROM intel_feeds ORDER BY name').all() });
});

// ── CORRELATION ────────────────────────────────────────────────────────────
router.get('/correlation/rules', authenticate, async (req, res) => {
  res.json({ rules: await db().prepare('SELECT * FROM correlation_rules ORDER BY risk_score DESC').all() });
});

router.patch('/correlation/rules/:id', authenticate, authorize(ROLE_T2, ROLE_ADMIN), async (req, res) => {
  const { enabled } = req.body;
  await db().prepare('UPDATE correlation_rules SET enabled = ? WHERE id = ?').run(enabled?1:0, req.params.id);
  res.json(await db().prepare('SELECT * FROM correlation_rules WHERE id = ?').get(req.params.id));
});

router.post('/correlation/rules', authenticate, authorize(ROLE_T2, ROLE_ADMIN), async (req, res) => {
  const { name, description, logic, severity='High', risk_score=80, window_minutes=5, indices, threshold=1 } = req.body;
  if (!name || !logic) return res.status(400).json({ error: 'name and logic required' });
  const id = uuidv4();
  await db().prepare('INSERT INTO correlation_rules(id,name,description,logic,severity,risk_score,window_minutes,indices,threshold) VALUES(?,?,?,?,?,?,?,?,?)').run(id,name,description,logic,severity,risk_score,window_minutes,JSON.stringify(indices||[]),threshold);
  res.status(201).json(await db().prepare('SELECT * FROM correlation_rules WHERE id = ?').get(id));
});

// ── PLAYBOOKS ──────────────────────────────────────────────────────────────
router.get('/soar/playbooks', authenticate, async (req, res) => {
  const d = db();
  res.json({ playbooks: await d.prepare('SELECT * FROM playbooks ORDER BY execution_count DESC').all(), executions: await d.prepare('SELECT * FROM playbook_executions ORDER BY started_at DESC LIMIT 20').all() });
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

  let step = 0;
  const tick = setInterval(() => {
    step++;
    (async () => {
      const d2 = db();
      if (step >= steps.length) {
        clearInterval(tick);
        await d2.prepare(`UPDATE playbook_executions SET status='completed',steps_completed=?,completed_at=${sqlNow()},result=? WHERE id=?`).run(steps.length,'All steps completed successfully',execId);
      } else {
        await d2.prepare('UPDATE playbook_executions SET steps_completed=? WHERE id=?').run(step,execId);
      }
    })().catch(() => {});
  }, 900);

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
  const wc = where.length ? 'WHERE ' + where.join(' AND ') : '';
  const total = (await d.prepare(`SELECT COUNT(*) as cnt FROM incidents i ${wc}`).get(...params))?.cnt || 0;
  const incidents = await d.prepare(`
    SELECT
      i.*,
      (SELECT COUNT(*) FROM incident_alerts ia WHERE ia.incident_id = i.id) as alerts_count,
      (SELECT COUNT(*) FROM incident_notes n WHERE n.incident_id = i.id) as notes_count
    FROM incidents i
    ${wc}
    ORDER BY i.created_at DESC
    LIMIT ? OFFSET ?
  `).all(...params, parseInt(limit), offset);
  res.json({ incidents, total, page: parseInt(page), pages: Math.ceil(total / parseInt(limit)) });
});

router.post('/incidents', authenticate, authorize(ROLE_T1, ROLE_T2, ROLE_ADMIN), async (req, res) => {
  const { title, description, severity = 'Medium', priority = 3, owner, tags, alert_ids } = req.body || {};
  if (!title) return res.status(400).json({ error: 'title required' });
  const id = uuidv4();
  const d = db();
  await d.prepare('INSERT INTO incidents(id,title,description,severity,status,priority,owner,tags) VALUES(?,?,?,?,?,?,?,?)')
    .run(id, title, description || null, severity, 'Open', priority, owner || req.user.username, JSON.stringify(tags || []));
  const ids = Array.isArray(alert_ids) ? alert_ids : [];
  if (ids.length) {
    const linkSql = getDialect() === 'postgres'
      ? 'INSERT INTO incident_alerts(incident_id,alert_id) VALUES(?,?) ON CONFLICT DO NOTHING'
      : 'INSERT OR IGNORE INTO incident_alerts(incident_id,alert_id) VALUES(?,?)';
    const link = d.prepare(linkSql);
    await d.transaction(async (rows) => { for (const aid of rows) await link.run(id, aid); })(ids);
  }
  res.status(201).json(await d.prepare('SELECT * FROM incidents WHERE id = ?').get(id));
});

router.post('/incidents/from-alert/:alertId', authenticate, authorize(ROLE_T1, ROLE_T2, ROLE_ADMIN), async (req, res) => {
  const d = db();
  const alert = await d.prepare('SELECT * FROM alerts WHERE id = ?').get(req.params.alertId);
  if (!alert) return res.status(404).json({ error: 'Alert not found' });
  const id = uuidv4();
  const title = `Incident: ${alert.title}`;
  await d.prepare('INSERT INTO incidents(id,title,description,severity,status,priority,owner,tags) VALUES(?,?,?,?,?,?,?,?)')
    .run(id, title, alert.description || null, alert.severity || 'Medium', 'Open', 2, req.user.username, JSON.stringify(['from-alert']));
  const linkSql = getDialect() === 'postgres'
    ? 'INSERT INTO incident_alerts(incident_id,alert_id) VALUES(?,?) ON CONFLICT DO NOTHING'
    : 'INSERT OR IGNORE INTO incident_alerts(incident_id,alert_id) VALUES(?,?)';
  await d.prepare(linkSql).run(id, alert.id);
  await d.prepare('INSERT INTO incident_notes(id,incident_id,author,note) VALUES(?,?,?,?)')
    .run(uuidv4(), id, req.user.username, `Created from alert ${alert.id.slice(0, 8)} (${alert.severity})`);
  res.status(201).json(await d.prepare('SELECT * FROM incidents WHERE id = ?').get(id));
});

router.get('/incidents/:id', authenticate, async (req, res) => {
  const d = db();
  const incident = await d.prepare('SELECT * FROM incidents WHERE id = ?').get(req.params.id);
  if (!incident) return res.status(404).json({ error: 'Not found' });
  const alerts = await d.prepare(`
    SELECT a.*
    FROM incident_alerts ia
    JOIN alerts a ON a.id = ia.alert_id
    WHERE ia.incident_id = ?
    ORDER BY a.created_at DESC
  `).all(req.params.id);
  const notes = await d.prepare('SELECT * FROM incident_notes WHERE incident_id = ? ORDER BY created_at DESC').all(req.params.id);
  res.json({ incident, alerts, notes });
});

router.patch('/incidents/:id', authenticate, authorize(ROLE_T1, ROLE_T2, ROLE_ADMIN), async (req, res) => {
  const { title, description, severity, status, priority, owner, tags } = req.body || {};
  const d = db();
  const fields = [];
  const params = [];
  if (title !== undefined) { fields.push('title = ?'); params.push(title); }
  if (description !== undefined) { fields.push('description = ?'); params.push(description); }
  if (severity !== undefined) { fields.push('severity = ?'); params.push(severity); }
  if (status !== undefined) { fields.push('status = ?'); params.push(status); }
  if (priority !== undefined) { fields.push('priority = ?'); params.push(priority); }
  if (owner !== undefined) { fields.push('owner = ?'); params.push(owner); }
  if (tags !== undefined) { fields.push('tags = ?'); params.push(JSON.stringify(tags || [])); }
  fields.push(`updated_at = ${sqlNow()}`);
  if (status === 'Closed') fields.push(`closed_at = ${sqlNow()}`);
  if (status && status !== 'Closed') fields.push('closed_at = NULL');
  params.push(req.params.id);
  await d.prepare(`UPDATE incidents SET ${fields.join(', ')} WHERE id = ?`).run(...params);
  res.json(await d.prepare('SELECT * FROM incidents WHERE id = ?').get(req.params.id));
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

// ── HEALTH ─────────────────────────────────────────────────────────────────
router.get('/health', (req, res) => res.json({ status:'ok', version:'2.4.1', platform:'K3 SIEM', time:new Date().toISOString() }));

module.exports = router;
