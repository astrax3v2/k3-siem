'use strict';
const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { db, sqlNowMinus } = require('../models/db');
const { authenticate, authorize } = require('../middleware/auth');
const { INGEST_API_KEY } = require('../config');
const { logAction } = require('../services/audit');
const { isAdmin, scopeClause, guardTeamAccess } = require('../services/teamScope');
const router = express.Router();

function apiKeyAuth(req, res, next) {
  const key = req.headers['x-api-key'];
  if (key !== INGEST_API_KEY)
    return res.status(401).json({ error: 'Invalid API key' });
  next();
}

router.post('/register', apiKeyAuth, async (req, res) => {
  const { hostname, os, ip, agent_version, tags, collected_sources } = req.body;
  if (!hostname) return res.status(400).json({ error: 'hostname is required' });

  const d = db();
  const existing = await d.prepare('SELECT id FROM agents WHERE hostname = ? AND ip = ?').get(hostname, ip || '');

  if (existing) {
    await d.prepare('UPDATE agents SET os = ?, agent_version = ?, tags = ?, collected_sources = ?, status = ?, last_heartbeat = ? WHERE id = ?')
      .run(os || null, agent_version || null, tags ? JSON.stringify(tags) : null, collected_sources ? JSON.stringify(collected_sources) : null, 'online', new Date().toISOString(), existing.id);
    return res.json({ agent_id: existing.id, status: 'reconnected' });
  }

  const id = uuidv4();
  await d.prepare('INSERT INTO agents(id, hostname, os, ip, agent_version, tags, collected_sources, status, last_heartbeat) VALUES(?,?,?,?,?,?,?,?,?)')
    .run(id, hostname, os || null, ip || null, agent_version || null, tags ? JSON.stringify(tags) : null, collected_sources ? JSON.stringify(collected_sources) : null, 'online', new Date().toISOString());

  console.log(`[Agent] Registered: ${hostname} (${os || 'unknown'}) - ${id}`);
  res.status(201).json({ agent_id: id, status: 'registered' });
});

router.post('/:id/heartbeat', apiKeyAuth, async (req, res) => {
  const { id } = req.params;
  const { metrics } = req.body;
  const d = db();

  const agent = await d.prepare('SELECT id FROM agents WHERE id = ?').get(id);
  if (!agent) return res.status(404).json({ error: 'Agent not found' });

  await d.prepare('UPDATE agents SET status = ?, last_heartbeat = ? WHERE id = ?')
    .run('online', new Date().toISOString(), id);

  res.json({ status: 'ok', server_time: new Date().toISOString() });
});

router.get('/', authenticate, async (req, res) => {
  const d = db();
  const scope = scopeClause(req.user, 'ag.team_id');
  const wc = scope.clause ? `WHERE ${scope.clause}` : '';
  const agents = await d.prepare(`SELECT ag.*, t.name as team_name FROM agents ag LEFT JOIN teams t ON t.id = ag.team_id ${wc} ORDER BY ag.registered_at DESC`).all(...scope.params);

  const now = Date.now();
  const enriched = agents.map(a => {
    const lastHb = a.last_heartbeat ? new Date(a.last_heartbeat).getTime() : 0;
    const diff = now - lastHb;
    let computedStatus = 'offline';
    if (diff < 60000) computedStatus = 'online';
    else if (diff < 300000) computedStatus = 'stale';

    return {
      ...a,
      tags: a.tags ? (typeof a.tags === 'string' ? JSON.parse(a.tags) : a.tags) : [],
      collected_sources: a.collected_sources ? (typeof a.collected_sources === 'string' ? JSON.parse(a.collected_sources) : a.collected_sources) : [],
      computed_status: computedStatus,
    };
  });

  res.json({ agents: enriched, total: enriched.length });
});

router.get('/stats', authenticate, async (req, res) => {
  const d = db();
  const total = (await d.prepare('SELECT COUNT(*) as cnt FROM agents').get())?.cnt || 0;
  const all = await d.prepare('SELECT last_heartbeat FROM agents').all();

  const now = Date.now();
  let online = 0, stale = 0, offline = 0;
  for (const a of all) {
    const diff = now - new Date(a.last_heartbeat).getTime();
    if (diff < 60000) online++;
    else if (diff < 300000) stale++;
    else offline++;
  }

  const totalEvents = (await d.prepare('SELECT SUM(events_sent) as total FROM agents').get())?.total || 0;

  res.json({ total, online, stale, offline, total_events: totalEvents });
});

router.get('/:id', authenticate, async (req, res) => {
  const d = db();
  const agent = await d.prepare('SELECT ag.*, t.name as team_name FROM agents ag LEFT JOIN teams t ON t.id = ag.team_id WHERE ag.id = ?').get(req.params.id);
  if (!agent) return res.status(404).json({ error: 'Agent not found' });
  if (!guardTeamAccess(res, req.user, agent.team_id)) return;

  const eventCount = (await d.prepare('SELECT COUNT(*) as cnt FROM events WHERE agent_id = ?').get(req.params.id))?.cnt || 0;
  const recentEvents = await d.prepare('SELECT * FROM events WHERE agent_id = ? ORDER BY timestamp DESC LIMIT 20').all(req.params.id);

  res.json({
    ...agent,
    tags: agent.tags ? (typeof agent.tags === 'string' ? JSON.parse(agent.tags) : agent.tags) : [],
    collected_sources: agent.collected_sources ? (typeof agent.collected_sources === 'string' ? JSON.parse(agent.collected_sources) : agent.collected_sources) : [],
    event_count: eventCount,
    recent_events: recentEvents,
  });
});

router.patch('/:id', authenticate, authorize('admin', 't2_analyst'), async (req, res) => {
  const { tags, config, team_id } = req.body;
  const d = db();
  const agent = await d.prepare('SELECT id, team_id FROM agents WHERE id = ?').get(req.params.id);
  if (!agent) return res.status(404).json({ error: 'Agent not found' });
  if (!guardTeamAccess(res, req.user, agent.team_id)) return;

  if (tags !== undefined) {
    await d.prepare('UPDATE agents SET tags = ? WHERE id = ?').run(JSON.stringify(tags), req.params.id);
  }
  if (config !== undefined) {
    await d.prepare('UPDATE agents SET config = ? WHERE id = ?').run(JSON.stringify(config), req.params.id);
  }
  // Assigning which team owns/monitors an endpoint is an admin-only action.
  if (team_id !== undefined && isAdmin(req.user)) {
    await d.prepare('UPDATE agents SET team_id = ? WHERE id = ?').run(team_id, req.params.id);
  }

  res.json({ status: 'updated' });
});

router.delete('/:id', authenticate, authorize('admin'), async (req, res) => {
  const d = db();
  await d.prepare('DELETE FROM agents WHERE id = ?').run(req.params.id);
  await logAction(req.user.username, 'agent_deleted', 'agent', req.params.id, null, req.ip);
  res.json({ status: 'deleted' });
});

// ── Inventory ──────────────────────────────────────────────────────────

router.post('/:id/inventory', apiKeyAuth, async (req, res) => {
  const { id } = req.params;
  const inv = req.body;
  const d = db();

  const agent = await d.prepare('SELECT id, hostname FROM agents WHERE id = ?').get(id);
  if (!agent) return res.status(404).json({ error: 'Agent not found' });

  const existing = await d.prepare('SELECT id FROM assets WHERE agent_id = ?').get(id);
  const now = new Date().toISOString();

  if (existing) {
    await d.prepare(`UPDATE assets SET hostname=?, os_name=?, os_version=?, os_arch=?, cpu_model=?, cpu_cores=?, ram_total_gb=?, disk_total_gb=?, disk_used_gb=?, network_interfaces=?, installed_software=?, running_services=?, open_ports=?, local_users=?, antivirus_status=?, firewall_enabled=?, last_patch_date=?, uptime_hours=?, domain=?, serial_number=?, updated_at=? WHERE agent_id=?`)
      .run(inv.hostname || agent.hostname, inv.os_name, inv.os_version, inv.os_arch, inv.cpu_model, inv.cpu_cores || 0, inv.ram_total_gb || 0, inv.disk_total_gb || 0, inv.disk_used_gb || 0, JSON.stringify(inv.network_interfaces || []), JSON.stringify(inv.installed_software || []), JSON.stringify(inv.running_services || []), JSON.stringify(inv.open_ports || []), JSON.stringify(inv.local_users || []), inv.antivirus_status || 'Unknown', inv.firewall_enabled ? 1 : 0, inv.last_patch_date || null, inv.uptime_hours || 0, inv.domain || null, inv.serial_number || null, now, id);
    res.json({ status: 'updated' });
  } else {
    const assetId = require('uuid').v4();
    await d.prepare(`INSERT INTO assets(id, agent_id, hostname, os_name, os_version, os_arch, cpu_model, cpu_cores, ram_total_gb, disk_total_gb, disk_used_gb, network_interfaces, installed_software, running_services, open_ports, local_users, antivirus_status, firewall_enabled, last_patch_date, uptime_hours, domain, serial_number, collected_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
      .run(assetId, id, inv.hostname || agent.hostname, inv.os_name, inv.os_version, inv.os_arch, inv.cpu_model, inv.cpu_cores || 0, inv.ram_total_gb || 0, inv.disk_total_gb || 0, inv.disk_used_gb || 0, JSON.stringify(inv.network_interfaces || []), JSON.stringify(inv.installed_software || []), JSON.stringify(inv.running_services || []), JSON.stringify(inv.open_ports || []), JSON.stringify(inv.local_users || []), inv.antivirus_status || 'Unknown', inv.firewall_enabled ? 1 : 0, inv.last_patch_date || null, inv.uptime_hours || 0, inv.domain || null, inv.serial_number || null, now, now);
    res.status(201).json({ status: 'created', asset_id: assetId });
  }
});

router.get('/assets/list', authenticate, async (req, res) => {
  const { os, search, compliance } = req.query;
  const d = db();
  let where = [], params = [];
  if (os) { where.push('os_name LIKE ?'); params.push(`%${os}%`); }
  if (search) {
    where.push('(hostname LIKE ? OR os_name LIKE ? OR cpu_model LIKE ? OR installed_software LIKE ?)');
    params.push(`%${search}%`, `%${search}%`, `%${search}%`, `%${search}%`);
  }
  if (compliance === 'compliant') { where.push('firewall_enabled = 1 AND antivirus_status != ? AND antivirus_status != ?'); params.push('None', 'Unknown'); }
  if (compliance === 'non-compliant') { where.push('(firewall_enabled = 0 OR antivirus_status = ? OR antivirus_status = ?)'); params.push('None', 'Unknown'); }
  const wc = where.length ? 'WHERE ' + where.join(' AND ') : '';
  const assets = await d.prepare(`SELECT a.*, ag.status as agent_status, ag.last_heartbeat, ag.ip as agent_ip FROM assets a LEFT JOIN agents ag ON a.agent_id = ag.id ${wc} ORDER BY a.updated_at DESC`).all(...params);

  const parsed = assets.map(a => ({
    ...a,
    network_interfaces: tryParse(a.network_interfaces),
    installed_software: tryParse(a.installed_software),
    running_services: tryParse(a.running_services),
    open_ports: tryParse(a.open_ports),
    local_users: tryParse(a.local_users),
  }));

  res.json({ assets: parsed, total: parsed.length });
});

router.post('/:id/vulnerabilities', apiKeyAuth, async (req, res) => {
  const { id } = req.params;
  const { vulnerabilities } = req.body;
  const d = db();

  const agent = await d.prepare('SELECT id FROM agents WHERE id = ?').get(id);
  if (!agent) return res.status(404).json({ error: 'Agent not found' });

  if (!Array.isArray(vulnerabilities) || vulnerabilities.length === 0) {
    return res.json({ status: 'ok', stored: 0 });
  }

  await d.prepare('DELETE FROM vulnerabilities WHERE agent_id = ?').run(id);

  let stored = 0;
  const now = new Date().toISOString();
  for (const v of vulnerabilities) {
    try {
      const vid = require('uuid').v4();
      await d.prepare(`INSERT INTO vulnerabilities(id, agent_id, cve_id, software_name, software_version, software_type, description, cvss_score, severity, published, last_modified, vuln_status, scanned_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`)
        .run(vid, id, v.cve_id, v.software_name || null, v.software_version || null, v.software_type || 'software', v.description || null, v.cvss_score != null ? v.cvss_score : null, (v.severity || 'UNKNOWN').toUpperCase(), v.published || null, v.last_modified || null, v.vuln_status || null, now);
      stored++;
    } catch (e) {
      // skip duplicates
    }
  }

  console.log(`[Vuln] Agent ${id}: stored ${stored} CVEs`);
  res.json({ status: 'ok', stored });
});

router.get('/assets/vulnerabilities/stats', authenticate, async (req, res) => {
  const d = db();
  const total = (await d.prepare('SELECT COUNT(*) as cnt FROM vulnerabilities').get())?.cnt || 0;
  const critical = (await d.prepare("SELECT COUNT(*) as cnt FROM vulnerabilities WHERE severity = 'CRITICAL'").get())?.cnt || 0;
  const high = (await d.prepare("SELECT COUNT(*) as cnt FROM vulnerabilities WHERE severity = 'HIGH'").get())?.cnt || 0;
  const medium = (await d.prepare("SELECT COUNT(*) as cnt FROM vulnerabilities WHERE severity = 'MEDIUM'").get())?.cnt || 0;
  const low = (await d.prepare("SELECT COUNT(*) as cnt FROM vulnerabilities WHERE severity IN ('LOW', 'NONE')").get())?.cnt || 0;
  const affected = (await d.prepare('SELECT COUNT(DISTINCT agent_id) as cnt FROM vulnerabilities').get())?.cnt || 0;
  res.json({ total, critical, high, medium, low, affected_assets: affected });
});

router.get('/assets/vulnerabilities', authenticate, async (req, res) => {
  const { agent_id, severity, search } = req.query;
  const d = db();
  let where = [], params = [];
  if (agent_id) { where.push('v.agent_id = ?'); params.push(agent_id); }
  if (severity) { where.push('v.severity = ?'); params.push(severity.toUpperCase()); }
  if (search) { where.push('(v.cve_id LIKE ? OR v.software_name LIKE ? OR v.description LIKE ?)'); params.push(`%${search}%`, `%${search}%`, `%${search}%`); }
  const wc = where.length ? 'WHERE ' + where.join(' AND ') : '';
  const vulns = await d.prepare(`SELECT v.*, a.hostname FROM vulnerabilities v LEFT JOIN assets a ON v.agent_id = a.agent_id ${wc} ORDER BY v.cvss_score DESC, v.scanned_at DESC LIMIT 500`).all(...params);
  res.json({ vulnerabilities: vulns, total: vulns.length });
});

router.get('/assets/stats', authenticate, async (req, res) => {
  const d = db();
  const total = (await d.prepare('SELECT COUNT(*) as cnt FROM assets').get())?.cnt || 0;
  const byOs = await d.prepare('SELECT os_name, COUNT(*) as cnt FROM assets GROUP BY os_name ORDER BY cnt DESC').all();
  const compliant = (await d.prepare("SELECT COUNT(*) as cnt FROM assets WHERE firewall_enabled = 1 AND antivirus_status != 'None' AND antivirus_status != 'Unknown'").get())?.cnt || 0;
  const avgUptime = (await d.prepare('SELECT AVG(uptime_hours) as avg FROM assets').get())?.avg || 0;
  const totalRam = (await d.prepare('SELECT SUM(ram_total_gb) as total FROM assets').get())?.total || 0;
  const totalDisk = (await d.prepare('SELECT SUM(disk_total_gb) as total FROM assets').get())?.total || 0;

  res.json({ total, byOs, compliant, compliancePercent: total > 0 ? Math.round((compliant / total) * 100) : 0, avgUptime: Math.round(avgUptime), totalRam: Math.round(totalRam), totalDisk: Math.round(totalDisk) });
});

router.get('/assets/:agentId', authenticate, async (req, res) => {
  const d = db();
  const asset = await d.prepare('SELECT a.*, ag.status as agent_status, ag.last_heartbeat, ag.hostname as agent_hostname, ag.ip as agent_ip FROM assets a LEFT JOIN agents ag ON a.agent_id = ag.id WHERE a.agent_id = ?').get(req.params.agentId);
  if (!asset) return res.status(404).json({ error: 'Asset not found' });
  res.json({
    ...asset,
    network_interfaces: tryParse(asset.network_interfaces),
    installed_software: tryParse(asset.installed_software),
    running_services: tryParse(asset.running_services),
    open_ports: tryParse(asset.open_ports),
    local_users: tryParse(asset.local_users),
  });
});

router.get('/assets/:agentId/vulnerabilities', authenticate, async (req, res) => {
  const d = db();
  const vulns = await d.prepare('SELECT * FROM vulnerabilities WHERE agent_id = ? ORDER BY cvss_score DESC, scanned_at DESC').all(req.params.agentId);
  res.json({ vulnerabilities: vulns, total: vulns.length });
});

function tryParse(val) {
  if (!val) return [];
  if (typeof val !== 'string') return val;
  try { return JSON.parse(val); } catch { return []; }
}

module.exports = router;
