'use strict';
const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { db, sqlNowMinus } = require('../models/db');
const { authenticate, authorize } = require('../middleware/auth');
const router = express.Router();

function apiKeyAuth(req, res, next) {
  const key = req.headers['x-api-key'];
  if (key !== (process.env.INGEST_API_KEY || 'k3-ingest-key'))
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
  const agents = await d.prepare('SELECT * FROM agents ORDER BY registered_at DESC').all();

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
  const agent = await d.prepare('SELECT * FROM agents WHERE id = ?').get(req.params.id);
  if (!agent) return res.status(404).json({ error: 'Agent not found' });

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
  const { tags, config } = req.body;
  const d = db();
  const agent = await d.prepare('SELECT id FROM agents WHERE id = ?').get(req.params.id);
  if (!agent) return res.status(404).json({ error: 'Agent not found' });

  if (tags !== undefined) {
    await d.prepare('UPDATE agents SET tags = ? WHERE id = ?').run(JSON.stringify(tags), req.params.id);
  }
  if (config !== undefined) {
    await d.prepare('UPDATE agents SET config = ? WHERE id = ?').run(JSON.stringify(config), req.params.id);
  }

  res.json({ status: 'updated' });
});

router.delete('/:id', authenticate, authorize('admin'), async (req, res) => {
  const d = db();
  await d.prepare('DELETE FROM agents WHERE id = ?').run(req.params.id);
  res.json({ status: 'deleted' });
});

module.exports = router;
