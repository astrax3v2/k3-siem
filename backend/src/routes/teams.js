'use strict';
const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { db } = require('../models/db');
const { authenticate, authorize, ROLE_ADMIN } = require('../middleware/auth');
const { normalizeTenantId, scopeTenantClause } = require('../services/tenantScope');
const router = express.Router();

router.get('/', authenticate, async (req, res) => {
  const d = db();
  const scope = scopeTenantClause(req.user, 'tm.tenant_id');
  const wc = scope.clause ? `WHERE ${scope.clause}` : '';
  const teams = await d.prepare(`SELECT tm.*, tn.name as tenant_name FROM teams tm LEFT JOIN tenants tn ON tn.id = tm.tenant_id ${wc} ORDER BY tm.name`).all(...scope.params);
  res.json({ teams });
});

router.post('/', authenticate, authorize(ROLE_ADMIN), async (req, res) => {
  const { name, description, tenant_id } = req.body || {};
  if (!name) return res.status(400).json({ error: 'name is required' });
  const d = db();
  const id = uuidv4();
  const nextTenantId = normalizeTenantId(tenant_id || req.user?.tenant_id);
  try {
    await d.prepare('INSERT INTO teams(id, name, description, tenant_id) VALUES(?,?,?,?)').run(id, name, description || null, nextTenantId);
  } catch (e) {
    return res.status(400).json({ error: 'A team with this name already exists' });
  }
  res.status(201).json(await d.prepare('SELECT tm.*, tn.name as tenant_name FROM teams tm LEFT JOIN tenants tn ON tn.id = tm.tenant_id WHERE tm.id = ?').get(id));
});

router.patch('/:id', authenticate, authorize(ROLE_ADMIN), async (req, res) => {
  const { name, description, tenant_id } = req.body || {};
  const d = db();
  const team = await d.prepare('SELECT * FROM teams WHERE id = ?').get(req.params.id);
  if (!team) return res.status(404).json({ error: 'Team not found' });

  const nextTenantId = tenant_id !== undefined ? normalizeTenantId(tenant_id) : normalizeTenantId(team.tenant_id);
  const assigned = await Promise.all([
    d.prepare('SELECT 1 as ok FROM users WHERE team_id = ? AND tenant_id != ? LIMIT 1').get(req.params.id, nextTenantId),
    d.prepare('SELECT 1 as ok FROM agents WHERE team_id = ? AND tenant_id != ? LIMIT 1').get(req.params.id, nextTenantId),
  ]);
  if (assigned.some(Boolean)) return res.status(400).json({ error: 'Move users and agents to the target tenant before changing the team tenant' });

  try {
    await d.prepare('UPDATE teams SET name = ?, description = ?, tenant_id = ? WHERE id = ?')
      .run(name !== undefined ? name : team.name, description !== undefined ? description : team.description, nextTenantId, req.params.id);
  } catch (e) {
    return res.status(400).json({ error: 'A team with this name already exists' });
  }
  res.json(await d.prepare('SELECT tm.*, tn.name as tenant_name FROM teams tm LEFT JOIN tenants tn ON tn.id = tm.tenant_id WHERE tm.id = ?').get(req.params.id));
});

router.delete('/:id', authenticate, authorize(ROLE_ADMIN), async (req, res) => {
  const d = db();
  const inUse = await Promise.all([
    d.prepare('SELECT 1 as ok FROM users WHERE team_id = ? LIMIT 1').get(req.params.id),
    d.prepare('SELECT 1 as ok FROM agents WHERE team_id = ? LIMIT 1').get(req.params.id),
    d.prepare('SELECT 1 as ok FROM incidents WHERE team_id = ? LIMIT 1').get(req.params.id),
  ]);
  if (inUse.some(Boolean)) return res.status(400).json({ error: 'Team is still assigned to users, agents, or incidents' });
  await d.prepare('DELETE FROM teams WHERE id = ?').run(req.params.id);
  res.json({ status: 'deleted' });
});

module.exports = router;
