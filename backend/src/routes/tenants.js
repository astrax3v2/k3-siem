'use strict';
const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { db } = require('../models/db');
const { authenticate, authorize, ROLE_ADMIN } = require('../middleware/auth');
const { DEFAULT_TENANT_ID, normalizeTenantId } = require('../services/tenantScope');

const router = express.Router();

router.get('/', authenticate, authorize(ROLE_ADMIN), async (_req, res) => {
  const d = db();
  const tenants = await d.prepare(`
    SELECT tn.*,
           (SELECT COUNT(*) FROM users u WHERE u.tenant_id = tn.id) as user_count,
           (SELECT COUNT(*) FROM teams tm WHERE tm.tenant_id = tn.id) as team_count,
           (SELECT COUNT(*) FROM agents ag WHERE ag.tenant_id = tn.id) as agent_count
    FROM tenants tn
    ORDER BY tn.name
  `).all();
  res.json({ tenants });
});

router.post('/', authenticate, authorize(ROLE_ADMIN), async (req, res) => {
  const { name, description, is_active = true } = req.body || {};
  if (!name || !String(name).trim()) return res.status(400).json({ error: 'name is required' });
  const d = db();
  const id = uuidv4();
  try {
    await d.prepare('INSERT INTO tenants(id, name, description, is_active) VALUES(?,?,?,?)')
      .run(id, String(name).trim(), description || null, is_active ? 1 : 0);
  } catch (e) {
    return res.status(400).json({ error: 'A tenant with this name already exists' });
  }
  res.status(201).json(await d.prepare('SELECT * FROM tenants WHERE id = ?').get(id));
});

router.patch('/:id', authenticate, authorize(ROLE_ADMIN), async (req, res) => {
  const { name, description, is_active } = req.body || {};
  const d = db();
  const tenant = await d.prepare('SELECT * FROM tenants WHERE id = ?').get(req.params.id);
  if (!tenant) return res.status(404).json({ error: 'Tenant not found' });

  try {
    await d.prepare('UPDATE tenants SET name = ?, description = ?, is_active = ? WHERE id = ?')
      .run(
        name !== undefined ? String(name).trim() : tenant.name,
        description !== undefined ? description : tenant.description,
        is_active !== undefined ? (is_active ? 1 : 0) : tenant.is_active,
        req.params.id,
      );
  } catch (e) {
    return res.status(400).json({ error: 'A tenant with this name already exists' });
  }
  res.json(await d.prepare('SELECT * FROM tenants WHERE id = ?').get(req.params.id));
});

router.delete('/:id', authenticate, authorize(ROLE_ADMIN), async (req, res) => {
  const tenantId = normalizeTenantId(req.params.id);
  if (tenantId === DEFAULT_TENANT_ID) {
    return res.status(400).json({ error: 'The default tenant cannot be deleted' });
  }

  const d = db();
  const inUse = await Promise.all([
    d.prepare('SELECT 1 as ok FROM users WHERE tenant_id = ? LIMIT 1').get(tenantId),
    d.prepare('SELECT 1 as ok FROM teams WHERE tenant_id = ? LIMIT 1').get(tenantId),
    d.prepare('SELECT 1 as ok FROM agents WHERE tenant_id = ? LIMIT 1').get(tenantId),
    d.prepare('SELECT 1 as ok FROM dashboards WHERE tenant_id = ? LIMIT 1').get(tenantId),
  ]);
  if (inUse.some(Boolean)) return res.status(400).json({ error: 'Tenant is still assigned to users, teams, agents, or dashboards' });

  await d.prepare('DELETE FROM tenants WHERE id = ?').run(tenantId);
  res.json({ status: 'deleted' });
});

module.exports = router;
