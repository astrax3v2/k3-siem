'use strict';
const express = require('express');
const { db } = require('../models/db');
const { authenticate, authorize, ROLE_ADMIN } = require('../middleware/auth');
const { normalizeTenantId } = require('../services/tenantScope');
const router = express.Router();

const USER_TEAM_SELECT = `
  SELECT u.id, u.username, u.email, u.role, u.full_name, u.department, u.team_id, t.name as team_name,
         u.tenant_id, tn.name as tenant_name, u.created_at, u.last_login
  FROM users u LEFT JOIN teams t ON t.id = u.team_id
  LEFT JOIN tenants tn ON tn.id = u.tenant_id
`;

router.get('/', authenticate, authorize(ROLE_ADMIN), async (req, res) => {
  const users = await db().prepare(`${USER_TEAM_SELECT} ORDER BY u.username`).all();
  res.json({ users });
});

router.patch('/:id', authenticate, authorize(ROLE_ADMIN), async (req, res) => {
  const { role, team_id, tenant_id } = req.body || {};
  const d = db();
  const user = await d.prepare('SELECT id, tenant_id FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const nextTenantId = tenant_id !== undefined ? normalizeTenantId(tenant_id) : normalizeTenantId(user.tenant_id);
  if (team_id) {
    const team = await d.prepare('SELECT id FROM teams WHERE id = ? AND tenant_id = ?').get(team_id, nextTenantId);
    if (!team) return res.status(400).json({ error: 'Selected team does not belong to the selected tenant' });
  }

  const fields = [], params = [];
  if (role !== undefined) { fields.push('role = ?'); params.push(role); }
  if (tenant_id !== undefined) { fields.push('tenant_id = ?'); params.push(nextTenantId); }
  if (team_id !== undefined) { fields.push('team_id = ?'); params.push(team_id); }
  if (!fields.length) return res.status(400).json({ error: 'Nothing to update' });
  params.push(req.params.id);
  await d.prepare(`UPDATE users SET ${fields.join(', ')} WHERE id = ?`).run(...params);

  res.json(await d.prepare(`${USER_TEAM_SELECT} WHERE u.id = ?`).get(req.params.id));
});

module.exports = router;
