'use strict';
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { db } = require('../models/db');
const { authenticate, normalizeRole, SECRET } = require('../middleware/auth');
const { logAction } = require('../services/audit');
const { normalizeTenantId } = require('../services/tenantScope');
const router = express.Router();

router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  const user = await db().prepare(`
    SELECT u.*, tm.name as team_name, tn.name as tenant_name
    FROM users u
    LEFT JOIN teams tm ON tm.id = u.team_id
    LEFT JOIN tenants tn ON tn.id = u.tenant_id
    WHERE u.username = ?
  `).get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    await logAction(username, 'login_failed', 'user', null, null, req.ip);
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  await logAction(username, 'login_success', 'user', user.id, null, req.ip);
  const role = normalizeRole(user.role);
  const tenantId = normalizeTenantId(user.tenant_id);
  const tenantName = user.tenant_name || 'K3 Default Tenant';
  const token = jwt.sign(
    { id: user.id, username: user.username, role, roles: [role], full_name: user.full_name, team_id: user.team_id || null, team_name: user.team_name || null, tenant_id: tenantId, tenant_name: tenantName },
    SECRET, { expiresIn: '12h' }
  );
  res.json({ token, user: { id: user.id, username: user.username, role, roles: [role], full_name: user.full_name, email: user.email, department: user.department, team_id: user.team_id || null, team_name: user.team_name || null, tenant_id: tenantId, tenant_name: tenantName } });
});

router.get('/me', authenticate, (req, res) => res.json({ user: req.user }));

module.exports = router;
