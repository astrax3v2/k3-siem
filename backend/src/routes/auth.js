'use strict';
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { db } = require('../models/db');
const { authenticate, normalizeRole, SECRET } = require('../middleware/auth');
const { logAction } = require('../services/audit');
const router = express.Router();

router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  const user = await db().prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    await logAction(username, 'login_failed', 'user', null, null, req.ip);
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  await logAction(username, 'login_success', 'user', user.id, null, req.ip);
  const role = normalizeRole(user.role);
  const token = jwt.sign(
    { id: user.id, username: user.username, role, roles: [role], full_name: user.full_name },
    SECRET, { expiresIn: '12h' }
  );
  res.json({ token, user: { id: user.id, username: user.username, role, roles: [role], full_name: user.full_name, email: user.email, department: user.department } });
});

router.get('/me', authenticate, (req, res) => res.json({ user: req.user }));

module.exports = router;
