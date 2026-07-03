'use strict';
const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { db } = require('../models/db');
const { authenticate, authorize, ROLE_ADMIN } = require('../middleware/auth');
const router = express.Router();

router.get('/', authenticate, async (req, res) => {
  const teams = await db().prepare('SELECT * FROM teams ORDER BY name').all();
  res.json({ teams });
});

router.post('/', authenticate, authorize(ROLE_ADMIN), async (req, res) => {
  const { name, description } = req.body || {};
  if (!name) return res.status(400).json({ error: 'name is required' });
  const d = db();
  const id = uuidv4();
  try {
    await d.prepare('INSERT INTO teams(id, name, description) VALUES(?,?,?)').run(id, name, description || null);
  } catch (e) {
    return res.status(400).json({ error: 'A team with this name already exists' });
  }
  res.status(201).json(await d.prepare('SELECT * FROM teams WHERE id = ?').get(id));
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
