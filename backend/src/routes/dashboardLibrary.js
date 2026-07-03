'use strict';
const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { db } = require('../models/db');
const { authenticate } = require('../middleware/auth');
const { DASHBOARD_TEMPLATES } = require('../data/dashboardTemplates');
const router = express.Router();

function parseWidgets(row) {
  if (!row) return row;
  let widgets = [];
  try { widgets = JSON.parse(row.widgets || '[]'); } catch { widgets = []; }
  return { ...row, widgets, is_shared: !!row.is_shared };
}

router.get('/templates', authenticate, (req, res) => {
  res.json({ templates: DASHBOARD_TEMPLATES });
});

router.get('/', authenticate, async (req, res) => {
  const d = db();
  const rows = await d.prepare('SELECT * FROM dashboards WHERE owner = ? OR is_shared = 1 ORDER BY updated_at DESC')
    .all(req.user.username);
  res.json({ dashboards: rows.map(parseWidgets), total: rows.length });
});

router.post('/', authenticate, async (req, res) => {
  const { name, description, category, widgets, is_shared } = req.body;
  if (!name) return res.status(400).json({ error: 'name is required' });
  if (!Array.isArray(widgets)) return res.status(400).json({ error: 'widgets must be an array' });

  const id = uuidv4();
  const now = new Date().toISOString();
  const d = db();
  await d.prepare('INSERT INTO dashboards(id, name, description, category, owner, is_shared, widgets, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?)')
    .run(id, name, description || null, category || 'Custom', req.user.username, is_shared ? 1 : 0, JSON.stringify(widgets), now, now);

  const row = await d.prepare('SELECT * FROM dashboards WHERE id = ?').get(id);
  res.status(201).json(parseWidgets(row));
});

router.get('/:id', authenticate, async (req, res) => {
  const d = db();
  const row = await d.prepare('SELECT * FROM dashboards WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Dashboard not found' });
  if (row.owner !== req.user.username && !row.is_shared) return res.status(403).json({ error: 'Forbidden' });
  res.json(parseWidgets(row));
});

router.patch('/:id', authenticate, async (req, res) => {
  const d = db();
  const row = await d.prepare('SELECT * FROM dashboards WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Dashboard not found' });
  if (row.owner !== req.user.username) return res.status(403).json({ error: 'Forbidden' });

  const { name, description, category, widgets, is_shared } = req.body;
  await d.prepare('UPDATE dashboards SET name = ?, description = ?, category = ?, widgets = ?, is_shared = ?, updated_at = ? WHERE id = ?')
    .run(
      name !== undefined ? name : row.name,
      description !== undefined ? description : row.description,
      category !== undefined ? category : row.category,
      widgets !== undefined ? JSON.stringify(widgets) : row.widgets,
      is_shared !== undefined ? (is_shared ? 1 : 0) : row.is_shared,
      new Date().toISOString(),
      req.params.id,
    );

  const updated = await d.prepare('SELECT * FROM dashboards WHERE id = ?').get(req.params.id);
  res.json(parseWidgets(updated));
});

router.delete('/:id', authenticate, async (req, res) => {
  const d = db();
  const row = await d.prepare('SELECT * FROM dashboards WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Dashboard not found' });
  if (row.owner !== req.user.username) return res.status(403).json({ error: 'Forbidden' });

  await d.prepare('DELETE FROM dashboards WHERE id = ?').run(req.params.id);
  res.json({ status: 'deleted' });
});

module.exports = router;
