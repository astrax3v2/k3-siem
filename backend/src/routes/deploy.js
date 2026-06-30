'use strict';
const express = require('express');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const { db } = require('../models/db');
const { authenticate, authorize } = require('../middleware/auth');
const { deployViaSSH, generateInstallScript, getAgentFiles } = require('../services/deployer');
const router = express.Router();

router.post('/', authenticate, authorize('admin', 't2_analyst'), async (req, res) => {
  const { target_ip, target_os, username, password, ssh_key } = req.body;
  if (!target_ip || !target_os) return res.status(400).json({ error: 'target_ip and target_os required' });
  if (!username) return res.status(400).json({ error: 'username required' });

  const id = uuidv4();
  const d = db();
  await d.prepare('INSERT INTO deployments(id, target_ip, target_os, target_user, status, logs, created_by) VALUES(?,?,?,?,?,?,?)')
    .run(id, target_ip, target_os, username, 'pending', '', req.user.username);

  deployViaSSH(id, { target_ip, target_os, username, password, ssh_key }).catch((err) => {
    console.error('[Deploy] Error:', err.message);
  });

  res.status(201).json({ deployment_id: id, status: 'pending' });
});

router.get('/', authenticate, async (req, res) => {
  const d = db();
  const deployments = await d.prepare('SELECT * FROM deployments ORDER BY created_at DESC').all();
  res.json({ deployments, total: deployments.length });
});

router.get('/script/:os', authenticate, async (req, res) => {
  const { os } = req.params;
  const siemUrl = req.query.siem_url || process.env.SIEM_PUBLIC_URL || `${req.protocol}://${req.get('host')}`;
  const apiKey = process.env.INGEST_API_KEY || 'k3-ingest-key';
  const script = generateInstallScript(os, siemUrl, apiKey);
  res.type('text/plain').send(script);
});

router.get('/download/:filename', (req, res) => {
  const { filename } = req.params;
  const allowed = ['agent.py', 'requirements.txt', 'config.yaml'];
  if (!allowed.includes(filename)) return res.status(404).json({ error: 'File not found' });

  const filePath = path.resolve(__dirname, '../../../k3-agent', filename);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'File not found' });
  res.sendFile(filePath);
});

router.get('/:id', authenticate, async (req, res) => {
  const d = db();
  const dep = await d.prepare('SELECT * FROM deployments WHERE id = ?').get(req.params.id);
  if (!dep) return res.status(404).json({ error: 'Deployment not found' });
  res.json(dep);
});

module.exports = router;
