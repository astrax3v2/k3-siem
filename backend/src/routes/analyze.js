'use strict';
// New capability: offline-style batch log analysis with OSINT-enriched IOC hits, powered by
// the Go analyzer service (go-service/internal/analyzer) — proxies to POST /v1/analyze. This
// is additive: it does not touch the existing live-ingestion pipeline in events.js (/import,
// /ingest), which keeps writing to ClickHouse and generating alerts exactly as before.
const express = require('express');
const { authenticate, authorize, ROLE_ADMIN, ROLE_T1, ROLE_T2 } = require('../middleware/auth');
const router = express.Router();

const GO_SERVICE_URL = process.env.GO_SERVICE_URL || 'http://localhost:8090';

router.post('/offline', authenticate, authorize(ROLE_T1, ROLE_T2, ROLE_ADMIN), async (req, res) => {
  const { content, file_path } = req.body || {};
  if (!content && !file_path) return res.status(400).json({ error: 'content or file_path is required' });

  const wantsHtml = req.query.format === 'html';
  try {
    const upstream = await fetch(`${GO_SERVICE_URL}/v1/analyze${wantsHtml ? '?format=html' : ''}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content, file_path }),
      signal: AbortSignal.timeout(120000),
    });
    const body = await upstream.text();
    res.status(upstream.status).type(wantsHtml ? 'text/html' : 'application/json').send(body);
  } catch (err) {
    res.status(503).json({ error: 'Offline analyzer service unavailable', detail: err.message });
  }
});

module.exports = router;
