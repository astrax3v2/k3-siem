'use strict';
// Proxies to the Go OSINT/IOC-cache service (go-service/) — Go now owns OSINT enrichment
// (VirusTotal/AbuseIPDB/Shodan/RDAP/reverse-DNS/crt.sh/geoip) behind a disk-backed cache that
// survives restarts, replacing the in-memory 24h Map this route used to hold directly. Query
// validation and the response shape stay the same as before so the frontend needs no changes.
const express = require('express');
const { authenticate } = require('../middleware/auth');
const router = express.Router();

const GO_SERVICE_URL = process.env.GO_SERVICE_URL || 'http://localhost:8090';

async function proxyGet(res, path) {
  try {
    const upstream = await fetch(`${GO_SERVICE_URL}${path}`, { signal: AbortSignal.timeout(15000) });
    const body = await upstream.text();
    res.status(upstream.status).type('application/json').send(body);
  } catch (err) {
    res.status(503).json({ error: 'OSINT service unavailable', detail: err.message });
  }
}

router.get('/ip', authenticate, async (req, res) => {
  const ip = (req.query.ip || '').trim();
  if (!ip) return res.status(400).json({ error: 'ip is required' });
  await proxyGet(res, `/v1/osint/ip?ip=${encodeURIComponent(ip)}`);
});

router.get('/domain', authenticate, async (req, res) => {
  const domain = (req.query.domain || '').trim().toLowerCase();
  if (!domain) return res.status(400).json({ error: 'domain is required' });
  await proxyGet(res, `/v1/osint/domain?domain=${encodeURIComponent(domain)}`);
});

router.get('/hash', authenticate, async (req, res) => {
  const hash = (req.query.hash || '').trim().toLowerCase();
  if (!hash) return res.status(400).json({ error: 'hash is required' });
  await proxyGet(res, `/v1/osint/hash?hash=${encodeURIComponent(hash)}`);
});

router.get('/email', authenticate, async (req, res) => {
  const email = (req.query.email || '').trim().toLowerCase();
  if (!email || !email.includes('@')) return res.status(400).json({ error: 'a valid email is required' });
  await proxyGet(res, `/v1/osint/email?email=${encodeURIComponent(email)}`);
});

module.exports = router;
