'use strict';
// Route-level test for the OSINT lookup panel's backend: confirms paid sources report
// `configured:false` (no network call, no crash) when their API key is absent, and that free
// sources still attempt a lookup. Mirrors the isConfigured() gating pattern in connectors.test.js.
const express = require('express');
const request = require('supertest');
const jwt = require('jsonwebtoken');

describe('osint routes', () => {
  let app;
  const ORIGINAL_ENV = process.env;

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...ORIGINAL_ENV };
    delete process.env.VIRUSTOTAL_API_KEY;
    delete process.env.ABUSEIPDB_API_KEY;
    delete process.env.SHODAN_API_KEY;

    jest.spyOn(global, 'fetch').mockResolvedValue({ ok: false });
    jest.spyOn(require('dns').promises, 'reverse').mockRejectedValue(new Error('no ptr record'));

    const osintRouter = require('../../src/routes/osint');
    app = express();
    app.use(express.json());
    app.use('/api/osint', osintRouter);
  });

  afterEach(() => { jest.restoreAllMocks(); });
  afterAll(() => { process.env = ORIGINAL_ENV; });

  function token() {
    return jwt.sign({ id: 'u1', username: 'tester', role: 'admin' }, process.env.JWT_SECRET);
  }

  test('rejects unauthenticated requests', async () => {
    const res = await request(app).get('/api/osint/ip').query({ ip: '8.8.8.8' });
    expect(res.status).toBe(401);
  });

  test('requires an ip parameter', async () => {
    const res = await request(app).get('/api/osint/ip').set('Authorization', `Bearer ${token()}`);
    expect(res.status).toBe(400);
  });

  test('ip lookup reports paid sources as not configured without keys', async () => {
    const res = await request(app).get('/api/osint/ip').query({ ip: '8.8.8.8' }).set('Authorization', `Bearer ${token()}`);
    expect(res.status).toBe(200);
    expect(res.body.sources.virustotal.configured).toBe(false);
    expect(res.body.sources.virustotal.data).toBeNull();
    expect(res.body.sources.abuseipdb.configured).toBe(false);
    expect(res.body.sources.shodan.configured).toBe(false);
    expect(res.body.sources.rdap.configured).toBe(true);
    expect(res.body.sources.reverse_dns.configured).toBe(true);
  });

  test('hash lookup reports virustotal as not configured without a key', async () => {
    const res = await request(app).get('/api/osint/hash').query({ hash: 'a'.repeat(64) }).set('Authorization', `Bearer ${token()}`);
    expect(res.status).toBe(200);
    expect(res.body.sources.virustotal.configured).toBe(false);
  });

  test('email lookup requires a valid-looking address', async () => {
    const res = await request(app).get('/api/osint/email').query({ email: 'not-an-email' }).set('Authorization', `Bearer ${token()}`);
    expect(res.status).toBe(400);
  });
});
