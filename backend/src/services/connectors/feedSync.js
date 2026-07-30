'use strict';
const cron = require('node-cron');
const net = require('node:net');
const { v4: uuidv4 } = require('uuid');
const { db, sqlNow, getDialect } = require('../../models/db');
const abuseipdb = require('./abuseipdb');
const otx = require('./otx');

let task = null;
// In-memory, per-feed cooldown after a 429 — avoids hammering a provider that just rate-limited
// us again on the very next 5-minute tick. Resets on process restart, which is fine here.
const rateLimitCooldownUntil = new Map();
const RATE_LIMIT_COOLDOWN_MS = 20 * 60 * 1000;

const OTX_TYPE_MAP = {
  IPv4: 'IP',
  IPv6: 'IP',
  domain: 'Domain',
  hostname: 'Domain',
  URL: 'URL',
  'FileHash-MD5': 'Hash',
  'FileHash-SHA1': 'Hash',
  'FileHash-SHA256': 'Hash',
  email: 'Email',
};

const FEEDS = [
  {
    name: 'AbuseIPDB',
    source: 'AbuseIPDB',
    url: 'https://api.abuseipdb.com/api/v2/blacklist?limit=100&confidenceMinimum=75',
    type: 'REST',
    requiresConfig: true,
    isConfigured: () => abuseipdb.isConfigured(),
    sync: syncAbuseIPDB,
  },
  {
    name: 'OTX AlienVault',
    source: 'OTX AlienVault',
    // limit=1 on purpose — on accounts subscribed to very large pulses, even a single pulse's
    // embedded indicator list can be 10+ MB, so anything more risks the request never returning.
    url: 'https://otx.alienvault.com/api/v1/pulses/subscribed?limit=1',
    type: 'REST',
    requiresConfig: true,
    isConfigured: () => otx.isConfigured(),
    sync: syncOTX,
  },
  {
    name: 'OpenPhish Community',
    source: 'OpenPhish',
    url: 'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt',
    type: 'TXT',
    requiresConfig: false,
    isConfigured: () => true,
    sync: syncOpenPhish,
  },
  {
    name: 'PhishTank Verified Online',
    source: 'PhishTank',
    url: 'http://data.phishtank.com/data/online-valid.json',
    type: 'JSON',
    requiresConfig: false,
    isConfigured: () => true,
    sync: syncPhishTank,
  },
  {
    name: 'Spamhaus DROP IPv4',
    source: 'Spamhaus DROP IPv4',
    url: 'https://www.spamhaus.org/drop/drop_v4.json',
    type: 'NDJSON',
    requiresConfig: false,
    isConfigured: () => true,
    sync: syncSpamhausDrop,
  },
  {
    name: 'Spamhaus DROP IPv6',
    source: 'Spamhaus DROP IPv6',
    url: 'https://www.spamhaus.org/drop/drop_v6.json',
    type: 'NDJSON',
    requiresConfig: false,
    isConfigured: () => true,
    sync: syncSpamhausDrop,
  },
  {
    name: 'Feodo Tracker Recommended',
    source: 'Feodo Tracker',
    url: 'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt',
    type: 'TXT',
    requiresConfig: false,
    isConfigured: () => true,
    sync: syncFeodoTracker,
  },
  {
    name: 'SSLBL JA3',
    source: 'SSLBL JA3',
    url: 'https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv',
    type: 'CSV',
    requiresConfig: false,
    isConfigured: () => true,
    sync: syncSslblJa3,
  },
  {
    name: 'URLhaus Recent',
    source: 'URLhaus',
    url: 'https://urlhaus.abuse.ch/downloads/csv_recent/',
    type: 'CSV',
    requiresConfig: false,
    isConfigured: () => true,
    sync: syncUrlhaus,
  },
  {
    name: 'ThreatFox Recent IOCs',
    source: 'ThreatFox',
    url: 'https://threatfox.abuse.ch/export/csv/recent/',
    type: 'CSV',
    requiresConfig: false,
    isConfigured: () => true,
    sync: syncThreatFox,
  },
  {
    name: 'MalwareBazaar Recent Samples',
    source: 'MalwareBazaar',
    url: 'https://bazaar.abuse.ch/export/txt/sha256/recent/',
    type: 'TXT',
    requiresConfig: false,
    isConfigured: () => true,
    sync: syncMalwareBazaar,
  },
  {
    name: 'Blocklist.de Attackers',
    source: 'Blocklist.de',
    url: 'https://lists.blocklist.de/lists/all.txt',
    type: 'TXT',
    requiresConfig: false,
    isConfigured: () => true,
    sync: syncBlocklistDe,
  },
  {
    name: 'CINS Army List',
    source: 'CINS Army',
    url: 'https://cinsscore.com/list/ci-badguys.txt',
    type: 'TXT',
    requiresConfig: false,
    isConfigured: () => true,
    sync: syncCinsArmy,
  },
];

function normalizeIndicator(type, value) {
  if (value == null) return null;
  const raw = String(value).trim();
  if (!raw) return null;
  if (type === 'Hash' || type === 'Domain' || type === 'Email') return raw.toLowerCase();
  return raw;
}

function iocKey(type, value) {
  return `${type}\u0000${value}`;
}

function resolveCatalogStatus(feed) {
  if (feed.requiresConfig && !feed.isConfigured()) return 'requires_config';
  return 'ready';
}

function splitLines(text) {
  return String(text || '')
    .replace(/\r/g, '\n')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);
}

function parseCsvLine(line) {
  const out = [];
  let current = '';
  let inQuotes = false;

  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') {
        current += '"';
        i += 1;
      } else {
        inQuotes = !inQuotes;
      }
      continue;
    }
    if (ch === ',' && !inQuotes) {
      out.push(current.trim());
      current = '';
      continue;
    }
    current += ch;
  }

  out.push(current.trim());
  return out.map((part) => part.replace(/^"(.*)"$/, '$1').trim());
}

function parseSpamhausLines(text) {
  const trimmed = String(text || '').trim();
  if (!trimmed) return [];

  if (trimmed.startsWith('[')) {
    try {
      const rows = JSON.parse(trimmed);
      return Array.isArray(rows) ? rows.filter((row) => row && row.cidr) : [];
    } catch {
      return [];
    }
  }

  const rows = [];
  for (const line of splitLines(trimmed)) {
    if (!line.startsWith('{')) continue;
    try {
      const row = JSON.parse(line);
      if (row && row.cidr) rows.push(row);
    } catch {}
  }
  return rows;
}

async function fetchText(url, options = {}) {
  const { headers, timeoutMs = 30000 } = options;
  const res = await fetch(url, { headers, signal: AbortSignal.timeout(timeoutMs) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.text();
}

async function fetchJson(url, options = {}) {
  const { headers, timeoutMs = 30000 } = options;
  const res = await fetch(url, { headers, signal: AbortSignal.timeout(timeoutMs) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

async function createContext(d) {
  const existingRows = await d.prepare('SELECT type, value FROM iocs').all();
  const sourceRows = await d.prepare('SELECT source, COUNT(*) as cnt FROM iocs GROUP BY source').all();
  const existingKeys = new Set();
  const sourceCounts = Object.create(null);

  for (const row of existingRows) {
    const normalized = normalizeIndicator(row.type, row.value);
    if (normalized) existingKeys.add(iocKey(row.type, normalized));
  }
  for (const row of sourceRows) {
    sourceCounts[row.source || ''] = row.cnt || 0;
  }

  return {
    d,
    existingKeys,
    sourceCounts,
    insertIoc: d.prepare('INSERT INTO iocs(id,type,value,confidence,severity,source,description,tags,hits) VALUES(?,?,?,?,?,?,?,?,0)'),
  };
}

async function upsertIOC(ctx, type, value, confidence, severity, source, description) {
  const normalizedValue = normalizeIndicator(type, value);
  if (!normalizedValue) return false;
  const key = iocKey(type, normalizedValue);
  if (ctx.existingKeys.has(key)) return false;

  await ctx.insertIoc.run(
    uuidv4(),
    type,
    normalizedValue,
    Math.max(0, Math.min(100, parseInt(confidence, 10) || 50)),
    severity || 'Medium',
    source,
    description || null,
    JSON.stringify([])
  );
  ctx.existingKeys.add(key);
  ctx.sourceCounts[source] = (ctx.sourceCounts[source] || 0) + 1;
  return true;
}

async function ensureFeedCatalog(d = db()) {
  for (const feed of FEEDS) {
    const existing = await d.prepare('SELECT id, status, last_sync, ioc_count FROM intel_feeds WHERE name = ?').get(feed.name);
    if (existing) {
      const nextStatus = existing.status === 'requires_config' && feed.isConfigured()
        ? 'ready'
        : (!feed.isConfigured() && feed.requiresConfig ? 'requires_config' : existing.status);
      await d.prepare('UPDATE intel_feeds SET url = ?, type = ?, status = ? WHERE name = ?')
        .run(feed.url, feed.type, nextStatus || resolveCatalogStatus(feed), feed.name);
      continue;
    }
    const insertSql = getDialect() === 'postgres'
      ? 'INSERT INTO intel_feeds(id,name,url,type,status,last_sync,ioc_count) VALUES(?,?,?,?,?,?,?) ON CONFLICT (name) DO NOTHING'
      : 'INSERT OR IGNORE INTO intel_feeds(id,name,url,type,status,last_sync,ioc_count) VALUES(?,?,?,?,?,?,?)';
    await d.prepare(insertSql)
      .run(uuidv4(), feed.name, feed.url, feed.type, resolveCatalogStatus(feed), null, 0);
  }
}

async function updateFeedRow(d, feed, patch) {
  const fields = [];
  const params = [];

  if (patch.status !== undefined) {
    fields.push('status = ?');
    params.push(patch.status);
  }
  if (patch.iocCount !== undefined) {
    fields.push('ioc_count = ?');
    params.push(patch.iocCount);
  }
  if (patch.lastSync === 'now') {
    fields.push(`last_sync = ${sqlNow()}`);
  }
  if (!fields.length) return;

  params.push(feed.name);
  await d.prepare(`UPDATE intel_feeds SET ${fields.join(', ')} WHERE name = ?`).run(...params);
}

function buildFeedResult(feed, patch) {
  return {
    name: feed.name,
    status: patch.status,
    added: patch.added || 0,
    total: patch.iocCount || 0,
    error: patch.error || null,
  };
}

async function markFeedSuccess(ctx, feed, added) {
  const total = ctx.sourceCounts[feed.source] || 0;
  await updateFeedRow(ctx.d, feed, { status: 'active', iocCount: total, lastSync: 'now' });
  return buildFeedResult(feed, { status: 'active', added, iocCount: total });
}

async function markFeedError(ctx, feed, error) {
  const status = feed.requiresConfig && !feed.isConfigured() ? 'requires_config' : 'error';
  await updateFeedRow(ctx.d, feed, { status });
  return buildFeedResult(feed, { status, iocCount: ctx.sourceCounts[feed.source] || 0, error: error.message });
}

async function syncAbuseIPDB(ctx, feed) {
  const data = await fetchJson(feed.url, {
    headers: { Key: process.env.ABUSEIPDB_API_KEY, Accept: 'application/json' },
  });
  let added = 0;
  for (const entry of data?.data || []) {
    const isNew = await upsertIOC(
      ctx,
      'IP',
      entry.ipAddress,
      entry.abuseConfidenceScore,
      entry.abuseConfidenceScore >= 90 ? 'Critical' : 'High',
      feed.source,
      `Abuse confidence ${entry.abuseConfidenceScore}%`
    );
    if (isNew) added += 1;
  }
  return markFeedSuccess(ctx, feed, added);
}

async function syncOTX(ctx, feed) {
  // Large accounts (many thousands of subscribed pulses) can still take a while to serve even
  // a single pulse, since each one embeds its full indicator list — give this one more headroom
  // than the default fetch timeout (observed up to ~36s for a 10MB single-pulse response).
  const data = await fetchJson(feed.url, {
    headers: { 'X-OTX-API-KEY': process.env.OTX_API_KEY },
    timeoutMs: 120000,
  });
  let added = 0;
  for (const pulse of data?.results || []) {
    for (const indicator of pulse.indicators || []) {
      const type = OTX_TYPE_MAP[indicator.type];
      if (!type) continue;
      const isNew = await upsertIOC(ctx, type, indicator.indicator, 70, 'High', feed.source, pulse.name);
      if (isNew) added += 1;
    }
  }
  return markFeedSuccess(ctx, feed, added);
}

async function syncOpenPhish(ctx, feed) {
  const text = await fetchText(feed.url);
  let added = 0;
  for (const value of text.split(/\s+/).map((item) => item.trim()).filter((item) => /^https?:\/\//i.test(item))) {
    const isNew = await upsertIOC(ctx, 'URL', value, 88, 'High', feed.source, 'OpenPhish community phishing URL');
    if (isNew) added += 1;
  }
  return markFeedSuccess(ctx, feed, added);
}

async function syncPhishTank(ctx, feed) {
  const appKey = process.env.PHISHTANK_APP_KEY;
  const urls = appKey
    ? [
      `https://data.phishtank.com/data/${encodeURIComponent(appKey)}/online-valid.json`,
      `http://data.phishtank.com/data/${encodeURIComponent(appKey)}/online-valid.json`,
    ]
    : [
      'https://data.phishtank.com/data/online-valid.json',
      feed.url,
    ];
  let data = null;
  let lastError = null;
  for (const url of urls) {
    try {
      data = await fetchJson(url, {
        timeoutMs: 60000,
        headers: { 'User-Agent': 'k3-siem-threat-sync/2.0' },
      });
      break;
    } catch (error) {
      lastError = error;
    }
  }
  if (!data) throw lastError || new Error('Unable to fetch PhishTank feed');
  let added = 0;
  for (const entry of Array.isArray(data) ? data : []) {
    if (!entry?.url) continue;
    const detail = entry.target
      ? `Verified phishing URL targeting ${entry.target}`
      : 'Verified online phishing URL';
    const isNew = await upsertIOC(ctx, 'URL', entry.url, 90, 'High', feed.source, detail);
    if (isNew) added += 1;
  }
  return markFeedSuccess(ctx, feed, added);
}

async function syncSpamhausDrop(ctx, feed) {
  const text = await fetchText(feed.url);
  const rows = parseSpamhausLines(text);
  let added = 0;
  for (const row of rows) {
    const description = row.sblid ? `Spamhaus DROP ${row.sblid}` : 'Spamhaus DROP netblock';
    const isNew = await upsertIOC(ctx, 'IP', row.cidr, 95, 'Critical', feed.source, description);
    if (isNew) added += 1;
  }
  return markFeedSuccess(ctx, feed, added);
}

async function syncFeodoTracker(ctx, feed) {
  const text = await fetchText(feed.url);
  let added = 0;
  for (const token of text.split(/\s+/).map((item) => item.trim()).filter(Boolean)) {
    if (net.isIP(token) !== 4) continue;
    const isNew = await upsertIOC(ctx, 'IP', token, 92, 'Critical', feed.source, 'Feodo Tracker active/recent botnet C2');
    if (isNew) added += 1;
  }
  return markFeedSuccess(ctx, feed, added);
}

async function syncSslblJa3(ctx, feed) {
  const text = await fetchText(feed.url);
  let added = 0;
  for (const line of splitLines(text)) {
    if (line.startsWith('#')) continue;
    const cols = parseCsvLine(line);
    const fingerprint = cols.find((part) => /^[a-f0-9]{32}$/i.test(part));
    if (!fingerprint) continue;
    const reason = cols[cols.length - 1] || 'Malicious JA3 fingerprint';
    const isNew = await upsertIOC(ctx, 'Hash', fingerprint, 86, 'High', feed.source, `SSLBL JA3 ${reason}`);
    if (isNew) added += 1;
  }
  return markFeedSuccess(ctx, feed, added);
}

async function syncUrlhaus(ctx, feed) {
  const text = await fetchText(feed.url);
  let added = 0;
  for (const line of splitLines(text)) {
    if (line.startsWith('#')) continue;
    const cols = parseCsvLine(line);
    const url = cols[2];
    if (!url) continue;
    const threat = cols[5] || 'malware_download';
    const isNew = await upsertIOC(ctx, 'URL', url, 85, 'High', feed.source, `URLhaus ${threat}`);
    if (isNew) added += 1;
  }
  return markFeedSuccess(ctx, feed, added);
}

async function syncThreatFox(ctx, feed) {
  const text = await fetchText(feed.url);
  let added = 0;
  for (const line of splitLines(text)) {
    if (line.startsWith('#')) continue;
    const cols = parseCsvLine(line);
    const iocType = (cols[3] || '').toLowerCase();
    const rawValue = cols[2];
    if (!rawValue) continue;
    let type = null;
    let value = rawValue;
    if (iocType.startsWith('ip')) { type = 'IP'; value = rawValue.split(':')[0]; }
    else if (iocType === 'domain') type = 'Domain';
    else if (iocType === 'url') type = 'URL';
    else if (iocType.includes('hash')) type = 'Hash';
    if (!type) continue;
    const confidence = parseInt(cols[8], 10) || 75;
    const threatType = cols[4] || 'threat';
    const malware = cols[7] || cols[6] || '';
    const description = `ThreatFox ${threatType}${malware ? ' — ' + malware : ''}`;
    const isNew = await upsertIOC(ctx, type, value, confidence, confidence >= 80 ? 'Critical' : 'High', feed.source, description);
    if (isNew) added += 1;
  }
  return markFeedSuccess(ctx, feed, added);
}

async function syncMalwareBazaar(ctx, feed) {
  const text = await fetchText(feed.url);
  let added = 0;
  for (const rawLine of splitLines(text)) {
    if (rawLine.startsWith('#')) continue;
    const hash = rawLine.replace(/^"(.*)"$/, '$1').trim();
    if (!/^[a-f0-9]{64}$/i.test(hash)) continue;
    const isNew = await upsertIOC(ctx, 'Hash', hash, 85, 'High', feed.source, 'MalwareBazaar recent malware sample (SHA256)');
    if (isNew) added += 1;
  }
  return markFeedSuccess(ctx, feed, added);
}

async function syncBlocklistDe(ctx, feed) {
  const text = await fetchText(feed.url);
  let added = 0;
  for (const line of splitLines(text)) {
    if (line.startsWith('#') || net.isIP(line) !== 4) continue;
    const isNew = await upsertIOC(ctx, 'IP', line, 75, 'Medium', feed.source, 'Blocklist.de reported attack source');
    if (isNew) added += 1;
  }
  return markFeedSuccess(ctx, feed, added);
}

async function syncCinsArmy(ctx, feed) {
  const text = await fetchText(feed.url);
  let added = 0;
  for (const line of splitLines(text)) {
    if (line.startsWith('#') || net.isIP(line) !== 4) continue;
    const isNew = await upsertIOC(ctx, 'IP', line, 80, 'High', feed.source, 'CINS Army flagged attacker IP');
    if (isNew) added += 1;
  }
  return markFeedSuccess(ctx, feed, added);
}

async function runOnce() {
  const d = db();
  await ensureFeedCatalog(d);
  const ctx = await createContext(d);
  const results = [];

  for (const feed of FEEDS) {
    if (feed.requiresConfig && !feed.isConfigured()) {
      results.push(await markFeedError(ctx, feed, new Error('Feed requires API credentials')));
      continue;
    }
    const cooldownUntil = rateLimitCooldownUntil.get(feed.name);
    if (cooldownUntil && Date.now() < cooldownUntil) {
      results.push(buildFeedResult(feed, {
        status: 'error',
        iocCount: ctx.sourceCounts[feed.source] || 0,
        error: `Rate limited — retrying after ${new Date(cooldownUntil).toLocaleTimeString()}`,
      }));
      continue;
    }
    try {
      results.push(await feed.sync(ctx, feed));
      rateLimitCooldownUntil.delete(feed.name);
    } catch (error) {
      if (/HTTP 429/.test(error.message)) {
        rateLimitCooldownUntil.set(feed.name, Date.now() + RATE_LIMIT_COOLDOWN_MS);
      }
      console.error(`[FeedSync] ${feed.name} failed:`, error.message);
      results.push(await markFeedError(ctx, feed, error));
    }
  }

  return {
    started_at: new Date().toISOString(),
    feeds: results,
    totals: {
      feeds: results.length,
      active: results.filter((item) => item.status === 'active').length,
      errors: results.filter((item) => item.status === 'error').length,
      waiting_on_config: results.filter((item) => item.status === 'requires_config').length,
      added: results.reduce((sum, item) => sum + (item.added || 0), 0),
    },
  };
}

function startFeedSync() {
  if (task) return;
  // runOnce() already calls ensureFeedCatalog() as its first step — calling it again here,
  // unawaited, used to race with that call on a fresh feed name and insert it twice.
  console.log('[FeedSync] Syncing threat intel feeds every 5 minutes');
  task = cron.schedule('*/5 * * * *', () => {
    runOnce().catch((error) => console.error('[FeedSync] Scheduled sync failed:', error.message));
  });
  runOnce().catch((error) => console.error('[FeedSync] Initial sync failed:', error.message));
}

function stopFeedSync() {
  if (task) {
    task.stop();
    task = null;
  }
}

function getFeedDefinitions() {
  return FEEDS.map((feed) => ({
    name: feed.name,
    source: feed.source,
    url: feed.url,
    type: feed.type,
    requiresConfig: feed.requiresConfig,
  }));
}

module.exports = { startFeedSync, stopFeedSync, runOnce, ensureFeedCatalog, getFeedDefinitions };
