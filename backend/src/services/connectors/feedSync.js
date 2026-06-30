'use strict';
// Pulls real indicators from threat-intel providers into the iocs table on a schedule —
// previously intel_feeds rows were static seed data with a fake last_sync timestamp and
// no code path ever actually contacted MISP/VirusTotal/AbuseIPDB/OTX.
const cron = require('node-cron');
const { v4: uuidv4 } = require('uuid');
const { db, sqlNow } = require('../../models/db');
const abuseipdb = require('./abuseipdb');
const otx = require('./otx');

let task = null;

const OTX_TYPE_MAP = {
  IPv4: 'IP', IPv6: 'IP', domain: 'Domain', hostname: 'Domain', URL: 'URL',
  'FileHash-MD5': 'Hash', 'FileHash-SHA1': 'Hash', 'FileHash-SHA256': 'Hash', email: 'Email',
};

async function upsertIOC(d, type, value, confidence, severity, source, description) {
  const existing = await d.prepare('SELECT id FROM iocs WHERE type = ? AND value = ?').get(type, value);
  if (existing) {
    await d.prepare(`UPDATE iocs SET confidence = ?, last_seen = ${sqlNow()} WHERE id = ?`).run(confidence, existing.id);
    return false;
  }
  await d.prepare('INSERT INTO iocs(id,type,value,confidence,severity,source,description,tags,hits) VALUES(?,?,?,?,?,?,?,?,0)')
    .run(uuidv4(), type, value, confidence, severity, source, description, JSON.stringify([]));
  return true;
}

async function touchFeed(d, name, added) {
  await d.prepare(`UPDATE intel_feeds SET status='active', last_sync=${sqlNow()}, ioc_count = ioc_count + ? WHERE name = ?`).run(added, name);
}

async function syncAbuseIPDB(d) {
  if (!abuseipdb.isConfigured()) return;
  try {
    const res = await fetch('https://api.abuseipdb.com/api/v2/blacklist?limit=100&confidenceMinimum=75', {
      headers: { Key: process.env.ABUSEIPDB_API_KEY, Accept: 'application/json' }, signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) return;
    const data = await res.json();
    let added = 0;
    for (const entry of data?.data || []) {
      const isNew = await upsertIOC(d, 'IP', entry.ipAddress, entry.abuseConfidenceScore,
        entry.abuseConfidenceScore >= 90 ? 'Critical' : 'High', 'AbuseIPDB', `Abuse confidence ${entry.abuseConfidenceScore}%`);
      if (isNew) added++;
    }
    await touchFeed(d, 'AbuseIPDB', added);
    console.log(`[FeedSync] AbuseIPDB: ${added} new IOCs`);
  } catch (e) { console.error('[FeedSync] AbuseIPDB failed:', e.message); }
}

async function syncOTX(d) {
  if (!otx.isConfigured()) return;
  try {
    const res = await fetch('https://otx.alienvault.com/api/v1/pulses/subscribed?limit=20', {
      headers: { 'X-OTX-API-KEY': process.env.OTX_API_KEY }, signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) return;
    const data = await res.json();
    let added = 0;
    for (const pulse of data?.results || []) {
      for (const ind of pulse.indicators || []) {
        const type = OTX_TYPE_MAP[ind.type];
        if (!type) continue;
        const isNew = await upsertIOC(d, type, ind.indicator, 70, 'High', 'OTX AlienVault', pulse.name);
        if (isNew) added++;
      }
    }
    await touchFeed(d, 'OTX AlienVault', added);
    console.log(`[FeedSync] OTX: ${added} new IOCs`);
  } catch (e) { console.error('[FeedSync] OTX failed:', e.message); }
}

async function runOnce() {
  const d = db();
  await syncAbuseIPDB(d);
  await syncOTX(d);
}

function startFeedSync() {
  if (task) return;
  if (!abuseipdb.isConfigured() && !otx.isConfigured()) {
    console.log('[FeedSync] No threat-intel API keys configured (ABUSEIPDB_API_KEY / OTX_API_KEY) — feed sync idle');
    return;
  }
  console.log('[FeedSync] Syncing threat intel feeds every 30 minutes');
  task = cron.schedule('*/30 * * * *', () => runOnce().catch(() => {}));
  runOnce().catch(() => {});
}

function stopFeedSync() {
  if (task) { task.stop(); task = null; }
}

module.exports = { startFeedSync, stopFeedSync, runOnce };
