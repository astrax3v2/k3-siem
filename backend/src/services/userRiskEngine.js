'use strict';
// Computes real UEBA risk scores from ingested event history — replacing the previous
// behavior where ueba_scores was purely static seeded data with no computation behind it.
// Statistical baselining (histograms, z-scores), not ML — appropriate for a SIEM where
// analysts need to understand *why* a score fired.
const cron = require('node-cron');
const { v4: uuidv4 } = require('uuid');
const { db, sqlNow, sqlNowMinus, sqlDate } = require('../models/db');
const { lookupGeo, haversineKm } = require('./geoip');

let task = null;
const LOGON_COND = "(event_id = '4624' OR action = 'User Logon')";

const mean = (arr) => (arr.length ? arr.reduce((a, b) => a + b, 0) / arr.length : 0);
const stddev = (arr) => {
  if (arr.length < 2) return 0;
  const m = mean(arr);
  return Math.sqrt(mean(arr.map((x) => (x - m) ** 2)));
};

async function loginTimeAnomaly(d, username) {
  const baseline = await d.prepare(
    `SELECT timestamp FROM events WHERE username = ? AND ${LOGON_COND} AND timestamp < ${sqlNowMinus(1, 'day')} AND timestamp >= ${sqlNowMinus(30, 'day')}`
  ).all(username);
  if (baseline.length < 5) return false; // not enough history to baseline confidently

  const hourCounts = new Array(24).fill(0);
  for (const r of baseline) hourCounts[new Date(r.timestamp).getUTCHours()]++;
  const total = baseline.length;
  const normalHours = new Set(hourCounts.map((c, h) => ({ c, h })).filter((x) => x.c / total >= 0.04).map((x) => x.h));

  const recent = await d.prepare(
    `SELECT timestamp FROM events WHERE username = ? AND ${LOGON_COND} AND timestamp >= ${sqlNowMinus(1, 'day')}`
  ).all(username);
  return recent.some((r) => !normalHours.has(new Date(r.timestamp).getUTCHours()));
}

async function geoVelocityAnomaly(d, username) {
  const logins = await d.prepare(
    `SELECT timestamp, ip_address FROM events WHERE username = ? AND ip_address IS NOT NULL AND timestamp >= ${sqlNowMinus(7, 'day')} ORDER BY timestamp DESC LIMIT 8`
  ).all(username);
  for (let i = 0; i < logins.length - 1; i++) {
    const a = logins[i], b = logins[i + 1];
    if (a.ip_address === b.ip_address) continue;
    const hours = Math.abs(new Date(a.timestamp) - new Date(b.timestamp)) / 3600000;
    if (hours < 0.05) continue;
    const [geoA, geoB] = await Promise.all([lookupGeo(a.ip_address), lookupGeo(b.ip_address)]);
    if (!geoA || !geoB) continue;
    const speedKmh = haversineKm(geoA, geoB) / hours;
    if (speedKmh > 900) return true; // faster than plausible commercial travel
  }
  return false;
}

async function dataVolumeZ(d, username, recentCount) {
  const rows = await d.prepare(
    `SELECT ${sqlDate('timestamp')} as day, COUNT(*) as cnt FROM events
     WHERE username = ? AND timestamp >= ${sqlNowMinus(30, 'day')} AND timestamp < ${sqlNowMinus(1, 'day')}
     GROUP BY ${sqlDate('timestamp')}`
  ).all(username);
  const counts = rows.map((r) => r.cnt);
  if (counts.length < 3) return 0;
  const m = mean(counts), sd = stddev(counts);
  if (sd === 0) return recentCount > m ? 3 : 0;
  return (recentCount - m) / sd;
}

async function runOnce() {
  const d = db();
  const active = await d.prepare(
    `SELECT DISTINCT username FROM events WHERE username IS NOT NULL AND timestamp >= ${sqlNowMinus(30, 'day')}`
  ).all();
  if (!active.length) return;

  const recentRows = await d.prepare(
    `SELECT username, COUNT(*) as cnt FROM events WHERE username IS NOT NULL AND timestamp >= ${sqlNowMinus(1, 'day')} GROUP BY username`
  ).all();
  const recentCountByUser = Object.fromEntries(recentRows.map((r) => [r.username, r.cnt]));

  const existing = await d.prepare('SELECT username, department, location FROM ueba_scores').all();
  const deptByUser = Object.fromEntries(existing.map((r) => [r.username, r.department || 'Unknown']));
  const locByUser = Object.fromEntries(existing.map((r) => [r.username, r.location || '—']));

  // Peer-group baseline: mean/stddev of today's event volume within each department.
  const byDept = {};
  for (const { username } of active) {
    const dept = deptByUser[username] || 'Unknown';
    (byDept[dept] = byDept[dept] || []).push(recentCountByUser[username] || 0);
  }
  const peerStatsByDept = Object.fromEntries(
    Object.entries(byDept).map(([dept, counts]) => [dept, { mean: mean(counts), sd: stddev(counts) }])
  );

  for (const { username } of active) {
    try {
      const recentCount = recentCountByUser[username] || 0;
      const flags = [];
      let maxAbsZ = 0;

      if (await loginTimeAnomaly(d, username)) flags.push('Login Time Anomaly');
      if (await geoVelocityAnomaly(d, username)) flags.push('Geo-Velocity');

      const dept = deptByUser[username] || 'Unknown';
      const peer = peerStatsByDept[dept] || { mean: 0, sd: 0 };
      const peerZ = peer.sd > 0 ? (recentCount - peer.mean) / peer.sd : 0;
      if (peerZ > 2) flags.push('Peer Group Deviation');
      maxAbsZ = Math.max(maxAbsZ, Math.abs(peerZ));

      const volZ = await dataVolumeZ(d, username, recentCount);
      if (volZ > 2) flags.push('Data Volume Spike');
      maxAbsZ = Math.max(maxAbsZ, Math.abs(volZ));

      const riskScore = Math.max(0, Math.min(100, Math.round(flags.length * 18 + Math.max(0, maxAbsZ) * 8)));

      const row = await d.prepare('SELECT id FROM ueba_scores WHERE username = ?').get(username);
      if (row) {
        await d.prepare(
          `UPDATE ueba_scores SET risk_score = ?, anomaly_count = ?, baseline_deviation = ?, flags = ?, last_activity = ?, updated_at = ${sqlNow()} WHERE id = ?`
        ).run(riskScore, flags.length, Number(maxAbsZ.toFixed(2)), JSON.stringify(flags), new Date().toISOString(), row.id);
      } else {
        await d.prepare(
          `INSERT INTO ueba_scores(id,username,risk_score,anomaly_count,baseline_deviation,flags,department,location,last_activity) VALUES(?,?,?,?,?,?,?,?,?)`
        ).run(uuidv4(), username, riskScore, flags.length, Number(maxAbsZ.toFixed(2)), JSON.stringify(flags), dept, locByUser[username] || '—', new Date().toISOString());
      }
    } catch (e) {
      console.error(`[UEBA] Scoring failed for ${username}:`, e.message);
    }
  }
}

function startUebaEngine() {
  if (task) return;
  console.log('[UEBA] Baseline scoring every 5 minutes');
  task = cron.schedule('*/5 * * * *', () => { runOnce().catch((e) => console.error('[UEBA] Run failed:', e.message)); });
  runOnce().catch(() => {}); // prime scores on boot instead of waiting 5 minutes
}

function stopUebaEngine() {
  if (task) { task.stop(); task = null; }
}

module.exports = { startUebaEngine, stopUebaEngine, runOnce };
