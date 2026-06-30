'use strict';
// Matches ingested events against the iocs table — previously IOC `hits` never incremented
// and no alert was ever generated from a match; IOCs were purely a CRUD list with no
// connection to the event pipeline.
const { v4: uuidv4 } = require('uuid');
const { db, sqlNow } = require('../models/db');

const HASH_RE = /\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b/g;
const URL_RE = /https?:\/\/[^\s"'<>]+/gi;
const DOMAIN_RE = /\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi;
const EMAIL_RE = /[\w.+-]+@[\w-]+\.[\w.-]+/gi;
const MAX_CANDIDATES_PER_TYPE = 25;

function extractCandidates(event) {
  const out = { IP: new Set(), Hash: new Set(), URL: new Set(), Domain: new Set(), Email: new Set() };
  if (event.ip_address) out.IP.add(event.ip_address);
  const raw = typeof event.raw_log === 'string' ? event.raw_log : JSON.stringify(event.raw_log || {});
  for (const m of raw.match(HASH_RE) || []) out.Hash.add(m.toLowerCase());
  for (const m of raw.match(URL_RE) || []) out.URL.add(m);
  for (const m of raw.match(EMAIL_RE) || []) out.Email.add(m.toLowerCase());
  for (const m of raw.match(DOMAIN_RE) || []) {
    if (!out.Email.has(m)) out.Domain.add(m.toLowerCase());
  }
  return out;
}

async function matchIOCs(event) {
  const d = db();
  const candidates = extractCandidates(event);
  const hits = [];

  for (const [type, values] of Object.entries(candidates)) {
    if (!values.size) continue;
    const list = Array.from(values).slice(0, MAX_CANDIDATES_PER_TYPE);
    const placeholders = list.map(() => '?').join(',');
    const matched = await d.prepare(
      `SELECT * FROM iocs WHERE active = 1 AND type = ? AND value IN (${placeholders})`
    ).all(type, ...list);

    for (const ioc of matched) {
      await d.prepare(`UPDATE iocs SET hits = hits + 1, last_seen = ${sqlNow()} WHERE id = ?`).run(ioc.id);
      const alertId = uuidv4();
      await d.prepare(
        `INSERT INTO alerts(id,title,description,severity,status,source,asset,username,ip_address,mitre_tactic,risk_score,rule_id)
         VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`
      ).run(
        alertId, `Threat Intel Match: ${ioc.type} ${ioc.value}`,
        `Event matched known IOC (source: ${ioc.source || 'internal'}, confidence ${ioc.confidence}%)${ioc.description ? ' — ' + ioc.description : ''}`,
        ioc.severity || 'High', 'New', event.source, event.computer, event.username, event.ip_address,
        'Command & Control', Math.min(99, 50 + Math.round((ioc.confidence || 50) / 2)), `ioc:${ioc.id}`
      );
      hits.push({ ioc, alertId });
    }
  }
  return hits;
}

module.exports = { matchIOCs, extractCandidates };
