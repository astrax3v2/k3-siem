'use strict';
// On-demand OSINT enrichment for analysts investigating an IP/domain/hash/email seen in an
// alert. Combines free/keyless sources (RDAP, reverse DNS, crt.sh, the existing geoip client)
// with optional paid sources (VirusTotal/AbuseIPDB/Shodan) that degrade to `configured:false`
// rather than erroring when their API key isn't set — mirrors the isConfigured() gating already
// used by the SOAR connectors.
const dns = require('dns').promises;
const express = require('express');
const { authenticate } = require('../middleware/auth');
const { lookupGeo } = require('../services/geoip');
const virustotal = require('../services/connectors/virustotal');
const abuseipdb = require('../services/connectors/abuseipdb');
const shodan = require('../services/connectors/shodan');
const router = express.Router();

const cache = new Map();
const TTL_MS = 24 * 60 * 60 * 1000;

async function cached(key, fn) {
  const hit = cache.get(key);
  if (hit && Date.now() - hit.ts < TTL_MS) return hit.value;
  const value = await fn();
  cache.set(key, { value, ts: Date.now() });
  return value;
}

async function rdap(kind, target) {
  try {
    const res = await fetch(`https://rdap.org/${kind}/${encodeURIComponent(target)}`, { signal: AbortSignal.timeout(8000) });
    if (!res.ok) return null;
    return await res.json();
  } catch { return null; }
}

async function reverseDns(ip) {
  try {
    const names = await dns.reverse(ip);
    return names?.length ? names : null;
  } catch { return null; }
}

async function crtSh(domain) {
  try {
    const res = await fetch(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`, { signal: AbortSignal.timeout(8000) });
    if (!res.ok) return null;
    return await res.json();
  } catch { return null; }
}

// Runs each source independently so one slow/unconfigured/failing source never blocks the rest.
async function settleSources(sources) {
  const entries = Object.entries(sources);
  const results = await Promise.allSettled(entries.map(([, fn]) => fn()));
  const out = {};
  entries.forEach(([name], i) => {
    out[name] = results[i].status === 'fulfilled' ? results[i].value : null;
  });
  return out;
}

router.get('/ip', authenticate, async (req, res) => {
  const ip = (req.query.ip || '').trim();
  if (!ip) return res.status(400).json({ error: 'ip is required' });

  const sources = await cached(`ip:${ip}`, () => settleSources({
    geo: () => lookupGeo(ip),
    reverse_dns: () => reverseDns(ip),
    rdap: () => rdap('ip', ip),
    virustotal: () => virustotal.lookupIp(ip),
    abuseipdb: () => abuseipdb.checkIp(ip),
    shodan: () => shodan.lookupIp(ip),
  }));

  res.json({
    target: ip,
    type: 'ip',
    sources: {
      geo: { configured: true, data: sources.geo },
      reverse_dns: { configured: true, data: sources.reverse_dns },
      rdap: { configured: true, data: sources.rdap },
      virustotal: { configured: virustotal.isConfigured(), data: sources.virustotal },
      abuseipdb: { configured: abuseipdb.isConfigured(), data: sources.abuseipdb },
      shodan: { configured: shodan.isConfigured(), data: sources.shodan },
    },
  });
});

router.get('/domain', authenticate, async (req, res) => {
  const domain = (req.query.domain || '').trim().toLowerCase();
  if (!domain) return res.status(400).json({ error: 'domain is required' });

  const sources = await cached(`domain:${domain}`, () => settleSources({
    rdap: () => rdap('domain', domain),
    crtsh: () => crtSh(domain),
    virustotal: () => virustotal.lookupDomain(domain),
  }));

  res.json({
    target: domain,
    type: 'domain',
    sources: {
      rdap: { configured: true, data: sources.rdap },
      crtsh: { configured: true, data: sources.crtsh },
      virustotal: { configured: virustotal.isConfigured(), data: sources.virustotal },
    },
  });
});

router.get('/hash', authenticate, async (req, res) => {
  const hash = (req.query.hash || '').trim().toLowerCase();
  if (!hash) return res.status(400).json({ error: 'hash is required' });

  const data = await cached(`hash:${hash}`, () => virustotal.lookupHash(hash));
  res.json({
    target: hash,
    type: 'hash',
    sources: { virustotal: { configured: virustotal.isConfigured(), data } },
  });
});

router.get('/email', authenticate, async (req, res) => {
  const email = (req.query.email || '').trim().toLowerCase();
  if (!email || !email.includes('@')) return res.status(400).json({ error: 'a valid email is required' });
  const domain = email.split('@')[1];

  const sources = await cached(`email-domain:${domain}`, () => settleSources({
    rdap: () => rdap('domain', domain),
    mx: async () => { try { return await dns.resolveMx(domain); } catch { return null; } },
  }));

  // No free reputation source exists for raw email addresses — report the domain-level
  // findings only rather than fabricating a verdict on the mailbox itself.
  res.json({
    target: email,
    type: 'email',
    sources: {
      domain_rdap: { configured: true, data: sources.rdap },
      domain_mx: { configured: true, data: sources.mx },
    },
  });
});

module.exports = router;
