'use strict';
// Minimal IP geolocation client used for UEBA geo-velocity scoring. Uses the free,
// keyless ip-api.com endpoint (45 req/min limit) — set GEOIP_DISABLED=true to turn this
// off entirely (e.g. in offline/air-gapped deployments).
const PRIVATE_RE = /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.)/;
const cache = new Map();
const TTL_MS = 24 * 60 * 60 * 1000;

function isPrivate(ip) {
  return !ip || PRIVATE_RE.test(ip);
}

async function lookupGeo(ip) {
  if (isPrivate(ip) || process.env.GEOIP_DISABLED === 'true') return null;
  const cached = cache.get(ip);
  if (cached && Date.now() - cached.ts < TTL_MS) return cached.geo;

  try {
    const res = await fetch(`http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,lat,lon,country`, {
      signal: AbortSignal.timeout(3000),
    });
    const data = await res.json();
    const geo = data.status === 'success' ? { lat: data.lat, lon: data.lon, country: data.country } : null;
    cache.set(ip, { geo, ts: Date.now() });
    return geo;
  } catch {
    cache.set(ip, { geo: null, ts: Date.now() });
    return null;
  }
}

function haversineKm(a, b) {
  const R = 6371;
  const dLat = (b.lat - a.lat) * Math.PI / 180;
  const dLon = (b.lon - a.lon) * Math.PI / 180;
  const la1 = a.lat * Math.PI / 180, la2 = b.lat * Math.PI / 180;
  const h = Math.sin(dLat / 2) ** 2 + Math.cos(la1) * Math.cos(la2) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(h));
}

module.exports = { lookupGeo, haversineKm, isPrivate };
