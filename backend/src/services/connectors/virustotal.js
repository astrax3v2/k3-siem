'use strict';
function isConfigured() { return !!process.env.VIRUSTOTAL_API_KEY; }

async function lookupIp(ip) {
  if (!isConfigured()) return null;
  try {
    const res = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ip)}`, {
      headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY }, signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return null;
    const data = await res.json();
    return data?.data?.attributes || null;
  } catch { return null; }
}

async function lookupHash(hash) {
  if (!isConfigured()) return null;
  try {
    const res = await fetch(`https://www.virustotal.com/api/v3/files/${encodeURIComponent(hash)}`, {
      headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY }, signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return null;
    const data = await res.json();
    return data?.data?.attributes || null;
  } catch { return null; }
}

async function lookupDomain(domain) {
  if (!isConfigured()) return null;
  try {
    const res = await fetch(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`, {
      headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY }, signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return null;
    const data = await res.json();
    return data?.data?.attributes || null;
  } catch { return null; }
}

module.exports = { isConfigured, lookupIp, lookupHash, lookupDomain };
