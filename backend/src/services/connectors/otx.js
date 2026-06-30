'use strict';
function isConfigured() { return !!process.env.OTX_API_KEY; }

async function lookupIp(ip) {
  if (!isConfigured()) return null;
  try {
    const res = await fetch(`https://otx.alienvault.com/api/v1/indicators/IPv4/${encodeURIComponent(ip)}/general`, {
      headers: { 'X-OTX-API-KEY': process.env.OTX_API_KEY }, signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return null;
    return await res.json();
  } catch { return null; }
}

module.exports = { isConfigured, lookupIp };
